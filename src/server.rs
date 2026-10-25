//! Process-level proxy server: bind, banner, accept loop.
//!
//! Extracted from the binary so embedders (the Android app, tests) can start
//! and stop the same accept loop the CLI runs, without spawning a process or
//! duplicating the fallback / pool / FD-budget setup.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::check;
use crate::config::{Config, UpstreamTier};
use crate::default_domains;
use crate::limits::{auto_max_connections, soft_nofile_limit};
use crate::pool::WsPool;
use crate::proxy;
use crate::runtime::Runtime;

/// Why [`run`] / [`run_with_listen`] stopped before serving, or failed to start.
#[derive(Debug)]
pub enum RunError {
    /// `--outbound-proxy` / `NO_PROXY` could not be parsed.
    InvalidOutbound(String),
    /// A pinned upstream tier (`--pinned-upstream` / `--pinned-media-upstream`)
    /// names a tier nothing configures.
    InvalidPin(String),
    /// `{host}:{port}` is not a valid socket address.
    InvalidListenAddress(String),
    /// The listen socket could not be bound.
    Bind {
        addr: SocketAddr,
        source: std::io::Error,
    },
    /// `--check` ran and at least one probe failed.
    CheckFailed,
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOutbound(e) => write!(f, "invalid outbound proxy config: {e}"),
            Self::InvalidPin(e) => write!(f, "invalid pinned upstream config: {e}"),
            Self::InvalidListenAddress(addr) => write!(f, "invalid listen address: {addr}"),
            Self::Bind { addr, source } => write!(f, "cannot bind {addr}: {source}"),
            Self::CheckFailed => write!(f, "connectivity check failed"),
        }
    }
}

impl std::error::Error for RunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Bound address and `tg://` link, handed to [`run_with_listen`] once the
/// listener is up and the startup banner has been logged.
#[derive(Clone, Debug)]
pub struct ListenInfo {
    pub addr: SocketAddr,
    pub tg_link: String,
}

/// Install the rustls `ring` provider if nothing else has yet.
///
/// Safe to call more than once — later calls are ignored, including when a
/// test harness already installed a provider.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Run the proxy until `shutdown` completes.
///
/// Same path as the binary: fetch `--default-domains`, honour `--check`, bind,
/// print the banner, warm the pool, then accept clients.  Completing `shutdown`
/// breaks the accept loop and returns; in-flight connections are dropped with
/// the Tokio runtime that called this.
pub async fn run(
    config: Config,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), RunError> {
    run_with_listen(config, shutdown, |_| {}).await
}

/// Awaits a check's verdict when one is running, and never completes otherwise,
/// so the accept loop can keep a single `select!` shape whether or not
/// `--check-listener` asked for one.
async fn check_verdict(rx: &mut Option<tokio::sync::oneshot::Receiver<bool>>) -> bool {
    match rx {
        Some(rx) => rx.await.unwrap_or(false),
        None => std::future::pending().await,
    }
}

/// [`run`] plus a one-shot callback after the listen socket is bound.
///
/// `on_listen` is how an embedder learns the real port (when `--port 0`) and
/// the `tg://proxy` link without scraping log lines.
pub async fn run_with_listen(
    mut config: Config,
    shutdown: impl Future<Output = ()> + Send,
    on_listen: impl FnOnce(ListenInfo) + Send,
) -> Result<(), RunError> {
    install_crypto_provider();

    let outbound = config
        .outbound_connector()
        .map_err(RunError::InvalidOutbound)?;
    let runtime = Arc::new(
        Runtime::new(outbound)
            .with_cf_ips(config.cf_ips.clone())
            .with_cf_fail_cooldown(Duration::from_secs(config.cf_fail_cooldown))
            .with_fronting(config.fronting_domain.clone()),
    );

    tokio::pin!(shutdown);

    // ── Default CF domain list (--default-domains) ────────────────────────
    // Fetch the obfuscated domain list from GitHub, deobfuscate it, and
    // append the resulting domains to any that were supplied with --cf-domain.
    // Done once here so both --check mode and the normal server path share
    // the same fetched list.  The fetch selects on `shutdown` so an embedder
    // can cancel a slow fetch instead of blocking a stop for the full timeout.
    // A failed fetch serves from the built-in list and, once serving, keeps
    // retrying in the background — see `default_domains::refetch_delays`.
    let mut refetch_onto = None;
    if config.default_domains {
        info!("Fetching default CF proxy domain list from GitHub…");
        let fetched = tokio::select! {
            _ = &mut shutdown => {
                info!("proxy stopped");
                return Ok(());
            }
            fetched = default_domains::try_fetch_default_domains(runtime.outbound()) => fetched,
        };
        match fetched {
            Ok(fetched) => {
                info!("  Got {} default CF domain(s)", fetched.len());
                config.cf_domains.extend(fetched);
            }
            Err(e) => {
                let builtin = default_domains::fallback_domains();
                warn!(
                    "Failed to fetch default CF domain list ({}); using the {} built-in \
                     domain(s) until a background re-fetch succeeds",
                    e,
                    builtin.len()
                );
                refetch_onto = Some(config.cf_domains.clone());
                config.cf_domains.extend(builtin);
            }
        }
    }

    // ── Pinned upstream sanity ───────────────────────────────────────────
    // After the domain fetch (so a cfproxy pin plus --default-domains is
    // judged on the fetched list) and before anything binds: a class pinned
    // to an unconfigured tier would drop every connection at runtime.
    config
        .validate_pinned_upstreams()
        .map_err(RunError::InvalidPin)?;
    for (flag, tiers) in [
        ("--pinned-upstream", &config.pinned_upstreams),
        ("--pinned-media-upstream", &config.pinned_media_upstreams),
    ] {
        if let Some(pos) = tiers.iter().position(|t| *t == UpstreamTier::Tcp)
            && pos + 1 != tiers.len()
        {
            warn!(
                "{flag}: tcp is a terminal tier — everything listed after it \
                 ({}) is never reached",
                tiers[pos + 1..]
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    }

    // ── Connectivity check mode (--check) ────────────────────────────────
    // Run probes for every configured CF domain and MTProto proxy, print the
    // results, then return.  This lets the user verify their configuration
    // before starting the proxy server.
    //
    // With `--check-listener` there is a socket of our own to probe, so the
    // check runs after the bind below instead, against the listener this
    // process serves on.
    if config.check && !config.check_listener {
        let all_ok = tokio::select! {
            _ = &mut shutdown => return Ok(()),
            all_ok = check::run_check_with_outbound(&config, runtime.outbound(), None) => all_ok,
        };
        return if all_ok {
            Ok(())
        } else {
            Err(RunError::CheckFailed)
        };
    }

    // ── Bind the server socket ────────────────────────────────────────────
    let bind_host = config.bind_host();
    let addr: SocketAddr = format!("{}:{}", bind_host, config.port)
        .parse()
        .map_err(|_| RunError::InvalidListenAddress(format!("{bind_host}:{}", config.port)))?;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| RunError::Bind { addr, source })?;
    let bound_addr = listener.local_addr().unwrap_or(addr);
    let listen_port = bound_addr.port();

    // ── FD budget & effective max_connections ────────────────────────────
    // Each active connection uses 2 FDs: the accepted client socket and the
    // outbound connection to Telegram (WS or TCP fallback).  The pool adds
    // pool_size × dc_buckets × 2 FDs (idle + one in-flight refill per bucket).
    // Auto-compute a safe default when the user has not set --max-connections,
    // so the proxy stays within the process's soft file-descriptor limit.
    let fd_limit = soft_nofile_limit();
    let dc_redirects = config.dc_redirects();
    let dc_buckets = dc_redirects.len() * 2; // non-media + media per DC
    let max_connections = match config.max_connections {
        Some(n) => {
            let safe = auto_max_connections(fd_limit, config.pool_size, dc_buckets);
            if n > safe {
                warn!(
                    "max-connections={} may exceed the safe limit for this system's \
                     FD budget (fd-limit={}, recommended ≤{}). \
                     Consider raising `ulimit -n` or reducing --max-connections.",
                    n, fd_limit, safe
                );
            }
            n
        }
        None => auto_max_connections(fd_limit, config.pool_size, dc_buckets),
    };

    // ── Print startup banner ──────────────────────────────────────────────
    let secret = config.primary_secret();

    let link_host = config.link_host();
    let tg_link = format!(
        "tg://proxy?server={}&port={}&secret={}",
        link_host,
        listen_port,
        config.link_secret()
    );

    info!("{}", "=".repeat(60));
    info!(
        "  Telegram MTProto WS Bridge Proxy  (tg-ws-proxy-rs v{})",
        env!("CARGO_PKG_VERSION")
    );
    info!("  Listening on   {}:{}", bind_host, listen_port);
    info!("  Secret:        {}", secret);
    if let Some(domain) = config.listen_faketls_domain() {
        info!("  Inbound mode:   FakeTLS ee (SNI: {})", domain);
    } else {
        info!("  Inbound mode:   padded MTProto dd");
    }
    info!("  Target DC IPs:");
    let mut dcs: Vec<_> = dc_redirects.iter().collect();
    dcs.sort_by_key(|(k, _)| *k);
    for (dc, ip) in &dcs {
        info!("    DC{}: {}", dc, ip);
    }

    if config.skip_tls_verify {
        info!("  ⚠  TLS certificate verification DISABLED");
    }

    if !config.cf_domains.is_empty() {
        info!("  Cloudflare proxy domain(s):");
        for d in &config.cf_domains {
            info!("    {} (kws{{N}}.{} subdomains)", d, d);
        }
        if config.cf_balance && config.cf_domains.len() > 1 {
            info!("    ⚖  CF balance mode: connections are round-robin'd across domains");
        }
    }

    let cf_worker_domains = config.cf_worker_domains();
    if !cf_worker_domains.is_empty() {
        info!("  Cloudflare Worker domain(s):");
        for domain in cf_worker_domains {
            info!("    {}", domain);
        }
    }

    if config.cf_disable_tls && (!config.cf_domains.is_empty() || !cf_worker_domains.is_empty()) {
        warn!(
            "  ⚠  CF transport: plaintext ws:// on port 80 — the obfuscated MTProto stream is \
             on the wire in the clear: every frame's auth_key_id is readable and the \
             obfuscation is recoverable from captured bytes (#123), so connections are \
             identifiable. Route media through these tiers, not text."
        );
    }
    if !config.pinned_upstreams.is_empty() || !config.pinned_media_upstreams.is_empty() {
        info!("  Pinned upstream order (default ladder is used for the rest):");
        let names = |tiers: &[UpstreamTier]| {
            tiers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        if !config.pinned_upstreams.is_empty() {
            info!("    non-media: {}", names(&config.pinned_upstreams));
        }
        if !config.pinned_media_upstreams.is_empty() {
            info!("    media: {}", names(&config.pinned_media_upstreams));
        } else if !config.pinned_upstreams.is_empty() {
            info!("    media: inherits non-media pin above");
        }
    }

    if !config.cf_ips.is_empty() {
        info!(
            "  Cloudflare preferred IP(s): {}",
            config
                .cf_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        );
        if config.cf_domains.is_empty() && cf_worker_domains.is_empty() {
            warn!(
                "  ⚠  --cf-ip has no effect: no --cf-domain, --default-domains, \
                 or --cf-worker-domain route is configured"
            );
        }
    }

    if !config.mtproto_proxies.is_empty() {
        info!("  Upstream MTProto proxies (WS fallback):");
        for p in &config.mtproto_proxies {
            info!("    {}:{}", p.host, p.port);
        }
    }

    if let Some(summary) = runtime.outbound().summary() {
        info!("  Outbound proxy: {}", summary);
    }

    if let Some(domain) = runtime.fronting_domain() {
        if dc_redirects.is_empty() {
            warn!(
                "  ⚠  --fronting-domain {} has no effect: no --dc-ip is configured. \
                 Fronting only applies to a direct connection to a DC's real IP \
                 (matching upstream tg-ws-proxy) — it is never used for CF proxy, \
                 CF Worker, or upstream MTProto proxy connections.",
                domain
            );
        } else {
            info!("  Domain fronting: always (SNI {})", domain);
        }
    }

    info!(
        "  Max connections: {} (fd-limit: {})",
        max_connections, fd_limit
    );
    info!("{}", "=".repeat(60));
    info!("  Telegram proxy link (use this on all devices):");
    info!("    {}", tg_link);
    if config.secrets.len() > 1 {
        info!("  Additional per-user proxy links:");
        for secret in &config.secrets[1..] {
            let link_secret = config.link_secret_for(secret);
            info!(
                "    tg://proxy?server={}&port={}&secret={}",
                link_host, listen_port, link_secret
            );
        }
    }

    if link_host != bind_host {
        info!(
            "  ℹ  Link uses auto-detected IP {}. \
             Use --link-ip <IP> to override.",
            link_host
        );
    } else if matches!(bind_host.as_str(), "127.0.0.1" | "::1") {
        warn!(
            "  ⚠  Link shows {} — only the local machine can use this link. \
             Run with --host 0.0.0.0 (or --link-ip <router-LAN-IP>) \
             so other devices on the network can connect.",
            bind_host
        );
    }
    info!("{}", "=".repeat(60));

    on_listen(ListenInfo {
        addr: bound_addr,
        tg_link,
    });

    // ── Connection pool warm-up ───────────────────────────────────────────
    let pool = Arc::new(WsPool::with_runtime(
        config.pool_size,
        Duration::from_secs(config.pool_max_age),
        Arc::clone(&runtime),
    ));
    // Shared for the rest of the process: every connection reads the same
    // settings, so they are behind one `Arc` instead of a per-connection clone.
    let config = Arc::new(config);
    // Connections take their settings from here, so a re-fetched domain list
    // reaches every connection accepted after it lands.
    let (config_tx, config_rx) = watch::channel(Arc::clone(&config));
    let _refetch = match refetch_onto {
        Some(own_domains) if !config.check => Some(AbortOnDrop(tokio::spawn(refetch_domains(
            config_tx,
            own_domains,
            Arc::clone(&runtime),
        )))),
        _ => None,
    };
    {
        let pool_clone = pool.clone();
        let config_clone = Arc::clone(&config);
        tokio::spawn(async move {
            pool_clone.warmup(&config_clone).await;
        });
    }

    // ── Own-listener check (--check --check-listener) ─────────────────────
    // The probes run as a task, not before the bind: the listener probe has to
    // be accepted by the loop below, so the two run together, and the loop
    // stops on the verdict.  The socket handed over is the one just bound, so
    // the secret, address and inbound mode are the ones being served rather
    // than copies the user has to repeat.
    let (check_tx, check_rx) = tokio::sync::oneshot::channel::<bool>();
    let mut check_rx = Some(check_rx);
    let _check_keep = if config.check {
        let config = Arc::clone(&config);
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            let all_ok =
                check::run_check_with_outbound(&config, runtime.outbound(), Some(bound_addr)).await;
            let _ = check_tx.send(all_ok);
        });
        None
    } else {
        // Held for the life of the loop, so the receiver never resolves and the
        // selects below keep one shape.
        Some(check_tx)
    };
    let mut check_ok = None;

    // ── Accept loop ───────────────────────────────────────────────────────
    // Acquire a permit before each accept() to cap concurrent connections.
    // This prevents EMFILE (too many open files) by keeping file-descriptor
    // usage bounded: at most `max_connections` client sockets plus the pool
    // connections can be open simultaneously.
    const EMFILE: i32 = 24; // too many open files (per-process fd limit)
    const ENFILE: i32 = 23; // file table overflow (system-wide fd limit)
    let semaphore = Arc::new(Semaphore::new(max_connections));
    loop {
        // Block here when we are already at the connection limit.  Pending
        // TCP connections queue in the kernel backlog until capacity frees up.
        let permit = tokio::select! {
            _ = &mut shutdown => break,
            all_ok = check_verdict(&mut check_rx) => {
                check_ok = Some(all_ok);
                break;
            }
            permit = Arc::clone(&semaphore).acquire_owned() => {
                permit.expect("semaphore closed unexpectedly")
            }
        };

        tokio::select! {
            _ = &mut shutdown => break,
            all_ok = check_verdict(&mut check_rx) => {
                check_ok = Some(all_ok);
                break;
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer_addr)) => {
                        let cfg = Arc::clone(&config_rx.borrow());
                        let pool = pool.clone();
                        let runtime = Arc::clone(&runtime);
                        tokio::spawn(async move {
                            // Hold the permit for the lifetime of this connection so
                            // it is released (and the slot freed) when the task ends.
                            let _permit = permit;
                            proxy::handle_client_with_runtime(
                                stream, peer_addr, cfg, pool, runtime,
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        // EMFILE / ENFILE: the process has run out of file descriptors
                        // (e.g. from pool connections).  Back off longer to let
                        // existing connections close, and log at warn-level to avoid
                        // flooding the log with repeated identical messages.
                        if matches!(e.raw_os_error(), Some(EMFILE) | Some(ENFILE)) {
                            warn!("accept error: {} — backing off to allow FDs to free", e);
                            tokio::time::sleep(Duration::from_millis(500)).await;
                        } else {
                            error!("accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
            }
        }
    }

    if let Some(all_ok) = check_ok {
        return if all_ok {
            Ok(())
        } else {
            Err(RunError::CheckFailed)
        };
    }

    info!("proxy stopped");
    Ok(())
}

/// Aborts the task when dropped, so a background task started by
/// [`run_with_listen`] ends with it rather than outliving a stopped proxy in
/// an embedder that keeps its runtime.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Re-fetch the `--default-domains` list after the startup fetch failed, and
/// swap it in for the built-in one once it arrives.
///
/// `own_domains` is the `--cf-domain` list the fetched one is appended to,
/// exactly as at startup.  The pool's spares were opened through the built-in
/// domains and are left alone: they still work, and refill through whichever
/// domain the next connection answers on.
async fn refetch_domains(
    config_tx: watch::Sender<Arc<Config>>,
    own_domains: Vec<String>,
    runtime: Arc<Runtime>,
) {
    let fetched = default_domains::refetch(default_domains::refetch_delays(), || {
        default_domains::try_fetch_default_domains(runtime.outbound())
    })
    .await;
    let Some(fetched) = fetched else {
        warn!(
            "Giving up on re-fetching the default CF domain list; the built-in list stays in use"
        );
        return;
    };

    info!(
        "Re-fetched the default CF domain list: {} domain(s) now in use",
        fetched.len()
    );
    let mut next = Config::clone(&config_tx.borrow());
    next.cf_domains = own_domains;
    next.cf_domains.extend(fetched);
    config_tx.send_replace(Arc::new(next));
}
