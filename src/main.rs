//! tg-ws-proxy-rs — Telegram MTProto WebSocket Bridge Proxy
//!
//! Listens for Telegram Desktop MTProto connections and forwards them through
//! WebSocket tunnels to Telegram's DC servers, bypassing networks that block
//! direct Telegram TCP traffic.
//!
//! # Architecture
//!
//! ```
//! Telegram Desktop → MTProto (TCP 1443) → tg-ws-proxy-rs → WS (TLS 443) → Telegram DC
//! ```
//!
//! See [`proxy`] for the connection handling logic and [`crypto`] for the
//! MTProto obfuscation details.

use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

// ── File-descriptor budget helpers ───────────────────────────────────────────

/// Read the soft per-process open-file limit from `/proc/self/limits` (Linux).
/// Falls back to 1 024 on other platforms or when the file cannot be parsed.
fn soft_nofile_limit() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/self/limits") {
            for line in content.lines() {
                // Example line:
                //   Max open files            1024                 4096                 files
                if line.starts_with("Max open files")
                    && let Some(soft_str) = line.split_whitespace().nth(3)
                {
                    if soft_str == "unlimited" {
                        return usize::MAX;
                    }
                    if let Ok(n) = soft_str.parse::<usize>() {
                        return n;
                    }
                }
            }
        }
    }

    1024 // conservative fallback for non-Linux or parse failures
}

/// Compute a safe default for the maximum number of concurrent connections
/// given the system FD limit and pool configuration.
///
/// FD budget:
///   1 (listener) + pool_size × dc_buckets × 2 (idle + one refill per bucket)
///   + 32 (Tokio runtime, stdio, safety margin)
///   + max_connections × 2 (one client socket + one outbound socket per conn)
///
/// Rearranging for max_connections:
///   max_connections = (fd_limit − reserved) / 2
fn auto_max_connections(fd_limit: usize, pool_size: usize, dc_buckets: usize) -> usize {
    if fd_limit == usize::MAX {
        // Unlimited FDs: cap at a large but sane value.
        return 512;
    }

    let reserved = 1 + pool_size * dc_buckets * 2 + 32;

    (fd_limit.saturating_sub(reserved) / 2).max(4)
}

use tg_ws_proxy_rs::{
    check, config::Config, default_domains, pool::WsPool, proxy, runtime::Runtime, update_check,
};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    let mut config = Config::from_args();
    let outbound = match config.outbound_connector() {
        Ok(outbound) => outbound,
        Err(e) => {
            eprintln!("invalid outbound proxy config: {e}");
            std::process::exit(2);
        }
    };
    let runtime = Arc::new(Runtime::new(outbound));

    // ── Logging ──────────────────────────────────────────────────────────
    let log_level = if config.quiet {
        "off"
    } else if config.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| log_level.into());

    if let Some(ref path) = config.log_file {
        // File output: always disable ANSI color codes in log files.
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|e| panic!("cannot open log file '{}': {}", path, e));
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(false)
            .with_writer(file)
            .init();
    } else {
        // Console output: ANSI color codes are not rendered correctly on
        // Windows consoles that lack Virtual Terminal Processing support, so
        // disable them there.  Also disable when stderr is not a terminal
        // (e.g. output is piped or redirected).
        let use_ansi = std::io::stderr().is_terminal() && !cfg!(windows);
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_ansi(use_ansi)
            .init();
    }

    // ── Default CF domain list (--default-domains) ────────────────────────
    // Fetch the obfuscated domain list from GitHub, deobfuscate it, and
    // append the resulting domains to any that were supplied with --cf-domain.
    // Done once here so both --check mode and the normal server path share
    // the same fetched list.
    if config.default_domains {
        info!("Fetching default CF proxy domain list from GitHub…");
        let fetched =
            default_domains::fetch_default_domains_with_outbound(runtime.outbound()).await;
        info!("  Got {} default CF domain(s)", fetched.len());
        config.cf_domains.extend(fetched);
    }

    // ── Connectivity check mode (--check) ────────────────────────────────
    // Run probes for every configured CF domain and MTProto proxy, print the
    // results, then exit.  This lets the user verify their configuration
    // before starting the proxy server.
    if config.check {
        let all_ok = check::run_check_with_outbound(&config, runtime.outbound()).await;
        std::process::exit(if all_ok { 0 } else { 1 });
    }

    // ── Update check ──────────────────────────────────────────────────────
    // Always runs, in the background, so a slow/blocked GitHub API call
    // never delays accepting connections. Failures (no network, rate
    // limited, unparsable response) are logged at debug level only and
    // never affect startup — this is purely informational. Results are
    // cached to disk for an hour (see update_check.rs) so frequent restarts
    // don't hammer the GitHub API.

    let runtime_for_update = Arc::clone(&runtime);
    tokio::spawn(async move {
        match update_check::check_for_update(runtime_for_update.outbound()).await {
            update_check::UpdateCheck::UpdateAvailable {
                current,
                latest,
                html_url,
            } => {
                let link = html_url
                    .unwrap_or_else(|| format!("{}/releases/latest", env!("CARGO_PKG_REPOSITORY")));
                info!(
                    "  A newer version is available: v{} (running v{}). See {}",
                    latest, current, link
                );
            }
            update_check::UpdateCheck::AheadOfRelease { current, latest } => {
                debug!(
                    "Running v{}, ahead of the latest tagged release (v{})",
                    current, latest
                );
            }
            update_check::UpdateCheck::UpToDate => {
                info!(
                    "Running the latest released version (v{})",
                    env!("CARGO_PKG_VERSION")
                );
            }
            update_check::UpdateCheck::Failed(e) => {
                // Never surfaced above debug: this must not look like a
                // real problem (no network, GitHub rate limit, etc. are
                // all expected and harmless here).
                debug!("Update check skipped: {}", e);
            }
        }
    });

    // ── Bind the server socket ────────────────────────────────────────────
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("invalid listen address");

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {}", addr, e));

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
        config.port,
        config.link_secret()
    );

    info!("{}", "=".repeat(60));
    info!("  Telegram MTProto WS Bridge Proxy  (tg-ws-proxy-rs)");
    info!("  Listening on   {}:{}", config.host, config.port);
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

    if config.proxy_protocol {
        info!("  ℹ  PROXY protocol v1 expected on every inbound connection");
    }

    match config.ws_keepalive_interval() {
        Some(d) => info!("  WS keepalive:  every {:.0}s", d.as_secs_f64()),
        None => info!("  WS keepalive:  disabled"),
    }

    if !config.cf_domains.is_empty() {
        info!("  Cloudflare proxy domain(s):");
        for d in &config.cf_domains {
            info!("    {} (kws{{N}}.{} subdomains)", d, d);
        }
        if config.cf_priority {
            info!("    ⚡ CF priority mode: CF proxy is tried BEFORE direct WS");
        }
        if config.cf_balance && config.cf_domains.len() > 1 {
            info!("    ⚖  CF balance mode: connections are round-robin'd across domains");
        }
    }

    let cf_worker_domains = config.cf_worker_domains();
    if !cf_worker_domains.is_empty() {
        info!("  Cloudflare Worker domain(s):");
        for domain in &cf_worker_domains {
            info!("    {}", domain);
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
                link_host, config.port, link_secret
            );
        }
    }

    if link_host != config.host {
        info!(
            "  ℹ  Link uses auto-detected IP {}. \
             Use --link-ip <IP> to override.",
            link_host
        );
    } else if matches!(config.host.as_str(), "127.0.0.1" | "::1") {
        warn!(
            "  ⚠  Link shows {} — only the local machine can use this link. \
             Run with --host 0.0.0.0 (or --link-ip <router-LAN-IP>) \
             so other devices on the network can connect.",
            config.host
        );
    }
    info!("{}", "=".repeat(60));

    // ── Connection pool warm-up ───────────────────────────────────────────
    let pool = Arc::new(WsPool::with_runtime(
        config.pool_size,
        Duration::from_secs(config.pool_max_age),
        Arc::clone(&runtime),
    ));
    {
        let pool_clone = pool.clone();
        let config_clone = config.clone();
        tokio::spawn(async move {
            pool_clone.warmup(&config_clone).await;
        });
    }

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
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("semaphore closed unexpectedly");

        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let cfg = config.clone();
                let pool = pool.clone();
                let runtime = Arc::clone(&runtime);
                tokio::spawn(async move {
                    // Hold the permit for the lifetime of this connection so
                    // it is released (and the slot freed) when the task ends.
                    let _permit = permit;
                    proxy::handle_client_with_runtime(stream, peer_addr, cfg, pool, runtime).await;
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
