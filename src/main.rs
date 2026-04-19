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
use tracing::{error, info, warn};

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
                if line.starts_with("Max open files") {
                    if let Some(soft_str) = line.split_whitespace().nth(3) {
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

mod check;
mod config;
mod crypto;
mod faketls;
mod pool;
mod proxy;
mod splitter;
mod ws_client;

use config::Config;
use pool::WsPool;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    let config = Config::from_args();

    // ── Logging ──────────────────────────────────────────────────────────
    let log_level = if config.quiet {
        "off"
    } else if config.verbose {
        "debug"
    } else {
        "info"
    };

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| log_level.into());

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

    // ── Connectivity check mode (--check) ────────────────────────────────
    // Run probes for every configured CF domain and MTProto proxy, print the
    // results, then exit.  This lets the user verify their configuration
    // before starting the proxy server.
    if config.check {
        let all_ok = check::run_check(&config).await;
        std::process::exit(if all_ok { 0 } else { 1 });
    }

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
    let secret = config.secret.as_deref().unwrap_or("");

    let link_host = config.link_host();
    let tg_link = format!(
        "tg://proxy?server={}&port={}&secret=dd{}",
        link_host, config.port, secret
    );

    info!("{}", "=".repeat(60));
    info!("  Telegram MTProto WS Bridge Proxy  (tg-ws-proxy-rs)");
    info!("  Listening on   {}:{}", config.host, config.port);
    info!("  Secret:        {}", secret);
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
        if config.cf_priority {
            info!("    ⚡ CF priority mode: CF proxy is tried BEFORE direct WS");
        }
    }

    if !config.mtproto_proxies.is_empty() {
        info!("  Upstream MTProto proxies (WS fallback):");
        for p in &config.mtproto_proxies {
            info!("    {}:{}", p.host, p.port);
        }
    }

    info!(
        "  Max connections: {} (fd-limit: {})",
        max_connections, fd_limit
    );
    info!("{}", "=".repeat(60));
    info!("  Telegram proxy link (use this on all devices):");
    info!("    {}", tg_link);

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
    let pool = Arc::new(WsPool::new(
        config.pool_size,
        Duration::from_secs(config.pool_max_age),
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
                tokio::spawn(async move {
                    // Hold the permit for the lifetime of this connection so
                    // it is released (and the slot freed) when the task ends.
                    let _permit = permit;
                    proxy::handle_client(stream, peer_addr, cfg, pool).await;
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
