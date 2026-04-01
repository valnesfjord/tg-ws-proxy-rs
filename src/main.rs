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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

mod config;
mod crypto;
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
    let log_level = if config.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_level.into()),
        )
        .init();

    // ── Bind the server socket ────────────────────────────────────────────
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .expect("invalid listen address");

    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("cannot bind {}: {}", addr, e));

    // ── Print startup banner ──────────────────────────────────────────────
    let secret = config.secret.as_deref().unwrap_or("");
    let dc_redirects = config.dc_redirects();

    let link_host = &config.host;
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
    info!("  Max connections: {}", config.max_connections);
    info!("{}", "=".repeat(60));
    info!("  Telegram proxy link:");
    info!("    {}", tg_link);
    info!("{}", "=".repeat(60));

    // ── Connection pool warm-up ───────────────────────────────────────────
    let pool = Arc::new(WsPool::new(config.pool_size));
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
    let semaphore = Arc::new(Semaphore::new(config.max_connections));
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
