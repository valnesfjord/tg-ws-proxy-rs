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
use tracing::{error, info};

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
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let cfg = config.clone();
                let pool = pool.clone();
                tokio::spawn(async move {
                    proxy::handle_client(stream, peer_addr, cfg, pool).await;
                });
            }
            Err(e) => {
                error!("accept error: {}", e);
                // Brief pause to avoid a tight error loop on transient issues.
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
