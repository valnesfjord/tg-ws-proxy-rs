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
//! See [`tg_ws_proxy_rs::proxy`] for the connection handling logic and
//! [`tg_ws_proxy_rs::crypto`] for the MTProto obfuscation details.

use std::io::IsTerminal as _;

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::server::{self, RunError};

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls ring CryptoProvider");

    let config = Config::from_args();
    init_logging(&config);

    match server::run(config, std::future::pending()).await {
        Ok(()) => {}
        Err(RunError::CheckFailed) => std::process::exit(1),
        Err(RunError::InvalidOutbound(e)) => {
            eprintln!("invalid outbound proxy config: {e}");
            std::process::exit(2);
        }
        Err(e) => panic!("{e}"),
    }
}

fn init_logging(config: &Config) {
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
}
