//! Configuration for tg-ws-proxy-rs.
//!
//! Settings are read from CLI arguments.  Every flag also has a corresponding
//! environment-variable fallback (e.g. `--port` → `TG_PORT`).
//! That makes Docker / systemd deployments trivial without a config file.

use std::collections::HashMap;

use clap::Parser;

// ─── Telegram DC default IPs ─────────────────────────────────────────────────
// These are the "fallback" addresses used when a DC is not listed in
// `--dc-ip` or when WebSocket routing fails and we must fall back to TCP.
pub fn default_dc_ips() -> HashMap<u32, String> {
    [
        (1, "149.154.175.50"),
        (2, "149.154.167.51"),
        (3, "149.154.175.100"),
        (4, "149.154.167.91"),
        (5, "149.154.171.5"),
        (203, "91.105.192.100"),
    ]
    .iter()
    .map(|(k, v)| (*k, v.to_string()))
    .collect()
}

// DC numbers that are remapped to another DC for WebSocket domain selection.
// DC 203 (the "test" DC) is treated as DC 2 for websocket connections.
pub fn default_dc_overrides() -> HashMap<u32, u32> {
    [(203, 2)].iter().copied().collect()
}

// ─── CLI / env-var configuration ─────────────────────────────────────────────

/// Parse a `DC:IP` pair such as `2:149.154.167.220`.
fn parse_dc_ip(s: &str) -> Result<(u32, String), String> {
    let (dc_s, ip_s) = s
        .split_once(':')
        .ok_or_else(|| format!("expected DC:IP, got {s:?}"))?;
    let dc: u32 = dc_s
        .parse()
        .map_err(|_| format!("invalid DC number {dc_s:?}"))?;
    // Validate the IP address string.
    let _: std::net::IpAddr = ip_s
        .parse()
        .map_err(|_| format!("invalid IP address {ip_s:?}"))?;
    Ok((dc, ip_s.to_string()))
}

#[derive(Parser, Clone, Debug)]
#[command(
    name = "tg-ws-proxy",
    about = "Telegram MTProto WebSocket Bridge Proxy",
    long_about = "Local MTProto proxy that tunnels Telegram Desktop traffic \
                  through WebSocket connections to Telegram DCs.\n\
                  Useful on networks where raw TCP to Telegram is blocked."
)]
pub struct Config {
    /// Port to listen on.
    #[arg(long, default_value = "1443", env = "TG_PORT")]
    pub port: u16,

    /// Host / IP address to bind.
    #[arg(long, default_value = "127.0.0.1", env = "TG_HOST")]
    pub host: String,

    /// MTProto proxy secret (32 hex chars).
    /// A random secret is generated if not provided.
    #[arg(long, env = "TG_SECRET")]
    pub secret: Option<String>,

    /// Target IP for a DC, e.g. `--dc-ip 2:149.154.167.220`.
    /// Can be specified multiple times.
    /// Default: DC 2 and DC 4 → 149.154.167.220
    #[arg(long = "dc-ip", value_name = "DC:IP", value_parser = parse_dc_ip)]
    pub dc_ip: Vec<(u32, String)>,

    /// Socket send/recv buffer size in KiB.
    #[arg(long = "buf-kb", default_value = "256", env = "TG_BUF_KB")]
    pub buf_kb: usize,

    /// Number of pre-warmed WebSocket connections per DC.
    #[arg(long = "pool-size", default_value = "4", env = "TG_POOL_SIZE")]
    pub pool_size: usize,

    /// Maximum number of concurrent client connections.
    /// Limits file-descriptor consumption and prevents EMFILE errors under load.
    #[arg(long = "max-connections", default_value = "200", env = "TG_MAX_CONNECTIONS")]
    pub max_connections: usize,

    /// Enable verbose (DEBUG) logging.
    #[arg(short, long, env = "TG_VERBOSE")]
    pub verbose: bool,

    /// Skip TLS certificate verification when connecting to Telegram.
    /// Matches the Python reference implementation behaviour.
    /// **Do not use on untrusted networks unless you understand the risks.**
    #[arg(long = "danger-accept-invalid-certs", env = "TG_SKIP_TLS_VERIFY")]
    pub skip_tls_verify: bool,
}

impl Config {
    /// Parse configuration from CLI arguments.
    pub fn from_args() -> Self {
        let mut cfg = Self::parse();

        // Fill in a random secret if none was supplied.
        if cfg.secret.is_none() {
            let bytes: [u8; 16] = rand::random();
            cfg.secret = Some(hex::encode(bytes));
        }

        // If no --dc-ip was given, use the built-in defaults.
        if cfg.dc_ip.is_empty() {
            cfg.dc_ip = vec![
                (2, "149.154.167.220".to_string()),
                (4, "149.154.167.220".to_string()),
            ];
        }

        cfg
    }

    /// The proxy secret as raw bytes (decoded from hex).
    pub fn secret_bytes(&self) -> Vec<u8> {
        hex::decode(self.secret.as_deref().unwrap_or("")).expect("secret must be valid hex")
    }

    /// Map of DC ID → target IP from `--dc-ip` flags.
    pub fn dc_redirects(&self) -> HashMap<u32, String> {
        self.dc_ip.iter().cloned().collect()
    }

    /// Socket buffer size in bytes.
    #[allow(dead_code)]
    pub fn buf_bytes(&self) -> usize {
        self.buf_kb * 1024
    }
}
