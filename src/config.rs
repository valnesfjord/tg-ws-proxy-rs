//! Configuration for tg-ws-proxy-rs.
//!
//! Settings are read from CLI arguments.  Every flag also has a corresponding
//! environment-variable fallback (e.g. `--port` → `TG_PORT`).
//! That makes Docker / systemd deployments trivial without a config file.

use std::collections::HashMap;
use std::net::UdpSocket;

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

// ─── Upstream MTProto proxy config ───────────────────────────────────────────

/// An upstream MTProto proxy to fall back to when the WebSocket path fails.
#[derive(Clone, Debug)]
pub struct MtProtoProxy {
    pub host: String,
    pub port: u16,
    /// Hex-encoded proxy secret as it appears in the `tg://proxy` link.
    /// May be 32 hex chars (16 bytes, plain secret), or 34 hex chars (17 bytes)
    /// with a 1-byte mode-indicator prefix: `dd` = padded intermediate,
    /// `ee` = FakeTLS.  The prefix byte is stripped before key derivation —
    /// only the trailing 16 bytes are used as the actual cryptographic key.
    pub secret: String,
}

/// Parse a `HOST:PORT:SECRET` triplet.
/// Splitting from the right handles IPv4/domain hosts; the two right-most
/// colons delimit port and secret.
/// Note: IPv6 addresses in bracket notation (e.g. `[::1]:443:secret`) are
/// not supported — use a hostname or IPv4 address instead.
fn parse_mtproto_proxy(s: &str) -> Result<MtProtoProxy, String> {
    // rsplitn(3, ':') yields at most 3 parts, right-to-left: [secret, port, host]
    let parts: Vec<&str> = s.rsplitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!("expected HOST:PORT:SECRET, got {:?}", s));
    }
    let secret = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| format!("invalid port {:?}", parts[1]))?;
    let host = parts[2].to_string();

    hex::decode(&secret).map_err(|_| format!("invalid hex secret {:?}", secret))?;

    Ok(MtProtoProxy { host, port, secret })
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

    /// Accept inbound Telegram clients using `ee` FakeTLS camouflage with this
    /// SNI hostname. The generated proxy link will use `secret=ee<key><hosthex>`.
    #[arg(long = "listen-faketls-domain", env = "TG_LISTEN_FAKETLS_DOMAIN")]
    pub listen_faketls_domain: Option<String>,

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
    /// When omitted, a safe value is computed automatically from the process's
    /// soft file-descriptor limit (ulimit -n):
    ///   max_connections = (fd_limit - reserved_fds) / 2
    /// where reserved_fds covers the pool, the listener socket, and runtime
    /// overhead.  Set this explicitly only if you need to override the
    /// auto-computed limit.
    #[arg(long = "max-connections", env = "TG_MAX_CONNECTIONS")]
    pub max_connections: Option<usize>,

    /// Enable verbose (DEBUG) logging.
    #[arg(short, long, env = "TG_VERBOSE")]
    pub verbose: bool,

    /// Skip TLS certificate verification when connecting to Telegram.
    /// Matches the Python reference implementation behaviour.
    /// **Do not use on untrusted networks unless you understand the risks.**
    #[arg(long = "danger-accept-invalid-certs", env = "TG_SKIP_TLS_VERIFY")]
    pub skip_tls_verify: bool,

    /// Suppress all log output (useful on routers / embedded devices).
    /// Overrides `--verbose` when both are set.
    #[arg(short = 'q', long, env = "TG_QUIET")]
    pub quiet: bool,

    /// Write log output to this file instead of stderr.
    /// Log lines written to a file never contain ANSI color codes.
    #[arg(long = "log-file", value_name = "PATH", env = "TG_LOG_FILE")]
    pub log_file: Option<String>,

    /// Upstream MTProto proxy to try when the WebSocket path fails.
    /// Format: `HOST:PORT:SECRET` (32 hex chars).  Can be specified multiple times.
    /// Multiple proxies are tried in order until one succeeds.
    /// Via env: comma-separated list, e.g. `host1:443:sec1,host2:8888:sec2`.
    #[arg(
        long = "mtproto-proxy",
        value_name = "HOST:PORT:SECRET",
        value_parser = parse_mtproto_proxy,
        value_delimiter = ',',
        env = "TG_MTPROTO_PROXY"
    )]
    pub mtproto_proxies: Vec<MtProtoProxy>,

    /// IP address to advertise in the generated `tg://proxy` link.
    /// Useful when the proxy listens on `0.0.0.0` or `127.0.0.1` but clients
    /// need to connect via a specific LAN or public IP.
    /// When omitted, the proxy attempts to auto-detect a non-loopback local IP;
    /// if that fails it falls back to `--host`.
    #[arg(long = "link-ip", env = "TG_LINK_IP")]
    pub link_ip: Option<String>,

    /// Cloudflare-proxied domain(s) for alternative WebSocket routing.
    ///
    /// When set, the proxy will attempt to connect to Telegram DCs through
    /// Cloudflare's CDN using `kws{N}.{cf-domain}` subdomains.  This can
    /// bypass ISP-level blocks on Telegram's IP ranges (common in Russia).
    ///
    /// Setup: add `kws1`–`kws5` A records in your Cloudflare DNS pointing to
    /// the respective Telegram DC IPs, enable the orange-cloud proxy, and set
    /// SSL/TLS mode to **Flexible**.  See docs/CfProxy.md for full instructions.
    ///
    /// Multiple domains can be specified as a comma-separated list.  They are
    /// tried in the order given (first domain has highest priority).
    ///
    /// The CF proxy is tried as a fallback after direct WebSocket connections
    /// fail, and as the primary path when no `--dc-ip` is configured for a DC.
    #[arg(long = "cf-domain", value_name = "DOMAIN", value_delimiter = ',', env = "TG_CF_DOMAIN")]
    pub cf_domains: Vec<String>,

    /// Prioritise Cloudflare proxy over direct WebSocket connections for all
    /// DCs (even those with `--dc-ip` configured).
    ///
    /// When set, the proxy tries the CF path first; if it fails, falls back to
    /// the normal WS path, then upstream MTProto proxies, then direct TCP.
    #[arg(long = "cf-priority", env = "TG_CF_PRIORITY")]
    pub cf_priority: bool,

    /// Evenly distribute connections across multiple Cloudflare proxy domains.
    ///
    /// When set and multiple `--cf-domain` values are given, each new
    /// connection starts from a different CF domain in round-robin order
    /// instead of always trying the first domain first.  The remaining domains
    /// are still tried in order as fallbacks if the primary one fails.
    ///
    /// Has no effect when only one CF domain is configured.
    #[arg(long = "cf-balance", env = "TG_CF_BALANCE")]
    pub cf_balance: bool,

    // ── Timeout / cooldown knobs ─────────────────────────────────────────

    /// WebSocket connection timeout in seconds (normal path).
    #[arg(long = "ws-connect-timeout", default_value = "10", env = "TG_WS_CONNECT_TIMEOUT")]
    pub ws_connect_timeout: u64,

    /// WebSocket connection timeout in seconds when the DC is in failure
    /// cooldown (fast-probe path, allows quick recovery after a network change).
    #[arg(long = "ws-fail-probe-timeout", default_value = "2", env = "TG_WS_FAIL_PROBE_TIMEOUT")]
    pub ws_fail_probe_timeout: u64,

    /// Seconds to back off from a DC's WebSocket after a connection failure.
    #[arg(long = "ws-fail-cooldown", default_value = "30", env = "TG_WS_FAIL_COOLDOWN")]
    pub ws_fail_cooldown: u64,

    /// Seconds to back off from a DC's WebSocket after all domains returned
    /// a redirect (WS blacklisted by Telegram).
    #[arg(long = "ws-redirect-cooldown", default_value = "300", env = "TG_WS_REDIRECT_COOLDOWN")]
    pub ws_redirect_cooldown: u64,

    /// Client MTProto handshake read timeout in seconds.
    #[arg(long = "handshake-timeout", default_value = "10", env = "TG_HANDSHAKE_TIMEOUT")]
    pub handshake_timeout: u64,

    /// TCP fallback connect timeout in seconds.
    #[arg(long = "tcp-fallback-timeout", default_value = "10", env = "TG_TCP_FALLBACK_TIMEOUT")]
    pub tcp_fallback_timeout: u64,

    /// Connect timeout in seconds for upstream MTProto proxies.
    #[arg(long = "upstream-connect-timeout", default_value = "5", env = "TG_UPSTREAM_CONNECT_TIMEOUT")]
    pub upstream_connect_timeout: u64,

    /// Seconds to back off from an upstream MTProto proxy after a failure.
    #[arg(long = "upstream-fail-cooldown", default_value = "60", env = "TG_UPSTREAM_FAIL_COOLDOWN")]
    pub upstream_fail_cooldown: u64,

    /// Connect timeout in seconds for the Cloudflare proxy path.
    #[arg(long = "cf-connect-timeout", default_value = "10", env = "TG_CF_CONNECT_TIMEOUT")]
    pub cf_connect_timeout: u64,

    /// Seconds to back off from the Cloudflare proxy path after a failure.
    #[arg(long = "cf-fail-cooldown", default_value = "60", env = "TG_CF_FAIL_COOLDOWN")]
    pub cf_fail_cooldown: u64,

    /// Maximum age of a pooled WebSocket connection in seconds.
    /// Connections older than this are discarded and re-established.
    #[arg(long = "pool-max-age", default_value = "55", env = "TG_POOL_MAX_AGE")]
    pub pool_max_age: u64,

    /// Test configured Cloudflare proxy domains and upstream MTProto proxies
    /// for suitability, then exit.
    ///
    /// For each CF domain, a WebSocket connection is attempted through
    /// `kws2.{domain}` (DC 2, non-media); the result is printed as OK/FAIL
    /// with the round-trip latency.
    ///
    /// For each MTProto proxy, a TCP connection is made and the MTProto
    /// obfuscation handshake is sent.  FakeTLS (0xee) proxies are also asked
    /// to complete their TLS handshake so the check verifies end-to-end
    /// protocol negotiation.
    ///
    /// Exits with status code 0 when all configured items pass, 1 otherwise.
    #[arg(long = "check", env = "TG_CHECK")]
    pub check: bool,

    /// Use the default Cloudflare-proxy domain list from the upstream repository.
    ///
    /// When set, the proxy fetches an obfuscated list of working CF proxy
    /// domains from GitHub at startup, deobfuscates them, and uses them as
    /// `--cf-domain` entries.  This lets users get started without having to
    /// configure their own Cloudflare DNS zone.
    ///
    /// The fetched domains are appended after any domains supplied with
    /// `--cf-domain`.  If the fetch fails the proxy falls back to a small
    /// built-in list.
    ///
    /// Source:
    ///   https://github.com/Flowseal/tg-ws-proxy/blob/main/.github/cfproxy-domains.txt
    #[arg(long = "default-domains", env = "TG_DEFAULT_DOMAINS")]
    pub default_domains: bool,
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

        // If no --dc-ip was given, use the built-in defaults — unless a CF
        // domain is configured or --default-domains was requested (in which
        // case CF proxy becomes the primary path for all DCs without explicit
        // IPs, and the default dc_ip list would be misleading).
        if cfg.dc_ip.is_empty() && cfg.cf_domains.is_empty() && !cfg.default_domains {
            cfg.dc_ip = vec![
                (2, "149.154.167.220".to_string()),
                (4, "149.154.167.220".to_string()),
            ];
        }

        cfg
    }

    /// The proxy secret as raw bytes (decoded from hex).
    pub fn secret_bytes(&self) -> Vec<u8> {
        let raw = hex::decode(self.secret.as_deref().unwrap_or("")).expect("secret must be valid hex");
        if raw.len() >= 17 && matches!(raw[0], 0xdd | 0xee) {
            raw[1..17].to_vec()
        } else {
            raw
        }
    }

    /// Inbound FakeTLS domain, either from `--listen-faketls-domain` or from
    /// an `ee<key><domainhex>` secret.
    pub fn listen_faketls_domain(&self) -> Option<String> {
        if let Some(domain) = &self.listen_faketls_domain {
            return Some(domain.clone());
        }

        let raw = hex::decode(self.secret.as_deref().unwrap_or("")).ok()?;
        if raw.len() > 17 && raw[0] == 0xee {
            return std::str::from_utf8(&raw[17..]).ok().map(ToOwned::to_owned);
        }

        None
    }

    /// Full secret value for the generated Telegram link.
    pub fn link_secret(&self) -> String {
        let secret = self.secret.as_deref().unwrap_or("");
        if let Some(domain) = self.listen_faketls_domain() {
            let raw = hex::decode(secret).expect("secret must be valid hex");
            let key = if raw.len() >= 17 && matches!(raw[0], 0xdd | 0xee) {
                &raw[1..17]
            } else {
                &raw[..]
            };
            return format!("ee{}{}", hex::encode(key), hex::encode(domain.as_bytes()));
        }

        if secret.starts_with("dd") || secret.starts_with("ee") {
            secret.to_string()
        } else {
            format!("dd{}", secret)
        }
    }

    /// Map of DC ID → target IP from `--dc-ip` flags.
    pub fn dc_redirects(&self) -> HashMap<u32, String> {
        self.dc_ip.iter().cloned().collect()
    }

    /// The hostname/IP to advertise in the generated `tg://proxy` link.
    ///
    /// Resolution order:
    /// 1. `--link-ip` if explicitly set.
    /// 2. Auto-detected first non-loopback IPv4 address when `--host` is a
    ///    wildcard (`0.0.0.0`) or loopback (`127.0.0.1` / `::1`).
    /// 3. `--host` verbatim as the final fallback.
    pub fn link_host(&self) -> String {
        if let Some(ref ip) = self.link_ip {
            return ip.clone();
        }

        // Auto-detect when the bind address is not directly reachable by
        // remote clients (wildcard or loopback).
        let bind_is_local = matches!(self.host.as_str(), "0.0.0.0" | "::" | "127.0.0.1" | "::1");
        if bind_is_local {
            if let Some(lan_ip) = detect_lan_ip() {
                return lan_ip;
            }
        }

        self.host.clone()
    }

    /// Socket buffer size in bytes.
    #[allow(dead_code)]
    pub fn buf_bytes(&self) -> usize {
        self.buf_kb * 1024
    }
}

// ─── LAN IP auto-detection ────────────────────────────────────────────────────

/// Return the first non-loopback, non-link-local IPv4 address found on the
/// system's network interfaces.  Used to generate a usable `tg://` proxy link
/// when the proxy is bound to a wildcard or loopback address.
///
/// Works by opening a UDP socket and "connecting" it to a public IP (no
/// packet is actually sent); the OS routing table then fills in the local
/// source address.
fn detect_lan_ip() -> Option<String> {
    // 8.8.8.8:80 is Google's public DNS. No packet is actually sent — we just
    // need any well-known routable address so the kernel can select the right
    // source interface for us via the routing table.
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;

    let local_addr = socket.local_addr().ok()?;
    let ip = local_addr.ip();

    // Only return a usable unicast IPv4 address.
    if let std::net::IpAddr::V4(v4) = ip {
        if !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified() {
            return Some(v4.to_string());
        }
    }

    None
}
