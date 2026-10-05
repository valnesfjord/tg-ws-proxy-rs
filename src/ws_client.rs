//! WebSocket client for Telegram DC connections.
//!
//! Telegram exposes WebSocket endpoints at `wss://kwsN.web.telegram.org/apiws`
//! (where N is the DC id).  The proxy connects TCP to the configured **IP**
//! while using the **domain** as the TLS SNI / HTTP Host, matching the Python
//! reference implementation.
//!
//! DC numbers that don't have dedicated WebSocket hostnames (e.g. DC 203, the
//! test DC) are remapped to their canonical counterpart via
//! `config::websocket_dc()` before the domain is constructed, so the TLS
//! certificate presented by Telegram's servers remains valid.
//!
//! TLS certificate verification is controlled by `Config::skip_tls_verify`.
//! When disabled (default), verification uses the bundled WebPKI root store.
//! When enabled (via `--danger-accept-invalid-certs`), a no-op verifier is
//! used — matching the Python reference implementation which always passes
//! `verify_mode = CERT_NONE`.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::websocket_dc;
use crate::outbound::OutboundConnector;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    client_async_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue},
};
use tracing::{debug, warn};
use tungstenite::Error as WsError;
use tungstenite::Message;
use tungstenite::protocol::WebSocketConfig;

/// A live WebSocket connection to a Telegram DC.
pub type TgWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Suffix that marks a media DC in log lines (`DC2` vs `DC2m`).
///
/// Every DC is logged together with its media flag, so this keeps the format
/// arguments readable at the ~30 call sites across the proxy.
pub(crate) fn media_tag(is_media: bool) -> &'static str {
    if is_media { "m" } else { "" }
}

// ─── Preferred Cloudflare edge IPs (--cf-ip) ─────────────────────────────────

/// Round-robin counter for `--cf-ip`, shared by every dial site so the load
/// spreads across the preferred edges instead of hammering the first one.
static CF_IP_ROTATION: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct CooldownMap<K> {
    entries: StdMutex<Option<HashMap<K, Instant>>>,
}

impl<K: Eq + Hash> CooldownMap<K> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: StdMutex::new(None),
        }
    }

    pub(crate) fn set(&self, key: K, cooldown: Duration) {
        self.entries
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(key, Instant::now() + cooldown);
    }

    pub(crate) fn clear<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(entries) = self.entries.lock().unwrap().as_mut() {
            entries.remove(key);
        }
    }

    pub(crate) fn active<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock().unwrap();
        match entries.as_ref().and_then(|entries| entries.get(key)) {
            Some(&until) => Instant::now() < until,
            None => false,
        }
    }
}

static CF_EDGE_TLS_FAIL: CooldownMap<IpAddr> = CooldownMap::new();
static CF_EDGE_PLAINTEXT_FAIL: CooldownMap<IpAddr> = CooldownMap::new();

/// Cloudflare-specific dial settings shared by proxy, Worker, and pool paths.
#[derive(Clone, Copy)]
pub struct CfDialOpts<'a> {
    pub cf_ips: &'a [IpAddr],
    pub disable_tls: bool,
    pub fail_cooldown: Duration,
}

impl CfDialOpts<'_> {
    const DEFAULT: Self = Self {
        cf_ips: &[],
        disable_tls: false,
        fail_cooldown: Duration::ZERO,
    };
}

/// Starting index for one logical Cloudflare connection. Every configured IP
/// is still tried before failure; rotating only spreads which one gets first
/// chance.
fn cf_ip_start(ips: &[IpAddr]) -> usize {
    if ips.len() <= 1 {
        return 0;
    }
    CF_IP_ROTATION.fetch_add(1, AtomicOrdering::Relaxed) % ips.len()
}

fn cf_ip_attempts<F>(
    ips: &[IpAddr],
    first: usize,
    cooldowns: &CooldownMap<IpAddr>,
    uses_cooldown: F,
) -> Vec<IpAddr>
where
    F: Fn(IpAddr) -> bool,
{
    let entries = cooldowns.entries.lock().unwrap();
    let now = Instant::now();
    let is_cooling = |ip: &IpAddr| {
        uses_cooldown(*ip)
            && entries
                .as_ref()
                .and_then(|entries| entries.get(ip))
                .is_some_and(|&until| now < until)
    };
    let all_cooling = ips.iter().all(is_cooling);
    let limit = if all_cooling { 1 } else { ips.len() };
    (0..ips.len())
        .map(move |offset| ips[(first + offset) % ips.len()])
        .filter(|ip| all_cooling || !is_cooling(ip))
        .take(limit)
        .collect()
}

/// WebSocket domains for a given DC.
///
/// Telegram provides two hostnames per DC; trying both increases resilience.
/// Media DCs prefer the `kwsN-1` variant first.
///
/// Non-standard DC numbers (e.g. DC 203, the test/alternate DC) are remapped
/// to their canonical WebSocket DC via `config::websocket_dc()` so that TLS
/// certificate validation succeeds — Telegram's wildcard cert only covers the
/// real DC numbers (1-5).
pub fn ws_domains(dc: u32, is_media: bool) -> Vec<String> {
    let effective_dc = websocket_dc(dc);

    ordered_records(
        format!("kws{}.web.telegram.org", effective_dc),
        format!("kws{}-1.web.telegram.org", effective_dc),
        is_media,
    )
}

/// Order a `kws{N}` / `kws{N}-1` record pair by preference: media DCs prefer
/// the `-1` variant, everything else prefers the base record.
fn ordered_records(base: String, dash_one: String, is_media: bool) -> Vec<String> {
    if is_media {
        vec![dash_one, base]
    } else {
        vec![base, dash_one]
    }
}

/// Outcome of a WebSocket connection attempt.
#[derive(Debug)]
// Keep the successful stream unboxed to preserve the public API.
#[allow(clippy::large_enum_variant)]
pub enum WsConnectResult {
    /// Successful WebSocket upgrade.
    Connected(TgWsStream),
    /// The server returned a redirect (301/302/303/307/308).
    /// Telegram sometimes does this when WS is unavailable — the caller
    /// should fall back to direct TCP.
    Redirect(u16),
    /// Any other non-101 status code or transport error.
    Failed(String),
    /// The TCP connect ran out the clock: nothing at `ip:443` answered.
    ///
    /// Distinct from [`Self::TimedOut`] because the two call for opposite
    /// responses. Nothing answered here, so the address is treated as blocked
    /// and skipped — swapping the SNI cannot conjure up a route to it.
    ConnectTimedOut(String),
    /// The TLS handshake or WebSocket upgrade ran out the clock.
    ///
    /// The address *did* answer and then the handshake stalled, which is what
    /// SNI-based DPI looks like — so this is the one that triggers domain
    /// fronting.
    TimedOut,
}

/// The outcome of walking one DC's WebSocket hostnames.
///
/// The three flags are what the routing ladder backs off on, and they are
/// deliberately not collapsed into one "it failed" bit: each points at a
/// different fallback (fronting, skipping the address, plain TCP).
pub struct WsAttempt {
    pub ws: Option<TgWsStream>,
    /// Every hostname answered with a redirect — Telegram has taken the
    /// WebSocket path away for this DC rather than the network blocking it.
    pub all_redirects: bool,
    /// A TLS/upgrade handshake stalled: the address answers, the handshake
    /// does not finish.  The SNI-blocking signature that domain fronting is
    /// for.
    pub upgrade_timed_out: bool,
    /// A TCP connect stalled: nothing at the address answered at all.
    pub connect_timed_out: bool,
}

impl WsAttempt {
    fn connected(ws: TgWsStream) -> Self {
        Self {
            ws: Some(ws),
            all_redirects: false,
            upgrade_timed_out: false,
            connect_timed_out: false,
        }
    }
}

/// Try to establish a WebSocket connection to one Telegram DC domain.
///
/// Connects TCP to `ip:443`, performs TLS with `domain` as SNI, then does
/// the WebSocket upgrade to `wss://{domain}/apiws`.
pub async fn connect_ws(
    ip: &str,
    domain: &str,
    skip_tls_verify: bool,
    timeout: Duration,
) -> WsConnectResult {
    connect_ws_with_outbound(
        ip,
        domain,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
        None,
    )
    .await
}

/// Same as [`connect_ws`], but routes the TCP connection through the supplied
/// outbound connector.
///
/// `sni_override`, when set, presents that hostname as the TLS SNI instead of
/// `domain` while still using `domain` as the HTTP `Host` — see
/// [`connect_ws_with_path`] for why and how.
pub async fn connect_ws_with_outbound(
    ip: &str,
    domain: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    sni_override: Option<&str>,
) -> WsConnectResult {
    connect_ws_with_outbound_mode(
        ip,
        domain,
        skip_tls_verify,
        timeout,
        outbound,
        sni_override,
        false,
    )
    .await
}

/// Same as [`connect_ws_with_outbound`], optionally using plaintext `ws://` on
/// port 80. Only Cloudflare tiers should pass `disable_tls = true`; Telegram's
/// direct WebSocket endpoint requires TLS.
pub async fn connect_ws_with_outbound_mode(
    ip: &str,
    domain: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    sni_override: Option<&str>,
    disable_tls: bool,
) -> WsConnectResult {
    connect_ws_with_path(
        ip,
        domain,
        "/apiws",
        true,
        skip_tls_verify,
        timeout,
        outbound,
        sni_override,
        disable_tls,
    )
    .await
}

/// Connect to the DC endpoint and perform the WebSocket upgrade to
/// `{ws|wss}://{domain}{path}`.
///
/// Normally the TLS SNI is `domain` (matching the `Host` header). When
/// `sni_override` is set, the TLS handshake instead presents that unrelated
/// hostname as SNI — domain fronting — while the HTTP request still targets
/// `domain` as `Host`. DPI that filters by SNI sees the fronted name; the
/// actual (TLS-encrypted) request still reaches the real `domain` normally.
/// Because the server's real certificate can never match a fronted SNI,
/// certificate verification is unconditionally skipped in that case,
/// regardless of `skip_tls_verify`.
///
/// `disable_tls` (`--cf-disable-tls`) turns the whole TLS layer off: the TCP
/// dial goes to port 80 and the upgrade request is built for plaintext
/// `ws://`. Only the Cloudflare tiers ever pass it — Cloudflare's edge serves
/// plaintext HTTP on 80 for proxied hostnames whose SSL mode does not force
/// HTTPS.
#[allow(clippy::too_many_arguments)]
async fn connect_ws_with_path(
    ip: &str,
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    sni_override: Option<&str>,
    disable_tls: bool,
) -> WsConnectResult {
    // ── TCP connection to the configured IP ──────────────────────────────
    let port = if disable_tls { 80 } else { 443 };
    let tcp = match outbound.connect(ip, port, timeout).await {
        Ok(s) => s,
        Err(e) if e.timed_out => return WsConnectResult::ConnectTimedOut(e.reason),
        Err(e) => return WsConnectResult::Failed(e.reason),
    };

    // Disable Nagle algorithm for lower latency.
    let _ = tcp.set_nodelay(true);

    // ── Build WebSocket request with Telegram-required headers ───────────
    let scheme = if disable_tls { "ws" } else { "wss" };
    let url = format!("{}://{}{}", scheme, domain, path);
    let mut request = match url.into_client_request() {
        Ok(r) => r,
        Err(e) => return WsConnectResult::Failed(format!("bad URL: {}", e)),
    };
    {
        let h = request.headers_mut();

        if request_binary_subprotocol {
            h.insert("Sec-WebSocket-Protocol", HeaderValue::from_static("binary"));
        }
        h.insert(
            "Origin",
            HeaderValue::from_static("https://web.telegram.org"),
        );
        h.insert(
            "User-Agent",
            HeaderValue::from_static(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                 AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/131.0.0.0 Safari/537.36",
            ),
        );
    }

    // ── TLS handshake + WebSocket upgrade ─────────────────────────────────
    let upgrade = async {
        if disable_tls {
            // Plaintext ws:// — no TLS handshake at all, just the HTTP
            // upgrade. Wrapping in MaybeTlsStream::Plain keeps the
            // connection type identical for the bridge.
            client_async_with_config(request, MaybeTlsStream::Plain(tcp), Some(ws_config())).await
        } else {
            tls_handshake_and_upgrade(tcp, request, skip_tls_verify, sni_override).await
        }
    };
    let result = tokio::time::timeout(timeout, upgrade).await;

    match result {
        Ok(Ok((ws, response))) => {
            let status = response.status().as_u16();

            if status == 101 {
                WsConnectResult::Connected(ws)
            } else if matches!(status, 301 | 302 | 303 | 307 | 308) {
                WsConnectResult::Redirect(status)
            } else {
                WsConnectResult::Failed(format!("unexpected HTTP status {}", status))
            }
        }
        Ok(Err(e)) => {
            // tungstenite returns `Error::Http(response)` when the server
            // sends a non-101 HTTP response.  Extract the status code from
            // the structured error rather than doing fragile string matching.
            if let WsError::Http(ref resp) = e {
                let status = resp.status().as_u16();
                if matches!(status, 301 | 302 | 303 | 307 | 308) {
                    return WsConnectResult::Redirect(status);
                }

                WsConnectResult::Failed(format!("HTTP {} from server", status))
            } else {
                WsConnectResult::Failed(e.to_string())
            }
        }
        Err(_) => WsConnectResult::TimedOut,
    }
}

/// Connect to a Cloudflare hostname through the configured preferred edges.
///
/// With no preferred IPs, the hostname is dialled normally and DNS chooses
/// Cloudflare's anycast edge. With `--cf-ip`, DNS is never used for the TCP
/// destination: every configured address is attempted, starting at a rotating
/// offset. `domain` remains the TLS SNI and HTTP `Host` on every attempt.
#[allow(clippy::too_many_arguments)]
async fn connect_cf_with_path(
    domain: &str,
    path: &str,
    request_binary_subprotocol: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> WsConnectResult {
    if opts.cf_ips.is_empty() {
        return connect_ws_with_path(
            domain,
            domain,
            path,
            request_binary_subprotocol,
            skip_tls_verify,
            timeout,
            outbound,
            None,
            opts.disable_tls,
        )
        .await;
    }

    let first = cf_ip_start(opts.cf_ips);
    let port = if opts.disable_tls { 80 } else { 443 };
    let cooldowns = if opts.disable_tls {
        &CF_EDGE_PLAINTEXT_FAIL
    } else {
        &CF_EDGE_TLS_FAIL
    };
    let mut last_non_redirect = None;
    let mut last_redirect = None;

    for ip in cf_ip_attempts(opts.cf_ips, first, cooldowns, |ip| {
        outbound.connects_directly(&ip.to_string(), port)
    }) {
        let target = ip.to_string();
        let direct = outbound.connects_directly(&target, port);
        debug!("CF edge trying {} for {}", ip, domain);
        match connect_ws_with_path(
            &target,
            domain,
            path,
            request_binary_subprotocol,
            skip_tls_verify,
            timeout,
            outbound,
            None,
            opts.disable_tls,
        )
        .await
        {
            WsConnectResult::Connected(ws) => {
                cooldowns.clear(&ip);
                return WsConnectResult::Connected(ws);
            }
            WsConnectResult::Redirect(code) => {
                cooldowns.clear(&ip);
                last_redirect = Some(code);
            }
            WsConnectResult::Failed(reason) => {
                cooldowns.clear(&ip);
                last_non_redirect = Some(WsConnectResult::Failed(reason));
            }
            WsConnectResult::TimedOut => {
                cooldowns.clear(&ip);
                last_non_redirect = Some(WsConnectResult::TimedOut);
            }
            WsConnectResult::ConnectTimedOut(reason) => {
                if direct {
                    cooldowns.set(ip, opts.fail_cooldown);
                }
                last_non_redirect = Some(WsConnectResult::ConnectTimedOut(reason));
            }
        }
    }

    last_non_redirect.unwrap_or_else(|| {
        WsConnectResult::Redirect(last_redirect.expect("non-empty CF IP list attempted"))
    })
}

/// Perform the TLS handshake (with optional SNI override) and the WebSocket
/// upgrade over an already-connected TCP stream.
///
/// Split out from `connect_ws_with_path` so it can be exercised in tests
/// against a stream connected to an arbitrary local port — the public
/// connect functions always dial `:443`, Telegram's real WS port.
async fn tls_handshake_and_upgrade<R>(
    tcp: TcpStream,
    request: R,
    skip_tls_verify: bool,
    sni_override: Option<&str>,
) -> Result<(TgWsStream, tungstenite::handshake::client::Response), WsError>
where
    R: IntoClientRequest + Unpin,
{
    if let Some(sni) = sni_override {
        // Domain fronting: TLS SNI = `sni`, Host stays whatever `request`
        // already carries. Manual TLS is required here because
        // `client_async_tls_with_config` always derives the SNI from the
        // request's own host, with no way to override it.
        let server_name = ServerName::try_from(sni)
            .map_err(|_| WsError::Url(tungstenite::error::UrlError::NoHostName))?
            .to_owned();
        let tls_connector = tokio_rustls::TlsConnector::from(no_verify_rustls_config());
        let tls_stream = tls_connector
            .connect(server_name, tcp)
            .await
            .map_err(WsError::Io)?;
        client_async_with_config(
            request,
            MaybeTlsStream::Rustls(tls_stream),
            Some(ws_config()),
        )
        .await
    } else {
        let connector = build_tls_connector(skip_tls_verify);
        client_async_tls_with_config(request, tcp, Some(ws_config()), Some(connector)).await
    }
}

/// Ceiling for one incoming WebSocket frame and its reassembled message.
///
/// Tungstenite otherwise permits 16 MiB frames and 64 MiB messages, while its
/// input buffer retains the largest capacity reached by a connection. Telegram
/// media parts are at most 1 MiB, so 4 MiB leaves protocol headroom without
/// letting one unusual frame park tens of megabytes for the session lifetime.
const WS_MAX_FRAME: usize = 4 * 1024 * 1024;

/// Target size of tungstenite's per-connection write buffer.
///
/// Every send in the bridge is awaited and flushed before the next message, so
/// the default 128 KiB batching target only increases the retained footprint.
const WS_WRITE_BUFFER: usize = 16 * 1024;

fn ws_config() -> WebSocketConfig {
    WebSocketConfig {
        write_buffer_size: WS_WRITE_BUFFER,
        max_frame_size: Some(WS_MAX_FRAME),
        max_message_size: Some(WS_MAX_FRAME),
        ..WebSocketConfig::default()
    }
}

/// Path used by the Cloudflare Worker TCP-tunnel mode.
///
/// The Worker accepts a WebSocket at `/apiws`, opens a raw TCP connection to
/// `dst:443`, and forwards every WebSocket message payload as TCP bytes.
pub fn cf_worker_path(dst: &str, dc: u32, is_media: bool) -> String {
    format!(
        "/apiws?dst={}&dc={}&media={}",
        dst,
        dc,
        if is_media { 1 } else { 0 }
    )
}

/// Try all domains for a DC in order; return the first success or the last error.
///
/// Returns `(Some(stream), all_redirects)`:
/// - `all_redirects = true` when every domain returned a redirect (WS is
///   blacklisted for this DC by Telegram).
pub async fn connect_ws_for_dc(
    ip: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
) -> (Option<TgWsStream>, bool) {
    let attempt = connect_ws_for_dc_with_outbound(
        ip,
        dc,
        is_media,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
        None,
    )
    .await;

    (attempt.ws, attempt.all_redirects)
}

/// Same as [`connect_ws_for_dc`], but routes each TCP connection through the
/// supplied outbound connector.
///
/// `sni_override` is forwarded to every domain attempt — see
/// [`connect_ws_with_path`] for what it does. Returns a [`WsAttempt`] whose
/// flags say *how* the attempt failed, which is what the caller's next step
/// hangs on (as opposed to a
/// redirect or other failure) — used to trigger the domain-fronting fallback.
pub async fn connect_ws_for_dc_with_outbound(
    ip: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    sni_override: Option<&str>,
) -> WsAttempt {
    let domains = ws_domains(dc, is_media);
    let media = media_tag(is_media);
    let mut all_redirects = true;
    let mut any_upgrade_timed_out = false;
    let mut any_connect_timed_out = false;

    for domain in &domains {
        debug!("WS trying DC{}{} → {} via {}", dc, media, domain, ip);

        match connect_ws_with_outbound_mode(
            ip,
            domain,
            skip_tls_verify,
            timeout,
            outbound,
            sni_override,
            false,
        )
        .await
        {
            WsConnectResult::Connected(ws) => {
                return WsAttempt::connected(ws);
            }
            WsConnectResult::Redirect(code) => {
                warn!(
                    "WS DC{}{} got {} from {} (redirect)",
                    dc, media, code, domain
                );
                // Keep trying next domain; still counts as all_redirects.
            }
            WsConnectResult::Failed(reason) => {
                warn!("WS DC{}{} failed on {}: {}", dc, media, domain, reason);

                all_redirects = false; // a real failure, not just a redirect
            }
            WsConnectResult::TimedOut => {
                warn!("WS DC{}{} timed out on {}", dc, media, domain);

                all_redirects = false;
                any_upgrade_timed_out = true;
            }
            WsConnectResult::ConnectTimedOut(reason) => {
                warn!("WS DC{}{} failed on {}: {}", dc, media, domain, reason);

                all_redirects = false;
                any_connect_timed_out = true;
            }
        }
    }

    WsAttempt {
        ws: None,
        all_redirects,
        upgrade_timed_out: any_upgrade_timed_out,
        connect_timed_out: any_connect_timed_out,
    }
}

/// WebSocket domains for a given DC when routing through one or more
/// Cloudflare-proxied domains.
///
/// Each DNS record `kws{N}.{cf_domain}` should be an **orange-cloud** (proxied)
/// A record in Cloudflare pointing at the corresponding Telegram DC IP, with
/// the zone's SSL/TLS mode set to **Flexible**.  Cloudflare then terminates TLS
/// from our side and forwards the WebSocket traffic as plain HTTP to Telegram.
///
/// Unlike `ws_domains()`, the raw DC number is used **without** applying
/// the `config::websocket_dc()` remap.  The user controls the Cloudflare DNS zone and
/// creates explicit records for every DC — including non-canonical ones like
/// DC 203 (`kws203.{cf_domain}`).  Remapping 203 → 2 would incorrectly route
/// traffic to DC 2 instead of DC 203 (they have different IPs/servers).
///
/// Only the base `kws{N}` record is used, never a `kws{N}-1` one.  Through
/// Cloudflare the hostname only selects the origin IP, and both records point
/// at the same DC, so a `-1` record buys nothing — while the shared
/// `--default-domains` zones do not define it at all, which made every lookup
/// a guaranteed NXDOMAIN.  `is_media` is accepted for API compatibility only.
///
/// When multiple CF domains are given, they are returned in order — the first
/// domain has highest priority.
pub fn cf_ws_domains(dc: u32, cf_domains: &[String], _is_media: bool) -> Vec<String> {
    cf_domains
        .iter()
        .map(|cf_domain| format!("kws{}.{}", dc, cf_domain))
        .collect()
}

/// Ordering policy for the Cloudflare connect loop.
///
/// Each configured domain's `kws{N}` record is attempted twice in a row, and
/// duplicate domains are skipped.  The second attempt is skipped when the
/// first ran out the clock — retrying it just buys another full connect
/// timeout before the fallback chain can move on.
///
/// That second attempt is load-bearing, not an accident.  It used to happen
/// implicitly, as the fallback for a missing `kws{N}-1` record, and
/// deduplicating it away measurably pushed connections into the (often
/// blocked) TCP fallback: on one tester's network the fallback share nearly
/// doubled, 5.9% -> 11.4%, each costing a full `--tcp-fallback-timeout`.
struct CfAttempts<'a> {
    dc: u32,
    domains: &'a [String],
    first_domain: usize,
    next_ordinal: usize,
    /// The domain just attempted for the first time, until its retry is due.
    pending_retry: Option<usize>,
}

impl<'a> CfAttempts<'a> {
    #[cfg(test)]
    fn new(dc: u32, domains: &'a [String]) -> Self {
        Self::with_offset(dc, domains, 0)
    }

    fn with_offset(dc: u32, domains: &'a [String], first_domain: usize) -> Self {
        Self {
            dc,
            domains,
            first_domain: if domains.is_empty() {
                0
            } else {
                first_domain % domains.len()
            },
            next_ordinal: 0,
            pending_retry: None,
        }
    }

    /// The next record to attempt.
    fn next_domain(&mut self) -> Option<String> {
        if let Some(domain_index) = self.pending_retry.take() {
            return Some(self.hostname(domain_index));
        }

        while self.next_ordinal < self.domains.len() {
            let ordinal = self.next_ordinal;
            self.next_ordinal += 1;
            let domain_index = (self.first_domain + ordinal) % self.domains.len();
            if (0..ordinal).any(|prior| {
                self.domains[(self.first_domain + prior) % self.domains.len()]
                    == self.domains[domain_index]
            }) {
                continue;
            }

            self.pending_retry = Some(domain_index);
            return Some(self.hostname(domain_index));
        }

        None
    }

    /// Record that the attempt just returned by `next_domain` hit the connect
    /// timeout, so it is not retried.
    fn note_timed_out(&mut self) {
        self.pending_retry = None;
    }

    fn hostname(&self, domain_index: usize) -> String {
        format!("kws{}.{}", self.dc, self.domains[domain_index])
    }
}

/// Try all Cloudflare-proxy domains for a DC in order.
///
/// The hostname serves as both the TCP destination (DNS resolves to Cloudflare's
/// anycast IP, not directly to Telegram) and the TLS SNI, so no separate DC IP
/// is required.
///
/// Returns `(Some(stream), record, all_redirects)`, where `record` is the
/// expanded `kws{N}` hostname that answered — the caller can reconnect straight
/// to it with [`connect_cf_record_with_outbound`] instead of walking the list
/// again.  `all_redirects` has the same semantics as [`connect_ws_for_dc`].
pub async fn connect_cf_ws_for_dc(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
) -> (Option<TgWsStream>, Option<String>, bool) {
    connect_cf_ws_for_dc_with_outbound_mode(
        dc,
        cf_domains,
        is_media,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
        false,
    )
    .await
}

/// Same as [`connect_cf_ws_for_dc`], but routes each TCP connection through the
/// supplied outbound connector.
pub async fn connect_cf_ws_for_dc_with_outbound(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> (Option<TgWsStream>, Option<String>, bool) {
    connect_cf_ws_for_dc_with_outbound_opts(
        dc,
        cf_domains,
        is_media,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts::DEFAULT,
    )
    .await
}

/// Same as [`connect_cf_ws_for_dc_with_outbound`], optionally using plaintext
/// `ws://` on port 80.
#[allow(clippy::too_many_arguments)]
pub async fn connect_cf_ws_for_dc_with_outbound_mode(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    disable_tls: bool,
) -> (Option<TgWsStream>, Option<String>, bool) {
    connect_cf_ws_for_dc_with_outbound_opts(
        dc,
        cf_domains,
        is_media,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts {
            disable_tls,
            ..CfDialOpts::DEFAULT
        },
    )
    .await
}

/// Same as [`connect_cf_ws_for_dc_with_outbound`], with Cloudflare dial options.
#[allow(clippy::too_many_arguments)]
pub async fn connect_cf_ws_for_dc_with_outbound_opts(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> (Option<TgWsStream>, Option<String>, bool) {
    connect_cf_ws_for_dc_with_outbound_ordered(
        dc,
        cf_domains,
        is_media,
        skip_tls_verify,
        timeout,
        outbound,
        0,
        opts,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_cf_ws_for_dc_with_outbound_ordered(
    dc: u32,
    cf_domains: &[String],
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    first_domain: usize,
    opts: CfDialOpts<'_>,
) -> (Option<TgWsStream>, Option<String>, bool) {
    let media = media_tag(is_media);
    let mut all_redirects = true;
    let mut attempts = CfAttempts::with_offset(dc, cf_domains, first_domain);

    while let Some(domain) = attempts.next_domain() {
        debug!("CF WS trying DC{}{} → {}", dc, media, domain);

        match connect_cf_with_path(
            &domain,
            "/apiws",
            true,
            skip_tls_verify,
            timeout,
            outbound,
            opts,
        )
        .await
        {
            WsConnectResult::Connected(ws) => {
                return (Some(ws), Some(domain), false);
            }
            WsConnectResult::Redirect(code) => {
                warn!(
                    "CF WS DC{}{} got {} from {} (redirect)",
                    dc, media, code, domain
                );
            }
            WsConnectResult::Failed(reason) => {
                warn!("CF WS DC{}{} failed on {}: {}", dc, media, domain, reason);
                all_redirects = false;
            }
            WsConnectResult::TimedOut | WsConnectResult::ConnectTimedOut(_) => {
                warn!("CF WS DC{}{} timed out on {}", dc, media, domain);
                attempts.note_timed_out();
                all_redirects = false;
            }
        }
    }

    (None, None, all_redirects)
}

/// Reconnect to a single already-expanded `kws{N}` Cloudflare record.
///
/// Used by the pool to re-open the exact route that just served a client,
/// skipping the per-DC domain walk and the retry that
/// [`connect_cf_ws_for_dc_with_outbound`] performs on a cold connect.
pub async fn connect_cf_record_with_outbound(
    record: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> Option<TgWsStream> {
    connect_cf_record_with_outbound_opts(
        record,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts::DEFAULT,
    )
    .await
}

/// Same as [`connect_cf_record_with_outbound`], optionally using plaintext
/// `ws://` on port 80.
pub async fn connect_cf_record_with_outbound_mode(
    record: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    disable_tls: bool,
) -> Option<TgWsStream> {
    connect_cf_record_with_outbound_opts(
        record,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts {
            disable_tls,
            ..CfDialOpts::DEFAULT
        },
    )
    .await
}

/// Same as [`connect_cf_record_with_outbound`], with Cloudflare dial options.
pub async fn connect_cf_record_with_outbound_opts(
    record: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> Option<TgWsStream> {
    match connect_cf_with_path(
        record,
        "/apiws",
        true,
        skip_tls_verify,
        timeout,
        outbound,
        opts,
    )
    .await
    {
        WsConnectResult::Connected(ws) => Some(ws),
        _ => None,
    }
}

/// Connect through a Cloudflare Worker TCP tunnel.
///
/// Unlike `--cf-domain`, the Worker does not expose `kws{N}` subdomains.  We
/// connect to the Worker domain and pass the real Telegram DC destination in
/// the query string. The returned stream is the outer WebSocket to the Worker;
/// the Worker forwards its binary frames to Telegram as raw TCP bytes.
pub async fn connect_cf_worker_ws_for_dc(
    worker_domain: &str,
    dst: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
) -> Option<TgWsStream> {
    connect_cf_worker_ws_for_dc_with_outbound_mode(
        worker_domain,
        dst,
        dc,
        is_media,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
        false,
    )
    .await
}

/// Same as [`connect_cf_worker_ws_for_dc`], but routes the TCP connection
/// through the supplied outbound connector.
pub async fn connect_cf_worker_ws_for_dc_with_outbound(
    worker_domain: &str,
    dst: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> Option<TgWsStream> {
    connect_cf_worker_ws_for_dc_with_outbound_opts(
        worker_domain,
        dst,
        dc,
        is_media,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts::DEFAULT,
    )
    .await
}

/// Same as [`connect_cf_worker_ws_for_dc_with_outbound`], optionally using
/// plaintext `ws://` on port 80.
#[allow(clippy::too_many_arguments)]
pub async fn connect_cf_worker_ws_for_dc_with_outbound_mode(
    worker_domain: &str,
    dst: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    disable_tls: bool,
) -> Option<TgWsStream> {
    connect_cf_worker_ws_for_dc_with_outbound_opts(
        worker_domain,
        dst,
        dc,
        is_media,
        skip_tls_verify,
        timeout,
        outbound,
        CfDialOpts {
            disable_tls,
            ..CfDialOpts::DEFAULT
        },
    )
    .await
}

/// Same as [`connect_cf_worker_ws_for_dc_with_outbound`], with Cloudflare dial
/// options.
#[allow(clippy::too_many_arguments)]
pub async fn connect_cf_worker_ws_for_dc_with_outbound_opts(
    worker_domain: &str,
    dst: &str,
    dc: u32,
    is_media: bool,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> Option<TgWsStream> {
    let path = cf_worker_path(dst, dc, is_media);
    let media = media_tag(is_media);
    debug!(
        "CF Worker trying DC{}{} → {} via {}",
        dc, media, dst, worker_domain
    );

    match connect_cf_with_path(
        worker_domain,
        &path,
        false,
        skip_tls_verify,
        timeout,
        outbound,
        opts,
    )
    .await
    {
        WsConnectResult::Connected(ws) => Some(ws),
        WsConnectResult::Redirect(code) => {
            warn!(
                "CF Worker DC{}{} got {} from {} (redirect)",
                dc, media, code, worker_domain
            );
            None
        }
        WsConnectResult::Failed(reason) => {
            warn!(
                "CF Worker DC{}{} failed on {}: {}",
                dc, media, worker_domain, reason
            );
            None
        }
        WsConnectResult::TimedOut | WsConnectResult::ConnectTimedOut(_) => {
            warn!("CF Worker DC{}{} timed out on {}", dc, media, worker_domain);
            None
        }
    }
}

/// Send a binary WebSocket message and flush.
pub async fn ws_send(ws: &mut TgWsStream, data: Vec<u8>) -> Result<(), String> {
    ws.send(Message::Binary(data))
        .await
        .map_err(|e| e.to_string())
}

/// Receive the next binary message from the WebSocket.
/// Returns `None` when the connection is closed gracefully.
#[allow(dead_code)]
pub async fn ws_recv(ws: &mut TgWsStream) -> Option<Vec<u8>> {
    loop {
        match ws.next().await {
            Some(Ok(Message::Binary(b))) => return Some(b),
            Some(Ok(Message::Text(t))) => return Some(t.into_bytes()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Ok(Message::Close(_))) | None => return None,
            Some(Err(_)) => return None,
            Some(Ok(_)) => continue,
        }
    }
}

// ─── TLS connector helpers ───────────────────────────────────────────────────

// Both client configs are built once and shared by every connection.
//
// Rebuilding them per connection — as this used to — cost a fresh copy of the
// ~150-entry WebPKI root store each time, and, far worse, a fresh TLS session
// cache: `rustls` keeps resumption tickets in the `ClientConfig`, so a config
// that lives for one connection can never resume anything. Every single
// connection therefore paid a full TLS 1.3 handshake. Sharing the config lets
// repeat connections to the same DC or CF domain resume instead, which is the
// difference between a key exchange plus certificate verification and almost
// nothing — the dominant CPU cost on the routers and phones this runs on.
//
// `ClientConfig` is `Sync` and its session store is internally locked, so
// sharing one across connections is the intended usage.
static VERIFYING_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
static NO_VERIFY_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// How many TLS sessions to keep for resumption — `rustls`'s own default,
/// stated explicitly because it is easy to assume it is oversized and shrink
/// it. It is not: it leaves headroom over the largest realistic config.
///
/// The cache holds one entry per *hostname*, and this proxy dials a lot of
/// them. Each CF domain contributes `kws{N}` for every DC in play (media and
/// non-media share that name), plus `kws{1..5}[-1].web.telegram.org` for the
/// direct path and one name per Worker. With `--default-domains` that is
/// roughly:
///
/// ```text
///   21 domains x 3 DCs + 10 + 1  ~=  75 names
///   21 domains x 6 DCs + 10 + 1  ~= 140 names
/// ```
///
/// and `--cf-balance` deliberately keeps every one of them hot. Undersizing
/// the cache is the worst outcome available: the memory is still spent, and
/// entries get evicted before they can be reused, so the handshakes come back.
const TLS_SESSION_CACHE_SIZE: usize = 256;

fn build_tls_connector(skip_verify: bool) -> Connector {
    let config = if skip_verify {
        no_verify_rustls_config()
    } else {
        verifying_rustls_config()
    };

    Connector::Rustls(config)
}

/// The shared certificate-verifying client config, using the bundled WebPKI
/// root store.
fn verifying_rustls_config() -> Arc<rustls::ClientConfig> {
    VERIFYING_CONFIG
        .get_or_init(|| {
            let mut root_store = rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let mut config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            config.resumption =
                rustls::client::Resumption::in_memory_sessions(TLS_SESSION_CACHE_SIZE);

            Arc::new(config)
        })
        .clone()
}

/// The shared `rustls::ClientConfig` that accepts any certificate, regardless
/// of hostname or trust chain. Used by `--danger-accept-invalid-certs` and by
/// the domain-fronting path, which *always* needs it: the real certificate
/// presented by Telegram can never match a fronted (spoofed) SNI hostname, so
/// hostname verification would fail even for an otherwise-legitimate server.
fn no_verify_rustls_config() -> Arc<rustls::ClientConfig> {
    NO_VERIFY_CONFIG
        .get_or_init(|| {
            let mut config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier))
                .with_no_client_auth();
            config.resumption =
                rustls::client::Resumption::in_memory_sessions(TLS_SESSION_CACHE_SIZE);

            Arc::new(config)
        })
        .clone()
}

// ── No-op certificate verifier for `--danger-accept-invalid-certs` ──────────

#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests;
