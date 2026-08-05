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

use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

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
    connect_ws_with_path(
        ip,
        domain,
        "/apiws",
        true,
        skip_tls_verify,
        timeout,
        outbound,
        sni_override,
    )
    .await
}

/// Connect to `ip:443` and perform the WebSocket upgrade to `wss://{domain}{path}`.
///
/// Normally the TLS SNI is `domain` (matching the `Host` header). When
/// `sni_override` is set, the TLS handshake instead presents that unrelated
/// hostname as SNI — domain fronting — while the HTTP request still targets
/// `domain` as `Host`. DPI that filters by SNI sees the fronted name; the
/// actual (TLS-encrypted) request still reaches the real `domain` normally.
/// Because the server's real certificate can never match a fronted SNI,
/// certificate verification is unconditionally skipped in that case,
/// regardless of `skip_tls_verify`.
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
) -> WsConnectResult {
    // ── TCP connection to the configured IP ──────────────────────────────
    let tcp = match outbound.connect(ip, 443, timeout).await {
        Ok(s) => s,
        Err(e) if e.timed_out => return WsConnectResult::ConnectTimedOut(e.reason),
        Err(e) => return WsConnectResult::Failed(e.reason),
    };

    // Disable Nagle algorithm for lower latency.
    let _ = tcp.set_nodelay(true);

    // ── Build WebSocket request with Telegram-required headers ───────────
    let url = format!("wss://{}{}", domain, path);
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
    let result = tokio::time::timeout(
        timeout,
        tls_handshake_and_upgrade(tcp, request, skip_tls_verify, sni_override),
    )
    .await;

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

/// Ceiling on a single WebSocket frame from Telegram, and on a message
/// reassembled from them.
///
/// tungstenite defaults to 16 MiB and 64 MiB, and grows a per-connection input
/// buffer to whatever it has actually seen — so the frame size is what a
/// connection's memory settles at, and the default ceiling is far above
/// anything Telegram sends. One MTProto packet arrives per message here, and
/// the largest is a media part: `upload.getFile` caps a part at 1 MiB, so
/// 4 MiB leaves generous headroom for transport framing while keeping a
/// misbehaving or hostile upstream from parking megabytes per connection.
const WS_MAX_FRAME: usize = 4 << 20;

/// Bytes tungstenite may queue before it flushes to the socket.
///
/// Its default is 128 KiB, sized for callers that batch many small messages.
/// Both bridge directions here `await` each send, so the queue never usefully
/// exceeds one message — the smaller threshold just keeps a burst from
/// growing the buffer and holding that capacity for the connection's life.
const WS_WRITE_BUFFER: usize = 16 * 1024;

/// Frame limits applied to every WebSocket this proxy opens.
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

/// Return `true` when `reason` describes a DNS lookup failure.
///
/// Used in the CF-proxy path to detect when a `kws{N}-1.domain` record is
/// absent so that the connection can be transparently retried using the base
/// `kws{N}.domain` record (which the user is only required to configure once).
fn is_dns_not_found(reason: &str) -> bool {
    // The error originates from the "TCP connect" phase and contains one of
    // several platform-specific messages for "host not found":
    //   Linux glibc:  "failed to lookup address information: ..."
    //   macOS/BSD:    "nodename nor servname provided, or not known"
    //   Windows:      "No such host is known"
    reason.starts_with("TCP connect:")
        && (reason.contains("failed to lookup address information")
            || reason.contains("nodename nor servname provided")
            || reason.contains("No such host is known")
            || reason.contains("Name or service not known"))
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

        match connect_ws_with_outbound(ip, domain, skip_tls_verify, timeout, outbound, sni_override)
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
/// When multiple CF domains are given, each domain's subdomains are generated
/// in order — the first domain has highest priority.
pub fn cf_ws_domains(dc: u32, cf_domains: &[String], is_media: bool) -> Vec<String> {
    cf_domains
        .iter()
        .flat_map(|cf_domain| {
            ordered_records(
                format!("kws{}.{}", dc, cf_domain),
                format!("kws{}-1.{}", dc, cf_domain),
                is_media,
            )
        })
        .collect()
}

/// The base `kws{N}` record matching a `kws{N}-1` record, if `domain` is one.
///
/// `kws{N}-1` records are optional in a user-managed Cloudflare zone, so a
/// missing DNS entry transparently falls back to the base record.
fn base_cf_record(domain: &str) -> Option<String> {
    domain
        .contains("-1.")
        .then(|| domain.replacen("-1.", ".", 1))
}

/// Ordering policy for the Cloudflare connect loop.
///
/// The configured records are attempted in order, skipping any already tried.
/// A `kws{N}-1` record missing from DNS additionally queues its base record as
/// a *forced* attempt, which neither skips nor consumes the record's normal
/// turn — so the base record is attempted twice.
///
/// That second attempt is load-bearing, not an accident. `kws{N}-1` records
/// are optional and most zones omit them, so a missing one is the normal case
/// and its fallback is what gives a transiently-failing base record another
/// chance. Deduplicating it away measurably pushed connections into the (often
/// blocked) TCP fallback: on one tester's network the fallback share nearly
/// doubled, 5.9% -> 11.4%, each costing a full `--tcp-fallback-timeout`.
///
/// Forcing rather than merely queueing matters because the two orderings would
/// otherwise get different numbers of attempts. Media DCs try `-1` first, so
/// its fallback *is* the base record's first attempt; without the force, the
/// base record's own turn would then be skipped as already-tried and media
/// would get one attempt where everything else got two. The same tester's log
/// showed exactly that asymmetry — 61 base attempts against 61 `-1` attempts
/// on media, versus 99 against 11 elsewhere — while video was the thing that
/// kept failing to load first time.
struct CfAttempts {
    queue: VecDeque<CfAttempt>,
    tried: HashSet<String>,
    /// Records whose attempt ran out the clock. Retrying one of these just
    /// buys another full connect timeout, so the forced retry skips them.
    timed_out: HashSet<String>,
}

struct CfAttempt {
    domain: String,
    /// Queued by the `-1` fallback: runs even if already tried, and does not
    /// use up the record's own turn later in the list.
    forced: bool,
}

impl CfAttempts {
    fn new(domains: Vec<String>) -> Self {
        Self {
            queue: domains
                .into_iter()
                .map(|domain| CfAttempt {
                    domain,
                    forced: false,
                })
                .collect(),
            tried: HashSet::new(),
            timed_out: HashSet::new(),
        }
    }

    /// The next record to attempt, skipping ones already tried unless they
    /// were queued as a forced retry.
    fn next_domain(&mut self) -> Option<String> {
        while let Some(attempt) = self.queue.pop_front() {
            if attempt.forced {
                return Some(attempt.domain);
            }
            if self.tried.insert(attempt.domain.clone()) {
                return Some(attempt.domain);
            }
        }

        None
    }

    /// Record that `domain`'s attempt hit the connect timeout.
    fn note_timed_out(&mut self, domain: &str) {
        self.timed_out.insert(domain.to_string());
    }

    /// Queue the base record for `domain` as a forced retry, if `domain` is a
    /// `-1` record whose base is worth attempting again. Returns the queued
    /// record.
    fn retry_base_of(&mut self, domain: &str) -> Option<String> {
        let base = base_cf_record(domain)?;
        if self.timed_out.contains(&base) {
            return None;
        }
        self.queue.push_front(CfAttempt {
            domain: base.clone(),
            forced: true,
        });

        Some(base)
    }
}

/// Try all Cloudflare-proxy domains for a DC in order.
///
/// The hostname serves as both the TCP destination (DNS resolves to Cloudflare's
/// anycast IP, not directly to Telegram) and the TLS SNI, so no separate DC IP
/// is required.
///
/// `kws{N}-1` records are **optional** in a CF setup.  When one is absent the
/// proxy transparently retries the same DC using `kws{N}` — the user only needs
/// to configure the base record in Cloudflare.
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
    connect_cf_ws_for_dc_with_outbound(
        dc,
        cf_domains,
        is_media,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
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
    let media = media_tag(is_media);
    let mut all_redirects = true;
    let mut attempts = CfAttempts::new(cf_ws_domains(dc, cf_domains, is_media));

    while let Some(domain) = attempts.next_domain() {
        debug!("CF WS trying DC{}{} → {}", dc, media, domain);

        // Pass the CF domain as the TCP host so that Tokio's DNS resolution
        // returns Cloudflare's anycast IP rather than Telegram's DC IP.
        match connect_ws_with_outbound(&domain, &domain, skip_tls_verify, timeout, outbound, None)
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
                // A `kws{N}-1` record that is simply absent from the user's CF
                // zone is expected, not a failure: retry the base record next
                // without a warning and without counting it against
                // `all_redirects`.
                if is_dns_not_found(&reason)
                    && let Some(base) = attempts.retry_base_of(&domain)
                {
                    debug!(
                        "CF WS DC{}{}: {} not in DNS, retrying with {}",
                        dc, media, domain, base
                    );
                    continue;
                }

                warn!("CF WS DC{}{} failed on {}: {}", dc, media, domain, reason);
                all_redirects = false;
            }
            WsConnectResult::TimedOut | WsConnectResult::ConnectTimedOut(_) => {
                warn!("CF WS DC{}{} timed out on {}", dc, media, domain);
                attempts.note_timed_out(&domain);
                all_redirects = false;
            }
        }
    }

    (None, None, all_redirects)
}

/// Reconnect to a single already-expanded `kws{N}` Cloudflare record.
///
/// Used by the pool to re-open the exact route that just served a client,
/// skipping the per-DC record expansion and the `-1`/base fallback dance that
/// [`connect_cf_ws_for_dc_with_outbound`] performs on a cold connect.
pub async fn connect_cf_record_with_outbound(
    record: &str,
    skip_tls_verify: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> Option<TgWsStream> {
    match connect_ws_with_outbound(record, record, skip_tls_verify, timeout, outbound, None).await {
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
    connect_cf_worker_ws_for_dc_with_outbound(
        worker_domain,
        dst,
        dc,
        is_media,
        skip_tls_verify,
        timeout,
        &OutboundConnector::direct(),
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
    let path = cf_worker_path(dst, dc, is_media);
    let media = media_tag(is_media);
    debug!(
        "CF Worker trying DC{}{} → {} via {}",
        dc, media, dst, worker_domain
    );

    match connect_ws_with_path(
        worker_domain,
        worker_domain,
        &path,
        false,
        skip_tls_verify,
        timeout,
        outbound,
        None,
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
/// it. It is not: it is about right for the largest realistic config.
///
/// The cache holds one entry per *hostname*, and this proxy dials a lot of
/// them. Each CF domain contributes `kws{N}` and `kws{N}-1` for every DC in
/// play (media and non-media share those names, they only reorder them), plus
/// `kws{1..5}[-1].web.telegram.org` for the direct path and one name per
/// Worker. With `--default-domains` that is roughly:
///
/// ```text
///   21 domains x 3 DCs x 2 records + 10 + 1  ~= 140 names
///   21 domains x 6 DCs x 2 records + 10 + 1  ~= 260 names
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
