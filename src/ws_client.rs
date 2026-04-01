//! WebSocket client for Telegram DC connections.
//!
//! Telegram exposes WebSocket endpoints at `wss://kwsN.web.telegram.org/apiws`
//! (where N is the DC id).  The proxy connects TCP to the configured **IP**
//! while using the **domain** as the TLS SNI / HTTP Host, matching the Python
//! reference implementation.
//!
//! TLS certificate verification is controlled by `Config::skip_tls_verify`.
//! When disabled (default), verification uses the bundled WebPKI root store.
//! When enabled (via `--danger-accept-invalid-certs`), a no-op verifier is
//! used — matching the Python reference implementation which always passes
//! `verify_mode = CERT_NONE`.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    client_async_tls_with_config,
    tungstenite::{client::IntoClientRequest, http::HeaderValue},
    Connector, MaybeTlsStream, WebSocketStream,
};
use tracing::{debug, warn};

/// A live WebSocket connection to a Telegram DC.
pub type TgWsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// WebSocket domains for a given DC.
///
/// Telegram provides two hostnames per DC; trying both increases resilience.
/// Media DCs prefer the `kwsN-1` variant first.
pub fn ws_domains(dc: u32, is_media: bool) -> Vec<String> {
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", dc),
            format!("kws{}.web.telegram.org", dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", dc),
            format!("kws{}-1.web.telegram.org", dc),
        ]
    }
}

/// Outcome of a WebSocket connection attempt.
#[derive(Debug)]
pub enum WsConnectResult {
    /// Successful WebSocket upgrade.
    Connected(TgWsStream),
    /// The server returned a redirect (301/302/303/307/308).
    /// Telegram sometimes does this when WS is unavailable — the caller
    /// should fall back to direct TCP.
    Redirect(u16),
    /// Any other non-101 status code or transport error.
    Failed(String),
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
    // ── TCP connection to the configured IP ──────────────────────────────
    let tcp = match tokio::time::timeout(
        timeout,
        TcpStream::connect(format!("{}:443", ip)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return WsConnectResult::Failed(format!("TCP connect: {}", e)),
        Err(_) => return WsConnectResult::Failed("TCP connect timed out".into()),
    };

    // Disable Nagle algorithm for lower latency.
    let _ = tcp.set_nodelay(true);

    // ── Build WebSocket request with Telegram-required headers ───────────
    let url = format!("wss://{}/apiws", domain);
    let mut request = match url.into_client_request() {
        Ok(r) => r,
        Err(e) => return WsConnectResult::Failed(format!("bad URL: {}", e)),
    };
    {
        let h = request.headers_mut();
        h.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static("binary"),
        );
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

    // ── TLS connector ────────────────────────────────────────────────────
    let connector = build_tls_connector(skip_tls_verify);

    // ── WebSocket handshake over the existing TCP stream ─────────────────
    let result = tokio::time::timeout(
        timeout,
        client_async_tls_with_config(request, tcp, None, Some(connector)),
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
            use tungstenite::Error as WsError;
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
        Err(_) => WsConnectResult::Failed("WebSocket handshake timed out".into()),
    }
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
    let domains = ws_domains(dc, is_media);
    let mut all_redirects = true;

    for domain in &domains {
        debug!("WS trying DC{}{} → {} via {}", dc, if is_media { "m" } else { "" }, domain, ip);
        match connect_ws(ip, domain, skip_tls_verify, timeout).await {
            WsConnectResult::Connected(ws) => {
                return (Some(ws), false);
            }
            WsConnectResult::Redirect(code) => {
                warn!("WS DC{}{} got {} from {} (redirect)", dc, if is_media { "m" } else { "" }, code, domain);
                // Keep trying next domain; still counts as all_redirects.
            }
            WsConnectResult::Failed(reason) => {
                warn!("WS DC{}{} failed on {}: {}", dc, if is_media { "m" } else { "" }, domain, reason);
                all_redirects = false; // a real failure, not just a redirect
            }
        }
    }
    (None, all_redirects)
}

/// Send a binary WebSocket message and flush.
pub async fn ws_send(ws: &mut TgWsStream, data: Vec<u8>) -> Result<(), String> {
    use tungstenite::Message;
    ws.send(Message::Binary(data))
        .await
        .map_err(|e| e.to_string())
}

/// Receive the next binary message from the WebSocket.
/// Returns `None` when the connection is closed gracefully.
#[allow(dead_code)]
pub async fn ws_recv(ws: &mut TgWsStream) -> Option<Vec<u8>> {
    use tungstenite::Message;
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

fn build_tls_connector(skip_verify: bool) -> Connector {
    if skip_verify {
        build_no_verify_connector()
    } else {
        // Use the default connector; tokio-tungstenite with
        // `rustls-tls-webpki-roots` bundles the WebPKI root store.
        Connector::Rustls(Arc::new(build_default_rustls_config()))
    }
}

fn build_default_rustls_config() -> rustls::ClientConfig {
    // The `rustls-tls-webpki-roots` feature pulls in the Mozilla root store.
    // We recreate an equivalent config here so we can share the type.
    let root_store = webpki_roots_store();
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

fn build_no_verify_connector() -> Connector {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Connector::Rustls(Arc::new(config))
}

/// Build a root certificate store from the bundled WebPKI roots.
fn webpki_roots_store() -> rustls::RootCertStore {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
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
