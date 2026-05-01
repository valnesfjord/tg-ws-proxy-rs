//! Fetches and deobfuscates the default Cloudflare-proxy domain list from
//! the upstream repository.
//!
//! The upstream repository maintains an obfuscated list of CF proxy domains.
//! Each entry uses a simple Caesar cipher: every alphabetic character in the
//! domain prefix is shifted **forward** by `n` (the total number of alphabetic
//! characters in that prefix), and the real `.co.uk` suffix is replaced with
//! `.com`.  Deobfuscation reverses the shift and restores the original suffix.
//!
//! Reference Python implementation:
//!   <https://github.com/Flowseal/tg-ws-proxy/blob/main/proxy/config.py#L36>

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::warn;

const DOMAINS_URL_HOST: &str = "raw.githubusercontent.com";
const DOMAINS_URL_PATH: &str =
    "/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt";

/// The real TLD suffix that the encoded `.com` maps back to.
const REAL_SUFFIX: &str = ".co.uk";

const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Embedded fallback list (obfuscated) used when the GitHub fetch fails.
///
/// Kept in sync with the `_CFPROXY_ENC` constant in the Python reference.
static FALLBACK_ENCODED: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
];

// ─── Deobfuscation ───────────────────────────────────────────────────────────

/// Deobfuscate a single encoded domain.
///
/// Algorithm (mirrors `_dd()` in the Python reference):
///  1. Require a `.com` suffix; return `None` if absent.
///  2. Count the alphabetic characters in the prefix → `n`.
///  3. Shift each alphabetic character **backward** by `n` (mod 26),
///     preserving case; leave non-alpha characters unchanged.
///  4. Append `.co.uk` in place of `.com`.
pub fn deobfuscate(s: &str) -> Option<String> {
    let prefix = s.strip_suffix(".com")?;
    let n = prefix.chars().filter(|c| c.is_ascii_alphabetic()).count() as i32;
    let decoded: String = prefix
        .chars()
        .map(|c| {
            if c.is_ascii_lowercase() {
                let v = ((c as i32 - b'a' as i32) - n).rem_euclid(26) as u8 + b'a';
                v as char
            } else if c.is_ascii_uppercase() {
                let v = ((c as i32 - b'A' as i32) - n).rem_euclid(26) as u8 + b'A';
                v as char
            } else {
                c
            }
        })
        .collect();
    Some(format!("{}{}", decoded, REAL_SUFFIX))
}

// ─── HTTPS fetch ─────────────────────────────────────────────────────────────

/// Build a `rustls` `ClientConfig` using the bundled WebPKI root store.
fn build_tls_config() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Perform a minimal HTTPS GET and return the response body as a `String`.
async fn https_get(host: &str, path: &str) -> Result<String, String> {
    let connector = TlsConnector::from(Arc::new(build_tls_config()));

    // TCP connect.
    let tcp = tokio::time::timeout(
        FETCH_TIMEOUT,
        TcpStream::connect(format!("{}:443", host)),
    )
    .await
    .map_err(|_| "TCP connect timed out".to_string())?
    .map_err(|e| format!("TCP connect: {}", e))?;

    let _ = tcp.set_nodelay(true);

    // TLS handshake.
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| format!("invalid server name: {}", e))?;
    let mut tls = tokio::time::timeout(
        FETCH_TIMEOUT,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_| "TLS handshake timed out".to_string())?
    .map_err(|e| format!("TLS handshake: {}", e))?;

    // HTTP/1.1 GET.
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nUser-Agent: tg-ws-proxy\r\n\r\n",
        path, host
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {}", e))?;

    // Read the full response (server closes the connection after sending it).
    let mut buf = Vec::new();
    tokio::time::timeout(FETCH_TIMEOUT, tls.read_to_end(&mut buf))
        .await
        .map_err(|_| "read timed out".to_string())?
        .map_err(|e| format!("read: {}", e))?;

    // Split headers and body at the first blank line.
    let response = String::from_utf8_lossy(&buf);
    if let Some(pos) = response.find("\r\n\r\n") {
        Ok(response[pos + 4..].to_string())
    } else {
        Err("response has no body separator (\\r\\n\\r\\n)".to_string())
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Parse a plain-text domain list (one domain per line; `#` comments ignored).
/// Each line is deobfuscated before being included.
fn parse_domain_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(deobfuscate)
        .collect()
}

fn fallback_domains() -> Vec<String> {
    FALLBACK_ENCODED
        .iter()
        .filter_map(|s| deobfuscate(s))
        .collect()
}

/// Fetch the default CF-proxy domain list from GitHub, deobfuscate it, and
/// return the decoded domains.  Falls back to the embedded list on any error.
pub async fn fetch_default_domains() -> Vec<String> {
    match https_get(DOMAINS_URL_HOST, DOMAINS_URL_PATH).await {
        Ok(body) => {
            let domains = parse_domain_list(&body);
            if domains.is_empty() {
                warn!("Default domain list from GitHub was empty; using built-in fallback");
                fallback_domains()
            } else {
                domains
            }
        }
        Err(e) => {
            warn!(
                "Failed to fetch default CF domain list ({}); using built-in fallback",
                e
            );
            fallback_domains()
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscate_has_co_uk_suffix() {
        for encoded in FALLBACK_ENCODED {
            let decoded = deobfuscate(encoded).expect("should decode");
            assert!(
                decoded.ends_with(REAL_SUFFIX),
                "expected .co.uk suffix, got {decoded:?}"
            );
        }
    }

    #[test]
    fn deobfuscate_rejects_non_com() {
        assert!(deobfuscate("example.org").is_none());
        assert!(deobfuscate("nocomhere").is_none());
        assert!(deobfuscate("").is_none());
    }

    #[test]
    fn parse_skips_blank_lines_and_comments() {
        let text = "# header\nvirkgj.com\n\n# comment\nvmmzovy.com\n";
        let domains = parse_domain_list(text);
        assert_eq!(domains.len(), 2);
        for d in &domains {
            assert!(d.ends_with(REAL_SUFFIX));
        }
    }

    /// Validate the Caesar-cipher arithmetic for one known pair.
    ///
    /// `virkgj.com` has prefix `virkgj` (n=6).  Shifting each letter back by 6:
    ///   v→p, i→c, r→l, k→e, g→a, j→d  → `pclead.co.uk`
    #[test]
    fn deobfuscate_known_pair() {
        assert_eq!(
            deobfuscate("virkgj.com"),
            Some("pclead.co.uk".to_string())
        );
    }
}
