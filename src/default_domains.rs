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

pub(crate) mod http;

use tracing::warn;

use crate::outbound::OutboundConnector;
use http::https_get;

const DOMAINS_URL_HOST: &str = "raw.githubusercontent.com";
const DOMAINS_URL_PATH: &str = "/Flowseal/tg-ws-proxy/refs/heads/main/.github/cfproxy-domains.txt";

/// The real TLD suffix that the encoded `.com` maps back to.
const REAL_SUFFIX: &str = ".co.uk";

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

/// Deobfuscate a single encoded domain.
///
/// Algorithm (mirrors `_dd()` in the Python reference):
///  1. Require a `.com` suffix; return `None` if absent.
///  2. Count the alphabetic characters in the prefix -> `n`.
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

/// Fetch the default CF-proxy domain list using a direct outbound connection.
///
/// This preserves the original public API. The proxy binary uses
/// [`fetch_default_domains_with_outbound`] so the fetch can honor outbound
/// proxy configuration.
pub async fn fetch_default_domains() -> Vec<String> {
    let outbound = OutboundConnector::direct();
    fetch_default_domains_with_outbound(&outbound).await
}

/// Fetch the default CF-proxy domain list through the supplied outbound
/// connector, deobfuscate it, and return the decoded domains. Falls back to
/// the embedded list on any error.
pub async fn fetch_default_domains_with_outbound(outbound: &OutboundConnector) -> Vec<String> {
    match https_get(DOMAINS_URL_HOST, DOMAINS_URL_PATH, outbound).await {
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

#[cfg(test)]
mod tests;
