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

mod http;

use std::future::Future;
use std::time::Duration;

use tracing::{debug, warn};

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

/// The decoded built-in list `--default-domains` serves from until a fetch
/// succeeds.
pub fn fallback_domains() -> Vec<String> {
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
    match try_fetch_default_domains(outbound).await {
        Ok(domains) => domains,
        Err(e) => {
            warn!(
                "Failed to fetch default CF domain list ({}); using built-in fallback",
                e
            );
            fallback_domains()
        }
    }
}

/// Fetch and decode the default CF-proxy domain list, without falling back.
///
/// An empty list is an error too: it would leave `--default-domains`
/// contributing nothing, which is worse than the built-in five.
pub async fn try_fetch_default_domains(
    outbound: &OutboundConnector,
) -> Result<Vec<String>, String> {
    let body = https_get(DOMAINS_URL_HOST, DOMAINS_URL_PATH, outbound).await?;
    let domains = parse_domain_list(&body);
    if domains.is_empty() {
        return Err("the list from GitHub was empty".to_string());
    }
    Ok(domains)
}

/// Delays between background re-fetches after the startup fetch failed.
///
/// The startup fetch runs before the listener binds, which on a router is
/// routinely before the uplink or DNS is up (#159).  The built-in list keeps
/// the proxy serving meanwhile, but it is the smallest list there is, and
/// without a retry it stayed in use until the next restart.  Doubling from
/// 15 s reaches a 5-minute cap and gives up after about an hour: past that the
/// network is up and GitHub itself is what is unreachable, and one more GET
/// every few minutes for the rest of the run would buy nothing.
pub fn refetch_delays() -> impl Iterator<Item = Duration> {
    const FIRST: Duration = Duration::from_secs(15);
    const CAP: Duration = Duration::from_secs(300);
    const ATTEMPTS: usize = 15;
    std::iter::successors(Some(FIRST), |d| Some((*d * 2).min(CAP))).take(ATTEMPTS)
}

/// Retry `fetch` after each of `delays` until it yields a list.
///
/// Returns `None` once `delays` runs out.  Failures are logged at debug: the
/// caller has already warned once that the built-in list is in use.
pub async fn refetch<F, Fut>(
    delays: impl IntoIterator<Item = Duration>,
    mut fetch: F,
) -> Option<Vec<String>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<String>, String>>,
{
    for delay in delays {
        tokio::time::sleep(delay).await;
        match fetch().await {
            Ok(domains) => return Some(domains),
            Err(e) => debug!("Default CF domain list re-fetch failed: {}", e),
        }
    }
    None
}

#[cfg(test)]
mod tests;
