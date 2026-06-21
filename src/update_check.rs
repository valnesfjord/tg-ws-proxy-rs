//! Lightweight GitHub release version check.
//!
//! Compares the running binary's version (`CARGO_PKG_VERSION`, set by Cargo
//! from this crate's `Cargo.toml`) against the latest GitHub release tag for
//! this repository (`CARGO_PKG_REPOSITORY`, likewise from `Cargo.toml`).
//!
//! This intentionally adds **no new dependency**. It reuses:
//!  - the hand-rolled HTTPS client already in [`crate::default_domains::http`]
//!    (built on `tokio-rustls` + `httparse`, both already dependencies for
//!    other reasons) for the network request, routed through the same
//!    [`OutboundConnector`] as every other outbound connection this proxy
//!    makes, so it also honours `--outbound-proxy` / `--no-proxy`;
//!  - a few lines of manual string searching instead of a JSON crate, since
//!    the only things needed out of the GitHub API response are two fields
//!    (`tag_name`, `html_url`), which have a small, fixed shape — release
//!    tag names and URLs can't contain a literal `"`, so a plain substring
//!    search is exact, not just a heuristic;
//!  - a tiny hand-written numeric version comparison instead of a `semver`
//!    crate;
//!  - a tiny `key=value` text file instead of a `serde`-backed cache.
//!
//! ## Rate limiting
//!
//! GitHub's unauthenticated REST API allows only 60 requests/hour per IP.
//! Checking on every process start would be wasteful at best and could hit
//! that limit on a flapping service (crash loops, frequent container
//! restarts). Like the Python reference implementation, results are cached
//! to disk and a fresh request is only made once an hour has passed since
//! the last one — restarts within that window reuse the cached tag.

use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::default_domains::http::https_get;
use crate::outbound::OutboundConnector;

const GITHUB_API_HOST: &str = "api.github.com";

/// Minimum time between live GitHub API requests. Mirrors the Python
/// reference implementation's `_MIN_FETCH_INTERVAL_SEC`.
const MIN_RECHECK_INTERVAL_SECS: u64 = 3600;

/// Outcome of a version check.
pub enum UpdateCheck {
    /// The running version matches the latest GitHub release.
    UpToDate,
    /// The running version is newer than the latest tagged GitHub release
    /// (e.g. a local build off `main` ahead of the last tag). Not an error
    /// and not "update available" — just informational.
    AheadOfRelease {
        current: &'static str,
        latest: String,
    },
    /// A newer release is available on GitHub.
    UpdateAvailable {
        current: &'static str,
        latest: String,
        /// Direct link to the release, when GitHub returned one.
        html_url: Option<String>,
    },
    /// The check could not be completed (no network, rate-limited,
    /// unexpected response shape, etc.). Callers should treat this the same
    /// as "nothing to report" — it's never fatal.
    Failed(String),
}

/// Check GitHub for a newer release than the one currently running.
///
/// Reuses a cached result (see the module docs) when one was fetched less
/// than [`MIN_RECHECK_INTERVAL_SECS`] ago, otherwise performs a live request
/// and refreshes the cache.
pub async fn check_for_update(outbound: &OutboundConnector) -> UpdateCheck {
    let cache_path = cache_file_path();
    let now = unix_now();

    if let Some(cached) = cache_path.as_deref().and_then(read_cache) {
        if now.saturating_sub(cached.checked_at) < MIN_RECHECK_INTERVAL_SECS {
            return evaluate_tag(&cached.tag_name, &cached.html_url);
        }
    }

    let Some((owner, repo)) = repo_slug() else {
        return UpdateCheck::Failed(
            "CARGO_PKG_REPOSITORY is not a https://github.com/<owner>/<repo> URL".to_string(),
        );
    };

    let path = format!("/repos/{owner}/{repo}/releases/latest");
    let body = match https_get(GITHUB_API_HOST, &path, outbound).await {
        Ok(body) => body,
        Err(e) => return UpdateCheck::Failed(friendly_fetch_error(&e)),
    };

    let Some(tag) = extract_json_string_field(&body, "tag_name") else {
        return UpdateCheck::Failed("GitHub response had no tag_name field".to_string());
    };
    let html_url = extract_json_string_field(&body, "html_url").unwrap_or("");

    if let Some(path) = cache_path.as_deref() {
        write_cache(path, now, tag, html_url);
    }

    evaluate_tag(tag, html_url)
}

/// Turn a raw HTTP-failure string from [`https_get`] into a clearer message
/// for the two cases that are common and benign here: rate limiting and a
/// repository with no releases yet.
fn friendly_fetch_error(e: &str) -> String {
    if e.contains("HTTP status 403") {
        "GitHub API rate limit hit (403); will retry later".to_string()
    } else if e.contains("HTTP status 404") {
        "repository has no releases yet (404)".to_string()
    } else {
        e.to_string()
    }
}

/// Compare a fetched tag against the running version and build the result.
fn evaluate_tag(tag: &str, html_url: &str) -> UpdateCheck {
    let latest_display = tag.trim_start_matches(['v', 'V']).to_string();
    let html_url = if html_url.is_empty() {
        None
    } else {
        Some(html_url.to_string())
    };

    match compare_versions(env!("CARGO_PKG_VERSION"), tag) {
        Some(Ordering::Less) => UpdateCheck::UpdateAvailable {
            current: env!("CARGO_PKG_VERSION"),
            latest: latest_display,
            html_url,
        },
        Some(Ordering::Greater) => UpdateCheck::AheadOfRelease {
            current: env!("CARGO_PKG_VERSION"),
            latest: latest_display,
        },
        Some(Ordering::Equal) => UpdateCheck::UpToDate,
        None => UpdateCheck::Failed(format!("could not parse version from tag '{tag}'")),
    }
}

// ─── Disk cache ────────────────────────────────────────────────────────────

struct CachedRelease {
    checked_at: u64,
    tag_name: String,
    html_url: String,
}

/// `$XDG_CACHE_HOME/tg-ws-proxy/update_check`, falling back to
/// `$HOME/.cache/tg-ws-proxy/update_check`. Returns `None` when neither
/// environment variable is set (e.g. some minimal service-user setups) —
/// callers degrade to "always check live" in that case, never erroring.
fn cache_file_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))?;
    Some(base.join("tg-ws-proxy").join("update_check"))
}

/// Read and parse the cache file. Any I/O error or malformed/incomplete
/// content is treated as a cache miss, not a hard error — the caller just
/// falls through to a live check.
fn read_cache(path: &Path) -> Option<CachedRelease> {
    let text = std::fs::read_to_string(path).ok()?;

    let mut checked_at = None;
    let mut tag_name = None;
    let mut html_url = None;
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "checked_at" => checked_at = value.trim().parse::<u64>().ok(),
                "tag_name" => tag_name = Some(value.trim().to_string()),
                "html_url" => html_url = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }

    Some(CachedRelease {
        checked_at: checked_at?,
        tag_name: tag_name?,
        html_url: html_url.unwrap_or_default(),
    })
}

/// Best-effort cache write. Failures (read-only filesystem, no permission,
/// ephemeral container storage, ...) are silently ignored — caching is an
/// optimization, not a requirement.
fn write_cache(path: &Path, checked_at: u64, tag_name: &str, html_url: &str) {
    if let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_err()
    {
        return;
    }
    let contents = format!("checked_at={checked_at}\ntag_name={tag_name}\nhtml_url={html_url}\n");
    let _ = std::fs::write(path, contents);
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── GitHub plumbing ─────────────────────────────────────────────────────────

/// Split `CARGO_PKG_REPOSITORY` (e.g. `https://github.com/owner/repo`) into
/// `(owner, repo)`.
fn repo_slug() -> Option<(&'static str, &'static str)> {
    let url = env!("CARGO_PKG_REPOSITORY");
    let rest = url
        .strip_prefix("https://github.com/")
        .or_else(|| url.strip_prefix("http://github.com/"))?;
    let rest = rest.trim_end_matches('/');
    let mut parts = rest.splitn(2, '/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        None
    } else {
        Some((owner, repo))
    }
}

/// Extract the string value of a top-level `"<key>":"<value>"` field from a
/// JSON object without a JSON-parsing crate.
///
/// This is intentionally narrow: it works for the GitHub releases API
/// response (a flat object with plain, unescaped string fields) and is not
/// a general JSON parser.
fn extract_json_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{key}\"");
    let key_pos = json.find(&needle)?;
    let after_key = &json[key_pos + needle.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    let value = after_colon.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(&value[..end])
}

// ─── Version comparison ────────────────────────────────────────────────────

/// Compare two version strings numerically, segment by segment
/// (`1.10.0` > `1.9.0`, unlike a plain string comparison), padding the
/// shorter one with zeros so `1.6` compares equal to `1.6.0`. Returns `None`
/// if either string doesn't start with a numeric segment (e.g. an
/// unexpected API response).
fn compare_versions(current: &str, latest: &str) -> Option<Ordering> {
    let cur = parse_version(current)?;
    let lat = parse_version(latest)?;
    let len = cur.len().max(lat.len());
    for i in 0..len {
        let c = cur.get(i).copied().unwrap_or(0);
        let l = lat.get(i).copied().unwrap_or(0);
        match c.cmp(&l) {
            Ordering::Equal => continue,
            other => return Some(other),
        }
    }
    Some(Ordering::Equal)
}

/// Parse a `MAJOR.MINOR.PATCH`-style string into numeric segments.
///
/// Each dot-separated segment contributes the value of its leading run of
/// ASCII digits (`"2rc1"` → `2`, matching Python's reference
/// `_parse_version_tuple`), so a pre-release suffix glued onto the last
/// numeric segment doesn't break parsing. A segment with no leading digit
/// contributes `0`, *except* the first segment: if the string doesn't even
/// start with a digit (e.g. "latest", "nightly"), it's not a version at
/// all and this returns `None`.
fn parse_version(v: &str) -> Option<Vec<u64>> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    if v.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    for (i, seg) in v.split('.').enumerate() {
        let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            if i == 0 {
                return None;
            }
            parts.push(0);
        } else {
            parts.push(digits.parse::<u64>().unwrap_or(0));
        }
    }
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_tag_name_from_github_release_json() {
        let body = r#"{"url":"https://api.github.com/...","tag_name":"v1.6.2","name":"v1.6.2"}"#;
        assert_eq!(extract_json_string_field(body, "tag_name"), Some("v1.6.2"));
    }

    #[test]
    fn extracts_html_url_alongside_tag_name() {
        let body = r#"{"tag_name":"v1.4.1","html_url":"https://github.com/valnesfjord/tg-ws-proxy-rs/releases/tag/v1.4.1"}"#;
        assert_eq!(
            extract_json_string_field(body, "html_url"),
            Some("https://github.com/valnesfjord/tg-ws-proxy-rs/releases/tag/v1.4.1")
        );
    }

    #[test]
    fn missing_field_returns_none() {
        let body = r#"{"name":"v1.6.2"}"#;
        assert_eq!(extract_json_string_field(body, "tag_name"), None);
    }

    #[test]
    fn parses_plain_semver() {
        assert_eq!(parse_version("1.6.2"), Some(vec![1, 6, 2]));
        assert_eq!(parse_version("v1.6.2"), Some(vec![1, 6, 2]));
    }

    #[test]
    fn parses_version_with_glued_prerelease_suffix() {
        // No separator before "rc1" — a naive whole-segment parse would
        // fail here and silently drop the patch number.
        assert_eq!(parse_version("1.6.2rc1"), Some(vec![1, 6, 2]));
        assert_eq!(parse_version("1.6.2-rc1"), Some(vec![1, 6, 2]));
    }

    #[test]
    fn non_numeric_trailing_segment_becomes_zero() {
        assert_eq!(parse_version("1.6.rc1"), Some(vec![1, 6, 0]));
    }

    #[test]
    fn rejects_strings_that_dont_start_with_a_version() {
        assert_eq!(parse_version("latest"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn compares_versions_numerically_not_lexically() {
        // A plain string compare would get this backwards ("1.10" < "1.9").
        assert_eq!(compare_versions("1.9.0", "1.10.0"), Some(Ordering::Less));
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Some(Ordering::Greater));
        assert_eq!(compare_versions("1.6.2", "1.6.2"), Some(Ordering::Equal));
    }

    #[test]
    fn compares_versions_of_different_length_as_equal_when_padded() {
        assert_eq!(compare_versions("1.6", "1.6.0"), Some(Ordering::Equal));
        assert_eq!(compare_versions("1.6.0", "1.6"), Some(Ordering::Equal));
        assert_eq!(compare_versions("1.6", "1.6.1"), Some(Ordering::Less));
    }

    #[test]
    fn splits_repo_slug_from_github_url() {
        // Mirrors this crate's own Cargo.toml `repository` field shape.
        let url = "https://github.com/valnesfjord/tg-ws-proxy-rs";
        let rest = url.strip_prefix("https://github.com/").unwrap();
        let mut parts = rest.splitn(2, '/');
        assert_eq!(parts.next(), Some("valnesfjord"));
        assert_eq!(parts.next(), Some("tg-ws-proxy-rs"));
    }

    #[test]
    fn cache_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!(
            "tg-ws-proxy-update-check-test-{}",
            std::process::id()
        ));
        let path = dir.join("update_check");

        write_cache(&path, 12345, "v1.4.1", "https://example.com/releases/tag/v1.4.1");
        let cached = read_cache(&path).expect("cache should be readable right after writing");

        assert_eq!(cached.checked_at, 12345);
        assert_eq!(cached.tag_name, "v1.4.1");
        assert_eq!(cached.html_url, "https://example.com/releases/tag/v1.4.1");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_cache_file_is_a_clean_miss() {
        let path = std::env::temp_dir().join("tg-ws-proxy-update-check-does-not-exist");
        let _ = std::fs::remove_file(&path);
        assert!(read_cache(&path).is_none());
    }
}
