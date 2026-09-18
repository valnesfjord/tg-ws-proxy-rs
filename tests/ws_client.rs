use std::time::Duration;

use tg_ws_proxy_rs::outbound::OutboundConnector;
use tg_ws_proxy_rs::ws_client::{
    WsConnectResult, cf_worker_path, cf_ws_domains, connect_cf_worker_ws_for_dc_with_outbound,
    connect_cf_worker_ws_for_dc_with_outbound_and_ips, connect_cf_ws_for_dc_with_outbound,
    connect_ws_for_dc_with_outbound, connect_ws_with_outbound, ws_domains,
};

mod common;

use common::{await_proxy_request, rejecting_http_proxy};

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

// ─── Domain construction ─────────────────────────────────────────────────────

#[test]
fn ws_domains_prefer_the_base_record_and_media_the_dash_one_variant() {
    assert_eq!(
        ws_domains(2, false),
        ["kws2.web.telegram.org", "kws2-1.web.telegram.org"]
    );
    assert_eq!(
        ws_domains(2, true),
        ["kws2-1.web.telegram.org", "kws2.web.telegram.org"]
    );
}

#[test]
fn ws_domains_remap_dc_203_so_telegrams_certificate_still_matches() {
    // DC 203 has no WebSocket hostname of its own; the wildcard certificate
    // only covers the real DC numbers, so the domain must say kws2.
    assert_eq!(
        ws_domains(203, false),
        ["kws2.web.telegram.org", "kws2-1.web.telegram.org"]
    );
}

#[test]
fn cf_ws_domains_keep_the_raw_dc_number_and_domain_priority() {
    // Unlike ws_domains, CF records are user-managed, so DC 203 must NOT be
    // remapped — kws203.{domain} is a distinct record pointing at a different
    // server.
    assert_eq!(
        cf_ws_domains(203, &["a.example".to_string()], false),
        ["kws203.a.example", "kws203-1.a.example"]
    );

    // Multiple domains are tried in the order given, both records each.
    assert_eq!(
        cf_ws_domains(2, &["a.example".to_string(), "b.example".to_string()], true),
        [
            "kws2-1.a.example",
            "kws2.a.example",
            "kws2-1.b.example",
            "kws2.b.example",
        ]
    );
}

#[test]
fn cf_ws_domains_are_empty_without_configured_domains() {
    assert!(cf_ws_domains(2, &[], false).is_empty());
}

#[test]
fn cf_worker_path_carries_destination_dc_and_media_flag() {
    // The Worker is a TCP tunnel: dst tells it which Telegram DC IP to open,
    // while dc/media are kept for compatibility with the Python Worker code.
    assert_eq!(
        cf_worker_path("149.154.167.51", 2, true),
        "/apiws?dst=149.154.167.51&dc=2&media=1"
    );
    assert_eq!(
        cf_worker_path("149.154.167.51", 2, false),
        "/apiws?dst=149.154.167.51&dc=2&media=0"
    );
}

// ─── Outbound proxy routing ──────────────────────────────────────────────────

#[tokio::test]
async fn ws_client_connects_through_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let result = connect_ws_with_outbound(
        "203.0.113.10",
        "kws2.web.telegram.org",
        false,
        PROBE_TIMEOUT,
        &outbound,
        None,
    )
    .await;

    match result {
        WsConnectResult::Failed(reason) => {
            assert!(reason.contains("HTTP proxy"));
            assert!(reason.contains("407"));
        }
        other => panic!("expected proxy failure, got {other:?}"),
    }

    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 203.0.113.10:443 HTTP/1.1"));
}

#[tokio::test]
async fn telegram_ws_dc_connector_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let attempt = connect_ws_for_dc_with_outbound(
        "203.0.113.10",
        2,
        false,
        false,
        PROBE_TIMEOUT,
        &outbound,
        None,
    )
    .await;

    assert!(attempt.ws.is_none());
    // A rejected CONNECT is a hard failure, not a redirect and not a timeout —
    // the distinction drives which fallback the proxy reaches for next.
    assert!(!attempt.all_redirects);
    assert!(!attempt.upgrade_timed_out);
    assert!(!attempt.connect_timed_out);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 203.0.113.10:443 HTTP/1.1"));
}

#[tokio::test]
async fn cloudflare_ws_connector_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let (ws, _record, all_redirects) = connect_cf_ws_for_dc_with_outbound(
        2,
        &["example.net".to_string()],
        false,
        false,
        PROBE_TIMEOUT,
        &outbound,
    )
    .await;

    assert!(ws.is_none());
    assert!(!all_redirects);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT kws2.example.net:443 HTTP/1.1"));
}

#[tokio::test]
async fn cloudflare_ws_connector_tries_every_record_of_every_domain() {
    // Two CF domains × the kwsN / kwsN-1 record pair = four attempts before
    // the caller is told the whole CF tier failed.
    let (proxy_addr, proxy_task) = common::rejecting_http_proxy_requests().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let (ws, _record, _all_redirects) = connect_cf_ws_for_dc_with_outbound(
        2,
        &["a.example".to_string(), "b.example".to_string()],
        false,
        false,
        PROBE_TIMEOUT,
        &outbound,
    )
    .await;

    assert!(ws.is_none());
    let requests = common::await_proxy_requests(proxy_task).await;
    let targets: Vec<&str> = requests
        .iter()
        .filter_map(|r| r.split_whitespace().nth(1))
        .collect();
    assert_eq!(
        targets,
        [
            "kws2.a.example:443",
            "kws2-1.a.example:443",
            "kws2.b.example:443",
            "kws2-1.b.example:443",
        ]
    );
}

#[tokio::test]
async fn cloudflare_worker_connector_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let ws = connect_cf_worker_ws_for_dc_with_outbound(
        "worker.example.dev",
        "149.154.167.51",
        2,
        false,
        false,
        PROBE_TIMEOUT,
        &outbound,
    )
    .await;

    assert!(ws.is_none());
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT worker.example.dev:443 HTTP/1.1"));
}

#[tokio::test]
async fn cf_ip_ipv6_uses_a_bracketed_http_connect_authority() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();
    let ips = ["2001:db8::10".parse().unwrap()];

    let ws = connect_cf_worker_ws_for_dc_with_outbound_and_ips(
        "worker.example.dev",
        "149.154.167.51",
        2,
        false,
        false,
        PROBE_TIMEOUT,
        &outbound,
        &ips,
    )
    .await;

    assert!(ws.is_none());
    let request = await_proxy_request(proxy_task).await;
    assert!(
        request.starts_with("CONNECT [2001:db8::10]:443 HTTP/1.1"),
        "unexpected IPv6 CONNECT authority: {request:?}"
    );
}
