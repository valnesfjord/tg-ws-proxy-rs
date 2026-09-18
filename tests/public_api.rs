//! Compile-time guards for the crate's published API.
//!
//! `tg-ws-proxy-rs` is released as a library as well as a binary, so the
//! pre-`_with_outbound` entry points have to keep both their names and their
//! signatures. Nothing here asserts on behavior — the point is that these
//! calls still type-check.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tg_ws_proxy_rs::check::run_check;
use tg_ws_proxy_rs::config::{Config, default_dc_ips, default_dc_overrides};
use tg_ws_proxy_rs::default_domains::fetch_default_domains;
use tg_ws_proxy_rs::outbound::OutboundConnector;
use tg_ws_proxy_rs::pool::WsPool;
use tg_ws_proxy_rs::proxy::handle_client;
use tg_ws_proxy_rs::ws_client::{
    TgWsStream, WsConnectResult, connect_cf_record_with_outbound, connect_cf_worker_ws_for_dc,
    connect_cf_worker_ws_for_dc_with_outbound, connect_cf_ws_for_dc,
    connect_cf_ws_for_dc_with_outbound, connect_ws, connect_ws_for_dc,
};
use tokio::net::{TcpListener, TcpStream};

#[test]
fn old_ws_client_public_signatures_still_compile() {
    let _connect = connect_ws(
        "127.0.0.1",
        "kws2.web.telegram.org",
        false,
        Duration::from_millis(1),
    );
    let _direct_dc = connect_ws_for_dc("127.0.0.1", 2, false, false, Duration::from_millis(1));
    let cf_domains = ["example.net".to_string()];
    let _cf_dc = connect_cf_ws_for_dc(2, &cf_domains, false, false, Duration::from_millis(1));
    let _worker = connect_cf_worker_ws_for_dc(
        "worker.example.dev",
        "149.154.167.51",
        2,
        false,
        false,
        Duration::from_millis(1),
    );

    let outbound = OutboundConnector::direct();
    let _cf_outbound = connect_cf_ws_for_dc_with_outbound(
        2,
        &cf_domains,
        false,
        false,
        Duration::from_millis(1),
        &outbound,
    );
    let _cf_record = connect_cf_record_with_outbound(
        "kws2.example.net",
        false,
        Duration::from_millis(1),
        &outbound,
    );
    let _worker_outbound = connect_cf_worker_ws_for_dc_with_outbound(
        "worker.example.dev",
        "149.154.167.51",
        2,
        false,
        false,
        Duration::from_millis(1),
        &outbound,
    );
}

#[test]
fn old_check_and_pool_public_signatures_still_compile() {
    let config = Config::try_parse_from(["tg-ws-proxy", "--check"]).unwrap();
    let _check = run_check(&config);
    let _pool = WsPool::new(0, Duration::from_secs(55));
}

#[tokio::test]
async fn old_handle_client_public_signature_still_compiles() {
    let config = Config::try_parse_from(["tg-ws-proxy"]).unwrap();
    let pool = Arc::new(WsPool::new(0, Duration::from_secs(55)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr);
    let accepted = listener.accept();
    let (client, accepted) = tokio::join!(client, accepted);
    let _client = client.unwrap();
    let (server, peer) = accepted.unwrap();

    let _future = handle_client(server, peer, std::sync::Arc::new(config), pool);
}

#[test]
fn old_default_domain_helpers_still_compile() {
    let _future = fetch_default_domains();
}

#[test]
fn dc_metadata_maps_still_agree_with_the_single_entry_lookups() {
    // The map-returning helpers are public API; the per-DC lookups the hot
    // path now uses must stay consistent with them.
    let ips = default_dc_ips();
    for dc in [1, 2, 3, 4, 5, 203] {
        assert_eq!(
            tg_ws_proxy_rs::config::default_dc_ip(dc),
            ips.get(&dc).map(String::as_str),
            "default_dc_ip disagrees with default_dc_ips for DC{dc}"
        );
    }

    let overrides = default_dc_overrides();
    for dc in [1, 2, 3, 4, 5, 42, 203] {
        assert_eq!(
            tg_ws_proxy_rs::config::websocket_dc(dc),
            overrides.get(&dc).copied().unwrap_or(dc),
            "websocket_dc disagrees with default_dc_overrides for DC{dc}"
        );
    }
}

#[allow(dead_code)]
fn connected_variant_payload_stays_unboxed(result: WsConnectResult) -> Option<TgWsStream> {
    match result {
        WsConnectResult::Connected(ws) => Some(ws),
        _ => None,
    }
}
