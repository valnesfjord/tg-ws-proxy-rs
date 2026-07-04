use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tg_ws_proxy_rs::check::run_check_with_outbound;
use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::crypto::{ProtoTag, generate_client_handshake};
use tg_ws_proxy_rs::default_domains::fetch_default_domains_with_outbound;
use tg_ws_proxy_rs::outbound::OutboundConnector;
use tg_ws_proxy_rs::pool::WsPool;
use tg_ws_proxy_rs::proxy::handle_client_with_runtime;
use tg_ws_proxy_rs::runtime::Runtime;
use tg_ws_proxy_rs::ws_client::{
    WsConnectResult, connect_cf_worker_ws_for_dc_with_outbound, connect_cf_ws_for_dc_with_outbound,
    connect_ws_for_dc_with_outbound, connect_ws_with_outbound,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn ws_client_connects_through_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();
    let result = connect_ws_with_outbound(
        "203.0.113.10",
        "kws2.web.telegram.org",
        false,
        Duration::from_secs(2),
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

    let (ws, all_redirects, _timed_out) = connect_ws_for_dc_with_outbound(
        "203.0.113.10",
        2,
        false,
        false,
        Duration::from_secs(2),
        &outbound,
        None,
    )
    .await;

    assert!(ws.is_none());
    assert!(!all_redirects);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 203.0.113.10:443 HTTP/1.1"));
}

#[tokio::test]
async fn cloudflare_ws_connector_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let (ws, all_redirects) = connect_cf_ws_for_dc_with_outbound(
        2,
        &["example.net".to_string()],
        false,
        false,
        Duration::from_secs(2),
        &outbound,
    )
    .await;

    assert!(ws.is_none());
    assert!(!all_redirects);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT kws2.example.net:443 HTTP/1.1"));
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
        Duration::from_secs(2),
        &outbound,
    )
    .await;

    assert!(ws.is_none());
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT worker.example.dev:443 HTTP/1.1"));
}

#[tokio::test]
async fn default_domain_fetch_attempts_github_through_outbound_proxy_before_fallback() {
    install_rustls_provider();

    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let outbound =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();

    let domains = fetch_default_domains_with_outbound(&outbound).await;

    assert!(!domains.is_empty());
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT raw.githubusercontent.com:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_cf_domain_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--cf-domain",
        "example.net",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--cf-connect-timeout",
        "2",
    ])
    .unwrap();
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT kws2.example.net:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--mtproto-proxy",
        "upstream.example:443:00112233445566778899aabbccddeeff",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--upstream-connect-timeout",
        "2",
    ])
    .unwrap();
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_successfully_tunnels_through_proxy() {
    let (upstream, upstream_task) = mtproto_acceptor().await;
    let (proxy_addr, proxy_task) = tunneling_http_proxy(upstream).await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--mtproto-proxy",
        "upstream.example:443:00112233445566778899aabbccddeeff",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--upstream-connect-timeout",
        "2",
    ])
    .unwrap();
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
    await_unit_task(upstream_task).await;
}

#[tokio::test]
async fn proxy_upstream_fallback_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests(2).await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--mtproto-proxy",
        "upstream.example:443:00112233445566778899aabbccddeeff",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--handshake-timeout",
        "2",
        "--upstream-connect-timeout",
        "2",
        "--tcp-fallback-timeout",
        "1",
    ])
    .unwrap();

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("CONNECT upstream.example:443 HTTP/1.1")),
        "expected upstream fallback CONNECT, got {requests:?}"
    );
}

#[tokio::test]
async fn proxy_tcp_fallback_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--handshake-timeout",
        "2",
        "--tcp-fallback-timeout",
        "2",
    ])
    .unwrap();

    run_proxy_once(config).await;

    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 149.154.167.51:443 HTTP/1.1"));
}

#[tokio::test]
async fn proxy_tries_fronting_before_tcp_fallback_when_dc_ip_is_unconfigured() {
    // Regression test for issue #81: fronting was only wired into the
    // `--dc-ip`-configured branch, making it unreachable for the far more
    // common case of relying solely on --cf-domain/--default-domains (which
    // suppresses the built-in --dc-ip defaults, see Config::from_args).
    // With no CF domain/worker/upstream proxy configured, WS trying to reach
    // Telegram directly is expected to fail (no real DC connectivity in this
    // test), so the flow should now attempt a fronted WS connect (SNI
    // override) before falling through to the plain TCP fallback below it —
    // both attempts open a fresh outbound TCP connection, so the rejecting
    // proxy should see exactly 2 CONNECT requests instead of 1.
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests(2).await;
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        "--fronting-domain",
        "sprinthost.ru",
        "--outbound-proxy",
        &format!("http://{proxy_addr}"),
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--handshake-timeout",
        "2",
        "--ws-connect-timeout",
        "2",
        "--tcp-fallback-timeout",
        "2",
    ])
    .unwrap();

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        requests.len(),
        2,
        "expected a fronting attempt followed by the TCP fallback, got {requests:?}"
    );
    assert!(
        requests
            .iter()
            .all(|r| r.starts_with("CONNECT 149.154.167.51:443 HTTP/1.1")),
        "both attempts should target the same fallback DC IP, got {requests:?}"
    );
}

async fn rejecting_http_proxy() -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
    let (addr, task) = rejecting_http_proxy_requests(1).await;
    let task = tokio::spawn(async move { await_proxy_requests(task).await.remove(0) });
    (addr, task)
}

async fn rejecting_http_proxy_requests(
    expected: usize,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<Vec<String>>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for _ in 0..expected {
            let (mut inbound, _) = proxy.accept().await.unwrap();
            let request = read_http_connect_request(&mut inbound).await;
            inbound
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
            requests.push(request);
        }
        requests
    });

    (proxy_addr, proxy_task)
}

async fn await_proxy_request(proxy_task: tokio::task::JoinHandle<String>) -> String {
    tokio::time::timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task panicked")
}

async fn await_proxy_requests(proxy_task: tokio::task::JoinHandle<Vec<String>>) -> Vec<String> {
    tokio::time::timeout(Duration::from_secs(2), proxy_task)
        .await
        .expect("proxy task timed out")
        .expect("proxy task panicked")
}

async fn tunneling_http_proxy(
    target: std::net::SocketAddr,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<String>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let request = read_http_connect_request(&mut inbound).await;
        inbound.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();

        let outbound = TcpStream::connect(target).await.unwrap();
        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = tokio::io::split(outbound);
        let _ = tokio::join!(
            tokio::io::copy(&mut ri, &mut wo),
            tokio::io::copy(&mut ro, &mut wi)
        );

        request
    });

    (proxy_addr, proxy_task)
}

async fn mtproto_acceptor() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut handshake = [0u8; 64];
        stream.read_exact(&mut handshake).await.unwrap();
    });
    (addr, task)
}

async fn read_http_connect_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&request).to_string()
}

async fn run_proxy_once(config: Config) {
    let secret = config.secret_bytes();
    let outbound = config.outbound_connector().unwrap();
    let runtime = Arc::new(Runtime::new(outbound).with_fronting(
        config.fronting_domain.clone(),
        Duration::from_secs(config.fronting_cooldown),
    ));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(config.pool_max_age),
        Arc::clone(&runtime),
    ));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr);
    let accept = listener.accept();
    let (client, accepted) = tokio::join!(client, accept);
    let mut client = client.unwrap();
    let (server, peer) = accepted.unwrap();

    let proxy_task = tokio::spawn(handle_client_with_runtime(
        server, peer, config, pool, runtime,
    ));
    let (handshake, _, _) = generate_client_handshake(&secret, 2, ProtoTag::PaddedIntermediate);
    client.write_all(&handshake).await.unwrap();
    drop(client);

    tokio::time::timeout(Duration::from_secs(5), proxy_task)
        .await
        .unwrap()
        .unwrap();
}

async fn await_unit_task(task: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("test helper task timed out")
        .expect("test helper task panicked");
}

fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
