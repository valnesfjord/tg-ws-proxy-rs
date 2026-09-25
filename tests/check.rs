use std::net::SocketAddr;

use clap::Parser;
use tokio::task::JoinHandle;

use tg_ws_proxy_rs::check::run_check_with_outbound;
use tg_ws_proxy_rs::config::Config;

mod common;

use common::{
    await_proxy_request, await_task, await_unit_task, mtproto_acceptor, rejecting_http_proxy,
    silent_mtproto_acceptor, tunneling_http_proxy,
};

/// Build a `--check` config that routes through `proxy_addr` and disables
/// environment proxy discovery so the test is not affected by the host's
/// `HTTPS_PROXY` / `NO_PROXY` settings.
fn check_config(proxy_addr: &str, extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--check",
        "--outbound-proxy",
        proxy_addr,
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--cf-connect-timeout",
        "2",
        "--upstream-connect-timeout",
        "2",
    ];
    args.extend_from_slice(extra);

    // Same normalization the binary applies before running a check.
    Config::try_parse_from(args).unwrap().with_defaults()
}

#[tokio::test]
async fn check_reports_success_when_there_is_nothing_configured() {
    let config = Config::try_parse_from(["tg-ws-proxy", "--check"]).unwrap();
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound, None).await);
}

#[tokio::test]
async fn check_cf_domain_honors_disabled_tls() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &["--cf-domain", "example.net", "--cf-disable-tls"],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, None).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT kws2.example.net:80 HTTP/1.1"));
}

#[tokio::test]
async fn check_cf_worker_probes_the_dc2_tunnel_through_the_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &["--cf-worker-domain", "https://worker.example.dev/"],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, None).await);
    // The scheme and trailing slash are normalized away before the connect.
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT worker.example.dev:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &[
            "--mtproto-proxy",
            "upstream.example:443:00112233445566778899aabbccddeeff",
        ],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, None).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
}

#[tokio::test]
async fn check_upstream_mtproto_successfully_tunnels_through_proxy() {
    let (upstream, upstream_task) = mtproto_acceptor(upstream_secret_bytes()).await;
    let (proxy_addr, proxy_task) = tunneling_http_proxy(upstream).await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &[
            "--mtproto-proxy",
            "upstream.example:443:00112233445566778899aabbccddeeff",
        ],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound, None).await);
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT upstream.example:443 HTTP/1.1"));
    await_unit_task(upstream_task).await;
}

/// The 16 bytes `--mtproto-proxy` is given as hex below, decoded — the secret
/// the fixture upstream has to parse the handshake with.
fn upstream_secret_bytes() -> Vec<u8> {
    vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]
}

#[tokio::test]
async fn check_upstream_mtproto_fails_when_it_never_answers() {
    // An upstream that accepts the handshake and then says nothing, as one
    // whose own route to a data centre is dead does.  Before the probe read a
    // reply it passed, which is exactly the weakness this pins.
    let (upstream, upstream_task) = silent_mtproto_acceptor().await;
    let (proxy_addr, proxy_task) = tunneling_http_proxy(upstream).await;
    let config = check_config(
        &format!("http://{proxy_addr}"),
        &[
            "--mtproto-proxy",
            "upstream.example:443:00112233445566778899aabbccddeeff",
        ],
    );
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, None).await);
    await_proxy_request(proxy_task).await;
    await_unit_task(upstream_task).await;
}

#[tokio::test]
async fn check_fails_fast_on_an_invalid_upstream_secret() {
    // `--mtproto-proxy` validates the hex at parse time, so an odd-length
    // secret must never reach the probe.
    let parsed = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--mtproto-proxy",
        "upstream.example:443:not-hex",
    ]);

    assert!(parsed.is_err());
}

/// A `--check --check-listener` config with every connect timeout at a second,
/// so a probe that has to give up costs seconds instead of the sum of the
/// defaults, and with proxy discovery off so the host's environment cannot
/// change the outcome.
fn listener_config(extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--check",
        "--check-listener",
        "--no-outbound-proxy",
        "--handshake-timeout",
        "1",
        "--ws-connect-timeout",
        "1",
        "--cf-connect-timeout",
        "1",
        "--upstream-connect-timeout",
        "1",
        "--tcp-fallback-timeout",
        "1",
    ];
    args.extend_from_slice(extra);
    Config::try_parse_from(args).unwrap().with_defaults()
}

/// A fake listener speaking the server half of the transport with the crate's
/// own parsing and cipher construction: it reads the client handshake,
/// decrypts the request with `clt_dec`, and answers with a `resPQ` frame
/// encrypted with `clt_enc`.
///
/// That is what pins the round trip.  A swapped `enc`/`dec`, a wrong
/// constructor offset or a mis-framed request fails here rather than only on a
/// real network.
async fn res_pq_listener(secret: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        common::answer_res_pq(&mut stream, &secret).await;
    });

    (addr, task)
}

/// A listener that answers with `resPQ` is a pass — the round trip the probe
/// exists for.
#[tokio::test]
async fn check_listener_reports_ok_when_the_listener_answers() {
    let config = listener_config(&["--secret", "00112233445566778899aabbccddeeff"]);
    let (addr, server) = res_pq_listener(config.secret_bytes()).await;
    let outbound = config.outbound_connector().unwrap();

    assert!(run_check_with_outbound(&config, &outbound, Some(addr)).await);
    await_task(server).await;
}

/// A listener that accepts the connection and never answers is a failure: a
/// handshake that was merely accepted is not a working proxy.
#[tokio::test]
async fn check_listener_fails_when_nothing_answers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let held = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        // Hold the connection open, so the probe has to time out instead of
        // reading a close.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    });

    let config = listener_config(&["--secret", "00112233445566778899aabbccddeeff"]);
    let outbound = config.outbound_connector().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, Some(addr)).await);
    held.abort();
}

/// A FakeTLS listener is skipped rather than failed — the plain probe cannot
/// speak to it — but a run whose only probe was skipped has verified nothing,
/// so it must not report success.
#[tokio::test]
async fn check_listener_skips_a_faketls_listener_and_fails_the_run() {
    let config = listener_config(&[
        "--listen-faketls-domain",
        "www.example.com",
        "--secret",
        "ee00112233445566778899aabbccddeeff7777772e6578616d706c652e636f6d",
    ]);
    let outbound = config.outbound_connector().unwrap();
    // Never dialled: the FakeTLS branch is decided before the probe connects.
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

    assert!(!run_check_with_outbound(&config, &outbound, Some(addr)).await);
}
