use std::time::Duration;

use clap::Parser;
use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::server;

fn test_config(port: u16) -> Config {
    Config::try_parse_from([
        "tg-ws-proxy",
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--link-ip",
        "127.0.0.1",
        "--quiet",
        "--pool-size",
        "0",
    ])
    .unwrap()
    .with_defaults()
}

#[tokio::test]
async fn run_binds_then_stops_on_shutdown() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        server::run_with_listen(
            // Port 0 instead of a port a throwaway listener just released:
            // on a loaded CI runner something else can grab it in between.
            test_config(0),
            async {
                let _ = shutdown_rx.await;
            },
            move |info| {
                let _ = listen_tx.send(info);
            },
        )
        .await
    });

    let info = tokio::time::timeout(Duration::from_secs(5), listen_rx)
        .await
        .expect("server did not bind in time")
        .expect("listen callback dropped");

    assert_ne!(info.addr.port(), 0);
    assert!(info.socks_addr.is_none());
    assert!(
        info.tg_link
            .starts_with("tg://proxy?server=127.0.0.1&port="),
        "unexpected link: {}",
        info.tg_link
    );
    assert!(info.tg_link.contains(&format!("port={}", info.addr.port())));

    tokio::net::TcpStream::connect(info.addr)
        .await
        .expect("listener should accept connections");

    shutdown_tx.send(()).unwrap();
    server
        .await
        .expect("server task panicked")
        .expect("server returned an error");

    tokio::net::TcpListener::bind(info.addr)
        .await
        .expect("port should be released after stop");
}

#[tokio::test]
async fn run_refuses_to_start_on_a_pinned_but_unconfigured_tier() {
    // Pinning a class to a tier nothing configures would drop every one of
    // its connections at runtime; startup is the place to say so.
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--quiet",
        "--pinned-media-upstream",
        "cfproxy",
    ])
    .unwrap()
    .with_defaults();

    let err = server::run(config, std::future::pending())
        .await
        .unwrap_err();
    assert!(
        matches!(err, server::RunError::InvalidPin(_)),
        "expected InvalidPin, got {err:?}"
    );
}

#[tokio::test]
async fn port_zero_reports_the_real_bound_port_in_the_link() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel();

    let server = tokio::spawn(async move {
        server::run_with_listen(
            test_config(0),
            async {
                let _ = shutdown_rx.await;
            },
            move |info| {
                let _ = listen_tx.send(info);
            },
        )
        .await
    });

    let info = tokio::time::timeout(Duration::from_secs(5), listen_rx)
        .await
        .expect("server did not bind in time")
        .expect("listen callback dropped");

    assert_ne!(info.addr.port(), 0);
    assert!(
        info.tg_link.contains(&format!("port={}", info.addr.port())),
        "link should use the bound port, got {}",
        info.tg_link
    );

    shutdown_tx.send(()).unwrap();
    server
        .await
        .expect("server task panicked")
        .expect("server returned an error");
}

/// `--check-listener` serves, probes the socket it just bound, and stops with
/// the check's verdict: the accept loop has to end on it rather than keep
/// serving, and the exit code has to be the check's.
#[tokio::test]
async fn check_listener_mode_stops_with_the_check_verdict() {
    // A FakeTLS listener is skipped, so this run verifies nothing and has to
    // fail — which is also the cheapest way to reach the verdict, with no
    // network involved.
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check-listener",
        "--no-outbound-proxy",
        "--host",
        "127.0.0.1",
        "--port",
        "0",
        "--quiet",
        "--pool-size",
        "0",
        "--listen-faketls-domain",
        "www.example.com",
        "--secret",
        "ee00112233445566778899aabbccddeeff7777772e6578616d706c652e636f6d",
    ])
    .unwrap()
    .with_defaults();

    let result = server::run_with_listen(config, std::future::pending(), |_| {}).await;

    assert!(matches!(result, Err(server::RunError::CheckFailed)));
}

#[tokio::test]
async fn socks_listener_is_optional_shares_limit_and_releases_port_on_shutdown() {
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (listen_tx, listen_rx) = tokio::sync::oneshot::channel();
    let mut config = test_config(0);
    config.socks_enabled = true;
    config.socks_port = 0;
    config.max_connections = Some(1);
    let task = tokio::spawn(server::run_with_listen(
        config,
        async {
            let _ = shutdown_rx.await;
        },
        move |info| {
            let _ = listen_tx.send(info);
        },
    ));
    let info = listen_rx.await.unwrap();
    let socks = info.socks_addr.unwrap();
    let mut client = tokio::net::TcpStream::connect(socks).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
    // The second SOCKS greeting cannot be served until the first handler
    // releases the shared permit. Unlike an invalid MTProto handshake, a
    // SOCKS greeting has an observable reply when it actually gets accepted.
    let mut second = tokio::net::TcpStream::connect(socks).await.unwrap();
    second.write_all(&[5, 1, 0]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), second.read_u8())
            .await
            .is_err()
    );
    drop(client);
    tokio::time::timeout(Duration::from_secs(3), second.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [5, 0]);
    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::net::TcpListener::bind(socks).await.unwrap();
    drop(second);
}

#[tokio::test]
async fn socks_bind_failure_is_reported_before_ready_callback() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = test_config(0);
    config.socks_enabled = true;
    config.socks_port = occupied.local_addr().unwrap().port();
    let result = server::run_with_listen(config, std::future::pending(), |_| {
        panic!("server must not signal ready after a SOCKS bind failure")
    })
    .await;
    assert!(matches!(result, Err(server::RunError::Bind { .. })));
}

#[test]
fn connection_links_describe_every_enabled_listener_without_binding() {
    let secret = "00112233445566778899aabbccddeeff";
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--host",
        "0.0.0.0",
        "--port",
        "1443",
        "--link-ip",
        "192.168.1.1",
        "--secret",
        &format!("{secret},ffeeddccbbaa99887766554433221100"),
        "--socks-enabled",
        "--socks-host",
        "0.0.0.0",
        "--socks-port",
        "1081",
    ])
    .unwrap();
    assert_eq!(
        server::connection_links(&config).unwrap(),
        [
            format!("MTProto\tTelegram\ttg://proxy?server=192.168.1.1&port=1443&secret=dd{secret}"),
            "MTProto\tTelegram\ttg://proxy?server=192.168.1.1&port=1443\
             &secret=ddffeeddccbbaa99887766554433221100"
                .to_string(),
            "SOCKS5\tRouter service\tsocks5://127.0.0.1:1081".to_string(),
            "SOCKS5\tTelegram\ttg://socks?server=192.168.1.1&port=1081".to_string(),
        ]
    );

    // No other device can reach a loopback SOCKS listener, so no tg:// link.
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--host",
        "0.0.0.0",
        "--secret",
        secret,
        "--socks-enabled",
    ])
    .unwrap();
    let links = server::connection_links(&config).unwrap();
    assert_eq!(links.len(), 2, "{links:?}");
    assert_eq!(links[1], "SOCKS5\tRouter service\tsocks5://127.0.0.1:1080");
}
