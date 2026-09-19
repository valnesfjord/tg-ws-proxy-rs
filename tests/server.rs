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
