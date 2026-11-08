use std::sync::Mutex;
use std::time::Duration;

use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::outbound::OutboundConnector;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn parses_http_proxy_with_auth() {
    let connector = OutboundConnector::from_config(
        Some("http://user:p%40ss@example.local:3128/"),
        Some("localhost,.internal"),
        true,
    )
    .unwrap();

    assert_eq!(
        connector.summary().as_deref(),
        Some("http://user:***@example.local:3128")
    );
}

#[test]
fn parses_socks_proxy_with_default_port() {
    let connector =
        OutboundConnector::from_config(Some("socks5://user:pass@example.local"), None, false)
            .unwrap();

    assert_eq!(
        connector.summary().as_deref(),
        Some("socks5://user:***@example.local:1080")
    );
}

#[test]
fn proxy_url_password_without_username_is_rejected() {
    let err = match OutboundConnector::from_config(
        Some("http://:pass@example.local:3128"),
        None,
        false,
    ) {
        Ok(_) => panic!("password without username should fail"),
        Err(err) => err,
    };

    assert!(err.contains("password requires a username"));
}

#[test]
fn parses_bracketed_ipv6_proxy_url() {
    let connector = OutboundConnector::from_config(Some("http://[::1]:3128"), None, false).unwrap();

    assert_eq!(connector.summary().as_deref(), Some("http://[::1]:3128"));
}

#[test]
fn proxy_url_rejects_path_query_and_fragment() {
    for url in [
        "http://proxy.example:3128/path",
        "http://proxy.example:3128?query=1",
        "http://proxy.example:3128#fragment",
    ] {
        let err = match OutboundConnector::from_config(Some(url), None, false) {
            Ok(_) => panic!("proxy URL with path/query/fragment should fail"),
            Err(err) => err,
        };
        assert!(err.contains("must not include a path"));
    }
}

#[test]
fn direct_marker_disables_proxy() {
    let connector = OutboundConnector::from_config(Some("direct"), None, true).unwrap();

    assert_eq!(connector.summary(), None);
}

#[test]
fn env_https_proxy_falls_back_to_supported_http_proxy() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_proxy_env(
        [
            ("HTTPS_PROXY", Some("https://secure-proxy.example:8443")),
            ("HTTP_PROXY", Some("http://plain-proxy.example:3128")),
        ],
        || {
            let connector = OutboundConnector::from_config(None, None, true).unwrap();
            assert_eq!(
                connector.summary().as_deref(),
                Some("http://plain-proxy.example:3128")
            );
        },
    );
}

#[test]
fn env_unsupported_proxy_errors_when_no_supported_fallback_exists() {
    let _guard = ENV_LOCK.lock().unwrap();
    with_proxy_env(
        [("HTTPS_PROXY", Some("https://secure-proxy.example:8443"))],
        || {
            let err = match OutboundConnector::from_config(None, None, true) {
                Ok(_) => panic!("unsupported env proxy should fail without a fallback"),
                Err(err) => err,
            };
            assert!(err.contains("no supported outbound proxy URL"));
            assert!(err.contains("HTTPS_PROXY"));
        },
    );
}

#[test]
fn disabled_proxy_ignores_malformed_no_proxy() {
    let connector =
        OutboundConnector::from_config(Some("direct"), Some("example.com:abc"), true).unwrap();
    assert_eq!(connector.summary(), None);

    let connector = OutboundConnector::from_config(None, Some("example.com:abc"), false).unwrap();
    assert_eq!(connector.summary(), None);
}

#[test]
fn disabled_proxy_cli_ignores_malformed_no_proxy() {
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--no-outbound-proxy",
        "--no-proxy",
        "example.com:abc",
    ])
    .unwrap();

    assert!(config.outbound_connector().unwrap().summary().is_none());
}

#[test]
fn direct_proxy_cli_ignores_malformed_no_proxy() {
    let config = Config::try_parse_from([
        "tg-ws-proxy",
        "--check",
        "--outbound-proxy",
        "direct",
        "--no-proxy",
        "example.com:abc",
    ])
    .unwrap();

    assert!(config.outbound_connector().unwrap().summary().is_none());
}

#[test]
fn malformed_no_proxy_entries_are_rejected() {
    for no_proxy in [
        "example.com:abc",
        "[2001:db8::1",
        "https://example.com",
        "2001:db8::1:zz",
        "bad_host.example",
        "example..com",
        "-example.com",
        "example-.com",
    ] {
        let err = match OutboundConnector::from_config(
            Some("http://proxy.example:3128"),
            Some(no_proxy),
            false,
        ) {
            Ok(_) => panic!("malformed NO_PROXY entry should fail"),
            Err(err) => err,
        };
        assert!(err.contains("NO_PROXY"));
    }
}

#[test]
fn no_proxy_accepts_standard_hosts_ports_suffixes_and_cidr() {
    let connector = OutboundConnector::from_config(
        Some("http://proxy.example:3128"),
        Some("localhost,.example.com,*.internal,example.net:443,127.0.0.0/8,[2001:db8::1]:443"),
        false,
    )
    .unwrap();

    assert_eq!(
        connector.summary().as_deref(),
        Some("http://proxy.example:3128")
    );
}

#[test]
fn proxy_url_parse_errors_do_not_leak_userinfo() {
    let err = match OutboundConnector::from_config(
        Some("http://user:super-secret@example.local:bad"),
        None,
        true,
    ) {
        Ok(_) => panic!("invalid proxy URL should fail"),
        Err(err) => err,
    };

    assert!(!err.contains("user"));
    assert!(!err.contains("super-secret"));
    assert!(!err.contains("example.local"));
    assert!(err.contains("invalid outbound proxy URL"));
}

#[tokio::test]
async fn http_connect_proxy_tunnels_bytes() {
    let (target, target_task) = echo_server().await;
    let (proxy, proxy_task) = http_proxy(target, b"HTTP/1.1 200 OK\r\n\r\n").await;

    let connector =
        OutboundConnector::from_config(Some(&format!("http://user:p%40ss@{proxy}")), None, false)
            .unwrap();
    let mut stream = connector
        .connect(
            &target.ip().to_string(),
            target.port(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();

    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    drop(stream);

    await_task(target_task).await;
    await_task(proxy_task).await;
}

#[tokio::test]
async fn http_connect_rejects_bad_status() {
    let (proxy, proxy_task) = http_proxy(
        "127.0.0.1:9".parse().unwrap(),
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
    )
    .await;

    let connector =
        OutboundConnector::from_config(Some(&format!("http://{proxy}")), None, false).unwrap();
    let err = connector
        .connect("example.local", 443, Duration::from_secs(2))
        .await
        .unwrap_err();

    assert!(err.reason.contains("HTTP code is not equal 200: 407"));
    await_task(proxy_task).await;
}

#[tokio::test]
async fn no_proxy_bypasses_configured_proxy() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector = OutboundConnector::from_config(
        Some("http://127.0.0.1:9"),
        Some(&format!("{}:{}", target.ip(), target.port())),
        true,
    )
    .unwrap();

    let mut stream = connector
        .connect(
            &target.ip().to_string(),
            target.port(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_cidr_bypasses_configured_proxy() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector =
        OutboundConnector::from_config(Some("http://127.0.0.1:9"), Some("127.0.0.0/8"), false)
            .unwrap();

    let mut stream = connector
        .connect("127.0.0.1", target.port(), Duration::from_secs(2))
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_suffix_bypasses_configured_proxy() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector =
        OutboundConnector::from_config(Some("http://127.0.0.1:9"), Some(".localhost"), false)
            .unwrap();

    let mut stream = connector
        .connect("api.localhost", target.port(), Duration::from_secs(2))
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_bare_domain_matches_subdomains_by_standard_semantics() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector =
        OutboundConnector::from_config(Some("http://127.0.0.1:9"), Some("localhost"), false)
            .unwrap();

    let mut stream = connector
        .connect("api.localhost", target.port(), Duration::from_secs(2))
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_wildcard_bypasses_configured_proxy() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector =
        OutboundConnector::from_config(Some("http://127.0.0.1:9"), Some("*"), false).unwrap();

    let mut stream = connector
        .connect("127.0.0.1", target.port(), Duration::from_secs(2))
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_ipv6_port_bypasses_configured_proxy() {
    let Ok((target, target_task)) = ipv6_one_shot_server(b"direct").await else {
        return;
    };
    let connector = OutboundConnector::from_config(
        Some("http://127.0.0.1:9"),
        Some(&format!("[::1]:{}", target.port())),
        true,
    )
    .unwrap();

    let mut stream = connector
        .connect("::1", target.port(), Duration::from_secs(2))
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_host_port_match_bypasses_non_http_target() {
    let (target, target_task) = one_shot_server(b"direct").await;
    let connector = OutboundConnector::from_config(
        Some("http://127.0.0.1:9"),
        Some(&format!("{}:{}", target.ip(), target.port())),
        true,
    )
    .unwrap();

    let mut stream = connector
        .connect(
            &target.ip().to_string(),
            target.port(),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"direct");
    await_task(target_task).await;
}

#[tokio::test]
async fn no_proxy_host_port_does_not_bypass_different_port() {
    let (proxy, proxy_task) = http_proxy(
        "127.0.0.1:9".parse().unwrap(),
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
    )
    .await;
    let connector = OutboundConnector::from_config(
        Some(&format!("http://{proxy}")),
        Some("example.local:80"),
        true,
    )
    .unwrap();

    let err = connector
        .connect("example.local", 443, Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(err.reason.contains("407"));
    await_task(proxy_task).await;
}

#[tokio::test]
async fn explicit_empty_no_proxy_overrides_env_bypass() {
    let (proxy, proxy_task) = http_proxy(
        "127.0.0.1:9".parse().unwrap(),
        b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
    )
    .await;

    let connector = {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut connector = None;
        with_proxy_env([("NO_PROXY", Some("*"))], || {
            connector = Some(
                OutboundConnector::from_config(Some(&format!("http://{proxy}")), Some(""), true)
                    .unwrap(),
            );
        });
        connector.unwrap()
    };

    let err = connector
        .connect("example.local", 443, Duration::from_secs(2))
        .await
        .unwrap_err();

    assert!(err.reason.contains("407"));
    await_task(proxy_task).await;
}

#[tokio::test]
async fn proxy_handshake_uses_one_deadline() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (_inbound, _) = proxy.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let connector =
        OutboundConnector::from_config(Some(&format!("http://{proxy_addr}")), None, false).unwrap();
    let start = std::time::Instant::now();
    let err = connector
        .connect("example.local", 443, Duration::from_millis(200))
        .await
        .unwrap_err();

    assert!(err.reason.contains("handshake timed out"));
    assert!(start.elapsed() < Duration::from_secs(1));
    proxy_task.abort();
    assert!(proxy_task.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn socks5h_proxy_authenticates_and_tunnels_domain_target() {
    let (target, target_task) = echo_server().await;
    let (proxy, proxy_task) = socks5_proxy(target, SocksMode::RemoteDnsWithAuth).await;

    let connector =
        OutboundConnector::from_config(Some(&format!("socks5h://user:pass@{proxy}")), None, false)
            .unwrap();
    let mut stream = connector
        .connect("example.local", target.port(), Duration::from_secs(2))
        .await
        .unwrap();

    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    drop(stream);

    await_task(target_task).await;
    await_task(proxy_task).await;
}

#[tokio::test]
async fn socks5_proxy_uses_local_dns() {
    let (target, target_task) = echo_server().await;
    let (proxy, proxy_task) = socks5_proxy(target, SocksMode::LocalDnsNoAuth).await;

    let connector =
        OutboundConnector::from_config(Some(&format!("socks5://{proxy}")), None, false).unwrap();
    let mut stream = connector
        .connect("localhost", target.port(), Duration::from_secs(2))
        .await
        .unwrap();

    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    drop(stream);

    await_task(target_task).await;
    await_task(proxy_task).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn outbound_mark_covers_direct_proxy_and_no_proxy_connections() {
    let probe = tokio::net::TcpSocket::new_v4().unwrap();
    let can_mark = match socket2::SockRef::from(&probe).set_mark(0x1234) {
        Ok(()) => true,
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            false
        }
    };
    for mode in ["direct", "http", "socks5", "socks5h", "no_proxy"] {
        let (target, target_task) = echo_server().await;
        let (proxy_url, proxy_task) = match mode {
            "http" => {
                let (proxy, task) = http_proxy(target, b"HTTP/1.1 200 OK\r\n\r\n").await;
                (Some(format!("http://{proxy}")), Some(task))
            }
            "socks5" | "socks5h" => {
                let auth = if mode == "socks5h" {
                    SocksMode::RemoteDnsWithAuth
                } else {
                    SocksMode::LocalDnsNoAuth
                };
                let (proxy, task) = socks5_proxy(target, auth).await;
                let credentials = if mode == "socks5h" { "user:pass@" } else { "" };
                (Some(format!("{mode}://{credentials}{proxy}")), Some(task))
            }
            "no_proxy" => (Some("http://127.0.0.1:1".into()), None),
            _ => (None, None),
        };
        let no_proxy = (mode == "no_proxy").then_some("localhost");
        let mut cfg =
            Config::try_parse_from(["test", "--outbound-mark", "0x1234", "--no-outbound-proxy"])
                .unwrap();
        cfg.outbound_proxy = proxy_url;
        cfg.no_proxy = no_proxy.map(str::to_owned);
        let connector = cfg.outbound_connector().unwrap();
        let host = match mode {
            "socks5h" => "example.local".to_string(),
            "no_proxy" => "localhost".to_string(),
            _ => target.ip().to_string(),
        };
        let result = connector
            .connect(&host, target.port(), Duration::from_secs(2))
            .await;
        if !can_mark {
            let error = result.unwrap_err();
            assert!(error.reason.contains("SO_MARK"), "{mode}: {error}");
            assert!(!error.timed_out);
            target_task.abort();
            if let Some(task) = proxy_task {
                task.abort();
            }
            continue;
        }
        let mut stream = result.unwrap();
        assert_eq!(
            socket2::SockRef::from(&stream).mark().unwrap(),
            0x1234,
            "{mode}"
        );
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        drop(stream);
        await_task(target_task).await;
        if let Some(task) = proxy_task {
            await_task(task).await;
        }
    }
    if can_mark {
        let (target, task) = ipv6_one_shot_server(b"ipv6").await.unwrap();
        let connector = OutboundConnector::direct()
            .with_mark(Some(u32::MAX))
            .unwrap();
        let mut stream = connector
            .connect("::1", target.port(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(socket2::SockRef::from(&stream).mark().unwrap(), u32::MAX);
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ipv6");
        await_task(task).await;
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn outbound_mark_is_rejected_on_unsupported_platforms() {
    assert!(OutboundConnector::direct().with_mark(Some(1)).is_err());
    assert!(OutboundConnector::direct().with_mark(None).is_ok());
}

async fn echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").await.unwrap();
    });
    (addr, task)
}

async fn one_shot_server(
    reply: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(reply).await.unwrap();
    });
    (addr, task)
}

async fn ipv6_one_shot_server(
    reply: &'static [u8],
) -> std::io::Result<(std::net::SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("[::1]:0").await?;
    let addr = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(reply).await.unwrap();
    });
    Ok((addr, task))
}

async fn http_proxy(
    target: std::net::SocketAddr,
    response: &'static [u8],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let n = inbound.read(&mut buf).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let request = String::from_utf8_lossy(&request);
        if response.starts_with(b"HTTP/1.1 200") {
            assert!(request.starts_with(&format!("CONNECT 127.0.0.1:{} HTTP/1.1", target.port())));
        }
        if request.contains("Proxy-Authorization") {
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwQHNz"));
        }

        inbound.write_all(response).await.unwrap();
        if response.starts_with(b"HTTP/1.1 200") {
            let outbound = TcpStream::connect(target).await.unwrap();
            let (mut ri, mut wi) = inbound.split();
            let (mut ro, mut wo) = tokio::io::split(outbound);
            let _ = tokio::join!(
                tokio::io::copy(&mut ri, &mut wo),
                tokio::io::copy(&mut ro, &mut wi)
            );
        }
    });
    (addr, task)
}

#[derive(Clone, Copy)]
enum SocksMode {
    RemoteDnsWithAuth,
    LocalDnsNoAuth,
}

async fn socks5_proxy(
    target: std::net::SocketAddr,
    mode: SocksMode,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut inbound, _) = listener.accept().await.unwrap();

        let mut version_and_len = [0u8; 2];
        inbound.read_exact(&mut version_and_len).await.unwrap();
        assert_eq!(version_and_len[0], 0x05);
        let mut methods = vec![0u8; version_and_len[1] as usize];
        inbound.read_exact(&mut methods).await.unwrap();

        match mode {
            SocksMode::RemoteDnsWithAuth => {
                assert!(methods.contains(&0x02));
                inbound.write_all(&[0x05, 0x02]).await.unwrap();
                read_socks_auth(&mut inbound).await;
            }
            SocksMode::LocalDnsNoAuth => {
                assert_eq!(methods, [0x00]);
                inbound.write_all(&[0x05, 0x00]).await.unwrap();
            }
        }

        let mut request_header = [0u8; 4];
        inbound.read_exact(&mut request_header).await.unwrap();
        assert_eq!(request_header[..3], [0x05, 0x01, 0x00]);

        match mode {
            SocksMode::RemoteDnsWithAuth => {
                assert_eq!(request_header[3], 0x03);
                let mut name_len = [0u8; 1];
                inbound.read_exact(&mut name_len).await.unwrap();
                let mut name = vec![0u8; name_len[0] as usize];
                inbound.read_exact(&mut name).await.unwrap();
                assert_eq!(name, b"example.local");
            }
            SocksMode::LocalDnsNoAuth => {
                assert_ne!(request_header[3], 0x03);
                let addr_len = if request_header[3] == 0x01 { 4 } else { 16 };
                let mut addr = vec![0u8; addr_len];
                inbound.read_exact(&mut addr).await.unwrap();
            }
        }

        let mut port = [0u8; 2];
        inbound.read_exact(&mut port).await.unwrap();
        assert_eq!(u16::from_be_bytes(port), target.port());

        inbound
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();

        let outbound = TcpStream::connect(target).await.unwrap();
        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = tokio::io::split(outbound);
        let _ = tokio::join!(
            tokio::io::copy(&mut ri, &mut wo),
            tokio::io::copy(&mut ro, &mut wi)
        );
    });
    (addr, task)
}

async fn read_socks_auth(stream: &mut TcpStream) {
    let mut auth_header = [0u8; 2];
    stream.read_exact(&mut auth_header).await.unwrap();
    assert_eq!(auth_header, [0x01, 0x04]);
    let mut username = [0u8; 4];
    stream.read_exact(&mut username).await.unwrap();
    assert_eq!(&username, b"user");
    let mut pass_len = [0u8; 1];
    stream.read_exact(&mut pass_len).await.unwrap();
    assert_eq!(pass_len, [0x04]);
    let mut password = [0u8; 4];
    stream.read_exact(&mut password).await.unwrap();
    assert_eq!(&password, b"pass");
    stream.write_all(&[0x01, 0x00]).await.unwrap();
}

fn with_proxy_env<const N: usize>(vars: [(&str, Option<&str>); N], test: impl FnOnce()) {
    let _guard = ProxyEnvGuard::new(vars);
    test();
}

struct ProxyEnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl ProxyEnvGuard {
    fn new<const N: usize>(vars: [(&str, Option<&str>); N]) -> Self {
        let names = [
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "NO_PROXY",
            "no_proxy",
        ];
        let saved: Vec<_> = names
            .iter()
            .map(|name| (*name, std::env::var(name).ok()))
            .collect();

        for name in names {
            // SAFETY: protected by ENV_LOCK so these tests do not concurrently
            // mutate process environment.
            unsafe { std::env::remove_var(name) };
        }
        for (name, value) in vars {
            if let Some(value) = value {
                // SAFETY: protected by ENV_LOCK so these tests do not concurrently
                // mutate process environment.
                unsafe { std::env::set_var(name, value) };
            }
        }

        Self { saved }
    }
}

impl Drop for ProxyEnvGuard {
    fn drop(&mut self) {
        for (name, value) in self.saved.drain(..) {
            match value {
                Some(value) => {
                    // SAFETY: protected by ENV_LOCK so these tests do not
                    // concurrently mutate process environment.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: protected by ENV_LOCK so these tests do not
                    // concurrently mutate process environment.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}

async fn await_task(task: tokio::task::JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("test helper task timed out")
        .expect("test helper task panicked");
}
