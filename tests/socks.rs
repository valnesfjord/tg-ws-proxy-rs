//! Loopback-only protocol tests: the fake upstream verifies the actual WSS
//! payload, not just SOCKS CONNECT, so a raw-TCP fallback cannot hide a failure.
mod common;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::crypto::{ProtoTag, apply_keystream, generate_relay_init, make_cipher};
use tg_ws_proxy_rs::inbound::socks;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tungstenite::Message;

fn config() -> Config {
    Config::try_parse_from(["test", "--pool-size", "0", "--handshake-timeout", "1"])
        .unwrap()
        .with_defaults()
}

async fn handler(cfg: Config) -> (TcpStream, impl Future<Output = ()> + Send) {
    common::proxy_connection(cfg, socks::handle_client).await
}

async fn start(cfg: Config) -> (TcpStream, tokio::task::JoinHandle<()>) {
    let (client, handler) = handler(cfg).await;
    (client, tokio::spawn(handler))
}

#[tokio::test]
async fn client_handler_future_stays_compact() {
    // Every SOCKS client holds this state for its whole session, so it gets
    // the same budget as the MTProto listener's handler.
    let (_client, handler) = handler(config()).await;
    let future_size = std::mem::size_of_val(&handler);
    assert!(
        future_size <= 4 * 1024,
        "the SOCKS client future grew to {future_size} bytes"
    );
}

async fn read<const N: usize>(client: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0; N];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}

async fn greet(client: &mut TcpStream) {
    // Fragment the greeting across writes and include an unsupported method.
    client.write_all(&[5]).await.unwrap();
    client.write_all(&[2, 2, 0]).await.unwrap();
    assert_eq!(read::<2>(client).await, [5, 0]);
}

async fn request(client: &mut TcpStream, ip: IpAddr, port: u16, cmd: u8) -> u8 {
    let mut packet = vec![5, cmd, 0];
    match ip {
        IpAddr::V4(ip) => {
            packet.push(1);
            packet.extend(ip.octets());
        }
        IpAddr::V6(ip) => {
            packet.push(4);
            packet.extend(ip.octets());
        }
    }
    packet.extend(port.to_be_bytes());
    client.write_all(&packet).await.unwrap();
    let response = read::<10>(client).await;
    assert_eq!(response[0], 5);
    response[1]
}

#[tokio::test]
async fn accepts_mapped_ips_and_rejects_auth_udp_bind_unknown_and_domains() {
    let (mut client, task) = start(config()).await;
    client.write_all(&[5, 1, 2]).await.unwrap();
    assert_eq!(read::<2>(&mut client).await, [5, 255]);
    task.await.unwrap();
    for (ip, port, cmd, code) in [
        ("149.154.167.51", 443, 2, 7),
        ("149.154.167.51", 443, 3, 7),
        ("127.0.0.1", 443, 1, 2),
        ("198.18.0.20", 443, 1, 2),
        // Built into the official clients, so no --socks-dc is needed.
        ("2001:67c:4e8:f002::a", 443, 1, 0),
        // From a dual-stack socket: still the IPv4 DC2 address.
        ("::ffff:149.154.167.51", 443, 1, 0),
        // The port never decides where the bridge connects.
        ("149.154.167.51", 8443, 1, 0),
    ] {
        let (mut client, task) = start(config()).await;
        greet(&mut client).await;
        let reply = request(&mut client, ip.parse().unwrap(), port, cmd).await;
        assert_eq!(reply, code, "{ip}:{port}");
        if code != 0 {
            assert_closed_cleanly(&mut client).await;
        }
        drop(client);
        task.await.unwrap();
    }
    let (mut client, task) = start(config()).await;
    greet(&mut client).await;
    client
        .write_all(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
        .await
        .unwrap();
    assert_eq!(read::<10>(&mut client).await[1], 4);
    assert_closed_cleanly(&mut client).await;
    task.await.unwrap();
}

/// After an error reply the listener must close with FIN: closing with
/// request bytes still unread sends RST, and a Windows client then drops the
/// reply it had not read yet.
async fn assert_closed_cleanly(client: &mut TcpStream) {
    let mut byte = [0; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0)), "expected FIN, got {read:?}");
}

#[tokio::test]
async fn bounds_handshake_time_and_rejects_unsupported_transport() {
    let (mut client, task) = start(config()).await;
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        client.read_u8().await.unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
    let (mut client, task) = start(config()).await;
    greet(&mut client).await;
    assert_eq!(
        request(&mut client, "149.154.167.51".parse().unwrap(), 443, 1).await,
        0
    );
    client.write_all(&[0; 64]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[allow(clippy::result_large_err)] // tungstenite fixes the handshake callback error type.
async fn fake_ws(
    dc: i16,
    proto: ProtoTag,
    packets: Vec<Vec<u8>>,
    packet_framing: bool,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let connect = common::read_http_connect_request(&mut socket).await;
        assert!(connect.contains(if packet_framing {
            "kws2"
        } else {
            "worker.test"
        }));
        socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let mut ws = tokio_tungstenite::accept_hdr_async(
            socket,
            |request: &tungstenite::handshake::server::Request,
             mut response: tungstenite::handshake::server::Response| {
                if let Some(protocol) = request.headers().get("Sec-WebSocket-Protocol") {
                    response
                        .headers_mut()
                        .insert("Sec-WebSocket-Protocol", protocol.clone());
                }
                Ok(response)
            },
        )
        .await
        .unwrap();
        let init = ws.next().await.unwrap().unwrap().into_data();
        assert_eq!(init.len(), 64);
        let mut dec = make_cipher(&init[8..40], &init[40..56]);
        let mut plain = init.clone();
        apply_keystream(&mut dec, &mut plain);
        assert_eq!(&plain[56..60], proto.as_bytes());
        assert_eq!(i16::from_le_bytes([plain[60], plain[61]]), dc);
        let mut reverse = init[8..56].to_vec();
        reverse.reverse();
        let mut enc = make_cipher(&reverse[..32], &reverse[32..]);
        let expected: Vec<u8> = packets.concat();
        let mut received = Vec::new();
        let mut frames = Vec::new();
        while received.len() < expected.len() {
            let mut data = ws.next().await.unwrap().unwrap().into_data();
            apply_keystream(&mut dec, &mut data);
            received.extend_from_slice(&data);
            frames.push(data);
        }
        assert_eq!(received, expected);
        if packet_framing {
            assert_eq!(frames, packets);
        }
        let mut response = expected;
        apply_keystream(&mut enc, &mut response);
        ws.send(Message::Binary(response)).await.unwrap();
        // Keep the stream alive until the client receives the response.
        while let Some(Ok(message)) = ws.next().await {
            if message.is_close() {
                break;
            }
        }
    });
    (addr, task)
}

async fn roundtrip(proto: ProtoTag, obfuscated: bool, ipv6: bool, packet_framing: bool) {
    common::install_rustls_provider();
    let packets: Vec<Vec<u8>> = [b"abcd", b"efgh"]
        .into_iter()
        .map(|payload| {
            let mut packet = if proto == ProtoTag::Abridged {
                vec![1]
            } else {
                4u32.to_le_bytes().to_vec()
            };
            packet.extend(payload);
            packet
        })
        .collect();
    let dc = if ipv6 { -2 } else { 2 };
    let (upstream, upstream_task) = fake_ws(dc, proto, packets.clone(), packet_framing).await;
    let mut cfg = Config::try_parse_from([
        "test",
        "--pool-size",
        "0",
        "--cf-disable-tls",
        if packet_framing {
            "--cf-domain"
        } else {
            "--cf-worker-domain"
        },
        if packet_framing {
            "relay.test"
        } else {
            "worker.test"
        },
        "--pinned-upstream",
        if packet_framing {
            "cfproxy"
        } else {
            "cfworker"
        },
        "--outbound-proxy",
        &format!("http://{upstream}"),
    ])
    .unwrap()
    .with_defaults();
    let ip: IpAddr = if ipv6 {
        "2001:db8::2"
    } else {
        "149.154.167.51"
    }
    .parse()
    .unwrap();
    if ipv6 {
        cfg.socks_dc
            .push(socks::parse_dc_mapping("-2:2001:db8::2").unwrap());
    }
    let (mut client, task) = start(cfg).await;
    greet(&mut client).await;
    assert_eq!(request(&mut client, ip, 443, 1).await, 0);
    let expected = packets.concat();
    let mut payload = expected.clone();
    let mut decrypt_response = None;
    let mut bytes = if obfuscated {
        // Intentionally conflicting DC metadata: the SOCKS target must win.
        let init = generate_relay_init(proto, 5);
        let mut enc = make_cipher(&init[8..40], &init[40..56]);
        apply_keystream(&mut enc, &mut [0; 64]);
        apply_keystream(&mut enc, &mut payload);
        let mut reverse = init[8..56].to_vec();
        reverse.reverse();
        decrypt_response = Some(make_cipher(&reverse[..32], &reverse[32..]));
        init.to_vec()
    } else if proto == ProtoTag::Abridged {
        vec![0xef]
    } else {
        proto.as_bytes().to_vec()
    };
    bytes.extend(payload);
    // Header fragmentation followed by coalesced header tail + two packets.
    client.write_all(&bytes[..1]).await.unwrap();
    client.write_all(&bytes[1..]).await.unwrap();
    let mut response = vec![0; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    if let Some(mut cipher) = decrypt_response {
        apply_keystream(&mut cipher, &mut response);
    }
    assert_eq!(response, expected);
    drop(client);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), upstream_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn plain_and_obfuscated_transports_roundtrip_through_both_ws_framings() {
    for proto in [
        ProtoTag::Abridged,
        ProtoTag::Intermediate,
        ProtoTag::PaddedIntermediate,
    ] {
        for obfuscated in [false, true] {
            for packet_framing in [false, true] {
                roundtrip(proto, obfuscated, !packet_framing, packet_framing).await;
            }
        }
    }
}
