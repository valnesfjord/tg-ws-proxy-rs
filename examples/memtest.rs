//! Throwaway memory harness: fake Telegram WebSocket upstream + CONNECT proxy
//! + N clients pulling media-sized frames through the proxy.
//!
//! `cargo run --release --example memtest -- <proxy-addr> <clients> <frames> <frame-kib>`
//!
//! `proxy-addr` is where the proxy under test listens — `127.0.0.1:1443` for a
//! local run, or `192.168.1.1:25565` to drive one on a router from a machine
//! that has a Rust toolchain. Everything here binds `0.0.0.0`, so the proxy
//! can reach it across the LAN:
//!
//!   --outbound-proxy http://<this-machine>:<connect-port>
//!   --danger-accept-invalid-certs --cf-domain fake.local

use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tungstenite::Message;

use tg_ws_proxy_rs::crypto::{ProtoTag, generate_client_handshake};

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args: Vec<String> = std::env::args().collect();
    let proxy_addr = args[1].clone();
    let clients: usize = args[2].parse().unwrap();
    let frames: usize = args[3].parse().unwrap();
    let frame_kib: usize = args[4].parse().unwrap();

    // ── Fake Telegram: TLS + WebSocket, streams `frames` big binary frames ──
    let cert = rcgen::generate_simple_self_signed(vec!["fake.local".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.serialize_der().unwrap());
    let key_der = PrivateKeyDer::try_from(cert.serialize_private_key_der()).unwrap();
    let tls = TlsAcceptor::from(Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap(),
    ));

    let upstream = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let upstream_addr = format!("127.0.0.1:{}", upstream_port);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = upstream.accept().await else {
                break;
            };
            let tls = tls.clone();
            tokio::spawn(async move {
                let Ok(stream) = tls.accept(stream).await else {
                    return;
                };
                // The proxy asks for the `binary` subprotocol, exactly as
                // Telegram's endpoint expects; echo it back or it bails out.
                let callback =
                    |_req: &tungstenite::handshake::server::Request,
                     mut response: tungstenite::handshake::server::Response| {
                        response.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            tungstenite::http::HeaderValue::from_static("binary"),
                        );
                        Ok(response)
                    };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
                    return;
                };
                // Drain the proxy's relay init, then push media-sized frames.
                let payload = vec![0x7Eu8; frame_kib * 1024];
                for _ in 0..frames {
                    if ws.send(Message::Binary(payload.clone())).await.is_err() {
                        return;
                    }
                }
                tokio::time::sleep(Duration::from_secs(120)).await;
            });
        }
    });

    // ── CONNECT proxy: tunnels every target to the fake upstream ───────────
    let connect = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let connect_addr = connect.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut inbound, _)) = connect.accept().await else {
                break;
            };
            let upstream_addr = upstream_addr.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let mut seen = 0;
                while let Ok(n) = inbound.read(&mut buf[seen..]).await {
                    if n == 0 {
                        return;
                    }
                    seen += n;
                    if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                if inbound.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                    return;
                }
                let Ok(outbound) = TcpStream::connect(upstream_addr.as_str()).await else {
                    return;
                };
                let (mut ri, mut wi) = inbound.split();
                let (mut ro, mut wo) = tokio::io::split(outbound);
                let _ = tokio::join!(
                    async {
                        let _ = tokio::io::copy(&mut ri, &mut wo).await;
                    },
                    async {
                        let _ = tokio::io::copy(&mut ro, &mut wi).await;
                    }
                );
            });
        }
    });

    println!("CONNECT proxy listening on port {}", connect_addr.port());
    println!("start the proxy under test now; clients connect in 10s");
    tokio::time::sleep(Duration::from_secs(10)).await;

    // ── Clients ────────────────────────────────────────────────────────────
    let secret = hex::decode("0ea7201141bf2763a7dee49ba68eeb4c").unwrap();
    let mut held = Vec::new();
    for _ in 0..clients {
        let Ok(mut stream) = TcpStream::connect(proxy_addr.as_str()).await else {
            continue;
        };
        let (handshake, _, _) = generate_client_handshake(&secret, 2, ProtoTag::PaddedIntermediate);
        if stream.write_all(&handshake).await.is_err() {
            continue;
        }
        held.push(stream);
    }
    println!("{} clients connected, draining…", held.len());

    // Drain everything the proxy relays down so the bridge keeps flowing.
    let mut readers = Vec::new();
    for mut stream in held {
        readers.push(tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            let mut total = 0usize;
            while let Ok(n) = stream.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                total += n;
            }
            total
        }));
    }

    tokio::time::sleep(Duration::from_secs(20)).await;
    println!("done");
}
