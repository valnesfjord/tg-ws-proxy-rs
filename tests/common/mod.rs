//! Shared fixtures for the integration tests.
//!
//! Most subsystems are exercised by pointing them at a local fake HTTP
//! CONNECT proxy and asserting on the `CONNECT` line it received — that
//! proves the code path both reached the outbound connector and asked for the
//! right target, without needing real network access.
//!
//! Each test binary only uses a subset of these helpers, so unused ones are
//! expected in any given crate.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::crypto::{ProtoTag, generate_client_handshake};
use tg_ws_proxy_rs::pool::WsPool;
use tg_ws_proxy_rs::proxy::handle_client_with_runtime;
use tg_ws_proxy_rs::runtime::Runtime;

/// How long a helper task may take before the test is considered hung.
pub const TASK_TIMEOUT: Duration = Duration::from_secs(5);

/// How long [`rejecting_http_proxy_requests`] keeps listening after the last
/// connection before deciding the fallback chain is finished.
const QUIET_PERIOD: Duration = Duration::from_millis(300);

/// Same idea for [`stalling_http_proxy_requests`], but it has to outlast the
/// connect timeout every stalled attempt burns before the next one arrives.
const STALL_QUIET_PERIOD: Duration = Duration::from_millis(1500);

/// Install the process-wide rustls crypto provider.
///
/// Required by any test that performs a TLS handshake; safe to call from
/// several tests in the same binary.
pub fn install_rustls_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A fake HTTP proxy that answers one `CONNECT` with `407` and reports the
/// request line it saw.
///
/// Deliberately serves exactly one connection and never resolves without it,
/// so a test can also use it to prove that *nothing* was dialled out.
pub async fn rejecting_http_proxy() -> (SocketAddr, JoinHandle<String>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let request = read_http_connect_request(&mut inbound).await;
        reject(&mut inbound).await;

        request
    });

    (proxy_addr, proxy_task)
}

/// Accept one HTTP CONNECT tunnel, capture the first tunneled HTTP request,
/// then reject the WebSocket upgrade.
pub async fn capturing_http_tunnel() -> (SocketAddr, JoinHandle<(String, String)>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let connect = read_http_connect_request(&mut inbound).await;
        inbound.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let request = read_http_connect_request(&mut inbound).await;
        inbound
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();

        (connect, request)
    });

    (proxy_addr, proxy_task)
}

/// Same as [`rejecting_http_proxy`], but reports *every* `CONNECT` a fallback
/// chain made, so a test can assert on the full shape of the chain.
///
/// Keeps listening until the chain has been quiet for [`QUIET_PERIOD`] rather
/// than stopping at an expected count — otherwise the returned length would be
/// fixed by this fixture and `assert_eq!(requests.len(), n)` could never fail.
/// A chain that makes one attempt too many is then just as visible as one that
/// makes one too few.
pub async fn rejecting_http_proxy_requests() -> (SocketAddr, JoinHandle<Vec<String>>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        // Allow the usual generous budget for the first attempt, then only the
        // quiet period between subsequent ones.
        let mut budget = TASK_TIMEOUT;

        while let Ok(Ok((mut inbound, _))) = tokio::time::timeout(budget, proxy.accept()).await {
            requests.push(read_http_connect_request(&mut inbound).await);
            reject(&mut inbound).await;
            budget = QUIET_PERIOD;
        }

        requests
    });

    (proxy_addr, proxy_task)
}

/// Like [`rejecting_http_proxy_requests`], but leaves every `CONNECT` whose
/// target contains `stall_target` hanging with no answer at all, so the caller
/// hits its connect *timeout* instead of a refusal.
///
/// The distinction matters to the routing code: a refusal says the address
/// answered, a timeout says it is unreachable — only the latter is treated as
/// a blocked IP.  Everything else is rejected immediately so the rest of the
/// fallback chain still runs at full speed.
pub async fn stalling_http_proxy_requests(
    stall_target: &'static str,
) -> (SocketAddr, JoinHandle<Vec<String>>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let mut requests = Vec::new();
        // Held open (not dropped) for the whole run: closing a stalled socket
        // would surface as a connection error rather than a timeout.
        let mut stalled = Vec::new();
        let mut budget = TASK_TIMEOUT;

        while let Ok(Ok((mut inbound, _))) = tokio::time::timeout(budget, proxy.accept()).await {
            let request = read_http_connect_request(&mut inbound).await;
            if request.contains(stall_target) {
                stalled.push(inbound);
            } else {
                reject(&mut inbound).await;
            }
            requests.push(request);
            // Long enough to outlast the connect timeout a stalled attempt
            // waits out before the next one starts.
            budget = STALL_QUIET_PERIOD;
        }

        requests
    });

    (proxy_addr, proxy_task)
}

async fn reject(inbound: &mut TcpStream) {
    inbound
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
        .await
        .unwrap();
}

/// A fake HTTP proxy that accepts one `CONNECT` and then splices the
/// connection through to `target`.
pub async fn tunneling_http_proxy(target: SocketAddr) -> (SocketAddr, JoinHandle<String>) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let request = read_http_connect_request(&mut inbound).await;
        inbound.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();

        let outbound = TcpStream::connect(target).await.unwrap();
        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = tokio::io::split(outbound);
        // Shut the write half down once its source hits EOF, so the close
        // propagates end to end. `tokio::io::copy` alone only flushes, which
        // would leave a peer that reads until EOF waiting forever.
        let _ = tokio::join!(
            async {
                let _ = tokio::io::copy(&mut ri, &mut wo).await;
                let _ = wo.shutdown().await;
            },
            async {
                let _ = tokio::io::copy(&mut ro, &mut wi).await;
                let _ = wi.shutdown().await;
            }
        );

        request
    });

    (proxy_addr, proxy_task)
}

/// A server that accepts one connection and reads a 64-byte MTProto
/// obfuscation handshake — the minimum an upstream MTProto proxy must do for
/// a `--check` probe to pass.
pub async fn mtproto_acceptor() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut handshake = [0u8; 64];
        stream.read_exact(&mut handshake).await.unwrap();
    });

    (addr, task)
}

/// Like [`mtproto_acceptor`], but keeps reading after the handshake and
/// reports how many payload bytes the proxy relayed before the client went
/// away.
pub async fn counting_mtproto_acceptor() -> (SocketAddr, JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut handshake = [0u8; 64];
        stream.read_exact(&mut handshake).await.unwrap();

        let mut relayed = 0usize;
        let mut buf = vec![0u8; 8192];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
            relayed += n;
        }

        relayed
    });

    (addr, task)
}

pub async fn read_http_connect_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0, "proxy client closed before sending a full request");
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8_lossy(&request).to_string()
}

pub async fn await_proxy_request(proxy_task: JoinHandle<String>) -> String {
    await_task(proxy_task).await
}

pub async fn await_proxy_requests(proxy_task: JoinHandle<Vec<String>>) -> Vec<String> {
    await_task(proxy_task).await
}

pub async fn await_unit_task(task: JoinHandle<()>) {
    await_task(task).await;
}

pub async fn await_task<T>(task: JoinHandle<T>) -> T {
    tokio::time::timeout(TASK_TIMEOUT, task)
        .await
        .expect("test helper task timed out")
        .expect("test helper task panicked")
}

/// Drive one full client connection through the proxy: connect, send a valid
/// MTProto handshake for DC 2, then disconnect and wait for the handler to
/// finish its fallback chain.
pub async fn run_proxy_once(config: Config) {
    run_proxy_once_for_dc(config, 2).await;
}

/// Same as [`run_proxy_once`], but lets the caller pick the DC so tests that
/// touch DC-keyed global cooldown state (e.g. the fronting fail-cooldown)
/// don't collide with other tests sharing the same test binary process.
pub async fn run_proxy_once_for_dc(config: Config, dc: i16) {
    let secret = config.secret_bytes();
    let (mut client, handler) = start_proxy_connection(config).await;

    let (handshake, _, _) = generate_client_handshake(&secret, dc, ProtoTag::PaddedIntermediate);
    client.write_all(&handshake).await.unwrap();
    drop(client);

    await_proxy_handler(handler).await;
}

/// Wire up a loopback client socket to a spawned `handle_client_with_runtime`
/// task built from `config`, leaving the client end to the caller.
///
/// Tests that need to speak something other than a plain MTProto handshake
/// (e.g. the inbound FakeTLS camouflage) drive the client side themselves.
pub async fn start_proxy_connection(config: Config) -> (TcpStream, JoinHandle<()>) {
    let outbound = config.outbound_connector().unwrap();
    let runtime = Arc::new(Runtime::new(outbound).with_fronting(config.fronting_domain.clone()));
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
    let (server, peer) = accepted.unwrap();

    let handler = tokio::spawn(handle_client_with_runtime(
        server,
        peer,
        Arc::new(config),
        pool,
        runtime,
    ));

    (client.unwrap(), handler)
}

/// Wait for a proxy connection handler to run its fallback chain to the end.
pub async fn await_proxy_handler(handler: JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(5), handler)
        .await
        .expect("proxy handler timed out")
        .expect("proxy handler panicked");
}
