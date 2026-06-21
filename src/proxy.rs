//! Core proxy logic: client handling, re-encryption bridge, TCP fallback.
//!
//! Flow for each inbound client connection:
//!
//! ```text
//!  Telegram Desktop
//!       │  MTProto obfuscated TCP (port 1443)
//!       ▼
//!  [parse_handshake]  ← validates secret, extracts DC id + protocol
//!       │
//!       ├─ WebSocket path (preferred):
//!       │   [connect WebSocket]  →  wss://kwsN.web.telegram.org/apiws
//!       │   [bridge_ws]          ←  bidirectional re-encrypted bridge
//!       │
//!       ├─ Upstream MTProto proxy fallback (when WS fails, if configured):
//!       │   [connect_mtproto_upstream]  →  external MTProto proxy TCP
//!       │   [bridge_mtproto_relay]      ←  bidirectional re-encrypted bridge
//!       │
//!       └─ Direct TCP fallback (last resort):
//!           [bridge_tcp]  →  direct TCP to Telegram DC IP:443
//! ```

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use cipher::StreamCipher;
use futures_util::SinkExt;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use tungstenite::Message;

use crate::config::Config;
use crate::crypto::{
    AesCtr256, ConnectionCiphers, build_connection_ciphers, generate_client_handshake,
    generate_relay_init, parse_handshake,
};
use crate::faketls::{
    TLS_MAX_RECORD_PAYLOAD, TLS_RECORD_HANDSHAKE, build_faketls_client_hello,
    build_faketls_server_hello, drain_faketls_server_hello, parse_faketls_client_hello,
    read_tls_appdata, sign_faketls_client_hello, write_tls_appdata,
};
use crate::outbound::OutboundConnector;
use crate::pool::WsPool;
use crate::runtime::Runtime;
use crate::splitter::MsgSplitter;
use crate::ws_client::{
    TgWsStream, connect_cf_worker_ws_for_dc_with_outbound, connect_cf_ws_for_dc_with_outbound,
    connect_ws_for_dc_with_outbound, ws_send,
};

// WS failure cooldown is global for the process lifetime.
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

// ─── Global failure tracking ─────────────────────────────────────────────────

/// Per-DC cooldown: avoid retrying WS until this instant.
/// Also used for the "all redirects" case (longer cooldown of 5 min).
static DC_FAIL_UNTIL: StdMutex<Option<HashMap<(u32, bool), Instant>>> = StdMutex::new(None);

// ─── Upstream MTProto proxy failure tracking ─────────────────────────────────

/// Per-upstream cooldown: keyed by "host:port".
static UPSTREAM_FAIL_UNTIL: StdMutex<Option<HashMap<String, Instant>>> = StdMutex::new(None);

fn upstream_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

fn set_upstream_cooldown(host: &str, port: u16, cooldown: Duration) {
    let key = upstream_key(host, port);
    let mut lock = UPSTREAM_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert(key, Instant::now() + cooldown);
}

fn clear_upstream_cooldown(host: &str, port: u16) {
    let key = upstream_key(host, port);
    let mut lock = UPSTREAM_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_mut() {
        map.remove(&key);
    }
}

fn upstream_in_cooldown(host: &str, port: u16) -> bool {
    let key = upstream_key(host, port);
    let lock = UPSTREAM_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref()
        && let Some(&until) = map.get(&key)
    {
        return Instant::now() < until;
    }
    false
}

// ─── Cloudflare proxy failure tracking ───────────────────────────────────────

/// Round-robin counter for CF domain balancing (`--cf-balance`).
static CF_BALANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
/// Round-robin counter for CF Worker domain balancing (`--cf-balance`).
static CF_WORKER_BALANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Return a rotated view of `cf_domains` based on a global round-robin counter.
///
/// Each call atomically increments the counter and uses it to determine which
/// domain should be tried first.  The remaining domains follow in their
/// original order, wrapping around to the beginning of the slice, so the
/// full fallback chain is always available.
///
/// `Relaxed` ordering is intentional: the counter only drives load distribution
/// and does not guard access to any other shared state, so no cross-thread
/// memory synchronisation is required.  Wrapping overflow on `usize` is
/// harmless — the modulo operation still produces a valid index.
fn balanced_cf_domains(cf_domains: &[String]) -> Vec<String> {
    let n = cf_domains.len();
    if n <= 1 {
        return cf_domains.to_vec();
    }
    // `fetch_add` wraps silently on overflow, keeping the index valid.
    let idx = CF_BALANCE_COUNTER.fetch_add(1, Ordering::Relaxed) % n;
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        result.push(cf_domains[(idx + i) % n].clone());
    }
    result
}

/// Return a rotated view of `cf_worker_domains` for Worker load balancing.
fn balanced_cf_workers(cf_worker_domains: &[String]) -> Vec<String> {
    let n = cf_worker_domains.len();
    if n <= 1 {
        return cf_worker_domains.to_vec();
    }
    let idx = CF_WORKER_BALANCE_COUNTER.fetch_add(1, Ordering::Relaxed) % n;
    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        result.push(cf_worker_domains[(idx + i) % n].clone());
    }
    result
}

/// Per-DC cooldown for the CF proxy path.
static CF_FAIL_UNTIL: StdMutex<Option<HashMap<(u32, bool), Instant>>> = StdMutex::new(None);
/// Per-Worker cooldown for the Cloudflare Worker path.
static CF_WORKER_FAIL_UNTIL: StdMutex<Option<HashMap<String, Instant>>> = StdMutex::new(None);
type TcpReader = ReadHalf<TcpStream>;
type TcpWriter = WriteHalf<TcpStream>;

fn set_cf_cooldown(dc: u32, is_media: bool, cooldown: Duration) {
    let mut lock = CF_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert((dc, is_media), Instant::now() + cooldown);
}

fn clear_cf_cooldown(dc: u32, is_media: bool) {
    let mut lock = CF_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_mut() {
        map.remove(&(dc, is_media));
    }
}

fn cf_in_cooldown(dc: u32, is_media: bool) -> bool {
    let lock = CF_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref()
        && let Some(&until) = map.get(&(dc, is_media))
    {
        return Instant::now() < until;
    }
    false
}

fn set_cf_worker_cooldown(worker_domain: &str, cooldown: Duration) {
    let mut lock = CF_WORKER_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert(worker_domain.to_string(), Instant::now() + cooldown);
}

fn clear_cf_worker_cooldown(worker_domain: &str) {
    let mut lock = CF_WORKER_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_mut() {
        map.remove(worker_domain);
    }
}

fn cf_worker_in_cooldown(worker_domain: &str) -> bool {
    let lock = CF_WORKER_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref()
        && let Some(&until) = map.get(worker_domain)
    {
        return Instant::now() < until;
    }
    false
}

fn blacklist_ws(dc: u32, is_media: bool, cooldown: Duration) {
    // Instead of a permanent blacklist, apply a long cooldown so the proxy
    // can recover automatically if WS becomes available again (e.g. after a
    // network change or Telegram-side redirect policy change).
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert((dc, is_media), Instant::now() + cooldown);
}

fn set_dc_cooldown(dc: u32, is_media: bool, cooldown: Duration) {
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert((dc, is_media), Instant::now() + cooldown);
}

fn clear_dc_cooldown(dc: u32, is_media: bool) {
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_mut() {
        map.remove(&(dc, is_media));
    }
}

fn ws_timeout_for(
    dc: u32,
    is_media: bool,
    normal_timeout: Duration,
    fail_probe_timeout: Duration,
) -> Duration {
    let lock = DC_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref()
        && let Some(&until) = map.get(&(dc, is_media))
        && Instant::now() < until
    {
        return fail_probe_timeout; // still in cooldown → try fast
    }

    normal_timeout
}

enum ClientReader {
    Plain(TcpReader),
    FakeTls { reader: TcpReader, pending: Vec<u8> },
}

impl ClientReader {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(buf).await,
            Self::FakeTls { reader, pending } => {
                if !pending.is_empty() {
                    let n = std::cmp::min(buf.len(), pending.len());
                    buf[..n].copy_from_slice(&pending[..n]);
                    pending.drain(..n);
                    return Ok(n);
                }

                read_tls_appdata(reader, buf).await
            }
        }
    }

    async fn drain(self) {
        match self {
            Self::Plain(mut reader) | Self::FakeTls { mut reader, .. } => {
                let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            }
        }
    }
}

enum ClientWriter {
    Plain(TcpWriter),
    FakeTls(TcpWriter),
}

impl ClientWriter {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(writer) => writer.write_all(data).await,
            Self::FakeTls(writer) => write_tls_appdata(writer, data).await,
        }
    }
}

/// Outcome of reading the inbound handshake on a connection.
///
/// When `--listen-faketls-domain` is enabled, a connection that doesn't
/// present a valid, freshly-signed ClientHello for the expected domain is
/// not simply dropped — it is treated the way a real webserver fronting
/// that domain would treat it, so that active probing (a censor connecting
/// and inspecting the response) cannot distinguish this proxy from a
/// genuine HTTPS endpoint. Mirrors the Python reference implementation's
/// `proxy_to_masking_domain` / HTTP-redirect fallback in `_read_client_init`.
enum InboundHandshake {
    /// A valid 64-byte MTProto obfuscation init was recovered; proceed with
    /// the normal MTProto routing logic.
    Handshake([u8; 64], Vec<u8>),
    /// The client sent what looks like a TLS ClientHello but it failed
    /// FakeTLS authentication (no secret's HMAC matched, expired/replayed
    /// timestamp, or wrong SNI). Carries the raw bytes already read from the
    /// socket so they can be replayed to the real masking domain.
    Masquerade(Vec<u8>),
    /// The very first byte wasn't a TLS record at all (e.g. a bare HTTP
    /// probe). No FakeTLS bytes were consumed beyond that one byte.
    PlaintextProbe,
}

async fn accept_inbound_faketls(
    label: &str,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    expected_domain: &str,
) -> Option<InboundHandshake> {
    // Peek the record-type byte before committing to reading a full TLS
    // record, so a bare non-TLS probe (e.g. a plain HTTP request) can be
    // answered immediately instead of blocking on a payload length derived
    // from garbage bytes that may never fully arrive.
    let mut record_type = [0u8; 1];
    if reader.read_exact(&mut record_type).await.is_err() {
        return None;
    }

    if record_type[0] != TLS_RECORD_HANDSHAKE {
        debug!(
            "[{}] non-TLS byte 0x{:02X} on FakeTLS listener -> masking",
            label, record_type[0]
        );
        return Some(InboundHandshake::PlaintextProbe);
    }

    let mut rest = [0u8; 4];
    if reader.read_exact(&mut rest).await.is_err() {
        return None;
    }
    let version = [rest[0], rest[1]];
    let payload_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
    if payload_len > TLS_MAX_RECORD_PAYLOAD + 256 {
        return None;
    }
    let mut payload = vec![0u8; payload_len];
    if reader.read_exact(&mut payload).await.is_err() {
        return None;
    }

    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(record_type[0]);
    record.extend_from_slice(&rest);
    record.extend_from_slice(&payload);

    if version != [0x03, 0x01] {
        debug!("[{}] bad FakeTLS ClientHello record version", label);
        return Some(InboundHandshake::Masquerade(record));
    }

    let (hello, matched_secret) = match secrets
        .iter()
        .find_map(|secret| parse_faketls_client_hello(&record, secret).map(|hello| (hello, secret)))
    {
        Some(v) => v,
        None => {
            debug!("[{}] bad FakeTLS ClientHello digest/timestamp", label);
            return Some(InboundHandshake::Masquerade(record));
        }
    };

    if hello.hostname.as_deref() != Some(expected_domain) {
        debug!(
            "[{}] FakeTLS SNI mismatch: got {:?}, expected {}",
            label, hello.hostname, expected_domain
        );
        return Some(InboundHandshake::Masquerade(record));
    }

    let server_hello = build_faketls_server_hello(matched_secret, &hello);
    if let Err(e) = writer.write_all(&server_hello).await {
        debug!("[{}] write FakeTLS ServerHello: {}", label, e);
        return None;
    }

    let mut handshake_buf = [0u8; 64];
    let mut filled = 0;
    let mut buf = vec![0u8; TLS_MAX_RECORD_PAYLOAD + 256];
    while filled < handshake_buf.len() {
        let n = match read_tls_appdata(reader, &mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        let before = filled;
        let take = std::cmp::min(n, handshake_buf.len() - filled);
        handshake_buf[filled..filled + take].copy_from_slice(&buf[..take]);
        filled += take;
        if take != n {
            if before == 0 {
                return split_mtproto_init_and_pending(&buf[..n])
                    .map(|(h, p)| InboundHandshake::Handshake(h, p));
            }
            return Some(InboundHandshake::Handshake(
                handshake_buf,
                buf[take..n].to_vec(),
            ));
        }
    }

    Some(InboundHandshake::Handshake(handshake_buf, Vec::new()))
}

/// Transparently relay a misauthenticated FakeTLS connection to the real
/// masking domain over plain TCP, so an active prober sees a normal-looking
/// HTTPS session to that domain rather than an instant connection reset or a
/// behaviour distinguishable from a real webserver. `initial` is the raw
/// bytes already read from the client (the TLS record that failed
/// authentication) and is forwarded first. Routed through the shared
/// [`OutboundConnector`] so it honours `--outbound-proxy` like every other
/// outgoing connection this proxy makes. Mirrors the Python reference
/// implementation's `proxy_to_masking_domain`.
async fn masquerade_to_domain(
    label: &str,
    mut client_reader: TcpReader,
    mut client_writer: TcpWriter,
    initial: Vec<u8>,
    domain: &str,
    outbound: &OutboundConnector,
) {
    if domain.is_empty() {
        return;
    }

    let upstream = match outbound.connect(domain, 443, Duration::from_secs(10)).await {
        Ok(stream) => stream,
        Err(e) => {
            debug!("[{}] masking: cannot connect to {}:443: {}", label, domain, e);
            return;
        }
    };

    debug!("[{}] masking -> {}:443", label, domain);
    let _ = upstream.set_nodelay(true);
    let (mut up_reader, mut up_writer) = tokio::io::split(upstream);

    if !initial.is_empty() && up_writer.write_all(&initial).await.is_err() {
        return;
    }

    let start = std::time::Instant::now();

    // Mirror bridge_tcp's spawn-per-direction structure: each task owns its
    // half of the relay outright, so neither blocks the other and the whole
    // session unwinds promptly once either side hangs up.
    let mut upload = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = match client_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if up_writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        total
    });

    let mut download = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        let mut total = 0u64;
        loop {
            let n = match up_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if client_writer.write_all(&buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }
        total
    });

    let (bytes_up, bytes_down) = tokio::select! {
        result = &mut upload => {
            let up = result.unwrap_or(0);
            download.abort();
            let down = download.await.unwrap_or(0);
            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or(0);
            upload.abort();
            let up = upload.await.unwrap_or(0);
            (up, down)
        }
    };

    debug!(
        "[{}] masking session to {} closed: ↑{}  ↓{}  {:.1}s",
        label,
        domain,
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        start.elapsed().as_secs_f32()
    );
}

/// Respond to a bare (non-TLS) probe on the FakeTLS port the way a real
/// webserver fronting `domain` would respond to a plaintext HTTP request on
/// its HTTPS port: redirect to the HTTPS site. Mirrors the Python reference
/// implementation's plaintext-probe handling in `_read_client_init`.
async fn send_masking_redirect(writer: &mut TcpWriter, domain: &str) {
    if domain.is_empty() {
        let _ = writer.shutdown().await;
        return;
    }
    let body = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: https://{domain}/\r\n\
         Content-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    let _ = writer.write_all(body.as_bytes()).await;
    let _ = writer.shutdown().await;
}

// ─── Client handler ──────────────────────────────────────────────────────────

/// Handle one inbound client connection end-to-end.
pub async fn handle_client(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: Config,
    pool: Arc<WsPool>,
) {
    handle_client_with_runtime(
        stream,
        peer,
        config,
        pool,
        Arc::new(Runtime::new(OutboundConnector::direct())),
    )
    .await;
}

/// Same as [`handle_client`], but uses the supplied runtime context for shared
/// outbound routing and DC metadata.
pub async fn handle_client_with_runtime(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: Config,
    pool: Arc<WsPool>,
    runtime: Arc<Runtime>,
) {
    let mut label = peer.to_string();
    let _ = stream.set_nodelay(true);

    let secrets = config.secret_bytes_list();
    let dc_redirects = config.dc_redirects();
    let skip_tls = config.skip_tls_verify;
    let keepalive_interval = config.ws_keepalive_interval();

    // ── Timeouts / cooldowns from config ─────────────────────────────────
    let ws_connect_timeout = Duration::from_secs(config.ws_connect_timeout);
    let ws_fail_probe_timeout = Duration::from_secs(config.ws_fail_probe_timeout);
    let ws_fail_cooldown = Duration::from_secs(config.ws_fail_cooldown);
    let ws_redirect_cooldown = Duration::from_secs(config.ws_redirect_cooldown);
    let handshake_timeout = Duration::from_secs(config.handshake_timeout);
    let tcp_fallback_timeout = Duration::from_secs(config.tcp_fallback_timeout);
    let upstream_connect_timeout = Duration::from_secs(config.upstream_connect_timeout);
    let upstream_fail_cooldown = Duration::from_secs(config.upstream_fail_cooldown);
    let cf_connect_timeout = Duration::from_secs(config.cf_connect_timeout);
    let cf_fail_cooldown = Duration::from_secs(config.cf_fail_cooldown);

    // Split into independent read / write halves.
    let (mut reader, mut writer) = tokio::io::split(stream);

    // ── Step 0: optional PROXY protocol v1 header ─────────────────────────
    // When running behind nginx/haproxy with `proxy_protocol on`, every
    // connection is prefixed with a `PROXY TCP4 src dst sport dport\r\n`
    // line carrying the real client address. Consume it here so the rest of
    // the handshake reads the actual MTProto/FakeTLS bytes.
    if config.proxy_protocol {
        match tokio::time::timeout(Duration::from_secs(10), read_proxy_protocol_line(&mut reader))
            .await
        {
            Ok(Ok(Some(real_label))) => {
                debug!("[{}] PROXY protocol: {}", label, real_label);
                label = real_label;
            }
            Ok(Ok(None)) => {
                debug!("[{}] expected PROXY protocol header, none found", label);
            }
            Ok(Err(_)) => {
                debug!("[{}] disconnected during PROXY header", label);
                return;
            }
            Err(_) => {
                debug!("[{}] timeout reading PROXY header", label);
                return;
            }
        }
    }

    // ── Step 1: read the 64-byte MTProto obfuscation init ────────────────
    let inbound_faketls_domain = config.listen_faketls_domain();
    let (handshake_buf, faketls_pending) = match tokio::time::timeout(
        handshake_timeout,
        read_inbound_handshake(
            &label,
            &mut reader,
            &mut writer,
            &secrets,
            inbound_faketls_domain.as_deref(),
        ),
    )
    .await
    {
        Ok(Some(InboundHandshake::Handshake(h, p))) => (h, p),
        Ok(Some(InboundHandshake::Masquerade(initial))) => {
            // The client presented something TLS-shaped but it didn't
            // authenticate against any configured secret (wrong key,
            // replayed/expired timestamp, or wrong SNI). Rather than
            // dropping the connection — which an active prober could use to
            // fingerprint this proxy — transparently relay it to the real
            // masking domain so it looks exactly like a normal HTTPS
            // session to that site.
            let domain = inbound_faketls_domain.as_deref().unwrap_or("");
            info!(
                "[{}] FakeTLS verification failed -> masking to {}",
                label, domain
            );
            masquerade_to_domain(&label, reader, writer, initial, domain, runtime.outbound())
                .await;
            return;
        }
        Ok(Some(InboundHandshake::PlaintextProbe)) => {
            // A bare non-TLS request on the FakeTLS port — answer the way a
            // real webserver fronting the masking domain would.
            let domain = inbound_faketls_domain.as_deref().unwrap_or("");
            debug!(
                "[{}] plaintext probe on FakeTLS listener -> redirect to {}",
                label, domain
            );
            send_masking_redirect(&mut writer, domain).await;
            return;
        }
        Ok(None) => return,
        Err(_) => {
            debug!("[{}] handshake timeout", label);
            return;
        }
    };

    let reader = if inbound_faketls_domain.is_some() {
        ClientReader::FakeTls {
            reader,
            pending: faketls_pending,
        }
    } else {
        ClientReader::Plain(reader)
    };
    let writer = if inbound_faketls_domain.is_some() {
        ClientWriter::FakeTls(writer)
    } else {
        ClientWriter::Plain(writer)
    };

    // ── Step 2: parse and validate the handshake ─────────────────────────
    let (info, secret) = match secrets
        .iter()
        .find_map(|secret| parse_handshake(&handshake_buf, secret).map(|i| (i, secret.as_slice())))
    {
        Some(v) => v,
        None => {
            debug!(
                "[{}] bad handshake (wrong secret or reserved prefix)",
                label
            );

            // Drain the connection silently to avoid giving information to scanners.
            reader.drain().await;

            return;
        }
    };

    let dc_id = info.dc_id;
    let is_media = info.is_media;
    let proto = info.proto;

    // Apply DC override (e.g. DC 203 → DC 2 for WS domain selection).
    let ws_dc = runtime.websocket_dc(dc_id);
    let dc_idx: i16 = if is_media {
        -(dc_id as i16)
    } else {
        dc_id as i16
    };

    debug!(
        "[{}] handshake ok: DC{}{} proto={:?}",
        label,
        dc_id,
        if is_media { " media" } else { "" },
        proto
    );

    // ── Step 3: generate the relay init packet for the Telegram backend ──
    let relay_init = generate_relay_init(proto, dc_idx);

    // ── Step 4: build all four AES-256-CTR ciphers ───────────────────────
    let ciphers = build_connection_ciphers(&info.prekey_and_iv, secret, &relay_init);

    // ── Step 5: route the connection ──────────────────────────────────────
    let target_ip = dc_redirects.get(&dc_id).cloned();
    let cf_worker_domains = config.cf_worker_domains();
    let media_tag = if is_media { "m" } else { "" };

    if target_ip.is_none() {
        // DC not in config — match the Python fallback order:
        // CF Worker, CF proxy/default domains, then TCP fallback.  Rust keeps
        // upstream MTProto proxies before TCP as an extra fallback tier.
        let reason = format!("DC{} not in --dc-ip config", dc_id);
        let fallback = match runtime.fallback_ip(dc_id) {
            Some(ip) => ip.to_string(),
            None => {
                warn!("[{}] {} — no fallback IP available", label, reason);
                return;
            }
        };

        // ── Try Cloudflare Worker if configured ──────────────────────────
        if !cf_worker_domains.is_empty() {
            let workers_for_conn: Cow<'_, [String]> = if config.cf_balance {
                Cow::Owned(balanced_cf_workers(&cf_worker_domains))
            } else {
                Cow::Borrowed(&cf_worker_domains)
            };
            for worker_domain in workers_for_conn.iter() {
                if cf_worker_in_cooldown(worker_domain) {
                    debug!(
                        "[{}] DC{}{} CF Worker {} in cooldown, skipping",
                        label, dc_id, media_tag, worker_domain
                    );
                    continue;
                }

                debug!(
                    "[{}] DC{}{} {} → trying CF Worker {} for {}",
                    label, dc_id, media_tag, reason, worker_domain, fallback
                );

                if let Some(ws) = connect_cf_worker_ws_for_dc_with_outbound(
                    worker_domain,
                    &fallback,
                    dc_id,
                    is_media,
                    skip_tls,
                    cf_connect_timeout,
                    runtime.outbound(),
                )
                .await
                {
                    clear_cf_worker_cooldown(worker_domain);
                    info!(
                        "[{}] DC{}{} {} → CF Worker connected ({})",
                        label, dc_id, media_tag, reason, worker_domain
                    );
                    bridge_ws(
                        reader,
                        writer,
                        WsBridgeParams {
                            label: &label,
                            ws,
                            relay_init,
                            ciphers,
                            proto,
                            dc: dc_id,
                            is_media,
                            keepalive_interval,
                        },
                    )
                    .await;
                    return;
                } else {
                    set_cf_worker_cooldown(worker_domain, cf_fail_cooldown);
                    warn!(
                        "[{}] DC{}{} CF Worker {} failed, cooldown {}s",
                        label,
                        dc_id,
                        media_tag,
                        worker_domain,
                        cf_fail_cooldown.as_secs()
                    );
                }
            }
        }

        // ── Try Cloudflare proxy if configured ────────────────────────────
        if !config.cf_domains.is_empty() {
            if !cf_in_cooldown(dc_id, is_media) {
                let cf_domains_for_conn = if config.cf_balance {
                    balanced_cf_domains(&config.cf_domains)
                } else {
                    config.cf_domains.clone()
                };
                debug!(
                    "[{}] DC{}{} {} → trying CF proxy via {:?}",
                    label, dc_id, media_tag, reason, cf_domains_for_conn
                );

                let (cf_ws_opt, _all_redirects) = connect_cf_ws_for_dc_with_outbound(
                    dc_id,
                    &cf_domains_for_conn,
                    is_media,
                    skip_tls,
                    cf_connect_timeout,
                    runtime.outbound(),
                )
                .await;

                if let Some(ws) = cf_ws_opt {
                    clear_cf_cooldown(dc_id, is_media);
                    info!(
                        "[{}] DC{}{} {} → CF proxy connected",
                        label, dc_id, media_tag, reason
                    );
                    bridge_ws(
                        reader,
                        writer,
                        WsBridgeParams {
                            label: &label,
                            ws,
                            relay_init,
                            ciphers,
                            proto,
                            dc: dc_id,
                            is_media,
                            keepalive_interval,
                        },
                    )
                    .await;
                    return;
                } else {
                    set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                    warn!(
                        "[{}] DC{}{} CF proxy failed, cooldown {}s",
                        label,
                        dc_id,
                        media_tag,
                        cf_fail_cooldown.as_secs()
                    );
                }
            } else {
                debug!(
                    "[{}] DC{}{} CF proxy in cooldown, skipping",
                    label, dc_id, media_tag
                );
            }
        }

        // Try each configured upstream MTProto proxy.
        for upstream in &config.mtproto_proxies {
            if upstream_in_cooldown(&upstream.host, upstream.port) {
                debug!(
                    "[{}] upstream {}:{} in cooldown, skipping",
                    label, upstream.host, upstream.port
                );
                continue;
            }

            match connect_mtproto_upstream(
                &upstream.host,
                upstream.port,
                &upstream.secret,
                dc_idx,
                proto,
                upstream_connect_timeout,
                runtime.outbound(),
            )
            .await
            {
                Some(conn) => {
                    let is_ft = matches!(conn, UpstreamConnection::FakeTls(..));
                    clear_upstream_cooldown(&upstream.host, upstream.port);
                    info!(
                        "[{}] DC{}{} {} → upstream {} MTProto {}:{}",
                        label,
                        dc_id,
                        media_tag,
                        reason,
                        if is_ft { "FakeTLS" } else { "plain" },
                        upstream.host,
                        upstream.port
                    );
                    let ConnectionCiphers {
                        clt_dec, clt_enc, ..
                    } = ciphers;
                    match conn {
                        UpstreamConnection::Plain(rem_reader, rem_writer, up_enc, up_dec) => {
                            let up_ciphers = ConnectionCiphers {
                                clt_dec,
                                clt_enc,
                                tg_enc: up_enc,
                                tg_dec: up_dec,
                            };
                            bridge_mtproto_relay(
                                reader,
                                writer,
                                MtprotoRelayParams {
                                    label: &label,
                                    rem_reader,
                                    rem_writer,
                                    ciphers: up_ciphers,
                                    dc: dc_id,
                                    is_media,
                                },
                            )
                            .await;
                        }
                        UpstreamConnection::FakeTls(rem_reader, rem_writer, up_enc, up_dec) => {
                            let up_ciphers = ConnectionCiphers {
                                clt_dec,
                                clt_enc,
                                tg_enc: up_enc,
                                tg_dec: up_dec,
                            };
                            bridge_faketls_relay(
                                reader,
                                writer,
                                FaketlsRelayParams {
                                    label: &label,
                                    rem_reader,
                                    rem_writer,
                                    ciphers: up_ciphers,
                                    dc: dc_id,
                                    is_media,
                                },
                            )
                            .await;
                        }
                    }
                    return;
                }
                None => {
                    set_upstream_cooldown(&upstream.host, upstream.port, upstream_fail_cooldown);
                    warn!(
                        "[{}] upstream {}:{} failed, cooldown {}s",
                        label,
                        upstream.host,
                        upstream.port,
                        upstream_fail_cooldown.as_secs()
                    );
                }
            }
        }

        info!("[{}] {} → TCP fallback {}:443", label, reason, fallback);

        bridge_tcp(
            reader,
            writer,
            TcpBridgeParams {
                label: &label,
                dst: &fallback,
                relay_init: &relay_init,
                ciphers,
                dc: dc_id,
                is_media,
                connect_timeout: tcp_fallback_timeout,
                runtime: Arc::clone(&runtime),
            },
        )
        .await;

        return;
    }

    let target_ip = target_ip.unwrap();
    let ws_timeout = ws_timeout_for(dc_id, is_media, ws_connect_timeout, ws_fail_probe_timeout);

    // ── Step 6: CF priority — try CF proxy before direct WS if enabled ──
    if config.cf_priority && !config.cf_domains.is_empty() {
        if !cf_in_cooldown(dc_id, is_media) {
            let cf_domains_for_conn = if config.cf_balance {
                balanced_cf_domains(&config.cf_domains)
            } else {
                config.cf_domains.clone()
            };
            debug!(
                "[{}] DC{}{} cf-priority → trying CF proxy first",
                label, dc_id, media_tag
            );

            let (cf_ws_opt, _all_redirects) = connect_cf_ws_for_dc_with_outbound(
                dc_id,
                &cf_domains_for_conn,
                is_media,
                skip_tls,
                cf_connect_timeout,
                runtime.outbound(),
            )
            .await;

            if let Some(ws) = cf_ws_opt {
                clear_cf_cooldown(dc_id, is_media);
                info!(
                    "[{}] DC{}{} → CF proxy connected (priority)",
                    label, dc_id, media_tag
                );
                bridge_ws(
                    reader,
                    writer,
                    WsBridgeParams {
                        label: &label,
                        ws,
                        relay_init,
                        ciphers,
                        proto,
                        dc: dc_id,
                        is_media,
                        keepalive_interval,
                    },
                )
                .await;
                return;
            } else {
                set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                warn!(
                    "[{}] DC{}{} CF proxy failed (priority), cooldown {}s — falling back to WS",
                    label,
                    dc_id,
                    media_tag,
                    cf_fail_cooldown.as_secs()
                );
            }
        } else {
            debug!(
                "[{}] DC{}{} CF proxy in cooldown (priority), trying WS",
                label, dc_id, media_tag
            );
        }
    }

    // ── Step 6a: try pool first ──────────────────────────────────────────
    let ws_opt = pool.get(dc_id, is_media, target_ip.clone(), skip_tls).await;

    let ws = if let Some(ws) = ws_opt {
        info!(
            "[{}] DC{}{} → pool hit via {}",
            label, dc_id, media_tag, target_ip
        );

        ws
    } else {
        // ── Step 6b: fresh WebSocket connect ────────────────────────────
        let (ws_opt, all_redirects) = connect_ws_for_dc_with_outbound(
            &target_ip,
            ws_dc,
            is_media,
            skip_tls,
            ws_timeout,
            runtime.outbound(),
        )
        .await;

        match ws_opt {
            Some(ws) => {
                clear_dc_cooldown(dc_id, is_media);

                info!(
                    "[{}] DC{}{} → WS connected via {}",
                    label, dc_id, media_tag, target_ip
                );

                ws
            }
            None => {
                // WS failed — apply cooldown and try CF proxy, upstream proxies, or TCP fallback.
                if all_redirects {
                    blacklist_ws(dc_id, is_media, ws_redirect_cooldown);

                    warn!(
                        "[{}] DC{}{} WS cooldown {}s (all domains returned redirect)",
                        label,
                        dc_id,
                        media_tag,
                        ws_redirect_cooldown.as_secs()
                    );
                } else {
                    set_dc_cooldown(dc_id, is_media, ws_fail_cooldown);

                    info!(
                        "[{}] DC{}{} WS cooldown {}s",
                        label,
                        dc_id,
                        media_tag,
                        ws_fail_cooldown.as_secs()
                    );
                }

                // ── Try Cloudflare Worker if configured ──────────────────
                if !cf_worker_domains.is_empty() {
                    let workers_for_conn: Cow<'_, [String]> = if config.cf_balance {
                        Cow::Owned(balanced_cf_workers(&cf_worker_domains))
                    } else {
                        Cow::Borrowed(&cf_worker_domains)
                    };
                    for worker_domain in workers_for_conn.iter() {
                        if cf_worker_in_cooldown(worker_domain) {
                            debug!(
                                "[{}] DC{}{} CF Worker {} in cooldown, skipping",
                                label, dc_id, media_tag, worker_domain
                            );
                            continue;
                        }

                        debug!(
                            "[{}] DC{}{} WS failed → trying CF Worker {} for {}",
                            label, dc_id, media_tag, worker_domain, target_ip
                        );

                        if let Some(ws) = connect_cf_worker_ws_for_dc_with_outbound(
                            worker_domain,
                            &target_ip,
                            dc_id,
                            is_media,
                            skip_tls,
                            cf_connect_timeout,
                            runtime.outbound(),
                        )
                        .await
                        {
                            clear_cf_worker_cooldown(worker_domain);
                            info!(
                                "[{}] DC{}{} → CF Worker connected ({})",
                                label, dc_id, media_tag, worker_domain
                            );
                            bridge_ws(
                                reader,
                                writer,
                                WsBridgeParams {
                                    label: &label,
                                    ws,
                                    relay_init,
                                    ciphers,
                                    proto,
                                    dc: dc_id,
                                    is_media,
                                    keepalive_interval,
                                },
                            )
                            .await;
                            return;
                        } else {
                            set_cf_worker_cooldown(worker_domain, cf_fail_cooldown);
                            warn!(
                                "[{}] DC{}{} CF Worker {} failed, cooldown {}s",
                                label,
                                dc_id,
                                media_tag,
                                worker_domain,
                                cf_fail_cooldown.as_secs()
                            );
                        }
                    }
                }

                // ── Try Cloudflare proxy if configured ────────────────────
                // (Skip if --cf-priority already tried the CF path above.)
                if !config.cf_priority && !config.cf_domains.is_empty() {
                    if !cf_in_cooldown(dc_id, is_media) {
                        let cf_domains_for_conn = if config.cf_balance {
                            balanced_cf_domains(&config.cf_domains)
                        } else {
                            config.cf_domains.clone()
                        };
                        debug!(
                            "[{}] DC{}{} WS/Worker failed → trying CF proxy",
                            label, dc_id, media_tag
                        );

                        let (cf_ws_opt, _all_redirects) = connect_cf_ws_for_dc_with_outbound(
                            dc_id,
                            &cf_domains_for_conn,
                            is_media,
                            skip_tls,
                            cf_connect_timeout,
                            runtime.outbound(),
                        )
                        .await;

                        if let Some(ws) = cf_ws_opt {
                            clear_cf_cooldown(dc_id, is_media);
                            info!("[{}] DC{}{} → CF proxy connected", label, dc_id, media_tag);
                            bridge_ws(
                                reader,
                                writer,
                                WsBridgeParams {
                                    label: &label,
                                    ws,
                                    relay_init,
                                    ciphers,
                                    proto,
                                    dc: dc_id,
                                    is_media,
                                    keepalive_interval,
                                },
                            )
                            .await;
                            return;
                        } else {
                            set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                            warn!(
                                "[{}] DC{}{} CF proxy failed, cooldown {}s",
                                label,
                                dc_id,
                                media_tag,
                                cf_fail_cooldown.as_secs()
                            );
                        }
                    } else {
                        debug!(
                            "[{}] DC{}{} CF proxy in cooldown, skipping",
                            label, dc_id, media_tag
                        );
                    }
                }

                // Try each configured upstream MTProto proxy before direct TCP.
                for upstream in &config.mtproto_proxies {
                    if upstream_in_cooldown(&upstream.host, upstream.port) {
                        debug!(
                            "[{}] upstream {}:{} in cooldown, skipping",
                            label, upstream.host, upstream.port
                        );
                        continue;
                    }

                    match connect_mtproto_upstream(
                        &upstream.host,
                        upstream.port,
                        &upstream.secret,
                        dc_idx,
                        proto,
                        upstream_connect_timeout,
                        runtime.outbound(),
                    )
                    .await
                    {
                        Some(conn) => {
                            let is_ft = matches!(conn, UpstreamConnection::FakeTls(..));
                            clear_upstream_cooldown(&upstream.host, upstream.port);
                            info!(
                                "[{}] DC{}{} → upstream {} MTProto {}:{}",
                                label,
                                dc_id,
                                media_tag,
                                if is_ft { "FakeTLS" } else { "plain" },
                                upstream.host,
                                upstream.port
                            );
                            let ConnectionCiphers {
                                clt_dec, clt_enc, ..
                            } = ciphers;
                            match conn {
                                UpstreamConnection::Plain(
                                    rem_reader,
                                    rem_writer,
                                    up_enc,
                                    up_dec,
                                ) => {
                                    let up_ciphers = ConnectionCiphers {
                                        clt_dec,
                                        clt_enc,
                                        tg_enc: up_enc,
                                        tg_dec: up_dec,
                                    };
                                    bridge_mtproto_relay(
                                        reader,
                                        writer,
                                        MtprotoRelayParams {
                                            label: &label,
                                            rem_reader,
                                            rem_writer,
                                            ciphers: up_ciphers,
                                            dc: dc_id,
                                            is_media,
                                        },
                                    )
                                    .await;
                                }
                                UpstreamConnection::FakeTls(
                                    rem_reader,
                                    rem_writer,
                                    up_enc,
                                    up_dec,
                                ) => {
                                    let up_ciphers = ConnectionCiphers {
                                        clt_dec,
                                        clt_enc,
                                        tg_enc: up_enc,
                                        tg_dec: up_dec,
                                    };
                                    bridge_faketls_relay(
                                        reader,
                                        writer,
                                        FaketlsRelayParams {
                                            label: &label,
                                            rem_reader,
                                            rem_writer,
                                            ciphers: up_ciphers,
                                            dc: dc_id,
                                            is_media,
                                        },
                                    )
                                    .await;
                                }
                            }
                            return;
                        }
                        None => {
                            set_upstream_cooldown(
                                &upstream.host,
                                upstream.port,
                                upstream_fail_cooldown,
                            );
                            warn!(
                                "[{}] upstream {}:{} failed, cooldown {}s",
                                label,
                                upstream.host,
                                upstream.port,
                                upstream_fail_cooldown.as_secs()
                            );
                        }
                    }
                }

                let fallback = runtime
                    .fallback_ip(dc_id)
                    .map(str::to_string)
                    .unwrap_or(target_ip.clone());

                info!(
                    "[{}] DC{}{} → TCP fallback {}:443",
                    label, dc_id, media_tag, fallback
                );

                bridge_tcp(
                    reader,
                    writer,
                    TcpBridgeParams {
                        label: &label,
                        dst: &fallback,
                        relay_init: &relay_init,
                        ciphers,
                        dc: dc_id,
                        is_media,
                        connect_timeout: tcp_fallback_timeout,
                        runtime: Arc::clone(&runtime),
                    },
                )
                .await;

                return;
            }
        }
    };

    // ── Step 7: bidirectional WebSocket bridge ───────────────────────────
    bridge_ws(
        reader,
        writer,
        WsBridgeParams {
            label: &label,
            ws,
            relay_init,
            ciphers,
            proto,
            dc: dc_id,
            is_media,
            keepalive_interval,
        },
    )
    .await;
}

// ─── WebSocket bridge ────────────────────────────────────────────────────────

/// Run a bidirectional re-encrypted bridge between the client (TCP) and
/// Telegram (WebSocket).
///
/// ```text
/// client  →  clt_dec  →  plaintext  →  tg_enc  →  split  →  WebSocket frames  →  Telegram
/// Telegram  →  WS frame  →  tg_dec  →  plaintext  →  clt_enc  →  client TCP
/// ```
struct WsBridgeParams<'a> {
    label: &'a str,
    ws: TgWsStream,
    relay_init: [u8; 64],
    ciphers: ConnectionCiphers,
    proto: crate::crypto::ProtoTag,
    dc: u32,
    is_media: bool,
    keepalive_interval: Option<Duration>,
}

async fn bridge_ws(reader: ClientReader, writer: ClientWriter, params: WsBridgeParams<'_>) {
    let WsBridgeParams {
        label,
        mut ws,
        relay_init,
        ciphers,
        proto,
        dc,
        is_media,
        keepalive_interval,
    } = params;

    // Send the relay init packet to Telegram before bridging.
    if let Err(e) = ws_send(&mut ws, relay_init.to_vec()).await {
        warn!("[{}] failed to send relay init: {}", label, e);
        return;
    }

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;
    let splitter = MsgSplitter::new(&relay_init, proto);

    // Split the WebSocket stream into sink (send) and source (recv).
    let (mut ws_sink, mut ws_source) = ws.split();

    let start = std::time::Instant::now();

    // Spawn each bridge direction as an independent task so that when one
    // side closes (e.g. Telegram drops the WS after an idle timeout), the
    // other side is aborted immediately rather than hanging on blocked I/O
    // until the OS-level connection eventually times out.  With tokio::join!
    // both halves had to complete before the function returned, causing
    // zombie connections that exhausted the process file-descriptor limit.

    let mut upload = tokio::spawn({
        let mut splitter = splitter;

        async move {
            let mut reader = reader;
            let mut buf = vec![0u8; 65536];
            let mut total = 0u64;

            // Periodic WS PING frames keep the upstream connection alive
            // through NATs/firewalls that silently drop idle TCP flows.
            // Mirrors the Python reference implementation's `_ws_keepalive`
            // task: the loop exits as soon as a PING send fails, so a dead
            // upstream is detected promptly instead of lingering until the
            // next client packet.
            let mut keepalive_timer = keepalive_interval.map(tokio::time::interval);
            if let Some(timer) = keepalive_timer.as_mut() {
                // The first tick of a freshly created interval fires
                // immediately; consume it so the first PING is sent after a
                // full interval has elapsed, not right at connection start.
                timer.tick().await;
            }

            loop {
                let read_result = if let Some(timer) = keepalive_timer.as_mut() {
                    tokio::select! {
                        result = reader.read(&mut buf) => result,
                        _ = timer.tick() => {
                            if ws_sink.send(Message::Ping(Vec::new())).await.is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                } else {
                    reader.read(&mut buf).await
                };

                let n = match read_result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let chunk = &mut buf[..n];

                // Decrypt from client, then re-encrypt for Telegram.
                clt_dec.apply_keystream(chunk);
                tg_enc.apply_keystream(chunk);

                // Split into MTProto packets and send as separate WS frames.
                let parts = splitter.split(chunk);
                for part in parts {
                    if ws_sink.send(Message::Binary(part)).await.is_err() {
                        return total;
                    }
                }

                total += n as u64;
            }

            // Flush any partial last packet.
            for part in splitter.flush() {
                let _ = ws_sink.send(Message::Binary(part)).await;
            }

            // Close the WS sink so Telegram knows we are done and the
            // download direction (ws_source) receives the close frame and
            // terminates promptly instead of waiting indefinitely.
            let _ = ws_sink.close().await;
            total
        }
    });

    let mut download = tokio::spawn(async move {
        let mut writer = writer;
        let mut total = 0u64;

        loop {
            // Use the source half of the split WS stream.
            let data = match ws_source.next().await {
                Some(Ok(Message::Binary(b))) => b,
                Some(Ok(Message::Text(t))) => t.into_bytes(),
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                _ => break,
            };
            let mut data = data;

            // Decrypt from Telegram, then re-encrypt for client.
            tg_dec.apply_keystream(&mut data);
            clt_enc.apply_keystream(&mut data);

            if writer.write_all(&data).await.is_err() {
                break;
            }

            total += data.len() as u64;
        }

        total
    });

    // Wait for whichever direction finishes first, then abort the other so
    // its I/O handles (and file descriptors) are released immediately.
    let (bytes_up, bytes_down) = tokio::select! {
        result = &mut upload => {
            let up = result.unwrap_or(0);
            download.abort();

            let down = download.await.unwrap_or(0);

            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or(0);
            upload.abort();

            let up = upload.await.unwrap_or(0);

            (up, down)
        }
    };

    let elapsed = start.elapsed().as_secs_f32();

    info!(
        "[{}] DC{}{} WS session closed: ↑{}  ↓{}  {:.1}s",
        label,
        dc,
        if is_media { "m" } else { "" },
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        elapsed
    );
}

// ─── Upstream MTProto proxy connection ───────────────────────────────────────

/// Result of connecting to an upstream MTProto proxy.
///
/// - `Plain`: standard obfuscated TCP — data is sent/received raw.
/// - `FakeTls`: the connection is wrapped in TLS Application Data records.
enum UpstreamConnection {
    Plain(
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        AesCtr256,
        AesCtr256,
    ),
    FakeTls(
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        AesCtr256,
        AesCtr256,
    ),
}

/// Connect to an upstream MTProto proxy and perform the client handshake.
///
/// - `0xdd` or plain 16-byte secrets: standard obfuscated TCP.
/// - `0xee` secrets (≥17 bytes): FakeTLS — sends a TLS ClientHello with HMAC
///   authentication, drains the server's fake handshake, then sends the 64-byte
///   MTProto init inside a TLS Application Data record.
///
/// Returns the split TCP stream and the two ciphers for the session:
/// - `enc`: encrypts data we send to the upstream proxy.
/// - `dec`: decrypts data we receive from the upstream proxy.
async fn connect_mtproto_upstream(
    host: &str,
    port: u16,
    secret_hex: &str,
    dc_idx: i16,
    proto: crate::crypto::ProtoTag,
    timeout: Duration,
    outbound: &crate::outbound::OutboundConnector,
) -> Option<UpstreamConnection> {
    let secret = match hex::decode(secret_hex) {
        Ok(b) => b,
        Err(e) => {
            warn!("[upstream] {}:{} invalid hex secret: {}", host, port, e);
            return None;
        }
    };

    // ── Secret parsing ────────────────────────────────────────────────────
    //
    // Telegram MTProto proxy secrets start with an optional 1-byte mode flag:
    //   0xdd → padded-intermediate, key = secret[1..17]
    //   0xee → FakeTLS, key = secret[1..17], hostname = secret[17..]
    let is_faketls = secret.len() > 17 && secret[0] == 0xee;
    let key_bytes: &[u8] = if secret.len() >= 17 && matches!(secret[0], 0xdd | 0xee) {
        &secret[1..17]
    } else {
        &secret
    };

    // ── TCP connect ───────────────────────────────────────────────────────
    let stream = match outbound.connect(host, port, timeout).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[upstream] {}:{} connect error: {}", host, port, e);
            return None;
        }
    };
    let _ = stream.set_nodelay(true);

    let (handshake, enc, dec) = generate_client_handshake(key_bytes, dc_idx, proto);
    let (mut reader, mut writer) = tokio::io::split(stream);

    if is_faketls {
        // ── FakeTLS path ──────────────────────────────────────────────────
        let hostname = match std::str::from_utf8(&secret[17..]) {
            Ok(h) => h,
            Err(_) => {
                warn!(
                    "[upstream] {}:{} FakeTLS secret has non-UTF-8 hostname",
                    host, port
                );
                return None;
            }
        };

        // Build the ClientHello with HMAC authentication.
        let mut client_hello = build_faketls_client_hello(hostname);
        sign_faketls_client_hello(&mut client_hello, key_bytes);

        if let Err(e) = writer.write_all(&client_hello).await {
            warn!(
                "[upstream] {}:{} FakeTLS send ClientHello error: {}",
                host, port, e
            );
            return None;
        }

        // Drain the server's fake TLS handshake response.
        if !drain_faketls_server_hello(&mut reader).await {
            warn!(
                "[upstream] {}:{} FakeTLS server handshake failed",
                host, port
            );
            return None;
        }

        // Send the 64-byte MTProto init as the first Application Data record.
        if let Err(e) = write_tls_appdata(&mut writer, &handshake).await {
            warn!(
                "[upstream] {}:{} FakeTLS send MTProto init error: {}",
                host, port, e
            );
            return None;
        }

        Some(UpstreamConnection::FakeTls(reader, writer, enc, dec))
    } else {
        // ── Plain MTProto path ────────────────────────────────────────────
        if let Err(e) = writer.write_all(&handshake).await {
            warn!("[upstream] {}:{} send handshake error: {}", host, port, e);
            return None;
        }

        Some(UpstreamConnection::Plain(reader, writer, enc, dec))
    }
}

// ─── Upstream MTProto relay bridge ───────────────────────────────────────────

/// Bidirectional bridge between the client (TCP) and an upstream MTProto proxy
/// (TCP).  The upstream proxy handles the onward Telegram connection.
///
/// `ciphers.tg_enc` / `ciphers.tg_dec` must already be set to the upstream
/// session ciphers returned by [`connect_mtproto_upstream`].
struct MtprotoRelayParams<'a> {
    label: &'a str,
    rem_reader: tokio::io::ReadHalf<TcpStream>,
    rem_writer: tokio::io::WriteHalf<TcpStream>,
    ciphers: ConnectionCiphers,
    dc: u32,
    is_media: bool,
}

async fn bridge_mtproto_relay(
    reader: ClientReader,
    writer: ClientWriter,
    params: MtprotoRelayParams<'_>,
) {
    let MtprotoRelayParams {
        label,
        rem_reader,
        mut rem_writer,
        ciphers,
        dc,
        is_media,
    } = params;

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;

    // The upstream proxy is already expecting encrypted data (the client
    // handshake was the only "setup" packet; no additional relay_init is sent).

    let start = std::time::Instant::now();

    let mut upload = tokio::spawn(async move {
        let mut reader = reader;
        let mut buf = vec![0u8; 65536];
        let mut total = 0u64;

        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            clt_dec.apply_keystream(chunk);
            tg_enc.apply_keystream(chunk);
            if rem_writer.write_all(chunk).await.is_err() {
                break;
            }
            total += n as u64;
        }
        total
    });

    let mut download = tokio::spawn(async move {
        let mut rem_reader = rem_reader;
        let mut writer = writer;
        let mut buf = vec![0u8; 65536];
        let mut total = 0u64;

        loop {
            let n = match rem_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            tg_dec.apply_keystream(chunk);
            clt_enc.apply_keystream(chunk);
            if writer.write_all(chunk).await.is_err() {
                break;
            }
            total += n as u64;
        }
        total
    });

    let (bytes_up, bytes_down) = tokio::select! {
        result = &mut upload => {
            let up = result.unwrap_or(0);
            download.abort();
            let down = download.await.unwrap_or(0);
            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or(0);
            upload.abort();
            let up = upload.await.unwrap_or(0);
            (up, down)
        }
    };

    let elapsed = start.elapsed().as_secs_f32();
    info!(
        "[{}] DC{}{} upstream session closed: ↑{}  ↓{}  {:.1}s",
        label,
        dc,
        if is_media { "m" } else { "" },
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        elapsed
    );
}

// ─── FakeTLS upstream relay bridge ───────────────────────────────────────────

/// Bidirectional bridge between the client (TCP) and an upstream FakeTLS proxy.
///
/// Identical to [`bridge_mtproto_relay`] except that:
/// - **Writes to upstream** are wrapped in TLS Application Data records
///   (`\x17\x03\x03` + 2-byte big-endian length + payload).
/// - **Reads from upstream** parse TLS record headers and extract payloads.
///
/// The AES-CTR re-encryption (`clt_dec` / `tg_enc` and `tg_dec` / `clt_enc`)
/// operates on the payload inside TLS records, exactly as in the plain bridge.
struct FaketlsRelayParams<'a> {
    label: &'a str,
    rem_reader: tokio::io::ReadHalf<TcpStream>,
    rem_writer: tokio::io::WriteHalf<TcpStream>,
    ciphers: ConnectionCiphers,
    dc: u32,
    is_media: bool,
}

async fn bridge_faketls_relay(
    reader: ClientReader,
    writer: ClientWriter,
    params: FaketlsRelayParams<'_>,
) {
    let FaketlsRelayParams {
        label,
        rem_reader,
        rem_writer,
        ciphers,
        dc,
        is_media,
    } = params;

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;

    let start = std::time::Instant::now();

    // ── Upload: client → upstream (wrapped in TLS Application Data records)
    let mut upload = tokio::spawn(async move {
        let mut reader = reader;
        let mut rem_writer = rem_writer;
        let mut buf = vec![0u8; TLS_MAX_RECORD_PAYLOAD];
        let mut total = 0u64;

        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            clt_dec.apply_keystream(chunk);
            tg_enc.apply_keystream(chunk);

            if write_tls_appdata(&mut rem_writer, &buf[..n]).await.is_err() {
                break;
            }
            total += n as u64;
        }

        total
    });

    // ── Download: upstream → client (unwrap TLS Application Data records)
    let mut download = tokio::spawn(async move {
        let mut rem_reader = rem_reader;
        let mut writer = writer;
        let mut buf = vec![0u8; TLS_MAX_RECORD_PAYLOAD + 256];
        let mut total = 0u64;

        loop {
            let n = match read_tls_appdata(&mut rem_reader, &mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };

            let chunk = &mut buf[..n];
            tg_dec.apply_keystream(chunk);
            clt_enc.apply_keystream(chunk);

            if writer.write_all(chunk).await.is_err() {
                break;
            }
            total += n as u64;
        }

        total
    });

    let (bytes_up, bytes_down) = tokio::select! {
        result = &mut upload => {
            let up = result.unwrap_or(0);
            download.abort();
            let down = download.await.unwrap_or(0);
            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or(0);
            upload.abort();
            let up = upload.await.unwrap_or(0);
            (up, down)
        }
    };

    let elapsed = start.elapsed().as_secs_f32();
    info!(
        "[{}] DC{}{} upstream FakeTLS session closed: ↑{}  ↓{}  {:.1}s",
        label,
        dc,
        if is_media { "m" } else { "" },
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        elapsed
    );
}

// ─── TCP fallback bridge ─────────────────────────────────────────────────────

/// Connect directly to `dst:443` and bridge the re-encrypted streams.
///
/// Logs a session-close line on return (matching the `bridge_ws` format).
struct TcpBridgeParams<'a> {
    label: &'a str,
    dst: &'a str,
    relay_init: &'a [u8; 64],
    ciphers: crate::crypto::ConnectionCiphers,
    dc: u32,
    is_media: bool,
    connect_timeout: Duration,
    runtime: Arc<Runtime>,
}

async fn bridge_tcp(
    mut reader: ClientReader,
    mut writer: ClientWriter,
    params: TcpBridgeParams<'_>,
) {
    let TcpBridgeParams {
        label,
        dst,
        relay_init,
        ciphers,
        dc,
        is_media,
        connect_timeout,
        runtime,
    } = params;

    let remote = match runtime.outbound().connect(dst, 443, connect_timeout).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[{}] TCP fallback connect failed: {}", label, e);
            return;
        }
    };

    let _ = remote.set_nodelay(true);
    let (mut rem_reader, mut rem_writer) = tokio::io::split(remote);

    // Send relay init to the remote Telegram server.
    if let Err(e) = rem_writer.write_all(relay_init).await {
        warn!("[{}] TCP fallback: send relay init failed: {}", label, e);
        return;
    }

    let crate::crypto::ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;

    let start = std::time::Instant::now();

    let mut upload = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut total = 0u64;

        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];

            clt_dec.apply_keystream(chunk);
            tg_enc.apply_keystream(chunk);

            if rem_writer.write_all(chunk).await.is_err() {
                break;
            }

            total += n as u64;
        }

        total
    });

    let mut download = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut total = 0u64;

        loop {
            let n = match rem_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];

            tg_dec.apply_keystream(chunk);
            clt_enc.apply_keystream(chunk);

            if writer.write_all(chunk).await.is_err() {
                break;
            }

            total += n as u64;
        }
        total
    });

    // Same cross-direction cancellation as bridge_ws: abort the peer task
    // when one direction closes so FDs are freed immediately.
    let (bytes_up, bytes_down) = tokio::select! {
        result = &mut upload => {
            let up = result.unwrap_or(0);
            download.abort();

            let down = download.await.unwrap_or(0);

            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or(0);
            upload.abort();

            let up = upload.await.unwrap_or(0);

            (up, down)
        }
    };

    let elapsed = start.elapsed().as_secs_f32();

    info!(
        "[{}] DC{}{} TCP session closed: ↑{}  ↓{}  {:.1}s",
        label,
        dc,
        if is_media { "m" } else { "" },
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        elapsed
    );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

async fn read_inbound_handshake(
    label: &str,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    faketls_domain: Option<&str>,
) -> Option<InboundHandshake> {
    if let Some(domain) = faketls_domain {
        return accept_inbound_faketls(label, reader, writer, secrets, domain).await;
    }

    let mut handshake_buf = [0u8; 64];
    match reader.read_exact(&mut handshake_buf).await {
        Ok(_) => Some(InboundHandshake::Handshake(handshake_buf, Vec::new())),
        Err(e) => {
            debug!("[{}] read handshake: {}", label, e);
            None
        }
    }
}

/// Read a PROXY protocol v1 header line (`PROXY TCP4 src dst sport dport\r\n`)
/// and return the parsed `src_ip:src_port` label.
///
/// - `Ok(Some(label))`: a well-formed `PROXY ` line was parsed.
/// - `Ok(None)`: a line was read but it wasn't a `PROXY ` header — the
///   caller keeps using the original peer address. This mirrors the Python
///   reference implementation, which only logs a warning in this case
///   rather than dropping the connection; `--proxy-protocol` is only meant
///   to be enabled behind a trusted reverse proxy that always sends the
///   header, so this leniency is intentional.
/// - `Err(_)`: the socket closed or errored while reading the header.
async fn read_proxy_protocol_line(reader: &mut TcpReader) -> std::io::Result<Option<String>> {
    const MAX_LINE: usize = 256;
    let mut line = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        reader.read_exact(&mut byte).await?;
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > MAX_LINE {
            return Ok(None);
        }
    }

    let text = String::from_utf8_lossy(&line);
    let text = text.trim_end_matches('\r');
    if !text.starts_with("PROXY ") {
        return Ok(None);
    }

    // "PROXY" "TCP4"/"TCP6"/"UNKNOWN" src_ip dst_ip src_port dst_port
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 5 {
        return Ok(None);
    }
    let src_ip = parts[2];
    let src_port = parts[4];
    Ok(Some(format!("{}:{}", src_ip, src_port)))
}

pub fn split_mtproto_init_and_pending(data: &[u8]) -> Option<([u8; 64], Vec<u8>)> {
    if data.len() < 64 {
        return None;
    }

    let mut handshake_buf = [0u8; 64];
    handshake_buf.copy_from_slice(&data[..64]);

    Some((handshake_buf, data[64..].to_vec()))
}

fn human_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];

    let mut v = n as f64;
    for unit in UNITS {
        if v < 1024.0 {
            return format!("{:.1}{}", v, unit);
        }
        v /= 1024.0;
    }

    format!("{:.1}PB", v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balanced_cf_workers_rotates_start_domain() {
        CF_WORKER_BALANCE_COUNTER.store(0, Ordering::Relaxed);
        let workers = vec![
            "w1.example.workers.dev".to_string(),
            "w2.example.workers.dev".to_string(),
            "w3.example.workers.dev".to_string(),
        ];

        assert_eq!(
            balanced_cf_workers(&workers),
            vec![
                "w1.example.workers.dev".to_string(),
                "w2.example.workers.dev".to_string(),
                "w3.example.workers.dev".to_string(),
            ]
        );
        assert_eq!(
            balanced_cf_workers(&workers),
            vec![
                "w2.example.workers.dev".to_string(),
                "w3.example.workers.dev".to_string(),
                "w1.example.workers.dev".to_string(),
            ]
        );
        assert_eq!(
            balanced_cf_workers(&workers),
            vec![
                "w3.example.workers.dev".to_string(),
                "w1.example.workers.dev".to_string(),
                "w2.example.workers.dev".to_string(),
            ]
        );
    }

    #[test]
    fn worker_cooldown_is_tracked_per_domain() {
        clear_cf_worker_cooldown("w1.example.workers.dev");
        clear_cf_worker_cooldown("w2.example.workers.dev");

        assert!(!cf_worker_in_cooldown("w1.example.workers.dev"));
        assert!(!cf_worker_in_cooldown("w2.example.workers.dev"));

        set_cf_worker_cooldown("w1.example.workers.dev", Duration::from_secs(60));
        assert!(cf_worker_in_cooldown("w1.example.workers.dev"));
        assert!(!cf_worker_in_cooldown("w2.example.workers.dev"));

        clear_cf_worker_cooldown("w1.example.workers.dev");
        assert!(!cf_worker_in_cooldown("w1.example.workers.dev"));
    }
}
