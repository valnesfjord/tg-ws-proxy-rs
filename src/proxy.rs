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
//!       ▼
//!  [select_upstream]  ← the fallback ladder: pooled/direct WebSocket,
//!       │                Cloudflare Worker, Cloudflare proxy, upstream
//!       │                MTProto proxy, and finally raw TCP
//!       ▼
//!  [bridge_ws / bridge_relay / bridge_tcp]  ← bidirectional re-encryption
//! ```
//!
//! Routing and bridging are deliberately separated: [`select_upstream`] owns
//! the whole fallback ladder and hands back a connected upstream, so the
//! client's own reader/writer halves only ever have to be moved into a single
//! bridge call.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use cipher::StreamCipher;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use tungstenite::Message;

use crate::config::{Config, MtProtoProxy, UpstreamTier};
use crate::crypto::{
    AesCtr256, ConnectionCiphers, ProtoTag, build_connection_ciphers, generate_client_handshake,
    generate_relay_init, parse_handshake,
};
use crate::faketls::{
    TLS_MAX_RECORD_PAYLOAD, TLS_RECORD_HANDSHAKE, build_faketls_client_hello,
    build_faketls_server_hello, drain_faketls_server_hello, parse_faketls_client_hello,
    read_tls_appdata, read_tls_record_bytes, sign_faketls_client_hello, write_tls_appdata,
};
use crate::outbound::OutboundConnector;
use crate::pool::{CfTarget, CfTier, WsPool};
use crate::runtime::Runtime;
use crate::splitter::MsgSplitter;
use crate::ws_client::{
    TgWsStream, WsAttempt, connect_cf_worker_ws_for_dc_with_outbound,
    connect_cf_ws_for_dc_with_outbound_ordered, connect_ws_for_dc_with_outbound, media_tag,
};

type TcpReader = OwnedReadHalf;
type TcpWriter = OwnedWriteHalf;

/// Relay buffer size for reads from the *remote* side.
///
/// Deliberately small: it is allocated (and zeroed) per connection, so on the
/// routers and embedded boxes this proxy targets it dominates the
/// per-connection footprint.  16 KiB matches the cap the FakeTLS bridge has
/// always run at — a full TLS record — and costs only extra `read` syscalls,
/// since the per-byte work (AES-CTR, framing) is unchanged.
///
/// How many of these a connection holds depends on its path.  The default
/// WebSocket bridge holds none: `bridge_ws` reads downloads as owned frames
/// off the socket and only buffers the client direction.  `bridge_tcp` and the
/// plain relay hold one per direction.  So 200 concurrent connections went
/// from 12.5 MiB to 3.1 MiB on the WebSocket path, and from 25 MiB to 6.2 MiB
/// on the TCP fallback.
const RELAY_BUF_SIZE: usize = 16 * 1024;
/// AEAD expansion allowance over a full TLS record payload (RFC 8446 §5.2
/// caps a ciphertext record at 2^14 + 256).  The 5-byte record header is read
/// separately and never lands in these buffers.
const TLS_READ_HEADROOM: usize = 256;

/// Buffer size for reads from the *client*.
///
/// With `--listen-faketls-domain` a client read is a whole TLS record, and
/// `read_tls_appdata` reports a record that does not fit as `Ok(0)` — which
/// every bridge loop reads as EOF and silently ends the session. Sizing this
/// to the same tolerance the inbound handshake already accepts keeps a client
/// that emits a slightly oversized record working, for 256 bytes per
/// connection.
const CLIENT_READ_BUF_SIZE: usize = TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM;

// ─── Failure cooldowns ───────────────────────────────────────────────────────

/// Process-wide "do not retry until" deadlines for one fallback tier.
///
/// Each tier backs off independently after a failure so that a dead path is
/// not re-probed on every single connection.  Cooldowns are deliberately used
/// instead of a permanent blacklist: the proxy recovers on its own once the
/// network changes (or Telegram's redirect policy does).
struct CooldownMap<K> {
    entries: StdMutex<Option<HashMap<K, Instant>>>,
}

impl<K: Eq + Hash> CooldownMap<K> {
    const fn new() -> Self {
        Self {
            entries: StdMutex::new(None),
        }
    }

    fn set(&self, key: K, cooldown: Duration) {
        self.entries
            .lock()
            .unwrap()
            .get_or_insert_with(HashMap::new)
            .insert(key, Instant::now() + cooldown);
    }

    fn clear<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        if let Some(entries) = self.entries.lock().unwrap().as_mut() {
            entries.remove(key);
        }
    }

    /// Whether `key` is still inside its cooldown window.
    fn active<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock().unwrap();
        match entries.as_ref().and_then(|entries| entries.get(key)) {
            Some(&until) => Instant::now() < until,
            None => false,
        }
    }
}

/// Per-DC cooldown for the direct WebSocket path, keyed by `(dc, is_media)`.
/// Also carries the longer "all domains redirected" cooldown.
static WS_FAIL: CooldownMap<(u32, bool)> = CooldownMap::new();
/// Per-target-IP cooldown, keyed by the `--dc-ip` address that timed out.
///
/// Coarser than `WS_FAIL` on purpose.  `WS_FAIL` says "this DC's WebSocket is
/// unhappy, probe it with a short timeout"; this one says "TCP to this address
/// does not complete at all", which is what a DPI-blocked IP looks like and
/// does not change for hours.  Every DC sharing that address then skips the
/// direct path outright instead of each paying a connect timeout.
static IP_FAIL: CooldownMap<String> = CooldownMap::new();
/// Per-upstream cooldown for MTProto proxies, keyed by `host:port`.
static UPSTREAM_FAIL: CooldownMap<String> = CooldownMap::new();
/// Per-Worker cooldown for the Cloudflare Worker path.
static CF_WORKER_FAIL: CooldownMap<String> = CooldownMap::new();

fn upstream_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

// ─── Cloudflare domain balancing ─────────────────────────────────────────────

/// Round-robin counter for CF domain balancing (`--cf-balance`).
static CF_BALANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);
/// Round-robin counter for CF Worker domain balancing (`--cf-balance`).
static CF_WORKER_BALANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn balance_offset(domains: &[String], enabled: bool, counter: &AtomicUsize) -> usize {
    let n = domains.len();
    if !enabled || n <= 1 {
        return 0;
    }

    counter.fetch_add(1, Ordering::Relaxed) % n
}

fn domain_order(domains: &[String], first: usize) -> impl Iterator<Item = &str> {
    (0..domains.len()).map(move |offset| domains[(first + offset) % domains.len()].as_str())
}

// ─── Client-side framing ─────────────────────────────────────────────────────

enum ClientReader {
    Plain(TcpReader),
    FakeTls {
        reader: TcpReader,
        pending: PendingData,
    },
}

#[derive(Default)]
struct PendingData {
    data: Vec<u8>,
    offset: usize,
}

impl PendingData {
    fn from_record(data: Vec<u8>, offset: usize) -> Self {
        Self { data, offset }
    }

    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        let remaining = self.data.get(self.offset..)?;
        if remaining.is_empty() {
            return None;
        }

        let n = std::cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.offset += n;
        if self.offset == self.data.len() {
            self.data = Vec::new();
            self.offset = 0;
        }
        Some(n)
    }
}

impl ClientReader {
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(buf).await,
            Self::FakeTls { reader, pending } => {
                if let Some(n) = pending.read(buf) {
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

async fn accept_inbound_faketls(
    label: SocketAddr,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    expected_domain: &str,
) -> Option<([u8; 64], PendingData)> {
    let record = read_tls_record_bytes(reader, TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM)
        .await
        .ok()??;
    if record[0] != TLS_RECORD_HANDSHAKE || record[1..3] != [0x03, 0x01] {
        debug!("[{}] bad FakeTLS ClientHello record", label);
        return None;
    }

    let Some((hello, matched_secret)) = secrets.iter().find_map(|secret| {
        parse_faketls_client_hello(&record, secret).map(|hello| (hello, secret))
    }) else {
        debug!("[{}] bad FakeTLS ClientHello digest", label);
        return None;
    };

    if hello.hostname.as_deref() != Some(expected_domain) {
        debug!(
            "[{}] FakeTLS SNI mismatch: got {:?}, expected {}",
            label, hello.hostname, expected_domain
        );
        return None;
    }

    let server_hello = build_faketls_server_hello(matched_secret, &hello);
    if let Err(e) = writer.write_all(&server_hello).await {
        debug!("[{}] write FakeTLS ServerHello: {}", label, e);
        return None;
    }

    let mut handshake_buf = [0u8; 64];
    let mut filled = 0;
    while filled < handshake_buf.len() {
        let record = read_tls_record_bytes(reader, TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM)
            .await
            .ok()??;
        let record_type = record[0];
        let payload_len = record.len() - 5;
        if record_type == crate::faketls::TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != crate::faketls::TLS_RECORD_APPLICATION_DATA || payload_len == 0 {
            return None;
        }
        let take = std::cmp::min(payload_len, handshake_buf.len() - filled);
        handshake_buf[filled..filled + take].copy_from_slice(&record[5..5 + take]);
        filled += take;
        if take != payload_len {
            return Some((handshake_buf, PendingData::from_record(record, 5 + take)));
        }
    }

    Some((handshake_buf, PendingData::default()))
}

// ─── Client handler ──────────────────────────────────────────────────────────

/// Connect timeouts and failure cooldowns for one connection, resolved from
/// the CLI/env configuration.
struct Timeouts {
    ws_connect: Duration,
    ws_fail_probe: Duration,
    ws_fail_cooldown: Duration,
    ws_redirect_cooldown: Duration,
    ip_fail_cooldown: Duration,
    handshake: Duration,
    tcp_fallback: Duration,
    upstream_connect: Duration,
    upstream_fail_cooldown: Duration,
    cf_connect: Duration,
    cf_fail_cooldown: Duration,
}

impl Timeouts {
    fn from_config(config: &Config) -> Self {
        Self {
            ws_connect: Duration::from_secs(config.ws_connect_timeout),
            ws_fail_probe: Duration::from_secs(config.ws_fail_probe_timeout),
            ws_fail_cooldown: Duration::from_secs(config.ws_fail_cooldown),
            ws_redirect_cooldown: Duration::from_secs(config.ws_redirect_cooldown),
            ip_fail_cooldown: Duration::from_secs(config.ip_fail_cooldown),
            handshake: Duration::from_secs(config.handshake_timeout),
            tcp_fallback: Duration::from_secs(config.tcp_fallback_timeout),
            upstream_connect: Duration::from_secs(config.upstream_connect_timeout),
            upstream_fail_cooldown: Duration::from_secs(config.upstream_fail_cooldown),
            cf_connect: Duration::from_secs(config.cf_connect_timeout),
            cf_fail_cooldown: Duration::from_secs(config.cf_fail_cooldown),
        }
    }
}

/// Handle one inbound client connection end-to-end.
///
/// `config` is shared rather than owned: it is read-only for the whole life of
/// the process, and cloning it per connection meant copying every secret and
/// domain list — with `--default-domains` that is a few dozen `String`s on the
/// accept path.
pub async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
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
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<WsPool>,
    runtime: Arc<Runtime>,
) {
    let label = peer;
    let _ = stream.set_nodelay(true);

    let secrets = config.normalized_secrets();
    let timeouts = Timeouts::from_config(&config);

    // Split into independent read / write halves.
    let (mut reader, mut writer) = stream.into_split();

    // ── Step 1: read the 64-byte MTProto obfuscation init ────────────────
    let inbound_faketls_domain = config.normalized_listen_faketls_domain();
    let handshake = tokio::time::timeout(
        timeouts.handshake,
        read_inbound_handshake(
            label,
            &mut reader,
            &mut writer,
            secrets,
            inbound_faketls_domain,
        ),
    )
    .await;

    let (handshake_buf, faketls_pending) = match handshake {
        Ok(Some(result)) => result,
        Ok(None) => return,
        Err(_) => {
            debug!("[{}] handshake timeout", label);
            return;
        }
    };

    let (reader, writer) = if inbound_faketls_domain.is_some() {
        (
            ClientReader::FakeTls {
                reader,
                pending: faketls_pending,
            },
            ClientWriter::FakeTls(writer),
        )
    } else {
        (ClientReader::Plain(reader), ClientWriter::Plain(writer))
    };

    // ── Step 2: parse and validate the handshake ─────────────────────────
    let Some((info, secret)) = secrets
        .iter()
        .find_map(|secret| parse_handshake(&handshake_buf, secret).map(|i| (i, secret.as_slice())))
    else {
        debug!(
            "[{}] bad handshake (wrong secret or reserved prefix)",
            label
        );

        // Drain the connection silently to avoid giving information to scanners.
        reader.drain().await;

        return;
    };

    let dc_id = info.dc_id;
    let is_media = info.is_media;
    let proto = info.proto;
    let dc_idx: i16 = if is_media {
        -(dc_id as i16)
    } else {
        dc_id as i16
    };

    debug!(
        "[{}] handshake ok: DC{}{} proto={:?}",
        label,
        dc_id,
        media_tag(is_media),
        proto
    );

    // ── Step 3: generate the relay init packet for the Telegram backend ──
    let relay_init = generate_relay_init(proto, dc_idx);

    // ── Step 4: build all four AES-256-CTR ciphers ───────────────────────
    let ciphers = build_connection_ciphers(&info.prekey_and_iv, secret, &relay_init);

    // ── Step 5: walk the fallback ladder ─────────────────────────────────
    let route = Route {
        label,
        config: &config,
        runtime: &runtime,
        pool: &pool,
        timeouts,
        dc: dc_id,
        is_media,
        media: media_tag(is_media),
        dc_idx,
        proto,
    };
    let target_ip = config.dc_target_ip(dc_id);

    // ── Step 6: bridge whatever we ended up connected to ─────────────────
    // The routing ladder contains every TLS/WS fallback handshake, while only
    // one bridge branch survives for the session. Box the short-lived ladder,
    // then box only the bridge actually selected; otherwise Rust's async state
    // machine reserves space for their combined widest variants forever.
    let bridge = Box::pin(select_bridge(
        &route,
        target_ip,
        reader,
        writer,
        BridgeDispatch {
            label,
            relay_init,
            ciphers,
            proto,
            dc: dc_id,
            is_media,
            tcp_connect_timeout: route.timeouts.tcp_fallback,
            runtime: Arc::clone(&runtime),
        },
    ))
    .await;
    if let Some(bridge) = bridge {
        bridge.await;
    }
}

// ─── Routing ─────────────────────────────────────────────────────────────────

async fn select_bridge(
    route: &Route<'_>,
    target_ip: Option<&str>,
    reader: ClientReader,
    writer: ClientWriter,
    params: BridgeDispatch,
) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
    select_upstream(route, target_ip)
        .await
        .map(|upstream| bridge_selected(reader, writer, upstream, params))
}

/// The upstream a connection was routed to, ready to be bridged.
// Every other layer (the pool, `WsConnectResult`, the bridges) moves
// `TgWsStream` unboxed; boxing it only here would add a heap allocation to the
// connect path for one move per connection.
#[allow(clippy::large_enum_variant)]
enum Upstream {
    /// A WebSocket to Telegram — direct, via the Cloudflare proxy, or through
    /// a Cloudflare Worker tunnel.  See [`WsFraming`] for why the two are not
    /// interchangeable once bridged.
    Ws { ws: TgWsStream, framing: WsFraming },
    /// An upstream MTProto proxy, plain or FakeTLS-wrapped.
    Mtproto(UpstreamConnection),
    /// Last resort: a direct TCP connection to this Telegram DC IP.
    Tcp(String),
}

struct BridgeDispatch {
    label: SocketAddr,
    relay_init: [u8; 64],
    ciphers: ConnectionCiphers,
    proto: ProtoTag,
    dc: u32,
    is_media: bool,
    tcp_connect_timeout: Duration,
    runtime: Arc<Runtime>,
}

/// Erase the unselected bridge variants before the session-long await.
///
/// Returning one boxed trait object matters here: an `async` `match` reserves
/// enough state for its widest branch even though a connection uses exactly
/// one of them. This synchronous dispatch moves only the selected bridge into
/// its allocation, then drops the `Upstream` enum immediately.
fn bridge_selected(
    reader: ClientReader,
    writer: ClientWriter,
    upstream: Upstream,
    params: BridgeDispatch,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    let BridgeDispatch {
        label,
        relay_init,
        ciphers,
        proto,
        dc,
        is_media,
        tcp_connect_timeout,
        runtime,
    } = params;

    match upstream {
        Upstream::Ws { ws, framing } => Box::pin(bridge_ws(
            reader,
            writer,
            WsBridgeParams {
                label,
                ws,
                framing,
                relay_init,
                ciphers,
                proto,
                dc,
                is_media,
            },
        )),
        Upstream::Mtproto(conn) => {
            let ConnectionCiphers {
                clt_dec, clt_enc, ..
            } = ciphers;

            Box::pin(bridge_relay(
                reader,
                writer,
                RelayParams {
                    label,
                    rem_reader: conn.reader,
                    rem_writer: conn.writer,
                    ciphers: ConnectionCiphers {
                        clt_dec,
                        clt_enc,
                        tg_enc: conn.enc,
                        tg_dec: conn.dec,
                    },
                    faketls: conn.faketls,
                    dc,
                    is_media,
                },
            ))
        }
        Upstream::Tcp(dst) => Box::pin(async move {
            bridge_tcp(
                reader,
                writer,
                TcpBridgeParams {
                    label,
                    dst: &dst,
                    relay_init: &relay_init,
                    ciphers,
                    dc,
                    is_media,
                    connect_timeout: tcp_connect_timeout,
                    runtime,
                },
            )
            .await;
        }),
    }
}

/// How the client's byte stream has to be cut into WebSocket messages.
///
/// The two upstream kinds want opposite things, and getting it wrong only
/// shows up under load:
///
/// * Telegram's own `/apiws` endpoint (direct or fronted by the Cloudflare
///   proxy) treats every WebSocket message as exactly one MTProto packet, so
///   the stream must go through [`MsgSplitter`].
/// * A Cloudflare Worker is a raw TCP tunnel — it writes each message's
///   payload straight into the socket, so boundaries carry no meaning there.
///   Packet-aligning for it is not just pointless but harmful: Cloudflare
///   caps a WebSocket message at 1 MiB, and a media upload produces MTProto
///   packets well past that, which killed the connection mid-transfer
///   (Flowseal/tg-ws-proxy#1161, fixed upstream in v1.9.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum WsFraming {
    /// One WebSocket message per MTProto packet.
    Packets,
    /// Opaque byte stream, chunked at whatever size reads off the client.
    Tunnel,
}

/// Everything the fallback ladder needs to route one client connection.
struct Route<'a> {
    label: SocketAddr,
    config: &'a Config,
    runtime: &'a Runtime,
    pool: &'a Arc<WsPool>,
    timeouts: Timeouts,
    dc: u32,
    is_media: bool,
    /// Cached [`media_tag`] for this DC, used in every log line.
    media: &'static str,
    dc_idx: i16,
    proto: ProtoTag,
}

/// Walk the fallback ladder and return the upstream to bridge, or `None` when
/// the connection cannot be routed at all.
///
/// `target_ip` is the DC's `--dc-ip` override, if the user configured one.
/// Without it the direct WebSocket path is skipped entirely and the Python
/// reference's order is used (Worker, CF proxy, upstream proxies, then TCP).
async fn select_upstream(route: &Route<'_>, target_ip: Option<&str>) -> Option<Upstream> {
    // ── Pinned per-class ladder (--pinned-upstream / --pinned-media-upstream)
    // Replaces the default priority order wholesale, including --cf-priority:
    // the user asked for exactly these tiers in exactly this order.
    if let Some(tiers) = route.config.forced_upstreams(route.is_media) {
        return route.pinned_ladder(tiers, target_ip).await;
    }

    let Some(target_ip) = target_ip else {
        // Every log line already carries the DC, so the reason only has to say
        // what is missing.
        let reason = "not in --dc-ip config";
        let Some(fallback) = route.runtime.fallback_ip(route.dc) else {
            warn!(
                "[{}] DC{}{} {} — no fallback IP available",
                route.label, route.dc, route.media, reason
            );
            return None;
        };

        return Some(
            route
                .fallback_chain(fallback, reason)
                .await
                .unwrap_or_else(|| route.tcp_fallback(fallback, reason)),
        );
    };

    // ── An IP that just timed out is stepped over ────────────────────────
    // A DPI-blocked DC IP does not come back within one connection's
    // lifetime, so re-probing it per connection only adds the connect
    // timeout to every single client — the delay that makes Telegram sit in
    // "Connecting..." forever.  Only worth skipping when there is somewhere
    // else to go; without a fallback the doomed attempt is still the only
    // path we have.
    let ip_cooling = IP_FAIL.active(target_ip) && route.has_fallback();
    if ip_cooling {
        let reason = "IP in cooldown";
        info!(
            "[{}] DC{}{} {} → skipping direct WS to {}",
            route.label, route.dc, route.media, reason, target_ip
        );

        // Stepped over, not written off: if every fallback is also gone the
        // address gets its chance back rather than leaving the client on the
        // raw-TCP path for the rest of the cooldown.  That is what makes the
        // cooldown self-healing — a direct connect is the only thing that
        // clears it, so something has to keep asking.
        if let Some(upstream) = route.fallback_chain(target_ip, reason).await {
            return Some(upstream);
        }

        info!(
            "[{}] DC{}{} every fallback failed → re-probing {}",
            route.label, route.dc, route.media, target_ip
        );
    }

    // ── Pool first, then a fresh WebSocket connect ───────────────────────
    if let Some(upstream) = route.direct_ws_tier(target_ip).await {
        return Some(upstream);
    }

    // WS failed (and is now in cooldown) — walk the rest of the ladder.
    let reason = "WS failed";
    if ip_cooling {
        // The re-probe above was the last thing left to try: every other tier
        // already failed on the way in, and nothing since then can have
        // revived them.
        return Some(route.tcp_last_resort(target_ip, reason));
    }

    Some(
        route
            .fallback_chain(target_ip, reason)
            .await
            .unwrap_or_else(|| route.tcp_last_resort(target_ip, reason)),
    )
}

impl Route<'_> {
    /// The direct-WebSocket rung shared by both ladders: pool first, then a
    /// fresh connect (fronted from the first attempt when configured).
    async fn direct_ws_tier(&self, target_ip: &str) -> Option<Upstream> {
        let pooled = self
            .pool
            .get(
                self.dc,
                self.is_media,
                target_ip,
                self.config.skip_tls_verify,
                !IP_FAIL.active(target_ip),
            )
            .await;
        if let Some(ws) = pooled {
            info!(
                "[{}] DC{}{} → pool hit via {}",
                self.label, self.dc, self.media, target_ip
            );
            return Some(Upstream::Ws {
                ws,
                framing: WsFraming::Packets,
            });
        }

        self.direct_ws(target_ip).await.map(|ws| Upstream::Ws {
            ws,
            framing: WsFraming::Packets,
        })
    }

    /// Walk the user-pinned tier order (`--pinned-upstream` /
    /// `--pinned-media-upstream`) instead of the default ladder.
    ///
    /// Each tier runs with the same pool, cooldown and fronting behavior it
    /// has in the default ladder; the first tier that produces a connection
    /// wins.  A tier that is not configured — or not reachable, like `ws` for
    /// a DC without a `--dc-ip` target — is skipped with a log line, so the
    /// user can see the pin referring to nothing.  When every listed tier
    /// fails, the connection is dropped: pinning is opt-in, so tiers the user
    /// left out are not quietly re-added as fallbacks.
    ///
    /// The one departure from the default cooldown behavior is on the last
    /// tier that can still connect: the Worker and upstream-MTProto rungs
    /// dial through their cooldown there instead of skipping.  In the default
    /// ladder a cooldown only buys a faster step to the next rung, and the
    /// terminal TCP rung always attempts; a pin has no next rung, so
    /// respecting the skip would turn one transient failure into a
    /// cooldown-length outage with nothing left to clear it.
    async fn pinned_ladder(
        &self,
        tiers: &[UpstreamTier],
        target_ip: Option<&str>,
    ) -> Option<Upstream> {
        for (index, tier) in tiers.iter().enumerate() {
            let last_resort = !self.tier_attemptable_after(tiers, index + 1, target_ip);
            match tier {
                UpstreamTier::Ws => {
                    let Some(target_ip) = target_ip else {
                        warn!(
                            "[{}] DC{}{} pinned ws tier has no --dc-ip target, skipping",
                            self.label, self.dc, self.media
                        );
                        continue;
                    };
                    if let Some(upstream) = self.direct_ws_tier(target_ip).await {
                        return Some(upstream);
                    }
                }
                UpstreamTier::Cfworker => {
                    let Some(dst) = self.runtime.fallback_ip(self.dc).or(target_ip) else {
                        warn!(
                            "[{}] DC{}{} pinned cfworker tier has no destination IP, skipping",
                            self.label, self.dc, self.media
                        );
                        continue;
                    };
                    if let Some(ws) = self.cf_worker(dst, "pinned", last_resort).await {
                        return Some(Upstream::Ws {
                            ws,
                            framing: WsFraming::Tunnel,
                        });
                    }
                }
                UpstreamTier::Cfproxy => {
                    if let Some(ws) = self.cf_proxy("pinned").await {
                        return Some(Upstream::Ws {
                            ws,
                            framing: WsFraming::Packets,
                        });
                    }
                }
                UpstreamTier::Mtproto => {
                    if let Some(conn) = self.upstream_proxies("pinned", last_resort).await {
                        return Some(Upstream::Mtproto(conn));
                    }
                }
                UpstreamTier::Tcp => {
                    let Some(dst) = self.runtime.fallback_ip(self.dc).or(target_ip) else {
                        warn!(
                            "[{}] DC{}{} pinned tcp tier has no fallback IP, skipping",
                            self.label, self.dc, self.media
                        );
                        continue;
                    };
                    return Some(self.tcp_fallback(dst, "pinned"));
                }
            }
        }

        warn!(
            "[{}] DC{}{} every pinned upstream failed",
            self.label, self.dc, self.media
        );
        None
    }

    /// Whether any pinned tier after `from` can produce a connection at all.
    ///
    /// Mirrors the rungs' own skip conditions: `ws` needs a `--dc-ip` target,
    /// the Cloudflare and upstream rungs need their configuration, `tcp`
    /// needs any destination. This is what tells the cooldown-gated rungs
    /// whether they are the ladder's last resort.
    fn tier_attemptable_after(
        &self,
        tiers: &[UpstreamTier],
        from: usize,
        target_ip: Option<&str>,
    ) -> bool {
        tiers[from..].iter().any(|tier| match tier {
            UpstreamTier::Ws => target_ip.is_some(),
            UpstreamTier::Cfworker => !self.config.cf_worker_domains().is_empty(),
            UpstreamTier::Cfproxy => !self.config.cf_domains.is_empty(),
            UpstreamTier::Mtproto => !self.config.mtproto_proxies.is_empty(),
            UpstreamTier::Tcp => target_ip.is_some() || self.runtime.fallback_ip(self.dc).is_some(),
        })
    }

    /// The Cloudflare Worker → Cloudflare proxy → upstream MTProto ladder,
    /// shared by both entry points into the fallback chain.
    ///
    /// `dst` is the Telegram DC IP the Worker should open its TCP tunnel to.
    /// Returns `None` when every configured tier failed or was skipped.
    async fn fallback_chain(&self, dst: &str, reason: &str) -> Option<Upstream> {
        if let Some(upstream) = self.cf_tiers(dst, reason).await {
            return Some(upstream);
        }

        self.upstream_proxies(reason, false)
            .await
            .map(Upstream::Mtproto)
    }

    /// Both Cloudflare tiers in upstream's order: Worker tunnel first, then
    /// the Cloudflare proxy.
    ///
    /// Kept as one step so `--cf-priority` and the post-failure fallback walk
    /// the identical ladder — a Worker-only setup used to sit out
    /// `--cf-priority` entirely and pay the full direct-WS timeout on every
    /// connection before reaching its only working path.
    async fn cf_tiers(&self, dst: &str, reason: &str) -> Option<Upstream> {
        if let Some(ws) = self.cf_worker(dst, reason, false).await {
            return Some(Upstream::Ws {
                ws,
                framing: WsFraming::Tunnel,
            });
        }

        self.cf_proxy(reason).await.map(|ws| Upstream::Ws {
            ws,
            framing: WsFraming::Packets,
        })
    }

    /// Describe the connection the pool should re-open, off the one that just
    /// worked.
    ///
    /// Only one domain is carried over, not the whole candidate list: the
    /// spare is opened through a known-good route rather than re-walking the
    /// ladder in the background, and a domain that stops working simply stops
    /// refilling — the inline path still tries every candidate.
    ///
    /// Which one depends on `--cf-balance`.  Off, it is the domain that just
    /// answered, so the pool inherits the same preference order the inline
    /// path has.  On, pinning the pool to one domain would quietly undo the
    /// balancing — roughly every other connection is a pool hit — so the spare
    /// is opened through the next domain in the rotation instead.
    ///
    /// `dst` is only meaningful for [`CfTier::Worker`] — the DC IP its tunnel
    /// opens onto.
    fn cf_target(
        &self,
        tier: CfTier,
        dst: &str,
        domain: &str,
        rotation: &[String],
        counter: &AtomicUsize,
    ) -> CfTarget {
        let domain = if self.config.cf_balance {
            domain_order(rotation, balance_offset(rotation, true, counter))
                .next()
                .unwrap_or(domain)
                .to_string()
        } else {
            domain.to_string()
        };

        CfTarget {
            tier,
            dc: self.dc,
            is_media: self.is_media,
            dst: dst.to_string(),
            domain,
            skip_tls_verify: self.config.skip_tls_verify,
            connect_timeout: self.timeouts.cf_connect,
        }
    }

    /// Whether anything other than the direct WebSocket path is configured.
    fn has_fallback(&self) -> bool {
        !self.config.cf_worker_domains().is_empty()
            || !self.config.cf_domains.is_empty()
            || !self.config.mtproto_proxies.is_empty()
    }

    /// Try every configured Cloudflare Worker tunnel in `--cf-balance` order.
    /// `force` dials through the per-domain failure cooldown — the pinned
    /// ladder's last resort, where a skip would drop the connection rather
    /// than reach a next rung.  The default ladder always passes `false`.
    async fn cf_worker(&self, dst: &str, reason: &str, force: bool) -> Option<TgWsStream> {
        let worker_domains = self.config.cf_worker_domains();
        if worker_domains.is_empty() {
            return None;
        }

        // `--dc-ip` says which address *this host* should dial; the Worker
        // dials from Cloudflare's network, where that choice carries no
        // weight and a stale override would just send the tunnel somewhere
        // dead. Upstream tg-ws-proxy likewise always tunnels to the built-in
        // DC address.
        let dst = self.runtime.fallback_ip(self.dc).unwrap_or(dst);

        if let Some((ws, domain)) = self
            .pool
            .cf_get(CfTier::Worker, self.dc, self.is_media)
            .await
        {
            info!(
                "[{}] DC{}{} {} → CF Worker pool hit ({})",
                self.label, self.dc, self.media, reason, domain
            );

            return Some(ws);
        }

        let first_worker = balance_offset(
            worker_domains,
            self.config.cf_balance,
            &CF_WORKER_BALANCE_COUNTER,
        );

        for worker_domain in domain_order(worker_domains, first_worker) {
            if !force && CF_WORKER_FAIL.active(worker_domain) {
                debug!(
                    "[{}] DC{}{} CF Worker {} in cooldown, skipping",
                    self.label, self.dc, self.media, worker_domain
                );
                continue;
            }

            debug!(
                "[{}] DC{}{} {} → trying CF Worker {} for {}",
                self.label, self.dc, self.media, reason, worker_domain, dst
            );

            let ws = connect_cf_worker_ws_for_dc_with_outbound(
                worker_domain,
                dst,
                self.dc,
                self.is_media,
                self.config.skip_tls_verify,
                self.timeouts.cf_connect,
                self.runtime.outbound(),
            )
            .await;

            match ws {
                Some(ws) => {
                    CF_WORKER_FAIL.clear(worker_domain);
                    info!(
                        "[{}] DC{}{} {} → CF Worker connected ({})",
                        self.label, self.dc, self.media, reason, worker_domain
                    );
                    // This Worker answers, so it is worth holding a spare
                    // tunnel open for the client's next connection — Telegram
                    // opens a new one per media transfer, and each pays the
                    // handshake to Cloudflare *and* Cloudflare's own connect
                    // to the DC.
                    self.pool.cf_prefetch(self.cf_target(
                        CfTier::Worker,
                        dst,
                        worker_domain,
                        worker_domains,
                        &CF_WORKER_BALANCE_COUNTER,
                    ));

                    return Some(ws);
                }
                None => {
                    CF_WORKER_FAIL.set(worker_domain.to_string(), self.timeouts.cf_fail_cooldown);
                    warn!(
                        "[{}] DC{}{} CF Worker {} failed, cooldown {}s",
                        self.label,
                        self.dc,
                        self.media,
                        worker_domain,
                        self.timeouts.cf_fail_cooldown.as_secs()
                    );
                }
            }
        }

        None
    }

    /// Try the configured Cloudflare proxy domains in `--cf-balance` order.
    ///
    /// Deliberately has no per-DC cooldown, matching upstream's
    /// `_cfproxy_fallback`, which retries every configured domain on every
    /// single connection with no failure memory at all.  A per-DC cooldown
    /// (removed) meant one flaky domain among many (e.g. with
    /// `--cf-balance`/`--default-domains`) blocked *all* of them for the whole
    /// cooldown window, forcing every connection in that window down into the
    /// fronting/TCP fallback instead.
    async fn cf_proxy(&self, reason: &str) -> Option<TgWsStream> {
        if self.config.cf_domains.is_empty() {
            return None;
        }

        let first_domain = balance_offset(
            &self.config.cf_domains,
            self.config.cf_balance,
            &CF_BALANCE_COUNTER,
        );

        if let Some((ws, domain)) = self
            .pool
            .cf_get(CfTier::Proxy, self.dc, self.is_media)
            .await
        {
            info!(
                "[{}] DC{}{} {} → CF proxy pool hit ({})",
                self.label, self.dc, self.media, reason, domain
            );

            return Some(ws);
        }

        debug!(
            "[{}] DC{}{} {} → trying CF proxy via {:?}",
            self.label, self.dc, self.media, reason, self.config.cf_domains
        );

        let (ws, domain, _all_redirects) = connect_cf_ws_for_dc_with_outbound_ordered(
            self.dc,
            &self.config.cf_domains,
            self.is_media,
            self.config.skip_tls_verify,
            self.timeouts.cf_connect,
            self.runtime.outbound(),
            first_domain,
        )
        .await;

        if ws.is_some() {
            info!(
                "[{}] DC{}{} {} → CF proxy connected",
                self.label, self.dc, self.media, reason
            );
            if let Some(domain) = domain {
                self.pool.cf_prefetch(self.cf_target(
                    CfTier::Proxy,
                    "",
                    &domain,
                    &self.config.cf_domains,
                    &CF_BALANCE_COUNTER,
                ));
            }
        } else {
            warn!(
                "[{}] DC{}{} CF proxy failed (all configured domains)",
                self.label, self.dc, self.media
            );
        }

        ws
    }

    /// Try each configured upstream MTProto proxy in order.
    ///
    /// `force` dials through the failure cooldown — see [`Self::cf_worker`].
    async fn upstream_proxies(&self, reason: &str, force: bool) -> Option<UpstreamConnection> {
        for upstream in &self.config.mtproto_proxies {
            let key = upstream_key(&upstream.host, upstream.port);
            if !force && UPSTREAM_FAIL.active(key.as_str()) {
                debug!("[{}] upstream {} in cooldown, skipping", self.label, key);
                continue;
            }

            let conn = connect_mtproto_upstream(
                upstream,
                self.dc_idx,
                self.proto,
                self.timeouts.upstream_connect,
                self.runtime.outbound(),
            )
            .await;

            match conn {
                Some(conn) => {
                    UPSTREAM_FAIL.clear(key.as_str());
                    info!(
                        "[{}] DC{}{} {} → upstream {} MTProto {}",
                        self.label,
                        self.dc,
                        self.media,
                        reason,
                        if conn.faketls { "FakeTLS" } else { "plain" },
                        key
                    );
                    return Some(conn);
                }
                None => {
                    UPSTREAM_FAIL.set(key.clone(), self.timeouts.upstream_fail_cooldown);
                    warn!(
                        "[{}] upstream {} failed, cooldown {}s",
                        self.label,
                        key,
                        self.timeouts.upstream_fail_cooldown.as_secs()
                    );
                }
            }
        }

        None
    }

    /// Open a fresh direct WebSocket to `target_ip`, always fronted when
    /// `--fronting-domain` is set, and applying the per-DC cooldown on
    /// failure.
    async fn direct_ws(&self, target_ip: &str) -> Option<TgWsStream> {
        // `--fronting-domain` means the very first ClientHello carries the
        // fronted SNI. A reactive "front only after the direct SNI times out"
        // switch sends the real `telegram.org` SNI first, which networks that
        // RST it on sight never let through (#111) — so there is nothing left
        // to decide here: front when configured, otherwise don't.
        let fronting = self.runtime.fronting_domain();

        // A DC inside its own cooldown is probed on a much shorter clock, so
        // a timeout there says far less about the address than a full-budget
        // one does — see `cool_down_ip`.
        let probing = WS_FAIL.active(&(self.dc, self.is_media));
        let attempt = self.connect_ws(target_ip, fronting).await;

        if let Some(ws) = attempt.ws {
            WS_FAIL.clear(&(self.dc, self.is_media));
            IP_FAIL.clear(target_ip);
            match fronting {
                Some(domain) => info!(
                    "[{}] DC{}{} → WS connected via {} (fronted SNI {})",
                    self.label, self.dc, self.media, target_ip, domain
                ),
                None => info!(
                    "[{}] DC{}{} → WS connected via {}",
                    self.label, self.dc, self.media, target_ip
                ),
            }

            return Some(ws);
        }

        self.cool_down_ws(attempt.all_redirects);

        // Only a TCP connect that ran out the clock says the address itself is
        // unreachable.  A redirect, a refusal, or a handshake that stalled all
        // came from a host that is very much there, and taking it out of the
        // rotation for an hour on that basis would be wrong.
        if attempt.connect_timed_out && !probing {
            self.cool_down_ip(target_ip);
        }

        None
    }

    async fn connect_ws(&self, target_ip: &str, sni_override: Option<&str>) -> WsAttempt {
        // A DC still inside its failure cooldown is probed with a much shorter
        // timeout so a doomed attempt does not delay the fallback chain.
        let timeout = if WS_FAIL.active(&(self.dc, self.is_media)) {
            self.timeouts.ws_fail_probe
        } else {
            self.timeouts.ws_connect
        };

        connect_ws_for_dc_with_outbound(
            target_ip,
            self.runtime.websocket_dc(self.dc),
            self.is_media,
            self.config.skip_tls_verify,
            timeout,
            self.runtime.outbound(),
            sni_override,
        )
        .await
    }

    /// Back off from this DC's WebSocket path after a failed attempt.
    ///
    /// A cooldown rather than a permanent blacklist, so the proxy recovers
    /// automatically if WS becomes available again (e.g. after a network
    /// change or a Telegram-side redirect policy change).
    fn cool_down_ws(&self, all_redirects: bool) {
        let cooldown = if all_redirects {
            self.timeouts.ws_redirect_cooldown
        } else {
            self.timeouts.ws_fail_cooldown
        };
        WS_FAIL.set((self.dc, self.is_media), cooldown);

        if all_redirects {
            warn!(
                "[{}] DC{}{} WS cooldown {}s (all domains returned redirect)",
                self.label,
                self.dc,
                self.media,
                cooldown.as_secs()
            );
        } else {
            info!(
                "[{}] DC{}{} WS cooldown {}s",
                self.label,
                self.dc,
                self.media,
                cooldown.as_secs()
            );
        }
    }

    /// Back off from a target IP whose TCP connect timed out.
    ///
    /// Recorded even with no fallback tier configured, where nothing will skip
    /// the address: the pool reads the same cooldown to stop pre-connecting
    /// into a hole, which is worth doing either way.  [`select_upstream`] is
    /// where the skipping decision — the part that does need a fallback — is
    /// made.
    fn cool_down_ip(&self, target_ip: &str) {
        IP_FAIL.set(target_ip.to_string(), self.timeouts.ip_fail_cooldown);
        info!(
            "[{}] DC{}{} TCP to {} timed out, cooldown {}s",
            self.label,
            self.dc,
            self.media,
            target_ip,
            self.timeouts.ip_fail_cooldown.as_secs()
        );
    }

    /// Raw TCP to the DC, once every tunnelled tier is out.
    ///
    /// Prefers the built-in DC address over the `--dc-ip` override: this is
    /// only reached after that override failed, and on the paths that get here
    /// it failed by timing out — the one signal that says the address itself
    /// is unreachable.
    fn tcp_last_resort(&self, target_ip: &str, reason: &str) -> Upstream {
        let dst = self.runtime.fallback_ip(self.dc).unwrap_or(target_ip);

        self.tcp_fallback(dst, reason)
    }

    fn tcp_fallback(&self, dst: &str, reason: &str) -> Upstream {
        info!(
            "[{}] DC{}{} {} → TCP fallback {}:443",
            self.label, self.dc, self.media, reason, dst
        );

        Upstream::Tcp(dst.to_string())
    }
}

// ─── WebSocket bridge ────────────────────────────────────────────────────────

/// Run a bidirectional re-encrypted bridge between the client (TCP) and
/// Telegram (WebSocket).
///
/// ```text
/// client  →  clt_dec  →  split + tg_enc  →  WebSocket frames  →  Telegram
/// Telegram  →  WS frame  →  tg_dec  →  plaintext  →  clt_enc  →  client TCP
/// ```
struct WsBridgeParams {
    label: SocketAddr,
    ws: TgWsStream,
    framing: WsFraming,
    relay_init: [u8; 64],
    ciphers: ConnectionCiphers,
    proto: ProtoTag,
    dc: u32,
    is_media: bool,
}

async fn bridge_ws(reader: ClientReader, writer: ClientWriter, params: WsBridgeParams) {
    let WsBridgeParams {
        label,
        ws,
        framing,
        relay_init,
        ciphers,
        proto,
        dc,
        is_media,
    } = params;

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;
    let mut splitter = (framing == WsFraming::Packets).then(|| MsgSplitter::new(proto));

    // Split the WebSocket stream into sink (send) and source (recv).
    let (mut ws_sink, mut ws_source) = ws.split();

    let start = Instant::now();
    let bytes_up = Arc::new(StdMutex::new(0));
    let mut bytes_down = 0;

    let upload = tokio::spawn({
        let mut bytes = UploadCounter::new(Arc::clone(&bytes_up));
        async move {
            // Keep every sink operation in this direction so upload and download
            // can be polled independently by `join_bridge`.
            if let Err(e) = ws_sink.send(Message::Binary(relay_init.to_vec())).await {
                warn!("[{}] failed to send relay init: {}", label, e);
                return;
            }

            let mut reader = reader;
            let mut buf = vec![0u8; CLIENT_READ_BUF_SIZE];

            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let chunk = &mut buf[..n];

                // Packet framing needs the plaintext header. The splitter
                // encrypts each consumed slice in stream order afterwards.
                clt_dec.apply_keystream(chunk);

                let sent = match splitter.as_mut() {
                    // Split into MTProto packets and send as separate WS frames.
                    Some(splitter) => {
                        let mut sent = true;
                        for part in splitter.split_and_encrypt(chunk, &mut tg_enc) {
                            if ws_sink.send(Message::Binary(part)).await.is_err() {
                                sent = false;
                                break;
                            }
                        }
                        sent
                    }
                    // Tunnel: forward the read as one frame.  A client read is
                    // bounded by `CLIENT_READ_BUF_SIZE`, far under Cloudflare's
                    // 1 MiB message cap, so it needs no further chunking — and
                    // no intermediate `Vec` of parts either.
                    None => {
                        tg_enc.apply_keystream(chunk);
                        ws_sink.send(Message::Binary(chunk.to_vec())).await.is_ok()
                    }
                };

                if !sent {
                    return;
                }

                bytes.add(n);
            }

            // Flush any partial last packet.
            for part in splitter
                .as_mut()
                .map(MsgSplitter::flush)
                .unwrap_or_default()
            {
                let _ = ws_sink.send(Message::Binary(part)).await;
            }

            // Close the WS sink so Telegram knows we are done and the download
            // direction (ws_source) receives the close frame and terminates
            // promptly instead of waiting indefinitely.
            let _ = ws_sink.close().await;
        }
    });

    let download = async {
        let mut writer = writer;

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

            bytes_down += data.len() as u64;
        }
    };

    let closed_by = join_bridge(upload, download).await;
    let bytes_up = *bytes_up.lock().unwrap();

    log_session_closed(
        label, dc, is_media, "WS", closed_by, bytes_up, bytes_down, start,
    );
}

// ─── Upstream MTProto proxy connection ───────────────────────────────────────

/// A connected upstream MTProto proxy, ready to be bridged.
struct UpstreamConnection {
    reader: TcpReader,
    writer: TcpWriter,
    /// Encrypts data we send to the upstream proxy.
    enc: AesCtr256,
    /// Decrypts data we receive from the upstream proxy.
    dec: AesCtr256,
    /// Whether the session is wrapped in TLS Application Data records
    /// (`0xee` FakeTLS secrets) rather than sent as raw obfuscated TCP.
    faketls: bool,
}

/// Connect to an upstream MTProto proxy and perform the client handshake.
///
/// - `0xdd` or plain 16-byte secrets: standard obfuscated TCP.
/// - `0xee` secrets (≥17 bytes): FakeTLS — sends a TLS ClientHello with HMAC
///   authentication, drains the server's fake handshake, then sends the 64-byte
///   MTProto init inside a TLS Application Data record.
async fn connect_mtproto_upstream(
    proxy: &MtProtoProxy,
    dc_idx: i16,
    proto: ProtoTag,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> Option<UpstreamConnection> {
    let host = &proxy.host;
    let port = proxy.port;
    let key_bytes = proxy.secret_key();

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
    let (mut reader, mut writer) = stream.into_split();

    let Some(hostname) = proxy.faketls_hostname() else {
        // ── Plain MTProto path ────────────────────────────────────────────
        if let Err(e) = writer.write_all(&handshake).await {
            warn!("[upstream] {}:{} send handshake error: {}", host, port, e);
            return None;
        }

        return Some(UpstreamConnection {
            reader,
            writer,
            enc,
            dec,
            faketls: false,
        });
    };

    // ── FakeTLS path ──────────────────────────────────────────────────────
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

    Some(UpstreamConnection {
        reader,
        writer,
        enc,
        dec,
        faketls: true,
    })
}

// ─── Upstream MTProto relay bridge ───────────────────────────────────────────

/// Bidirectional bridge between the client (TCP) and an upstream MTProto proxy
/// (TCP).  The upstream proxy handles the onward Telegram connection.
///
/// With `faketls` set, traffic to and from the upstream is additionally
/// wrapped in TLS Application Data records (`\x17\x03\x03` + 2-byte
/// big-endian length + payload).  The AES-CTR re-encryption operates on the
/// payload inside those records, exactly as in the plain case.
///
/// `ciphers.tg_enc` / `ciphers.tg_dec` must already be set to the upstream
/// session ciphers returned by [`connect_mtproto_upstream`].  No relay init is
/// sent here — the client handshake was the only setup packet.
struct RelayParams {
    label: SocketAddr,
    rem_reader: TcpReader,
    rem_writer: TcpWriter,
    ciphers: ConnectionCiphers,
    faketls: bool,
    dc: u32,
    is_media: bool,
}

async fn bridge_relay(reader: ClientReader, writer: ClientWriter, params: RelayParams) {
    let RelayParams {
        label,
        rem_reader,
        rem_writer,
        ciphers,
        faketls,
        dc,
        is_media,
    } = params;

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;

    let start = Instant::now();
    let bytes_up = Arc::new(StdMutex::new(0));
    let mut bytes_down = 0;

    // ── Upload: client → upstream ────────────────────────────────────────
    let upload = tokio::spawn({
        let mut bytes = UploadCounter::new(Arc::clone(&bytes_up));

        async move {
            let mut reader = reader;
            let mut rem_writer = rem_writer;
            // Sized for the client side; `write_tls_appdata` re-chunks to the TLS
            // record limit on its way out, so a larger read is safe.
            let mut buf = vec![0u8; CLIENT_READ_BUF_SIZE];

            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let chunk = &mut buf[..n];
                clt_dec.apply_keystream(chunk);
                tg_enc.apply_keystream(chunk);

                let written = if faketls {
                    write_tls_appdata(&mut rem_writer, chunk).await
                } else {
                    rem_writer.write_all(chunk).await
                };
                if written.is_err() {
                    break;
                }

                bytes.add(n);
            }
        }
    });

    // ── Download: upstream → client ──────────────────────────────────────
    let download = async {
        let mut rem_reader = rem_reader;
        let mut writer = writer;
        // In FakeTLS mode this must fit a whole record: `read_tls_appdata`
        // reports one that does not as `Ok(0)`, which the loop below cannot
        // tell from a clean EOF.
        let mut buf = vec![
            0u8;
            if faketls {
                TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM
            } else {
                RELAY_BUF_SIZE
            }
        ];

        loop {
            let read = if faketls {
                read_tls_appdata(&mut rem_reader, &mut buf).await
            } else {
                rem_reader.read(&mut buf).await
            };
            let n = match read {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };

            let chunk = &mut buf[..n];
            tg_dec.apply_keystream(chunk);
            clt_enc.apply_keystream(chunk);

            if writer.write_all(chunk).await.is_err() {
                break;
            }

            bytes_down += n as u64;
        }
    };

    let closed_by = join_bridge(upload, download).await;
    let bytes_up = *bytes_up.lock().unwrap();

    let kind = if faketls {
        "upstream FakeTLS"
    } else {
        "upstream"
    };
    log_session_closed(
        label, dc, is_media, kind, closed_by, bytes_up, bytes_down, start,
    );
}

// ─── TCP fallback bridge ─────────────────────────────────────────────────────

/// Connect directly to `dst:443` and bridge the re-encrypted streams.
///
/// Logs a session-close line on return (matching the `bridge_ws` format).
struct TcpBridgeParams<'a> {
    label: SocketAddr,
    dst: &'a str,
    relay_init: &'a [u8; 64],
    ciphers: ConnectionCiphers,
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
    let (mut rem_reader, mut rem_writer) = remote.into_split();

    // Send relay init to the remote Telegram server.
    if let Err(e) = rem_writer.write_all(relay_init).await {
        warn!("[{}] TCP fallback: send relay init failed: {}", label, e);
        return;
    }

    let ConnectionCiphers {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ciphers;

    let start = Instant::now();
    let bytes_up = Arc::new(StdMutex::new(0));
    let mut bytes_down = 0;

    let upload = tokio::spawn({
        let mut bytes = UploadCounter::new(Arc::clone(&bytes_up));

        async move {
            let mut buf = vec![0u8; CLIENT_READ_BUF_SIZE];

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

                bytes.add(n);
            }
        }
    });

    let download = async {
        let mut buf = vec![0u8; RELAY_BUF_SIZE];

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

            bytes_down += n as u64;
        }
    };

    let closed_by = join_bridge(upload, download).await;
    let bytes_up = *bytes_up.lock().unwrap();

    log_session_closed(
        label, dc, is_media, "TCP", closed_by, bytes_up, bytes_down, start,
    );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Wait for whichever bridge direction finishes first, then drop the other.
///
/// Download is polled by the existing client task; only upload needs a spawned
/// task. When either side closes, the other future is cancelled immediately.
/// Joining both directions instead left zombie connections behind that
/// exhausted the file-descriptor limit.
///
async fn join_bridge<D>(mut upload: JoinHandle<()>, download: D) -> ClosedBy
where
    D: Future<Output = ()>,
{
    tokio::pin!(download);

    tokio::select! {
        _ = &mut upload => {
            // The upload direction only ends when the client stops sending.
            ClosedBy::Client
        }
        _ = &mut download => {
            upload.abort();
            let _ = upload.await;
            ClosedBy::Upstream
        }
    }
}

/// Which side ended a bridged session.
///
/// Each direction runs until *its* source stops, so whichever task finishes
/// first names the side that hung up. Worth logging: a session that closes
/// with no bytes in either direction looks identical either way, and telling
/// "the client walked away while we were still connecting" apart from
/// "Telegram dropped us straight after the handshake" is the difference
/// between a client-side timeout and a broken upstream.
#[derive(Clone, Copy)]
enum ClosedBy {
    Client,
    Upstream,
}

impl ClosedBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Upstream => "upstream",
        }
    }
}

struct UploadCounter {
    shared: Arc<StdMutex<u64>>,
    bytes: u64,
}

impl UploadCounter {
    fn new(shared: Arc<StdMutex<u64>>) -> Self {
        Self { shared, bytes: 0 }
    }

    fn add(&mut self, n: usize) {
        self.bytes += n as u64;
    }
}

impl Drop for UploadCounter {
    fn drop(&mut self) {
        *self.shared.lock().unwrap() = self.bytes;
    }
}

#[allow(clippy::too_many_arguments)]
fn log_session_closed(
    label: SocketAddr,
    dc: u32,
    is_media: bool,
    kind: &str,
    closed_by: ClosedBy,
    bytes_up: u64,
    bytes_down: u64,
    start: Instant,
) {
    info!(
        "[{}] DC{}{} {} session closed by {}: ↑{}  ↓{}  {:.1}s",
        label,
        dc,
        media_tag(is_media),
        kind,
        closed_by.as_str(),
        human_bytes(bytes_up),
        human_bytes(bytes_down),
        start.elapsed().as_secs_f32()
    );
}

async fn read_inbound_handshake(
    label: SocketAddr,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    faketls_domain: Option<&str>,
) -> Option<([u8; 64], PendingData)> {
    if let Some(domain) = faketls_domain {
        return accept_inbound_faketls(label, reader, writer, secrets, domain).await;
    }

    let mut handshake_buf = [0u8; 64];
    match reader.read_exact(&mut handshake_buf).await {
        Ok(_) => Some((handshake_buf, PendingData::default())),
        Err(e) => {
            debug!("[{}] read handshake: {}", label, e);
            None
        }
    }
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
mod tests;
