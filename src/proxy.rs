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
//!       └─ TCP fallback (when WS is blocked / fails):
//!           [bridge_tcp]  →  direct TCP to Telegram DC IP:443
//! ```

use std::sync::Arc;
use std::time::Duration;

use cipher::StreamCipher;
use futures_util::SinkExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use tungstenite::Message;

use crate::config::{default_dc_ips, default_dc_overrides, Config};
use crate::crypto::{build_connection_ciphers, generate_relay_init, parse_handshake};
use crate::pool::WsPool;
use crate::splitter::MsgSplitter;
use crate::ws_client::{connect_ws_for_dc, ws_send, TgWsStream};

// WS failure cooldown and blacklist are global for the process lifetime.
use std::collections::HashSet;
use std::sync::Mutex as StdMutex;
use std::time::Instant;
use std::collections::HashMap;

// ─── Global failure tracking ─────────────────────────────────────────────────

/// DCs for which WebSocket is permanently blacklisted (all domains 302).
static WS_BLACKLIST: StdMutex<Option<HashSet<(u32, bool)>>> = StdMutex::new(None);

/// Per-DC cooldown: avoid retrying WS until this instant.
static DC_FAIL_UNTIL: StdMutex<Option<HashMap<(u32, bool), Instant>>> = StdMutex::new(None);

const WS_FAIL_COOLDOWN: Duration = Duration::from_secs(30);
const WS_FAIL_TIMEOUT: Duration = Duration::from_secs(2);
const WS_NORMAL_TIMEOUT: Duration = Duration::from_secs(10);

fn is_ws_blacklisted(dc: u32, is_media: bool) -> bool {
    let lock = WS_BLACKLIST.lock().unwrap();
    lock.as_ref()
        .map(|s| s.contains(&(dc, is_media)))
        .unwrap_or(false)
}

fn blacklist_ws(dc: u32, is_media: bool) {
    let mut lock = WS_BLACKLIST.lock().unwrap();
    lock.get_or_insert_with(HashSet::new)
        .insert((dc, is_media));
}

fn set_dc_cooldown(dc: u32, is_media: bool) {
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert((dc, is_media), Instant::now() + WS_FAIL_COOLDOWN);
}

fn clear_dc_cooldown(dc: u32, is_media: bool) {
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_mut() {
        map.remove(&(dc, is_media));
    }
}

fn ws_timeout_for(dc: u32, is_media: bool) -> Duration {
    let lock = DC_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref() {
        if let Some(&until) = map.get(&(dc, is_media)) {
            if Instant::now() < until {
                return WS_FAIL_TIMEOUT; // still in cooldown → try fast
            }
        }
    }
    WS_NORMAL_TIMEOUT
}

// ─── Client handler ──────────────────────────────────────────────────────────

/// Handle one inbound client connection end-to-end.
pub async fn handle_client(stream: TcpStream, peer: std::net::SocketAddr, config: Config, pool: Arc<WsPool>) {
    let label = peer.to_string();
    let _ = stream.set_nodelay(true);

    let secret = config.secret_bytes();
    let dc_redirects = config.dc_redirects();
    let dc_overrides = default_dc_overrides();
    let dc_fallback_ips = default_dc_ips();
    let skip_tls = config.skip_tls_verify;

    // Split into independent read / write halves.
    let (mut reader, writer) = tokio::io::split(stream);

    // ── Step 1: read the 64-byte MTProto obfuscation init ────────────────
    let mut handshake_buf = [0u8; 64];
    match tokio::time::timeout(
        Duration::from_secs(10),
        reader.read_exact(&mut handshake_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            debug!("[{}] read handshake: {}", label, e);
            return;
        }
        Err(_) => {
            warn!("[{}] handshake timeout", label);
            return;
        }
    }

    // ── Step 2: parse and validate the handshake ─────────────────────────
    let info = match parse_handshake(&handshake_buf, &secret) {
        Some(i) => i,
        None => {
            debug!("[{}] bad handshake (wrong secret or reserved prefix)", label);
            // Drain the connection silently to avoid giving information to scanners.
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            return;
        }
    };

    let dc_id = info.dc_id;
    let is_media = info.is_media;
    let proto = info.proto;
    // Apply DC override (e.g. DC 203 → DC 2 for WS domain selection).
    let ws_dc = *dc_overrides.get(&dc_id).unwrap_or(&dc_id);
    let dc_idx: i16 = if is_media { -(dc_id as i16) } else { dc_id as i16 };

    debug!(
        "[{}] handshake ok: DC{}{} proto={:?}",
        label, dc_id, if is_media { " media" } else { "" }, proto
    );

    // ── Step 3: generate the relay init packet for the Telegram backend ──
    let relay_init = generate_relay_init(proto, dc_idx);

    // ── Step 4: build all four AES-256-CTR ciphers ───────────────────────
    let ciphers = build_connection_ciphers(&info.prekey_and_iv, &secret, &relay_init);

    // ── Step 5: route the connection ──────────────────────────────────────
    let target_ip = dc_redirects.get(&dc_id).cloned();
    let media_tag = if is_media { "m" } else { "" };

    if target_ip.is_none() || is_ws_blacklisted(dc_id, is_media) {
        // DC not in config, or WS permanently blacklisted for this DC.
        let reason = if target_ip.is_none() {
            format!("DC{} not in --dc-ip config", dc_id)
        } else {
            format!("DC{}{} WS blacklisted", dc_id, media_tag)
        };
        let fallback = match target_ip.as_ref().or_else(|| dc_fallback_ips.get(&dc_id)) {
            Some(ip) => ip.clone(),
            None => {
                warn!("[{}] {} — no fallback IP available", label, reason);
                return;
            }
        };
        info!("[{}] {} → TCP fallback {}:443", label, reason, fallback);
        bridge_tcp(
            &label, reader, writer, &fallback, &relay_init, ciphers,
        )
        .await;
        return;
    }

    let target_ip = target_ip.unwrap();
    let ws_timeout = ws_timeout_for(dc_id, is_media);

    // ── Step 6a: try pool first ───────────────────────────────────────────
    let ws_opt = pool
        .get(dc_id, is_media, target_ip.clone(), skip_tls)
        .await;

    let ws = if let Some(ws) = ws_opt {
        info!("[{}] DC{}{} → pool hit via {}", label, dc_id, media_tag, target_ip);
        ws
    } else {
        // ── Step 6b: fresh WebSocket connect ─────────────────────────────
        let (ws_opt, all_redirects) =
            connect_ws_for_dc(&target_ip, ws_dc, is_media, skip_tls, ws_timeout).await;

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
                // WS failed — apply blacklist or cooldown and fall back to TCP.
                if all_redirects {
                    blacklist_ws(dc_id, is_media);
                    warn!(
                        "[{}] DC{}{} blacklisted (all domains returned redirect)",
                        label, dc_id, media_tag
                    );
                } else {
                    set_dc_cooldown(dc_id, is_media);
                    info!(
                        "[{}] DC{}{} WS cooldown {}s",
                        label, dc_id, media_tag,
                        WS_FAIL_COOLDOWN.as_secs()
                    );
                }

                let fallback = dc_fallback_ips
                    .get(&dc_id)
                    .cloned()
                    .unwrap_or(target_ip.clone());
                info!("[{}] DC{}{} → TCP fallback {}:443", label, dc_id, media_tag, fallback);
                bridge_tcp(
                    &label, reader, writer, &fallback, &relay_init, ciphers,
                )
                .await;
                return;
            }
        }
    };

    // ── Step 7: bidirectional WebSocket bridge ───────────────────────────
    bridge_ws(&label, reader, writer, ws, relay_init, ciphers, proto, dc_id, is_media).await;
}

// ─── WebSocket bridge ────────────────────────────────────────────────────────

/// Run a bidirectional re-encrypted bridge between the client (TCP) and
/// Telegram (WebSocket).
///
/// ```text
/// client  →  clt_dec  →  plaintext  →  tg_enc  →  split  →  WebSocket frames  →  Telegram
/// Telegram  →  WS frame  →  tg_dec  →  plaintext  →  clt_enc  →  client TCP
/// ```
async fn bridge_ws(
    label: &str,
    reader: tokio::io::ReadHalf<TcpStream>,
    writer: tokio::io::WriteHalf<TcpStream>,
    mut ws: TgWsStream,
    relay_init: [u8; 64],
    ciphers: crate::crypto::ConnectionCiphers,
    proto: crate::crypto::ProtoTag,
    dc: u32,
    is_media: bool,
) {
    use crate::crypto::ConnectionCiphers;

    // Send the relay init packet to Telegram before bridging.
    if let Err(e) = ws_send(&mut ws, relay_init.to_vec()).await {
        warn!("[{}] failed to send relay init: {}", label, e);
        return;
    }

    let ConnectionCiphers { mut clt_dec, mut clt_enc, mut tg_enc, mut tg_dec } = ciphers;
    let splitter = MsgSplitter::new(&relay_init, proto);

    // Split the WebSocket stream into sink (send) and source (recv).
    use futures_util::StreamExt;
    let (mut ws_sink, mut ws_source) = ws.split();

    let start = std::time::Instant::now();

    let (bytes_up, bytes_down) = tokio::join!(
        // ── TCP → WebSocket (client data → Telegram) ──────────────────
        {
            let mut splitter = splitter;
            async move {
                let mut reader = reader;
                let mut buf = vec![0u8; 65536];
                let mut total = 0u64;
                loop {
                    let n = match reader.read(&mut buf).await {
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
                total
            }
        },
        // ── WebSocket → TCP (Telegram data → client) ──────────────────
        async move {
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
        }
    );

    let elapsed = start.elapsed().as_secs_f32();
    info!(
        "[{}] DC{}{} WS session closed: ↑{}  ↓{}  {:.1}s",
        label, dc, if is_media { "m" } else { "" },
        human_bytes(bytes_up), human_bytes(bytes_down), elapsed
    );
}

// ─── TCP fallback bridge ─────────────────────────────────────────────────────

/// Connect directly to `dst:443` and bridge the re-encrypted streams.
async fn bridge_tcp(
    label: &str,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    dst: &str,
    relay_init: &[u8; 64],
    ciphers: crate::crypto::ConnectionCiphers,
) {
    let remote = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:443", dst)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[{}] TCP fallback connect failed: {}", label, e);
            return;
        }
        Err(_) => {
            warn!("[{}] TCP fallback connect timed out", label);
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

    let crate::crypto::ConnectionCiphers { mut clt_dec, mut clt_enc, mut tg_enc, mut tg_dec } = ciphers;

    tokio::join!(
        // ── Client → Telegram ─────────────────────────────────────────
        async {
            let mut buf = vec![0u8; 65536];
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
            }
        },
        // ── Telegram → Client ─────────────────────────────────────────
        async {
            let mut buf = vec![0u8; 65536];
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
            }
        }
    );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
