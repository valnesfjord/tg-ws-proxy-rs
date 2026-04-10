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

use std::sync::Arc;
use std::time::Duration;

use cipher::StreamCipher;
use futures_util::SinkExt;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use tungstenite::Message;

use crate::config::{default_dc_ips, default_dc_overrides, Config};
use crate::crypto::{
    build_connection_ciphers, generate_client_handshake, generate_relay_init, parse_handshake,
    AesCtr256, ConnectionCiphers,
};
use crate::pool::WsPool;
use crate::splitter::MsgSplitter;
use crate::ws_client::{connect_ws_for_dc, ws_send, TgWsStream};

// WS failure cooldown is global for the process lifetime.
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

// ─── Global failure tracking ─────────────────────────────────────────────────

/// Per-DC cooldown: avoid retrying WS until this instant.
/// Also used for the "all redirects" case (longer cooldown of 5 min).
static DC_FAIL_UNTIL: StdMutex<Option<HashMap<(u32, bool), Instant>>> = StdMutex::new(None);

const WS_FAIL_COOLDOWN: Duration = Duration::from_secs(30);
const WS_REDIRECT_COOLDOWN: Duration = Duration::from_secs(300); // 5 min for "all redirects"
const WS_FAIL_TIMEOUT: Duration = Duration::from_secs(2);
const WS_NORMAL_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Upstream MTProto proxy failure tracking ─────────────────────────────────

/// Per-upstream cooldown: keyed by "host:port".
static UPSTREAM_FAIL_UNTIL: StdMutex<Option<HashMap<String, Instant>>> = StdMutex::new(None);

const UPSTREAM_FAIL_COOLDOWN: Duration = Duration::from_secs(60);
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn upstream_key(host: &str, port: u16) -> String {
    format!("{}:{}", host, port)
}

fn set_upstream_cooldown(host: &str, port: u16) {
    let key = upstream_key(host, port);
    let mut lock = UPSTREAM_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert(key, Instant::now() + UPSTREAM_FAIL_COOLDOWN);
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
    if let Some(map) = lock.as_ref() {
        if let Some(&until) = map.get(&key) {
            return Instant::now() < until;
        }
    }
    false
}

fn blacklist_ws(dc: u32, is_media: bool) {
    // Instead of a permanent blacklist, apply a long cooldown so the proxy
    // can recover automatically if WS becomes available again (e.g. after a
    // network change or Telegram-side redirect policy change).
    let mut lock = DC_FAIL_UNTIL.lock().unwrap();
    lock.get_or_insert_with(HashMap::new)
        .insert((dc, is_media), Instant::now() + WS_REDIRECT_COOLDOWN);
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
pub async fn handle_client(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    config: Config,
    pool: Arc<WsPool>,
) {
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
            debug!(
                "[{}] bad handshake (wrong secret or reserved prefix)",
                label
            );

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
    let ciphers = build_connection_ciphers(&info.prekey_and_iv, &secret, &relay_init);

    // ── Step 5: route the connection ──────────────────────────────────────
    let target_ip = dc_redirects.get(&dc_id).cloned();
    let media_tag = if is_media { "m" } else { "" };

    if target_ip.is_none() {
        // DC not in config — try WS via fallback IP first, then upstream proxies,
        // then fall back to direct TCP.
        let reason = format!("DC{} not in --dc-ip config", dc_id);
        let fallback = match dc_fallback_ips.get(&dc_id) {
            Some(ip) => ip.clone(),
            None => {
                warn!("[{}] {} — no fallback IP available", label, reason);
                return;
            }
        };

        // ── Try WebSocket via fallback IP ────────────────────────────────
        // Use the same pool + cooldown logic as the configured-DC path so that
        // repeated failures are rate-limited and file descriptors don't pile up.
        let ws_timeout = ws_timeout_for(dc_id, is_media);
        let pool_hit = pool.get(dc_id, is_media, fallback.clone(), skip_tls).await;
        let ws_opt = if let Some(ws) = pool_hit {
            info!(
                "[{}] DC{}{} {} → pool hit via {}",
                label, dc_id, media_tag, reason, fallback
            );
            Some(ws)
        } else {
            let (ws, all_redirects) =
                connect_ws_for_dc(&fallback, ws_dc, is_media, skip_tls, ws_timeout).await;
            if ws.is_some() {
                clear_dc_cooldown(dc_id, is_media);
                info!(
                    "[{}] DC{}{} {} → WS via {}",
                    label, dc_id, media_tag, reason, fallback
                );
            } else if all_redirects {
                blacklist_ws(dc_id, is_media);
                warn!(
                    "[{}] DC{}{} WS cooldown {}s (all domains returned redirect)",
                    label,
                    dc_id,
                    media_tag,
                    WS_REDIRECT_COOLDOWN.as_secs()
                );
            } else {
                set_dc_cooldown(dc_id, is_media);
                info!(
                    "[{}] DC{}{} WS cooldown {}s",
                    label,
                    dc_id,
                    media_tag,
                    WS_FAIL_COOLDOWN.as_secs()
                );
            }
            ws
        };

        if let Some(ws) = ws_opt {
            bridge_ws(&label, reader, writer, ws, relay_init, ciphers, proto, dc_id, is_media)
                .await;
            return;
        }

        // ── WS failed — try each configured upstream MTProto proxy ───────
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
            )
            .await
            {
                Some((rem_reader, rem_writer, up_enc, up_dec)) => {
                    clear_upstream_cooldown(&upstream.host, upstream.port);
                    info!(
                        "[{}] DC{}{} {} → upstream MTProto {}:{}",
                        label, dc_id, media_tag, reason, upstream.host, upstream.port
                    );
                    let ConnectionCiphers { clt_dec, clt_enc, .. } = ciphers;
                    let up_ciphers = ConnectionCiphers {
                        clt_dec,
                        clt_enc,
                        tg_enc: up_enc,
                        tg_dec: up_dec,
                    };
                    bridge_mtproto_relay(
                        &label, reader, writer, rem_reader, rem_writer, up_ciphers, dc_id,
                        is_media,
                    )
                    .await;
                    return;
                }
                None => {
                    set_upstream_cooldown(&upstream.host, upstream.port);
                    warn!(
                        "[{}] upstream {}:{} failed, cooldown {}s",
                        label,
                        upstream.host,
                        upstream.port,
                        UPSTREAM_FAIL_COOLDOWN.as_secs()
                    );
                }
            }
        }

        info!("[{}] {} → TCP fallback {}:443", label, reason, fallback);

        bridge_tcp(
            &label,
            reader,
            writer,
            &fallback,
            &relay_init,
            ciphers,
            dc_id,
            is_media,
        )
        .await;

        return;
    }

    let target_ip = target_ip.unwrap();
    let ws_timeout = ws_timeout_for(dc_id, is_media);

    // ── Step 6a: try pool first ───────────────────────────────────────────
    let ws_opt = pool.get(dc_id, is_media, target_ip.clone(), skip_tls).await;

    let ws = if let Some(ws) = ws_opt {
        info!(
            "[{}] DC{}{} → pool hit via {}",
            label, dc_id, media_tag, target_ip
        );

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
                // WS failed — apply cooldown and try upstream proxies or TCP fallback.
                if all_redirects {
                    blacklist_ws(dc_id, is_media);

                    warn!(
                        "[{}] DC{}{} WS cooldown {}s (all domains returned redirect)",
                        label,
                        dc_id,
                        media_tag,
                        WS_REDIRECT_COOLDOWN.as_secs()
                    );
                } else {
                    set_dc_cooldown(dc_id, is_media);

                    info!(
                        "[{}] DC{}{} WS cooldown {}s",
                        label,
                        dc_id,
                        media_tag,
                        WS_FAIL_COOLDOWN.as_secs()
                    );
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
                    )
                    .await
                    {
                        Some((rem_reader, rem_writer, up_enc, up_dec)) => {
                            clear_upstream_cooldown(&upstream.host, upstream.port);
                            info!(
                                "[{}] DC{}{} → upstream MTProto {}:{}",
                                label, dc_id, media_tag, upstream.host, upstream.port
                            );
                            let ConnectionCiphers { clt_dec, clt_enc, .. } = ciphers;
                            let up_ciphers = ConnectionCiphers {
                                clt_dec,
                                clt_enc,
                                tg_enc: up_enc,
                                tg_dec: up_dec,
                            };
                            bridge_mtproto_relay(
                                &label, reader, writer, rem_reader, rem_writer, up_ciphers,
                                dc_id, is_media,
                            )
                            .await;
                            return;
                        }
                        None => {
                            set_upstream_cooldown(&upstream.host, upstream.port);
                            warn!(
                                "[{}] upstream {}:{} failed, cooldown {}s",
                                label,
                                upstream.host,
                                upstream.port,
                                UPSTREAM_FAIL_COOLDOWN.as_secs()
                            );
                        }
                    }
                }

                let fallback = dc_fallback_ips
                    .get(&dc_id)
                    .cloned()
                    .unwrap_or(target_ip.clone());

                info!(
                    "[{}] DC{}{} → TCP fallback {}:443",
                    label, dc_id, media_tag, fallback
                );

                bridge_tcp(
                    &label,
                    reader,
                    writer,
                    &fallback,
                    &relay_init,
                    ciphers,
                    dc_id,
                    is_media,
                )
                .await;

                return;
            }
        }
    };

    // ── Step 7: bidirectional WebSocket bridge ───────────────────────────
    bridge_ws(
        &label, reader, writer, ws, relay_init, ciphers, proto, dc_id, is_media,
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
            let up = result.unwrap_or_else(|_| 0);
            download.abort();

            let down = download.await.unwrap_or_else(|_| 0);

            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or_else(|_| 0);
            upload.abort();

            let up = upload.await.unwrap_or_else(|_| 0);

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

/// Connect to an upstream MTProto proxy and perform the client handshake.
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
) -> Option<(
    tokio::io::ReadHalf<TcpStream>,
    tokio::io::WriteHalf<TcpStream>,
    AesCtr256,
    AesCtr256,
)> {
    let secret = match hex::decode(secret_hex) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                "[upstream] {}:{} invalid hex secret: {}",
                host, port, e
            );
            return None;
        }
    };

    // Telegram MTProto proxy secrets in link format start with a 1-byte mode
    // indicator: 0xdd = padded intermediate, 0xee = FakeTLS.  Two things must
    // be derived from this byte:
    //
    // 1. The key material: the prefix byte is NOT part of the 16-byte
    //    cryptographic key used for SHA-256 derivation, so it must be stripped
    //    before calling generate_client_handshake.
    //
    // 2. The transport protocol: 0xdd proxies expect PaddedIntermediate;
    //    0xee proxies use FakeTLS which speaks Intermediate as the inner
    //    protocol.  Always pass the protocol the upstream advertises rather
    //    than the protocol the original Telegram client used, so the handshake
    //    is accepted.
    let (key_start, upstream_proto) = if secret.len() == 17 {
        match secret[0] {
            0xdd => (1, crate::crypto::ProtoTag::PaddedIntermediate),
            0xee => (1, crate::crypto::ProtoTag::Intermediate), // FakeTLS uses Intermediate as its inner protocol
            _ => (0, proto),
        }
    } else {
        (0, proto)
    };
    let key_bytes = &secret[key_start..];

    let stream = match tokio::time::timeout(
        UPSTREAM_CONNECT_TIMEOUT,
        TcpStream::connect(format!("{}:{}", host, port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("[upstream] {}:{} connect error: {}", host, port, e);
            return None;
        }
        Err(_) => {
            warn!("[upstream] {}:{} connect timed out", host, port);
            return None;
        }
    };
    let _ = stream.set_nodelay(true);

    let (handshake, enc, dec) = generate_client_handshake(key_bytes, dc_idx, upstream_proto);

    let (reader, mut writer) = tokio::io::split(stream);
    if let Err(e) = writer.write_all(&handshake).await {
        warn!("[upstream] {}:{} send handshake error: {}", host, port, e);
        return None;
    }

    Some((reader, writer, enc, dec))
}

// ─── Upstream MTProto relay bridge ───────────────────────────────────────────

/// Bidirectional bridge between the client (TCP) and an upstream MTProto proxy
/// (TCP).  The upstream proxy handles the onward Telegram connection.
///
/// `ciphers.tg_enc` / `ciphers.tg_dec` must already be set to the upstream
/// session ciphers returned by [`connect_mtproto_upstream`].
async fn bridge_mtproto_relay(
    label: &str,
    reader: tokio::io::ReadHalf<TcpStream>,
    writer: tokio::io::WriteHalf<TcpStream>,
    rem_reader: tokio::io::ReadHalf<TcpStream>,
    mut rem_writer: tokio::io::WriteHalf<TcpStream>,
    ciphers: ConnectionCiphers,
    dc: u32,
    is_media: bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

// ─── TCP fallback bridge ─────────────────────────────────────────────────────

/// Connect directly to `dst:443` and bridge the re-encrypted streams.
///
/// Logs a session-close line on return (matching the `bridge_ws` format).
async fn bridge_tcp(
    label: &str,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    dst: &str,
    relay_init: &[u8; 64],
    ciphers: crate::crypto::ConnectionCiphers,
    dc: u32,
    is_media: bool,
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
            let up = result.unwrap_or_else(|_| 0);
            download.abort();

            let down = download.await.unwrap_or_else(|_| 0);

            (up, down)
        }
        result = &mut download => {
            let down = result.unwrap_or_else(|_| 0);
            upload.abort();

            let up = upload.await.unwrap_or_else(|_| 0);

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
