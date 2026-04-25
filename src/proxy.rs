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
use crate::faketls::drain_faketls_server_hello;
use crate::pool::WsPool;
use crate::splitter::MsgSplitter;
use crate::ws_client::{connect_cf_ws_for_dc, connect_ws_for_dc, ws_send, TgWsStream};

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
    if let Some(map) = lock.as_ref() {
        if let Some(&until) = map.get(&key) {
            return Instant::now() < until;
        }
    }
    false
}

// ─── Cloudflare proxy failure tracking ───────────────────────────────────────

/// Round-robin counter for CF domain balancing (`--cf-balance`).
static CF_BALANCE_COUNTER: AtomicUsize = AtomicUsize::new(0);

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

/// Per-DC cooldown for the CF proxy path.
static CF_FAIL_UNTIL: StdMutex<Option<HashMap<(u32, bool), Instant>>> = StdMutex::new(None);

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
    if let Some(map) = lock.as_ref() {
        if let Some(&until) = map.get(&(dc, is_media)) {
            return Instant::now() < until;
        }
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

fn ws_timeout_for(dc: u32, is_media: bool, normal_timeout: Duration, fail_probe_timeout: Duration) -> Duration {
    let lock = DC_FAIL_UNTIL.lock().unwrap();
    if let Some(map) = lock.as_ref() {
        if let Some(&until) = map.get(&(dc, is_media)) {
            if Instant::now() < until {
                return fail_probe_timeout; // still in cooldown → try fast
            }
        }
    }

    normal_timeout
}

enum ClientReader {
    Plain(tokio::io::ReadHalf<TcpStream>),
    FakeTls {
        reader: tokio::io::ReadHalf<TcpStream>,
        pending: Vec<u8>,
    },
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

                crate::faketls::read_tls_appdata(reader, buf).await
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
    Plain(tokio::io::WriteHalf<TcpStream>),
    FakeTls(tokio::io::WriteHalf<TcpStream>),
}

impl ClientWriter {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Plain(writer) => writer.write_all(data).await,
            Self::FakeTls(writer) => crate::faketls::write_tls_appdata(writer, data).await,
        }
    }
}

async fn accept_inbound_faketls(
    label: &str,
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    secret: &[u8],
    expected_domain: &str,
) -> Option<([u8; 64], Vec<u8>)> {
    let (record_type, version, payload) =
        crate::faketls::read_tls_record(reader, crate::faketls::TLS_MAX_RECORD_PAYLOAD + 256)
            .await
            .ok()??;
    if record_type != crate::faketls::TLS_RECORD_HANDSHAKE || version != [0x03, 0x01] {
        debug!("[{}] bad FakeTLS ClientHello record", label);
        return None;
    }

    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(record_type);
    record.extend_from_slice(&version);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(&payload);

    let hello = match crate::faketls::parse_faketls_client_hello(&record, secret) {
        Some(hello) => hello,
        None => {
            debug!("[{}] bad FakeTLS ClientHello digest", label);
            return None;
        }
    };

    if hello.hostname.as_deref() != Some(expected_domain) {
        debug!(
            "[{}] FakeTLS SNI mismatch: got {:?}, expected {}",
            label, hello.hostname, expected_domain
        );
        return None;
    }

    let server_hello = crate::faketls::build_faketls_server_hello(secret, &hello);
    if let Err(e) = writer.write_all(&server_hello).await {
        debug!("[{}] write FakeTLS ServerHello: {}", label, e);
        return None;
    }

    let mut handshake_buf = [0u8; 64];
    let mut filled = 0;
    let mut buf = vec![0u8; crate::faketls::TLS_MAX_RECORD_PAYLOAD + 256];
    while filled < handshake_buf.len() {
        let n = match crate::faketls::read_tls_appdata(reader, &mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        let take = std::cmp::min(n, handshake_buf.len() - filled);
        handshake_buf[filled..filled + take].copy_from_slice(&buf[..take]);
        filled += take;
        if take != n {
            return Some((handshake_buf, buf[take..n].to_vec()));
        }
    }

    Some((handshake_buf, Vec::new()))
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

    // ── Step 1: read the 64-byte MTProto obfuscation init ────────────────
    let inbound_faketls_domain = config.listen_faketls_domain();
    let mut handshake_buf = [0u8; 64];
    let mut faketls_pending = Vec::new();
    if let Some(domain) = inbound_faketls_domain.as_deref() {
        match tokio::time::timeout(
            handshake_timeout,
            accept_inbound_faketls(&label, &mut reader, &mut writer, &secret, domain),
        )
        .await
        {
            Ok(Some((buf, pending))) => {
                handshake_buf = buf;
                faketls_pending = pending;
            }
            Ok(None) => return,
            Err(_) => {
                debug!("[{}] FakeTLS handshake timeout", label);
                return;
            }
        }
    } else {
        match tokio::time::timeout(handshake_timeout, reader.read_exact(&mut handshake_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                debug!("[{}] read handshake: {}", label, e);
                return;
            }
            Err(_) => {
                debug!("[{}] handshake timeout", label);
                return;
            }
        }
    }

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
    let info = match parse_handshake(&handshake_buf, &secret) {
        Some(i) => i,
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
        // DC not in config — try CF proxy, then upstream proxies, then TCP fallback.
        let reason = format!("DC{} not in --dc-ip config", dc_id);
        let fallback = match dc_fallback_ips.get(&dc_id) {
            Some(ip) => ip.clone(),
            None => {
                warn!("[{}] {} — no fallback IP available", label, reason);
                return;
            }
        };

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

                let (cf_ws_opt, _all_redirects) =
                    connect_cf_ws_for_dc(dc_id, &cf_domains_for_conn, is_media, skip_tls, cf_connect_timeout)
                        .await;

                if let Some(ws) = cf_ws_opt {
                    clear_cf_cooldown(dc_id, is_media);
                    info!(
                        "[{}] DC{}{} {} → CF proxy connected",
                        label, dc_id, media_tag, reason
                    );
                    bridge_ws(
                        &label, reader, writer, ws, relay_init, ciphers, proto, dc_id, is_media,
                    )
                    .await;
                    return;
                } else {
                    set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                    warn!(
                        "[{}] DC{}{} CF proxy failed, cooldown {}s",
                        label, dc_id, media_tag, cf_fail_cooldown.as_secs()
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
            )
            .await
            {
                Some(conn) => {
                    let is_ft = matches!(conn, UpstreamConnection::FakeTls(..));
                    clear_upstream_cooldown(&upstream.host, upstream.port);
                    info!(
                        "[{}] DC{}{} {} → upstream {} MTProto {}:{}",
                        label, dc_id, media_tag, reason,
                        if is_ft { "FakeTLS" } else { "plain" },
                        upstream.host, upstream.port
                    );
                    let ConnectionCiphers { clt_dec, clt_enc, .. } = ciphers;
                    match conn {
                        UpstreamConnection::Plain(rem_reader, rem_writer, up_enc, up_dec) => {
                            let up_ciphers = ConnectionCiphers {
                                clt_dec,
                                clt_enc,
                                tg_enc: up_enc,
                                tg_dec: up_dec,
                            };
                            bridge_mtproto_relay(
                                &label, reader, writer, rem_reader, rem_writer,
                                up_ciphers, dc_id, is_media,
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
                                &label, reader, writer, rem_reader, rem_writer,
                                up_ciphers, dc_id, is_media,
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
            &label,
            reader,
            writer,
            &fallback,
            &relay_init,
            ciphers,
            dc_id,
            is_media,
            tcp_fallback_timeout,
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

            let (cf_ws_opt, _all_redirects) =
                connect_cf_ws_for_dc(dc_id, &cf_domains_for_conn, is_media, skip_tls, cf_connect_timeout)
                    .await;

            if let Some(ws) = cf_ws_opt {
                clear_cf_cooldown(dc_id, is_media);
                info!(
                    "[{}] DC{}{} → CF proxy connected (priority)",
                    label, dc_id, media_tag
                );
                bridge_ws(
                    &label, reader, writer, ws, relay_init, ciphers, proto, dc_id, is_media,
                )
                .await;
                return;
            } else {
                set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                warn!(
                    "[{}] DC{}{} CF proxy failed (priority), cooldown {}s — falling back to WS",
                    label, dc_id, media_tag, cf_fail_cooldown.as_secs()
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
                            "[{}] DC{}{} WS failed → trying CF proxy",
                            label, dc_id, media_tag
                        );

                        let (cf_ws_opt, _all_redirects) = connect_cf_ws_for_dc(
                            dc_id,
                            &cf_domains_for_conn,
                            is_media,
                            skip_tls,
                            cf_connect_timeout,
                        )
                        .await;

                        if let Some(ws) = cf_ws_opt {
                            clear_cf_cooldown(dc_id, is_media);
                            info!(
                                "[{}] DC{}{} → CF proxy connected",
                                label, dc_id, media_tag
                            );
                            bridge_ws(
                                &label, reader, writer, ws, relay_init, ciphers, proto, dc_id,
                                is_media,
                            )
                            .await;
                            return;
                        } else {
                            set_cf_cooldown(dc_id, is_media, cf_fail_cooldown);
                            warn!(
                                "[{}] DC{}{} CF proxy failed, cooldown {}s",
                                label, dc_id, media_tag, cf_fail_cooldown.as_secs()
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
                    )
                    .await
                    {
                        Some(conn) => {
                            let is_ft = matches!(conn, UpstreamConnection::FakeTls(..));
                            clear_upstream_cooldown(&upstream.host, upstream.port);
                            info!(
                                "[{}] DC{}{} → upstream {} MTProto {}:{}",
                                label, dc_id, media_tag,
                                if is_ft { "FakeTLS" } else { "plain" },
                                upstream.host, upstream.port
                            );
                            let ConnectionCiphers { clt_dec, clt_enc, .. } = ciphers;
                            match conn {
                                UpstreamConnection::Plain(
                                    rem_reader, rem_writer, up_enc, up_dec,
                                ) => {
                                    let up_ciphers = ConnectionCiphers {
                                        clt_dec,
                                        clt_enc,
                                        tg_enc: up_enc,
                                        tg_dec: up_dec,
                                    };
                                    bridge_mtproto_relay(
                                        &label, reader, writer, rem_reader, rem_writer,
                                        up_ciphers, dc_id, is_media,
                                    )
                                    .await;
                                }
                                UpstreamConnection::FakeTls(
                                    rem_reader, rem_writer, up_enc, up_dec,
                                ) => {
                                    let up_ciphers = ConnectionCiphers {
                                        clt_dec,
                                        clt_enc,
                                        tg_enc: up_enc,
                                        tg_dec: up_dec,
                                    };
                                    bridge_faketls_relay(
                                        &label, reader, writer, rem_reader, rem_writer,
                                        up_ciphers, dc_id, is_media,
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
                    tcp_fallback_timeout,
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
    reader: ClientReader,
    writer: ClientWriter,
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
) -> Option<UpstreamConnection> {
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
    let stream = match tokio::time::timeout(
        timeout,
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
        let mut client_hello =
            crate::faketls::build_faketls_client_hello(hostname);
        crate::faketls::sign_faketls_client_hello(&mut client_hello, key_bytes);

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
        if let Err(e) =
            crate::faketls::write_tls_appdata(&mut writer, &handshake).await
        {
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
async fn bridge_mtproto_relay(
    label: &str,
    reader: ClientReader,
    writer: ClientWriter,
    rem_reader: tokio::io::ReadHalf<TcpStream>,
    mut rem_writer: tokio::io::WriteHalf<TcpStream>,
    ciphers: ConnectionCiphers,
    dc: u32,
    is_media: bool,
) {
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
async fn bridge_faketls_relay(
    label: &str,
    reader: ClientReader,
    writer: ClientWriter,
    rem_reader: tokio::io::ReadHalf<TcpStream>,
    rem_writer: tokio::io::WriteHalf<TcpStream>,
    ciphers: ConnectionCiphers,
    dc: u32,
    is_media: bool,
) {
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
        let mut buf = vec![0u8; crate::faketls::TLS_MAX_RECORD_PAYLOAD];
        let mut total = 0u64;

        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = &mut buf[..n];
            clt_dec.apply_keystream(chunk);
            tg_enc.apply_keystream(chunk);

            if crate::faketls::write_tls_appdata(&mut rem_writer, &buf[..n])
                .await
                .is_err()
            {
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
        let mut buf = vec![0u8; crate::faketls::TLS_MAX_RECORD_PAYLOAD + 256];
        let mut total = 0u64;

        loop {
            let n = match crate::faketls::read_tls_appdata(&mut rem_reader, &mut buf).await {
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
async fn bridge_tcp(
    label: &str,
    mut reader: ClientReader,
    mut writer: ClientWriter,
    dst: &str,
    relay_init: &[u8; 64],
    ciphers: crate::crypto::ConnectionCiphers,
    dc: u32,
    is_media: bool,
    connect_timeout: Duration,
) {
    let remote = match tokio::time::timeout(
        connect_timeout,
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

#[cfg(test)]
mod tests {
    use super::ClientReader;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn faketls_reader_returns_pending_bytes_before_socket_reads() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        let mut client = client.await.unwrap();
        let (reader, _) = tokio::io::split(server);

        let mut reader = ClientReader::FakeTls {
            reader,
            pending: b"hello".to_vec(),
        };
        let mut buf = [0u8; 3];

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(&buf, b"hel");

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"lo");

        client.shutdown().await.unwrap();
    }
}
