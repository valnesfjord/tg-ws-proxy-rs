//! Connectivity checker for Cloudflare proxy domains, upstream MTProto proxies
//! and the proxy's own listener.
//!
//! Run with `--check` to verify the routes before the proxy serves clients: it
//! exits with status 0 when every probe passes, or status 1 when any fails.
//! With `--check-listener` the process binds and serves as usual, probes the
//! socket it just bound, and then stops with the check's exit code — so the
//! listener's secret, address and inbound mode are the ones it is actually
//! serving rather than copies the user has to repeat.
//!
//! ## What is tested
//!
//! **CF domain** — A WebSocket connection is attempted through
//! `kws2.{domain}:443`.  A successful HTTP 101 upgrade (status `Connected`)
//! means Cloudflare is correctly routing the WebSocket traffic to Telegram's
//! DC 2 server and the domain is usable by the proxy.
//!
//! **CF Worker** — The Worker's WebSocket tunnel to DC 2 is opened *and* a
//! 64-byte MTProto init is pushed through it.  The upgrade on its own says
//! nothing: the Worker returns `101` before its TCP `connect()` to Telegram is
//! known to have worked, so only the init — and the silence that should follow
//! it — proves the far end is really a DC.
//!
//! **MTProto proxy (plain / 0xdd)** — A TCP connection is made and the
//! 64-byte MTProto obfuscation handshake is sent.  A successful send verifies
//! the proxy is reachable at the network level.
//!
//! **MTProto proxy (FakeTLS / 0xee)** — As above, but a proper TLS ClientHello
//! with HMAC authentication is sent first.  The probe waits for the server's
//! fake TLS handshake response; a successful drain confirms both reachability
//! and correct protocol support.
//!
//! **Own listener** (`--check-listener`) — The probe talks to the socket this
//! process just bound, the way a client would: a 64-byte obfuscated handshake,
//! then a real `req_pq_multi`, and the reply has to decrypt to Telegram's
//! `resPQ`.  A handshake the listener merely accepts is not the verdict here,
//! for the same reason the Worker probe sends an init: the listener accepts
//! those 64 bytes before it has anywhere to forward them, so only the DC's
//! answer says the chain — inbound handshake, chosen tier, DC — works.
//!
//! It covers the listener and the routing, not the `tg://` link: the probe
//! reaches the bound socket over loopback, so a wrong `--link-ip`, a missing
//! port-forward or a LAN firewall rule still passes.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cipher::StreamCipher;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{Config, MtProtoProxy, default_dc_ip};
use crate::crypto::{self, AesCtr256, ProtoTag, generate_client_handshake};
use crate::faketls;
use crate::outbound::OutboundConnector;
use crate::ws_client::{
    CfDialOpts, connect_cf_worker_ws_for_dc_with_outbound_opts,
    connect_cf_ws_for_dc_with_outbound_opts, ws_recv, ws_send,
};

// ─── Probe result ─────────────────────────────────────────────────────────────

enum ProbeStatus {
    Ok(Duration),
    Fail(String),
}

impl ProbeStatus {
    fn marker(&self) -> &'static str {
        match self {
            Self::Ok(_) => "OK ",
            Self::Fail(_) => "FAIL",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Ok(d) => format!("{}ms", d.as_millis()),
            Self::Fail(reason) => reason.clone(),
        }
    }

    fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }
}

// ─── Listener probe request ───────────────────────────────────────────────────

/// Telegram's `resPQ` constructor: the answer to `req_pq_multi`, and the only
/// proof that the far end of a tunnel is a data centre rather than a middlebox
/// that accepted the handshake.
const RES_PQ_CTOR: u32 = 0x0516_2463;

/// Byte offset of the constructor in a plain MTProto frame: 4 bytes of frame
/// length, 8 of `auth_key_id`, 8 of message id, 4 of body length.
const FRAME_CTOR_OFFSET: usize = 24;

/// Header of a plain MTProto frame — enough bytes to read the constructor.
const FRAME_HEADER_LEN: usize = FRAME_CTOR_OFFSET + 4;

/// Address to probe a listener bound to `bound`.
///
/// A wildcard is not a destination: `0.0.0.0` becomes IPv4 loopback and `[::]`
/// becomes IPv6 loopback — not `127.0.0.1`, because a v6 socket with V6ONLY
/// set (the Windows default, and Linux with `bindv6only=1`) is unreachable
/// over IPv4.  Anything else is already an address a client could dial.
fn probe_addr(bound: SocketAddr) -> SocketAddr {
    if !bound.ip().is_unspecified() {
        return bound;
    }
    match bound {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), v4.port()),
        SocketAddr::V6(v6) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), v6.port()),
    }
}

/// Size of a `req_pq_multi` request: a 4-byte length, the 40-byte packet it
/// covers, and no padding — the packet is already a multiple of 4.
const REQ_PQ_MULTI_LEN: usize = 44;

/// A `req_pq_multi` request in the padded-intermediate transport.
///
/// This is what a client sends once the obfuscation handshake is done: 8 zero
/// bytes where an established session would carry `auth_key_id`, then the
/// message id, the body length and the body — length-prefixed and padded to a
/// multiple of 4, the shape the splitter reads off the wire.  Every field is
/// fixed-width and the padding is always zero, so the frame is filled in place
/// rather than built up from buffers.
///
/// The message id is `unixtime << 32`, as the protocol defines it, and comes
/// from the local clock: a router whose RTC has not been set yet can be
/// refused here while its clients, which use their own clocks, are not.
fn build_req_pq_multi() -> [u8; REQ_PQ_MULTI_LEN] {
    const REQ_PQ_MULTI_CTOR: u32 = 0xbe7e_8ef1;
    const BODY_LEN: usize = 4 + 16;

    let msg_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        << 32;

    let mut frame = [0u8; REQ_PQ_MULTI_LEN];
    // The length prefix covers the packet: 8 + 8 + 4 + body, already a
    // multiple of 4, so the frame carries no padding of its own.
    frame[..4].copy_from_slice(&((REQ_PQ_MULTI_LEN - 4) as u32).to_le_bytes());
    // Bytes 4..12 stay zero: no session yet, so `auth_key_id` is 0.
    frame[12..20].copy_from_slice(&msg_id.to_le_bytes());
    frame[20..24].copy_from_slice(&(BODY_LEN as u32).to_le_bytes());
    frame[24..28].copy_from_slice(&REQ_PQ_MULTI_CTOR.to_le_bytes());
    rand::rng().fill_bytes(&mut frame[28..44]);
    frame
}

/// True when the decrypted reply is Telegram's `resPQ`.
fn reply_is_res_pq(plain: &[u8]) -> bool {
    let Some(header) = plain.get(..FRAME_HEADER_LEN) else {
        return false;
    };

    let mut auth_key_id = [0u8; 8];
    auth_key_id.copy_from_slice(&header[4..12]);
    let mut ctor = [0u8; 4];
    ctor.copy_from_slice(&header[FRAME_CTOR_OFFSET..FRAME_HEADER_LEN]);

    u64::from_le_bytes(auth_key_id) == 0 && u32::from_le_bytes(ctor) == RES_PQ_CTOR
}

// ─── Individual probes ────────────────────────────────────────────────────────

/// Probe a CF domain by attempting a WebSocket connection to DC 2 through it.
///
/// DC 2 is used as a representative data-centre — if the domain is correctly
/// configured in Cloudflare (`kws2.{domain}` A record, orange-cloud, Flexible
/// SSL), this probe will succeed and other DCs should work too.
async fn probe_cf_domain(
    domain: &str,
    skip_tls: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> ProbeStatus {
    let start = Instant::now();
    let (ws, _record, _all_redirects) = connect_cf_ws_for_dc_with_outbound_opts(
        2,
        &[domain.to_string()],
        false,
        skip_tls,
        timeout,
        outbound,
        opts,
    )
    .await;
    if ws.is_some() {
        ProbeStatus::Ok(start.elapsed())
    } else {
        ProbeStatus::Fail(if opts.cf_ips.is_empty() {
            "WebSocket connection failed — check DNS records and Cloudflare settings".to_string()
        } else {
            "WebSocket connection failed through every --cf-ip — check the preferred IPs and Cloudflare settings".to_string()
        })
    }
}

/// How long the Worker probe waits for its tunnel to be torn down before
/// calling it healthy.
///
/// Telegram answers the 64-byte init with silence — it only speaks once the
/// client sends a request — so silence *is* the success signal here and the
/// probe can only wait it out.  Long enough to cover a Worker round trip plus
/// the DC handshake, short enough that `--check` stays interactive.
const WORKER_TUNNEL_SETTLE: Duration = Duration::from_secs(3);

/// Probe a Cloudflare Worker by opening its WebSocket tunnel to DC 2 and
/// pushing a real MTProto init through it.
///
/// The WebSocket upgrade alone proves nothing about the tunnel: Cloudflare
/// answers `101` from the Worker script itself, before — and regardless of
/// whether — its `connect()` to the Telegram DC ever succeeds.  A Worker that
/// cannot reach Telegram therefore passed this check while every real client
/// through it died instantly (#93).  Sending the init and watching for a
/// close is what tells the two apart.
async fn probe_cf_worker(
    domain: &str,
    skip_tls: bool,
    timeout: Duration,
    outbound: &OutboundConnector,
    opts: CfDialOpts<'_>,
) -> ProbeStatus {
    let Some(dst) = default_dc_ip(2) else {
        return ProbeStatus::Fail("DC 2 default IP is missing".to_string());
    };

    let start = Instant::now();
    let ws = connect_cf_worker_ws_for_dc_with_outbound_opts(
        domain, dst, 2, false, skip_tls, timeout, outbound, opts,
    )
    .await;
    let Some(mut ws) = ws else {
        return ProbeStatus::Fail(if opts.cf_ips.is_empty() {
            "Worker WebSocket tunnel failed — check Worker code and domain".to_string()
        } else {
            "Worker WebSocket tunnel failed through every --cf-ip — check the preferred IPs and Worker code".to_string()
        });
    };

    let relay_init = crypto::generate_relay_init(ProtoTag::Intermediate, 2);
    if let Err(e) = ws_send(&mut ws, relay_init.to_vec()).await {
        return ProbeStatus::Fail(format!("Worker tunnel closed on send: {}", e));
    }

    // Everything the user cares about timing has happened by now; the settle
    // wait below is a fixed cost of the probe, not latency of the tunnel, and
    // reporting it would make every healthy Worker look three seconds slow.
    let elapsed = start.elapsed();

    // Anything arriving here is the tunnel dying: either a close frame, or a
    // stray payload from something on `dst:443` that is not a Telegram DC.
    match tokio::time::timeout(WORKER_TUNNEL_SETTLE, ws_recv(&mut ws)).await {
        Err(_) => ProbeStatus::Ok(elapsed),
        Ok(None) => ProbeStatus::Fail(format!(
            "Worker tunnel to {} closed immediately — the Worker cannot reach Telegram \
             (check its live logs in the Cloudflare dashboard)",
            dst
        )),
        Ok(Some(data)) => ProbeStatus::Fail(format!(
            "Worker tunnel to {} answered the MTProto init with {} unexpected bytes — \
             the far end is not a Telegram DC",
            dst,
            data.len()
        )),
    }
}

/// Probe an MTProto proxy (plain or FakeTLS) by connecting, sending the
/// MTProto obfuscation handshake and — on the plain path — requiring a real
/// `resPQ` back.
///
/// For FakeTLS proxies the probe drains the server's fake TLS handshake,
/// verifying end-to-end protocol negotiation; reading a `resPQ` through that
/// record layer is a further step.  For plain proxies a TCP connect plus a
/// handshake send used to be enough, which accepted an upstream that cannot
/// reach Telegram at all — the same weakness the listener probe had, so it now
/// shares [`require_res_pq`].
async fn probe_mtproto_proxy(
    proxy: &MtProtoProxy,
    timeout: Duration,
    outbound: &OutboundConnector,
) -> ProbeStatus {
    let key_bytes = proxy.secret_key();
    let faketls_hostname = proxy.faketls_hostname();

    let start = Instant::now();

    // ── TCP connect ───────────────────────────────────────────────────────
    let stream = match outbound.connect(&proxy.host, proxy.port, timeout).await {
        Ok(s) => s,
        Err(e) => return ProbeStatus::Fail(format!("TCP connect failed: {}", e)),
    };
    let _ = stream.set_nodelay(true);

    // Use DC index 2 (non-media) as a representative test target.
    let (handshake, mut enc, mut dec) =
        generate_client_handshake(key_bytes, 2, ProtoTag::PaddedIntermediate);
    let (mut reader, mut writer) = stream.into_split();

    if let Some(hostname) = faketls_hostname {
        // ── FakeTLS path ──────────────────────────────────────────────────
        let mut client_hello = faketls::build_faketls_client_hello(hostname);
        faketls::sign_faketls_client_hello(&mut client_hello, key_bytes);

        if let Err(e) = writer.write_all(&client_hello).await {
            return ProbeStatus::Fail(format!("send FakeTLS ClientHello: {}", e));
        }

        // Drain the server's fake TLS handshake (ServerHello → CCS → AppData).
        let drained =
            tokio::time::timeout(timeout, faketls::drain_faketls_server_hello(&mut reader))
                .await
                .unwrap_or(false);

        if !drained {
            return ProbeStatus::Fail(
                "FakeTLS server handshake failed or timed out — check secret and proxy address"
                    .to_string(),
            );
        }
    } else {
        // ── Plain MTProto path ────────────────────────────────────────────
        if let Err(e) = writer.write_all(&handshake).await {
            return ProbeStatus::Fail(format!("send MTProto handshake: {}", e));
        }

        // An accepted handshake only says the socket is open: the proxy answers
        // one before its own route to a DC works, and Telegram stays silent
        // behind it.  Ask for resPQ, as the listener probe does.
        if let Err(e) = require_res_pq(
            &mut reader,
            &mut writer,
            &mut enc,
            &mut dec,
            timeout,
            "the upstream proxy",
        )
        .await
        {
            return ProbeStatus::Fail(e);
        }
    }

    ProbeStatus::Ok(start.elapsed())
}

/// Send a real `req_pq_multi` through the obfuscated stream and require the
/// reply to decrypt to `resPQ`.
///
/// This is the part that separates "the peer accepted our handshake" from "the
/// peer reached Telegram", and both probes need it: a listener accepts a
/// handshake before it has anywhere to forward the connection, and an upstream
/// proxy accepts one before its own route to a data centre works.  A successful
/// send says only that a socket is open — the trap the Worker probe hit in #93.
///
/// `peer` names the other end in the failure messages ("the listener", "the
/// upstream proxy"), so each caller keeps its own wording.
async fn require_res_pq<R, W>(
    reader: &mut R,
    writer: &mut W,
    enc: &mut AesCtr256,
    dec: &mut AesCtr256,
    timeout: Duration,
    peer: &str,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut request = build_req_pq_multi();
    enc.apply_keystream(&mut request);
    writer
        .write_all(&request)
        .await
        .map_err(|e| format!("send req_pq_multi: {e}"))?;

    // Read until the fixed-size header is complete.  Telegram stays silent
    // until it has the request and the proxy's pool may still be coming up, so
    // this waits the whole budget the caller allows.
    let mut header = [0u8; FRAME_HEADER_LEN];
    let mut filled = 0;
    let read = tokio::time::timeout(timeout, async {
        while filled < header.len() {
            match reader.read(&mut header[filled..]).await {
                Ok(0) => break,
                Ok(read) => filled += read,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })
    .await;

    // Decrypt whatever arrived, so a transport error sent through the same
    // stream is readable as one.
    dec.apply_keystream(&mut header[..filled]);

    match read {
        Err(_) => Err(format!("no reply within {}s", timeout.as_secs())),
        Ok(Err(e)) => Err(format!("read from {peer}: {e}")),
        Ok(Ok(())) if filled == 0 => Err(format!(
            "{peer} closed without answering — no tier reached the DC"
        )),
        // A transport error arrives as an ordinary packet: a 4-byte length of 4
        // followed by the negative code, so 8 bytes on the wire.  A bare
        // 4-byte prefix is not an error — it is a truncated packet.
        Ok(Ok(())) if filled >= 8 && header[..4] == 4u32.to_le_bytes() => {
            let mut code = [0u8; 4];
            code.copy_from_slice(&header[4..8]);
            Err(format!(
                "{peer} reported a transport error: {}",
                i32::from_le_bytes(code)
            ))
        }
        Ok(Ok(())) if filled < header.len() => Err(format!(
            "{peer} closed after {filled} of {} header bytes — no tier reached the DC",
            header.len()
        )),
        Ok(Ok(())) if reply_is_res_pq(&header) => Ok(()),
        Ok(Ok(())) => Err(format!("{peer}'s reply is not resPQ")),
    }
}

/// Probe the listener at `addr` the way a client would.
///
/// Connects, sends the obfuscation handshake and a real `req_pq_multi`, and
/// requires the reply to decrypt to `resPQ` — see [`require_res_pq`] for why
/// nothing weaker will do.
///
/// The connection goes through a direct connector: our own listener is never
/// outbound, and a configured `--outbound-proxy` would otherwise carry the
/// probe to that machine's loopback instead of this one's.
async fn probe_listener(
    addr: SocketAddr,
    secret: &[u8],
    dc_idx: i16,
    timeout: Duration,
) -> ProbeStatus {
    let start = Instant::now();
    let direct = OutboundConnector::direct();

    let stream = match direct
        .connect(&addr.ip().to_string(), addr.port(), timeout)
        .await
    {
        Ok(stream) => stream,
        Err(e) => return ProbeStatus::Fail(format!("TCP connect failed: {}", e)),
    };
    let _ = stream.set_nodelay(true);
    let (mut reader, mut writer) = stream.into_split();

    let (handshake, mut enc, mut dec) =
        generate_client_handshake(secret, dc_idx, ProtoTag::PaddedIntermediate);
    if let Err(e) = writer.write_all(&handshake).await {
        return ProbeStatus::Fail(format!("send MTProto handshake: {}", e));
    }

    match require_res_pq(
        &mut reader,
        &mut writer,
        &mut enc,
        &mut dec,
        timeout,
        "the listener",
    )
    .await
    {
        Ok(()) => ProbeStatus::Ok(start.elapsed()),
        Err(e) => ProbeStatus::Fail(e),
    }
}

// ─── Proxy kind label ─────────────────────────────────────────────────────────

fn proxy_kind(proxy: &MtProtoProxy) -> &'static str {
    // Inspect the first byte of the decoded hex secret.
    let first_byte = proxy
        .secret
        .get(..2)
        .and_then(|s| u8::from_str_radix(s, 16).ok());
    match first_byte {
        Some(0xee) => "FakeTLS",
        Some(0xdd) => "padded",
        _ => "plain",
    }
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Run the full connectivity check for all configured CF domains and MTProto
/// proxies.
///
/// Prints a human-readable report to stdout.  Returns `true` when every probe
/// passed so that the caller can exit with the appropriate status code.
pub async fn run_check(config: &Config) -> bool {
    let outbound = match config.outbound_connector() {
        Ok(outbound) => outbound,
        Err(e) => {
            eprintln!("Invalid outbound proxy configuration: {e}");
            return false;
        }
    };
    run_check_with_outbound(config, &outbound, None).await
}

/// Same as [`run_check`], but uses a pre-built outbound connector so callers
/// can share proxy configuration across runtime components.
///
/// `listener` is the socket the calling process bound for its own listener,
/// when it has one — `--check-listener` probes that socket, so the secret,
/// address and inbound mode are the ones being served rather than copies the
/// user has to repeat by hand.
pub async fn run_check_with_outbound(
    config: &Config,
    outbound: &OutboundConnector,
    listener: Option<SocketAddr>,
) -> bool {
    let cf_timeout = Duration::from_secs(config.cf_connect_timeout);
    let cf_opts = CfDialOpts {
        cf_ips: &config.cf_ips,
        disable_tls: config.cf_disable_tls,
        fail_cooldown: Duration::from_secs(config.cf_fail_cooldown),
    };
    let upstream_timeout = Duration::from_secs(config.upstream_connect_timeout);
    let skip_tls = config.skip_tls_verify;

    let sep = "=".repeat(60);
    println!("{}", sep);
    println!("  tg-ws-proxy connectivity check");
    println!("{}", sep);

    let cf_worker_domains = config.cf_worker_domains();

    // Everything this run was asked to probe.  A run whose every probe turned
    // out to be a skip has verified nothing, and the exit code is what scripts
    // and healthchecks read.
    let requested = config.cf_domains.len()
        + cf_worker_domains.len()
        + config.mtproto_proxies.len()
        + usize::from(config.check_listener);

    if requested == 0 {
        println!();
        println!("  Nothing to check.");
        println!(
            "  Configure --cf-domain, --cf-worker-domain, --mtproto-proxy \
             and/or --check-listener and re-run."
        );
        println!("{}", sep);
        return true;
    }

    let mut all_ok = true;

    // ── Cloudflare domain probes ──────────────────────────────────────────
    if !config.cf_domains.is_empty() {
        println!();
        println!("Cloudflare proxy domains (DC2 WebSocket probe):");

        for domain in &config.cf_domains {
            print!("  {:40}  ... ", format!("kws2.{}", domain));
            // Flush so the user sees the label before the potentially slow probe.
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_cf_domain(domain, skip_tls, cf_timeout, outbound, cf_opts).await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── Cloudflare Worker probe ──────────────────────────────────────────
    if !cf_worker_domains.is_empty() {
        println!();
        println!("Cloudflare Worker domains (DC2 TCP tunnel probe):");
        for domain in cf_worker_domains {
            print!("  {:40}  ... ", domain);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_cf_worker(domain, skip_tls, cf_timeout, outbound, cf_opts).await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── MTProto proxy probes ──────────────────────────────────────────────
    if !config.mtproto_proxies.is_empty() {
        println!();
        println!("Upstream MTProto proxies:");

        for proxy in &config.mtproto_proxies {
            let label = format!("{}:{}  [{}]", proxy.host, proxy.port, proxy_kind(proxy));
            print!("  {:40}  ... ", label);
            let _ = std::io::Write::flush(&mut std::io::stdout());

            let status = probe_mtproto_proxy(proxy, upstream_timeout, outbound).await;
            println!("[{}]  {}", status.marker(), status.detail());

            if !status.is_ok() {
                all_ok = false;
            }
        }
    }

    // ── Own listener probe ────────────────────────────────────────────────
    // `listener` is the socket the caller bound for this process.  Without one
    // there is nothing of ours to probe: the probe is about the listener and
    // the routing this config actually serves with.
    let mut skipped = 0usize;
    if config.check_listener {
        println!();
        println!("Own listener (end-to-end MTProto probe):");

        match listener {
            // The probe is about the socket this process serves on: without one
            // there is nothing to probe, and saying so beats reporting a pass
            // for a probe that never ran.
            None => {
                println!("[FAIL]  no bound socket — run it in the process that listens");
                all_ok = false;
            }
            Some(addr) => {
                let target = probe_addr(addr);
                // Printed after the probe returns, in one piece: in this mode
                // the serving proxy logs to the same stdout, and the pool
                // warm-up plus the probe's own connection would otherwise land
                // in the middle of this line.
                let label = format!("  {:40}  ... ", target);

                // A listener configured for FakeTLS reads a TLS record before
                // anything else, so it is skipped rather than failed: the plain
                // probe cannot speak to it, and a failure would blame a config
                // that works for its clients.
                if config.normalized_listen_faketls_domain().is_some() {
                    println!(
                        "{label}[SKIP]  FakeTLS listener: this probe speaks the plain transport"
                    );
                    skipped += 1;
                } else {
                    // A cold route can spend every connect timeout in the ladder
                    // before the DC answers — the direct WS attempt alone may
                    // burn `--ws-connect-timeout` on a blackholed network — so
                    // the wait covers the sum rather than the handshake budget.
                    let reply_timeout = Duration::from_secs(
                        config.handshake_timeout
                            + config.ws_connect_timeout
                            + config.cf_connect_timeout
                            + config.upstream_connect_timeout
                            + config.tcp_fallback_timeout,
                    );
                    // DC 2, as in the probes above: a representative data centre.
                    let secret = config.secret_bytes();
                    let status = probe_listener(target, &secret, 2, reply_timeout).await;
                    println!("{label}[{}]  {}", status.marker(), status.detail());
                    if !status.is_ok() {
                        all_ok = false;
                    }
                }
            }
        }
    }

    // ── Summary ───────────────────────────────────────────────────────────
    println!();
    println!("{}", sep);
    if !all_ok {
        println!("  Result: one or more checks FAILED");
    } else if requested == skipped {
        // A skip is not a pass.  An exit code is what scripts and healthchecks
        // read, and a run that only skipped has verified nothing.
        println!("  Result: nothing was checked — every requested probe was skipped");
        all_ok = false;
    } else {
        println!("  Result: all checks passed");
    }
    println!("{}", sep);

    all_ok
}

#[cfg(test)]
mod tests;
