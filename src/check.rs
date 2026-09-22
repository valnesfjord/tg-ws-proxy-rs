//! Connectivity checker for Cloudflare proxy domains and upstream MTProto
//! proxies.
//!
//! Run with `--check` to verify that every configured CF domain and every
//! upstream MTProto proxy can reach Telegram before the proxy starts serving
//! clients.  The check exits with status 0 when all probes pass, or status 1
//! when any probe fails.
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

use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;

use crate::config::{Config, MtProtoProxy, default_dc_ip};
use crate::crypto::{self, ProtoTag, generate_client_handshake};
use crate::faketls;
use crate::outbound::OutboundConnector;
use crate::ws_client::{
    connect_cf_worker_ws_for_dc_with_outbound_mode, connect_cf_ws_for_dc_with_outbound_mode,
    ws_recv, ws_send,
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
    disable_tls: bool,
) -> ProbeStatus {
    let start = Instant::now();
    let (ws, _record, _all_redirects) = connect_cf_ws_for_dc_with_outbound_mode(
        2,
        &[domain.to_string()],
        false,
        skip_tls,
        timeout,
        outbound,
        disable_tls,
    )
    .await;
    if ws.is_some() {
        ProbeStatus::Ok(start.elapsed())
    } else {
        ProbeStatus::Fail(
            "WebSocket connection failed — check DNS records and Cloudflare settings".to_string(),
        )
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
    disable_tls: bool,
) -> ProbeStatus {
    let Some(dst) = default_dc_ip(2) else {
        return ProbeStatus::Fail("DC 2 default IP is missing".to_string());
    };

    let start = Instant::now();
    let ws = connect_cf_worker_ws_for_dc_with_outbound_mode(
        domain,
        dst,
        2,
        false,
        skip_tls,
        timeout,
        outbound,
        disable_tls,
    )
    .await;
    let Some(mut ws) = ws else {
        return ProbeStatus::Fail(
            "Worker WebSocket tunnel failed — check Worker code and domain".to_string(),
        );
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

/// Probe an MTProto proxy (plain or FakeTLS) by connecting and sending the
/// MTProto obfuscation handshake.
///
/// For FakeTLS proxies the probe also drains the server's fake TLS handshake,
/// verifying end-to-end protocol negotiation.  For plain proxies a successful
/// TCP connect + handshake send is sufficient to confirm reachability.
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
    let (handshake, _enc, _dec) =
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
    }

    ProbeStatus::Ok(start.elapsed())
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
    run_check_with_outbound(config, &outbound).await
}

/// Same as [`run_check`], but uses a pre-built outbound connector so callers
/// can share proxy configuration across runtime components.
pub async fn run_check_with_outbound(config: &Config, outbound: &OutboundConnector) -> bool {
    let cf_timeout = Duration::from_secs(config.cf_connect_timeout);
    let upstream_timeout = Duration::from_secs(config.upstream_connect_timeout);
    let skip_tls = config.skip_tls_verify;

    let sep = "=".repeat(60);
    println!("{}", sep);
    println!("  tg-ws-proxy connectivity check");
    println!("{}", sep);

    let cf_worker_domains = config.cf_worker_domains();

    if config.cf_domains.is_empty()
        && cf_worker_domains.is_empty()
        && config.mtproto_proxies.is_empty()
    {
        println!();
        println!("  Nothing to check.");
        println!("  Configure --cf-domain, --cf-worker-domain and/or --mtproto-proxy and re-run.");
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

            let status = probe_cf_domain(
                domain,
                skip_tls,
                cf_timeout,
                outbound,
                config.cf_disable_tls,
            )
            .await;
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

            let status = probe_cf_worker(
                domain,
                skip_tls,
                cf_timeout,
                outbound,
                config.cf_disable_tls,
            )
            .await;
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

    // ── Summary ───────────────────────────────────────────────────────────
    println!();
    println!("{}", sep);
    if all_ok {
        println!("  Result: all checks passed");
    } else {
        println!("  Result: one or more checks FAILED");
    }
    println!("{}", sep);

    all_ok
}
