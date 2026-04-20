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
//! **MTProto proxy (plain / 0xdd)** — A TCP connection is made and the
//! 64-byte MTProto obfuscation handshake is sent.  A successful send verifies
//! the proxy is reachable at the network level.
//!
//! **MTProto proxy (FakeTLS / 0xee)** — As above, but a proper TLS ClientHello
//! with HMAC authentication is sent first.  The probe waits for the server's
//! fake TLS handshake response; a successful drain confirms both reachability
//! and correct protocol support.

use std::time::{Duration, Instant};

use tokio::io::{AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Config, MtProtoProxy};
use crate::crypto::{generate_client_handshake, ProtoTag};
use crate::faketls;
use crate::ws_client::connect_cf_ws_for_dc;

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
async fn probe_cf_domain(domain: &str, skip_tls: bool, timeout: Duration) -> ProbeStatus {
    let start = Instant::now();
    let (ws, _) =
        connect_cf_ws_for_dc(2, &[domain.to_string()], false, skip_tls, timeout).await;
    if ws.is_some() {
        ProbeStatus::Ok(start.elapsed())
    } else {
        ProbeStatus::Fail(
            "WebSocket connection failed — check DNS records and Cloudflare settings".to_string(),
        )
    }
}

/// Probe an MTProto proxy (plain or FakeTLS) by connecting and sending the
/// MTProto obfuscation handshake.
///
/// For FakeTLS proxies the probe also drains the server's fake TLS handshake,
/// verifying end-to-end protocol negotiation.  For plain proxies a successful
/// TCP connect + handshake send is sufficient to confirm reachability.
async fn probe_mtproto_proxy(proxy: &MtProtoProxy, timeout: Duration) -> ProbeStatus {
    let secret = match hex::decode(&proxy.secret) {
        Ok(b) => b,
        Err(e) => return ProbeStatus::Fail(format!("invalid hex secret: {}", e)),
    };

    let is_faketls = secret.len() > 17 && secret[0] == 0xee;
    let key_bytes: &[u8] = if secret.len() >= 17 && matches!(secret[0], 0xdd | 0xee) {
        &secret[1..17]
    } else {
        &secret
    };

    let start = Instant::now();

    // ── TCP connect ───────────────────────────────────────────────────────
    let stream = match tokio::time::timeout(
        timeout,
        TcpStream::connect(format!("{}:{}", proxy.host, proxy.port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return ProbeStatus::Fail(format!("TCP connect failed: {}", e)),
        Err(_) => return ProbeStatus::Fail("TCP connect timed out".to_string()),
    };
    let _ = stream.set_nodelay(true);

    // Use DC index 2 (non-media) as a representative test target.
    let (handshake, _enc, _dec) =
        generate_client_handshake(key_bytes, 2, ProtoTag::PaddedIntermediate);
    let (mut reader, mut writer) = tokio::io::split(stream);

    if is_faketls {
        // ── FakeTLS path ──────────────────────────────────────────────────
        let hostname = match std::str::from_utf8(&secret[17..]) {
            Ok(h) => h,
            Err(_) => {
                return ProbeStatus::Fail(
                    "FakeTLS secret contains non-UTF-8 hostname".to_string(),
                )
            }
        };

        let mut client_hello = faketls::build_faketls_client_hello(hostname);
        faketls::sign_faketls_client_hello(&mut client_hello, key_bytes);

        if let Err(e) = writer.write_all(&client_hello).await {
            return ProbeStatus::Fail(format!("send FakeTLS ClientHello: {}", e));
        }

        // Drain the server's fake TLS handshake (ServerHello → CCS → AppData).
        let drained = tokio::time::timeout(
            timeout,
            faketls::drain_faketls_server_hello(&mut reader),
        )
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
    let cf_timeout = Duration::from_secs(config.cf_connect_timeout);
    let upstream_timeout = Duration::from_secs(config.upstream_connect_timeout);
    let skip_tls = config.skip_tls_verify;

    let sep = "=".repeat(60);
    println!("{}", sep);
    println!("  tg-ws-proxy connectivity check");
    println!("{}", sep);

    if config.cf_domains.is_empty() && config.mtproto_proxies.is_empty() {
        println!();
        println!("  Nothing to check.");
        println!("  Configure --cf-domain and/or --mtproto-proxy and re-run.");
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

            let status = probe_cf_domain(domain, skip_tls, cf_timeout).await;
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

            let status = probe_mtproto_proxy(proxy, upstream_timeout).await;
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
