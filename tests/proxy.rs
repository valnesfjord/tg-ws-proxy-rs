use std::time::Duration;

use clap::Parser;
use tokio::io::AsyncWriteExt;

use tg_ws_proxy_rs::config::Config;
use tg_ws_proxy_rs::crypto::{ProtoTag, generate_client_handshake};
use tg_ws_proxy_rs::faketls::{
    TLS_MAX_RECORD_PAYLOAD, build_faketls_client_hello, drain_faketls_server_hello,
    sign_faketls_client_hello, write_tls_appdata,
};
use tg_ws_proxy_rs::proxy::split_mtproto_init_and_pending;

mod common;

use common::{
    await_proxy_handler, await_proxy_request, await_proxy_requests, rejecting_http_proxy,
    rejecting_http_proxy_requests, run_proxy_once, run_proxy_once_for_dc,
    stalling_http_proxy_requests, start_proxy_connection,
};

const SECRET: &str = "00112233445566778899aabbccddeeff";

// The upstream-failure cooldown is a process-global map keyed by `host:port`,
// and every test in this binary shares it. Tests that need the upstream tier
// to actually be attempted therefore each use their own hostname, so a
// sibling test failing its upstream cannot make this one skip the tier and
// fall through to TCP instead.
const UPSTREAM_FULL_RECORD: &str = "upstream-full-record.example";
const UPSTREAM_OVERSIZED: &str = "upstream-oversized.example";

// ─── Inbound handshake framing ───────────────────────────────────────────────

#[test]
fn split_mtproto_init_keeps_coalesced_appdata_payload() {
    // Some clients send the MTProto init and the first payload in the same TLS
    // AppData record; the listener must preserve the extra bytes.
    let mut data = Vec::new();
    data.extend(0u8..64);
    data.extend_from_slice(b"first payload bytes");

    let (handshake, pending) =
        split_mtproto_init_and_pending(&data).expect("coalesced init + payload");

    assert_eq!(handshake, core::array::from_fn(|i| i as u8));
    assert_eq!(pending, b"first payload bytes");
}

#[test]
fn split_mtproto_init_accepts_exactly_64_bytes() {
    // The normal case is exactly one 64-byte MTProto obfuscation init packet.
    let data: Vec<u8> = (0u8..64).collect();

    let (handshake, pending) = split_mtproto_init_and_pending(&data).expect("exact init");

    assert_eq!(handshake, core::array::from_fn(|i| i as u8));
    assert!(pending.is_empty());
}

#[test]
fn split_mtproto_init_rejects_short_input() {
    // Less than 64 bytes cannot be a complete MTProto obfuscation init.
    let data: Vec<u8> = (0u8..63).collect();

    assert!(split_mtproto_init_and_pending(&data).is_none());
    assert!(split_mtproto_init_and_pending(&[]).is_none());
}

// ─── Fallback chain ──────────────────────────────────────────────────────────

/// Build a serving (non-`--check`) config routed through `proxy_addr`, with
/// environment proxy discovery disabled so the host's own `HTTPS_PROXY` /
/// `NO_PROXY` cannot influence the test.
fn proxy_config(proxy_addr: &str, extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--secret",
        SECRET,
        "--outbound-proxy",
        proxy_addr,
        "--no-outbound-proxy",
        "--no-proxy",
        "",
        "--handshake-timeout",
        "2",
        "--cf-connect-timeout",
        "2",
        "--upstream-connect-timeout",
        "2",
        "--tcp-fallback-timeout",
        "2",
    ];
    args.extend_from_slice(extra);

    Config::try_parse_from(args).unwrap()
}

/// The `CONNECT` targets a fallback chain asked the outbound proxy for, in
/// order — the observable shape of the ladder.
fn connect_targets(requests: &[String]) -> Vec<&str> {
    requests
        .iter()
        .filter_map(|request| request.split_whitespace().nth(1))
        .collect()
}

#[tokio::test]
async fn proxy_upstream_fallback_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &["--mtproto-proxy", &format!("upstream.example:443:{SECRET}")],
    );

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert!(
        requests
            .iter()
            .any(|request| request.starts_with("CONNECT upstream.example:443 HTTP/1.1")),
        "expected upstream fallback CONNECT, got {requests:?}"
    );
}

#[tokio::test]
async fn proxy_tcp_fallback_uses_outbound_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = proxy_config(&format!("http://{proxy_addr}"), &[]);

    run_proxy_once(config).await;

    // No --dc-ip and no CF/upstream tiers configured, so DC 2 falls straight
    // through to its built-in fallback IP.
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 149.154.167.51:443 HTTP/1.1"));
}

#[tokio::test]
async fn cf_proxy_is_retried_fresh_on_every_connection_no_cooldown() {
    // Regression test for issue #81: a per-DC cooldown used to block *every*
    // CF domain for a DC after a single failed attempt, so with
    // --cf-balance/--default-domains (many domains) one flaky domain could
    // knock out CF entirely for --cf-fail-cooldown seconds, forcing every
    // connection in that window straight to the (often doomed) TCP fallback.
    // Upstream tg-ws-proxy's `_cfproxy_fallback` has no such cooldown at
    // all — every connection retries every configured domain fresh — so we
    // now match that. With one CF domain configured (2 domain variants:
    // kwsN and kwsN-1) and no --dc-ip/upstream-proxy, each of 2 separate
    // client connections should independently try both CF domain variants
    // before falling through to TCP: 3 CONNECTs per connection, 6 total.
    // The old cooldown-gated behavior would only produce 4 (connection 2
    // skips CF and goes straight to its single TCP-fallback attempt).
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let make_config = || {
        proxy_config(
            &format!("http://{proxy_addr}"),
            &["--cf-domain", "example.net"],
        )
    };

    run_proxy_once(make_config()).await;
    run_proxy_once(make_config()).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        requests.len(),
        6,
        "expected both connections to retry CF fresh (2 domains + TCP \
         fallback each), got {requests:?}"
    );
}

#[tokio::test]
async fn cf_worker_is_tried_before_the_cf_proxy() {
    // The Python fallback order for a DC without --dc-ip is Worker, then CF
    // proxy, then TCP: 1 + 2 + 1 = 4 CONNECTs.
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--cf-worker-domain",
            "worker.example.dev",
            "--cf-domain",
            "example.net",
        ],
    );

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        connect_targets(&requests),
        [
            "worker.example.dev:443",
            "kws2.example.net:443",
            "kws2-1.example.net:443",
            "149.154.167.51:443",
        ]
    );
}

#[tokio::test]
async fn cf_ip_bypasses_dns_and_tries_every_edge_for_the_cf_proxy() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--cf-domain",
            "cfip.example.net",
            "--cf-ip",
            "203.0.113.10,198.51.100.20",
        ],
    );

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    let targets = connect_targets(&requests);
    assert_eq!(targets.len(), 5, "unexpected fallback shape: {targets:?}");
    assert_eq!(
        targets.iter().filter(|&&t| t == "203.0.113.10:443").count(),
        2
    );
    assert_eq!(
        targets
            .iter()
            .filter(|&&t| t == "198.51.100.20:443")
            .count(),
        2
    );
    assert_eq!(targets.last(), Some(&"149.154.167.51:443"));
    assert!(
        targets
            .iter()
            .all(|target| !target.contains("cfip.example.net")),
        "--cf-ip must never fall back to DNS: {targets:?}"
    );
}

#[tokio::test]
async fn cf_ip_bypasses_dns_and_tries_every_edge_for_the_worker() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--cf-worker-domain",
            "worker-cfip.example.dev",
            "--cf-ip",
            "203.0.113.11,198.51.100.21",
        ],
    );

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    let targets = connect_targets(&requests);
    assert_eq!(targets.len(), 3, "unexpected fallback shape: {targets:?}");
    assert!(targets[..2].contains(&"203.0.113.11:443"));
    assert!(targets[..2].contains(&"198.51.100.21:443"));
    assert_eq!(targets.last(), Some(&"149.154.167.51:443"));
    assert!(
        targets
            .iter()
            .all(|target| !target.contains("worker-cfip.example.dev")),
        "--cf-ip must never fall back to DNS: {targets:?}"
    );
}

#[tokio::test]
async fn cf_priority_tries_the_cf_proxy_before_the_direct_websocket() {
    // With --dc-ip set the direct WS path is normally first; --cf-priority
    // flips that, and the CF tier is then not retried after WS also fails.
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--cf-priority",
            "--cf-domain",
            "example.net",
            "--dc-ip",
            "2:149.154.167.220",
            "--ws-connect-timeout",
            "2",
        ],
    );

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        connect_targets(&requests),
        [
            // CF first, both records...
            "kws2.example.net:443",
            "kws2-1.example.net:443",
            // ...then the direct WS attempt on both Telegram hostnames...
            "149.154.167.220:443",
            "149.154.167.220:443",
            // ...and finally the TCP fallback. CF is not tried a second time.
            "149.154.167.51:443",
        ]
    );
}

#[tokio::test]
async fn cf_priority_tries_the_cf_worker_before_the_direct_websocket() {
    // Regression for #93: --cf-priority used to cover only --cf-domain, so a
    // Worker-only setup still paid the full direct-WS timeout on every
    // connection before reaching the one tier that worked.
    let (proxy_addr, proxy_task) = rejecting_http_proxy_requests().await;
    // The domain is given in URL form on purpose: normalization happens once
    // at startup now, so this is what keeps the routing path covered by it.
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--cf-priority",
            "--cf-worker-domain",
            "https://worker-priority.example.dev/apiws",
            "--dc-ip",
            "2:149.154.167.221",
            "--ws-connect-timeout",
            "2",
        ],
    )
    .with_defaults();

    run_proxy_once(config).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        connect_targets(&requests),
        [
            // The Worker comes first...
            "worker-priority.example.dev:443",
            // ...then the direct WS attempt on both Telegram hostnames...
            "149.154.167.221:443",
            "149.154.167.221:443",
            // ...and finally TCP. The Worker is not tried a second time.
            "149.154.167.51:443",
        ]
    );
}

#[tokio::test]
async fn a_dc_ip_that_timed_out_is_skipped_on_the_next_connection() {
    // A DPI-blocked DC IP costs a full connect timeout per attempt. Paying
    // that on every connection is what leaves Telegram sitting in
    // "Connecting..." — so once an address times out, later connections go
    // straight to the tiers that can still reach Telegram.
    //
    // Here every tier is dead, which is the case that must not turn into a
    // one-hour lockout: with nothing else left the address is re-probed, so a
    // cooldown set by a passing glitch can still be cleared by a connection
    // that works.
    const DEAD_IP: &str = "149.154.175.101";
    let (proxy_addr, proxy_task) = stalling_http_proxy_requests(DEAD_IP).await;
    let make_config = || {
        proxy_config(
            &format!("http://{proxy_addr}"),
            &[
                "--cf-worker-domain",
                "worker-ipfail.example.dev",
                "--dc-ip",
                &format!("3:{DEAD_IP}"),
                "--ws-connect-timeout",
                "1",
                "--ws-fail-probe-timeout",
                "1",
                "--cf-fail-cooldown",
                "0",
            ],
        )
    };

    run_proxy_once_for_dc(make_config(), 3).await;
    run_proxy_once_for_dc(make_config(), 3).await;

    let requests = await_proxy_requests(proxy_task).await;
    assert_eq!(
        connect_targets(&requests),
        [
            // First connection probes the DC IP on both Telegram hostnames...
            DEAD_IP,
            DEAD_IP,
            // ...then falls back to the Worker and finally to TCP.
            "worker-ipfail.example.dev:443",
            "149.154.175.100:443",
            // The second one goes to the Worker first, skipping the address...
            "worker-ipfail.example.dev:443",
            // ...and only re-probes it because nothing else was left, on the
            // short cooldown clock rather than the full connect timeout.
            DEAD_IP,
            DEAD_IP,
            "149.154.175.100:443",
        ]
        .map(|target| if target == DEAD_IP {
            format!("{DEAD_IP}:443")
        } else {
            target.to_string()
        })
    );
}

#[tokio::test]
async fn a_client_with_the_wrong_secret_is_dropped_without_dialling_out() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = proxy_config(&format!("http://{proxy_addr}"), &[]);

    let (mut client, handler) = start_proxy_connection(config).await;
    // A handshake generated with a different secret must not parse.
    let wrong_secret = hex::decode("ffeeddccbbaa99887766554433221100").unwrap();
    let (handshake, _, _) =
        generate_client_handshake(&wrong_secret, 2, ProtoTag::PaddedIntermediate);
    client.write_all(&handshake).await.unwrap();
    drop(client);

    await_proxy_handler(handler).await;

    // The scanner is drained silently: nothing was dialled outbound.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), proxy_task)
            .await
            .is_err(),
        "a bad handshake must not trigger an outbound connection"
    );
}

#[tokio::test]
async fn inbound_faketls_handshake_is_accepted_and_routed() {
    let domain = "example.com";
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &["--listen-faketls-domain", domain],
    );
    let secret = config.secret_bytes();

    let (client, handler) = start_proxy_connection(config).await;
    let (mut reader, mut writer) = tokio::io::split(client);

    // Speak the client half of the FakeTLS camouflage: a signed ClientHello,
    // then the real MTProto init inside an Application Data record.
    let mut client_hello = build_faketls_client_hello(domain);
    sign_faketls_client_hello(&mut client_hello, &secret);
    writer.write_all(&client_hello).await.unwrap();

    assert!(
        drain_faketls_server_hello(&mut reader).await,
        "proxy did not answer with a valid FakeTLS ServerHello"
    );

    let (handshake, _, _) = generate_client_handshake(&secret, 2, ProtoTag::PaddedIntermediate);
    write_tls_appdata(&mut writer, &handshake).await.unwrap();
    drop(writer);
    drop(reader);

    await_proxy_handler(handler).await;

    // The camouflaged handshake was unwrapped and routed like any other.
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with("CONNECT 149.154.167.51:443 HTTP/1.1"));
}

/// Drive a FakeTLS client through the handshake and hand back the two halves,
/// ready for the data phase.
async fn faketls_client_handshake(
    client: tokio::net::TcpStream,
    domain: &str,
    secret: &[u8],
) -> (
    tokio::io::ReadHalf<tokio::net::TcpStream>,
    tokio::io::WriteHalf<tokio::net::TcpStream>,
) {
    let (mut reader, mut writer) = tokio::io::split(client);

    let mut client_hello = build_faketls_client_hello(domain);
    sign_faketls_client_hello(&mut client_hello, secret);
    writer.write_all(&client_hello).await.unwrap();

    assert!(
        drain_faketls_server_hello(&mut reader).await,
        "proxy did not answer with a valid FakeTLS ServerHello"
    );

    let (handshake, _, _) = generate_client_handshake(secret, 2, ProtoTag::PaddedIntermediate);
    write_tls_appdata(&mut writer, &handshake).await.unwrap();

    (reader, writer)
}

#[tokio::test]
async fn inbound_faketls_relays_a_maximum_size_application_data_record() {
    // A client read is a whole TLS record, and `read_tls_appdata` signals a
    // record that does not fit the buffer as `Ok(0)` — indistinguishable from
    // EOF to the bridge. A full-size record (and one spanning two records)
    // must therefore still be relayed rather than silently ending the session.
    let domain = "example.com";
    let (upstream_addr, upstream_task) = common::counting_mtproto_acceptor().await;
    let (proxy_addr, proxy_task) = common::tunneling_http_proxy(upstream_addr).await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--listen-faketls-domain",
            domain,
            "--mtproto-proxy",
            &format!("{UPSTREAM_FULL_RECORD}:443:{SECRET}"),
        ],
    );
    let secret = config.secret_bytes();

    let (client, handler) = start_proxy_connection(config).await;
    let (reader, mut writer) = faketls_client_handshake(client, domain, &secret).await;

    // One maximum-size record, then a payload that spans two records.
    let full_record = vec![0xa5u8; TLS_MAX_RECORD_PAYLOAD];
    let spanning = vec![0x5au8; TLS_MAX_RECORD_PAYLOAD + 1024];
    write_tls_appdata(&mut writer, &full_record).await.unwrap();
    write_tls_appdata(&mut writer, &spanning).await.unwrap();
    drop(writer);
    drop(reader);

    await_proxy_handler(handler).await;

    let relayed = common::await_task(upstream_task).await;
    assert_eq!(
        relayed,
        full_record.len() + spanning.len(),
        "the proxy dropped part of the client's application data"
    );
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with(&format!("CONNECT {UPSTREAM_FULL_RECORD}:443 HTTP/1.1")));
}

#[tokio::test]
async fn inbound_faketls_tolerates_a_slightly_oversized_record() {
    // Regression guard: `read_tls_appdata` reports any record larger than the
    // read buffer as `Ok(0)`, so a client that emits a record above the RFC
    // maximum used to have its session end silently. The client-read buffer
    // keeps the same tolerance the inbound handshake already accepts.
    let domain = "example.com";
    let oversized_len = TLS_MAX_RECORD_PAYLOAD + 100;

    let (upstream_addr, upstream_task) = common::counting_mtproto_acceptor().await;
    let (proxy_addr, proxy_task) = common::tunneling_http_proxy(upstream_addr).await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &[
            "--listen-faketls-domain",
            domain,
            "--mtproto-proxy",
            &format!("{UPSTREAM_OVERSIZED}:443:{SECRET}"),
        ],
    );
    let secret = config.secret_bytes();

    let (client, handler) = start_proxy_connection(config).await;
    let (reader, mut writer) = faketls_client_handshake(client, domain, &secret).await;

    // Hand-rolled, because `write_tls_appdata` correctly chunks at the RFC
    // maximum and would never emit an oversized record itself.
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(oversized_len as u16).to_be_bytes());
    record.extend(std::iter::repeat_n(0x33u8, oversized_len));
    writer.write_all(&record).await.unwrap();
    drop(writer);
    drop(reader);

    await_proxy_handler(handler).await;

    let relayed = common::await_task(upstream_task).await;
    assert_eq!(
        relayed, oversized_len,
        "an oversized record was treated as EOF instead of being relayed"
    );
    let request = await_proxy_request(proxy_task).await;
    assert!(request.starts_with(&format!("CONNECT {UPSTREAM_OVERSIZED}:443 HTTP/1.1")));
}

#[tokio::test]
async fn inbound_faketls_rejects_a_client_hello_for_another_hostname() {
    let (proxy_addr, proxy_task) = rejecting_http_proxy().await;
    let config = proxy_config(
        &format!("http://{proxy_addr}"),
        &["--listen-faketls-domain", "example.com"],
    );
    let secret = config.secret_bytes();

    let (mut client, handler) = start_proxy_connection(config).await;

    let mut client_hello = build_faketls_client_hello("not-the-configured.example");
    sign_faketls_client_hello(&mut client_hello, &secret);
    client.write_all(&client_hello).await.unwrap();
    drop(client);

    await_proxy_handler(handler).await;

    assert!(
        tokio::time::timeout(Duration::from_millis(200), proxy_task)
            .await
            .is_err(),
        "an SNI mismatch must not trigger an outbound connection"
    );
}
