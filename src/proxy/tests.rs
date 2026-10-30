use super::*;

use clap::Parser;

use crate::crypto::HANDSHAKE_LEN;

#[test]
fn faketls_pending_uses_an_offset_and_releases_its_record() {
    let mut pending = PendingData::from_record(vec![10, 11, 12, 13, 14], 2);
    let original_ptr = pending.data.as_ptr();
    let mut first = [0u8; 2];

    assert_eq!(pending.read(&mut first), Some(2));
    assert_eq!(first, [12, 13]);
    assert_eq!(pending.data.as_ptr(), original_ptr);

    let mut last = [0u8; 2];
    assert_eq!(pending.read(&mut last), Some(1));
    assert_eq!(last[0], 14);
    assert!(pending.data.is_empty());
    assert_eq!(pending.data.capacity(), 0);
    assert_eq!(pending.read(&mut last), None);
}

#[tokio::test]
async fn client_handler_future_stays_compact() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, peer) = listener.accept().await.unwrap();

    let config = Arc::new(
        Config::try_parse_from([
            "tg-ws-proxy",
            "--secret",
            "00112233445566778899aabbccddeeff",
            "--pool-size",
            "0",
            "--no-outbound-proxy",
        ])
        .unwrap(),
    );
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let handler = handle_client_with_runtime(server, peer, config, pool, runtime);
    let future_size = std::mem::size_of_val(&handler);
    eprintln!("per-client future size: {future_size} bytes");

    assert!(
        future_size <= 4 * 1024,
        "the per-client future grew to {future_size} bytes"
    );

    drop(handler);
    drop(client);
}

#[test]
fn balanced_rotates_the_starting_domain() {
    let counter = AtomicUsize::new(0);
    let workers = vec![
        "w1.example.workers.dev".to_string(),
        "w2.example.workers.dev".to_string(),
        "w3.example.workers.dev".to_string(),
    ];

    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w1.example.workers.dev",
            "w2.example.workers.dev",
            "w3.example.workers.dev"
        ]
    );
    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w2.example.workers.dev",
            "w3.example.workers.dev",
            "w1.example.workers.dev"
        ]
    );
    assert_eq!(
        domain_order(&workers, balance_offset(&workers, true, &counter)).collect::<Vec<_>>(),
        [
            "w3.example.workers.dev",
            "w1.example.workers.dev",
            "w2.example.workers.dev"
        ]
    );
}

#[test]
fn balanced_leaves_short_lists_untouched() {
    let counter = AtomicUsize::new(0);
    let single = vec!["only.example".to_string()];

    assert_eq!(balance_offset(&[], true, &counter), 0);
    assert_eq!(balance_offset(&single, true, &counter), 0);
    // A list that cannot be rotated must not consume a counter tick either.
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn domain_order_borrows_without_cloning() {
    let counter = AtomicUsize::new(0);
    let domains = vec!["a.example".to_string(), "b.example".to_string()];

    let ordered =
        domain_order(&domains, balance_offset(&domains, false, &counter)).collect::<Vec<_>>();
    assert!(std::ptr::eq(ordered[0], domains[0].as_str()));
    assert!(std::ptr::eq(ordered[1], domains[1].as_str()));
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn cooldown_is_tracked_per_key() {
    let cooldowns: CooldownMap<String> = CooldownMap::new();

    assert!(!cooldowns.active("w1.example.workers.dev"));

    cooldowns.set(
        "w1.example.workers.dev".to_string(),
        Duration::from_secs(60),
    );
    assert!(cooldowns.active("w1.example.workers.dev"));
    assert!(!cooldowns.active("w2.example.workers.dev"));

    cooldowns.clear("w1.example.workers.dev");
    assert!(!cooldowns.active("w1.example.workers.dev"));
}

#[test]
fn cooldown_expires_once_the_window_passes() {
    let cooldowns: CooldownMap<(u32, bool)> = CooldownMap::new();

    cooldowns.set((2, false), Duration::ZERO);

    assert!(!cooldowns.active(&(2, false)));
}

#[test]
fn cooldown_keys_include_the_media_flag() {
    let cooldowns: CooldownMap<(u32, bool)> = CooldownMap::new();

    cooldowns.set((2, false), Duration::from_secs(60));

    assert!(cooldowns.active(&(2, false)));
    // The media flag is part of the key — a non-media cooldown must not leak
    // into the media bucket for the same DC.
    assert!(!cooldowns.active(&(2, true)));
}

#[test]
fn upstream_key_joins_host_and_port() {
    assert_eq!(upstream_key("proxy.example", 443), "proxy.example:443");
}

#[test]
fn human_bytes_scales_through_the_units() {
    assert_eq!(human_bytes(0), "0.0B");
    assert_eq!(human_bytes(1023), "1023.0B");
    assert_eq!(human_bytes(1024), "1.0KB");
    assert_eq!(human_bytes(1024 * 1024), "1.0MB");
    assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0GB");
}

#[tokio::test]
async fn an_aborted_direction_still_reports_the_bytes_it_moved() {
    let bytes_up = Arc::new(StdMutex::new(0));
    let mut bytes_down = 0;
    let upload = tokio::spawn({
        let mut bytes = UploadCounter::new(Arc::clone(&bytes_up));
        async move {
            bytes.add(4096);
            tokio::task::yield_now().await;
        }
    });
    let download = async {
        bytes_down += 1024;
        std::future::pending::<()>().await;
        bytes_down += 999_999;
    };

    let closed_by = join_bridge(upload, download).await;

    assert_eq!((*bytes_up.lock().unwrap(), bytes_down), (4096, 1024));
    // The upload direction ran out first, which means the client stopped.
    assert!(matches!(closed_by, ClosedBy::Client));
}

#[tokio::test]
async fn the_side_that_stops_first_is_the_one_reported() {
    // A session that transfers nothing looks identical whichever side hung
    // up; this is what tells a client-side timeout apart from an upstream
    // that dropped us right after the handshake.
    let upload = tokio::spawn(std::future::pending::<()>());
    let download = async {};
    assert!(matches!(
        join_bridge(upload, download).await,
        ClosedBy::Upstream
    ));

    let upload = tokio::spawn(async {});
    let download = std::future::pending::<()>();
    assert!(matches!(
        join_bridge(upload, download).await,
        ClosedBy::Client
    ));
}

// ─── WebSocket framing ───────────────────────────────────────────────────────

/// Bridge one client payload through `bridge_ws` and report the size of every
/// WebSocket message the upstream received.
///
/// Both ends are plain TCP: the framing decision under test happens above the
/// transport, so wrapping the stream in `MaybeTlsStream::Plain` exercises the
/// same code a real TLS connection would.
async fn upstream_frame_sizes(framing: WsFraming, payload: &[u8]) -> Vec<usize> {
    use tokio::net::TcpListener;
    use tokio_tungstenite::{MaybeTlsStream, accept_async, client_async};

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();
    let sizes = tokio::spawn(async move {
        let (stream, _) = upstream.accept().await.unwrap();
        let mut ws = accept_async(stream).await.unwrap();
        let mut sizes = Vec::new();

        while let Some(Ok(message)) = ws.next().await {
            match message {
                Message::Binary(data) => sizes.push(data.len()),
                Message::Close(_) => break,
                _ => {}
            }
        }

        sizes
    });

    let tcp = TcpStream::connect(upstream_addr).await.unwrap();
    let (ws, _) = client_async("ws://127.0.0.1/apiws", MaybeTlsStream::Plain(tcp))
        .await
        .unwrap();

    // The client half of the bridge, driven from this test.
    let clients = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let clients_addr = clients.local_addr().unwrap();
    let mut client = TcpStream::connect(clients_addr).await.unwrap();
    let (server, _) = clients.accept().await.unwrap();
    let (reader, writer) = server.into_split();

    let relay_init = generate_relay_init(ProtoTag::PaddedIntermediate, 2);
    let ciphers = build_connection_ciphers(&[0u8; 48], &[0u8; 32], &relay_init);

    let bridge = tokio::spawn(async move {
        bridge_ws(
            ClientReader::Plain(reader),
            ClientWriter::Plain(writer),
            WsBridgeParams {
                label: "127.0.0.1:1".parse().unwrap(),
                ws,
                framing,
                relay_init,
                ciphers,
                proto: ProtoTag::PaddedIntermediate,
                dc: 2,
                is_media: false,
            },
        )
        .await;
    });

    client.write_all(payload).await.unwrap();
    drop(client);
    bridge.await.unwrap();

    sizes.await.unwrap()
}

#[tokio::test]
async fn a_worker_tunnel_never_emits_an_oversized_frame() {
    // Regression for the upload bug upstream fixed in v1.9.1: packet-aligning
    // a Worker tunnel produces one WebSocket message per MTProto packet, and a
    // media upload's packets run past Cloudflare's 1 MiB message cap, which
    // kills the connection mid-transfer. A tunnel is a raw TCP socket at the
    // far end, so it is chunked by client reads instead — and the relay init
    // still goes out as its own first frame.
    const CF_MESSAGE_CAP: usize = 1024 * 1024;
    let payload = vec![0xA5; 3 * CF_MESSAGE_CAP];

    let sizes = upstream_frame_sizes(WsFraming::Tunnel, &payload).await;

    assert_eq!(sizes.first(), Some(&HANDSHAKE_LEN));
    assert!(
        sizes[1..].iter().all(|size| *size <= CLIENT_READ_BUF_SIZE),
        "a tunnel frame must not exceed one client read: {sizes:?}"
    );
    assert_eq!(
        sizes[1..].iter().sum::<usize>(),
        payload.len(),
        "every byte the client sent has to reach the upstream: {sizes:?}"
    );
}

// ─── A pinned ladder and a cooled `--dc-ip` ──────────────────────────────────

// `WS_FAIL` and `IP_FAIL` are process-global maps shared by every test in this
// binary, so each ladder test uses its own DC number (non-canonical test DCs)
// and its own IP address to prevent concurrent runs in libtest from wiping each
// other's state.
const LADDER_DC_STEP_OVER: u32 = 201;
const LADDER_IP_STEP_OVER: &str = "192.0.2.10"; // RFC 5737

const LADDER_DC_NO_LATER_RUNG: u32 = 202;
const LADDER_IP_NO_LATER_RUNG: &str = "192.0.2.11";

const LADDER_DC_RE_PROBE: u32 = 203;
const LADDER_IP_RE_PROBE: &str = "192.0.2.12";

fn ladder_config(extra: &[&str]) -> Config {
    let mut args = vec![
        "tg-ws-proxy",
        "--secret",
        "00112233445566778899aabbccddeeff",
        // A dial to a blackholed address has to be bounded by the test, not by
        // the default ten seconds.
        "--ws-connect-timeout",
        "1",
        "--pool-size",
        "0",
        "--no-outbound-proxy",
    ];
    args.extend_from_slice(extra);
    Config::try_parse_from(args).unwrap()
}

fn ladder_route<'a>(
    config: &'a Config,
    runtime: &'a Arc<Runtime>,
    pool: &'a Arc<WsPool>,
    dc: u32,
) -> Route<'a> {
    Route {
        label: "127.0.0.1:1".parse().unwrap(),
        config,
        runtime,
        pool,
        timeouts: Timeouts::from_config(config),
        dc,
        is_media: false,
        media: media_tag(false),
        dc_idx: dc as i16,
        proto: ProtoTag::Intermediate,
    }
}

#[tokio::test]
async fn a_pinned_ladder_steps_over_a_cooled_dc_ip() {
    // A pin replaces the default ladder, and the cooldown skip lives in the
    // default ladder.  Without it here, `--pinned-upstream ws,…` re-dials an
    // address that has already timed out on every cold-pool client, and each of
    // those waits out `--ws-connect-timeout` once per `kws` record before the
    // pin's next rung gets a turn.
    let config = ladder_config(&[]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_STEP_OVER);
    let ws_fail_key = (LADDER_DC_STEP_OVER, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_STEP_OVER.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(
            &[UpstreamTier::Ws, UpstreamTier::Tcp],
            Some(LADDER_IP_STEP_OVER),
        )
        .await;

    // A dial is what arms `WS_FAIL`, so leaving it clear is proof that the
    // cooled address never reached the connector -- the same signal the log's
    // "skipping direct WS" line carries, without needing a network.
    let dialled_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_STEP_OVER);

    assert!(
        matches!(upstream, Some(Upstream::Tcp(_))),
        "the rung after the skipped one is the one that connects"
    );
    assert!(
        !dialled_the_cooled_ip,
        "the pinned ladder dialled the cooled {LADDER_IP_STEP_OVER} again"
    );
}

#[tokio::test]
async fn a_pin_with_no_later_rung_dials_its_cooled_dc_ip_anyway() {
    // Stepped over, not written off: the cooldown is worth honouring only while
    // a later rung can connect.  A `ws`-only pin has no later rung, so the
    // cooled address is the client's only way out, and the doomed attempt beats
    // dropping the connection.
    let config = ladder_config(&[]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_NO_LATER_RUNG);
    let ws_fail_key = (LADDER_DC_NO_LATER_RUNG, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_NO_LATER_RUNG.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(&[UpstreamTier::Ws], Some(LADDER_IP_NO_LATER_RUNG))
        .await;

    let dialled_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_NO_LATER_RUNG);

    assert!(upstream.is_none(), "a pin has nothing to fall back to");
    assert!(
        dialled_the_cooled_ip,
        "the only rung was skipped, which leaves the client nowhere to go"
    );
}

#[tokio::test]
async fn a_pinned_ladder_re_probes_a_cooled_dc_ip_when_every_rung_fails() {
    // The other half of the rule: a skip must not become a dead end for the
    // rest of the cooldown.  An `--mtproto-proxy` on a closed local port fails
    // without a network the way a dead upstream does, so the last thing the
    // ladder has left is the address it stepped over — and asking it is what
    // keeps the cooldown self-healing, since only a successful direct connect
    // clears it.
    let config = ladder_config(&[
        "--mtproto-proxy",
        "127.0.0.1:1:00112233445566778899aabbccddeeff",
    ]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, LADDER_DC_RE_PROBE);
    let ws_fail_key = (LADDER_DC_RE_PROBE, false);

    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.set(LADDER_IP_RE_PROBE.to_string(), Duration::from_secs(60));

    let upstream = route
        .pinned_ladder(
            &[UpstreamTier::Ws, UpstreamTier::Mtproto],
            Some(LADDER_IP_RE_PROBE),
        )
        .await;

    let re_probed_the_cooled_ip = WS_FAIL.active(&ws_fail_key);
    WS_FAIL.clear(&ws_fail_key);
    IP_FAIL.clear(LADDER_IP_RE_PROBE);

    assert!(upstream.is_none(), "nothing in the pin can connect");
    assert!(
        re_probed_the_cooled_ip,
        "the cooled address was never asked again, so nothing can clear it"
    );
}

// ─── The background probe of a cooled `--dc-ip` ──────────────────────────────

/// An outbound HTTP proxy that counts CONNECTs and either holds them open
/// without a word — a dark address, as far as the dialler can tell — or
/// refuses them, which is an address that answers.
async fn probe_outbound(answer: bool) -> (Arc<Runtime>, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dials = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&dials);
    tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            if answer {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            } else {
                held.push(stream);
            }
        }
    });

    let outbound = OutboundConnector::from_config(Some(&format!("http://{addr}")), None, false);
    (Arc::new(Runtime::new(outbound.unwrap())), dials)
}

fn probe(runtime: &Arc<Runtime>, ip: &str, cooldown: Duration) -> IpProbe {
    IpProbe {
        runtime: Arc::clone(runtime),
        ip: ip.to_string(),
        dc: 2,
        is_media: false,
        skip_tls_verify: false,
        connect_timeout: Duration::from_millis(500),
        cooldown,
    }
}

async fn probe_finished(ip: &str) -> bool {
    for _ in 0..60 {
        if !IP_PROBES.lock().unwrap().contains(ip) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn a_cooled_dc_ip_stays_cooled_while_the_probe_finds_it_dark() {
    // #148: the cooldown used to simply run out, and the next client dialled
    // the address on the full connect timeout.  The entry now outlives the
    // window until the probe has its answer, and a probe that times out again
    // re-arms it.
    const IP: &str = "192.0.2.20";
    let (runtime, dials) = probe_outbound(false).await;
    let cooldown = Duration::from_millis(200);

    probe(&runtime, IP, cooldown).arm();
    // A second timeout while the first probe waits must not start another.
    probe(&runtime, IP, cooldown).arm();

    // Mid-probe: past the bare cooldown, before the 500 ms connect gives up.
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(
        IP_FAIL.active(IP),
        "a client could dial the address mid-probe"
    );
    assert_eq!(dials.load(Ordering::SeqCst), 1, "one probe per address");

    // The probe gave up at ~700 ms and re-armed the entry.
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert!(IP_FAIL.active(IP), "a dark address came back by itself");

    // A client's direct connect clearing the entry ends the probe.
    IP_FAIL.clear(IP);
    assert!(probe_finished(IP).await, "the probe outlived its entry");
}

#[tokio::test]
async fn a_cooled_dc_ip_that_answers_the_probe_comes_back() {
    // Any answer clears it, exactly as in `direct_ws`: only a connect that ran
    // out the clock says the address itself is gone.
    const IP: &str = "192.0.2.21";
    let (runtime, dials) = probe_outbound(true).await;

    probe(&runtime, IP, Duration::from_millis(50)).arm();

    assert!(probe_finished(IP).await, "the probe never finished");
    assert!(dials.load(Ordering::SeqCst) >= 1);
    assert!(
        !IP_FAIL.active(IP),
        "an address that answered stayed cooled"
    );
}

#[tokio::test]
async fn a_zero_ip_fail_cooldown_starts_no_probe() {
    // `--ip-fail-cooldown 0` turns the skipping off.  Holding the entry for a
    // probe's grace period would quietly turn it back on.
    const IP: &str = "192.0.2.22";
    let (runtime, dials) = probe_outbound(false).await;

    probe(&runtime, IP, Duration::ZERO).arm();

    assert!(!IP_FAIL.active(IP));
    assert!(!IP_PROBES.lock().unwrap().contains(IP));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(dials.load(Ordering::SeqCst), 0);
}

// ─── Pool spares under `--cf-balance` ────────────────────────────────────────

#[test]
fn a_balanced_cf_proxy_spare_is_dialled_at_the_kws_record() {
    // #161: with `--cf-balance` the spare's domain comes from the rotation,
    // which holds bare zones.  The pool dials it as-is, so every balanced
    // spare went to the zone apex — no record there, a 530 from Cloudflare,
    // and half of the `/apiws` requests in the reporter's analytics failing.
    let config = ladder_config(&[
        "--cf-domain",
        "a.example",
        "--cf-domain",
        "b.example",
        "--cf-balance",
    ]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, 203);
    let counter = AtomicUsize::new(0);

    let picks: Vec<_> = (0..2)
        .map(|_| {
            route
                .cf_target(
                    CfTier::Proxy,
                    "",
                    "kws203.a.example",
                    &config.cf_domains,
                    &counter,
                )
                .domain
        })
        .collect();
    assert_eq!(picks, ["kws203.a.example", "kws203.b.example"]);

    // A Worker is dialled at its own name; there is no record to expand.
    let workers = vec!["w.example".to_string()];
    let worker = route.cf_target(
        CfTier::Worker,
        "149.154.167.51",
        "w.example",
        &workers,
        &counter,
    );
    assert_eq!(worker.domain, "w.example");
}

#[test]
fn an_unbalanced_cf_proxy_spare_keeps_the_record_that_answered() {
    let config = ladder_config(&["--cf-domain", "a.example", "--cf-domain", "b.example"]);
    let runtime = Arc::new(Runtime::new(OutboundConnector::direct()));
    let pool = Arc::new(WsPool::with_runtime(
        0,
        Duration::from_secs(55),
        Arc::clone(&runtime),
    ));
    let route = ladder_route(&config, &runtime, &pool, 2);

    let target = route.cf_target(
        CfTier::Proxy,
        "",
        "kws2.b.example",
        &config.cf_domains,
        &AtomicUsize::new(0),
    );
    assert_eq!(target.domain, "kws2.b.example");
}
