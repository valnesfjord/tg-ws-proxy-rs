use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Barrier;

async fn lane<F, Fut>(handler: F) -> (Arc<Lane>, JoinHandle<()>)
where
    F: Fn(Request<h2::RecvStream>, h2::server::SendResponse<Bytes>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (client, server) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        let mut conn = h2::server::handshake(server).await.unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        while let Some(request) = conn.accept().await {
            let (request, response) = request.unwrap();
            tasks.spawn(handler(request, response));
        }
    });
    let (sender, connection) = h2::client::handshake(client).await.unwrap();
    let lane = Arc::new(Lane {
        host: "kws2.test".into(),
        sender,
        driver: tokio::spawn(async move {
            let _ = connection.await;
        }),
        requests: Arc::new(Semaphore::new(LANE_REQUESTS)),
        bytes: Arc::new(Semaphore::new(LANE_BYTES)),
        failed_until: StdMutex::new(None),
        cooldown: Duration::from_secs(60),
    });
    (lane, server)
}

async fn post(lane: Arc<Lane>, body: Bytes) -> Result<Reply> {
    let body = lane.prepare(body)?;
    lane.post(body, Arc::new(AtomicUsize::new(0))).await
}

async fn body(mut recv: h2::RecvStream) -> Vec<u8> {
    let mut result = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.unwrap();
        result.extend_from_slice(&chunk);
        recv.flow_control().release_capacity(chunk.len()).unwrap();
    }
    result
}

async fn respond(mut response: h2::server::SendResponse<Bytes>, bytes: Vec<u8>) {
    let head = http::Response::builder()
        .header("content-length", bytes.len())
        .body(())
        .unwrap();
    let mut stream = response.send_response(head, bytes.is_empty()).unwrap();
    let mut bytes = Bytes::from(bytes);
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len().min(16384));
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        let take = bytes.len().min(capacity).min(16384);
        if take == 0 {
            continue;
        }
        let chunk = bytes.split_to(take);
        stream.send_data(chunk, bytes.is_empty()).unwrap();
    }
}

#[tokio::test]
async fn parallel_requests_share_a_lane_and_obey_flow_control() {
    let barrier = Arc::new(Barrier::new(2));
    let (lane, server) = lane(move |req, resp| {
        let barrier = barrier.clone();
        async move {
            assert_eq!(req.method(), Method::POST);
            assert_eq!(req.uri().path(), "/api");
            assert_eq!(req.uri().host(), Some("kws2.test"));
            assert_eq!(req.headers()["content-type"], "application/octet-stream");
            let data = body(req.into_body()).await;
            barrier.wait().await;
            respond(resp, data).await;
        }
    })
    .await;
    let a = vec![11; 1024 * 1024 + 4];
    let b = vec![22; 128 * 1024];
    let (ra, rb) = timeout(Duration::from_secs(5), async {
        tokio::join!(
            post(lane.clone(), Bytes::from(a.clone())),
            post(lane.clone(), Bytes::from(b.clone()))
        )
    })
    .await
    .unwrap();
    assert_eq!(ra.unwrap().bytes, a);
    assert_eq!(rb.unwrap().bytes, b);
    assert_eq!(lane.bytes.available_permits(), LANE_BYTES);
    assert_eq!(lane.requests.available_permits(), LANE_REQUESTS);
    server.abort();
}

#[tokio::test]
async fn rejects_bad_http_responses_and_cools_the_lane() {
    for (status, length, data) in [
        (403, 0, vec![]),
        (200, MAX_PACKET + 1, vec![]),
        (200, 3, vec![1; 3]),
    ] {
        let (lane, server) = lane(move |req, mut resp| {
            let data = data.clone();
            async move {
                body(req.into_body()).await;
                let head = http::Response::builder()
                    .status(status)
                    .header("content-length", length)
                    .body(())
                    .unwrap();
                let mut stream = resp.send_response(head, data.is_empty()).unwrap();
                if !data.is_empty() {
                    stream.send_data(Bytes::from(data), true).unwrap();
                }
            }
        })
        .await;
        assert!(
            post(lane.clone(), Bytes::from_static(&[1; 24]))
                .await
                .is_err()
        );
        assert!(lane.failed_until.lock().unwrap().unwrap() > Instant::now());
        assert_eq!(lane.bytes.available_permits(), LANE_BYTES);
        assert_eq!(lane.requests.available_permits(), LANE_REQUESTS);
        server.abort();
    }
}

#[tokio::test]
async fn cancellation_resets_only_its_stream_and_releases_budgets() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let (lane, server) = lane(move |req, mut resp| {
        let tx = tx.clone();
        async move {
            body(req.into_body()).await;
            tx.send(None).unwrap();
            let reason = poll_fn(|cx| resp.poll_reset(cx)).await.unwrap();
            tx.send(Some(reason)).unwrap();
        }
    })
    .await;
    let task = tokio::spawn(post(lane.clone(), Bytes::from_static(&[1; 24])));
    assert_eq!(rx.recv().await.unwrap(), None);
    task.abort();
    let _ = task.await;
    assert_eq!(
        timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        Some(h2::Reason::CANCEL)
    );
    assert_eq!(lane.bytes.available_permits(), LANE_BYTES);
    assert_eq!(lane.requests.available_permits(), LANE_REQUESTS);
    assert!(lane.failed_until.lock().unwrap().is_none());
    server.abort();
}

#[test]
fn padded_envelopes_and_reply_framing() {
    for padding in 0..=15 {
        let mut encrypted = vec![1; 40 + padding];
        strip_padding(&mut encrypted, ProtoTag::PaddedIntermediate).unwrap();
        assert_eq!(encrypted.len(), 40);
        let mut plain = vec![0; 28 + padding];
        plain[16..20].copy_from_slice(&8u32.to_le_bytes());
        strip_padding(&mut plain, ProtoTag::PaddedIntermediate).unwrap();
        assert_eq!(plain.len(), 28);
    }
    let mut bad = vec![0; 32];
    bad[16..20].copy_from_slice(&100u32.to_le_bytes());
    assert!(strip_padding(&mut bad, ProtoTag::PaddedIntermediate).is_err());
    assert_eq!(reply_header(4, ProtoTag::Abridged), [1]);
    assert_eq!(reply_header(508, ProtoTag::Abridged), [0x7f, 0x7f, 0, 0]);
    assert_eq!(
        reply_header(1024 * 1024, ProtoTag::Abridged),
        [0x7f, 0, 0, 4]
    );
    assert_eq!(
        reply_header(40, ProtoTag::PaddedIntermediate),
        [40, 0, 0, 0]
    );
}

async fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    (client, server)
}

#[tokio::test]
async fn bridge_preserves_ciphers_and_faketls_across_fragmented_packets() {
    use crate::crypto::{build_raw_ciphers, generate_relay_init};
    use crate::faketls::{read_tls_appdata, write_tls_appdata};
    use crate::inbound::PendingData;
    for proto in [
        ProtoTag::Abridged,
        ProtoTag::Intermediate,
        ProtoTag::PaddedIntermediate,
    ] {
        for faketls in [false, true] {
            let (lane, server) = lane(|req, resp| async move {
                let data = body(req.into_body()).await;
                assert_eq!(data, vec![7; 40]);
                respond(resp, vec![8; 128 * 1024]).await;
            })
            .await;
            let (mut client, remote) = socket_pair().await;
            let init = generate_relay_init(proto, -2);
            let (mut client_enc, mut client_dec) = build_raw_ciphers(&init);
            let (proxy_dec, proxy_enc) = build_raw_ciphers(&init);
            let (reader, writer) = remote.into_split();
            let reader = if faketls {
                ClientReader::FakeTls {
                    reader,
                    pending: PendingData::default(),
                }
            } else {
                ClientReader::Plain(reader)
            };
            let writer = if faketls {
                ClientWriter::FakeTls(writer)
            } else {
                ClientWriter::Plain(writer)
            };
            let task = tokio::spawn(bridge(
                reader,
                writer,
                lane,
                proto,
                Some(proxy_dec),
                Some(proxy_enc),
            ));
            let length = if proto == ProtoTag::PaddedIntermediate {
                45
            } else {
                40
            };
            let mut packet = reply_header(length, proto);
            // A quick-ack request must be stripped with the transport header.
            if proto == ProtoTag::Abridged {
                packet[0] |= 0x80;
            } else {
                packet[3] |= 0x80;
            }
            packet.extend_from_slice(&[7; 40]);
            if proto == ProtoTag::PaddedIntermediate {
                packet.extend_from_slice(&[99; 5]);
            }
            client_enc.apply_keystream(&mut packet);
            for part in packet.chunks(3) {
                if faketls {
                    write_tls_appdata(&mut client, part).await.unwrap();
                } else {
                    client.write_all(part).await.unwrap();
                }
            }
            let mut expected = reply_header(128 * 1024, proto);
            expected.extend_from_slice(&vec![8; 128 * 1024]);
            let mut actual = Vec::new();
            timeout(Duration::from_secs(5), async {
                let mut buf = vec![0; CLIENT_READ_BUF_SIZE];
                while actual.len() < expected.len() {
                    let n = if faketls {
                        read_tls_appdata(&mut client, &mut buf).await.unwrap()
                    } else {
                        client.read(&mut buf).await.unwrap()
                    };
                    assert!(n > 0);
                    actual.extend_from_slice(&buf[..n]);
                }
            })
            .await
            .unwrap();
            client_dec.apply_keystream(&mut actual);
            assert_eq!(actual, expected);
            drop(client);
            timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            server.abort();
        }
    }
}

#[tokio::test]
async fn idle_http_channel_reposts_encrypted_packet_for_delayed_reply() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let count = Arc::new(AtomicUsize::new(0));
    let requests = count.clone();
    let (lane, server) = lane(move |req, resp| {
        let requests = requests.clone();
        async move {
            assert_eq!(body(req.into_body()).await, vec![7; 40]);
            let index = requests.fetch_add(1, Ordering::SeqCst);
            respond(resp, if index == 0 { vec![] } else { vec![9; 40] }).await;
        }
    })
    .await;
    let (mut client, remote) = socket_pair().await;
    let (reader, writer) = remote.into_split();
    let bridge = tokio::spawn(bridge(
        ClientReader::Plain(reader),
        ClientWriter::Plain(writer),
        lane,
        ProtoTag::Intermediate,
        None,
        None,
    ));
    client.write_all(&[40, 0, 0, 0]).await.unwrap();
    client.write_all(&[7; 40]).await.unwrap();
    let mut result = [0; 44];
    timeout(Duration::from_secs(4), client.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&result[4..], &[9; 40]);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    bridge.abort();
    server.abort();
}

#[tokio::test]
async fn preflight_accepts_telegram_head_errors_but_rejects_blocking_responses() {
    for (status, works) in [
        (200, true),
        (400, true),
        (405, true),
        (501, true),
        (302, false),
        (403, false),
        (429, false),
        (502, false),
    ] {
        let (lane, server) = lane(move |request, mut response| async move {
            assert_eq!(request.method(), Method::HEAD);
            response
                .send_response(
                    http::Response::builder().status(status).body(()).unwrap(),
                    true,
                )
                .unwrap();
        })
        .await;
        assert_eq!(lane.preflight().await.is_ok(), works, "status {status}");
        server.abort();
    }
}

#[tokio::test]
async fn cached_lane_is_reused_and_failed_lane_obeys_domain_cooldown() {
    let (lane, server) = lane(|request, mut response| async move {
        body(request.into_body()).await;
        response
            .send_response(
                http::Response::builder().status(503).body(()).unwrap(),
                true,
            )
            .unwrap();
    })
    .await;
    let runtime = Runtime::new(crate::outbound::OutboundConnector::direct());
    runtime.h2.lanes.lock().await.insert(
        (lane.host.clone(), false),
        Arc::new(Mutex::new(Slot {
            lane: Some(lane.clone()),
            failed_until: None,
        })),
    );
    let reused = runtime
        .h2
        .open(&lane.host, &runtime, false, Duration::from_secs(1))
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&reused, &lane));
    assert!(
        post(lane.clone(), Bytes::from_static(&[1; 24]))
            .await
            .is_err()
    );
    assert!(
        matches!(runtime.h2.open(&lane.host, &runtime, false, Duration::from_secs(1)).await,
        Err(error) if error.contains("cooldown"))
    );
    server.abort();
}

#[tokio::test]
async fn invalid_native_lengths_are_rejected_before_reading_a_body() {
    for (proto, header) in [
        (
            ProtoTag::Intermediate,
            (MAX_PACKET as u32 + 4).to_le_bytes().to_vec(),
        ),
        (
            ProtoTag::PaddedIntermediate,
            (MAX_PACKET as u32 + 16).to_le_bytes().to_vec(),
        ),
        (ProtoTag::Abridged, vec![0xff, 0xff, 0xff, 0xff]),
        (ProtoTag::Abridged, vec![0]),
        (ProtoTag::Intermediate, vec![20, 0, 0, 0]),
    ] {
        let (mut client, server) = socket_pair().await;
        client.write_all(&header).await.unwrap();
        let (reader, _) = server.into_split();
        let mut reader = PacketReader {
            reader: ClientReader::Plain(reader),
            cipher: None,
            buffer: vec![0; CLIENT_READ_BUF_SIZE],
            offset: 0,
            filled: 0,
        };
        assert!(
            timeout(Duration::from_secs(1), reader.packet(proto))
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn queued_uploads_reserve_bytes_before_acquiring_a_stream() {
    let (lane, server) = lane(|_, _| async { panic!("no request should be sent") }).await;
    let held = lane
        .bytes
        .clone()
        .acquire_many_owned((LANE_BYTES - 48) as u32)
        .await
        .unwrap();
    let first = lane.prepare(Bytes::from_static(&[1; 24])).unwrap();
    let second = lane.prepare(Bytes::from_static(&[2; 24])).unwrap();
    assert!(lane.prepare(Bytes::from_static(&[3; 24])).is_err());
    drop(first);
    assert!(lane.prepare(Bytes::from_static(&[3; 24])).is_ok());
    drop(second);
    drop(held);
    assert_eq!(lane.bytes.available_permits(), LANE_BYTES);
    server.abort();
}
