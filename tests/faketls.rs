use tg_ws_proxy_rs::faketls::{
    TLS_DIGEST_LEN, TLS_MAX_RECORD_PAYLOAD, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE, build_faketls_client_hello,
    build_faketls_server_hello, drain_faketls_server_hello, parse_faketls_client_hello,
    read_tls_appdata, sign_faketls_client_hello, write_tls_appdata,
};

const TLS_SERVER_RANDOM_OFFSET_IN_PACKET: usize = 11;

#[test]
fn tls_parser_accepts_the_padded_outbound_client_hello() {
    let hostname = "example.net";
    let mut hello = build_faketls_client_hello(hostname);
    sign_faketls_client_hello(&mut hello, &[0x42; 16]);
    assert_eq!(hello.len(), 517);

    let mut acceptor = rustls::server::Acceptor::default();
    acceptor.read_tls(&mut hello.as_slice()).unwrap();
    let accepted = acceptor
        .accept()
        .map_err(|(error, _)| error)
        .unwrap()
        .unwrap();
    let parsed = accepted.client_hello();
    assert_eq!(parsed.server_name(), Some(hostname));
    assert_eq!(
        parsed.alpn().unwrap().collect::<Vec<_>>(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
}

#[test]
fn signed_client_hello_parses_hostname_and_auth() {
    // The inbound listener accepts only a ClientHello signed with the shared
    // secret and keeps the SNI hostname for domain validation.
    let secret = [0x2a; 16];
    let hostname = "www.yandex.ru";
    let mut hello = build_faketls_client_hello(hostname);

    sign_faketls_client_hello(&mut hello, &secret);

    let parsed = parse_faketls_client_hello(&hello, &secret).expect("valid FakeTLS hello");
    assert_eq!(parsed.hostname.as_deref(), Some(hostname));
    assert_eq!(parsed.session_id.len(), 32);
    assert_ne!(parsed.random, [0u8; TLS_DIGEST_LEN]);
}

#[test]
fn signed_client_hello_rejects_wrong_secret() {
    // A real-looking ClientHello with the wrong HMAC must be rejected before
    // any MTProto bytes are accepted.
    let good_secret = [0x11; 16];
    let bad_secret = [0x22; 16];
    let mut hello = build_faketls_client_hello("www.yandex.ru");

    sign_faketls_client_hello(&mut hello, &good_secret);

    assert!(parse_faketls_client_hello(&hello, &bad_secret).is_none());
}

#[test]
fn server_hello_contains_expected_fake_tls_records() {
    // Telegram clients expect the fake server response to look like a normal
    // TLS handshake before application data starts flowing.
    let secret = [0x33; 16];
    let mut client_hello = build_faketls_client_hello("www.yandex.ru");
    sign_faketls_client_hello(&mut client_hello, &secret);
    let parsed = parse_faketls_client_hello(&client_hello, &secret).unwrap();

    let server_hello = build_faketls_server_hello(&secret, &parsed);

    assert_eq!(server_hello[0], TLS_RECORD_HANDSHAKE);
    assert_eq!(
        server_hello[TLS_SERVER_RANDOM_OFFSET_IN_PACKET
            ..TLS_SERVER_RANDOM_OFFSET_IN_PACKET + TLS_DIGEST_LEN]
            .len(),
        TLS_DIGEST_LEN
    );

    let first_len = u16::from_be_bytes([server_hello[3], server_hello[4]]) as usize;
    let second = 5 + first_len;
    assert_eq!(server_hello[second], TLS_RECORD_CHANGE_CIPHER_SPEC);

    let second_len =
        u16::from_be_bytes([server_hello[second + 3], server_hello[second + 4]]) as usize;
    let third = second + 5 + second_len;
    assert_eq!(server_hello[third], TLS_RECORD_APPLICATION_DATA);
}

#[test]
fn client_hello_hostname_is_carried_in_the_sni_extension() {
    // The SNI is what a DPI box sees, so it must literally be the configured
    // camouflage domain — and survive a round trip through the parser.
    let secret = [0x44; 16];
    for hostname in ["www.yandex.ru", "a.example", "sub.domain.example.com"] {
        let mut hello = build_faketls_client_hello(hostname);
        sign_faketls_client_hello(&mut hello, &secret);

        assert!(
            hello
                .windows(hostname.len())
                .any(|w| w == hostname.as_bytes()),
            "hostname missing from the ClientHello wire bytes"
        );
        let parsed = parse_faketls_client_hello(&hello, &secret).expect("valid FakeTLS hello");
        assert_eq!(parsed.hostname.as_deref(), Some(hostname));
    }
}

#[test]
fn unsigned_client_hello_is_rejected() {
    // An unsigned hello still has a zeroed random field; it must not
    // accidentally authenticate.
    let hello = build_faketls_client_hello("www.yandex.ru");

    assert!(parse_faketls_client_hello(&hello, &[0x55; 16]).is_none());
}

#[test]
fn truncated_or_garbage_records_are_rejected() {
    let secret = [0x66; 16];
    let mut hello = build_faketls_client_hello("www.yandex.ru");
    sign_faketls_client_hello(&mut hello, &secret);

    assert!(parse_faketls_client_hello(&[], &secret).is_none());
    assert!(parse_faketls_client_hello(&hello[..hello.len() / 2], &secret).is_none());

    // Flipping a byte inside the record invalidates the HMAC.
    let mut tampered = hello.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    assert!(parse_faketls_client_hello(&tampered, &secret).is_none());
}

#[test]
fn server_hello_echoes_the_clients_session_id() {
    // Real TLS 1.3 servers echo the session id; a mismatch is an easy
    // fingerprint for a censor comparing our handshake against a real one.
    let secret = [0x77; 16];
    let mut client_hello = build_faketls_client_hello("www.yandex.ru");
    sign_faketls_client_hello(&mut client_hello, &secret);
    let parsed = parse_faketls_client_hello(&client_hello, &secret).unwrap();

    let server_hello = build_faketls_server_hello(&secret, &parsed);

    assert!(
        server_hello
            .windows(parsed.session_id.len())
            .any(|w| w == parsed.session_id),
        "ServerHello does not echo the client's session id"
    );
}

#[test]
fn server_hello_never_selects_a_grease_cipher_suite() {
    // Telegram clients put a GREASE value first; a ServerHello selecting it is
    // something no real server sends (RFC 8701) and a passive DPI fingerprint.
    // Record + handshake headers, version, random, session id length + 32 bytes.
    const CLIENT_SUITES_OFFSET: usize = 5 + 4 + 2 + 32 + 1 + 32 + 2;
    const SERVER_SUITE_OFFSET: usize = 5 + 4 + 2 + 32 + 1 + 32;
    let secret = [0x88; 16];
    let cases: [(&[[u8; 2]], [u8; 2]); 2] = [
        // GREASE replaces 0x1301, so the client's first real TLS 1.3 suite is 0x1302.
        (&[[0x7a, 0x7a]], [0x13, 0x02]),
        // No TLS 1.3 suite offered at all: fall back to TLS_AES_128_GCM_SHA256.
        (&[[0x0a, 0x0a], [0xc0, 0x2b], [0xc0, 0x2f]], [0x13, 0x01]),
    ];

    for (leading_suites, expected) in cases {
        let mut client_hello = build_faketls_client_hello("www.yandex.ru");
        for (i, suite) in leading_suites.iter().enumerate() {
            let at = CLIENT_SUITES_OFFSET + 2 * i;
            client_hello[at..at + 2].copy_from_slice(suite);
        }
        sign_faketls_client_hello(&mut client_hello, &secret);
        let parsed = parse_faketls_client_hello(&client_hello, &secret).unwrap();

        let server_hello = build_faketls_server_hello(&secret, &parsed);

        assert_eq!(
            server_hello[SERVER_SUITE_OFFSET..SERVER_SUITE_OFFSET + 2],
            expected,
            "client suites starting with {leading_suites:02x?}"
        );
    }
}

#[tokio::test]
async fn application_data_records_round_trip() {
    // Everything after the handshake is wrapped in TLS Application Data
    // records; payloads larger than one record must be split and rejoined.
    for payload_len in [
        1usize,
        100,
        TLS_MAX_RECORD_PAYLOAD,
        TLS_MAX_RECORD_PAYLOAD + 1,
    ] {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();

        let mut wire = Vec::new();
        write_tls_appdata(&mut wire, &payload).await.unwrap();

        let mut reader = wire.as_slice();
        let mut received = Vec::new();
        let mut buf = vec![0u8; TLS_MAX_RECORD_PAYLOAD + 256];
        while received.len() < payload_len {
            let n = read_tls_appdata(&mut reader, &mut buf).await.unwrap();
            assert!(n > 0, "unexpected EOF at {} bytes", received.len());
            received.extend_from_slice(&buf[..n]);
        }

        assert_eq!(
            received, payload,
            "round trip failed for {payload_len} bytes"
        );
    }
}

#[tokio::test]
async fn reading_application_data_reports_a_clean_eof() {
    let mut reader: &[u8] = &[];
    let mut buf = [0u8; 64];

    assert_eq!(read_tls_appdata(&mut reader, &mut buf).await.unwrap(), 0);
}

#[tokio::test]
async fn server_handshake_drain_consumes_exactly_the_fake_handshake() {
    // The upstream FakeTLS probe has to stop draining at the end of the fake
    // handshake, leaving the first real Application Data byte for the caller.
    let secret = [0x88; 16];
    let mut client_hello = build_faketls_client_hello("www.yandex.ru");
    sign_faketls_client_hello(&mut client_hello, &secret);
    let parsed = parse_faketls_client_hello(&client_hello, &secret).unwrap();

    let mut stream = build_faketls_server_hello(&secret, &parsed);
    write_tls_appdata(&mut stream, b"payload after the handshake")
        .await
        .unwrap();

    let mut reader = stream.as_slice();
    assert!(drain_faketls_server_hello(&mut reader).await);

    let mut buf = vec![0u8; 256];
    let n = read_tls_appdata(&mut reader, &mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"payload after the handshake");
}

#[tokio::test]
async fn server_handshake_drain_fails_on_a_truncated_stream() {
    let mut reader: &[u8] = &[TLS_RECORD_HANDSHAKE, 0x03, 0x03, 0x00];

    assert!(!drain_faketls_server_hello(&mut reader).await);
}
