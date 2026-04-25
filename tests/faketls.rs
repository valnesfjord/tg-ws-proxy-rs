use tg_ws_proxy_rs::faketls::{
    TLS_DIGEST_LEN, TLS_RECORD_APPLICATION_DATA, TLS_RECORD_CHANGE_CIPHER_SPEC,
    TLS_RECORD_HANDSHAKE, build_faketls_client_hello, build_faketls_server_hello,
    parse_faketls_client_hello, sign_faketls_client_hello,
};

const TLS_SERVER_RANDOM_OFFSET_IN_PACKET: usize = 11;

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
        server_hello
            [TLS_SERVER_RANDOM_OFFSET_IN_PACKET..TLS_SERVER_RANDOM_OFFSET_IN_PACKET + TLS_DIGEST_LEN]
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
