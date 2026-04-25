use cipher::StreamCipher;
use tg_ws_proxy_rs::crypto::{
    ProtoTag, build_connection_ciphers, generate_client_handshake, generate_relay_init,
    parse_handshake,
};

#[test]
fn generated_client_handshake_roundtrips_for_plain_proxy_modes() {
    // Plain MTProto proxy links rely on the generated 64-byte init packet
    // being readable by the existing dd/padded handshake parser.
    let secret = test_secret();

    for proto in [
        ProtoTag::Abridged,
        ProtoTag::Intermediate,
        ProtoTag::PaddedIntermediate,
    ] {
        let (handshake, _, _) = generate_client_handshake(&secret, 2, proto);
        let parsed = parse_handshake(&handshake, &secret).expect("generated handshake parses");

        assert_eq!(parsed.dc_id, 2);
        assert!(!parsed.is_media);
        assert_eq!(parsed.proto, proto);
    }
}

#[test]
fn generated_client_handshake_preserves_media_dc_sign() {
    // Negative DC indexes are Telegram's media-DC marker; keep that behavior
    // independent from FakeTLS listener changes.
    let secret = test_secret();
    let (handshake, _, _) = generate_client_handshake(&secret, -4, ProtoTag::PaddedIntermediate);
    let parsed = parse_handshake(&handshake, &secret).expect("generated media handshake parses");

    assert_eq!(parsed.dc_id, 4);
    assert!(parsed.is_media);
    assert_eq!(parsed.proto, ProtoTag::PaddedIntermediate);
}

#[test]
fn generated_client_handshake_rejects_wrong_secret() {
    // A valid-looking init packet must not parse when the shared proxy secret
    // is different.
    let secret = test_secret();
    let wrong_secret = hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let (handshake, _, _) = generate_client_handshake(&secret, 2, ProtoTag::PaddedIntermediate);

    assert!(parse_handshake(&handshake, &wrong_secret).is_none());
}

#[test]
fn connection_ciphers_match_client_handshake_ciphers() {
    // After the handshake bytes, both sides must derive matching stream
    // ciphers for client -> proxy and proxy -> client traffic.
    let secret = test_secret();
    let (handshake, mut client_enc, mut client_dec) =
        generate_client_handshake(&secret, 2, ProtoTag::PaddedIntermediate);
    let parsed = parse_handshake(&handshake, &secret).expect("generated handshake parses");
    let relay_init = generate_relay_init(parsed.proto, parsed.dc_id as i16);
    let mut ciphers = build_connection_ciphers(&parsed.prekey_and_iv, &secret, &relay_init);

    let original_to_proxy = b"client payload after handshake".to_vec();
    let mut encrypted_to_proxy = original_to_proxy.clone();
    client_enc.apply_keystream(&mut encrypted_to_proxy);
    ciphers.clt_dec.apply_keystream(&mut encrypted_to_proxy);
    assert_eq!(encrypted_to_proxy, original_to_proxy);

    let original_to_client = b"proxy response after handshake".to_vec();
    let mut encrypted_to_client = original_to_client.clone();
    ciphers.clt_enc.apply_keystream(&mut encrypted_to_client);
    client_dec.apply_keystream(&mut encrypted_to_client);
    assert_eq!(encrypted_to_client, original_to_client);
}

fn test_secret() -> Vec<u8> {
    hex::decode("2a519e5be6c3219c69879e5fa2a0eab8").unwrap()
}
