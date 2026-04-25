use tg_ws_proxy_rs::proxy::split_mtproto_init_and_pending;

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
}
