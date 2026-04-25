use cipher::StreamCipher;
use tg_ws_proxy_rs::{
    crypto::{
        ProtoTag, build_connection_ciphers, generate_client_handshake, generate_relay_init,
        parse_handshake,
    },
    splitter::MsgSplitter,
};

#[test]
fn splitter_buffers_partial_intermediate_packet_until_complete() {
    // The WS backend expects complete MTProto packets, so a partial encrypted
    // TCP chunk must stay buffered until the length-prefixed packet is whole.
    let payload = b"0123456789abcdef";
    let mut plain_packet = Vec::new();
    plain_packet.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    plain_packet.extend_from_slice(payload);

    let (relay_init, encrypted) =
        encrypted_relay_packet(ProtoTag::PaddedIntermediate, &plain_packet);
    let mut splitter = MsgSplitter::new(&relay_init, ProtoTag::PaddedIntermediate);

    assert!(splitter.split(&encrypted[..5]).is_empty());
    assert_eq!(splitter.split(&encrypted[5..]), vec![encrypted]);
    assert!(splitter.flush().is_empty());
}

#[test]
fn splitter_returns_each_complete_abridged_packet_separately() {
    // A single TCP read can contain multiple MTProto packets; the splitter
    // must keep returning one encrypted packet per WebSocket message.
    let first_payload = b"abcdefgh";
    let second_payload = b"ijklmnop";
    let mut plain_stream = Vec::new();
    plain_stream.push((first_payload.len() / 4) as u8);
    plain_stream.extend_from_slice(first_payload);
    plain_stream.push((second_payload.len() / 4) as u8);
    plain_stream.extend_from_slice(second_payload);

    let (relay_init, encrypted_stream) = encrypted_relay_packet(ProtoTag::Abridged, &plain_stream);
    let mut splitter = MsgSplitter::new(&relay_init, ProtoTag::Abridged);

    let parts = splitter.split(&encrypted_stream);

    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0], encrypted_stream[..1 + first_payload.len()]);
    assert_eq!(parts[1], encrypted_stream[1 + first_payload.len()..]);
}

fn encrypted_relay_packet(proto: ProtoTag, plain_packet: &[u8]) -> ([u8; 64], Vec<u8>) {
    let secret = test_secret();
    let (handshake, _, _) = generate_client_handshake(&secret, 2, proto);
    let parsed = parse_handshake(&handshake, &secret).expect("generated handshake parses");
    let relay_init = generate_relay_init(parsed.proto, parsed.dc_id as i16);
    let mut ciphers = build_connection_ciphers(&parsed.prekey_and_iv, &secret, &relay_init);

    let mut encrypted = plain_packet.to_vec();
    ciphers.tg_enc.apply_keystream(&mut encrypted);

    (relay_init, encrypted)
}

fn test_secret() -> Vec<u8> {
    hex::decode("2a519e5be6c3219c69879e5fa2a0eab8").unwrap()
}
