//! FakeTLS (0xee-prefix) upstream proxy support.
//!
//! Upstream MTProto proxies with `0xee` secrets use a fake TLS 1.3 handshake
//! to disguise traffic as normal HTTPS.  The protocol works as follows:
//!
//! 1. **ClientHello** — a standard-looking TLS 1.2 ClientHello is sent with
//!    HMAC-SHA256 authentication in the `random` field and the SNI extension
//!    set to the hostname embedded in the secret.
//!
//! 2. **Server response** — the proxy replies with ServerHello + ChangeCipherSpec
//!    + an Application Data record (fake certificate).  All records are drained.
//!
//! 3. **Data phase** — all data is wrapped in TLS Application Data records
//!    (`\x17\x03\x03` + 2-byte big-endian length + payload).  Inside these
//!    records, the standard MTProto obfuscation (AES-CTR) is used.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

// ─── TLS protocol constants ─────────────────────────────────────────────────

/// TLS record type: Handshake.
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS record type: Change Cipher Spec.
pub const TLS_RECORD_CHANGE_CIPHER_SPEC: u8 = 0x14;
/// TLS record type: Application Data.
pub const TLS_RECORD_APPLICATION_DATA: u8 = 0x17;
/// TLS record type: Alert.
pub const TLS_RECORD_ALERT: u8 = 0x15;

/// TLS 1.2 version bytes (used in ClientHello body and Application Data records).
pub const TLS_VERSION_12: [u8; 2] = [0x03, 0x03];
/// TLS 1.0 version bytes (used in the ClientHello record layer for compatibility).
const TLS_RECORD_VERSION: [u8; 2] = [0x03, 0x01];

/// Maximum TLS record payload (RFC 8446 §5.1: 2^14 bytes).
pub const TLS_MAX_RECORD_PAYLOAD: usize = 16_384;
/// Maximum Application Data payload per record.
const TLS_MAX_APPDATA_WRITE: usize = TLS_MAX_RECORD_PAYLOAD;
/// Maximum number of TLS records to read during the server's fake handshake.
const TLS_MAX_HANDSHAKE_RECORDS: usize = 20;

/// Position of the `random` field in the full TLS record (after record header
/// + handshake header + ClientHello version = 5 + 4 + 2 = 11 bytes).
const TLS_DIGEST_POS: usize = 11;
/// Length of the `random` field (= HMAC-SHA256 digest length).
const TLS_DIGEST_LEN: usize = 32;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
const TLS_CLIENT_RANDOM_OFFSET_IN_HANDSHAKE: usize = 6;
const TLS_SERVER_RANDOM_OFFSET_IN_PACKET: usize = 11;
const TLS_CHANGE_CIPHER_SPEC_VALUE: u8 = 0x01;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct FakeTlsClientHello {
    pub random: [u8; TLS_DIGEST_LEN],
    pub session_id: Vec<u8>,
    pub cipher_suite: [u8; 2],
    pub hostname: Option<String>,
}

// ─── ClientHello construction ───────────────────────────────────────────────

/// Build a TLS 1.2-style ClientHello with the `random` field zeroed.
///
/// The returned record must be signed with [`sign_faketls_client_hello`]
/// before sending — that function fills the `random` field with the
/// HMAC-SHA256 authentication digest.
///
/// After signing, the `random` field carries:
/// - bytes [0..28]: first 28 bytes of `HMAC-SHA256(secret, record_with_random_zeroed)`
/// - bytes [28..32]: `XOR(hmac[28..32], timestamp_le)`
///
/// The `session_id` is 32 random bytes (the upstream proxy ignores it for auth).
/// The SNI extension carries the `hostname` from the decoded secret.
pub fn build_faketls_client_hello(hostname: &str) -> Vec<u8> {
    // ── Extensions ────────────────────────────────────────────────────────
    let mut exts: Vec<u8> = Vec::new();

    // server_name (SNI)
    let host_b = hostname.as_bytes();
    let host_len = host_b.len() as u16;
    let sni_entry_len = 1u16 + 2 + host_len; // type(1) + name_len(2) + name
    let sni_list_len = sni_entry_len;
    let sni_data_len = 2u16 + sni_list_len; // list_length(2) + entry
    exts.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type: server_name
    exts.extend_from_slice(&sni_data_len.to_be_bytes());
    exts.extend_from_slice(&sni_list_len.to_be_bytes());
    exts.push(0x00); // name_type: host_name
    exts.extend_from_slice(&host_len.to_be_bytes());
    exts.extend_from_slice(host_b);

    // extended_master_secret (empty)
    exts.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);

    // renegotiation_info (empty)
    exts.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);

    // supported_groups: x25519, secp256r1, secp384r1, secp521r1
    #[rustfmt::skip]
    exts.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08,
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19,
    ]);

    // ec_point_formats: uncompressed only
    exts.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

    // session_ticket (empty = requesting a ticket)
    exts.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);

    // signature_algorithms
    #[rustfmt::skip]
    exts.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x14, 0x00, 0x12,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
        0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
        0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
    ]);

    // ── Cipher suites ─────────────────────────────────────────────────────
    #[rustfmt::skip]
    let cipher_suites: &[u8] = &[
        0x13, 0x01,  // TLS_AES_128_GCM_SHA256
        0x13, 0x02,  // TLS_AES_256_GCM_SHA384
        0x13, 0x03,  // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b,  // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2f,  // ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2c,  // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x30,  // ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xcc, 0xa9,  // ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        0xcc, 0xa8,  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        0xc0, 0x13,  // ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xc0, 0x14,  // ECDHE_RSA_WITH_AES_256_CBC_SHA
        0x00, 0x9c,  // RSA_WITH_AES_128_GCM_SHA256
        0x00, 0x9d,  // RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x2f,  // RSA_WITH_AES_128_CBC_SHA
        0x00, 0x35,  // RSA_WITH_AES_256_CBC_SHA
        0x00, 0x0a,  // RSA_WITH_3DES_EDE_CBC_SHA
    ];

    // ── Random session_id (32 bytes) ──────────────────────────────────────
    let mut session_id = [0u8; 32];
    rand::rng().fill_bytes(&mut session_id);

    // ── ClientHello body ──────────────────────────────────────────────────
    let mut hello: Vec<u8> = Vec::new();
    hello.extend_from_slice(&TLS_VERSION_12); // version: TLS 1.2
    hello.extend_from_slice(&[0u8; 32]); // random: zeroed (will be filled with HMAC)
    hello.push(0x20); // session_id length = 32
    hello.extend_from_slice(&session_id);
    hello.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello.extend_from_slice(cipher_suites);
    hello.push(0x01); // compression_methods length: 1
    hello.push(0x00); // null compression
    hello.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hello.extend_from_slice(&exts);

    // ── Handshake message ─────────────────────────────────────────────────
    let hello_len = hello.len() as u32;
    let mut handshake: Vec<u8> = Vec::with_capacity(4 + hello.len());
    handshake.push(0x01); // HandshakeType: ClientHello
    handshake.push((hello_len >> 16) as u8);
    handshake.push((hello_len >> 8) as u8);
    handshake.push(hello_len as u8);
    handshake.extend_from_slice(&hello);

    // ── TLS record ────────────────────────────────────────────────────────
    let mut record: Vec<u8> = Vec::with_capacity(5 + handshake.len());
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&TLS_RECORD_VERSION);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Fill the `random` field in a pre-built ClientHello record with the
/// HMAC-SHA256 authentication digest.
///
/// The digest is computed as:
/// `HMAC-SHA256(secret, record_with_random_zeroed)`
///
/// Then:
/// - `random[0..28] = hmac[0..28]`
/// - `random[28..32] = hmac[28..32] XOR timestamp_le`
pub fn sign_faketls_client_hello(record: &mut [u8], secret: &[u8]) {
    // Zero the `random` field (it should already be zero from construction,
    // but do it explicitly for safety).
    record[TLS_DIGEST_POS..TLS_DIGEST_POS + TLS_DIGEST_LEN].fill(0);

    // Compute HMAC-SHA256(secret, record_with_zeroed_random).
    let mut mac =
        HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(record);
    let computed = mac.finalize().into_bytes();

    // First 28 bytes of the HMAC go directly into the `random` field.
    record[TLS_DIGEST_POS..TLS_DIGEST_POS + 28].copy_from_slice(&computed[..28]);

    // Last 4 bytes are XOR'd with the current Unix timestamp (little-endian).
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    let ts_bytes = timestamp.to_le_bytes();
    for i in 0..4 {
        record[TLS_DIGEST_POS + 28 + i] = computed[28 + i] ^ ts_bytes[i];
    }
}

// ─── Inbound ClientHello validation / ServerHello construction ─────────────

pub fn parse_faketls_client_hello(
    record: &[u8],
    secret: &[u8],
) -> Option<FakeTlsClientHello> {
    if record.len() < 5 + 4 + TLS_CLIENT_RANDOM_OFFSET_IN_HANDSHAKE + TLS_DIGEST_LEN {
        return None;
    }
    if record[0] != TLS_RECORD_HANDSHAKE {
        return None;
    }
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record.len() != 5 + record_len {
        return None;
    }

    let handshake = &record[5..];
    if handshake.len() < 4 || handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return None;
    }
    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() != 4 + handshake_len {
        return None;
    }

    let random_offset = 5 + TLS_CLIENT_RANDOM_OFFSET_IN_HANDSHAKE;
    let mut client_random = [0u8; TLS_DIGEST_LEN];
    client_random.copy_from_slice(&record[random_offset..random_offset + TLS_DIGEST_LEN]);

    let mut signed = record.to_vec();
    signed[random_offset..random_offset + TLS_DIGEST_LEN].fill(0);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(&signed);
    let computed = mac.finalize().into_bytes();

    let mut xored = [0u8; TLS_DIGEST_LEN];
    for i in 0..TLS_DIGEST_LEN {
        xored[i] = computed[i] ^ client_random[i];
    }
    if xored[..28].iter().any(|&b| b != 0) {
        return None;
    }

    let body = &handshake[4..];
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let session_id_len = body[34] as usize;
    let session_start = 35;
    let session_end = session_start + session_id_len;
    if body.len() < session_end + 2 {
        return None;
    }
    let session_id = body[session_start..session_end].to_vec();

    let cipher_suites_len = u16::from_be_bytes([body[session_end], body[session_end + 1]]) as usize;
    if cipher_suites_len < 2 || body.len() < session_end + 2 + cipher_suites_len + 1 {
        return None;
    }
    let cipher_suite = [body[session_end + 2], body[session_end + 3]];

    let mut p = session_end + 2 + cipher_suites_len;
    let compression_len = *body.get(p)? as usize;
    p += 1 + compression_len;
    if body.len() < p + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    if body.len() < p + extensions_len {
        return None;
    }

    let hostname = parse_sni_extension(&body[p..p + extensions_len]);

    Some(FakeTlsClientHello {
        random: client_random,
        session_id,
        cipher_suite,
        hostname,
    })
}

fn parse_sni_extension(mut extensions: &[u8]) -> Option<String> {
    while extensions.len() >= 4 {
        let ext_type = u16::from_be_bytes([extensions[0], extensions[1]]);
        let ext_len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        extensions = &extensions[4..];
        if extensions.len() < ext_len {
            return None;
        }
        let ext = &extensions[..ext_len];
        extensions = &extensions[ext_len..];

        if ext_type != 0x0000 || ext.len() < 5 {
            continue;
        }
        let list_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        if ext.len() < 2 + list_len || list_len < 3 || ext[2] != 0 {
            return None;
        }
        let host_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
        if ext.len() < 5 + host_len {
            return None;
        }
        return std::str::from_utf8(&ext[5..5 + host_len])
            .ok()
            .map(ToOwned::to_owned);
    }

    None
}

pub fn build_faketls_server_hello(secret: &[u8], hello: &FakeTlsClientHello) -> Vec<u8> {
    let mut server_body = Vec::new();
    server_body.extend_from_slice(&TLS_VERSION_12);
    server_body.extend_from_slice(&[0u8; TLS_DIGEST_LEN]);
    server_body.push(hello.session_id.len() as u8);
    server_body.extend_from_slice(&hello.session_id);
    server_body.extend_from_slice(&hello.cipher_suite);
    server_body.extend_from_slice(&[
        0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
        0x1d, 0x00, 0x20,
    ]);
    let mut rng = rand::rng();
    let mut key_share = [0u8; 32];
    rng.fill_bytes(&mut key_share);
    server_body.extend_from_slice(&key_share);

    let mut handshake = Vec::with_capacity(4 + server_body.len());
    handshake.push(TLS_HANDSHAKE_SERVER_HELLO);
    handshake.push(((server_body.len() >> 16) & 0xff) as u8);
    handshake.push(((server_body.len() >> 8) & 0xff) as u8);
    handshake.push((server_body.len() & 0xff) as u8);
    handshake.extend_from_slice(&server_body);

    let mut packet = Vec::new();
    push_tls_record(&mut packet, TLS_RECORD_HANDSHAKE, &handshake);
    push_tls_record(
        &mut packet,
        TLS_RECORD_CHANGE_CIPHER_SPEC,
        &[TLS_CHANGE_CIPHER_SPEC_VALUE],
    );

    let mut cert = vec![0u8; 1024 + (rng.next_u32() as usize % 3092)];
    rng.fill_bytes(&mut cert);
    push_tls_record(&mut packet, TLS_RECORD_APPLICATION_DATA, &cert);

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(&hello.random);
    mac.update(&packet);
    let digest = mac.finalize().into_bytes();
    packet[TLS_SERVER_RANDOM_OFFSET_IN_PACKET..TLS_SERVER_RANDOM_OFFSET_IN_PACKET + TLS_DIGEST_LEN]
        .copy_from_slice(&digest);

    packet
}

fn push_tls_record(out: &mut Vec<u8>, record_type: u8, payload: &[u8]) {
    out.push(record_type);
    out.extend_from_slice(&TLS_VERSION_12);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

pub async fn read_tls_record<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_payload_len: usize,
) -> std::io::Result<Option<(u8, [u8; 2], Vec<u8>)>> {
    let mut header = [0u8; 5];
    if reader.read_exact(&mut header).await.is_err() {
        return Ok(None);
    }
    let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if payload_len > max_payload_len {
        return Ok(None);
    }
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[0], [header[1], header[2]], payload)))
}

// ─── Server handshake draining ──────────────────────────────────────────────

/// Read and discard TLS records until the fake TLS handshake is complete.
///
/// FakeTLS proxies send:
///   Handshake (0x16) → ChangeCipherSpec (0x14) → Application Data (0x17)
///
/// We discard Handshake and ChangeCipherSpec records unconditionally and stop
/// (returning `true`) as soon as we see the first Application Data record,
/// which is the server's synthetic "finished" / fake certificate.
pub async fn drain_faketls_server_hello(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
) -> bool {
    let mut header = [0u8; 5];

    for _ in 0..TLS_MAX_HANDSHAKE_RECORDS {
        if reader.read_exact(&mut header).await.is_err() {
            return false;
        }

        let record_type = header[0];
        let version = [header[1], header[2]];
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        // Validate version — server should respond with TLS 1.2.
        if version != TLS_VERSION_12 {
            return false;
        }

        // TLS records must not exceed max plaintext + AEAD expansion overhead.
        // RFC 8446 §5.2: ciphertext record ≤ 2^14 + 256 bytes.
        if payload_len > TLS_MAX_RECORD_PAYLOAD + 256 {
            return false;
        }

        // Read and discard the record payload.
        let mut payload = vec![0u8; payload_len];
        if reader.read_exact(&mut payload).await.is_err() {
            return false;
        }

        match record_type {
            TLS_RECORD_HANDSHAKE | TLS_RECORD_CHANGE_CIPHER_SPEC => {
                // Discard and keep reading.
            }
            TLS_RECORD_APPLICATION_DATA => {
                // Fake handshake complete — data phase begins.
                return true;
            }
            TLS_RECORD_ALERT => return false,
            _ => return false,
        }
    }

    false // too many records without reaching Application Data
}

// ─── TLS Application Data record framing ─────────────────────────────────────

/// Wrap `data` in one or more TLS Application Data records.
///
/// Each record has the format: `\x17\x03\x03` + 2-byte BE length + payload.
/// Chunks larger than `TLS_MAX_APPDATA_WRITE` are split into multiple records.
pub async fn write_tls_appdata(
    writer: &mut (impl AsyncWrite + Unpin),
    data: &[u8],
) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let end = std::cmp::min(offset + TLS_MAX_APPDATA_WRITE, data.len());
        let chunk = &data[offset..end];
        let len = chunk.len();

        let hdr = [
            TLS_RECORD_APPLICATION_DATA,
            TLS_VERSION_12[0],
            TLS_VERSION_12[1],
            (len >> 8) as u8,
            len as u8,
        ];
        writer.write_all(&hdr).await?;
        writer.write_all(chunk).await?;

        offset = end;
    }
    Ok(())
}

/// Read one TLS Application Data record's payload.
///
/// Returns `Ok(n)` with the number of payload bytes read into `buf`.
/// Returns `Ok(0)` on EOF or if a non-Application-Data record is encountered
/// after the handshake phase (other than ChangeCipherSpec which is skipped).
pub async fn read_tls_appdata(
    reader: &mut (impl AsyncRead + Unpin),
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut header = [0u8; 5];

    loop {
        if reader.read_exact(&mut header).await.is_err() {
            return Ok(0);
        }

        let record_type = header[0];
        let payload_len = u16::from_be_bytes([header[3], header[4]]) as usize;

        if payload_len > buf.len() {
            // Payload too large for buffer — protocol error.
            return Ok(0);
        }

        match record_type {
            TLS_RECORD_APPLICATION_DATA => {
                if reader.read_exact(&mut buf[..payload_len]).await.is_err() {
                    return Ok(0);
                }
                return Ok(payload_len);
            }
            TLS_RECORD_CHANGE_CIPHER_SPEC => {
                // Discard CCS records (shouldn't appear in data phase but
                // handle gracefully).
                let mut discard = vec![0u8; payload_len];
                if reader.read_exact(&mut discard).await.is_err() {
                    return Ok(0);
                }
                continue;
            }
            _ => {
                // Unexpected record type — connection is broken.
                return Ok(0);
            }
        }
    }
}
