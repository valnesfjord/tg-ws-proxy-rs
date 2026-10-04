//! MTProto obfuscation layer crypto helpers.
//!
//! Telegram Desktop uses an "obfuscated" transport to disguise traffic as
//! random noise.  The scheme works as follows:
//!
//! 1. The **client** sends a 64-byte random-looking handshake.
//!    Bytes [8..40] are the "prekey" and bytes [40..56] are the IV.
//!    The actual key for decryption is  `SHA-256(prekey ∥ proxy_secret)`.
//!    After decrypting the handshake with AES-256-CTR, bytes [56..60]
//!    contain the protocol tag and bytes [60..62] the signed DC index.
//!
//! 2. The **relay** (this proxy) generates its own 64-byte init packet for
//!    the Telegram backend using raw (non-secret-hashed) AES-256-CTR keys
//!    baked into the random bytes.

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::RngCore;
use sha2::{Digest, Sha256};

// ─── AES-256-CTR alias ───────────────────────────────────────────────────────
pub type AesCtr256 = Ctr128BE<Aes256>;

// ─── MTProto constants ───────────────────────────────────────────────────────
pub const HANDSHAKE_LEN: usize = 64;
pub const SKIP_LEN: usize = 8; // random prefix bytes before the prekey
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
pub const PROTO_TAG_POS: usize = 56;
pub const DC_IDX_POS: usize = 60;

pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// Protocol integer values used by the message splitter.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProtoTag {
    Abridged,
    Intermediate,
    PaddedIntermediate,
}

impl ProtoTag {
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        match b {
            x if x == PROTO_TAG_ABRIDGED => Some(Self::Abridged),
            x if x == PROTO_TAG_INTERMEDIATE => Some(Self::Intermediate),
            x if x == PROTO_TAG_SECURE => Some(Self::PaddedIntermediate),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> [u8; 4] {
        match self {
            Self::Abridged => PROTO_TAG_ABRIDGED,
            Self::Intermediate => PROTO_TAG_INTERMEDIATE,
            Self::PaddedIntermediate => PROTO_TAG_SECURE,
        }
    }
}

// ─── Proxy secret layout ─────────────────────────────────────────────────────

/// Length of the mode-flag prefix that `dd`/`ee` secrets carry.
const SECRET_MODE_PREFIX_LEN: usize = 1;
/// Length of the actual cryptographic key inside a proxy secret.
const SECRET_KEY_LEN: usize = 16;
/// Offset of the key when a mode-flag prefix is present.
const PREFIXED_SECRET_LEN: usize = SECRET_MODE_PREFIX_LEN + SECRET_KEY_LEN;

/// FakeTLS mode flag: the secret carries a key plus an SNI hostname.
const SECRET_MODE_FAKETLS: u8 = 0xee;
/// Padded-intermediate mode flag: the secret carries a key only.
const SECRET_MODE_PADDED: u8 = 0xdd;

fn has_mode_prefix(raw: &[u8]) -> bool {
    raw.len() >= PREFIXED_SECRET_LEN && matches!(raw[0], SECRET_MODE_PADDED | SECRET_MODE_FAKETLS)
}

/// The 16-byte cryptographic key carried by a proxy secret.
///
/// Telegram proxy secrets optionally start with a 1-byte mode flag
/// (`dd` = padded intermediate, `ee` = FakeTLS) followed by the key; an `ee`
/// secret then appends the FakeTLS SNI hostname. Only the key participates in
/// key derivation, so every caller has to strip the prefix the same way.
/// Secrets without a recognised prefix are returned verbatim.
pub fn secret_key(raw: &[u8]) -> &[u8] {
    if has_mode_prefix(raw) {
        &raw[SECRET_MODE_PREFIX_LEN..PREFIXED_SECRET_LEN]
    } else {
        raw
    }
}

/// The FakeTLS SNI hostname carried by an `ee` secret, or `None` for any
/// other secret shape.
pub fn faketls_hostname(raw: &[u8]) -> Option<&[u8]> {
    (raw.len() > PREFIXED_SECRET_LEN && raw[0] == SECRET_MODE_FAKETLS)
        .then(|| &raw[PREFIXED_SECRET_LEN..])
}

// ─── Handshake parsing ───────────────────────────────────────────────────────

/// Result of a successfully parsed client handshake.
pub struct HandshakeInfo {
    /// Telegram DC id (absolute value, 1-5 or 203).
    pub dc_id: u32,
    /// True when the client requested a media DC.
    pub is_media: bool,
    /// Which MTProto transport protocol the client wants.
    pub proto: ProtoTag,
    /// Raw `prekey ∥ iv` slice from the client handshake (bytes [8..56]).
    /// Kept for key derivation of the client ↔ proxy ciphers.
    pub prekey_and_iv: [u8; PREKEY_LEN + IV_LEN],
}

/// Try to parse a 64-byte MTProto obfuscation handshake.
///
/// Returns `None` if the handshake does not decode to a valid protocol tag
/// (wrong secret, corrupt data, or a direct connection probe).
pub fn parse_handshake(handshake: &[u8; HANDSHAKE_LEN], secret: &[u8]) -> Option<HandshakeInfo> {
    let prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    // Key = SHA-256(prekey ∥ secret)
    let key = {
        let mut h = Sha256::new();
        h.update(prekey);
        h.update(secret);
        h.finalize()
    };

    // Decrypt the entire handshake to reveal proto_tag and dc_idx.
    let mut buf = *handshake;
    let mut cipher = make_cipher(&key, iv);
    cipher.apply_keystream(&mut buf);

    let proto = ProtoTag::from_bytes(&buf[PROTO_TAG_POS..PROTO_TAG_POS + 4])?;
    let dc_idx = i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]);

    let dc_id = dc_idx.unsigned_abs() as u32;
    let is_media = dc_idx < 0;

    let prekey_and_iv: [u8; PREKEY_LEN + IV_LEN] = handshake
        [SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
        .try_into()
        .unwrap();

    Some(HandshakeInfo {
        dc_id,
        is_media,
        proto,
        prekey_and_iv,
    })
}

// ─── Relay init generation ───────────────────────────────────────────────────

// First bytes that Telegram rejects as obfuscation init (plain-text HTTP, TLS…)
const RESERVED_FIRST_BYTES: &[u8] = &[0xef];
const RESERVED_STARTS: &[[u8; 4]] = &[
    [0x48, 0x45, 0x41, 0x44], // HEAD
    [0x50, 0x4f, 0x53, 0x54], // POST
    [0x47, 0x45, 0x54, 0x20], // GET
    [0xee, 0xee, 0xee, 0xee],
    [0xdd, 0xdd, 0xdd, 0xdd],
    [0x16, 0x03, 0x01, 0x02], // TLS ClientHello
];
const RESERVED_CONTINUE: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Generate a 64-byte obfuscation init packet for the Telegram backend.
///
/// The relay uses raw (non-secret-hashed) AES-256-CTR keys embedded in the
/// random bytes, so Telegram can verify the packet without knowing our secret.
///
/// `dc_idx` is the signed DC index: positive for normal DCs, negative for
/// media DCs (matching Telegram's convention).
pub fn generate_relay_init(proto: ProtoTag, dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let proto_tag = proto.as_bytes();
    let dc_bytes = dc_idx.to_le_bytes();

    loop {
        // Generate 64 random bytes.
        let mut rnd = [0u8; HANDSHAKE_LEN];
        rand::rng().fill_bytes(&mut rnd);

        // Reject reserved prefixes that Telegram or intermediate proxies
        // would misinterpret as an HTTP/TLS connection.
        if RESERVED_FIRST_BYTES.contains(&rnd[0]) {
            continue;
        }

        if RESERVED_STARTS.iter().any(|s| &rnd[..4] == s) {
            continue;
        }

        if rnd[4..8] == RESERVED_CONTINUE {
            continue;
        }

        // Encryption key and IV are embedded raw in bytes [8..56].
        let enc_key = &rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
        let enc_iv = &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut cipher = make_cipher(enc_key, enc_iv);

        // Encrypt a copy of the random bytes to obtain the CTR keystream.
        let mut encrypted = rnd;
        cipher.apply_keystream(&mut encrypted);

        // Positions [56..64]: XOR the plaintext tail (proto_tag ∥ dc_idx ∥ pad)
        // with the keystream at those positions.  This embeds the metadata in
        // a way that Telegram can recover after decrypting with the same cipher.
        let mut tail_plain = [0u8; 8];
        tail_plain[..4].copy_from_slice(&proto_tag);
        tail_plain[4..6].copy_from_slice(&dc_bytes);
        rand::rng().fill_bytes(&mut tail_plain[6..]);

        let mut result = rnd;
        for i in 0..8 {
            // keystream[56+i] = encrypted[56+i] XOR rnd[56+i]
            let ks = encrypted[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i];
            result[PROTO_TAG_POS + i] = tail_plain[i] ^ ks;
        }

        return result;
    }
}

// ─── Cipher construction ─────────────────────────────────────────────────────

/// Build an AES-256-CTR cipher from a 32-byte key and 16-byte IV.
pub fn make_cipher(key: &[u8], iv: &[u8]) -> AesCtr256 {
    AesCtr256::new_from_slices(key, iv).expect("key must be 32 bytes and iv must be 16 bytes")
}

/// Apply a cipher's keystream to `data` in place.
///
/// The one operation every caller of [`make_cipher`] and
/// [`build_connection_ciphers`] needs, without the `cipher` crate's
/// `StreamCipher` trait having to be in scope — which a caller outside this
/// crate (an integration test speaking the server half of the transport, say)
/// cannot bring in on its own.
pub fn apply_keystream(cipher: &mut AesCtr256, data: &mut [u8]) {
    cipher.apply_keystream(data);
}

// ─── Client handshake generation (our proxy acting as a client to upstream) ──

/// Generate a 64-byte MTProto obfuscation handshake that our proxy sends to
/// an upstream MTProto proxy, plus the two AES-256-CTR ciphers for the session.
///
/// Returns `(handshake, enc, dec)` where:
/// - `handshake` is the 64 bytes to send to the upstream proxy.
/// - `enc` encrypts data we send upstream (fast-forwarded 64 bytes).
/// - `dec` decrypts data we receive from upstream.
///
/// The upstream proxy parses our handshake with `SHA-256(prekey ∥ upstream_secret)`
/// and then routes the connection to the requested `dc_idx`.
pub fn generate_client_handshake(
    secret: &[u8],
    dc_idx: i16,
    proto: ProtoTag,
) -> ([u8; HANDSHAKE_LEN], AesCtr256, AesCtr256) {
    let proto_bytes = proto.as_bytes();
    let dc_bytes = dc_idx.to_le_bytes();

    loop {
        let mut raw = [0u8; HANDSHAKE_LEN];
        rand::rng().fill_bytes(&mut raw);

        // Reject reserved prefixes (same rules as generate_relay_init).
        if RESERVED_FIRST_BYTES.contains(&raw[0]) {
            continue;
        }
        if RESERVED_STARTS.iter().any(|s| &raw[..4] == s) {
            continue;
        }
        if raw[4..8] == RESERVED_CONTINUE {
            continue;
        }

        // Derive key and IV from the raw (pre-modification) bytes so the
        // upstream proxy can reproduce them from the handshake it receives.
        let key = {
            let mut h = Sha256::new();
            h.update(&raw[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let iv = &raw[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

        // Obtain the full keystream by encrypting a zero buffer.
        let mut keystream = [0u8; HANDSHAKE_LEN];
        make_cipher(&key, iv).apply_keystream(&mut keystream);

        // Embed proto_tag and dc_idx at positions [56..64] by XOR-ing with the
        // keystream so the upstream proxy sees the correct values after decryption.
        let mut handshake = raw;
        for i in 0..4 {
            handshake[PROTO_TAG_POS + i] = proto_bytes[i] ^ keystream[PROTO_TAG_POS + i];
        }
        for i in 0..2 {
            handshake[DC_IDX_POS + i] = dc_bytes[i] ^ keystream[DC_IDX_POS + i];
        }
        // handshake[62..64] stays as the original random raw bytes — these two
        // padding bytes are not interpreted by the upstream proxy and can be arbitrary.

        // Build enc cipher (what we use to encrypt data sent to upstream).
        // This mirrors the upstream's clt_dec cipher: same key/IV, fast-forwarded 64 bytes.
        let enc_key = {
            let mut h = Sha256::new();
            h.update(&handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let enc_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut enc = make_cipher(&enc_key, enc_iv);
        let mut dummy = [0u8; HANDSHAKE_LEN];
        enc.apply_keystream(&mut dummy); // fast-forward past the handshake bytes

        // Build dec cipher (what we use to decrypt data from upstream).
        // This mirrors the upstream's clt_enc cipher: reversed prekey+IV, not fast-forwarded.
        let reversed: Vec<u8> = handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]
            .iter()
            .rev()
            .copied()
            .collect();
        let dec_key = {
            let mut h = Sha256::new();
            h.update(&reversed[..PREKEY_LEN]);
            h.update(secret);
            h.finalize()
        };
        let dec_iv = &reversed[PREKEY_LEN..];
        let dec = make_cipher(&dec_key, dec_iv);

        return (handshake, enc, dec);
    }
}

// ─── Client ↔ proxy ciphers ──────────────────────────────────────────────────

/// All four AES-256-CTR ciphers needed for one proxied connection.
pub struct ConnectionCiphers {
    /// Decrypt data arriving from the client (client → proxy direction).
    pub clt_dec: AesCtr256,
    /// Encrypt data being sent to the client (proxy → client direction).
    pub clt_enc: AesCtr256,
    /// Encrypt data being forwarded to Telegram (proxy → Telegram direction).
    pub tg_enc: AesCtr256,
    /// Decrypt data arriving from Telegram (Telegram → proxy direction).
    pub tg_dec: AesCtr256,
}

/// Build the four connection ciphers from the parsed handshake.
///
/// `prekey_and_iv` is `handshake[8..56]` — the raw (unencrypted) prekey+IV
/// that the client embedded in the init packet.
pub fn build_connection_ciphers(
    prekey_and_iv: &[u8; PREKEY_LEN + IV_LEN],
    secret: &[u8],
    relay_init: &[u8; HANDSHAKE_LEN],
) -> ConnectionCiphers {
    let (clt_dec, clt_enc) = build_client_ciphers(prekey_and_iv, secret);

    // The relay uses RAW keys (no secret hash) — Telegram knows the keys
    // directly from the bytes embedded in the relay init packet.
    let (tg_enc, tg_dec) = build_raw_ciphers(relay_init);

    ConnectionCiphers {
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
    }
}

/// Build the client-side `(clt_dec, clt_enc)` pair of an MTProxy handshake.
///
/// `prekey_and_iv` is `handshake[8..56]` — the raw (unencrypted) prekey+IV
/// that the client embedded in the init packet.
pub fn build_client_ciphers(
    prekey_and_iv: &[u8; PREKEY_LEN + IV_LEN],
    secret: &[u8],
) -> (AesCtr256, AesCtr256) {
    // Decryption key = SHA-256(client_prekey ∥ secret)
    let clt_dec_key = {
        let mut h = Sha256::new();
        h.update(&prekey_and_iv[..PREKEY_LEN]);
        h.update(secret);
        h.finalize()
    };
    let clt_dec_iv = &prekey_and_iv[PREKEY_LEN..];

    // Encryption uses the *reversed* prekey+IV pair.
    let mut reversed = *prekey_and_iv;
    reversed.reverse();
    let clt_enc_key = {
        let mut h = Sha256::new();
        h.update(&reversed[..PREKEY_LEN]);
        h.update(secret);
        h.finalize()
    };
    let clt_enc_iv = &reversed[PREKEY_LEN..];

    let mut clt_dec = make_cipher(&clt_dec_key, clt_dec_iv);
    let clt_enc = make_cipher(&clt_enc_key, clt_enc_iv);

    // Fast-forward the client decryptor past the 64-byte handshake the client
    // already sent.  The CTR keystream used there must not be reused.
    clt_dec.apply_keystream(&mut [0u8; HANDSHAKE_LEN]);

    (clt_dec, clt_enc)
}

/// Build the two ciphers of an init packet keyed without a proxy secret:
/// `(sender, reply)`.
///
/// That is our relay init to Telegram, and also what a client sends when it
/// talks to Telegram directly rather than to an MTProxy. The key and IV are
/// the raw bytes [8..56], reversed for the reply direction; the sender's
/// cipher is fast-forwarded past the 64-byte init it already encrypted.
pub fn build_raw_ciphers(init: &[u8; HANDSHAKE_LEN]) -> (AesCtr256, AesCtr256) {
    let mut sender = make_cipher(
        &init[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
    );
    sender.apply_keystream(&mut [0u8; HANDSHAKE_LEN]);

    let mut reversed = [0u8; PREKEY_LEN + IV_LEN];
    reversed.copy_from_slice(&init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    reversed.reverse();
    let reply = make_cipher(&reversed[..PREKEY_LEN], &reversed[PREKEY_LEN..]);

    (sender, reply)
}
