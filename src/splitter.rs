//! MTProto message splitter.
//!
//! Each Telegram WebSocket message is expected to carry exactly **one**
//! complete MTProto transport packet.  If we forward chunks of the raw TCP
//! stream without respecting packet boundaries, Telegram will reject or
//! misparse the connection.
//!
//! The splitter maintains an internal decrypt copy of the AES-256-CTR cipher
//! (in lockstep with the proxy's `tg_enc` cipher) so it can peek at the
//! plaintext packet-length fields and figure out where each packet ends —
//! while returning the **encrypted** bytes for forwarding.

use cipher::StreamCipher;

use crate::crypto::{AesCtr256, HANDSHAKE_LEN, ProtoTag, SKIP_LEN, make_cipher};

const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;

pub struct MsgSplitter {
    /// Internal cipher that shadows `tg_enc` to decrypt the stream in-band.
    dec: AesCtr256,
    proto: ProtoTag,
    /// Buffered encrypted bytes (ready to be returned as WS frames).
    cipher_buf: Vec<u8>,
    /// Buffered plaintext (used only for length-parsing).
    plain_buf: Vec<u8>,
    /// Once set, the splitter stops trying to parse lengths and returns
    /// any buffered data as a single chunk (unknown / unsupported proto).
    disabled: bool,
}

impl MsgSplitter {
    /// Create a new splitter that mirrors the relay encryptor state.
    ///
    /// `relay_init` is the 64-byte obfuscation init sent to Telegram.
    /// The splitter builds the same AES-256-CTR cipher (raw key, no secret
    /// hash) and fast-forwards it by 64 bytes — identical to how `tg_enc`
    /// is initialised in `build_connection_ciphers`.
    pub fn new(relay_init: &[u8; HANDSHAKE_LEN], proto: ProtoTag) -> Self {
        let relay_enc_key = &relay_init[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
        let relay_enc_iv = &relay_init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut dec = make_cipher(relay_enc_key, relay_enc_iv);

        // Advance past the relay init (same fast-forward as tg_enc).
        let mut dummy = [0u8; HANDSHAKE_LEN];

        dec.apply_keystream(&mut dummy);

        Self {
            dec,
            proto,
            cipher_buf: Vec::new(),
            plain_buf: Vec::new(),
            disabled: false,
        }
    }

    /// Feed relay-encrypted bytes and receive back a list of complete
    /// encrypted MTProto packets, each to be sent as one WebSocket frame.
    ///
    /// Incomplete packets are buffered internally until the next call.
    pub fn split(&mut self, encrypted: &[u8]) -> Vec<Vec<u8>> {
        if encrypted.is_empty() {
            return Vec::new();
        }

        // If we don't know how to parse this protocol, pass everything through.
        if self.disabled {
            return vec![encrypted.to_vec()];
        }

        // Decrypt to a temporary buffer for length parsing.
        let mut plain = encrypted.to_vec();
        self.dec.apply_keystream(&mut plain);

        self.cipher_buf.extend_from_slice(encrypted);
        self.plain_buf.extend_from_slice(&plain);

        let mut parts = Vec::new();
        loop {
            match self.next_packet_len() {
                None => break, // need more bytes
                Some(0) => {
                    // Unsupported / unknown protocol variant — disable parsing
                    // and flush everything buffered so far.
                    parts.push(self.cipher_buf.clone());

                    self.cipher_buf.clear();
                    self.plain_buf.clear();
                    self.disabled = true;

                    break;
                }
                Some(len) => {
                    parts.push(self.cipher_buf[..len].to_vec());

                    self.cipher_buf.drain(..len);
                    self.plain_buf.drain(..len);
                }
            }
        }

        parts
    }

    /// Flush any remaining buffered bytes as a single chunk.
    pub fn flush(&mut self) -> Vec<Vec<u8>> {
        if self.cipher_buf.is_empty() {
            return Vec::new();
        }

        let tail = self.cipher_buf.clone();

        self.cipher_buf.clear();
        self.plain_buf.clear();

        vec![tail]
    }

    // ── Length parsers ────────────────────────────────────────────────────

    /// Returns the byte length of the next complete packet (header + payload),
    /// `None` if there isn't enough data yet, or `Some(0)` for unknown proto.
    fn next_packet_len(&self) -> Option<usize> {
        if self.plain_buf.is_empty() {
            return None;
        }

        match self.proto {
            ProtoTag::Abridged => self.abridged_len(),
            ProtoTag::Intermediate | ProtoTag::PaddedIntermediate => self.intermediate_len(),
        }
    }

    /// Abridged transport length parsing.
    ///
    /// - 1-byte header: payload_len = (byte & 0x7F) * 4
    /// - 4-byte header (first byte is 0x7F or 0xFF): payload_len = next_3_bytes_le * 4
    fn abridged_len(&self) -> Option<usize> {
        let first = self.plain_buf[0];
        let (payload_len, header_len) = if first == 0x7F || first == 0xFF {
            if self.plain_buf.len() < 4 {
                return None; // need more data for 4-byte header
            }

            let l = u32::from_le_bytes([self.plain_buf[1], self.plain_buf[2], self.plain_buf[3], 0])
                as usize
                * 4;

            (l, 4)
        } else {
            ((first & 0x7F) as usize * 4, 1)
        };

        if payload_len == 0 {
            return Some(0); // signal to disable splitter
        }

        let total = header_len + payload_len;
        if self.plain_buf.len() < total {
            None
        } else {
            Some(total)
        }
    }

    /// Intermediate / padded-intermediate transport length parsing.
    ///
    /// 4-byte LE header: payload_len = header & 0x7FFF_FFFF
    fn intermediate_len(&self) -> Option<usize> {
        if self.plain_buf.len() < 4 {
            return None;
        }

        let payload_len = (u32::from_le_bytes([
            self.plain_buf[0],
            self.plain_buf[1],
            self.plain_buf[2],
            self.plain_buf[3],
        ]) & 0x7FFF_FFFF) as usize;

        if payload_len == 0 {
            return Some(0);
        }

        let total = 4 + payload_len;
        if self.plain_buf.len() < total {
            None
        } else {
            Some(total)
        }
    }
}
