//! The MTProto listener: MTProxy-secret obfuscation, optionally inside
//! FakeTLS camouflage (`--listen-faketls-domain`).
//!
//! A client that fails the secret check is drained rather than closed, so a
//! scanner cannot tell a wrong guess from a slow server by when the
//! connection ends.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf as TcpReader, OwnedWriteHalf as TcpWriter};
use tracing::debug;

use super::{ClientReader, ClientWriter, Inbound, Link, PendingData, Reject, Session};
use crate::config::Config;
use crate::crypto::{build_client_ciphers, parse_handshake};
use crate::faketls::{
    TLS_MAX_RECORD_PAYLOAD, TLS_READ_HEADROOM, TLS_RECORD_APPLICATION_DATA,
    TLS_RECORD_CHANGE_CIPHER_SPEC, TLS_RECORD_HANDSHAKE, build_faketls_server_hello,
    parse_faketls_client_hello, read_tls_record_bytes,
};

pub(crate) struct MtProto;

impl Inbound for MtProto {
    const NAME: &'static str = "MTProto";

    async fn handshake(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        config: &Config,
    ) -> Result<Session, Reject> {
        let label = peer;
        let secrets = config.normalized_secrets();
        let faketls_domain = config.normalized_listen_faketls_domain();
        let (mut reader, mut writer) = stream.into_split();

        let (init, pending) =
            read_inbound_handshake(label, &mut reader, &mut writer, secrets, faketls_domain)
                .await
                .ok_or(Reject::Close)?;
        let (reader, writer) = if faketls_domain.is_some() {
            (
                ClientReader::FakeTls { reader, pending },
                ClientWriter::FakeTls(writer),
            )
        } else {
            (ClientReader::Plain(reader), ClientWriter::Plain(writer))
        };

        let Some((info, secret)) = secrets
            .iter()
            .find_map(|secret| parse_handshake(&init, secret).map(|i| (i, secret.as_slice())))
        else {
            debug!(
                "[{}] bad handshake (wrong secret or reserved prefix)",
                label
            );
            return Err(Reject::Drain(reader, writer));
        };

        // The index comes back unsigned; -32768 has no positive counterpart
        // to negate, and names no DC anyway.
        let Ok(dc) = i16::try_from(info.dc_id) else {
            debug!("[{}] DC index out of range: {}", label, info.dc_id);
            return Err(Reject::Close);
        };
        let dc_idx = if info.is_media { -dc } else { dc };
        Ok(Session {
            reader,
            writer,
            dc_idx,
            proto: info.proto,
            obfuscation: Some(build_client_ciphers(&info.prekey_and_iv, secret)),
        })
    }

    /// One `tg://proxy` link per secret, the primary one first.
    fn links(&self, addr: SocketAddr, config: &Config) -> Vec<Link> {
        let host = config.link_host();
        std::iter::once(config.primary_secret())
            .chain(config.secrets.iter().skip(1).map(String::as_str))
            .map(|secret| Link {
                inbound: Self::NAME,
                label: "Telegram",
                url: format!(
                    "tg://proxy?server={}&port={}&secret={}",
                    host,
                    addr.port(),
                    config.link_secret_for(secret)
                ),
            })
            .collect()
    }
}

async fn read_inbound_handshake(
    label: SocketAddr,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    faketls_domain: Option<&str>,
) -> Option<([u8; 64], PendingData)> {
    if let Some(domain) = faketls_domain {
        return accept_inbound_faketls(label, reader, writer, secrets, domain).await;
    }

    let mut handshake_buf = [0u8; 64];
    match reader.read_exact(&mut handshake_buf).await {
        Ok(_) => Some((handshake_buf, PendingData::default())),
        Err(e) => {
            debug!("[{}] read handshake: {}", label, e);
            None
        }
    }
}

async fn accept_inbound_faketls(
    label: SocketAddr,
    reader: &mut TcpReader,
    writer: &mut TcpWriter,
    secrets: &[Vec<u8>],
    expected_domain: &str,
) -> Option<([u8; 64], PendingData)> {
    let record = read_tls_record_bytes(reader, TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM)
        .await
        .ok()??;
    if record[0] != TLS_RECORD_HANDSHAKE || record[1..3] != [0x03, 0x01] {
        debug!("[{}] bad FakeTLS ClientHello record", label);
        return None;
    }

    let Some((hello, matched_secret)) = secrets.iter().find_map(|secret| {
        parse_faketls_client_hello(&record, secret).map(|hello| (hello, secret))
    }) else {
        debug!("[{}] bad FakeTLS ClientHello digest", label);
        return None;
    };

    if hello.hostname.as_deref() != Some(expected_domain) {
        debug!(
            "[{}] FakeTLS SNI mismatch: got {:?}, expected {}",
            label, hello.hostname, expected_domain
        );
        return None;
    }

    let server_hello = build_faketls_server_hello(matched_secret, &hello);
    if let Err(e) = writer.write_all(&server_hello).await {
        debug!("[{}] write FakeTLS ServerHello: {}", label, e);
        return None;
    }

    let mut handshake_buf = [0u8; 64];
    let mut filled = 0;
    while filled < handshake_buf.len() {
        let record = read_tls_record_bytes(reader, TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM)
            .await
            .ok()??;
        let record_type = record[0];
        let payload_len = record.len() - 5;
        if record_type == TLS_RECORD_CHANGE_CIPHER_SPEC {
            continue;
        }
        if record_type != TLS_RECORD_APPLICATION_DATA || payload_len == 0 {
            return None;
        }
        let take = std::cmp::min(payload_len, handshake_buf.len() - filled);
        handshake_buf[filled..filled + take].copy_from_slice(&record[5..5 + take]);
        filled += take;
        if take != payload_len {
            return Some((handshake_buf, PendingData::from_record(record, 5 + take)));
        }
    }

    Some((handshake_buf, PendingData::default()))
}
