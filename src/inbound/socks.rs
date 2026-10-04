//! A Telegram-only SOCKS5 entrance to the existing MTProto/WSS bridge.
//!
//! SOCKS carries the destination separately from MTProto. Unlike MTProxy,
//! ordinary clients do not hash their obfuscation key with a proxy secret;
//! un-obfuscated transports do not carry a DC at all. Resolve the destination
//! using an explicit DC map, then normalize either transport for the shared
//! upstream ladder. Never silently send an unknown destination over raw TCP.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use super::{ClientReader, ClientWriter, Inbound, Link, Reject, Session};
use crate::config::Config;
use crate::crypto::{AesCtr256, ProtoTag, apply_keystream, build_raw_ciphers, make_cipher};
use crate::inbound;
use crate::pool::WsPool;
use crate::runtime::Runtime;

#[derive(Clone, Debug)]
pub struct DcMapping {
    pub dc: i16,
    pub ip: IpAddr,
}

pub fn parse_dc_mapping(value: &str) -> Result<DcMapping, String> {
    let (dc, ip) = value.split_once(':').ok_or("expected signed DC:IP")?;
    let dc: i16 = dc.parse().map_err(|_| "invalid DC")?;
    if !matches!(dc.unsigned_abs(), 1..=5 | 203) {
        return Err("DC must be 1..5 or 203; use a negative value for media".into());
    }
    let ip: IpAddr = ip.parse().map_err(|_| "expected an IPv4 or IPv6 address")?;
    // Matched against canonical request addresses, like the built-in map.
    Ok(DcMapping {
        dc,
        ip: ip.to_canonical(),
    })
}

// Reference for common IPv4 DC/media endpoints:
// https://github.com/AlexMelanFromRingo/tg-proxy/blob/main/src/ip_map.rs
// IPv6 entries are the production addresses built into both official clients
// (tdesktop mtproto_dc_options.cpp, Android tgnet ConnectionsManager.cpp);
// media IPv6 addresses only arrive via help.getConfig, so they are not here.
// Exact destination addresses, not whole Telegram subnets: a subnet may host
// multiple DCs. Unknown/new/CDN endpoints need an explicit --socks-dc mapping.
const DC_IPS: &[(i16, IpAddr)] = &[
    (1, v4(149, 154, 175, 50)),
    (1, v4(149, 154, 175, 51)),
    (1, v4(149, 154, 175, 53)),
    (1, v4(149, 154, 175, 54)),
    (-1, v4(149, 154, 175, 52)),
    (2, v4(149, 154, 167, 41)),
    (2, v4(149, 154, 167, 50)),
    (2, v4(149, 154, 167, 51)),
    (2, v4(149, 154, 167, 220)),
    (2, v4(95, 161, 76, 100)),
    (-2, v4(149, 154, 167, 151)),
    (-2, v4(149, 154, 167, 222)),
    (-2, v4(149, 154, 167, 223)),
    (-2, v4(149, 154, 162, 123)),
    (3, v4(149, 154, 175, 100)),
    (3, v4(149, 154, 175, 101)),
    (-3, v4(149, 154, 175, 102)),
    (4, v4(149, 154, 167, 91)),
    (4, v4(149, 154, 167, 92)),
    (-4, v4(149, 154, 164, 250)),
    (-4, v4(149, 154, 166, 120)),
    (-4, v4(149, 154, 166, 121)),
    (-4, v4(149, 154, 167, 118)),
    (-4, v4(149, 154, 165, 111)),
    (5, v4(91, 108, 56, 100)),
    (5, v4(91, 108, 56, 101)),
    (5, v4(91, 108, 56, 116)),
    (5, v4(91, 108, 56, 126)),
    (5, v4(149, 154, 171, 5)),
    (-5, v4(91, 108, 56, 102)),
    (-5, v4(91, 108, 56, 128)),
    (-5, v4(91, 108, 56, 151)),
    (203, v4(91, 105, 192, 100)),
    (
        1,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xb28, 0xf23d, 0xf001, 0, 0, 0, 0xa)),
    ),
    (
        2,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x67c, 0x4e8, 0xf002, 0, 0, 0, 0xa)),
    ),
    (
        3,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xb28, 0xf23d, 0xf003, 0, 0, 0, 0xa)),
    ),
    (
        4,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x67c, 0x4e8, 0xf004, 0, 0, 0, 0xa)),
    ),
    (
        5,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xb28, 0xf23f, 0xf005, 0, 0, 0, 0xa)),
    ),
];

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn destination_dc(ip: IpAddr, config: &Config) -> Option<i16> {
    config
        .socks_dc
        .iter()
        .rev()
        .find(|m| m.ip == ip)
        .map(|m| m.dc)
        .or_else(|| {
            DC_IPS
                .iter()
                .find(|(_, known)| *known == ip)
                .map(|(dc, _)| *dc)
        })
}

/// Unknown destinations already reported at warn level. Telegram retries a
/// refused DC every few seconds, and one warning per attempt would flush a
/// router's small log ring. Bounded, so a client cycling through addresses
/// cannot grow it: an evicted address is merely reported again.
static REPORTED_UNKNOWN: Mutex<VecDeque<IpAddr>> = Mutex::new(VecDeque::new());
const REPORTED_UNKNOWN_CAP: usize = 64;

fn first_report(ip: IpAddr) -> bool {
    let mut reported = REPORTED_UNKNOWN
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if reported.contains(&ip) {
        return false;
    }
    if reported.len() == REPORTED_UNKNOWN_CAP {
        reported.pop_front();
    }
    reported.push_back(ip);
    true
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message)
}

async fn reply(stream: &mut TcpStream, code: u8) -> io::Result<()> {
    stream.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

async fn negotiate(stream: &mut TcpStream, config: &Config) -> io::Result<i16> {
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(invalid("expected SOCKS5"));
    }
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(greeting[1])];
    stream.read_exact(methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[5, 255]).await?;
        return Err(invalid("SOCKS5 no-auth method required"));
    }
    stream.write_all(&[5, 0]).await?;
    // Read the whole request before any reply: closing with request bytes
    // still unread makes the kernel send RST instead of FIN, and a client —
    // Windows notably — then discards the reply it was about to read.
    let mut request = [0; 4];
    stream.read_exact(&mut request).await?;
    let host: Option<IpAddr> = match request[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            Some(Ipv4Addr::from(bytes).into())
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            Some(Ipv6Addr::from(bytes).into())
        }
        3 => {
            let len = usize::from(stream.read_u8().await?);
            let mut bytes = [0; 255];
            stream.read_exact(&mut bytes[..len]).await?;
            // Accept an IP encoded as DOMAIN, but do not resolve arbitrary
            // hostnames or mistake FakeIP for a Telegram DC destination.
            std::str::from_utf8(&bytes[..len])
                .ok()
                .and_then(|s| s.parse().ok())
        }
        _ => {
            // Its length is unknown, so this one cannot be read to the end.
            reply(stream, 8).await?;
            return Err(invalid("unsupported SOCKS address type"));
        }
    };
    // Only for logs: the bridge reaches the DC over its own routes, so the
    // port a client asked for never decides where anything connects.
    let port = stream.read_u16().await?;
    if request[0] != 5 || request[2] != 0 {
        reply(stream, 1).await?;
        return Err(invalid("invalid SOCKS5 request"));
    }
    if request[1] != 1 {
        reply(stream, 7).await?;
        return Err(invalid("only SOCKS5 CONNECT is supported (no UDP/BIND)"));
    }
    let Some(host) = host else {
        reply(stream, 4).await?;
        return Err(invalid("SOCKS destination must be a mapped Telegram IP"));
    };
    // An IPv4 destination may arrive IPv4-mapped from a dual-stack socket.
    let ip = host.to_canonical();
    let Some(dc) = destination_dc(ip, config) else {
        if first_report(ip) {
            warn!(
                "SOCKS destination {}:{} has no DC mapping; configure --socks-dc \
                 (repeats for this address are logged at debug level)",
                ip, port
            );
        } else {
            debug!("SOCKS destination {}:{} has no DC mapping", ip, port);
        }
        reply(stream, 2).await?;
        return Err(invalid("unknown Telegram destination"));
    };
    // Telegram sends its transport header only after SOCKS CONNECT succeeds.
    // The WSS route is selected once that header reveals the framing protocol.
    reply(stream, 0).await?;
    Ok(dc)
}

/// Read the MTProto transport header that follows CONNECT: its framing, and
/// the client's obfuscation as `(decrypt, encrypt)` if it is obfuscated.
async fn read_transport(
    stream: &mut TcpStream,
) -> io::Result<(ProtoTag, Option<(AesCtr256, AesCtr256)>)> {
    let mut header = [0; 64];
    stream.read_exact(&mut header[..1]).await?;
    if header[0] == 0xef {
        return Ok((ProtoTag::Abridged, None));
    }
    stream.read_exact(&mut header[1..4]).await?;
    if let Some(proto) = ProtoTag::from_bytes(&header[..4]) {
        return Ok((proto, None));
    }
    stream.read_exact(&mut header[4..]).await?;
    let mut decrypted = header;
    apply_keystream(
        &mut make_cipher(&header[8..40], &header[40..56]),
        &mut decrypted,
    );
    let proto = ProtoTag::from_bytes(&decrypted[56..60]).ok_or_else(|| {
        invalid("unsupported MTProto transport (HTTP, Full and FakeTLS are not supported)")
    })?;
    // Without an MTProxy secret the header's DC bytes are not a reliable
    // routing source. The SOCKS destination is authoritative.
    Ok((proto, Some(build_raw_ciphers(&header))))
}

fn rejected(peer: SocketAddr, error: io::Error) -> Reject {
    debug!("[{}] SOCKS handshake rejected: {}", peer, error);
    Reject::Close
}

/// The SOCKS5 listener (`--socks-enabled`).
pub(crate) struct Socks5;

impl Inbound for Socks5 {
    const NAME: &'static str = "SOCKS5";

    async fn handshake(
        &self,
        mut stream: TcpStream,
        peer: SocketAddr,
        config: &Config,
    ) -> Result<Session, Reject> {
        let dc_idx = negotiate(&mut stream, config)
            .await
            .map_err(|error| rejected(peer, error))?;
        let (proto, obfuscation) = read_transport(&mut stream)
            .await
            .map_err(|error| rejected(peer, error))?;
        let (reader, writer) = stream.into_split();
        Ok(Session {
            reader: ClientReader::Plain(reader),
            writer: ClientWriter::Plain(writer),
            dc_idx,
            proto,
            obfuscation,
        })
    }

    /// A `socks5://` URL for a routing service on this machine, and — unless
    /// bound to loopback, which no other device can reach — a `tg://socks`
    /// link for Telegram apps on the network.
    fn links(&self, addr: SocketAddr, config: &Config) -> Vec<Link> {
        let local = if addr.ip().is_unspecified() {
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), addr.port())
        } else {
            addr
        };
        let mut links = vec![Link {
            inbound: Self::NAME,
            label: "Router service",
            url: format!("socks5://{local}"),
        }];
        if !addr.ip().is_loopback() {
            let host = if addr.ip().is_unspecified() {
                config.link_host()
            } else {
                addr.ip().to_string()
            };
            links.push(Link {
                inbound: Self::NAME,
                label: "Telegram",
                url: format!("tg://socks?server={}&port={}", host, addr.port()),
            });
        }
        links
    }
}

/// Serve one SOCKS5 client end-to-end: the SOCKS counterpart of
/// [`crate::proxy::handle_client_with_runtime`].
pub async fn handle_client(
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<WsPool>,
    runtime: Arc<Runtime>,
) {
    inbound::serve(&Socks5, stream, peer, config, pool, runtime).await;
}

#[cfg(test)]
mod tests;
