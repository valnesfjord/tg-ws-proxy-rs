//! A Telegram-only SOCKS5 entrance to the existing MTProto/WSS bridge.
//!
//! SOCKS carries the destination separately from MTProto. Unlike MTProxy,
//! ordinary clients do not hash their obfuscation key with a proxy secret;
//! un-obfuscated transports do not carry a DC at all. Resolve the destination
//! using an explicit DC map — or, for a Telegram address the map has not
//! caught up with, the DC an obfuscated header names — then normalize either
//! transport for the shared upstream ladder. Never silently send an unknown
//! destination over raw TCP.

use std::collections::VecDeque;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

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
    if !is_production_dc(dc) {
        return Err("DC must be 1..5 or 203; use a negative value for media".into());
    }
    let ip: IpAddr = ip.parse().map_err(|_| "expected an IPv4 or IPv6 address")?;
    // Matched against canonical request addresses, like the built-in map.
    Ok(DcMapping {
        dc,
        ip: ip.to_canonical(),
    })
}

/// A signed DC index naming a production DC: 1..5 or 203, negative for media.
fn is_production_dc(dc: i16) -> bool {
    matches!(dc.unsigned_abs(), 1..=5 | 203)
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
    (-4, v4(149, 154, 165, 136)),
    (5, v4(91, 108, 56, 100)),
    (5, v4(91, 108, 56, 101)),
    (5, v4(91, 108, 56, 116)),
    (5, v4(91, 108, 56, 126)),
    (5, v4(149, 154, 171, 5)),
    (-5, v4(91, 108, 56, 102)),
    (-5, v4(91, 108, 56, 128)),
    (-5, v4(91, 108, 56, 147)),
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

const fn v6(a: u16, b: u16, c: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(a, b, c, 0, 0, 0, 0, 0))
}

/// Telegram's published address ranges, https://core.telegram.org/resources/cidr.txt.
/// The exact map above lags behind the addresses `help.getConfig` hands out;
/// a destination missing from it but inside these is still Telegram, and is
/// routed by the DC its transport header names.
const TELEGRAM_RANGES: &[(IpAddr, u8)] = &[
    (v4(91, 108, 56, 0), 22),
    (v4(91, 108, 4, 0), 22),
    (v4(91, 108, 8, 0), 22),
    (v4(91, 108, 16, 0), 22),
    (v4(91, 108, 12, 0), 22),
    (v4(149, 154, 160, 0), 20),
    (v4(91, 105, 192, 0), 23),
    (v4(91, 108, 20, 0), 22),
    (v4(185, 76, 151, 0), 24),
    (v6(0x2001, 0xb28, 0xf23d), 48),
    (v6(0x2001, 0xb28, 0xf23f), 48),
    (v6(0x2001, 0x67c, 0x4e8), 48),
    (v6(0x2001, 0xb28, 0xf23c), 48),
    (v6(0x2a0a, 0xf280, 0), 32),
];

fn is_telegram(ip: IpAddr) -> bool {
    TELEGRAM_RANGES.iter().any(|&(net, len)| match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            u32::from(net) >> (32 - len) == u32::from(ip) >> (32 - len)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            u128::from(net) >> (128 - len) == u128::from(ip) >> (128 - len)
        }
        _ => false,
    })
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

/// Answer the SOCKS request, returning the destination and the DC the map
/// knows it as. An unmapped Telegram address is accepted with `None`: its DC
/// can only come from the transport header that follows.
async fn negotiate(stream: &mut TcpStream, config: &Config) -> io::Result<(IpAddr, Option<i16>)> {
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
    let dc = destination_dc(ip, config);
    if dc.is_none() && !is_telegram(ip) {
        if first_report(ip) {
            warn!(
                "SOCKS destination {}:{} is not a Telegram address; check what the \
                 router sends here (repeats for this address are logged at debug level)",
                ip, port
            );
        } else {
            debug!(
                "SOCKS destination {}:{} is not a Telegram address",
                ip, port
            );
        }
        reply(stream, 2).await?;
        return Err(invalid("not a Telegram destination"));
    }
    // Telegram sends its transport header only after SOCKS CONNECT succeeds.
    // The WSS route is selected once that header reveals the framing protocol.
    reply(stream, 0).await?;
    Ok((ip, dc))
}

/// The MTProto transport header that follows CONNECT.
struct Transport {
    proto: ProtoTag,
    /// The client's obfuscation as `(decrypt, encrypt)`, if it is obfuscated.
    obfuscation: Option<(AesCtr256, AesCtr256)>,
    /// The production DC an obfuscated header names, if it names one.
    named_dc: Option<i16>,
}

async fn read_transport(stream: &mut TcpStream) -> io::Result<Transport> {
    let plain = |proto| Transport {
        proto,
        obfuscation: None,
        named_dc: None,
    };
    let mut header = [0; 64];
    stream.read_exact(&mut header[..1]).await?;
    if header[0] == 0xef {
        return Ok(plain(ProtoTag::Abridged));
    }
    stream.read_exact(&mut header[1..4]).await?;
    if let Some(proto) = ProtoTag::from_bytes(&header[..4]) {
        return Ok(plain(proto));
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
    // Telegram Desktop writes the signed DC here even without a proxy, but
    // nothing checks it, and Android fills it randomly without a secret: the
    // mapped destination stays authoritative, this is only a fallback.
    let named_dc = i16::from_le_bytes([decrypted[60], decrypted[61]]);
    Ok(Transport {
        proto,
        obfuscation: Some(build_raw_ciphers(&header)),
        named_dc: is_production_dc(named_dc).then_some(named_dc),
    })
}

/// `DC4` or `DC4 media`, as the logs name a signed DC.
fn dc_label(dc: i16) -> String {
    format!(
        "DC{}{}",
        dc.unsigned_abs(),
        if dc < 0 { " media" } else { "" }
    )
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
        let (ip, mapped) = negotiate(&mut stream, config)
            .await
            .map_err(|error| rejected(peer, error))?;
        let transport = read_transport(&mut stream)
            .await
            .map_err(|error| rejected(peer, error))?;
        let dc_idx = match (mapped, transport.named_dc) {
            (Some(dc), _) => dc,
            (None, Some(dc)) => {
                if first_report(ip) {
                    info!(
                        "SOCKS destination {} is not in the DC map; routing it as {} by \
                         its transport header (pin it with --socks-dc {}:{})",
                        ip,
                        dc_label(dc),
                        dc,
                        ip
                    );
                }
                dc
            }
            (None, None) => {
                if first_report(ip) {
                    warn!(
                        "SOCKS destination {} is a Telegram address missing from the DC map, \
                         and its transport names no DC: these connections fail, often as \
                         media that never loads. Add its DC with --socks-dc DC:{} \
                         (negative DC for media)",
                        ip, ip
                    );
                }
                return Err(rejected(peer, invalid("unmapped Telegram destination")));
            }
        };
        let (reader, writer) = stream.into_split();
        Ok(Session {
            reader: ClientReader::Plain(reader),
            writer: ClientWriter::Plain(writer),
            dc_idx,
            proto: transport.proto,
            obfuscation: transport.obfuscation,
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
