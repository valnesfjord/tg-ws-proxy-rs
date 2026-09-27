//! The inbound layer: every listener protocol reduces a client to a
//! [`Session`], and everything after that is shared.
//!
//! An inbound owns only its handshake — MTProto's secret check and FakeTLS
//! camouflage, SOCKS5's destination lookup — up to the point where the DC,
//! the transport framing and the client's obfuscation, if any, are known.
//! [`serve`] bounds every handshake with the same timeout; `proxy` then
//! builds the relay init and Telegram-side ciphers once and runs the routing
//! ladder and bridges, none of which know which listener a client came in on.
//!
//! A new listener protocol is an [`Inbound`] impl, plus a [`Listener`] bound
//! for it in `server`.

pub(crate) mod mtproto;
pub mod socks;

use std::future::{Future, poll_fn};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use futures_util::future::Either;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::OwnedSemaphorePermit;
use tracing::debug;

use crate::config::Config;
use crate::crypto::{AesCtr256, ProtoTag};
use crate::faketls::{
    TLS_MAX_RECORD_PAYLOAD, TLS_READ_HEADROOM, read_tls_appdata, write_tls_appdata,
};
use crate::inbound::mtproto::MtProto;
use crate::inbound::socks::Socks5;
use crate::pool::WsPool;
use crate::proxy;
use crate::runtime::Runtime;

/// A client whose inbound handshake is done, in the only terms the routing
/// and bridging core needs.
pub(crate) struct Session {
    pub(crate) reader: ClientReader,
    pub(crate) writer: ClientWriter,
    /// Signed DC index: negative for a media DC.
    pub(crate) dc_idx: i16,
    pub(crate) proto: ProtoTag,
    /// The client's transport obfuscation as `(decrypt, encrypt)`, or `None`
    /// for a plain transport.
    pub(crate) obfuscation: Option<(AesCtr256, AesCtr256)>,
}

/// A way for a client to reach a listener, as offered to the user to copy.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Link {
    /// The [`Inbound::NAME`] of the listener it reaches.
    pub(crate) inbound: &'static str,
    /// What the link is for, e.g. a Telegram app or a router service.
    pub(crate) label: &'static str,
    pub(crate) url: String,
}

/// How a failed handshake ends the connection.
pub(crate) enum Reject {
    /// Close it now.
    Close,
    /// Read and discard until the client gives up, so a prober learns nothing
    /// from when the connection ends. Not bounded by the handshake timeout.
    /// The writer is held too: dropping a write half sends FIN, the very
    /// signal draining withholds.
    Drain(ClientReader, ClientWriter),
}

/// One listener protocol.
pub(crate) trait Inbound: Send + Sync + 'static {
    /// Names the protocol in logs.
    const NAME: &'static str;

    /// Run this protocol's handshake on an accepted client. [`serve`] bounds
    /// it with the handshake timeout; a rejection is logged here, where the
    /// reason is known.
    fn handshake(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        config: &Config,
    ) -> impl Future<Output = Result<Session, Reject>> + Send;

    /// The links a user copies into a client to reach this listener at
    /// `addr`.
    fn links(&self, addr: SocketAddr, config: &Config) -> Vec<Link>;
}

/// Serve one accepted client of `inbound` for the rest of its life.
pub(crate) async fn serve<I: Inbound>(
    inbound: &I,
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    pool: Arc<WsPool>,
    runtime: Arc<Runtime>,
) {
    let _ = stream.set_nodelay(true);
    let timeout = Duration::from_secs(config.handshake_timeout);
    // No arm awaits: the handshake's result, ciphers included, stays a
    // temporary of this statement instead of part of the session's state.
    let rest = match tokio::time::timeout(timeout, inbound.handshake(stream, peer, &config)).await {
        Ok(Ok(session)) => Either::Left(proxy::serve_session(peer, session, config, pool, runtime)),
        Ok(Err(Reject::Drain(reader, writer))) => Either::Right(async move {
            let _writer = writer;
            reader.drain().await;
        }),
        Ok(Err(Reject::Close)) => return,
        Err(_) => {
            debug!("[{}] {} handshake timeout", peer, I::NAME);
            return;
        }
    };
    rest.await;
}

// ─── Listeners ───────────────────────────────────────────────────────────────

/// A listener the configuration enables, not bound yet.
pub(crate) struct Planned {
    pub(crate) addr: SocketAddr,
    inbound: Arc<dyn Spawn>,
}

impl Planned {
    fn new(addr: SocketAddr, inbound: impl Inbound) -> Self {
        Self {
            addr,
            inbound: Arc::new(inbound),
        }
    }

    pub(crate) fn links(&self, config: &Config) -> Vec<Link> {
        self.inbound.links(self.addr, config)
    }

    pub(crate) async fn bind(self) -> io::Result<Listener> {
        Ok(Listener {
            socket: TcpListener::bind(self.addr).await?,
            planned: self,
        })
    }
}

/// Every listener `config` enables, MTProto first, at its configured address.
/// The one place a listener protocol is registered: the server binds these
/// and `--print-links` describes them. `Err` carries the unparsable address.
pub(crate) fn planned(config: &Config) -> Result<Vec<Planned>, String> {
    let host = config.bind_host();
    let mtproto = format!("{}:{}", host, config.port);
    let mut all = vec![Planned::new(
        mtproto.parse().map_err(|_| mtproto.clone())?,
        MtProto,
    )];
    if config.socks_enabled {
        all.push(Planned::new(
            SocketAddr::new(config.socks_host, config.socks_port),
            Socks5,
        ));
    }
    Ok(all)
}

/// A bound listener and the protocol it speaks.
pub(crate) struct Listener {
    socket: TcpListener,
    planned: Planned,
}

impl Listener {
    pub(crate) fn name(&self) -> &'static str {
        self.planned.inbound.name()
    }

    /// The bound address: the configured one with any port 0 resolved.
    pub(crate) fn addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap_or(self.planned.addr)
    }

    /// This listener's links, on the address it is actually bound to.
    pub(crate) fn links(&self, config: &Config) -> Vec<Link> {
        self.planned.inbound.links(self.addr(), config)
    }

    /// Serve an accepted client on its own task, which holds `permit` for
    /// the life of the connection.
    pub(crate) fn spawn(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
        permit: OwnedSemaphorePermit,
        config: Arc<Config>,
        pool: Arc<WsPool>,
        runtime: Arc<Runtime>,
    ) {
        Arc::clone(&self.planned.inbound).spawn(stream, peer, permit, config, pool, runtime);
    }
}

/// The object-safe side of [`Inbound`], whose `handshake` future has no name
/// to put behind `dyn`. Spawning inside the generic impl also keeps each
/// protocol's connection future inline in its task instead of boxed.
trait Spawn: Send + Sync {
    fn name(&self) -> &'static str;

    fn links(&self, addr: SocketAddr, config: &Config) -> Vec<Link>;

    fn spawn(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        permit: OwnedSemaphorePermit,
        config: Arc<Config>,
        pool: Arc<WsPool>,
        runtime: Arc<Runtime>,
    );
}

impl<I: Inbound> Spawn for I {
    fn name(&self) -> &'static str {
        I::NAME
    }

    fn links(&self, addr: SocketAddr, config: &Config) -> Vec<Link> {
        Inbound::links(self, addr, config)
    }

    fn spawn(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
        permit: OwnedSemaphorePermit,
        config: Arc<Config>,
        pool: Arc<WsPool>,
        runtime: Arc<Runtime>,
    ) {
        tokio::spawn(async move {
            let _permit = permit;
            serve(&*self, stream, peer, config, pool, runtime).await;
        });
    }
}

/// Accepts from whichever of a non-empty set of listeners is ready.
pub(crate) struct Listeners {
    all: Vec<Listener>,
    next: usize,
}

impl Listeners {
    pub(crate) fn new(all: Vec<Listener>) -> Self {
        assert!(!all.is_empty(), "at least one listener is required");
        Self { all, next: 0 }
    }

    /// Wait for a client on any listener; cancel-safe, like
    /// [`TcpListener::accept`]. Each call starts polling one listener further
    /// on, so a busy listener cannot starve the others.
    pub(crate) async fn accept(&mut self) -> (&Listener, io::Result<(TcpStream, SocketAddr)>) {
        let start = self.next;
        self.next = (start + 1) % self.all.len();
        let all = &self.all;
        poll_fn(|cx| {
            for offset in 0..all.len() {
                let listener = &all[(start + offset) % all.len()];
                if let Poll::Ready(accepted) = listener.socket.poll_accept(cx) {
                    return Poll::Ready((listener, accepted));
                }
            }
            Poll::Pending
        })
        .await
    }
}

// ─── Client stream ───────────────────────────────────────────────────────────

/// Buffer size for reads from the *client*.
///
/// With `--listen-faketls-domain` a client read is a whole TLS record, and
/// `read_tls_appdata` reports a record that does not fit as `Ok(0)` — which
/// every bridge loop reads as EOF and silently ends the session. Sizing this
/// to the same tolerance the inbound handshake already accepts keeps a client
/// that emits a slightly oversized record working, for 256 bytes per
/// connection.
pub(crate) const CLIENT_READ_BUF_SIZE: usize = TLS_MAX_RECORD_PAYLOAD + TLS_READ_HEADROOM;

/// The client's side of a session, with any listener camouflage removed.
pub(crate) enum ClientReader {
    Plain(OwnedReadHalf),
    FakeTls {
        reader: OwnedReadHalf,
        pending: PendingData,
    },
}

/// Handshake bytes that arrived in the same FakeTLS record as the MTProto
/// init, returned by the first reads of the session.
#[derive(Default)]
pub(crate) struct PendingData {
    data: Vec<u8>,
    offset: usize,
}

impl PendingData {
    pub(crate) fn from_record(data: Vec<u8>, offset: usize) -> Self {
        Self { data, offset }
    }

    fn read(&mut self, buf: &mut [u8]) -> Option<usize> {
        let remaining = self.data.get(self.offset..)?;
        if remaining.is_empty() {
            return None;
        }

        let n = std::cmp::min(buf.len(), remaining.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.offset += n;
        if self.offset == self.data.len() {
            self.data = Vec::new();
            self.offset = 0;
        }
        Some(n)
    }
}

impl ClientReader {
    pub(crate) async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(buf).await,
            Self::FakeTls { reader, pending } => {
                if let Some(n) = pending.read(buf) {
                    return Ok(n);
                }

                read_tls_appdata(reader, buf).await
            }
        }
    }

    async fn drain(self) {
        match self {
            Self::Plain(mut reader) | Self::FakeTls { mut reader, .. } => {
                let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            }
        }
    }
}

pub(crate) enum ClientWriter {
    Plain(OwnedWriteHalf),
    FakeTls(OwnedWriteHalf),
}

impl ClientWriter {
    pub(crate) async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.write_all(data).await,
            Self::FakeTls(writer) => write_tls_appdata(writer, data).await,
        }
    }
}

#[cfg(test)]
mod tests;
