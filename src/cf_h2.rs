//! Telegram's HTTP endpoint accepts bare MTProto envelopes, without transport
//! headers or obfuscation. Each POST supplies one receive opportunity for that
//! session; multiplexing these requests avoids a TLS socket per media client.
//!
//! Lanes live in Runtime, so embedders cannot reuse sockets after restart or
//! across outbound configurations. Flow control, bounded request concurrency,
//! and a shared byte budget keep slow clients from growing unbounded buffers.

use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use cipher::StreamCipher;
use futures_util::{StreamExt, stream::FuturesUnordered};
use h2::client::SendRequest;
use http::{Method, Request};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};

use crate::crypto::{AesCtr256, ProtoTag};
use crate::inbound::{CLIENT_READ_BUF_SIZE, ClientReader, ClientWriter};
use crate::runtime::Runtime;
use crate::ws_client::{cf_ip_start, no_verify_rustls_config, verifying_rustls_config};

const MAX_PACKET: usize = 4 * 1024 * 1024;
const LANE_BYTES: usize = 16 * 1024 * 1024;
const LANE_REQUESTS: usize = 16;
const CHANNEL_REQUESTS: usize = 4;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const REPLAY_BYTES: usize = 64 * 1024;

type Result<T> = std::result::Result<T, String>;
type LaneSlot = Arc<Mutex<Slot>>;

#[derive(Default)]
pub(crate) struct Pool {
    lanes: Mutex<HashMap<(String, bool), LaneSlot>>,
}

#[derive(Default)]
struct Slot {
    lane: Option<Arc<Lane>>,
    failed_until: Option<Instant>,
}

pub(crate) struct Lane {
    host: String,
    sender: SendRequest<Bytes>,
    driver: JoinHandle<()>,
    requests: Arc<Semaphore>,
    bytes: Arc<Semaphore>,
    failed_until: StdMutex<Option<Instant>>,
    cooldown: Duration,
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Pool {
    pub(crate) async fn open(
        &self,
        host: &str,
        runtime: &Runtime,
        skip_verify: bool,
        connect_timeout: Duration,
    ) -> Result<Arc<Lane>> {
        let slot = self
            .lanes
            .lock()
            .await
            .entry((host.to_owned(), skip_verify))
            .or_default()
            .clone();
        timeout(connect_timeout, async {
            let mut slot = slot.lock().await;
            let cooling = slot.failed_until.or_else(|| {
                slot.lane
                    .as_ref()
                    .and_then(|lane| *lane.failed_until.lock().unwrap())
            });
            if cooling.is_some_and(|until| until > Instant::now()) {
                return Err("HTTP/2 domain in cooldown".into());
            }
            if let Some(lane) = &slot.lane
                && !lane.driver.is_finished()
                && lane.failed_until.lock().unwrap().is_none()
            {
                return Ok(lane.clone());
            }
            slot.lane = None;
            // Set this before awaiting: cancellation of a stalled preflight must
            // also suppress a new handshake for every arriving media client.
            slot.failed_until = Some(Instant::now() + connect_timeout + runtime.cf_fail_cooldown());
            match Lane::connect(host, runtime, skip_verify, connect_timeout).await {
                Ok(lane) => {
                    slot.failed_until = None;
                    slot.lane = Some(lane.clone());
                    Ok(lane)
                }
                Err(error) => {
                    slot.failed_until = Some(Instant::now() + runtime.cf_fail_cooldown());
                    Err(error)
                }
            }
        })
        .await
        .map_err(|_| "HTTP/2 setup timed out".to_string())?
    }
}

fn tls_config(skip_verify: bool) -> Arc<rustls::ClientConfig> {
    static VERIFY: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    static INSECURE: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    (if skip_verify { &INSECURE } else { &VERIFY })
        .get_or_init(|| {
            let mut config = (*if skip_verify {
                no_verify_rustls_config()
            } else {
                verifying_rustls_config()
            })
            .clone();
            config.alpn_protocols = vec![b"h2".to_vec()];
            Arc::new(config)
        })
        .clone()
}

impl Lane {
    async fn connect(
        host: &str,
        runtime: &Runtime,
        skip_verify: bool,
        budget: Duration,
    ) -> Result<Arc<Self>> {
        let ips = runtime.cf_ips();
        let first = cf_ip_start(ips);
        let mut error = "no HTTP/2 edge available".to_string();
        for offset in 0..ips.len().max(1) {
            let target = if ips.is_empty() {
                host.to_string()
            } else {
                ips[(first + offset) % ips.len()].to_string()
            };
            let edge_budget = budget / ips.len().max(1) as u32;
            let attempt = timeout(edge_budget, async {
                let tcp = runtime
                    .outbound()
                    .connect(&target, 443, edge_budget)
                    .await
                    .map_err(|e| e.to_string())?;
                tcp.set_nodelay(true).map_err(|e| e.to_string())?;
                let name = rustls_pki_types::ServerName::try_from(host.to_owned())
                    .map_err(|e| e.to_string())?;
                let tls = tokio_rustls::TlsConnector::from(tls_config(skip_verify))
                    .connect(name, tcp)
                    .await
                    .map_err(|e| e.to_string())?;
                if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
                    return Err("server did not negotiate HTTP/2".into());
                }
                let (sender, connection) = h2::client::Builder::new()
                    .initial_window_size(256 * 1024)
                    .initial_connection_window_size(1024 * 1024)
                    .max_concurrent_streams(0)
                    .max_header_list_size(16 * 1024)
                    .enable_push(false)
                    .handshake(tls)
                    .await
                    .map_err(|e| e.to_string())?;
                let lane = Arc::new(Self {
                    host: host.to_string(),
                    sender,
                    driver: tokio::spawn(async move {
                        let _ = connection.await;
                    }),
                    requests: Arc::new(Semaphore::new(LANE_REQUESTS)),
                    bytes: Arc::new(Semaphore::new(LANE_BYTES)),
                    failed_until: StdMutex::new(None),
                    cooldown: runtime.cf_fail_cooldown(),
                });
                lane.preflight().await?;
                Ok(lane)
            })
            .await;
            match attempt {
                Ok(Ok(lane)) => return Ok(lane),
                Ok(Err(e)) => error = e,
                Err(_) => error = "HTTP/2 edge timed out".into(),
            }
        }
        Err(error)
    }

    fn request(&self, method: Method) -> http::request::Builder {
        Request::builder()
            .method(method)
            .uri(format!("https://{}/api", self.host))
    }

    async fn preflight(&self) -> Result<()> {
        let mut sender = self
            .sender
            .clone()
            .ready()
            .await
            .map_err(|e| e.to_string())?;
        let request = self
            .request(Method::HEAD)
            .body(())
            .map_err(|e| e.to_string())?;
        let (response, _) = sender
            .send_request(request, true)
            .map_err(|e| e.to_string())?;
        let status = response.await.map_err(|e| e.to_string())?.status();
        // Telegram can reject HEAD even when POST works. Match upstream's
        // preflight, but do not treat redirects as an available /api endpoint.
        if status.is_redirection()
            || matches!(status.as_u16(), 403 | 429)
            || (status.is_server_error() && status.as_u16() != 501)
        {
            return Err(format!("HTTP/2 preflight returned {status}"));
        }
        Ok(())
    }

    fn prepare(&self, bytes: Bytes) -> Result<Upload> {
        let budget = self
            .bytes
            .clone()
            .try_acquire_many_owned(bytes.len() as u32)
            .map_err(|_| "HTTP/2 upload byte budget exhausted".to_string())?;
        Ok(Upload { bytes, budget })
    }

    async fn post(self: Arc<Self>, body: Upload, receiving: Arc<AtomicUsize>) -> Result<Reply> {
        let result = timeout(REQUEST_TIMEOUT, self.exchange(body, receiving))
            .await
            .map_err(|_| "HTTP/2 request timed out".to_string())
            .and_then(|r| r);
        if result.is_err() {
            *self.failed_until.lock().unwrap() = Some(Instant::now() + self.cooldown);
        }
        result
    }

    async fn exchange(&self, upload: Upload, receiving: Arc<AtomicUsize>) -> Result<Reply> {
        let Upload {
            bytes: mut body,
            budget: upload,
        } = upload;
        let slot = self
            .requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| e.to_string())?;
        let request = self
            .request(Method::POST)
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .header("content-length", body.len())
            .body(())
            .map_err(|e| e.to_string())?;
        let mut sender = self
            .sender
            .clone()
            .ready()
            .await
            .map_err(|e| e.to_string())?;
        let (response, stream) = sender
            .send_request(request, false)
            .map_err(|e| e.to_string())?;
        let mut stream = ResetOnDrop(stream);
        while !body.is_empty() {
            stream.0.reserve_capacity(body.len().min(16 * 1024));
            let capacity = poll_fn(|cx| stream.0.poll_capacity(cx))
                .await
                .ok_or("HTTP/2 upload closed")?
                .map_err(|e| e.to_string())?;
            let take = capacity.min(body.len()).min(16 * 1024);
            if take == 0 {
                continue;
            }
            let chunk = body.split_to(take);
            stream
                .0
                .send_data(chunk, body.is_empty())
                .map_err(|e| e.to_string())?;
        }
        drop(upload);
        let response = response.await.map_err(|e| e.to_string())?;
        if response.status() != http::StatusCode::OK {
            return Err(format!("HTTP/2 POST returned {}", response.status()));
        }
        if response
            .headers()
            .get("content-encoding")
            .is_some_and(|v| v != "identity")
        {
            return Err("compressed HTTP/2 response is unsupported".into());
        }
        let declared = response
            .headers()
            .get("content-length")
            .map(|v| {
                v.to_str()
                    .ok()
                    .and_then(|v| v.parse::<usize>().ok())
                    .ok_or("invalid content-length")
            })
            .transpose()?;
        if declared.is_some_and(|n| n > MAX_PACKET) {
            return Err("HTTP/2 response too large".into());
        }
        receiving.fetch_add(1, Ordering::Relaxed);
        let _receiving = Receiving(receiving);
        let mut receive = response.into_body();
        let mut bytes = Vec::new();
        let mut budget = self.bytes.clone().try_acquire_many_owned(0).unwrap();
        while let Some(chunk) = receive.data().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            if bytes.len() + chunk.len() > MAX_PACKET {
                return Err("HTTP/2 response too large".into());
            }
            budget.merge(
                self.bytes
                    .clone()
                    .try_acquire_many_owned(chunk.len() as u32)
                    .map_err(|_| "HTTP/2 response byte budget exhausted".to_string())?,
            );
            bytes.extend_from_slice(&chunk);
            receive
                .flow_control()
                .release_capacity(chunk.len())
                .map_err(|e| e.to_string())?;
        }
        if declared.is_some_and(|n| n != bytes.len()) || !bytes.len().is_multiple_of(4) {
            return Err("invalid HTTP/2 response length".into());
        }
        Ok(Reply {
            bytes,
            _budget: budget,
            _slot: slot,
        })
    }
}

// Dropping a completed upload alone does not reset a response still in flight.
// Explicit cancellation also releases peer resources on timeout/client EOF.
struct ResetOnDrop(h2::SendStream<Bytes>);
impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        self.0.send_reset(h2::Reason::CANCEL);
    }
}
struct Receiving(Arc<AtomicUsize>);
impl Drop for Receiving {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
struct Upload {
    bytes: Bytes,
    // Charged before enqueueing, including while waiting for an H2 stream.
    budget: OwnedSemaphorePermit,
}
struct Reply {
    bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
    _slot: OwnedSemaphorePermit,
}

struct PacketReader {
    reader: ClientReader,
    cipher: Option<AesCtr256>,
    buffer: Vec<u8>,
    offset: usize,
    filled: usize,
}

impl PacketReader {
    async fn read_exact(&mut self, dst: &mut [u8]) -> io::Result<()> {
        let mut written = 0;
        while written < dst.len() {
            if self.offset == self.filled {
                self.filled = self.reader.read(&mut self.buffer).await?;
                self.offset = 0;
                if self.filled == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                if let Some(cipher) = &mut self.cipher {
                    cipher.apply_keystream(&mut self.buffer[..self.filled]);
                }
            }
            let take = (dst.len() - written).min(self.filled - self.offset);
            dst[written..written + take]
                .copy_from_slice(&self.buffer[self.offset..self.offset + take]);
            written += take;
            self.offset += take;
        }
        Ok(())
    }

    async fn packet(&mut self, proto: ProtoTag) -> Result<Bytes> {
        let mut header = [0; 4];
        let length = if proto == ProtoTag::Abridged {
            self.read_exact(&mut header[..1])
                .await
                .map_err(|e| e.to_string())?;
            let words = if header[0] & 0x7f == 0x7f {
                self.read_exact(&mut header[..3])
                    .await
                    .map_err(|e| e.to_string())?;
                u32::from_le_bytes(header) as usize
            } else {
                usize::from(header[0] & 0x7f)
            };
            words * 4
        } else {
            self.read_exact(&mut header)
                .await
                .map_err(|e| e.to_string())?;
            (u32::from_le_bytes(header) & 0x7fff_ffff) as usize
        };
        let padding = if proto == ProtoTag::PaddedIntermediate {
            15
        } else {
            0
        };
        if !(24..=MAX_PACKET + padding).contains(&length) {
            return Err("invalid native MTProto packet length".into());
        }
        let mut body = vec![0; length];
        self.read_exact(&mut body)
            .await
            .map_err(|e| e.to_string())?;
        strip_padding(&mut body, proto)?;
        Ok(Bytes::from(body))
    }
}

fn strip_padding(body: &mut Vec<u8>, proto: ProtoTag) -> Result<()> {
    if proto == ProtoTag::PaddedIntermediate {
        let length = if body[..8] == [0; 8] {
            20usize
                .checked_add(u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize)
                .ok_or("invalid unencrypted MTProto length")?
        } else {
            24 + (body.len() - 24) / 16 * 16
        };
        if length < 24 || length > body.len() || body.len() - length > 15 {
            return Err("invalid padded MTProto packet".into());
        }
        body.truncate(length);
    }
    if !body.len().is_multiple_of(4) || body.len() > MAX_PACKET {
        return Err("invalid MTProto packet alignment".into());
    }
    Ok(())
}

fn reply_header(length: usize, proto: ProtoTag) -> Vec<u8> {
    if proto == ProtoTag::Abridged {
        let words = length / 4;
        if words < 127 {
            vec![words as u8]
        } else {
            let mut header = (words as u32).to_le_bytes();
            header.rotate_right(1);
            header[0] = 0x7f;
            header.to_vec()
        }
    } else {
        // Zero padding is legal for padded-intermediate; HTTP already hides
        // packet boundaries under TLS, and no random allocation is needed.
        (length as u32).to_le_bytes().to_vec()
    }
}

pub(crate) async fn bridge(
    reader: ClientReader,
    mut writer: ClientWriter,
    lane: Arc<Lane>,
    proto: ProtoTag,
    dec: Option<AesCtr256>,
    mut enc: Option<AesCtr256>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    let upload_lane = lane.clone();
    let upload = async move {
        let mut reader = PacketReader {
            reader,
            cipher: dec,
            buffer: vec![0; CLIENT_READ_BUF_SIZE],
            offset: 0,
            filled: 0,
        };
        loop {
            let packet = reader.packet(proto).await?;
            let packet = upload_lane.prepare(packet)?;
            tx.send(packet)
                .await
                .map_err(|_| "HTTP/2 channel closed".to_string())?;
        }
    };
    let download = async {
        let mut pending = FuturesUnordered::new();
        let receiving = Arc::new(AtomicUsize::new(0));
        let mut replay: Option<(Bytes, Instant, usize)> = None;
        let mut progress = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                packet = rx.recv(), if pending.len() < CHANNEL_REQUESTS - 1 => {
                    let Some(packet) = packet else { return Ok(()); };
                    // An HTTP response may only acknowledge a request, leaving
                    // the RPC reply queued. Reposting the same encrypted message
                    // opens another receive slot; Telegram deduplicates msg_id.
                    // Never replay auth-key setup or retain media upload bodies.
                    replay = if packet.bytes.len() <= REPLAY_BYTES && packet.bytes[..8] != [0; 8] {
                        Some((packet.bytes.clone(), Instant::now(), 0))
                    } else { None };
                    progress = Instant::now();
                    pending.push(lane.clone().post(packet, receiving.clone()));
                }
                reply = pending.next(), if !pending.is_empty() => {
                    let mut reply = reply.unwrap()?;
                    if !reply.bytes.is_empty() {
                        let mut header = reply_header(reply.bytes.len(), proto);
                        if let Some(cipher) = &mut enc { cipher.apply_keystream(&mut header); }
                        writer.write_all(&header).await.map_err(|e| e.to_string())?;
                        for chunk in reply.bytes.chunks_mut(16 * 1024) {
                            if let Some(cipher) = &mut enc { cipher.apply_keystream(chunk); }
                            writer.write_all(chunk).await.map_err(|e| e.to_string())?;
                        }
                    }
                    progress = Instant::now();
                }
                _ = tick.tick(), if pending.len() < CHANNEL_REQUESTS => {
                    let delay = if pending.is_empty() { 1 } else { 3 };
                    if receiving.load(Ordering::Relaxed) == 0 && progress.elapsed() >= Duration::from_secs(delay)
                        && let Some((body, created, attempts)) = &mut replay
                        && *attempts < 3 && created.elapsed() < Duration::from_secs(30)
                        && let Ok(packet) = lane.prepare(body.clone())
                    {
                        pending.push(lane.clone().post(packet, receiving.clone()));
                        *attempts += 1;
                        progress = Instant::now();
                    }
                }
            }
        }
    };
    tokio::select! {
        result = upload => result,
        result = download => result,
    }
}

#[cfg(test)]
mod tests;
