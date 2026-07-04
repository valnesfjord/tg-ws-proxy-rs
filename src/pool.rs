//! Pre-warmed WebSocket connection pool.
//!
//! Maintaining a small pool of idle WebSocket connections to each Telegram DC
//! eliminates the TLS + WebSocket handshake latency on the critical path of a
//! new client connection (typical saving: 100–400 ms).
//!
//! The pool is keyed by `(dc_id, is_media)`.  Background refill tasks run
//! after each pool hit to keep the bucket at `pool_size` connections.
//!
//! ## Active liveness check
//!
//! A pooled connection can go silently dead without either side ever seeing a
//! FIN/RST — e.g. a NAT/firewall mapping between us and Telegram expiring
//! while the *client* machine was asleep for a long stretch has nothing to do
//! with our end of the socket, so it looks perfectly fine to a passive check.
//! If such a connection were handed to a client, the first real write (the
//! relay-init packet) would sit in the OS send buffer until a TCP
//! retransmission timeout gives up — commonly 15-30s — before the caller
//! finds out. `get()` instead sends a WS ping and bounds the wait for any
//! response to `pool_liveness_timeout`, so a dead entry is caught and
//! discarded quickly instead of stalling the client's request.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{debug, warn};

use futures_util::{FutureExt, SinkExt, StreamExt};
use tungstenite::Message;

use crate::config::Config;
use crate::outbound::OutboundConnector;
use crate::runtime::Runtime;
use crate::ws_client::{TgWsStream, connect_ws_for_dc_with_outbound};

/// Default bound on the active liveness probe when a pool is built via
/// [`WsPool::new`] without an explicit timeout (see `with_runtime`).
const DEFAULT_LIVENESS_TIMEOUT: Duration = Duration::from_secs(1);

struct PoolEntry {
    ws: TgWsStream,
    created: Instant,
}

type Bucket = Vec<PoolEntry>;
type PoolMap = HashMap<(u32, bool), Bucket>;

pub struct WsPool {
    pool_size: usize,
    /// Maximum age for a pooled connection.  Connections older than this are
    /// discarded on next use rather than handed to a client.
    max_age: Duration,
    /// Bound on the active liveness probe performed in `get()` before a
    /// pooled connection is handed to a client. See the module docs.
    liveness_timeout: Duration,
    runtime: Arc<Runtime>,
    idle: Mutex<PoolMap>,
    /// Tracks which (dc, is_media) buckets currently have a refill in flight.
    /// Prevents a stampede of concurrent refill tasks when many clients arrive
    /// simultaneously — each `pool.get()` call spawns a refill, and without
    /// this guard they all open `pool_size` connections at once, exhausting FDs.
    ///
    /// Uses a standard (non-async) mutex because the critical section is tiny
    /// (a single HashSet insert/remove) and never holds the lock across an
    /// await point, which enables a simple Drop-based cleanup guard.
    refilling: StdMutex<HashSet<(u32, bool)>>,
}

/// RAII guard that removes a `(dc, is_media)` key from the `refilling` set
/// when dropped, guaranteeing cleanup even on early returns or panics.
struct RefillGuard<'a> {
    set: &'a StdMutex<HashSet<(u32, bool)>>,
    key: (u32, bool),
}

impl Drop for RefillGuard<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.key);
    }
}

impl WsPool {
    pub fn new(pool_size: usize, max_age: Duration) -> Self {
        Self::with_runtime(
            pool_size,
            max_age,
            Arc::new(Runtime::new(OutboundConnector::direct())),
        )
    }

    pub fn with_runtime(pool_size: usize, max_age: Duration, runtime: Arc<Runtime>) -> Self {
        Self::with_liveness_timeout(pool_size, max_age, DEFAULT_LIVENESS_TIMEOUT, runtime)
    }

    pub fn with_liveness_timeout(
        pool_size: usize,
        max_age: Duration,
        liveness_timeout: Duration,
        runtime: Arc<Runtime>,
    ) -> Self {
        Self {
            pool_size,
            max_age,
            liveness_timeout,
            runtime,
            idle: Mutex::new(HashMap::new()),
            refilling: StdMutex::new(HashSet::new()),
        }
    }

    /// Take a pre-warmed connection from the pool, if available and live.
    ///
    /// Returns `Some(ws)` on a pool hit, `None` if the bucket is empty or
    /// every entry was stale/dead.  Schedules a background refill either way.
    pub async fn get(
        self: &Arc<Self>,
        dc: u32,
        is_media: bool,
        target_ip: String,
        skip_tls_verify: bool,
    ) -> Option<TgWsStream> {
        let now = Instant::now();

        loop {
            // Pop one candidate at a time and release the lock before the
            // (potentially slow) liveness check below, so a dead entry on one
            // bucket doesn't stall `get()` calls for every other DC/media
            // bucket, which all share this single mutex.
            let mut entry = {
                let mut lock = self.idle.lock().await;
                match lock.entry((dc, is_media)).or_default().pop() {
                    Some(entry) => entry,
                    None => break,
                }
            };

            if now.saturating_duration_since(entry.created) > self.max_age {
                // Entry is stale; drop it (close happens on drop via tungstenite).
                continue;
            }

            if !Self::is_alive(&mut entry.ws, self.liveness_timeout).await {
                // Covers both an already-closed connection (the check returns
                // near-instantly) and a silently dead one that never answers
                // within `liveness_timeout` — see the module docs.
                debug!(
                    "pool: discarding dead DC{}{} connection",
                    dc,
                    if is_media { "m" } else { "" }
                );
                continue;
            }

            debug!("pool hit DC{}{}", dc, if is_media { "m" } else { "" });

            // Schedule a background task to refill the bucket.
            let pool = Arc::clone(self);
            tokio::spawn(async move {
                pool.refill(dc, is_media, target_ip, skip_tls_verify).await;
            });

            return Some(entry.ws);
        }

        // Bucket is empty (or every entry was stale/dead).
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.refill(dc, is_media, target_ip, skip_tls_verify).await;
        });

        None
    }

    /// Actively verify a pooled connection is still usable before handing it
    /// to a client, bounding the wait instead of trusting a passive check.
    /// See the module-level docs for why this matters.
    async fn is_alive(ws: &mut TgWsStream, timeout: Duration) -> bool {
        if timeout.is_zero() {
            // `--pool-liveness-timeout 0` opts out of the active probe for
            // callers who'd rather not pay even a small per-hit RTT cost.
            // Fall back to the pre-existing passive check: it only catches a
            // connection that already sent a close/error frame, not a
            // silently dead one — see the module docs.
            return ws.next().now_or_never().is_none();
        }

        if ws.send(Message::Ping(Vec::new())).await.is_err() {
            return false;
        }

        // Any successfully received frame (a Pong, or anything else) proves
        // the round trip to Telegram still works.  Timing out, an error, or
        // a graceful close all mean the entry cannot be trusted.
        matches!(
            tokio::time::timeout(timeout, ws.next()).await,
            Ok(Some(Ok(_)))
        )
    }

    /// Warm up the pool for all configured DCs on startup.
    pub async fn warmup(&self, config: &Config) {
        let dc_redirects = config.dc_redirects();
        let skip_tls = config.skip_tls_verify;
        let pool_size = self.pool_size;

        for (dc, ip) in dc_redirects {
            for is_media in [false, true] {
                let new_conns = self
                    .connect_batch(&ip, dc, is_media, skip_tls, pool_size)
                    .await;
                let mut lock = self.idle.lock().await;
                let bucket = lock.entry((dc, is_media)).or_default();

                for ws in new_conns {
                    bucket.push(PoolEntry {
                        ws,
                        created: Instant::now(),
                    });
                }
            }
        }

        debug!("WS pool warmup complete");
    }

    // ── Internal ─────────────────────────────────────────────────────────

    async fn refill(&self, dc: u32, is_media: bool, target_ip: String, skip_tls: bool) {
        // Ensure only one refill runs at a time per (dc, is_media) key.
        // Without this, a burst of simultaneous pool.get() calls spawns N
        // refill tasks that each open pool_size connections concurrently,
        // exhausting file descriptors well beyond the intended pool budget.
        let registered = self.refilling.lock().unwrap().insert((dc, is_media));
        if !registered {
            return; // another refill is already in progress for this key
        }

        // The guard removes the key from `refilling` when it goes out of scope,
        // covering all exit paths (normal return, early return, or panic).
        let _guard = RefillGuard {
            set: &self.refilling,
            key: (dc, is_media),
        };

        let needed = {
            let lock = self.idle.lock().await;

            let current = lock.get(&(dc, is_media)).map_or(0, |b| b.len());
            if current >= self.pool_size {
                return;
            }

            self.pool_size - current
        };

        let new_conns = self
            .connect_batch(&target_ip, dc, is_media, skip_tls, needed)
            .await;
        if !new_conns.is_empty() {
            let mut lock = self.idle.lock().await;
            let bucket = lock.entry((dc, is_media)).or_default();

            // Re-check available space; another path (e.g. warmup) may have
            // filled the bucket while we were connecting.  Drop any surplus
            // connections so their FDs are closed immediately.
            let can_add = self.pool_size.saturating_sub(bucket.len());
            for ws in new_conns.into_iter().take(can_add) {
                bucket.push(PoolEntry {
                    ws,
                    created: Instant::now(),
                });
            }

            debug!(
                "pool refilled DC{}{}: {} ready",
                dc,
                if is_media { "m" } else { "" },
                lock.get(&(dc, is_media)).map_or(0, |b| b.len())
            );
        }
    }

    async fn connect_batch(
        &self,
        ip: &str,
        dc: u32,
        is_media: bool,
        skip_tls: bool,
        count: usize,
    ) -> Vec<TgWsStream> {
        let mut results = Vec::new();
        // Limit pool fill timeout to avoid blocking for too long.
        let timeout = Duration::from_secs(8);
        // While the domain-fronting fallback is in its sticky window, warm the
        // pool with fronted connections too — otherwise a pool hit would hand
        // a client a connection that never had to front in the first place,
        // defeating the point of staying "sticky".
        let fronting_domain = self
            .runtime
            .fronting_active()
            .then(|| self.runtime.fronting_domain())
            .flatten();

        for _ in 0..count {
            match connect_ws_for_dc_with_outbound(
                ip,
                dc,
                is_media,
                skip_tls,
                timeout,
                self.runtime.outbound(),
                fronting_domain,
            )
            .await
            {
                (Some(ws), _, _) => results.push(ws),
                (None, _, _) => {
                    warn!(
                        "pool: failed to pre-connect DC{}{}",
                        dc,
                        if is_media { "m" } else { "" }
                    );

                    break;
                }
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::MaybeTlsStream;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    /// Connect a plain (non-TLS) `TgWsStream` to a local WS server, wrapped
    /// in `MaybeTlsStream::Plain` so the type matches production pooled
    /// entries without needing a real TLS handshake in tests.
    async fn connect_plain_ws(addr: std::net::SocketAddr) -> TgWsStream {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let request = format!("ws://{addr}/apiws").into_client_request().unwrap();
        let (ws, _response) = tokio_tungstenite::client_async(request, MaybeTlsStream::Plain(tcp))
            .await
            .unwrap();
        ws
    }

    fn make_pool(liveness_timeout: Duration) -> Arc<WsPool> {
        Arc::new(WsPool::with_liveness_timeout(
            1,
            Duration::from_secs(60),
            liveness_timeout,
            Arc::new(Runtime::new(OutboundConnector::direct())),
        ))
    }

    async fn seed_entry(pool: &Arc<WsPool>, dc: u32, is_media: bool, ws: TgWsStream) {
        pool.idle
            .lock()
            .await
            .entry((dc, is_media))
            .or_default()
            .push(PoolEntry {
                ws,
                created: Instant::now(),
            });
    }

    #[tokio::test]
    async fn get_discards_a_silently_dead_connection_within_the_liveness_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server accepts the WS upgrade, then goes silent — never reads or
        // writes again, simulating a connection that's dead from Telegram's
        // side without ever sending a close frame.
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            std::future::pending::<()>().await;
        });

        let pool = make_pool(Duration::from_millis(150));
        seed_entry(&pool, 2, false, connect_plain_ws(addr).await).await;

        let start = Instant::now();
        let result = pool.get(2, false, "203.0.113.10".to_string(), false).await;
        let elapsed = start.elapsed();

        assert!(result.is_none(), "dead connection should be discarded");
        assert!(
            elapsed < Duration::from_secs(2),
            "get() took {elapsed:?}, should bail out within the liveness timeout"
        );

        server.abort();
    }

    #[tokio::test]
    async fn get_returns_a_connection_that_answers_the_liveness_ping() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server accepts the WS upgrade, reads the incoming ping, and
        // explicitly replies with a Pong so the client-side liveness check
        // sees a real flushed response rather than relying on tungstenite's
        // internal auto-queued reply (which isn't flushed until the next
        // write anyway).
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            if let Some(Ok(Message::Ping(payload))) = ws.next().await {
                let _ = ws.send(Message::Pong(payload)).await;
            }
            std::future::pending::<()>().await;
        });

        let pool = make_pool(Duration::from_millis(500));
        seed_entry(&pool, 2, false, connect_plain_ws(addr).await).await;

        let result = pool.get(2, false, "203.0.113.10".to_string(), false).await;

        assert!(
            result.is_some(),
            "a connection that answers the ping should still be handed out"
        );

        server.abort();
    }

    #[tokio::test]
    async fn zero_liveness_timeout_skips_the_active_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server never sends anything — with the active probe this would be
        // discarded, but a liveness_timeout of 0 opts back into the old
        // passive-only check, which has nothing to detect here (no
        // close/error frame was ever sent), so the entry is handed out as-is.
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            std::future::pending::<()>().await;
        });

        let pool = make_pool(Duration::ZERO);
        seed_entry(&pool, 2, false, connect_plain_ws(addr).await).await;

        let result = pool.get(2, false, "203.0.113.10".to_string(), false).await;

        assert!(
            result.is_some(),
            "pool-liveness-timeout=0 should skip the active probe entirely"
        );

        server.abort();
    }
}
