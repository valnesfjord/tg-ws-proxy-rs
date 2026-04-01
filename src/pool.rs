//! Pre-warmed WebSocket connection pool.
//!
//! Maintaining a small pool of idle WebSocket connections to each Telegram DC
//! eliminates the TLS + WebSocket handshake latency on the critical path of a
//! new client connection (typical saving: 100–400 ms).
//!
//! The pool is keyed by `(dc_id, is_media)`.  Background refill tasks run
//! after each pool hit to keep the bucket at `pool_size` connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::Config;
use crate::ws_client::{connect_ws_for_dc, TgWsStream};

// Age limit for pooled connections.  An idle connection older than this is
// discarded rather than handed to a client (Telegram closes idle WS in ~2 min).
const MAX_AGE: Duration = Duration::from_secs(120);

struct PoolEntry {
    ws: TgWsStream,
    created: Instant,
}

type Bucket = Vec<PoolEntry>;
type PoolMap = HashMap<(u32, bool), Bucket>;

pub struct WsPool {
    pool_size: usize,
    idle: Mutex<PoolMap>,
}

impl WsPool {
    pub fn new(pool_size: usize) -> Self {
        Self {
            pool_size,
            idle: Mutex::new(HashMap::new()),
        }
    }

    /// Take a pre-warmed connection from the pool, if available and fresh.
    ///
    /// Returns `Some(ws)` on a pool hit, `None` if the bucket is empty or
    /// all entries were stale.  Schedules a background refill either way.
    pub async fn get(
        self: &Arc<Self>,
        dc: u32,
        is_media: bool,
        target_ip: String,
        skip_tls_verify: bool,
    ) -> Option<TgWsStream> {
        let now = Instant::now();
        let mut lock = self.idle.lock().await;
        let bucket = lock.entry((dc, is_media)).or_default();

        // Drain from the back (LIFO) so the freshest connections are used first.
        while let Some(entry) = bucket.pop() {
            if now.saturating_duration_since(entry.created) > MAX_AGE {
                // Entry is stale; drop it (close happens on drop via tungstenite).
                continue;
            }
            let remaining = bucket.len();
            drop(lock);

            debug!(
                "pool hit DC{}{} ({} left)",
                dc,
                if is_media { "m" } else { "" },
                remaining
            );

            // Schedule a background task to refill the bucket.
            let pool = Arc::clone(self);
            tokio::spawn(async move {
                pool.refill(dc, is_media, target_ip, skip_tls_verify).await;
            });

            return Some(entry.ws);
        }

        // Bucket is empty (or fully stale).
        drop(lock);
        let pool = Arc::clone(self);
        tokio::spawn(async move {
            pool.refill(dc, is_media, target_ip, skip_tls_verify).await;
        });
        None
    }

    /// Warm up the pool for all configured DCs on startup.
    pub async fn warmup(&self, config: &Config) {
        let dc_redirects = config.dc_redirects();
        let skip_tls = config.skip_tls_verify;
        let pool_size = self.pool_size;

        for (dc, ip) in dc_redirects {
            for is_media in [false, true] {
                let new_conns =
                    Self::connect_batch(&ip, dc, is_media, skip_tls, pool_size).await;
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
        let needed = {
            let lock = self.idle.lock().await;
            let current = lock.get(&(dc, is_media)).map_or(0, |b| b.len());
            if current >= self.pool_size {
                return;
            }
            self.pool_size - current
        };

        let new_conns = Self::connect_batch(&target_ip, dc, is_media, skip_tls, needed).await;
        if !new_conns.is_empty() {
            let mut lock = self.idle.lock().await;
            let bucket = lock.entry((dc, is_media)).or_default();
            for ws in new_conns {
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
        ip: &str,
        dc: u32,
        is_media: bool,
        skip_tls: bool,
        count: usize,
    ) -> Vec<TgWsStream> {
        let mut results = Vec::new();
        // Limit pool fill timeout to avoid blocking for too long.
        let timeout = Duration::from_secs(8);

        for _ in 0..count {
            match connect_ws_for_dc(ip, dc, is_media, skip_tls, timeout).await {
                (Some(ws), _) => results.push(ws),
                (None, _) => {
                    warn!("pool: failed to pre-connect DC{}{}", dc, if is_media { "m" } else { "" });
                    break;
                }
            }
        }
        results
    }
}
