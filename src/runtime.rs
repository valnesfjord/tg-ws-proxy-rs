//! Shared per-process runtime state.
//!
//! Holds what every connection needs but nothing owns: the outbound connector
//! and the domain-fronting fallback's sticky window.  The DC lookups are
//! stateless pass-throughs to `config`, kept as methods so call sites can take
//! everything they need from one place.

use std::net::IpAddr;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use crate::config::{default_dc_ip, websocket_dc};
use crate::outbound::OutboundConnector;

/// Default sticky window for the domain-fronting fallback.
const DEFAULT_FRONTING_COOLDOWN: Duration = Duration::from_secs(1800);

pub struct Runtime {
    outbound: OutboundConnector,
    /// Preferred Cloudflare edges from `--cf-ip`. Empty means DNS picks the
    /// anycast edge as usual.
    cf_ips: Vec<IpAddr>,
    /// Domain-fronting SNI, when enabled via `--fronting-domain`. `None` means
    /// the fallback is disabled entirely (the default).
    fronting_domain: Option<String>,
    /// How long the fronting fallback stays "sticky" after last succeeding.
    fronting_cooldown: Duration,
    /// Shared with `pool.rs`'s background refill (unlike the per-DC cooldowns
    /// in `proxy.rs`, which only that module's own fallback logic needs),
    /// which is why this lives on `Runtime` instead of a `proxy.rs` static.
    fronting_until: StdMutex<Option<Instant>>,
}

impl Runtime {
    pub fn new(outbound: OutboundConnector) -> Self {
        Self {
            outbound,
            cf_ips: Vec::new(),
            fronting_domain: None,
            fronting_cooldown: DEFAULT_FRONTING_COOLDOWN,
            fronting_until: StdMutex::new(None),
        }
    }

    /// Configure preferred Cloudflare edges (`--cf-ip`).
    pub fn with_cf_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.cf_ips = ips;
        self
    }

    /// Configure the domain-fronting fallback. `domain: None` keeps it disabled.
    pub fn with_fronting(mut self, domain: Option<String>, cooldown: Duration) -> Self {
        self.fronting_domain = domain;
        self.fronting_cooldown = cooldown;
        self
    }

    pub fn outbound(&self) -> &OutboundConnector {
        &self.outbound
    }

    pub fn cf_ips(&self) -> &[IpAddr] {
        &self.cf_ips
    }

    pub fn websocket_dc(&self, dc: u32) -> u32 {
        websocket_dc(dc)
    }

    pub fn fallback_ip(&self, dc: u32) -> Option<&'static str> {
        default_dc_ip(dc)
    }

    /// The configured fronting SNI, if the fallback is enabled.
    pub fn fronting_domain(&self) -> Option<&str> {
        self.fronting_domain.as_deref()
    }

    /// Whether the fronting fallback is currently in its sticky window.
    pub fn fronting_active(&self) -> bool {
        matches!(*self.fronting_until.lock().unwrap(), Some(until) if Instant::now() < until)
    }

    /// Mark the fronting fallback as active for another `fronting_cooldown`
    /// from now (called after a successful fronted connection).
    pub fn activate_fronting(&self) {
        *self.fronting_until.lock().unwrap() = Some(Instant::now() + self.fronting_cooldown);
    }

    /// Clear the sticky window (called after a fronted connection fails).
    pub fn deactivate_fronting(&self) {
        *self.fronting_until.lock().unwrap() = None;
    }
}
