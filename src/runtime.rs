//! Shared per-process runtime state.
//!
//! Holds what every connection needs: the outbound connector, shared HTTP/2
//! media lanes, and the always-on domain-fronting SNI. The DC lookups are stateless
//! pass-throughs to `config`, kept as methods so call sites can take
//! everything they need from one place.

use std::net::IpAddr;
use std::time::Duration;

use crate::config::{default_dc_ip, websocket_dc};
use crate::outbound::OutboundConnector;

pub struct Runtime {
    pub(crate) h2: crate::cf_h2::Pool,
    outbound: OutboundConnector,
    /// Preferred Cloudflare edges from `--cf-ip`. Empty means DNS picks the
    /// anycast edge as usual.
    cf_ips: Vec<IpAddr>,
    cf_fail_cooldown: Duration,
    /// Domain-fronting SNI, when enabled via `--fronting-domain`. `None` means
    /// fronting is disabled entirely; `Some` means every direct-WebSocket
    /// connect presents it as the SNI — unconditionally, with no trigger
    /// conditions and no cooldown windows (see #111: a reactive switch sends
    /// the real `telegram.org` SNI first, which networks that RST it on sight
    /// never let through).
    fronting_domain: Option<String>,
}

impl Runtime {
    pub fn new(outbound: OutboundConnector) -> Self {
        Self {
            h2: crate::cf_h2::Pool::default(),
            outbound,
            cf_ips: Vec::new(),
            cf_fail_cooldown: Duration::from_secs(60),
            fronting_domain: None,
        }
    }

    /// Configure preferred Cloudflare edges (`--cf-ip`).
    pub fn with_cf_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.cf_ips = ips;
        self
    }

    pub fn with_cf_fail_cooldown(mut self, cooldown: Duration) -> Self {
        self.cf_fail_cooldown = cooldown;
        self
    }

    /// Configure domain fronting. `domain: None` keeps it disabled.
    pub fn with_fronting(mut self, domain: Option<String>) -> Self {
        self.fronting_domain = domain;
        self
    }

    pub fn outbound(&self) -> &OutboundConnector {
        &self.outbound
    }

    pub fn cf_ips(&self) -> &[IpAddr] {
        &self.cf_ips
    }

    pub fn cf_fail_cooldown(&self) -> Duration {
        self.cf_fail_cooldown
    }

    pub fn websocket_dc(&self, dc: u32) -> u32 {
        websocket_dc(dc)
    }

    pub fn fallback_ip(&self, dc: u32) -> Option<&'static str> {
        default_dc_ip(dc)
    }

    /// The configured fronting SNI, if fronting is enabled.
    pub fn fronting_domain(&self) -> Option<&str> {
        self.fronting_domain.as_deref()
    }
}
