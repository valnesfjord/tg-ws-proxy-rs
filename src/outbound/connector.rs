use std::borrow::Cow;
use std::net::IpAddr;
use std::time::Duration;

use async_http_proxy::{http_connect_tokio, http_connect_tokio_with_basic_auth};
use tokio::net::{TcpStream, lookup_host};
use tokio_socks::TargetAddr;
use tokio_socks::tcp::Socks5Stream;

use super::config::{OutboundConfig, ProxyConfig, ProxyKind};

/// Why an outbound connect failed.
///
/// The distinction is load-bearing: a refusal or reset means the address
/// answered, while a timeout means nothing did — the signature of a
/// DPI-blocked address, which the routing ladder treats very differently from
/// an address that merely said no.  Carried as a flag rather than parsed back
/// out of the message, whose wording varies by platform and proxy kind.
#[derive(Debug, Clone)]
pub struct OutboundError {
    pub reason: String,
    pub timed_out: bool,
}

impl OutboundError {
    fn failed(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            timed_out: false,
        }
    }

    fn timed_out(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            timed_out: true,
        }
    }
}

impl std::fmt::Display for OutboundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for OutboundError {}

pub struct OutboundConnector {
    config: OutboundConfig,
    mark: Option<u32>,
}

impl OutboundConnector {
    pub fn direct() -> Self {
        Self {
            config: OutboundConfig {
                proxy: None,
                no_proxy: None,
            },
            mark: None,
        }
    }

    pub fn from_config(
        outbound_proxy: Option<&str>,
        no_proxy: Option<&str>,
        use_env: bool,
    ) -> Result<Self, String> {
        Ok(Self {
            config: OutboundConfig::from_sources(outbound_proxy, no_proxy, use_env)?,
            mark: None,
        })
    }

    /// Apply a Linux SO_MARK before connecting, including connections to proxies.
    pub fn with_mark(mut self, mark: Option<u32>) -> Result<Self, String> {
        if mark.is_some() && !cfg!(target_os = "linux") {
            return Err("outbound marks are only supported on Linux".into());
        }
        self.mark = mark;
        Ok(self)
    }

    pub fn summary(&self) -> Option<String> {
        self.config.proxy.as_ref().map(ProxyConfig::summary)
    }

    pub(crate) fn connects_directly(&self, target_host: &str, target_port: u16) -> bool {
        self.config.proxy.is_none() || self.should_bypass(target_host, target_port)
    }

    pub async fn connect(
        &self,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, OutboundError> {
        let Some(proxy) = &self.config.proxy else {
            return connect_direct(target_host, target_port, timeout, self.mark).await;
        };

        if self.should_bypass(target_host, target_port) {
            return connect_direct(target_host, target_port, timeout, self.mark).await;
        }

        match tokio::time::timeout(
            timeout,
            connect_via_proxy(proxy, target_host, target_port, self.mark),
        )
        .await
        {
            Ok(result) => result.map_err(OutboundError::failed),
            Err(_) => Err(OutboundError::timed_out(format!(
                "proxy {} handshake timed out",
                proxy.summary()
            ))),
        }
    }

    fn should_bypass(&self, target_host: &str, target_port: u16) -> bool {
        self.config
            .no_proxy
            .as_ref()
            .is_some_and(|no_proxy| no_proxy.matches(target_host, target_port))
    }
}

async fn connect_direct(
    host: &str,
    port: u16,
    timeout: Duration,
    mark: Option<u32>,
) -> Result<TcpStream, OutboundError> {
    match tokio::time::timeout(timeout, connect_tcp(host, port, mark)).await {
        Ok(result) => result.map_err(OutboundError::failed),
        Err(_) => Err(OutboundError::timed_out("TCP connect timed out")),
    }
}

async fn connect_via_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    mark: Option<u32>,
) -> Result<TcpStream, String> {
    match proxy.kind {
        ProxyKind::Http => connect_http_proxy(proxy, target_host, target_port, mark)
            .await
            .map_err(|e| format!("HTTP proxy {}: {e}", proxy.summary())),
        ProxyKind::Socks5 { remote_dns } => {
            connect_socks5_proxy(proxy, target_host, target_port, remote_dns, mark)
                .await
                .map_err(|e| format!("SOCKS5 proxy {}: {e}", proxy.summary()))
        }
    }
}

async fn connect_http_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    mark: Option<u32>,
) -> Result<TcpStream, String> {
    let mut stream = connect_tcp(&proxy.host, proxy.port, mark).await?;
    let target_host = if target_host.contains(':') && !target_host.starts_with('[') {
        Cow::Owned(format!("[{target_host}]"))
    } else {
        Cow::Borrowed(target_host)
    };

    if let Some(username) = proxy.username.as_deref() {
        http_connect_tokio_with_basic_auth(
            &mut stream,
            &target_host,
            target_port,
            username,
            proxy.password.as_deref().unwrap_or(""),
        )
        .await
    } else {
        http_connect_tokio(&mut stream, &target_host, target_port).await
    }
    .map_err(|e| e.to_string())?;

    Ok(stream)
}

async fn connect_socks5_proxy(
    proxy: &ProxyConfig,
    target_host: &str,
    target_port: u16,
    remote_dns: bool,
    mark: Option<u32>,
) -> Result<TcpStream, String> {
    let target = socks5_target(target_host, target_port, remote_dns).await?;
    let socket = connect_tcp(&proxy.host, proxy.port, mark).await?;

    let stream = if let Some(username) = proxy.username.as_deref() {
        Socks5Stream::connect_with_password_and_socket(
            socket,
            target,
            username,
            proxy.password.as_deref().unwrap_or(""),
        )
        .await
    } else {
        Socks5Stream::connect_with_socket(socket, target).await
    }
    .map_err(|e| e.to_string())?;

    Ok(stream.into_inner())
}

async fn connect_tcp(host: &str, port: u16, mark: Option<u32>) -> Result<TcpStream, String> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = mark {
        let mut last_error = "TCP lookup returned no addresses".to_string();
        for addr in lookup_host((host, port))
            .await
            .map_err(|e| format!("TCP lookup: {e}"))?
        {
            let socket = match if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()
            } else {
                tokio::net::TcpSocket::new_v6()
            } {
                Ok(socket) => socket,
                Err(error) => {
                    last_error = format!("TCP socket: {error}");
                    continue;
                }
            };
            // The first SYN must already carry the mark to avoid routing loops.
            socket2::SockRef::from(&socket)
                .set_mark(mark)
                .map_err(|e| {
                    format!(
                        "SO_MARK {mark}: {e} (requires CAP_NET_ADMIN or CAP_NET_RAW on Linux 5.17+)"
                    )
                })?;
            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = format!("TCP connect: {error}"),
            }
        }
        return Err(last_error);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;

    TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("TCP connect: {e}"))
}

async fn socks5_target<'a>(
    host: &'a str,
    port: u16,
    remote_dns: bool,
) -> Result<TargetAddr<'a>, String> {
    if remote_dns {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(TargetAddr::Ip((ip, port).into()));
        }
        return Ok(TargetAddr::Domain(Cow::Borrowed(host), port));
    }

    lookup_host((host, port))
        .await
        .map_err(|e| format!("SOCKS5 local DNS lookup: {e}"))?
        .next()
        .map(TargetAddr::Ip)
        .ok_or_else(|| "SOCKS5 local DNS lookup returned no addresses".to_string())
}
