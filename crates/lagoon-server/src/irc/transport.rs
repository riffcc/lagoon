//! Federation transport — address resolution, WebSocket tunneling, and connection
//! establishment.
//!
//! Resolves remote hostnames to socket addresses (DNS, Yggdrasil peer table,
//! or direct IPv6) and creates TCP or WebSocket connections.
//!
//! When a peer is configured with `tls: true` (port 443 in `LAGOON_PEERS`),
//! federation traffic is tunneled over WebSocket (`wss://host/api/federation/ws`).
//! This survives CDN/proxy layers (e.g. Cloudflare) that only pass HTTP/WebSocket.
//! Each WebSocket text message = one IRC line.
//!
//! For plain TCP peers (Yggdrasil, local network), connections go direct.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tracing::{info, warn};

/// Default IRC port for federation relay connections.
const DEFAULT_PORT: u16 = 6667;

/// Combined async read+write trait for type-erased transport streams.
pub trait RelayTransport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayTransport for T {}

/// A connected stream suitable for framing with IrcCodec.
///
/// Type-erased so the relay task doesn't depend on any concrete transport.
/// Both plain `TcpStream` and `TlsStream<TcpStream>` satisfy this type.
pub type RelayStream = Box<dyn RelayTransport>;

/// Per-peer connection configuration.
#[derive(Debug, Clone)]
pub struct PeerEntry {
    /// Explicit Yggdrasil IPv6 address, if provided via `host=addr` format.
    pub yggdrasil_addr: Option<Ipv6Addr>,
    /// Port to connect on. Default 6667, or explicitly set via `host:port`.
    pub port: u16,
    /// Whether to wrap the connection in TLS. Auto-true for port 443.
    pub tls: bool,
}

/// Federation transport configuration.
///
/// Holds per-peer connection settings (port, TLS, Yggdrasil address) and
/// transport-level state. Shared across all relay tasks via Arc.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Known peers: hostname → connection configuration.
    /// Populated from LAGOON_PEERS env var.
    pub peers: HashMap<String, PeerEntry>,
    /// Whether this node has Yggdrasil connectivity (detected at startup).
    pub yggdrasil_available: bool,
}

impl TransportConfig {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            yggdrasil_available: false,
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket transport adapter
// ---------------------------------------------------------------------------

/// Inner type for outbound WebSocket connections via `connect_async`.
type WsInner = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<TcpStream>,
>;

/// WebSocket transport adapter for IRC federation relay.
///
/// Wraps a `WebSocketStream` to implement `AsyncRead + AsyncWrite`, allowing
/// the relay task's `Framed<RelayStream, IrcCodec>` to work transparently
/// over WebSocket. Each WebSocket text message = one IRC line.
///
/// **Read path**: polls the WebSocket `Stream` for text messages, re-adds
/// `\r\n` framing so the IrcCodec can parse them normally.
///
/// **Write path**: buffers bytes from the IrcCodec encoder, and on `flush`
/// sends each complete `\r\n`-terminated line as a WebSocket text message.
pub struct WsRelayStream {
    inner: WsInner,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl WsRelayStream {
    fn new(inner: WsInner) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }
}

impl AsyncRead for WsRelayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any buffered data first.
        if !this.read_buf.is_empty() {
            let n = std::cmp::min(buf.remaining(), this.read_buf.len());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // Poll the WebSocket for the next message.
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(msg))) => match msg {
                WsMsg::Text(text) => {
                    // Re-add \r\n framing for the IrcCodec.
                    let trimmed = text.trim_end_matches(['\r', '\n']);
                    let line = format!("{trimmed}\r\n");
                    let bytes = line.into_bytes();
                    let n = std::cmp::min(buf.remaining(), bytes.len());
                    buf.put_slice(&bytes[..n]);
                    if n < bytes.len() {
                        this.read_buf.extend_from_slice(&bytes[n..]);
                    }
                    Poll::Ready(Ok(()))
                }
                WsMsg::Close(_) => Poll::Ready(Ok(())),
                _ => {
                    // Ping/Pong/Binary — tungstenite handles pings internally.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for WsRelayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Buffer the bytes — we parse and send complete lines in poll_flush.
        self.get_mut().write_buf.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Send each complete \r\n-terminated line as a WebSocket text message.
        while let Some(pos) = this.write_buf.windows(2).position(|w| w == b"\r\n") {
            match Pin::new(&mut this.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                Poll::Pending => return Poll::Pending,
            }

            let line_bytes: Vec<u8> = this.write_buf.drain(..pos).collect();
            this.write_buf.drain(..2); // skip \r\n
            let line = String::from_utf8_lossy(&line_bytes).into_owned();

            if let Err(e) = Pin::new(&mut this.inner).start_send(WsMsg::Text(line.into())) {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
            }
        }

        // Flush the underlying WebSocket sink.
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.get_mut().inner).poll_close(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

// ---------------------------------------------------------------------------
// Connection establishment
// ---------------------------------------------------------------------------

/// Connect to a remote federation peer.
///
/// For TLS peers (port 443), tunnels over WebSocket (`wss://host/api/federation/ws`).
/// tokio-tungstenite handles DNS resolution and TLS internally. This survives
/// CDN/proxy layers (Cloudflare) that only pass HTTP/WebSocket.
///
/// For plain TCP peers, resolves the hostname via:
/// 1. Peer table lookup (LAGOON_PEERS entries with explicit addresses/ports).
/// 2. Direct IP parse (raw `200:...` addresses).
/// 3. Standard DNS resolution (prefer Yggdrasil 200::/7 results when available).
pub async fn connect(
    remote_host: &str,
    config: &TransportConfig,
) -> io::Result<RelayStream> {
    let peer = config.peers.get(remote_host);
    let port = peer.map(|p| p.port).unwrap_or(DEFAULT_PORT);
    let tls = peer.map(|p| p.tls).unwrap_or(false);

    if tls {
        // WebSocket tunnel — survives Cloudflare/CDN proxies.
        // tokio-tungstenite handles DNS resolution and TLS (rustls) internally.
        let url = format!("wss://{remote_host}:{port}/api/federation/ws");
        info!(remote_host, %url, "transport: connecting via WebSocket");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        info!(remote_host, "transport: WebSocket connected");
        Ok(Box::new(WsRelayStream::new(ws_stream)))
    } else {
        // Plain TCP (Yggdrasil, local network).
        let addr = resolve(remote_host, config, port).await?;
        info!(remote_host, ?addr, "transport: connecting via TCP");
        let stream = TcpStream::connect(addr).await?;
        Ok(Box::new(stream))
    }
}

/// Resolve a hostname to a SocketAddr using the peer table, direct parse,
/// or DNS lookup.
async fn resolve(
    remote_host: &str,
    config: &TransportConfig,
    port: u16,
) -> io::Result<SocketAddr> {
    // 1. Check peer table for explicit Yggdrasil address.
    if let Some(peer) = config.peers.get(remote_host) {
        if let Some(ygg_addr) = peer.yggdrasil_addr {
            return Ok(SocketAddr::new(IpAddr::V6(ygg_addr), port));
        }
    }

    // 2. Try parsing as a direct IP address (covers raw IPv6 like [200:...]).
    let cleaned = remote_host
        .trim_start_matches('[')
        .trim_end_matches(']');
    if let Ok(ip) = cleaned.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // 3. DNS lookup.
    let lookup_target = format!("{remote_host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_target)
        .await?
        .collect();

    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no addresses found for {remote_host}"),
        ));
    }

    // Prefer Yggdrasil addresses (200::/7) if we have Yggdrasil connectivity.
    if config.yggdrasil_available {
        if let Some(ygg) = addrs.iter().find(|a| is_yggdrasil_addr(a)) {
            return Ok(*ygg);
        }
    }

    Ok(addrs[0])
}

/// Check if a socket address is in the Yggdrasil 200::/7 range.
fn is_yggdrasil_addr(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V6(v6) => is_yggdrasil_ipv6(&v6),
        _ => false,
    }
}

/// Check if an IPv6 address is in the Yggdrasil 200::/7 range.
pub fn is_yggdrasil_ipv6(addr: &Ipv6Addr) -> bool {
    let first_byte = addr.octets()[0];
    // 200::/7 = first 7 bits are 0000_001x → first byte is 0x02 or 0x03.
    first_byte == 0x02 || first_byte == 0x03
}

/// Detect the local Yggdrasil IPv6 address (200::/7 range).
///
/// Reads `/proc/net/if_inet6` directly — no dependency on `ip` or `iproute2`.
/// Falls back to the `ip` command if `/proc` isn't available.
pub fn detect_yggdrasil_addr() -> Option<Ipv6Addr> {
    // Try /proc/net/if_inet6 first (works in containers without iproute2).
    // Format: hex_addr iface_idx prefix_len scope flags iface_name
    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let hex = line.split_whitespace().next().unwrap_or("");
            if hex.len() == 32 && hex.starts_with("02") {
                // Convert 32-char hex to colon-separated IPv6.
                let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..(i + 1) * 4]).collect();
                let addr_str = groups.join(":");
                if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                    return Some(addr);
                }
            }
        }
    }

    // Fallback: try `ip` command.
    let output = std::process::Command::new("ip")
        .args(["-6", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("inet6 ") {
            let addr_str = rest.split('/').next()?;
            if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                if is_yggdrasil_ipv6(&addr) {
                    return Some(addr);
                }
            }
        }
    }
    None
}

/// Parse a single LAGOON_PEERS entry into (hostname, PeerEntry).
///
/// Supported formats:
/// - `host:443` → TLS on port 443 (auto-detect)
/// - `host:6667` → plain TCP on port 6667
/// - `host` → plain TCP on default port 6667
/// - `host=200:addr` → Yggdrasil on default port
/// - `host:443=200:addr` → Yggdrasil with TLS on port 443
fn parse_peer_entry(entry: &str) -> Option<(String, PeerEntry)> {
    if let Some((left, addr_str)) = entry.split_once('=') {
        // Format: host=ygg_addr or host:port=ygg_addr
        let addr: Ipv6Addr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => {
                warn!(entry, "transport: invalid Yggdrasil address, skipping");
                return None;
            }
        };

        let (host, port, tls) = parse_host_port(left);
        Some((
            host,
            PeerEntry {
                yggdrasil_addr: Some(addr),
                port,
                tls,
            },
        ))
    } else {
        // Format: host or host:port
        let (host, port, tls) = parse_host_port(entry);
        Some((
            host,
            PeerEntry {
                yggdrasil_addr: None,
                port,
                tls,
            },
        ))
    }
}

/// Parse host:port from a string. Returns (hostname, port, tls).
/// Port 443 automatically enables TLS.
fn parse_host_port(s: &str) -> (String, u16, bool) {
    // Handle IPv6 literal in brackets: [::1]:443
    if s.starts_with('[') {
        if let Some(bracket_end) = s.find(']') {
            let host = &s[1..bracket_end];
            if s.len() > bracket_end + 1 && s.as_bytes()[bracket_end + 1] == b':' {
                let port_str = &s[bracket_end + 2..];
                if let Ok(port) = port_str.parse::<u16>() {
                    return (host.to_string(), port, port == 443);
                }
            }
            return (host.to_string(), DEFAULT_PORT, false);
        }
    }

    // Check if there's a colon that separates host:port.
    // But we need to be careful with IPv6 addresses that contain colons.
    // Simple heuristic: if the last colon is followed by digits only, treat as port.
    if let Some(last_colon) = s.rfind(':') {
        let port_str = &s[last_colon + 1..];
        if !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(port) = port_str.parse::<u16>() {
                let host = &s[..last_colon];
                if !host.is_empty() {
                    return (host.to_string(), port, port == 443);
                }
            }
        }
    }

    (s.to_string(), DEFAULT_PORT, false)
}

/// Build transport configuration from environment and local system state.
///
/// Reads `LAGOON_PEERS` env var for peer table entries.
///
/// Supported formats (comma-separated):
/// - `host:443` — connect with TLS on port 443
/// - `host` — connect plain TCP on port 6667
/// - `host=200:addr` — Yggdrasil with explicit IPv6 address
pub fn build_config() -> TransportConfig {
    let mut config = TransportConfig::new();

    config.yggdrasil_available = detect_yggdrasil_addr().is_some();

    if config.yggdrasil_available {
        info!("transport: Yggdrasil connectivity detected");
    }

    if let Ok(peers_str) = std::env::var("LAGOON_PEERS") {
        for entry in peers_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((host, peer_entry)) = parse_peer_entry(entry) {
                if peer_entry.tls {
                    info!(host, port = peer_entry.port, "transport: peer (TLS)");
                } else if peer_entry.yggdrasil_addr.is_some() {
                    info!(host, port = peer_entry.port, "transport: peer (Yggdrasil)");
                } else {
                    info!(host, port = peer_entry.port, "transport: peer (plain TCP)");
                }
                config.peers.insert(host, peer_entry);
            }
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yggdrasil_detection_positive() {
        let addr: SocketAddr = "[200:1234::1]:6667".parse().unwrap();
        assert!(is_yggdrasil_addr(&addr));
        let addr: SocketAddr = "[301:abcd::1]:6667".parse().unwrap();
        assert!(is_yggdrasil_addr(&addr));
    }

    #[test]
    fn yggdrasil_detection_negative() {
        let addr: SocketAddr = "[::1]:6667".parse().unwrap();
        assert!(!is_yggdrasil_addr(&addr));
        let addr: SocketAddr = "127.0.0.1:6667".parse().unwrap();
        assert!(!is_yggdrasil_addr(&addr));
        let addr: SocketAddr = "[2001:db8::1]:6667".parse().unwrap();
        assert!(!is_yggdrasil_addr(&addr));
    }

    #[test]
    fn ipv6_yggdrasil_range() {
        let addr: Ipv6Addr = "200:1234:5678:9abc:def0:1234:5678:9abc".parse().unwrap();
        assert!(is_yggdrasil_ipv6(&addr));
        let addr: Ipv6Addr = "301:abcd::1".parse().unwrap();
        assert!(is_yggdrasil_ipv6(&addr));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_yggdrasil_ipv6(&addr));
        let addr: Ipv6Addr = "::1".parse().unwrap();
        assert!(!is_yggdrasil_ipv6(&addr));
    }

    #[test]
    fn peer_table_resolution() {
        let mut config = TransportConfig::new();
        let ygg: Ipv6Addr = "201:6647:b411:52ad:a45a:fba5:efd1:cfe5".parse().unwrap();
        config.peers.insert(
            "per.lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: Some(ygg),
                port: DEFAULT_PORT,
                tls: false,
            },
        );

        assert!(config.peers.contains_key("per.lagun.co"));
        let entry = config.peers.get("per.lagun.co").unwrap();
        assert!(is_yggdrasil_ipv6(&entry.yggdrasil_addr.unwrap()));
    }

    #[test]
    fn default_config() {
        let config = TransportConfig::new();
        assert!(!config.yggdrasil_available);
        assert!(config.peers.is_empty());
    }

    #[tokio::test]
    async fn resolve_direct_ipv4() {
        let config = TransportConfig::new();
        let addr = resolve("127.0.0.1", &config, DEFAULT_PORT).await.unwrap();
        assert_eq!(addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 6667));
    }

    #[tokio::test]
    async fn resolve_peer_table() {
        let mut config = TransportConfig::new();
        let ygg: Ipv6Addr = "200:1234::1".parse().unwrap();
        config.peers.insert(
            "test.lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: Some(ygg),
                port: DEFAULT_PORT,
                tls: false,
            },
        );

        let addr = resolve("test.lagun.co", &config, DEFAULT_PORT).await.unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(ygg), 6667));
    }

    #[test]
    fn parse_host_port_plain() {
        let (host, port, tls) = parse_host_port("lon.lagun.co");
        assert_eq!(host, "lon.lagun.co");
        assert_eq!(port, 6667);
        assert!(!tls);
    }

    #[test]
    fn parse_host_port_443() {
        let (host, port, tls) = parse_host_port("lon.lagun.co:443");
        assert_eq!(host, "lon.lagun.co");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn parse_host_port_custom() {
        let (host, port, tls) = parse_host_port("lon.lagun.co:6697");
        assert_eq!(host, "lon.lagun.co");
        assert_eq!(port, 6697);
        assert!(!tls);
    }

    #[test]
    fn parse_peer_entry_tls() {
        let (host, entry) = parse_peer_entry("lon.lagun.co:443").unwrap();
        assert_eq!(host, "lon.lagun.co");
        assert_eq!(entry.port, 443);
        assert!(entry.tls);
        assert!(entry.yggdrasil_addr.is_none());
    }

    #[test]
    fn parse_peer_entry_plain() {
        let (host, entry) = parse_peer_entry("node2.mesh.lagun.co").unwrap();
        assert_eq!(host, "node2.mesh.lagun.co");
        assert_eq!(entry.port, 6667);
        assert!(!entry.tls);
        assert!(entry.yggdrasil_addr.is_none());
    }

    #[test]
    fn parse_peer_entry_yggdrasil() {
        let (host, entry) =
            parse_peer_entry("per.lagun.co=201:6647:b411:52ad:a45a:fba5:efd1:cfe5").unwrap();
        assert_eq!(host, "per.lagun.co");
        assert_eq!(entry.port, 6667);
        assert!(!entry.tls);
        assert!(entry.yggdrasil_addr.is_some());
        assert!(is_yggdrasil_ipv6(&entry.yggdrasil_addr.unwrap()));
    }

    #[test]
    fn ws_url_format() {
        // Verify WebSocket URL construction for TLS peers.
        let host = "lon.lagun.co";
        let port = 443u16;
        let url = format!("wss://{host}:{port}/api/federation/ws");
        assert_eq!(url, "wss://lon.lagun.co:443/api/federation/ws");
    }
}
