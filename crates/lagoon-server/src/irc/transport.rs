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
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use rand::seq::SliceRandom;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message as WsMsg;
use tracing::{info, warn};

/// Default IRC port for federation relay connections.
const DEFAULT_PORT: u16 = 443;

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
#[derive(Clone)]
pub struct TransportConfig {
    /// Known peers: hostname → connection configuration.
    /// Populated from LAGOON_PEERS env var.
    pub peers: HashMap<String, PeerEntry>,
    /// Whether this node has Yggdrasil connectivity (detected at startup).
    pub yggdrasil_available: bool,
    /// Embedded Yggdrasil node for overlay networking.
    /// When present, Ygg-addressed peers are dialed directly through the overlay.
    pub ygg_node: Option<Arc<yggbridge::YggNode>>,
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConfig")
            .field("peers", &self.peers)
            .field("yggdrasil_available", &self.yggdrasil_available)
            .field("ygg_node", &self.ygg_node.is_some())
            .finish()
    }
}

impl TransportConfig {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            yggdrasil_available: false,
            ygg_node: None,
        }
    }
}

// ---------------------------------------------------------------------------
// WebSocket transport adapter
// ---------------------------------------------------------------------------

/// WebSocket transport adapter for IRC federation relay.
///
/// Generic over the underlying stream `S` so we can use the same adapter for:
/// - `wss://` over TCP (`MaybeTlsStream<TcpStream>`) — public internet
/// - `ws://` over Ygg overlay (`YggStream`) — encrypted mesh
///
/// Wraps a `WebSocketStream<S>` to implement `AsyncRead + AsyncWrite`, allowing
/// the relay task's `Framed<RelayStream, IrcCodec>` to work transparently
/// over WebSocket. Each WebSocket text message = one IRC line.
///
/// **Read path**: polls the WebSocket `Stream` for text messages, re-adds
/// `\r\n` framing so the IrcCodec can parse them normally.
///
/// **Write path**: buffers bytes from the IrcCodec encoder, and on `flush`
/// sends each complete `\r\n`-terminated line as a WebSocket text message.
pub struct WsRelayStream<S: AsyncRead + AsyncWrite + Unpin> {
    inner: tokio_tungstenite::WebSocketStream<S>,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsRelayStream<S> {
    fn new(inner: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            inner,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsRelayStream<S> {
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

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsRelayStream<S> {
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
/// Three transport modes, tried in priority order:
///
/// 1. **Ygg overlay WebSocket** (`ws://[ygg_addr]:8080/api/federation/ws`):
///    When the peer has a known Yggdrasil address and we have an embedded Ygg
///    node. Dials the overlay → WebSocket upgrade to the web gateway. No TLS
///    needed — Yggdrasil encrypts the transport. No DNS needed — we have the
///    overlay address from MESH HELLO / MESH PEERS.
///
/// 2. **TLS WebSocket** (`wss://host:443/api/federation/ws`):
///    For peers configured with `tls: true` (port 443). tokio-tungstenite
///    handles DNS and TLS. Survives CDN/proxy layers (Cloudflare, HAProxy).
///    Used for the anycast entry point (`LAGOON_PEERS=lagun.co:443`).
///
/// 3. **Plain TCP** (port 6667):
///    Direct IRC protocol for LAN peers. DNS or peer-table resolution.
///
/// Result includes the resolved TCP peer address (for APE underlay derivation).
/// WebSocket and overlay connections return `peer_addr: None`.
pub struct ConnectResult {
    pub stream: RelayStream,
    /// The resolved TCP peer address.  `None` for WebSocket or Ygg overlay
    /// connections (those don't need underlay APE bootstrapping).
    pub peer_addr: Option<SocketAddr>,
}

/// Web gateway port — the HTTP/WS server that lagoon-web runs on.
/// Overlay connections use this for `ws://` federation.
const WEB_GATEWAY_PORT: u16 = 8080;

/// Which transport to use for a federation connection.
///
/// Determined by `select_transport()` from the peer's configuration.
/// Priority: Ygg overlay (encrypted, no DNS) > TLS WebSocket (CDN) > plain TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportMode {
    /// Ygg overlay → `ws://[200:xxxx]:8080/api/federation/ws` (or `/api/mesh/ws`).
    /// Ygg encrypts the transport, no TLS needed.
    YggOverlay { addr: Ipv6Addr },
    /// TLS WebSocket → `wss://host:port/api/federation/ws`.
    /// Survives CDN/proxy layers.
    TlsWebSocket { host: String, port: u16 },
    /// Plain TCP → direct IRC protocol.
    PlainTcp { host: String, port: u16 },
}

/// Select the transport mode for connecting to a remote host.
///
/// Pure decision function — no I/O.  `connect()` calls this and then
/// establishes the connection according to the result.
///
/// Priority:
/// 1. **Ygg overlay** if we have an embedded Ygg node AND the peer has a known
///    overlay address.
/// 2. **TLS WebSocket** if the peer is configured with `tls: true` (port 443).
/// 3. **Plain TCP** for everything else.
pub fn select_transport(
    remote_host: &str,
    config: &TransportConfig,
) -> TransportMode {
    select_transport_inner(remote_host, &config.peers, config.ygg_node.is_some())
}

/// Inner logic for transport selection — testable without a real YggNode.
pub fn select_transport_inner(
    remote_host: &str,
    peers: &HashMap<String, PeerEntry>,
    has_ygg_node: bool,
) -> TransportMode {
    let peer = peers.get(remote_host);
    let port = peer.map(|p| p.port).unwrap_or(DEFAULT_PORT);
    let tls = peer.map(|p| p.tls).unwrap_or(false);
    let ygg_addr = peer.and_then(|p| p.yggdrasil_addr);

    if has_ygg_node {
        if let Some(ygg_v6) = ygg_addr {
            return TransportMode::YggOverlay { addr: ygg_v6 };
        }
    }

    if tls {
        return TransportMode::TlsWebSocket {
            host: remote_host.to_string(),
            port,
        };
    }

    TransportMode::PlainTcp {
        host: remote_host.to_string(),
        port,
    }
}

pub async fn connect(
    remote_host: &str,
    config: &TransportConfig,
) -> io::Result<ConnectResult> {
    let peer = config.peers.get(remote_host);
    let port = peer.map(|p| p.port).unwrap_or(DEFAULT_PORT);
    let tls = peer.map(|p| p.tls).unwrap_or(false);
    let ygg_addr = peer.and_then(|p| p.yggdrasil_addr);

    // ── Priority 1: Ygg overlay WebSocket ──────────────────────────────
    //
    // If we have an embedded Ygg node and this peer has a known overlay
    // address, dial ws:// through the mesh. Ygg encrypts, no TLS needed.
    // The web gateway on port 8080 handles the WebSocket federation
    // endpoint with all the authentication and proxying already built in.
    if let (Some(ygg_node), Some(ygg_v6)) = (&config.ygg_node, ygg_addr) {
        let url = format!("ws://[{ygg_v6}]:{WEB_GATEWAY_PORT}/api/federation/ws");
        info!(remote_host, %url, "transport: connecting via WebSocket over Ygg overlay");
        let stream = ygg_node
            .dial(ygg_v6, WEB_GATEWAY_PORT)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        let (ws_stream, _response) = tokio_tungstenite::client_async(&url, stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        info!(remote_host, "transport: WebSocket over Ygg overlay connected");
        return Ok(ConnectResult {
            stream: Box::new(WsRelayStream::new(ws_stream)),
            peer_addr: None, // overlay — no underlay APE needed
        });
    }

    // ── Priority 2: TLS WebSocket ──────────────────────────────────────
    //
    // Public internet path — wss:// through CDN/proxy/anycast.
    if tls {
        let url = if remote_host.contains(':') {
            format!("wss://[{remote_host}]:{port}/api/federation/ws")
        } else {
            format!("wss://{remote_host}:{port}/api/federation/ws")
        };
        info!(remote_host, %url, "transport: connecting via WebSocket (TLS)");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        info!(remote_host, "transport: WebSocket (TLS) connected");
        return Ok(ConnectResult {
            stream: Box::new(WsRelayStream::new(ws_stream)),
            peer_addr: None,
        });
    }

    // ── Priority 3: Plain TCP ──────────────────────────────────────────
    //
    // LAN peers — direct IRC protocol connection.
    let addr = resolve(remote_host, config, port).await?;
    info!(remote_host, ?addr, "transport: connecting via TCP");
    let stream = TcpStream::connect(addr).await?;
    set_tcp_keepalive(&stream)?;
    Ok(ConnectResult {
        stream: Box::new(stream),
        peer_addr: Some(addr),
    })
}

/// Apply aggressive TCP keepalive for fast dead peer detection.
///
/// time=2s (start probing after 2s idle), interval=2s (probe every 2s),
/// retries=3 (give up after 3 failures). Total detection: 2 + 2×3 = 8s.
pub(crate) fn set_tcp_keepalive(stream: &TcpStream) -> io::Result<()> {
    let sock = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(std::time::Duration::from_secs(2))
        .with_interval(std::time::Duration::from_secs(2))
        .with_retries(3);
    sock.set_tcp_keepalive(&keepalive)?;
    Ok(())
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
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_target)
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

    // Shuffle DNS results to avoid always picking the local machine.
    //
    // Anycast DNS (e.g. Fly's `.internal`) returns all machines but sorts
    // the local address first.  Without shuffling, every connection is a
    // self-connection that gets detected and retried — an infinite loop.
    addrs.shuffle(&mut rand::thread_rng());

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
    if let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "addr", "show", "scope", "global"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("inet6 ") {
                if let Some(addr_str) = rest.split('/').next() {
                    if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                        if is_yggdrasil_ipv6(&addr) {
                            return Some(addr);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Detect a non-Yggdrasil, non-loopback, non-link-local IPv6 address.
///
/// This is the node's **underlay** address — the real IP that other nodes
/// can use to reach this machine's Ygg listener.  Ygg peer URIs MUST be
/// underlay addresses because you don't tunnel Yggdrasil through Yggdrasil.
///
/// Reads `/proc/net/if_inet6` directly (no dependency on `ip` or `iproute2`).
pub fn detect_underlay_addr() -> Option<IpAddr> {
    // Collect all candidate addresses, then pick the best one.
    // Priority: ULA (fc00::/7, private network) > global unicast > IPv4.
    //
    // ULA addresses (fd00::/8 in practice) are private-network addresses
    // that are directly reachable between co-located machines. This is the
    // IPv6 equivalent of RFC1918 (10.x, 172.16.x, 192.168.x). Provider-
    // agnostic: works on any network with private IPv6 addressing.
    let mut ula_addr: Option<Ipv6Addr> = None;
    let mut global_addr: Option<Ipv6Addr> = None;

    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let hex = line.split_whitespace().next().unwrap_or("");
            if hex.len() != 32 {
                continue;
            }
            // Skip Yggdrasil (02xx, 03xx), loopback (::1), link-local (fe80::).
            if hex.starts_with("02") || hex.starts_with("03") {
                continue; // Yggdrasil overlay
            }
            if hex == "00000000000000000000000000000001" {
                continue; // ::1 loopback
            }
            if hex.starts_with("fe80") {
                continue; // link-local
            }
            // Convert 32-char hex to colon-separated IPv6.
            let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..(i + 1) * 4]).collect();
            let addr_str = groups.join(":");
            if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                // ULA = fc00::/7 (first byte fc or fd).
                let first_byte = addr.octets()[0];
                if first_byte == 0xfc || first_byte == 0xfd {
                    if ula_addr.is_none() {
                        ula_addr = Some(addr);
                    }
                } else if global_addr.is_none() {
                    global_addr = Some(addr);
                }
            }
        }
    }

    // Prefer ULA (private, locally reachable) over global unicast.
    if let Some(addr) = ula_addr.or(global_addr) {
        return Some(IpAddr::V6(addr));
    }

    // Fallback: try first non-loopback IPv4 from /proc/net/fib_trie or interfaces.
    if let Ok(output) = std::process::Command::new("hostname")
        .args(["-I"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for token in stdout.split_whitespace() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                if !ip.is_loopback() {
                    return Some(ip);
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
/// Reads `LAGOON_URL` for the WebSocket federation endpoint (CDN/reverse proxy).
/// `LAGOON_PEERS` is for Yggdrasil underlay peering — handled by init_yggdrasil().
///
/// Supported LAGOON_URL formats (comma-separated):
/// - `host.example.com` — WebSocket TLS on port 443
/// - `host:443` — explicit port, TLS auto-detected from port 443
/// - `host:6667` — plain TCP (legacy)
pub fn build_config() -> TransportConfig {
    let mut config = TransportConfig::new();

    config.yggdrasil_available = detect_yggdrasil_addr().is_some();

    if config.yggdrasil_available {
        info!("transport: Yggdrasil connectivity detected (TUN/system)");
    }

    // LAGOON_URL = WebSocket federation endpoint(s).
    if let Ok(url_str) = std::env::var("LAGOON_URL") {
        for entry in url_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((host, peer_entry)) = parse_peer_entry(entry) {
                if peer_entry.tls {
                    info!(host, port = peer_entry.port, "transport: federation endpoint (TLS)");
                } else {
                    info!(host, port = peer_entry.port, "transport: federation endpoint (plain)");
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
        assert_eq!(addr, SocketAddr::new("127.0.0.1".parse().unwrap(), 443));
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
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(ygg), 443));
    }

    #[test]
    fn parse_host_port_plain() {
        let (host, port, tls) = parse_host_port("lon.lagun.co");
        assert_eq!(host, "lon.lagun.co");
        assert_eq!(port, 443); // Default port is 443 (WebSocket behind CDN)
        assert!(!tls); // No client-side TLS — CDN terminates
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
        assert_eq!(entry.port, 443); // Default port is 443 (WebSocket)
        assert!(!entry.tls);
        assert!(entry.yggdrasil_addr.is_none());
    }

    #[test]
    fn parse_peer_entry_yggdrasil() {
        let (host, entry) =
            parse_peer_entry("per.lagun.co=201:6647:b411:52ad:a45a:fba5:efd1:cfe5").unwrap();
        assert_eq!(host, "per.lagun.co");
        assert_eq!(entry.port, 443); // Default port is 443 (WebSocket)
        assert!(!entry.tls);
        assert!(entry.yggdrasil_addr.is_some());
        assert!(is_yggdrasil_ipv6(&entry.yggdrasil_addr.unwrap()));
    }

    #[test]
    fn ws_url_format() {
        // Verify WebSocket URL construction for TLS peers.
        let host = "lon.lagun.co";
        let port = 443u16;
        let url = if host.contains(':') {
            format!("wss://[{host}]:{port}/api/federation/ws")
        } else {
            format!("wss://{host}:{port}/api/federation/ws")
        };
        assert_eq!(url, "wss://lon.lagun.co:443/api/federation/ws");
    }

    #[test]
    fn ws_url_format_ipv6() {
        let host = "2a09:8280:5d::d2:e42f:0";
        let port = 443u16;
        let url = if host.contains(':') {
            format!("wss://[{host}]:{port}/api/federation/ws")
        } else {
            format!("wss://{host}:{port}/api/federation/ws")
        };
        assert_eq!(
            url,
            "wss://[2a09:8280:5d::d2:e42f:0]:443/api/federation/ws"
        );
    }

    // ── Transport priority tests ─────────────────────────────────────

    #[test]
    fn select_transport_ygg_overlay_when_node_and_addr() {
        let ygg: Ipv6Addr = "200:1234::1".parse().unwrap();
        let mut peers = HashMap::new();
        peers.insert(
            "per.lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: Some(ygg),
                port: DEFAULT_PORT,
                tls: false,
            },
        );
        let mode = select_transport_inner("per.lagun.co", &peers, true);
        assert_eq!(mode, TransportMode::YggOverlay { addr: ygg });
    }

    #[test]
    fn select_transport_tls_ws_when_no_ygg_node() {
        let ygg: Ipv6Addr = "200:1234::1".parse().unwrap();
        let mut peers = HashMap::new();
        peers.insert(
            "per.lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: Some(ygg),
                port: 443,
                tls: true,
            },
        );
        // No ygg_node → falls through to TLS WS.
        let mode = select_transport_inner("per.lagun.co", &peers, false);
        assert_eq!(
            mode,
            TransportMode::TlsWebSocket {
                host: "per.lagun.co".into(),
                port: 443,
            }
        );
    }

    #[test]
    fn select_transport_tls_ws_when_no_ygg_addr() {
        let mut peers = HashMap::new();
        peers.insert(
            "lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: None,
                port: 443,
                tls: true,
            },
        );
        // ygg_node exists but peer has no ygg_addr → TLS WS.
        let mode = select_transport_inner("lagun.co", &peers, true);
        assert_eq!(
            mode,
            TransportMode::TlsWebSocket {
                host: "lagun.co".into(),
                port: 443,
            }
        );
    }

    #[test]
    fn select_transport_plain_tcp_fallback() {
        let mut peers = HashMap::new();
        peers.insert(
            "sanctuary.lon.riff.cc".into(),
            PeerEntry {
                yggdrasil_addr: None,
                port: 6667,
                tls: false,
            },
        );
        let mode = select_transport_inner("sanctuary.lon.riff.cc", &peers, false);
        assert_eq!(
            mode,
            TransportMode::PlainTcp {
                host: "sanctuary.lon.riff.cc".into(),
                port: 6667,
            }
        );
    }

    #[test]
    fn select_transport_unknown_peer_defaults_to_plain() {
        let peers = HashMap::new();
        let mode = select_transport_inner("unknown.host", &peers, true);
        assert_eq!(
            mode,
            TransportMode::PlainTcp {
                host: "unknown.host".into(),
                port: DEFAULT_PORT,
            }
        );
    }

    #[test]
    fn select_transport_ygg_overlay_takes_priority_over_tls() {
        let ygg: Ipv6Addr = "201:abcd::1".parse().unwrap();
        let mut peers = HashMap::new();
        peers.insert(
            "lon.lagun.co".into(),
            PeerEntry {
                yggdrasil_addr: Some(ygg),
                port: 443,
                tls: true, // would be TLS WS, but Ygg overlay wins
            },
        );
        let mode = select_transport_inner("lon.lagun.co", &peers, true);
        assert_eq!(mode, TransportMode::YggOverlay { addr: ygg });
    }
}
