//! Federation transport — address resolution, WebSocket tunneling, and connection
//! establishment.
//!
//! Resolves remote hostnames to socket addresses (DNS, Yggdrasil peer table,
//! or direct IPv6) and creates TCP or WebSocket connections.
//!
//! Two WebSocket modes:
//!
//! - **Native mesh** (`/api/mesh/ws`): JSON `MeshMessage` frames. Used by
//!   `relay_task_native()` for all WebSocket connections. This is the primary
//!   path — simple, correct, one dispatch function.
//!
//! - **Legacy IRC** (`connect()` with `WsRelayStream`): IRC-over-WebSocket for
//!   plain TCP relay_task backwards compatibility. Being phased out.
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
    /// Targeted switchboard dial — `"peer:{peer_id}"` requests a specific node
    /// via the anycast switchboard. Used by `dial_missing_spiral_neighbors` to
    /// reach peers through the anycast entry point without Ygg overlay routing.
    pub want: Option<String>,
    /// Override hostname for the switchboard TCP dial. When set, this IP/host
    /// is used instead of `remote_host` or `yggdrasil_addr`. Used for underlay
    /// addresses (LAN IPs) that are directly reachable without Ygg overlay routing.
    pub dial_host: Option<String>,
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
    pub ygg_node: Option<Arc<yggdrasil_rs::YggNode>>,
    /// Global anycast switchboard IP (e.g. `109.224.228.162`). No port — always 9443.
    /// When set, `dial_missing_spiral_neighbors` uses this as the dial target
    /// for peers without a direct underlay route. The switchboard routes the
    /// TCP connection to the requested peer via half-dial.
    /// Set via `LAGOON_SWITCHBOARD_ADDR` env var. IP only, no port suffix.
    pub switchboard_addr: Option<String>,
}

impl std::fmt::Debug for TransportConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConfig")
            .field("peers", &self.peers)
            .field("yggdrasil_available", &self.yggdrasil_available)
            .field("ygg_node", &self.ygg_node.is_some())
            .field("switchboard_addr", &self.switchboard_addr)
            .finish()
    }
}

impl TransportConfig {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            yggdrasil_available: false,
            ygg_node: None,
            switchboard_addr: None,
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
/// 1. **Ygg overlay WebSocket** (`ws://[ygg_addr]:8080/api/mesh/ws`):
///    When the peer has a known Yggdrasil address and we have an embedded Ygg
///    node. Dials the overlay → WebSocket upgrade to the web gateway. No TLS
///    needed — Yggdrasil encrypts the transport. No DNS needed — we have the
///    overlay address from MESH HELLO / MESH PEERS.
///
/// 2. **TLS WebSocket** (`wss://host:443/api/mesh/ws`):
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

/// Which transport to use for a federation connection.
///
/// Determined by `select_transport()` from the peer's configuration.
/// Priority: Ygg overlay (encrypted, no DNS) > TLS WebSocket (CDN) > plain TCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportMode {
    /// Ygg overlay → `ws://[200:xxxx]:8080/api/mesh/ws`.
    /// Ygg encrypts the transport, no TLS needed.
    YggOverlay { addr: Ipv6Addr },
    /// TLS WebSocket → `wss://host:port/api/mesh/ws`.
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

    // ── Priority 1: TLS WebSocket ──────────────────────────────────────
    //
    // Public internet path — wss:// through CDN/proxy/anycast.
    if tls {
        let url = if remote_host.contains(':') {
            format!("wss://[{remote_host}]:{port}/api/mesh/ws")
        } else {
            format!("wss://{remote_host}:{port}/api/mesh/ws")
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

// ---------------------------------------------------------------------------
// Native mesh connection (JSON MeshMessages, no IRC framing)
// ---------------------------------------------------------------------------

/// Connection stream for the native mesh relay — NOT wrapped in IRC framing.
///
/// The relay_task_native() uses these directly for JSON MeshMessage exchange.
/// Generic over the underlying transport (TLS WebSocket or raw TCP switchboard).
pub enum NativeWs {
    /// TLS WebSocket: `wss://host:port/api/mesh/ws`, internet path.
    Tls(tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>),
    /// Switchboard: raw TCP with JSON lines (no WebSocket). After half-dial
    /// PeerReady, mesh messages flow as newline-delimited JSON.
    Switchboard {
        reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: tokio::net::tcp::OwnedWriteHalf,
    },
}

/// Connect to a remote peer's native mesh endpoint.
///
/// Returns a `NativeWs` stream for JSON MeshMessage exchange.
///
/// Priority:
/// 1. **Switchboard half-dial** (port 9443, raw TCP JSON lines).
/// 2. **TLS WebSocket** if the peer is configured with `tls: true` (port 443).
/// 3. **PlainTcp** → error (native mode requires WebSocket or switchboard).
pub async fn connect_native(
    remote_host: &str,
    config: &TransportConfig,
    from_peer_id: Option<&str>,
) -> io::Result<NativeWs> {
    let peer = config.peers.get(remote_host);
    let port = peer.map(|p| p.port).unwrap_or(DEFAULT_PORT);
    let tls = peer.map(|p| p.tls).unwrap_or(false);

    // Mesh WS path — includes `from` param so the listener can detect
    // self-connections and drop them at the TCP level (transparent self).
    let ws_path = match from_peer_id {
        Some(pid) => format!("/api/mesh/ws?from={pid}"),
        None => "/api/mesh/ws".to_string(),
    };

    // Priority 1: Switchboard half-dial (port 9443, raw TCP JSON lines).
    //
    // Raw TCP anycast — bypasses Fly's HTTP proxy entirely. No WebSocket.
    // The switchboard handles self-rejection at the TCP level: if the peeked
    // bytes contain our peer_id, it goes silent. Client times out (3s), gets
    // SelfDetected, redials anycast → different machine answers.
    if port == SWITCHBOARD_PORT && !tls {
        let our_pid = from_peer_id.unwrap_or("");
        let want = peer.and_then(|p| p.want.as_deref()).unwrap_or("any");
        // Dial target priority:
        // 1. dial_host override (underlay LAN IP — works without Ygg overlay)
        // 2. yggdrasil_addr (overlay — needs functioning Ygg mesh)
        // 3. remote_host (hostname — needs DNS/hosts resolution)
        let dial_host = peer
            .and_then(|p| p.dial_host.as_deref().map(|s| s.to_string())
                .or_else(|| p.yggdrasil_addr.map(|a| a.to_string())))
            .unwrap_or_else(|| remote_host.to_string());
        info!(remote_host, %dial_host, want, "transport: native mesh via switchboard half-dial");
        match connect_switchboard(&dial_host, our_pid, want).await? {
            SwitchboardOutcome::Ready(ns) => return Ok(ns),
            SwitchboardOutcome::DirectRedirect { target_peer_id, ygg_addr } => {
                // Switchboard told us the target is at a different underlay
                // address. Dial that address directly via TCP switchboard,
                // asking for the specific peer. The ygg_addr field here is
                // actually the underlay URI (e.g. tcp://[fdaa::]:9443).
                let host = extract_host_from_uri(&ygg_addr);
                info!(%target_peer_id, %host,
                    "transport: redirect — dialing target underlay directly");
                let want = format!("peer:{target_peer_id}");
                match connect_switchboard(&host, our_pid, &want).await? {
                    SwitchboardOutcome::Ready(ns) => return Ok(ns),
                    SwitchboardOutcome::SelfDetected => {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "switchboard: self-connection detected (anycast routed to self)",
                        ));
                    }
                    SwitchboardOutcome::DirectRedirect { .. } => {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "switchboard: double redirect (target not found at underlay)",
                        ));
                    }
                }
            }
            SwitchboardOutcome::SelfDetected => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "switchboard: self-connection detected (anycast routed to self)",
                ));
            }
        }
    }

    // Priority 3: TLS WebSocket.
    if tls {
        let url = if remote_host.contains(':') {
            format!("wss://[{remote_host}]:{port}{ws_path}")
        } else {
            format!("wss://{remote_host}:{port}{ws_path}")
        };
        info!(remote_host, %url, "transport: native mesh via TLS WebSocket");
        let (ws_stream, _response) = tokio_tungstenite::connect_async(&url)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionRefused, e))?;
        info!(remote_host, "transport: native mesh via TLS WebSocket connected");
        return Ok(NativeWs::Tls(ws_stream));
    }

    // PlainTcp — not supported for native mesh mode (requires WebSocket or switchboard).
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("native mesh requires WebSocket or switchboard transport (peer {remote_host} is PlainTcp)"),
    ))
}

// ---------------------------------------------------------------------------
// Switchboard half-dial (client side)
// ---------------------------------------------------------------------------

/// Outcome of a switchboard half-dial. The client gets either:
/// - A ready WebSocket stream (PeerReady or splice redirect), or
/// - A direct redirect telling the client to dial the target via Ygg.
pub enum SwitchboardOutcome {
    /// We got PeerReady — the switchboard IS our target. WebSocket is live.
    Ready(NativeWs),
    /// The switchboard told us to dial the target directly via Ygg overlay.
    /// Close this connection and use the provided address.
    DirectRedirect {
        target_peer_id: String,
        ygg_addr: String,
    },
    /// Anycast routed to self — the switchboard went silent (or we detected
    /// our own peer_id in the handshake). Caller retries immediately with
    /// no backoff — the next dial through anycast hits a different machine.
    SelfDetected,
}

/// Switchboard port — the default port for half-dial connections.
pub const SWITCHBOARD_PORT: u16 = 9443;

/// Client-side half-dial protocol (raw TCP JSON lines, no WebSocket).
///
/// 1. TCP connect to `addr:9443`
/// 2. Send `PeerRequest` FIRST (so the switchboard's peek can detect protocol + self)
/// 3. Read `SwitchboardHello` (responder identifies itself)
/// 4. Read response: `PeerReady` or `PeerRedirect`
/// 5. If `PeerReady` → return `Ready(NativeWs::Switchboard)` — raw TCP continues
/// 6. If `PeerRedirect` with "direct" → return `DirectRedirect`
/// 7. Self-connection → caught by switchboard at peek (our peer_id in PeerRequest
///    bytes → silence, no response) or by us at step 3 (responder_peer_id == ours).
pub async fn connect_switchboard(
    addr: &str,
    our_peer_id: &str,
    want: &str,
) -> io::Result<SwitchboardOutcome> {
    use super::wire::SwitchboardMessage;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    // IPv6 addresses need brackets in socket addresses.
    let target = if addr.contains(':') && !addr.starts_with('[') {
        format!("[{addr}]:{SWITCHBOARD_PORT}")
    } else {
        format!("{addr}:{SWITCHBOARD_PORT}")
    };
    info!(%target, want, "switchboard client: dialing");

    let stream = TcpStream::connect(&target).await?;
    stream.set_nodelay(true)?;
    set_tcp_keepalive(&stream)?;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    // Step 1: Send PeerRequest FIRST.
    //
    // The switchboard peeks at the first bytes. If it sees our peer_id
    // (self-connection via anycast), it goes silent — doesn't respond.
    // If not, it sees `{` (JSON) and routes to the half-dial handler.
    let request = SwitchboardMessage::PeerRequest {
        my_peer_id: our_peer_id.to_string(),
        want: want.to_string(),
    };
    let request_line = request.to_line()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    write_half.write_all(request_line.as_bytes()).await?;

    // Step 2: Read the responder's SwitchboardHello.
    //
    // Short timeout: on the same anycast network, switchboard response is
    // sub-millisecond. If nothing comes in 3s, the responder detected a
    // self-connection and went silent. Return SelfDetected so the caller
    // retries immediately — the next dial through anycast hits a different
    // machine.
    let mut line = String::new();
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_line(&mut line),
    );
    match timeout.await {
        Ok(Ok(0)) | Err(_) => {
            // No response or timeout → server went silent (self-connection).
            // Another machine on the anycast address will answer next time.
            info!("switchboard client: no response — likely self-connection via anycast");
            return Ok(SwitchboardOutcome::SelfDetected);
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok(_)) => {}
    }

    let hello = SwitchboardMessage::from_line(&line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let (responder_peer_id, _responder_slot) = match hello {
        SwitchboardMessage::SwitchboardHello { peer_id, spiral_slot } => (peer_id, spiral_slot),
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switchboard client: expected SwitchboardHello, got {other:?}"),
            ));
        }
    };

    info!(
        %responder_peer_id,
        "switchboard client: received SwitchboardHello"
    );

    // Protocol-level self-detection (backup — transparent self should have
    // caught this at the peek level before we get here).
    if responder_peer_id == our_peer_id {
        info!("switchboard client: self-connection detected (anycast routed to self)");
        return Ok(SwitchboardOutcome::SelfDetected);
    }

    // Step 3: Read response.
    let mut response_line = String::new();
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_line(&mut response_line),
    );
    match timeout.await {
        Ok(Ok(0)) | Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "switchboard client: no response to PeerRequest",
            ));
        }
        Ok(Err(e)) => return Err(e),
        Ok(Ok(_)) => {}
    }

    let response = SwitchboardMessage::from_line(&response_line)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    match response {
        SwitchboardMessage::PeerReady { peer_id } => {
            info!(
                %peer_id,
                "switchboard client: PeerReady — raw TCP mesh session"
            );

            // Return the raw TCP stream for JSON-lines mesh messaging.
            // No WebSocket upgrade — the stream continues with newline-delimited
            // MeshMessage JSON.
            Ok(SwitchboardOutcome::Ready(NativeWs::Switchboard { reader, writer: write_half }))
        }

        SwitchboardMessage::PeerRedirect { target_peer_id, method, ygg_addr } => {
            match method.as_str() {
                "direct" => {
                    let ygg = ygg_addr.ok_or_else(|| io::Error::new(
                        io::ErrorKind::InvalidData,
                        "switchboard: direct redirect without ygg_addr",
                    ))?;
                    info!(
                        %target_peer_id,
                        %ygg,
                        "switchboard client: direct redirect — will dial via Ygg"
                    );
                    Ok(SwitchboardOutcome::DirectRedirect {
                        target_peer_id,
                        ygg_addr: ygg,
                    })
                }
                other => {
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("switchboard: unknown redirect method '{other}'"),
                    ))
                }
            }
        }

        other => {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("switchboard client: unexpected response: {other:?}"),
            ))
        }
    }
}

/// Extract the host (IP) from a Ygg peer URI like `tcp://[fdaa::1]:9443`.
///
/// Returns the bracketed address for IPv6, or the bare host for IPv4.
/// Falls back to returning the input as-is if parsing fails.
pub fn extract_host_from_uri(uri: &str) -> String {
    // Format: tcp://[host]:port or tcp://host:port
    let stripped = uri
        .strip_prefix("tcp://")
        .unwrap_or(uri);
    if stripped.starts_with('[') {
        // IPv6: [addr]:port → addr
        if let Some(bracket_end) = stripped.find(']') {
            return stripped[1..bracket_end].to_string();
        }
    }
    // IPv4 or plain: host:port → host
    if let Some(colon) = stripped.rfind(':') {
        let host = &stripped[..colon];
        if !host.is_empty() {
            return host.to_string();
        }
    }
    stripped.to_string()
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

/// Parse a CIDR string like "fdaa::/16" or "10.7.1.0/24" into (network_addr, prefix_len).
fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr_part, len_part) = s.split_once('/')?;
    let addr: IpAddr = addr_part.parse().ok()?;
    let prefix_len: u8 = len_part.parse().ok()?;
    match addr {
        IpAddr::V4(_) if prefix_len > 32 => None,
        IpAddr::V6(_) if prefix_len > 128 => None,
        _ => Some((addr, prefix_len)),
    }
}

/// Check whether `addr` falls within the CIDR range (network_addr/prefix_len).
fn addr_in_cidr(addr: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (addr, network) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            if prefix_len == 0 { return true; }
            let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            if prefix_len == 0 { return true; }
            let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false, // v4 addr vs v6 network or vice versa
    }
}

/// Detect a non-Yggdrasil, non-loopback, non-link-local IPv6 address.
///
/// This is the node's **underlay** address — the real IP that other nodes
/// can use to reach this machine's Ygg listener.  Ygg peer URIs MUST be
/// underlay addresses because you don't tunnel Yggdrasil through Yggdrasil.
///
/// Reads `/proc/net/if_inet6` directly (no dependency on `ip` or `iproute2`).
pub fn detect_underlay_addr() -> Option<IpAddr> {
    // ── Explicit address override ─────────────────────────────────────────
    //   LAGOON_UNDERLAY_ADDR=10.7.1.37       (bare metal LAN)
    //   LAGOON_UNDERLAY_ADDR=fdaa::1          (Fly.io 6PN)
    if let Ok(val) = std::env::var("LAGOON_UNDERLAY_ADDR") {
        if let Ok(addr) = val.parse::<IpAddr>() {
            tracing::info!(%addr, "underlay: using LAGOON_UNDERLAY_ADDR override");
            return Some(addr);
        } else {
            tracing::warn!(val, "underlay: LAGOON_UNDERLAY_ADDR is not a valid IP, falling back");
        }
    }

    // ── Candidate filters ──────────────────────────────────────────────
    //
    // EXCLUDE (CIDR) — remove addresses matching this range from candidates:
    //   LAGOON_UNDERLAY_EXCLUDE=172.16.0.0/12   (Fly.io edge proxy IPs)
    //   LAGOON_UNDERLAY_EXCLUDE=169.254.0.0/16  (APIPA link-local)
    //   LAGOON_UNDERLAY_EXCLUDE=100.64.0.0/10   (CGNAT range)
    //
    // INCLUDE (CIDR) — keep only addresses within this range:
    //   LAGOON_UNDERLAY_INCLUDE=fdaa::/16        (Fly.io 6PN — all regions)
    //   LAGOON_UNDERLAY_INCLUDE=10.7.1.0/24      (bare metal LAN subnet)
    //   LAGOON_UNDERLAY_INCLUDE=192.168.1.0/24   (home lab)
    //
    // Both are optional. The heuristic always runs on whatever candidates
    // remain after filtering. On most deployments neither is needed —
    // the heuristic picks private networks by default.
    let exclude_cidr = std::env::var("LAGOON_UNDERLAY_EXCLUDE").ok().and_then(|val| {
        parse_cidr(&val).or_else(|| {
            tracing::warn!(val, "underlay: LAGOON_UNDERLAY_EXCLUDE is not a valid CIDR, ignoring");
            None
        })
    });
    let include_cidr = std::env::var("LAGOON_UNDERLAY_INCLUDE").ok().and_then(|val| {
        parse_cidr(&val).or_else(|| {
            tracing::warn!(val, "underlay: LAGOON_UNDERLAY_INCLUDE is not a valid CIDR, ignoring");
            None
        })
    });

    // Collect ALL candidate addresses, then pick the best match.
    let mut candidates: Vec<IpAddr> = Vec::new();

    // IPv4 from hostname -I.
    if let Ok(output) = std::process::Command::new("hostname")
        .args(["-I"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for token in stdout.split_whitespace() {
            if let Ok(ip) = token.parse::<IpAddr>() {
                if !ip.is_loopback() {
                    candidates.push(ip);
                }
            }
        }
    }

    // IPv6 from /proc/net/if_inet6, skipping virtual/overlay interfaces.
    if let Ok(content) = std::fs::read_to_string("/proc/net/if_inet6") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let hex = fields.first().copied().unwrap_or("");
            let dev = fields.get(5).copied().unwrap_or("");
            if hex.len() != 32 { continue; }
            // Skip virtual/bridge/tunnel interfaces.
            if dev.starts_with("br-")
                || dev.starts_with("docker")
                || dev.starts_with("veth")
                || dev.starts_with("virbr")
                || dev.starts_with("tun")
                || dev.starts_with("tap")
                || dev.starts_with("wg")
            { continue; }
            // Skip Yggdrasil overlay (02xx, 03xx), loopback, link-local.
            if hex.starts_with("02") || hex.starts_with("03") { continue; }
            if hex == "00000000000000000000000000000001" { continue; }
            if hex.starts_with("fe80") { continue; }
            let groups: Vec<&str> = (0..8).map(|i| &hex[i * 4..(i + 1) * 4]).collect();
            let addr_str = groups.join(":");
            if let Ok(addr) = addr_str.parse::<Ipv6Addr>() {
                candidates.push(IpAddr::V6(addr));
            }
        }
    }

    // ── Apply filters ───────────────────────────────────────────────────
    if let Some((net_addr, prefix_len)) = exclude_cidr {
        let before = candidates.len();
        candidates.retain(|c| !addr_in_cidr(*c, net_addr, prefix_len));
        let removed = before - candidates.len();
        if removed > 0 {
            tracing::info!(removed, "underlay: excluded {removed} addresses via LAGOON_UNDERLAY_EXCLUDE");
        }
    }
    if let Some((net_addr, prefix_len)) = include_cidr {
        let before = candidates.len();
        candidates.retain(|c| addr_in_cidr(*c, net_addr, prefix_len));
        let kept = candidates.len();
        tracing::info!(before, kept, "underlay: filtered by LAGOON_UNDERLAY_INCLUDE, {kept}/{before} remain");
    }

    // ── Heuristic ─────────────────────────────────────────────────────────
    // Priority: private IPv4 (RFC1918) > ULA IPv6 > global IPv6 > any.
    // Filters above narrow the candidate set; this picks the best from
    // whatever remains.
    let mut private_ipv4: Option<IpAddr> = None;
    let mut ula_v6: Option<IpAddr> = None;
    let mut global_v6: Option<IpAddr> = None;
    let mut any_addr: Option<IpAddr> = None;

    for candidate in &candidates {
        match candidate {
            IpAddr::V4(v4) => {
                if private_ipv4.is_none() && (v4.is_private() || v4.is_link_local()) {
                    private_ipv4 = Some(*candidate);
                }
                if any_addr.is_none() {
                    any_addr = Some(*candidate);
                }
            }
            IpAddr::V6(v6) => {
                let first_byte = v6.octets()[0];
                if (first_byte == 0xfc || first_byte == 0xfd) && ula_v6.is_none() {
                    ula_v6 = Some(*candidate);
                } else if global_v6.is_none() && first_byte != 0xfc && first_byte != 0xfd {
                    global_v6 = Some(*candidate);
                }
                if any_addr.is_none() {
                    any_addr = Some(*candidate);
                }
            }
        }
    }

    let selected = private_ipv4.or(ula_v6).or(global_v6).or(any_addr);
    if let Some(addr) = selected {
        tracing::info!(
            %addr,
            candidates = ?candidates,
            "underlay: heuristic selected address"
        );
        return Some(addr);
    }

    tracing::warn!("underlay: no suitable address found");
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
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
/// Reads `LAGOON_PEERS` for mesh federation endpoints (comma-separated).
///
/// Supported formats:
/// - `host.example.com` — WebSocket TLS on port 443
/// - `host:443` — explicit port, TLS auto-detected from port 443
/// - `host:6667` — plain TCP (LAN)
pub fn build_config() -> TransportConfig {
    let mut config = TransportConfig::new();

    config.yggdrasil_available = detect_yggdrasil_addr().is_some();

    if config.yggdrasil_available {
        info!("transport: Yggdrasil connectivity detected (TUN/system)");
    }

    // LAGOON_SWITCHBOARD_ADDR = global anycast switchboard (e.g. "109.224.228.162:9443").
    // Used by dial_missing_spiral_neighbors to reach peers via half-dial when no
    // direct underlay route exists. Separate from LAGOON_PEERS (bootstrap/mesh WebSocket).
    if let Ok(addr) = std::env::var("LAGOON_SWITCHBOARD_ADDR") {
        let addr = addr.trim().to_string();
        if !addr.is_empty() {
            info!(switchboard_addr = %addr, "transport: global switchboard address configured");
            config.switchboard_addr = Some(addr);
        }
    }

    // LAGOON_PEERS = mesh federation endpoints.
    if let Ok(peers_str) = std::env::var("LAGOON_PEERS") {
        for entry in peers_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((host, peer_entry)) = parse_peer_entry(entry) {
                if peer_entry.tls {
                    info!(host, port = peer_entry.port, "transport: peer (TLS)");
                } else {
                    info!(host, port = peer_entry.port, "transport: peer");
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
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
            format!("wss://[{host}]:{port}/api/mesh/ws")
        } else {
            format!("wss://{host}:{port}/api/mesh/ws")
        };
        assert_eq!(url, "wss://lon.lagun.co:443/api/mesh/ws");
    }

    #[test]
    fn ws_url_format_ipv6() {
        let host = "2a09:8280:5d::d2:e42f:0";
        let port = 443u16;
        let url = if host.contains(':') {
            format!("wss://[{host}]:{port}/api/mesh/ws")
        } else {
            format!("wss://{host}:{port}/api/mesh/ws")
        };
        assert_eq!(
            url,
            "wss://[2a09:8280:5d::d2:e42f:0]:443/api/mesh/ws"
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
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
                want: None,
                dial_host: None,
            },
        );
        let mode = select_transport_inner("lon.lagun.co", &peers, true);
        assert_eq!(mode, TransportMode::YggOverlay { addr: ygg });
    }
}
