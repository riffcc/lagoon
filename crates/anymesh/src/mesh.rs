//! Distributed mesh peering with RTT measurement and migration support.
//!
//! Nodes peer via a simple text protocol:
//! - `HELLO <name>` — identity exchange
//! - `PING <timestamp_nanos>` — latency probe (outbound only)
//! - `PONG <timestamp_nanos>` — latency response (inbound only)
//! - `RESULT <name> <min> <avg> <max>` — RTT summary
//! - `MIGRATE <base64-bincode>` — socket migration state
//!
//! The mesh is event-driven. No polling, no sleeps.

use std::net::SocketAddr;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::repair::SocketMigration;
use crate::Error;

const DEFAULT_PORT: u16 = 42105;
const PING_COUNT: usize = 20;

/// Configuration for a mesh node.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    pub node_name: String,
    pub bind_ip: Option<String>,
    pub port: u16,
    pub peers: Vec<String>,
}

impl MeshConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let anycast_ip = std::env::var("ANYCAST_IP")
            .ok()
            .filter(|s| !s.is_empty());
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_PORT);
        let node_name = std::env::var("NODE_NAME")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                hostname::get()
                    .map(|h| h.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "unknown".into())
            });
        let peers: Vec<String> = std::env::var("PEERS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();

        Self {
            node_name,
            bind_ip: anycast_ip,
            port,
            peers,
        }
    }
}

/// Events emitted by the mesh.
#[derive(Debug)]
pub enum MeshEvent {
    PeerConnected {
        name: String,
        addr: SocketAddr,
    },
    PeerDisconnected {
        name: String,
    },
    RttMeasured {
        peer: String,
        min_us: f64,
        avg_us: f64,
        max_us: f64,
        samples: usize,
    },
    MigrationReceived {
        from_peer: String,
        state: SocketMigration,
    },
}

/// Run a peer session (one connection, either inbound or outbound).
///
/// Outbound connections send PING probes and measure RTT.
/// Inbound connections respond with PONG.
pub async fn peer_session(
    our_name: &str,
    stream: TcpStream,
    is_outbound: bool,
    event_tx: &mpsc::UnboundedSender<MeshEvent>,
) {
    let peer_addr = stream
        .peer_addr()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // Send HELLO.
    if writer
        .write_all(format!("HELLO {our_name}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }

    // Receive HELLO.
    let peer_name = match lines.next_line().await {
        Ok(Some(line)) => line
            .strip_prefix("HELLO ")
            .unwrap_or("unknown")
            .to_owned(),
        _ => return,
    };

    let direction = if is_outbound { "→" } else { "←" };
    tracing::info!(peer = %peer_name, addr = %peer_addr, direction, "peered");

    let _ = event_tx.send(MeshEvent::PeerConnected {
        name: peer_name.clone(),
        addr: peer_addr,
    });

    if is_outbound {
        // Measure RTT with PING/PONG.
        let mut rtts_us = Vec::with_capacity(PING_COUNT);
        for _ in 0..PING_COUNT {
            let t0 = std::time::Instant::now();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            if writer
                .write_all(format!("PING {nanos}\n").as_bytes())
                .await
                .is_err()
            {
                break;
            }
            match lines.next_line().await {
                Ok(Some(line)) if line.starts_with("PONG ") => {
                    rtts_us.push(t0.elapsed().as_micros() as f64);
                }
                _ => break,
            }
        }
        if !rtts_us.is_empty() {
            let min = rtts_us.iter().cloned().fold(f64::INFINITY, f64::min);
            let max = rtts_us
                .iter()
                .cloned()
                .fold(f64::NEG_INFINITY, f64::max);
            let avg = rtts_us.iter().sum::<f64>() / rtts_us.len() as f64;
            tracing::info!(
                peer = %peer_name,
                min_us = format!("{min:.0}"),
                avg_us = format!("{avg:.0}"),
                max_us = format!("{max:.0}"),
                samples = rtts_us.len(),
                "rtt measured"
            );
            let _ = event_tx.send(MeshEvent::RttMeasured {
                peer: peer_name.clone(),
                min_us: min,
                avg_us: avg,
                max_us: max,
                samples: rtts_us.len(),
            });
            let _ = writer
                .write_all(
                    format!("RESULT {our_name} {min:.0} {avg:.0} {max:.0}\n").as_bytes(),
                )
                .await;
        }
    } else {
        // Inbound: respond to PINGs.
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if let Some(ts) = line.strip_prefix("PING ") {
                        if writer
                            .write_all(format!("PONG {ts}\n").as_bytes())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    } else if line.starts_with("MIGRATE ") {
                        // Decode migration state.
                        if let Some(b64) = line.strip_prefix("MIGRATE ") {
                            if let Ok(bytes) = base64::Engine::decode(
                                &base64::engine::general_purpose::STANDARD,
                                b64,
                            ) {
                                if let Ok(state) =
                                    bincode::deserialize::<SocketMigration>(&bytes)
                                {
                                    let _ = event_tx.send(MeshEvent::MigrationReceived {
                                        from_peer: peer_name.clone(),
                                        state,
                                    });
                                }
                            }
                        }
                        break;
                    } else if line.starts_with("RESULT ") {
                        break;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    tracing::info!(peer = %peer_name, "session complete");
    let _ = event_tx.send(MeshEvent::PeerDisconnected {
        name: peer_name,
    });
}

/// Run the mesh node: listen for peers and dial configured peers.
pub async fn run_mesh(config: MeshConfig) -> Result<mpsc::UnboundedReceiver<MeshEvent>, Error> {
    let ip = config.bind_ip.as_deref().unwrap_or("0.0.0.0");
    let bind_addr = format_bind_addr(ip, config.port)?;

    let listener = TcpListener::bind(bind_addr).await?;
    tracing::info!(name = %config.node_name, addr = %bind_addr, "listening");

    let (event_tx, event_rx) = mpsc::unbounded_channel();

    // Dial configured peers.
    for peer in &config.peers {
        let (host, port) = parse_peer_addr(peer, config.port);
        let name = config.node_name.clone();
        let tx = event_tx.clone();
        tokio::spawn(async move {
            let dial_target = format!("{host}:{port}");
            tracing::info!(target = %dial_target, "dialing");
            match TcpStream::connect(dial_target.as_str()).await {
                Ok(stream) => peer_session(&name, stream, true, &tx).await,
                Err(e) => tracing::warn!(target = %dial_target, error = %e, "failed to dial"),
            }
        });
    }

    // Accept inbound peers.
    let name = config.node_name.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    tracing::debug!(addr = %addr, "incoming");
                    let name = name.clone();
                    let tx = event_tx.clone();
                    tokio::spawn(
                        async move { peer_session(&name, stream, false, &tx).await },
                    );
                }
                Err(e) => tracing::warn!(error = %e, "accept error"),
            }
        }
    });

    Ok(event_rx)
}

/// Parse a bind address string into a `SocketAddr`.
///
/// Handles both IPv4 (`0.0.0.0:port`) and IPv6 (`[::]:port`) formats.
fn format_bind_addr(ip: &str, port: u16) -> Result<SocketAddr, Error> {
    // If it's an IPv6 address (contains `::`), wrap in brackets.
    let formatted = if ip.contains("::") || ip == ":" {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    };
    formatted
        .parse()
        .map_err(|e| Error::Protocol(format!("invalid bind address '{formatted}': {e}")))
}

/// Parse a peer address string into (host, port).
///
/// Supports:
/// - `hostname` → (hostname, default_port)
/// - `hostname:port` → (hostname, port)
/// - `1.2.3.4:port` → (1.2.3.4, port)
/// - `[::1]:port` → (::1, port)
fn parse_peer_addr(peer: &str, default_port: u16) -> (String, u16) {
    // IPv6 literal with port: [::1]:42105
    if let Some(rest) = peer.strip_prefix('[') {
        if let Some((addr, port_str)) = rest.rsplit_once("]:") {
            if let Ok(port) = port_str.parse::<u16>() {
                return (addr.to_owned(), port);
            }
        }
        // Bare [::1] without port
        let addr = rest.trim_end_matches(']');
        return (addr.to_owned(), default_port);
    }
    // hostname:port or ip:port — but only split on LAST colon to avoid
    // splitting IPv6 addresses. For hostnames (no brackets), the last
    // colon is the port separator.
    if let Some((host, port_str)) = peer.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_owned(), port);
        }
    }
    // Plain hostname or IP
    (peer.to_owned(), default_port)
}

/// Encode a `SocketMigration` as a base64 string for wire transport.
pub fn encode_migration(state: &SocketMigration) -> String {
    use base64::Engine;
    let bytes = bincode::serialize(state).unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a `SocketMigration` from a base64 string.
pub fn decode_migration(b64: &str) -> Result<SocketMigration, Error> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| Error::Protocol(format!("base64 decode: {e}")))?;
    bincode::deserialize(&bytes).map_err(|e| Error::Protocol(format!("bincode decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_encode_decode_roundtrip() {
        use crate::repair::{SocketMigration, TcpRepairWindow};
        use std::net::{Ipv4Addr, SocketAddrV4};

        let state = SocketMigration {
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42105)),
            remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9999)),
            send_seq: 123456,
            recv_seq: 654321,
            window: TcpRepairWindow::default(),
        };

        let encoded = encode_migration(&state);
        let decoded = decode_migration(&encoded).unwrap();
        assert_eq!(state, decoded);
    }

    #[test]
    fn config_defaults() {
        let config = MeshConfig {
            node_name: "test".into(),
            bind_ip: None,
            port: 42105,
            peers: vec![],
        };
        assert_eq!(config.port, 42105);
        assert!(config.peers.is_empty());
    }

    #[test]
    fn parse_peer_addr_hostname_only() {
        let (host, port) = parse_peer_addr("lhr.anycast-mesh.internal", 42105);
        assert_eq!(host, "lhr.anycast-mesh.internal");
        assert_eq!(port, 42105);
    }

    #[test]
    fn parse_peer_addr_hostname_with_port() {
        let (host, port) = parse_peer_addr("lhr.anycast-mesh.internal:9999", 42105);
        assert_eq!(host, "lhr.anycast-mesh.internal");
        assert_eq!(port, 9999);
    }

    #[test]
    fn parse_peer_addr_ipv4_with_port() {
        let (host, port) = parse_peer_addr("10.0.0.1:42105", 9999);
        assert_eq!(host, "10.0.0.1");
        assert_eq!(port, 42105);
    }

    #[test]
    fn parse_peer_addr_ipv6_bracketed() {
        let (host, port) = parse_peer_addr("[::1]:42105", 9999);
        assert_eq!(host, "::1");
        assert_eq!(port, 42105);
    }

    #[test]
    fn parse_peer_addr_ipv6_bare_brackets() {
        let (host, port) = parse_peer_addr("[fdaa:47:35ee::2]", 42105);
        assert_eq!(host, "fdaa:47:35ee::2");
        assert_eq!(port, 42105);
    }

    #[test]
    fn format_bind_addr_ipv4() {
        let addr = format_bind_addr("0.0.0.0", 42105).unwrap();
        assert_eq!(addr.to_string(), "0.0.0.0:42105");
    }

    #[test]
    fn format_bind_addr_ipv6() {
        let addr = format_bind_addr("::", 42105).unwrap();
        assert_eq!(addr.to_string(), "[::]:42105");
    }
}
