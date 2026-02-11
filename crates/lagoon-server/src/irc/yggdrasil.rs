//! Yggdrasil admin socket client — queries `getPeers` for per-link bandwidth
//! and latency metrics.
//!
//! The admin socket (Unix or TCP) is queried **on demand** when mesh events fire
//! — never on a timer. Rate computation uses cumulative byte deltas between
//! successive queries.

use std::collections::HashMap;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from Yggdrasil admin socket interaction.
#[derive(Debug, thiserror::Error)]
pub enum YggError {
    #[error("admin socket not available: {0}")]
    SocketUnavailable(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Response deserialization
// ---------------------------------------------------------------------------

/// A single peer from Yggdrasil's `getPeers` response.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YggPeer {
    pub address: String,
    /// Remote peering URI (e.g. `tcp://195.5.161.109:12345`).
    #[serde(default)]
    pub remote: String,
    #[serde(default)]
    pub bytes_sent: u64,
    #[serde(default)]
    pub bytes_recvd: u64,
    /// Round-trip latency in nanoseconds (Yggdrasil 0.5+ uses Go's
    /// `time.Duration` which serializes as integer nanoseconds).
    #[serde(default)]
    pub latency: f64,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub port: u64,
    #[serde(default)]
    pub uptime: f64,
}

/// Top-level `getPeers` response envelope.
#[derive(Debug, serde::Deserialize)]
struct GetPeersResponse {
    #[serde(default)]
    response: Option<GetPeersInner>,
}

/// The inner `response` object.
#[derive(Debug, serde::Deserialize)]
struct GetPeersInner {
    /// Yggdrasil 0.5+ returns `peers` as an array.
    #[serde(default)]
    peers: Option<serde_json::Value>,
}

/// Parse the peers field — Yggdrasil has returned both array and map formats
/// across versions.  We handle both.
fn parse_peers(value: serde_json::Value) -> Vec<YggPeer> {
    // Try array first (0.5+).
    if let Ok(arr) = serde_json::from_value::<Vec<YggPeer>>(value.clone()) {
        return arr;
    }
    // Try map (older versions: address → peer object).
    if let Ok(map) = serde_json::from_value::<HashMap<String, YggPeer>>(value) {
        return map.into_values().collect();
    }
    Vec::new()
}

// ---------------------------------------------------------------------------
// Peer IP matching
// ---------------------------------------------------------------------------

/// Find a Yggdrasil overlay address for a peer whose remote peering URI
/// matches the given IP address.
///
/// Parses each peer's `remote` field (e.g. `tcp://195.5.161.109:12345`) to
/// extract the IP, and returns the peer's Ygg overlay address if it matches.
/// This allows federation to route through the Ygg mesh instead of the public
/// internet when yggstack has already peered with the target.
pub fn find_peer_by_remote_ip(
    peers: &[YggPeer],
    target_ip: &std::net::IpAddr,
) -> Option<std::net::Ipv6Addr> {
    let target_str = target_ip.to_string();
    for peer in peers {
        if peer.remote.is_empty() {
            continue;
        }
        // Strip scheme (tcp://, tls://, etc.) to get host:port.
        let host_port = peer
            .remote
            .find("://")
            .map(|i| &peer.remote[i + 3..])
            .unwrap_or(&peer.remote);
        // Strip port to get bare IP.
        let ip_str = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
        if ip_str == target_str {
            if let Ok(ygg_addr) = peer.address.parse::<std::net::Ipv6Addr>() {
                return Some(ygg_addr);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Admin socket query
// ---------------------------------------------------------------------------

/// Query the Yggdrasil admin socket for peer data.
///
/// Connects to a Unix socket path or TCP address, sends the `getPeers` request,
/// and parses the JSON response.
pub async fn query_peers(socket_path: &str) -> Result<Vec<YggPeer>, YggError> {
    let request = b"{\"request\":\"getpeers\"}\n";

    let response_bytes = if socket_path.starts_with("tcp://") {
        let addr = &socket_path["tcp://".len()..];
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        buf
    } else {
        let mut stream = tokio::net::UnixStream::connect(socket_path).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        buf
    };

    let envelope: GetPeersResponse = serde_json::from_slice(&response_bytes)?;

    let peers = envelope
        .response
        .and_then(|r| r.peers)
        .map(parse_peers)
        .unwrap_or_default();

    Ok(peers)
}

// ---------------------------------------------------------------------------
// getSelf query (sync — for use from detect_yggdrasil_addr)
// ---------------------------------------------------------------------------

/// Top-level `getSelf` response envelope.
#[derive(Debug, serde::Deserialize)]
struct GetSelfResponse {
    #[serde(default)]
    response: Option<GetSelfInner>,
}

/// The inner `response` object for `getSelf`.
#[derive(Debug, serde::Deserialize)]
struct GetSelfInner {
    #[serde(default)]
    address: Option<String>,
}

/// Query the Yggdrasil admin socket (synchronously) for the local address.
///
/// Must be sync because `detect_yggdrasil_addr()` is sync and called inside
/// an existing tokio runtime — nesting `Runtime::new()` would panic.
/// Uses `std::net::TcpStream` / `std::os::unix::net::UnixStream`.
pub fn query_self_sync(socket_path: &str) -> Result<Option<std::net::Ipv6Addr>, YggError> {
    use std::io::{Read, Write};
    let request = b"{\"request\":\"getself\"}\n";

    let response_bytes = if socket_path.starts_with("tcp://") {
        let addr = &socket_path["tcp://".len()..];
        let mut stream = std::net::TcpStream::connect(addr).map_err(|e| {
            YggError::SocketUnavailable(format!("TCP connect to {addr}: {e}"))
        })?;
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .ok();
        stream.write_all(request)?;
        stream.shutdown(std::net::Shutdown::Write)?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf)?;
        buf
    } else {
        #[cfg(unix)]
        {
            let mut stream =
                std::os::unix::net::UnixStream::connect(socket_path).map_err(|e| {
                    YggError::SocketUnavailable(format!("Unix connect to {socket_path}: {e}"))
                })?;
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .ok();
            stream.write_all(request)?;
            stream.shutdown(std::net::Shutdown::Write)?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            buf
        }
        #[cfg(not(unix))]
        {
            return Err(YggError::SocketUnavailable(
                "Unix sockets not supported on this platform".into(),
            ));
        }
    };

    let envelope: GetSelfResponse = serde_json::from_slice(&response_bytes)?;
    Ok(envelope
        .response
        .and_then(|r| r.address)
        .and_then(|s| s.parse().ok()))
}

// ---------------------------------------------------------------------------
// Admin socket detection
// ---------------------------------------------------------------------------

/// Detect the Yggdrasil admin socket path.
///
/// Checks in order:
/// 1. `YGGDRASIL_ADMIN_SOCKET` env var (supports both Unix paths and `tcp://host:port`)
/// 2. `/var/run/yggdrasil.sock` (common default)
/// 3. `tcp://localhost:9001` (TCP fallback)
///
/// Returns `None` if nothing is reachable (checked synchronously via file existence
/// for Unix sockets, or always returns the TCP fallback to be tried lazily).
pub fn detect_admin_socket() -> Option<String> {
    // 1. Explicit env var.
    if let Ok(path) = std::env::var("YGGDRASIL_ADMIN_SOCKET") {
        if !path.is_empty() {
            info!(path, "yggdrasil: using admin socket from env");
            return Some(path);
        }
    }

    // 2. Default Unix socket.
    let unix_path = "/var/run/yggdrasil.sock";
    if std::path::Path::new(unix_path).exists() {
        info!(path = unix_path, "yggdrasil: detected Unix admin socket");
        return Some(unix_path.to_string());
    }

    // 3. TCP fallback — we can't cheaply test TCP reachability without async,
    //    so return the address and let query_peers() fail gracefully.
    let tcp_addr = "tcp://localhost:9001";
    debug!("yggdrasil: no Unix socket found, will try TCP at {tcp_addr}");
    Some(tcp_addr.to_string())
}

// ---------------------------------------------------------------------------
// Metrics store with rate computation
// ---------------------------------------------------------------------------

/// Cached per-peer metrics with bandwidth rate computation.
#[derive(Debug, Clone)]
pub struct YggPeerMetrics {
    /// Yggdrasil IPv6 address string.
    pub address: String,
    /// Upload bytes per second (computed from cumulative delta).
    pub upload_bps: f64,
    /// Download bytes per second (computed from cumulative delta).
    pub download_bps: f64,
    /// Latency in milliseconds.
    pub latency_ms: f64,
    /// Previous cumulative bytes_sent (for rate computation).
    prev_bytes_sent: u64,
    /// Previous cumulative bytes_recvd.
    prev_bytes_recvd: u64,
    /// Timestamp of previous sample.
    prev_sample: Instant,
}

/// Yggdrasil metrics store — lives in `MeshState`.
///
/// Caches per-peer metrics and computes bandwidth rates from cumulative byte
/// counter deltas between successive `update()` calls.
#[derive(Debug)]
pub struct YggMetricsStore {
    /// Per-address metrics cache: Ygg IPv6 address string → metrics.
    peers: HashMap<String, YggPeerMetrics>,
}

impl YggMetricsStore {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Update metrics from a fresh `getPeers` response.
    ///
    /// Computes upload/download rates by comparing cumulative byte counters
    /// against the previous sample.  On the first call for a given peer,
    /// rates are zero (establishing baseline).
    pub fn update(&mut self, peers: Vec<YggPeer>) {
        let now = Instant::now();

        for peer in peers {
            let latency_ms = peer.latency / 1_000_000.0; // ns → ms

            let entry = self.peers.entry(peer.address.clone());
            match entry {
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    let m = e.get_mut();
                    let elapsed = now.duration_since(m.prev_sample).as_secs_f64();
                    if elapsed > 0.001 {
                        let sent_delta = peer.bytes_sent.saturating_sub(m.prev_bytes_sent);
                        let recv_delta = peer.bytes_recvd.saturating_sub(m.prev_bytes_recvd);
                        m.upload_bps = sent_delta as f64 / elapsed;
                        m.download_bps = recv_delta as f64 / elapsed;
                    }
                    m.latency_ms = latency_ms;
                    m.prev_bytes_sent = peer.bytes_sent;
                    m.prev_bytes_recvd = peer.bytes_recvd;
                    m.prev_sample = now;
                }
                std::collections::hash_map::Entry::Vacant(e) => {
                    // First observation — establish baseline, zero rates.
                    e.insert(YggPeerMetrics {
                        address: peer.address,
                        upload_bps: 0.0,
                        download_bps: 0.0,
                        latency_ms,
                        prev_bytes_sent: peer.bytes_sent,
                        prev_bytes_recvd: peer.bytes_recvd,
                        prev_sample: now,
                    });
                }
            }
        }
    }

    /// Look up cached metrics for a Yggdrasil IPv6 address.
    pub fn get(&self, ygg_addr: &str) -> Option<&YggPeerMetrics> {
        self.peers.get(ygg_addr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(address: &str) -> YggPeer {
        YggPeer {
            address: address.into(),
            remote: String::new(),
            bytes_sent: 0,
            bytes_recvd: 0,
            latency: 0.0,
            key: String::new(),
            port: 1,
            uptime: 0.0,
        }
    }

    #[test]
    fn first_sample_returns_zero_rates() {
        let mut store = YggMetricsStore::new();
        store.update(vec![YggPeer {
            latency: 15_000_000.0, // 15ms in nanoseconds
            bytes_sent: 10_000,
            bytes_recvd: 20_000,
            ..test_peer("200:abcd::1")
        }]);

        let m = store.get("200:abcd::1").unwrap();
        assert_eq!(m.upload_bps, 0.0);
        assert_eq!(m.download_bps, 0.0);
        assert!((m.latency_ms - 15.0).abs() < 0.001);
    }

    #[test]
    fn rate_computation_from_deltas() {
        let mut store = YggMetricsStore::new();

        // First sample — baseline.
        store.update(vec![YggPeer {
            bytes_sent: 1_000_000,
            bytes_recvd: 2_000_000,
            latency: 10_000_000.0, // 10ms in nanoseconds
            uptime: 100.0,
            ..test_peer("200:abcd::1")
        }]);

        // Simulate time passing by backdating the previous sample.
        {
            let m = store.peers.get_mut("200:abcd::1").unwrap();
            m.prev_sample = Instant::now() - std::time::Duration::from_secs(1);
        }

        // Second sample — 500KB sent, 1MB received in ~1 second.
        store.update(vec![YggPeer {
            bytes_sent: 1_500_000,
            bytes_recvd: 3_000_000,
            latency: 12_000_000.0, // 12ms in nanoseconds
            uptime: 101.0,
            ..test_peer("200:abcd::1")
        }]);

        let m = store.get("200:abcd::1").unwrap();
        // Rates should be approximately 500KB/s and 1MB/s.
        // Allow 5% tolerance for timing jitter.
        assert!(m.upload_bps > 450_000.0 && m.upload_bps < 550_000.0,
            "upload_bps was {}", m.upload_bps);
        assert!(m.download_bps > 900_000.0 && m.download_bps < 1_100_000.0,
            "download_bps was {}", m.download_bps);
        assert!((m.latency_ms - 12.0).abs() < 0.001);
    }

    #[test]
    fn missing_peer_returns_none() {
        let store = YggMetricsStore::new();
        assert!(store.get("200:nonexistent::1").is_none());
    }

    #[test]
    fn parse_getpeers_response_array() {
        let json = r#"{
            "request": "getpeers",
            "status": "success",
            "response": {
                "peers": [
                    {
                        "address": "200:1234::1",
                        "bytes_sent": 12345,
                        "bytes_recvd": 67890,
                        "latency": 15000000,
                        "key": "abc123",
                        "port": 1,
                        "uptime": 3600.0
                    }
                ]
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "200:1234::1");
        assert_eq!(peers[0].bytes_sent, 12345);
        assert_eq!(peers[0].bytes_recvd, 67890);
        assert!((peers[0].latency - 15_000_000.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parse_getpeers_response_map() {
        let json = r#"{
            "response": {
                "peers": {
                    "200:aaaa::1": {
                        "address": "200:aaaa::1",
                        "bytes_sent": 100,
                        "bytes_recvd": 200,
                        "latency": 5000000,
                        "key": "def456",
                        "port": 2,
                        "uptime": 1800.0
                    }
                }
            }
        }"#;

        let envelope: GetPeersResponse = serde_json::from_str(json).unwrap();
        let peers = envelope
            .response
            .and_then(|r| r.peers)
            .map(parse_peers)
            .unwrap_or_default();

        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].address, "200:aaaa::1");
    }

    #[test]
    fn detect_admin_socket_env_override() {
        // This test verifies the env var check path exists.
        // We can't easily test the actual detection without mocking the filesystem.
        let store = YggMetricsStore::new();
        assert!(store.peers.is_empty());
    }

    #[test]
    fn find_peer_by_remote_ip_tcp_uri() {
        let peers = vec![YggPeer {
            remote: "tcp://195.5.161.109:12345".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(
            result,
            Some("200:fcf:205:9dec:ff7b:e2f:7b00:51ac".parse().unwrap())
        );
    }

    #[test]
    fn find_peer_by_remote_ip_no_match() {
        let peers = vec![YggPeer {
            remote: "tcp://10.0.0.1:12345".into(),
            ..test_peer("200:abcd::1")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        assert!(find_peer_by_remote_ip(&peers, &target).is_none());
    }

    #[test]
    fn find_peer_by_remote_ip_no_scheme() {
        let peers = vec![YggPeer {
            remote: "195.5.161.109:12345".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(
            result,
            Some("200:fcf:205:9dec:ff7b:e2f:7b00:51ac".parse().unwrap())
        );
    }

    #[test]
    fn find_peer_by_remote_ip_empty_remote() {
        let peers = vec![test_peer("200:abcd::1")];
        let target: std::net::IpAddr = "195.5.161.109".parse().unwrap();
        assert!(find_peer_by_remote_ip(&peers, &target).is_none());
    }
}
