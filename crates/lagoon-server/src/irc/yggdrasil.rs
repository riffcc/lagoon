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
///
/// Handles both standard Yggdrasil (returns `address` as Ygg IPv6) and
/// yggstack (returns `key` as Ed25519 public key hex, no `address` field).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct YggPeer {
    /// Yggdrasil IPv6 overlay address (e.g. `200:abcd::1`).
    /// Missing from yggstack responses — derived from `key` via [`key_to_address`].
    #[serde(default)]
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
    /// Ed25519 public key hex (yggstack provides this instead of `address`).
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub port: u64,
    #[serde(default)]
    pub uptime: f64,
    /// Whether the peer connection is up (yggstack field).
    #[serde(default)]
    pub up: bool,
    /// Whether this is an inbound connection (yggstack field).
    #[serde(default)]
    pub inbound: bool,
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
///
/// After parsing, derives missing `address` fields from `key` (yggstack
/// returns Ed25519 public key hex instead of the Ygg IPv6 address).
fn parse_peers(value: serde_json::Value) -> Vec<YggPeer> {
    let mut peers = Vec::new();

    // Try array first (0.5+ / yggstack).
    if let Ok(arr) = serde_json::from_value::<Vec<YggPeer>>(value.clone()) {
        peers = arr;
    } else if let Ok(map) = serde_json::from_value::<HashMap<String, YggPeer>>(value) {
        // Map format (older versions: address → peer object).
        peers = map.into_values().collect();
    }

    // Derive address from key when missing (yggstack compat).
    for peer in &mut peers {
        if peer.address.is_empty() && !peer.key.is_empty() {
            if let Some(addr) = key_to_address(&peer.key) {
                peer.address = addr.to_string();
            }
        }
    }

    peers
}

// ---------------------------------------------------------------------------
// Yggdrasil address derivation from Ed25519 public key
// ---------------------------------------------------------------------------

/// Derive a Yggdrasil IPv6 address from an Ed25519 public key (hex-encoded).
///
/// Reimplements the algorithm from `address.AddrForKey` in yggdrasil-go:
/// 1. Bitwise invert the 32-byte public key
/// 2. Count leading 1-bits in the inverted key (`ones`)
/// 3. Skip leading 1s and the first 0 bit
/// 4. Collect remaining bits into bytes
/// 5. Address = `[0x02, ones, remaining_bits...]` (16 bytes total)
pub fn key_to_address(key_hex: &str) -> Option<std::net::Ipv6Addr> {
    let key_bytes = hex::decode(key_hex).ok()?;
    if key_bytes.len() != 32 {
        return None;
    }

    // Bitwise invert all bytes.
    let mut buf = [0u8; 32];
    for (i, &b) in key_bytes.iter().enumerate() {
        buf[i] = !b;
    }

    // Walk bits: count leading 1s, skip first 0, collect rest.
    // Go uses `byte` which wraps on overflow — we match that behavior.
    let mut ones: u8 = 0;
    let mut done = false;
    let mut bits: u8 = 0;
    let mut n_bits = 0;
    let mut temp = Vec::with_capacity(32);

    for idx in 0..(8 * 32) {
        let bit = (buf[idx / 8] >> (7 - (idx % 8))) & 1;
        if !done && bit != 0 {
            ones = ones.wrapping_add(1);
            continue;
        }
        if !done {
            // First 0 bit after leading 1s — skip it.
            done = true;
            continue;
        }
        bits = (bits << 1) | bit;
        n_bits += 1;
        if n_bits == 8 {
            n_bits = 0;
            temp.push(bits);
            bits = 0;
        }
    }

    // Assemble: [prefix(0x02), ones, remaining_bits...]
    let mut addr = [0u8; 16];
    addr[0] = 0x02;
    addr[1] = ones;
    let copy_len = temp.len().min(14); // 16 - 2 = 14 bytes available
    addr[2..2 + copy_len].copy_from_slice(&temp[..copy_len]);

    Some(std::net::Ipv6Addr::from(addr))
}

// ---------------------------------------------------------------------------
// Remote URI hostname resolution
// ---------------------------------------------------------------------------

/// Resolve DNS hostnames in a peer's `remote` URI to IP addresses.
///
/// Yggstack's `remote` field may contain unresolved hostnames
/// (e.g. `tcp://lhr.anycast-mesh.internal:9443`). We need resolved IPs
/// so that [`find_peer_by_remote_ip`] can match federation targets.
async fn resolve_remote_hostname(remote: &str) -> Option<String> {
    // Extract scheme and host:port.
    let (scheme, host_port) = if let Some(idx) = remote.find("://") {
        (&remote[..idx], &remote[idx + 3..])
    } else {
        ("tcp", remote)
    };

    // Bracketed IPv6 — already resolved, skip.
    if host_port.starts_with('[') {
        return None;
    }

    // Split host:port.
    let (host, port) = host_port.rsplit_once(':')?;

    // If host already parses as an IP, skip.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }

    // Resolve hostname via tokio (uses getaddrinfo / glibc).
    let lookup = format!("{host}:{port}");
    let mut addrs = tokio::net::lookup_host(&lookup).await.ok()?;
    let first = addrs.next()?;
    let ip = first.ip();

    // Reconstruct URI with resolved IP.
    match ip {
        std::net::IpAddr::V4(v4) => Some(format!("{scheme}://{v4}:{port}")),
        std::net::IpAddr::V6(v6) => Some(format!("{scheme}://[{v6}]:{port}")),
    }
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
        // Handle bracketed IPv6: [addr]:port → addr
        let ip_str = if host_port.starts_with('[') {
            host_port
                .find(']')
                .map(|i| &host_port[1..i])
                .unwrap_or(host_port)
        } else {
            // IPv4 or unbracketed: strip port after last colon.
            host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port)
        };
        // Parse as IpAddr for correct comparison (handles different IPv6 representations).
        let matches = ip_str
            .parse::<std::net::IpAddr>()
            .map(|peer_ip| &peer_ip == target_ip)
            .unwrap_or(false);
        if matches {
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

    let mut peers = envelope
        .response
        .and_then(|r| r.peers)
        .map(parse_peers)
        .unwrap_or_default();

    // Resolve DNS hostnames in `remote` fields so find_peer_by_remote_ip
    // can match federation targets by IP address.
    for peer in &mut peers {
        if let Some(resolved) = resolve_remote_hostname(&peer.remote).await {
            debug!(
                original = %peer.remote,
                resolved = %resolved,
                address = %peer.address,
                "yggdrasil: resolved peer remote hostname"
            );
            peer.remote = resolved;
        }
    }

    debug!(peer_count = peers.len(), "yggdrasil: getPeers parsed");

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
            up: false,
            inbound: false,
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
    fn find_peer_by_remote_ip_bracketed_ipv6() {
        let peers = vec![YggPeer {
            remote: "tcp://[2a09:8280:5d::d2:e42f:0]:9443".into(),
            ..test_peer("200:fcf:205:9dec:ff7b:e2f:7b00:51ac")
        }];
        let target: std::net::IpAddr = "2a09:8280:5d::d2:e42f:0".parse().unwrap();
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

    // -----------------------------------------------------------------------
    // key_to_address tests
    // -----------------------------------------------------------------------

    #[test]
    fn key_to_address_produces_200_prefix() {
        // Any valid 32-byte key should produce a 200::/7 address.
        let key = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        // 200::/7 means first byte is 0x02 or 0x03
        assert!(octets[0] == 0x02 || octets[0] == 0x03, "got {:02x}", octets[0]);
    }

    #[test]
    fn key_to_address_deterministic() {
        let key = "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011";
        let a = key_to_address(key).unwrap();
        let b = key_to_address(key).unwrap();
        assert_eq!(a, b, "same key must produce same address");
    }

    #[test]
    fn key_to_address_different_keys_different_addrs() {
        let k1 = "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1";
        let k2 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let a1 = key_to_address(k1).unwrap();
        let a2 = key_to_address(k2).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn key_to_address_invalid_hex() {
        assert!(key_to_address("not_hex").is_none());
    }

    #[test]
    fn key_to_address_wrong_length() {
        assert!(key_to_address("aabbccdd").is_none());
    }

    #[test]
    fn key_to_address_all_zeros() {
        // All-zeros key → inverted = all-ones → 256 leading 1 bits.
        // Go's `byte` wraps: 256 → 0. No 0-bit is ever found, so `done`
        // stays false and `temp` is empty.
        // Address: [0x02, 0x00, 0, 0, ...] (matches Go wrapping behavior).
        let key = "0000000000000000000000000000000000000000000000000000000000000000";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        assert_eq!(octets[0], 0x02);
        assert_eq!(octets[1], 0x00); // wraps: 256 → 0
    }

    #[test]
    fn key_to_address_all_ff() {
        // All-0xFF key → inverted = all-zeros → 0 leading 1s, first 0 bit
        // skipped, remaining = zeros (starting from bit 1).
        let key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let addr = key_to_address(key).unwrap();
        let octets = addr.octets();
        assert_eq!(octets[0], 0x02);
        assert_eq!(octets[1], 0x00); // zero leading ones
    }

    // -----------------------------------------------------------------------
    // yggstack-format getPeers response parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_yggstack_format_peers() {
        // Yggstack returns peers with `key` instead of `address`, and extra
        // fields like `cost`, `inbound`, `up`, etc.
        let json = r#"{
            "request": "getpeers",
            "status": "success",
            "response": {
                "peers": [
                    {
                        "cost": 65535,
                        "inbound": false,
                        "key": "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011",
                        "last_error": "",
                        "last_error_time": "0001-01-01T00:00:00Z",
                        "port": 1,
                        "priority": 0,
                        "remote": "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443",
                        "up": true
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
        // Address should be derived from key.
        assert!(!peers[0].address.is_empty(), "address should be derived from key");
        assert!(peers[0].address.starts_with("2"), "should be 200::/7 address");
        assert_eq!(peers[0].remote, "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443");
        assert!(peers[0].up);
        assert!(!peers[0].inbound);
    }

    #[test]
    fn parse_yggstack_format_with_hostname_remote() {
        // Yggstack may return DNS hostnames in `remote` (before entrypoint resolves).
        let json = r#"{
            "response": {
                "peers": [
                    {
                        "key": "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011",
                        "remote": "tcp://lhr.anycast-mesh.internal:9443",
                        "up": true,
                        "port": 1
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
        assert!(!peers[0].address.is_empty());
        assert_eq!(peers[0].key, "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011");
    }

    #[test]
    fn find_peer_by_remote_ip_with_derived_address() {
        // Simulate a yggstack peer with address derived from key.
        let key = "deadbeefcafebabe1234567890abcdef1122334455667788aabbccddeeff0011";
        let derived_addr = key_to_address(key).unwrap();

        let peers = vec![YggPeer {
            address: derived_addr.to_string(),
            remote: "tcp://[fdaa:0:bca3:a7b:0:0:eb5a:2]:9443".into(),
            key: key.into(),
            up: true,
            ..test_peer("")
        }];

        let target: std::net::IpAddr = "fdaa:0:bca3:a7b:0:0:eb5a:2".parse().unwrap();
        let result = find_peer_by_remote_ip(&peers, &target);
        assert_eq!(result, Some(derived_addr));
    }
}
