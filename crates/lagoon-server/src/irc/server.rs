/// IRC server core — state management, client handling, command dispatch.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use futures::SinkExt;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch, RwLock};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use base64::Engine as _;

use super::codec::IrcCodec;
use super::community::CommunityStore;
use super::federation::{self, FederatedChannel, FederationManager, RelayEvent};
use super::invite::InviteStore;
use super::lens::LensIdentity;
use super::profile::ProfileStore;
use super::message::Message;
use super::modes::{self, BanEntry, ChannelModes, WhowasBuffer};
use super::transport::{self, TransportConfig};

/// Normalize a string for case-insensitive IRC comparison (CASEMAPPING=ascii).
pub(crate) fn irc_lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Server identity — from `SERVER_NAME` env var, or system hostname at startup.
pub static SERVER_NAME: LazyLock<String> = LazyLock::new(|| {
    std::env::var("SERVER_NAME")
        .ok()
        .filter(|s| s.contains('.'))
        .or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .filter(|h| h.contains('.'))
        })
        .unwrap_or_else(|| "lagoon.lagun.co".into())
});

/// Site identity — the logical domain for supernode clustering.
///
/// Derived from SERVER_NAME by stripping the first subdomain:
///   `lon.lagun.co` → `lagun.co`
///   `lagun.co` → `lagun.co` (bare domain = site itself)
///
/// Override with `SITE_NAME` env var.
pub static SITE_NAME: LazyLock<String> = LazyLock::new(|| {
    if let Ok(val) = std::env::var("SITE_NAME") {
        if !val.is_empty() && val.contains('.') {
            return val;
        }
    }
    let sn = &*SERVER_NAME;
    // 2+ dots means there's a subdomain to strip.
    if sn.matches('.').count() >= 2 {
        // "lon.lagun.co" → "lagun.co"
        sn.splitn(2, '.').nth(1).unwrap_or(sn).to_string()
    } else {
        // "lagun.co" → "lagun.co" (the whole thing IS the site)
        sn.to_string()
    }
});

/// Node identity — unique name within a site.
///
/// Derived from SERVER_NAME by extracting the first subdomain:
///   `lon.lagun.co` → `lon`
///   `lagun.co` → auto-derived from system hostname
///
/// Override with `LAGOON_NODE_NAME` env var (or `NODE_NAME` for backward compat).
pub static NODE_NAME: LazyLock<String> = LazyLock::new(|| {
    for var in ["LAGOON_NODE_NAME", "NODE_NAME"] {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                return val;
            }
        }
    }
    let sn = &*SERVER_NAME;
    if sn.matches('.').count() >= 2 {
        // "lon.lagun.co" → "lon"
        sn.splitn(2, '.').next().unwrap_or(sn).to_string()
    } else {
        // Bare domain — derive from system hostname.
        hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "node".to_string())
    }
});

/// Derive site_name from a server_name string (same logic as SITE_NAME static).
pub fn derive_site_name(server_name: &str) -> String {
    if server_name.matches('.').count() >= 2 {
        server_name.splitn(2, '.').nth(1).unwrap_or(server_name).to_string()
    } else {
        server_name.to_string()
    }
}

/// Derive node_name from a server_name string (same logic as NODE_NAME static).
pub fn derive_node_name(server_name: &str) -> String {
    if server_name.matches('.').count() >= 2 {
        server_name.splitn(2, '.').next().unwrap_or(server_name).to_string()
    } else {
        server_name.to_string()
    }
}

/// Human-friendly display name for the welcome message.
pub static DISPLAY_NAME: LazyLock<String> = LazyLock::new(|| {
    let host = &*SERVER_NAME;
    if host.starts_with("lagoon.") {
        "Lagun".into()
    } else if host.starts_with("lon.") {
        "Lagun London".into()
    } else if host.starts_with("per.") {
        "Lagun Perth".into()
    } else if host.starts_with("nyc.") {
        "Lagun NYC".into()
    } else {
        "Lagun's Lagoon".into()
    }
});

/// NETWORK= token for ISUPPORT (no spaces allowed in IRC tokens).
pub static NETWORK_TAG: LazyLock<String> = LazyLock::new(|| {
    let host = &*SERVER_NAME;
    if host.starts_with("lagoon.") {
        "Lagun".into()
    } else if host.starts_with("lon.") {
        "Lagun-London".into()
    } else if host.starts_with("per.") {
        "Lagun-Perth".into()
    } else if host.starts_with("nyc.") {
        "Lagun-NYC".into()
    } else {
        "Lagun".into()
    }
});

/// Channel membership prefix levels (ordered for comparison).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberPrefix {
    Normal,
    Voice,   // +
    Op,      // @
    Admin,   // &
    Owner,   // ~
}

impl MemberPrefix {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Owner => "~",
            Self::Admin => "&",
            Self::Op => "@",
            Self::Voice => "+",
            Self::Normal => "",
        }
    }
}

/// Information about a known mesh peer.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshPeerInfo {
    /// Cryptographic PeerID (`"b3b3/{hex}"`) — per-node identity derived from Ed25519 key.
    #[serde(alias = "lens_id")]
    pub peer_id: String,
    /// The peer's server name (e.g. `"per.lagun.co"`).
    pub server_name: String,
    /// Hex-encoded ed25519 public key.
    pub public_key_hex: String,
    /// Port the peer listens on (default 6667).
    #[serde(default = "default_peer_port")]
    pub port: u16,
    /// Whether the peer uses TLS/WSS (default false).
    #[serde(default)]
    pub tls: bool,
    /// Unix timestamp of last contact with this peer.
    #[serde(default)]
    pub last_seen: u64,
    /// Claimed SPIRAL slot index (None = peer hasn't claimed yet).
    #[serde(default)]
    pub spiral_index: Option<u64>,
    /// VDF genesis hash (hex-encoded, derived from peer's public key).
    #[serde(default)]
    pub vdf_genesis: Option<String>,
    /// VDF current chain tip hash (hex-encoded).
    #[serde(default)]
    pub vdf_hash: Option<String>,
    /// VDF total steps (cumulative across sessions).
    #[serde(default)]
    pub vdf_step: Option<u64>,
    /// This peer's Yggdrasil IPv6 address (None if no Yggdrasil).
    #[serde(default)]
    pub yggdrasil_addr: Option<String>,
    /// Site identity for supernode clustering (derived from server_name if absent).
    #[serde(default)]
    pub site_name: String,
    /// Node identity within site (derived from server_name if absent).
    #[serde(default)]
    pub node_name: String,
    /// Resonance credit — how precisely this peer tracks its target VDF rate [0, 1].
    #[serde(default)]
    pub vdf_resonance_credit: Option<f64>,
    /// Actual measured VDF tick rate (Hz, exponential moving average).
    #[serde(default)]
    pub vdf_actual_rate_hz: Option<f64>,
    /// Cumulative resonance credit — total precision-weighted VDF work.
    /// Flows through gossip (NOT serde(skip)) for SPIRAL slot collision resolution.
    #[serde(default)]
    pub vdf_cumulative_credit: Option<f64>,
    /// Yggdrasil peer URI (self-reported underlay, e.g. `tcp://[fdaa::...]:9443`).
    #[serde(default)]
    pub ygg_peer_uri: Option<String>,
    /// Yggdrasil underlay peer URI for direct peering (e.g. `tcp://[10.7.1.37]:9443`).
    /// Derived from the relay's TCP peer address — a real IP, not an overlay address.
    /// Propagated via MESH PEERS so nodes can establish direct Ygg underlay links
    /// to SPIRAL neighbors they haven't directly connected to yet.
    #[serde(default)]
    pub underlay_uri: Option<String>,
    /// Previous VDF step — used to detect non-advancement.
    #[serde(skip)]
    pub prev_vdf_step: Option<u64>,
    /// Unix timestamp of last VDF step advancement.  VDF IS the heartbeat:
    /// if this hasn't updated in 10 seconds, the peer is dead.
    #[serde(skip)]
    pub last_vdf_advance: u64,
    /// Cluster identity chain value (hex-encoded blake3 hash).
    #[serde(default)]
    pub cluster_chain_value: Option<String>,
    /// Cluster identity chain round number.
    #[serde(default)]
    pub cluster_chain_round: Option<u64>,
}

fn default_peer_port() -> u16 {
    6667
}

impl Default for MeshPeerInfo {
    fn default() -> Self {
        Self {
            peer_id: String::new(),
            server_name: String::new(),
            public_key_hex: String::new(),
            port: 6667,
            tls: false,
            last_seen: 0,
            spiral_index: None,
            vdf_genesis: None,
            vdf_hash: None,
            vdf_step: None,
            yggdrasil_addr: None,
            site_name: String::new(),
            node_name: String::new(),
            vdf_resonance_credit: None,
            vdf_actual_rate_hz: None,
            vdf_cumulative_credit: None,
            ygg_peer_uri: None,
            underlay_uri: None,
            prev_vdf_step: None,
            last_vdf_advance: 0,
            cluster_chain_value: None,
            cluster_chain_round: None,
        }
    }
}

/// Connection state for a mesh peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MeshConnectionState {
    /// We know about this peer but aren't connected.
    Known,
    /// We have an active relay connection to this peer.
    Connected,
}

/// Mesh networking state — tracks known peers and their connections.
#[derive(Debug)]
pub struct MeshState {
    /// Known peers: mesh_key (`"{site_name}/{node_name}"`) → peer info.
    pub known_peers: HashMap<String, MeshPeerInfo>,
    /// Connection state per mesh_key (2D identity: site + node).
    pub connections: HashMap<String, MeshConnectionState>,
    /// Defederated LensIDs or server names — blocked from mesh.
    pub defederated: HashSet<String>,
    /// Currently connected web gateway users (nicks with `web~` ident).
    pub web_clients: HashSet<String>,
    /// Remote peers' topology snapshots — for debug composite view.
    pub remote_topologies: HashMap<String, MeshSnapshot>,
    /// SPIRAL topology engine for peer selection.
    pub spiral: super::spiral::SpiralTopology,
    /// VDF state watch channel — latest VDF engine snapshot.
    pub vdf_state_rx: Option<watch::Receiver<super::vdf::VdfState>>,
    /// VDF chain — shared with engine for ZK proof generation on demand.
    pub vdf_chain: Option<Arc<RwLock<lagoon_vdf::VdfChain>>>,
    /// Yggdrasil peer metrics store (populated from embedded Ygg node).
    pub ygg_metrics: super::yggdrasil::YggMetricsStore,
    /// SPORE gossip router for mesh-wide message replication.
    pub gossip: super::gossip::GossipRouter,
    /// SPORE-indexed latency proof store (PoLP Phase 2).
    pub proof_store: super::proof_store::ProofStore,
    /// SPIRAL-scoped latency proof gossip coordinator.
    pub latency_gossip: super::latency_gossip::LatencyGossip,
    /// SPORE-indexed connection snapshot store (mesh-wide visibility).
    pub connection_store: super::connection_store::ConnectionStore,
    /// SPIRAL-scoped connection snapshot gossip coordinator.
    pub connection_gossip: super::connection_gossip::ConnectionGossip,
    /// Bitmap-based liveness tracker: 1 bit per SPIRAL slot, SPORE reconciliation.
    pub liveness_bitmap: super::liveness_store::LivenessBitmap,
    /// SPIRAL-scoped liveness gossip coordinator (SPORE HaveList/Delta protocol).
    pub liveness_gossip: super::liveness_gossip::LivenessGossip,
    /// CVDF cooperative VDF service — Citadel's cooperative chain as a framework service.
    /// None until the node has peers and initializes the chain.
    pub cvdf_service: Option<citadel_lens::service::CvdfService<super::cvdf_transport::LagoonCvdfTransport>>,
    /// True when the last bootstrap attempt self-connected. When set, the
    /// Our cluster's total VDF work — cached when building HELLO payloads.
    /// This is the value we SEND in our HELLO. Used in merge evaluation so
    /// we compare two independently-computed values (ours vs theirs from HELLO)
    /// instead of recomputing ours (which would include the remote's credit).
    pub our_cluster_vdf_work: f64,
    /// Switchboard listener control channel. Send `Pause` before dialing
    /// anycast (drops the listening socket so the kernel RSTs self-routed
    /// SYNs) and `Resume` after.
    pub switchboard_ctl: Option<mpsc::UnboundedSender<super::switchboard::SwitchboardCtl>>,
    /// Timestamp when we last changed SPIRAL position via concierge assignment,
    /// VDF race, collision resolution, or reslot. reconverge_spiral skips
    /// within the grace window to prevent it from undoing the assignment before
    /// gossip propagates the full topology.
    pub spiral_settled_at: Option<std::time::Instant>,
    /// Slots tentatively reserved by outbound HELLO assigned_slot values.
    /// Prevents two outbound relays from computing the same assigned_slot.
    /// Entries are (slot, timestamp) — expired entries are cleaned up on access.
    /// The event processor removes entries when it does the real registration
    /// via eager slot registration (concierge_eager_registration theorem).
    pub pending_assigned_slots: HashMap<u64, std::time::Instant>,
    /// Tombstones for evicted peer_ids — prevents gossip from resurrecting dead peers.
    /// Key: mesh_key of evicted peer. Value: UNIX timestamp of eviction.
    /// Gossip handlers skip any peer_id found in this set. TTL: 250ms.
    /// Matches SPORE convergence time — stale gossip won't arrive after that.
    /// Direct HELLO always clears tombstones (proof of life).
    pub eviction_tombstones: HashMap<String, std::time::Instant>,
    /// Snapshot of our own VDF hash, frozen at HELLO build time.
    /// Used in PEERS universal merge for deterministic tiebreaking.
    /// Reading live `vdf_state_rx.current_hash` oscillates because it changes
    /// every VDF tick — the remote side sees our HELLO hash, not our live hash.
    /// (Lean: snapshot_immutability_required)
    pub our_vdf_hash_snapshot: Option<Vec<u8>>,
    /// URIs we've already successfully added as Ygg underlay peers.
    /// Prevents dial_missing_spiral_neighbors from hammering add_peer()
    /// on every cycle for already-configured peers.
    pub ygg_peered_uris: HashSet<String>,
    /// Cached count of connected Ygg underlay peers. Updated by the event
    /// processor in `refresh_ygg_metrics_embedded()`. Used by the sync
    /// `build_mesh_snapshot()` method (can't call async `.peers()`).
    pub ygg_peer_count: u32,
    /// Debounce timestamp for `announce_hello_to_all_relays()`. Prevents
    /// flooding: SPIRAL instability (reconverge, merge, collision) can trigger
    /// broadcasts at >30 Hz. 5 s minimum interval between broadcasts.
    pub last_hello_broadcast: Option<std::time::Instant>,
    /// Per-peer verified VDF chain tips. Key = mesh_key (peer_id), value =
    /// the last verified `h_end` from a VdfWindowProof. Chain continuity:
    /// each new proof's `h_start` must match this tip.
    pub verified_vdf_tips: HashMap<String, [u8; 32]>,
    /// Cluster identity chain — rotating blake3 hash for merge/split detection.
    /// Advances on VDF window ticks, carried in HELLO, compared on connection.
    pub cluster_chain: Option<super::cluster_chain::ClusterChain>,
    /// Cached VDF hash at the most recent quantum boundary (Universal Clock).
    /// Extracted from VdfChain BEFORE trim_to(1) discards historical hashes.
    /// Used as the round_seed for cluster chain advance — all nodes at the
    /// same quantized height use the same deterministic VDF hash.
    /// Format: (quantized_height, vdf_hash_at_that_height).
    pub last_quantum_hash: Option<(u64, [u8; 32])>,
}

impl MeshState {
    pub fn new(public_key_bytes: &[u8; 32], our_mesh_key: &str) -> Self {
        Self {
            known_peers: HashMap::new(),
            connections: HashMap::new(),
            defederated: HashSet::new(),
            web_clients: HashSet::new(),
            remote_topologies: HashMap::new(),
            spiral: super::spiral::SpiralTopology::new(),
            vdf_state_rx: None,
            vdf_chain: None,
            ygg_metrics: super::yggdrasil::YggMetricsStore::new(),
            gossip: super::gossip::GossipRouter::new(public_key_bytes),
            proof_store: super::proof_store::ProofStore::new(60_000), // 60s TTL — 2 PING cycles
            latency_gossip: super::latency_gossip::LatencyGossip::new(
                our_mesh_key.to_owned(),
                10_000, // 10s sync interval
            ),
            connection_store: super::connection_store::ConnectionStore::new(120_000), // 120s TTL
            connection_gossip: super::connection_gossip::ConnectionGossip::new(10_000), // 10s sync interval
            liveness_bitmap: super::liveness_store::LivenessBitmap::new(20), // 20s decay — convergence ~250ms
            liveness_gossip: super::liveness_gossip::LivenessGossip::new(0), // interval ignored — event-driven
            cvdf_service: None,
            our_cluster_vdf_work: 0.0,
            switchboard_ctl: None,
            spiral_settled_at: None,
            pending_assigned_slots: HashMap::new(),
            eviction_tombstones: HashMap::new(),
            our_vdf_hash_snapshot: None,
            ygg_peered_uris: HashSet::new(),
            ygg_peer_count: 0,
            last_hello_broadcast: None,
            verified_vdf_tips: HashMap::new(),
            cluster_chain: None,
            last_quantum_hash: None,
        }
    }
}

/// A single node in a mesh topology snapshot.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshNodeReport {
    /// Globally unique mesh key: `"{site_name}/{node_name}"`.
    #[serde(alias = "lens_id")]
    pub mesh_key: String,
    pub server_name: String,
    pub is_self: bool,
    pub connected: bool,
    pub node_type: String,
    /// SPIRAL slot index (None if unclaimed).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub spiral_index: Option<u64>,
    /// Whether this node is a SPIRAL neighbor of the reporter.
    #[serde(default)]
    pub is_spiral_neighbor: bool,
    /// VDF total steps (None if VDF not active on this peer).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub vdf_step: Option<u64>,
    /// SPIRAL world coordinates [x, y, z] for geometric positioning.
    /// None if the node hasn't claimed a SPIRAL slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub spiral_coord: Option<[f64; 3]>,
    /// Site identity for supernode clustering.
    #[serde(default)]
    pub site_name: String,
    /// Node identity within site.
    #[serde(default)]
    pub node_name: String,
    /// Yggdrasil overlay address (e.g. `"200:abcd::1"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ygg_addr: Option<String>,
    /// VDF resonance credit [0, 1] — how precisely this node tracks the target tick rate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub vdf_resonance_credit: Option<f64>,
    /// How many peers this node knows about (only populated for self).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub peer_count: Option<u32>,
    /// How many peers are connected via relay (only populated for self).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub connected_count: Option<u32>,
    /// How many Yggdrasil overlay peers are up (only populated for self).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub ygg_up_count: Option<u32>,
    /// How many known peers are disconnected (only populated for self).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub disconnected_count: Option<u32>,
    /// Cluster identity chain summary (debug visualization).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub cluster_chain: Option<super::cluster_chain::ChainSummary>,
}

/// A single link in a mesh topology snapshot.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshLinkReport {
    pub source: String,
    pub target: String,
    /// Upload bandwidth in bytes per second (None if metrics unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub upload_bps: Option<f64>,
    /// Download bandwidth in bytes per second (None if metrics unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub download_bps: Option<f64>,
    /// Latency in milliseconds (None if metrics unavailable).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub latency_ms: Option<f64>,
    /// Link type: "relay" (active IRC connection) or "spiral" (geometric neighbor).
    #[serde(default = "default_link_type")]
    pub link_type: String,
    /// Whether this link is routed through a switchboard L4 splice (not direct).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub spliced: Option<bool>,
}

fn default_link_type() -> String {
    "relay".into()
}

/// Complete mesh topology snapshot — pushed via watch channel.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshSnapshot {
    #[serde(alias = "self_lens_id")]
    pub self_mesh_key: String,
    pub self_server_name: String,
    #[serde(default)]
    pub self_site_name: String,
    pub nodes: Vec<MeshNodeReport>,
    pub links: Vec<MeshLinkReport>,
    pub timestamp: u64,
}

impl MeshSnapshot {
    pub fn empty() -> Self {
        Self {
            self_mesh_key: String::new(),
            self_server_name: String::new(),
            self_site_name: String::new(),
            nodes: Vec::new(),
            links: Vec::new(),
            timestamp: 0,
        }
    }
}

/// Debug view of the full mesh — local view, each peer's view, and merged global view.
#[derive(Debug, Clone, Serialize)]
pub struct MeshDebugSnapshot {
    /// Our own topology view.
    pub local: MeshSnapshot,
    /// Each connected peer's reported topology (server_name → snapshot).
    pub peer_views: HashMap<String, MeshSnapshot>,
    /// Merged global view — all unique nodes and links across all perspectives.
    pub global: MeshSnapshot,
}

/// Shared server state.
#[derive(Debug)]
pub struct ServerState {
    /// Registered clients: nick → sender handle.
    pub clients: HashMap<String, ClientHandle>,
    /// Channels: channel name → members (nick → prefix).
    pub channels: HashMap<String, HashMap<String, MemberPrefix>>,
    /// Persistent channel roles: channel name → (nick → prefix).
    /// Survives PART/QUIT — restored on rejoin.
    pub channel_roles: HashMap<String, HashMap<String, MemberPrefix>>,
    /// Channel topics: channel name → (topic text, set_by nick, unix timestamp).
    pub channel_topics: HashMap<String, (String, String, u64)>,
    /// Federation manager for `#room:server` relay connections.
    pub federation: FederationManager,
    /// Sender for federation relay events (relays send events here).
    pub federation_event_tx: mpsc::UnboundedSender<RelayEvent>,
    /// Transport configuration for federation relay connections.
    pub transport_config: Arc<TransportConfig>,
    /// This server's cryptographic identity.
    pub lens: Arc<LensIdentity>,
    /// Mesh networking state.
    pub mesh: MeshState,
    /// Topology watch channel — updated on every mesh change.
    pub mesh_topology_tx: watch::Sender<MeshSnapshot>,
    /// Invite code store.
    pub invites: InviteStore,
    /// Community (circle) store.
    pub communities: CommunityStore,
    /// Data directory for persistence.
    pub data_dir: PathBuf,
    /// Per-channel mode flags (created with defaults on first JOIN).
    pub channel_modes: HashMap<String, ChannelModes>,
    /// Per-channel ban lists.
    pub channel_bans: HashMap<String, Vec<BanEntry>>,
    /// Per-channel invite lists (invited nick_keys, for +i enforcement).
    pub channel_invites: HashMap<String, HashSet<String>>,
    /// Ring buffer of disconnected user records for WHOWAS.
    pub whowas: WhowasBuffer,
    /// Full-telemetry mode: push composite global topology (all peers' views merged)
    /// instead of local-only view.  Controlled by LAGOON_FULL_TELEMETRY env var.
    /// Default: ON.  Set LAGOON_FULL_TELEMETRY=0 to disable.
    pub full_telemetry: bool,
    /// User profile CRDT store — local cache + mesh query support.
    pub profile_store: ProfileStore,
}

/// Handle to send messages to a connected client.
#[derive(Debug, Clone)]
pub struct ClientHandle {
    pub nick: String,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub addr: SocketAddr,
    pub tx: mpsc::UnboundedSender<Message>,
    pub away_message: Option<String>,
}

impl ServerState {
    pub fn new(
        federation_event_tx: mpsc::UnboundedSender<RelayEvent>,
        transport_config: Arc<TransportConfig>,
        lens: Arc<LensIdentity>,
        mesh_topology_tx: watch::Sender<MeshSnapshot>,
        data_dir: PathBuf,
    ) -> Self {
        let invites = InviteStore::load_or_create(&data_dir);
        let communities = CommunityStore::load_or_create(&data_dir);
        let profile_store = ProfileStore::load_or_create(&data_dir);
        let pubkey = super::lens::pubkey_bytes(&lens).expect("valid lens identity");
        let mesh = MeshState::new(&pubkey, &lens.peer_id);

        // NOTE: We intentionally do NOT restore the persisted spiral_index here.
        // The merge protocol assigns fresh SPIRAL slots when connections form.
        // Persisted slots become stale across deploys (new peer IDs but old slot
        // numbers) causing slot inflation (e.g. slot 239 in a 10-node cluster).
        // The genesis path (no peers) still claims slot 0 correctly.
        // Persistence remains for peer_id, VDF genesis, and other identity fields.

        Self {
            clients: HashMap::new(),
            channels: HashMap::new(),
            channel_roles: HashMap::new(),
            channel_topics: HashMap::new(),
            federation: FederationManager::new(),
            federation_event_tx,
            transport_config,
            lens,
            mesh,
            mesh_topology_tx,
            invites,
            communities,
            data_dir,
            channel_modes: HashMap::new(),
            channel_bans: HashMap::new(),
            channel_invites: HashMap::new(),
            whowas: WhowasBuffer::new(100),
            full_telemetry: std::env::var("LAGOON_FULL_TELEMETRY")
                .map(|v| v != "0")
                .unwrap_or(true), // ON by default
            profile_store,
        }
    }

    /// Build a mesh topology snapshot from current state.
    pub fn build_mesh_snapshot(&self) -> MeshSnapshot {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut nodes = Vec::new();
        let mut links = Vec::new();

        // Our identity = peer_id (public key).
        let our_pid = self.lens.peer_id.clone();

        // Add self.
        let our_vdf_step = self.mesh.vdf_state_rx.as_ref().map(|rx| rx.borrow().total_steps);
        let our_ygg_addr = self.transport_config.ygg_node
            .as_ref()
            .map(|n| n.address().to_string());
        let our_vdf_credit = self.mesh.vdf_state_rx.as_ref()
            .and_then(|rx| rx.borrow().resonance.as_ref().map(|r| r.credit));

        // Self peer stats.
        let total_peers = self.mesh.known_peers.len() as u32;
        let connected_peers = self.mesh.connections.values()
            .filter(|&&s| s == MeshConnectionState::Connected)
            .count() as u32;
        let ygg_up = self.mesh.ygg_peer_count;

        nodes.push(MeshNodeReport {
            mesh_key: our_pid.clone(),
            server_name: self.lens.server_name.clone(),
            is_self: true,
            connected: true,
            node_type: "server".into(),
            spiral_index: self.mesh.spiral.our_index().map(|i| i.value()),
            is_spiral_neighbor: false,
            vdf_step: our_vdf_step,
            spiral_coord: self.mesh.spiral.our_world_coord(),
            site_name: self.lens.site_name.clone(),
            node_name: self.lens.node_name.clone(),
            ygg_addr: our_ygg_addr,
            vdf_resonance_credit: our_vdf_credit,
            peer_count: Some(total_peers),
            connected_count: Some(connected_peers),
            ygg_up_count: Some(ygg_up),
            disconnected_count: Some(total_peers - connected_peers),
            cluster_chain: self.mesh.cluster_chain.as_ref().map(|cc| cc.summary()),
        });

        // Add known peers.
        for (mkey, peer_info) in &self.mesh.known_peers {
            let connected = self
                .mesh
                .connections
                .get(mkey)
                .copied()
                == Some(MeshConnectionState::Connected);
            nodes.push(MeshNodeReport {
                mesh_key: mkey.clone(),
                server_name: peer_info.server_name.clone(),
                is_self: false,
                connected,
                node_type: "server".into(),
                spiral_index: peer_info.spiral_index,
                is_spiral_neighbor: self.mesh.spiral.is_neighbor(mkey),
                vdf_step: peer_info.vdf_step,
                spiral_coord: self.mesh.spiral.peer_world_coord(mkey),
                site_name: peer_info.site_name.clone(),
                node_name: peer_info.node_name.clone(),
                ygg_addr: peer_info.yggdrasil_addr.as_ref().map(|a| a.to_string()),
                vdf_resonance_credit: peer_info.vdf_resonance_credit,
                peer_count: None,
                connected_count: None,
                ygg_up_count: None,
                disconnected_count: None,
                cluster_chain: peer_info.cluster_chain_value.as_ref().map(|v| {
                    super::cluster_chain::ChainSummary {
                        chain_value_hex: v.clone(),
                        round: peer_info.cluster_chain_round.unwrap_or(0),
                        merge_count: 0,
                        split_count: 0,
                    }
                }),
            });
            if connected {
                // Latency priority: proof_store → relay PING/PONG → Yggdrasil.
                let proof_rtt = self.mesh.proof_store
                    .get(&our_pid, mkey)
                    .map(|e| e.rtt_ms);
                let relay_rtt = self.federation.relays.get(mkey)
                    .and_then(|r| r.last_rtt_ms);

                // Yggdrasil metrics (bandwidth + latency fallback).
                let ygg = peer_info
                    .yggdrasil_addr
                    .as_ref()
                    .and_then(|addr| self.mesh.ygg_metrics.get(addr));

                let upload_bps = ygg.map(|m| m.upload_bps);
                let download_bps = ygg.map(|m| m.download_bps);
                let latency_ms = proof_rtt.or(relay_rtt).or(ygg.map(|m| m.latency_ms));

                // SPIRAL neighbors get "spiral" link_type so the visualization
                // can render the overlay structure distinctly.
                let lt = if self.mesh.spiral.is_neighbor(mkey) {
                    "spiral"
                } else {
                    "relay"
                };
                // Detect spliced connections: relay's connect_target matches
                // our switchboard address → traffic goes through L4 splice.
                let spliced = self.transport_config.switchboard_addr.as_ref().and_then(|sb| {
                    self.federation.relays.get(mkey).map(|r| r.connect_target == *sb)
                });
                links.push(MeshLinkReport {
                    source: our_pid.clone(),
                    target: mkey.clone(),
                    upload_bps,
                    download_bps,
                    latency_ms,
                    link_type: lt.into(),
                    spliced,
                });
            }
        }

        // Add web gateway clients.
        for web_nick in &self.mesh.web_clients {
            nodes.push(MeshNodeReport {
                mesh_key: format!("web/{web_nick}"),
                server_name: self.lens.server_name.clone(),
                is_self: false,
                connected: true,
                node_type: "browser".into(),
                spiral_index: None,
                is_spiral_neighbor: false,
                vdf_step: None,
                spiral_coord: None,
                site_name: self.lens.site_name.clone(),
                node_name: self.lens.node_name.clone(),
                ygg_addr: None,
                vdf_resonance_credit: None,
                peer_count: None,
                connected_count: None,
                ygg_up_count: None,
                disconnected_count: None,
                cluster_chain: None,
            });
            links.push(MeshLinkReport {
                source: our_pid.clone(),
                target: format!("web/{web_nick}"),
                upload_bps: None,
                download_bps: None,
                latency_ms: None,
                link_type: "relay".into(),
                spliced: None,
            });
        }

        // Add SPIRAL geometric neighbor links for neighbors not already connected via relay.
        let relay_targets: HashSet<String> = links.iter().map(|l| l.target.clone()).collect();
        for neighbor_id in self.mesh.spiral.all_neighbor_ids() {
            if !relay_targets.contains(&neighbor_id) {
                links.push(MeshLinkReport {
                    source: our_pid.clone(),
                    target: neighbor_id,
                    upload_bps: None,
                    download_bps: None,
                    latency_ms: None,
                    link_type: "spiral".into(),
                    spliced: None,
                });
            }
        }

        // Transitive latency: proof-derived links between remote peers (via gossip).
        // Only include proofs where BOTH endpoints are known nodes (us or a known peer)
        // to avoid dangling references from gossiped proofs about peers we haven't met.
        {
            let known_ids: HashSet<&str> = {
                let mut s: HashSet<&str> = self.mesh.known_peers.keys().map(|k| k.as_str()).collect();
                s.insert(&our_pid);
                s
            };
            let existing_edges: HashSet<(String, String)> = links
                .iter()
                .map(|l| {
                    if l.source < l.target {
                        (l.source.clone(), l.target.clone())
                    } else {
                        (l.target.clone(), l.source.clone())
                    }
                })
                .collect();
            let latency_map = self.mesh.proof_store.latency_map((now * 1000) as i64);
            for ((peer_a, peer_b), rtt_ms) in &latency_map {
                if !known_ids.contains(peer_a.as_str()) || !known_ids.contains(peer_b.as_str()) {
                    continue;
                }
                let edge = if peer_a < peer_b {
                    (peer_a.clone(), peer_b.clone())
                } else {
                    (peer_b.clone(), peer_a.clone())
                };
                if !existing_edges.contains(&edge) {
                    links.push(MeshLinkReport {
                        source: peer_a.clone(),
                        target: peer_b.clone(),
                        upload_bps: None,
                        download_bps: None,
                        latency_ms: Some(*rtt_ms),
                        link_type: "proof".into(),
                        spliced: None,
                    });
                }
            }
        }

        // Connection gossip: edges reported by remote nodes via SPORE sync.
        // Only include edges where both endpoints are known nodes.
        {
            let known_ids: HashSet<&str> = {
                let mut s: HashSet<&str> = self.mesh.known_peers.keys().map(|k| k.as_str()).collect();
                s.insert(&our_pid);
                s
            };
            let existing_edges: HashSet<(String, String)> = links
                .iter()
                .map(|l| {
                    if l.source < l.target {
                        (l.source.clone(), l.target.clone())
                    } else {
                        (l.target.clone(), l.source.clone())
                    }
                })
                .collect();
            for (reporter, connected_peer) in self.mesh.connection_store.all_edges() {
                if !known_ids.contains(reporter.as_str())
                    || !known_ids.contains(connected_peer.as_str())
                {
                    continue;
                }
                let edge = if reporter < connected_peer {
                    (reporter.clone(), connected_peer.clone())
                } else {
                    (connected_peer.clone(), reporter.clone())
                };
                if !existing_edges.contains(&edge) {
                    links.push(MeshLinkReport {
                        source: reporter,
                        target: connected_peer,
                        upload_bps: None,
                        download_bps: None,
                        latency_ms: None,
                        link_type: "gossip".into(),
                        spliced: None,
                    });
                }
            }
        }

        MeshSnapshot {
            self_mesh_key: our_pid,
            self_server_name: self.lens.server_name.clone(),
            self_site_name: self.lens.site_name.clone(),
            nodes,
            links,
            timestamp: now,
        }
    }

    /// Build a debug topology snapshot with composite view.
    ///
    /// Since proof gossip makes latency data transitive, the local view
    /// already contains the full mesh latency graph. No more merging of
    /// remote_topologies needed.
    pub fn build_debug_snapshot(&self) -> MeshDebugSnapshot {
        let local = self.build_mesh_snapshot();
        MeshDebugSnapshot {
            global: local.clone(),
            local,
            peer_views: HashMap::new(),
        }
    }

    /// Update the topology watch channel with current state.
    ///
    /// When `full_telemetry` is enabled (default), sends the composite global
    /// view merging all peers' perspectives — every node in the mesh is visible.
    /// Set `LAGOON_FULL_TELEMETRY=0` to revert to local-only view.
    pub fn notify_topology_change(&self) {
        let snapshot = if self.full_telemetry {
            self.build_debug_snapshot().global
        } else {
            self.build_mesh_snapshot()
        };
        let _ = self.mesh_topology_tx.send(snapshot);
    }

    /// Query the mesh for a user profile. Sends ProfileQuery to all connected
    /// relays and returns a oneshot receiver that fires when the first
    /// ProfileResponse arrives (or the caller's timeout expires).
    pub fn query_profile_from_mesh(
        &mut self,
        username: &str,
    ) -> tokio::sync::oneshot::Receiver<Option<super::profile::UserProfile>> {
        let rx = self.profile_store.register_query(username);
        // Broadcast the query to all connected mesh relays.
        let query_msg = super::wire::MeshMessage::ProfileQuery {
            username: username.to_string(),
        };
        for relay in self.federation.relays.values() {
            let _ = relay.outgoing_tx.send(federation::RelayCommand::SendMesh(query_msg.clone()));
        }
        rx
    }
}

/// Shared, thread-safe server state.
pub type SharedState = Arc<RwLock<ServerState>>;

/// Start the IRC server, returning the shared state and task handles.
///
/// This is the library entry point for embedding the IRC server in another
/// process (e.g. lagoon-web). The caller owns the state and can subscribe
/// to the mesh topology watch channel.
pub async fn start(
    addrs: &[&str],
) -> Result<(SharedState, watch::Receiver<MeshSnapshot>, Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>, broadcast::Sender<()>), Box<dyn std::error::Error + Send + Sync>> {
    let mut transport_config = transport::build_config();
    let (event_tx, event_rx) = mpsc::unbounded_channel::<RelayEvent>();

    // Load or create Lens identity.
    let data_dir = PathBuf::from(
        std::env::var("LAGOON_DATA_DIR").unwrap_or_else(|_| "./lagoon-data".to_string()),
    );
    let lens = Arc::new(super::lens::load_or_create(&data_dir, &SERVER_NAME));
    info!(
        peer_id = %lens.peer_id,
        server_name = %lens.server_name,
        site_name = %*SITE_NAME,
        node_name = %*NODE_NAME,
        "lens identity active"
    );

    // Start embedded Yggdrasil node (if YGG_PEERS is set).
    let ygg_node = init_yggdrasil(&lens).await.map(Arc::new);
    if let Some(ref node) = ygg_node {
        info!(address = %node.address(), "embedded Yggdrasil node started");
        transport_config.yggdrasil_available = true;
    }
    transport_config.ygg_node = ygg_node.clone();
    let transport_config = Arc::new(transport_config);

    let (topology_tx, topology_rx) = watch::channel(MeshSnapshot::empty());

    let state: SharedState = Arc::new(RwLock::new(ServerState::new(
        event_tx,
        transport_config.clone(),
        Arc::clone(&lens),
        topology_tx,
        data_dir,
    )));

    // Start VDF engine.
    let (_vdf_shutdown_tx, _vdf_shutdown_rx) = broadcast::channel::<()>(1);
    {
        let mut st = state.write().await;
        let pubkey = super::lens::pubkey_bytes(&st.lens).expect("valid lens identity");
        let genesis = super::vdf::derive_genesis();
        let chain_seed = super::vdf::derive_chain_seed(&genesis, &pubkey);
        let restored_total = st.lens.vdf_total_steps;
        let chain = Arc::new(RwLock::new(lagoon_vdf::VdfChain::new(chain_seed)));
        let (vdf_state_tx, vdf_state_rx) = watch::channel(super::vdf::VdfState {
            genesis,
            current_hash: chain_seed,
            session_steps: 0,
            total_steps: restored_total,
            resonance: None,
        });
        st.mesh.vdf_state_rx = Some(vdf_state_rx);
        st.mesh.vdf_chain = Some(Arc::clone(&chain));
        // Initialize cluster identity chain from VDF genesis hash.
        // The chain advances on VDF window ticks and is carried in HELLO.
        st.mesh.cluster_chain = Some(super::cluster_chain::ClusterChain::genesis(
            genesis, 0, 1,
        ));
        let shutdown_rx = _vdf_shutdown_tx.subscribe();
        tokio::spawn(super::vdf::run_vdf_engine(
            genesis,
            restored_total,
            chain,
            vdf_state_tx,
            shutdown_rx,
        ));
    }

    // Load defederated peers.
    {
        let mut st = state.write().await;
        let defed_path = st.data_dir.join("defederated.json");
        if defed_path.exists() {
            if let Ok(json) = std::fs::read_to_string(&defed_path) {
                if let Ok(set) = serde_json::from_str::<HashSet<String>>(&json) {
                    st.mesh.defederated = set;
                    info!(count = st.mesh.defederated.len(), "loaded defederated peers");
                }
            }
        }
        st.notify_topology_change();
    }

    // Log telemetry mode.
    {
        let st = state.read().await;
        if st.full_telemetry {
            info!("FULL TELEMETRY mode ON — topology shows global composite view (set LAGOON_FULL_TELEMETRY=0 to disable)");
        } else {
            info!("telemetry: local-only topology view (set LAGOON_FULL_TELEMETRY=1 for global)");
        }
    }

    // Spawn federation event processor.
    federation::spawn_event_processor(Arc::clone(&state), event_rx);

    // Spawn LagoonBot.
    super::bot::spawn(Arc::clone(&state)).await;

    // Spawn mesh connector — proactively connects to all LAGOON_PEERS.
    federation::spawn_mesh_connector(Arc::clone(&state), transport_config);

    // Start the anycast switchboard on port 9443.
    // This multiplexes: JSON `{` → half-dial protocol, anything else → Ygg proxy.
    {
        let switchboard_port: u16 = std::env::var("LAGOON_SWITCHBOARD_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9443);
        let switchboard_addr: std::net::SocketAddr =
            ([0, 0, 0, 0, 0, 0, 0, 0], switchboard_port).into();
        let switchboard_ctl = super::switchboard::start_switchboard(switchboard_addr, Arc::clone(&state)).await;
        state.write().await.mesh.switchboard_ctl = switchboard_ctl;
    }

    // Bind all listeners first, so we fail fast on port conflicts.
    let mut listeners = Vec::with_capacity(addrs.len());
    for addr in addrs {
        let listener = TcpListener::bind(addr).await?;
        info!("lagoon listening on {addr}");
        listeners.push(listener);
    }

    // Spawn an accept loop per listener.
    let mut handles = Vec::new();
    for listener in listeners {
        let state = Arc::clone(&state);
        handles.push(tokio::spawn(accept_loop(listener, state)));
    }

    Ok((state, topology_rx, handles, _vdf_shutdown_tx))
}

/// Run the IRC server on the given addresses.
///
/// Binds to every address in the slice and accepts connections on all of them.
/// This enables dual-stack: TCP on `0.0.0.0:6667` + Yggdrasil on `[200:...]:6667`.
pub async fn run(addrs: &[&str]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (state, _topology_rx, handles, vdf_shutdown_tx) = start(addrs).await?;

    // Wait for shutdown signal (SIGTERM/SIGINT) or any listener to exit.
    let shutdown_signal = async {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            let mut sigterm = tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ).expect("failed to register SIGTERM handler");
            tokio::select! {
                _ = ctrl_c => info!("received SIGINT, shutting down"),
                _ = sigterm.recv() => info!("received SIGTERM, shutting down"),
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await.ok();
            info!("received SIGINT, shutting down");
        }
    };

    tokio::select! {
        _ = shutdown_signal => {
            // Persist VDF state before exiting.
            let st = state.read().await;
            let mut updated_lens = (*st.lens).clone();
            if let Some(ref rx) = st.mesh.vdf_state_rx {
                updated_lens.vdf_total_steps = rx.borrow().total_steps;
            }
            super::lens::persist_identity(&st.data_dir, &updated_lens);
            info!(
                vdf_total_steps = updated_lens.vdf_total_steps,
                "persisted VDF state on shutdown"
            );
            // Signal VDF engine to stop.
            let _ = vdf_shutdown_tx.send(());
        }
        result = async {
            for handle in handles {
                handle.await??;
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        } => {
            result?;
        }
    }

    Ok(())
}

/// Accept loop for a single listener.
async fn accept_loop(
    listener: TcpListener,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let (socket, addr) = listener.accept().await?;
        // Best-effort — don't fail the connection if keepalive can't be set.
        if let Err(e) = super::transport::set_tcp_keepalive(&socket) {
            tracing::debug!(%addr, "failed to set TCP keepalive: {e}");
        }
        info!(%addr, "new connection");
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, addr, state).await {
                warn!(%addr, "client error: {e}");
            }
            info!(%addr, "disconnected");
        });
    }
}

/// Initialize the embedded Yggdrasil node from the Lens identity key.
///
/// Ygg always starts with an **empty peer list**.  `LAGOON_PEERS` are WebSocket
/// bootstrap targets (e.g. `lagun.co:443`), NOT Ygg underlay peers.  APE
/// populates Ygg peers dynamically: after MESH HELLO, the event processor
/// calls `ygg.add_peer(ygg_peer_uri)` to connect to the remote's underlay.
///
/// Triggered by: `LAGOON_PEERS` is set (federation bootstrap targets exist),
/// or `LAGOON_YGG=1` (explicit enable).
///
/// Returns `None` if neither is set or initialization fails.
async fn init_yggdrasil(lens: &super::lens::LensIdentity) -> Option<yggdrasil_rs::YggNode> {
    if !should_start_yggdrasil() {
        return None;
    }

    // Build 64-byte Ed25519 private key from 32-byte seed.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&lens.secret_seed);
    let mut private_key = [0u8; 64];
    private_key[..32].copy_from_slice(&lens.secret_seed);
    private_key[32..].copy_from_slice(signing_key.verifying_key().as_bytes());

    // No listener — the switchboard on [::]:9443 detects "meta" first bytes
    // and hands Ygg connections directly via accept_inbound().
    let listen: Vec<String> = vec![];

    // Always start with empty peers — APE populates from MESH HELLO.
    let empty_peers: Vec<String> = vec![];

    match yggdrasil_rs::YggNode::new(&private_key, &empty_peers, &listen).await {
        Ok(node) => {
            info!(
                address = %node.address(),
                "Yggdrasil started with empty peer list — APE will populate peers"
            );
            Some(node)
        }
        Err(e) => {
            warn!("Yggdrasil init failed: {e}");
            None
        }
    }
}

/// Determine whether Yggdrasil should be started.
///
/// Returns `true` if `LAGOON_PEERS` is set (federation bootstrap targets exist)
/// or `LAGOON_YGG=1` (explicit enable).
pub fn should_start_yggdrasil() -> bool {
    let has_lagoon_peers = std::env::var("LAGOON_PEERS")
        .ok()
        .is_some_and(|s| !s.trim().is_empty());
    let ygg_explicit = std::env::var("LAGOON_YGG")
        .ok()
        .is_some_and(|v| v == "1");
    has_lagoon_peers || ygg_explicit
}

/// Per-connection state during registration.
struct PendingRegistration {
    nick: Option<String>,
    user: Option<(String, String)>, // (username, realname)
}

/// Handle a single client connection.
async fn handle_client<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send>(
    socket: S,
    addr: SocketAddr,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut framed = Framed::new(socket, IrcCodec::default());
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let mut pending = PendingRegistration {
        nick: None,
        user: None,
    };
    let mut registered_nick: Option<String> = None;
    let mut quit_reason: Option<String> = None;

    loop {
        tokio::select! {
            // Incoming message from the client's TCP stream.
            frame = framed.next() => {
                let msg = match frame {
                    Some(Ok(msg)) => msg,
                    Some(Err(e)) => {
                        warn!(%addr, "parse error: {e}");
                        break;
                    }
                    None => break, // Connection closed.
                };

                match registered_nick {
                    None => {
                        // Not yet registered — handle registration commands.
                        handle_registration(&mut framed, &mut pending, &msg, &tx, addr, &state).await?;

                        // Check if registration is now complete.
                        if let (Some(nick), Some((user, realname))) = (&pending.nick, &pending.user) {
                            let nick = nick.clone();
                            let user = user.clone();
                            let realname = realname.clone();

                            // Enforce NICKLEN=30.
                            if nick.len() > 30 {
                                let err = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "432".into(),
                                    params: vec!["*".into(), nick.clone(), "Erroneous nickname (too long)".into()],
                                };
                                framed.send(err).await?;
                                pending.nick = None;
                                continue;
                            }

                            // Check for nick collision (case-insensitive).
                            {
                                let st = state.read().await;
                                if st.clients.contains_key(&irc_lower(&nick)) {
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "433".into(),
                                        params: vec!["*".into(), nick.clone(), "Nickname is already in use".into()],
                                    };
                                    framed.send(err).await?;
                                    pending.nick = None;
                                    continue;
                                }
                            }

                            // Register the client (key is lowercased, nick preserves case).
                            {
                                let mut st = state.write().await;
                                st.clients.insert(irc_lower(&nick), ClientHandle {
                                    nick: nick.clone(),
                                    user: Some(user.clone()),
                                    realname: Some(realname.clone()),
                                    addr,
                                    tx: tx.clone(),
                                    away_message: None,
                                });
                                if user.starts_with("web~") {
                                    st.mesh.web_clients.insert(irc_lower(&nick));
                                    st.notify_topology_change();
                                }
                            }

                            // Send welcome numerics.
                            send_welcome(&mut framed, &nick).await?;

                            // Send LUSERS on connect.
                            {
                                let st = state.read().await;
                                let total_users = st.clients.len();
                                let total_channels = st.channels.len();
                                let mesh_peers = st.mesh.connections.values()
                                    .filter(|s| **s == MeshConnectionState::Connected)
                                    .count();
                                drop(st);
                                let lusers = [
                                    Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "251".into(),
                                        params: vec![
                                            nick.clone(),
                                            format!("There are {total_users} users and 0 invisible on {} servers", mesh_peers + 1),
                                        ],
                                    },
                                    Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "252".into(),
                                        params: vec![nick.clone(), "0".into(), "operator(s) online".into()],
                                    },
                                    Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "254".into(),
                                        params: vec![nick.clone(), total_channels.to_string(), "channels formed".into()],
                                    },
                                    Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "255".into(),
                                        params: vec![
                                            nick.clone(),
                                            format!("I have {total_users} clients and {mesh_peers} servers"),
                                        ],
                                    },
                                ];
                                for m in lusers {
                                    framed.send(m).await?;
                                }
                            }

                            registered_nick = Some(nick);
                        }
                    }
                    Some(ref nick) => {
                        // Registered — handle normal commands.
                        match handle_command(&mut framed, nick, &msg, &state).await? {
                            CommandResult::Ok => {}
                            CommandResult::Quit(reason) => {
                                quit_reason = Some(reason);
                                break;
                            }
                            CommandResult::NickChanged(new_nick) => {
                                registered_nick = Some(new_nick);
                            }
                        }
                    }
                }
            }

            // Outgoing message from other tasks (channel broadcasts, etc).
            Some(msg) = rx.recv() => {
                framed.send(msg).await?;
            }
        }
    }

    // Clean up on disconnect.
    if let Some(nick) = registered_nick {
        let reason = quit_reason.as_deref().unwrap_or("Connection closed");
        cleanup_client(&nick, reason, &state).await;
    }

    Ok(())
}

/// Handle NICK and USER commands during pre-registration.
async fn handle_registration(
    framed: &mut Framed<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send, IrcCodec>,
    pending: &mut PendingRegistration,
    msg: &Message,
    _tx: &mpsc::UnboundedSender<Message>,
    _addr: SocketAddr,
    _state: &SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    match msg.command.to_uppercase().as_str() {
        "CAP" => {
            // Minimal CAP handling — just ACK LS with empty capabilities for now.
            if msg.params.first().is_some_and(|p| p == "LS") {
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "CAP".into(),
                    params: vec!["*".into(), "LS".into(), "".into()],
                };
                framed.send(reply).await?;
            } else if msg.params.first().is_some_and(|p| p == "END") {
                // Client done with capability negotiation.
            }
        }
        "NICK" => {
            if let Some(nick) = msg.params.first() {
                pending.nick = Some(nick.clone());
            }
        }
        "USER" => {
            if msg.params.len() >= 4 {
                let username = msg.params[0].clone();
                let realname = msg.params[3].clone();
                pending.user = Some((username, realname));
            }
        }
        "PING" => {
            let token = msg.params.first().cloned().unwrap_or_default();
            let pong = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "PONG".into(),
                params: vec![SERVER_NAME.clone(), token],
            };
            framed.send(pong).await?;
        }
        _ => {
            // During registration, ignore unknown commands.
        }
    }
    Ok(())
}

/// Send the IRC welcome sequence (001-004).
async fn send_welcome(
    framed: &mut Framed<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send, IrcCodec>,
    nick: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let welcome_msgs = [
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "001".into(),
            params: vec![
                nick.into(),
                format!("Welcome to {}, {nick}", *DISPLAY_NAME),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "002".into(),
            params: vec![
                nick.into(),
                format!("Your host is {}, running Lagoon", *SERVER_NAME),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "003".into(),
            params: vec![
                nick.into(),
                "This server was created today".into(),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "004".into(),
            params: vec![
                nick.into(),
                SERVER_NAME.clone(),
                "lagoon-0.1.0".into(),
                "qaov".into(),
                "biiklmnst".into(),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "005".into(),
            params: vec![
                nick.into(),
                "PREFIX=(qaov)~&@+".into(),
                "CHANTYPES=#&".into(),
                "CHANMODES=b,k,l,imnst".into(),
                "MODES=4".into(),
                format!("NETWORK={}", *NETWORK_TAG),
                "are supported by this server".into(),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "005".into(),
            params: vec![
                nick.into(),
                "NICKLEN=30".into(),
                "CHANNELLEN=50".into(),
                "TOPICLEN=390".into(),
                "KICKLEN=390".into(),
                "AWAYLEN=200".into(),
                "CASEMAPPING=ascii".into(),
                "are supported by this server".into(),
            ],
        },
    ];

    for msg in welcome_msgs {
        framed.send(msg).await?;
    }

    // Send MOTD (375/372/376).
    let motd_lines = [
        &format!("Welcome to {} — decentralized chat for everyone.", *DISPLAY_NAME),
        "Powered by Lagoon IRC server.",
    ];
    let start = Message {
        prefix: Some(SERVER_NAME.clone()),
        command: "375".into(),
        params: vec![nick.into(), format!("- {} Message of the Day -", *SERVER_NAME)],
    };
    framed.send(start).await?;
    for line in motd_lines {
        let m = Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "372".into(),
            params: vec![nick.into(), format!("- {line}")],
        };
        framed.send(m).await?;
    }
    let end = Message {
        prefix: Some(SERVER_NAME.clone()),
        command: "376".into(),
        params: vec![nick.into(), "End of /MOTD command".into()],
    };
    framed.send(end).await?;

    Ok(())
}

/// Result of handling a command.
enum CommandResult {
    Ok,
    Quit(String),
    NickChanged(String),
}

/// Handle commands from a registered client.
async fn handle_command(
    framed: &mut Framed<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send, IrcCodec>,
    nick: &str,
    msg: &Message,
    state: &SharedState,
) -> Result<CommandResult, Box<dyn std::error::Error>> {
    match msg.command.to_uppercase().as_str() {
        "CAP" => {
            // Post-registration CAP — just acknowledge.
            if msg.params.first().is_some_and(|p| p == "LS") {
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "CAP".into(),
                    params: vec![nick.into(), "LS".into(), "".into()],
                };
                framed.send(reply).await?;
            }
            // CAP END, CAP REQ, etc — silently accept.
        }

        "PING" => {
            let token = msg.params.first().cloned().unwrap_or_default();
            let pong = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "PONG".into(),
                params: vec![SERVER_NAME.clone(), token],
            };
            framed.send(pong).await?;
        }

        "NICK" => {
            if let Some(new_nick) = msg.params.first() {
                if new_nick.is_empty() {
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "431".into(),
                        params: vec![nick.into(), "No nickname given".into()],
                    };
                    framed.send(err).await?;
                } else if new_nick.len() > 30 {
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "432".into(),
                        params: vec![nick.into(), new_nick.clone(), "Erroneous nickname (too long)".into()],
                    };
                    framed.send(err).await?;
                } else if irc_lower(new_nick) == irc_lower(nick) {
                    // Same nick (case-insensitive) — no-op.
                } else {
                    let mut st = state.write().await;

                    // Check for collision (case-insensitive).
                    if st.clients.contains_key(&irc_lower(new_nick)) {
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "433".into(),
                            params: vec![
                                nick.into(),
                                new_nick.clone(),
                                "Nickname is already in use".into(),
                            ],
                        };
                        drop(st);
                        framed.send(err).await?;
                    } else {
                        let nick_msg = Message {
                            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                            command: "NICK".into(),
                            params: vec![new_nick.clone()],
                        };

                        // Collect every user who shares a channel with us (deduplicated).
                        let nick_key = irc_lower(nick);
                        let new_nick_key = irc_lower(new_nick);
                        let mut notify: HashSet<String> = HashSet::new();
                        notify.insert(nick_key.clone()); // notify self
                        for (_ch, members) in &st.channels {
                            if members.contains_key(&nick_key) {
                                for member in members.keys() {
                                    notify.insert(member.clone());
                                }
                            }
                        }
                        let notify_list: Vec<_> = notify.into_iter().collect();
                        broadcast(&st, &notify_list, &nick_msg);

                        // Update client handle.
                        if let Some(mut handle) = st.clients.remove(&nick_key) {
                            handle.nick = new_nick.clone();
                            st.clients.insert(new_nick_key.clone(), handle);
                        }

                        // Update channel memberships.
                        for members in st.channels.values_mut() {
                            if let Some(prefix) = members.remove(&nick_key) {
                                members.insert(new_nick_key.clone(), prefix);
                            }
                        }

                        // Transfer persistent roles.
                        for roles in st.channel_roles.values_mut() {
                            if let Some(prefix) = roles.remove(&nick_key) {
                                roles.insert(new_nick_key.clone(), prefix);
                            }
                        }

                        // Update federation relay local_users.
                        for (_host, relay) in st.federation.relays.iter_mut() {
                            for (_local_ch, fed_ch) in relay.channels.iter_mut() {
                                if fed_ch.local_users.remove(&nick_key) {
                                    let _ = relay.outgoing_tx.send(
                                        federation::RelayCommand::Part {
                                            nick: nick.to_owned(),
                                            remote_channel: fed_ch.remote_channel.clone(),
                                            reason: format!("Nick changed to {new_nick}"),
                                        },
                                    );
                                    fed_ch.local_users.insert(new_nick_key.clone());
                                    let _ = relay.outgoing_tx.send(
                                        federation::RelayCommand::Join {
                                            nick: new_nick.clone(),
                                            remote_channel: fed_ch.remote_channel.clone(),
                                        },
                                    );
                                }
                            }
                        }

                        // Update web client tracking for topology.
                        if st.mesh.web_clients.remove(&nick_key) {
                            st.mesh.web_clients.insert(new_nick_key);
                            st.notify_topology_change();
                        }

                        drop(st);
                        return Ok(CommandResult::NickChanged(new_nick.clone()));
                    }
                }
            }
        }

        "JOIN" => {
            if let Some(channels_param) = msg.params.first() {
                // IRC allows comma-separated channel lists: JOIN #a,#b,#c
                let channels: Vec<String> = channels_param
                    .split(',')
                    .map(|s| s.to_owned())
                    .collect();

                for channel in channels {
                    if channel.is_empty() {
                        continue;
                    }

                    // Enforce CHANNELLEN=50.
                    if channel.len() > 50 {
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "479".into(),
                            params: vec![nick.into(), channel.clone(), "Channel name too long".into()],
                        };
                        framed.send(err).await?;
                        continue;
                    }

                    // Normalize channel name for case-insensitive lookup.
                    let channel = irc_lower(&channel);
                    let nick_key = irc_lower(nick);

                    // Federated channel? Route through federation manager.
                    if let Some((remote_chan, remote_host)) =
                        federation::parse_federated_channel(&channel)
                    {
                        let mut st = state.write().await;
                        let relay_key = derive_node_name(remote_host);
                        let relay_exists = st.federation.relays.contains_key(&relay_key);

                        if relay_exists {
                            let relay = st.federation.relays.get_mut(&relay_key).unwrap();
                            if relay.channels.contains_key(&channel) {
                                // Channel already tracked — just add user.
                                let fed_ch = relay.channels.get_mut(&channel).unwrap();
                                fed_ch.local_users.insert(nick_key.clone());
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::Join {
                                        nick: nick.to_owned(),
                                        remote_channel: remote_chan.to_owned(),
                                    },
                                );
                            } else {
                                // New channel on existing relay connection.
                                let mut local_users = HashSet::new();
                                local_users.insert(nick_key.clone());
                                relay.channels.insert(
                                    channel.clone(),
                                    FederatedChannel {
                                        remote_channel: remote_chan.to_owned(),
                                        local_users,
                                        remote_users: HashSet::new(),
                                    },
                                );
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::JoinChannel {
                                        remote_channel: remote_chan.to_owned(),
                                        local_channel: channel.clone(),
                                    },
                                );
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::Join {
                                        nick: nick.to_owned(),
                                        remote_channel: remote_chan.to_owned(),
                                    },
                                );
                            }
                        } else {
                            // New relay connection to this host.
                            let event_tx = st.federation_event_tx.clone();
                            let (cmd_tx, _task_handle) = federation::spawn_relay(
                                relay_key.clone(),
                                remote_host.to_owned(),
                                event_tx,
                                Arc::clone(&st.transport_config),
                            );
                            let mut local_users = HashSet::new();
                            local_users.insert(nick_key.clone());
                            // Tell relay to join the channel (buffered until registered).
                            let _ = cmd_tx.send(federation::RelayCommand::JoinChannel {
                                remote_channel: remote_chan.to_owned(),
                                local_channel: channel.clone(),
                            });
                            // Send initial FRELAY JOIN for this user.
                            let _ = cmd_tx.send(federation::RelayCommand::Join {
                                nick: nick.to_owned(),
                                remote_channel: remote_chan.to_owned(),
                            });
                            let mut channels = HashMap::new();
                            channels.insert(
                                channel.clone(),
                                FederatedChannel {
                                    remote_channel: remote_chan.to_owned(),
                                    local_users,
                                    remote_users: HashSet::new(),
                                },
                            );
                            st.federation.relays.insert(
                                relay_key.clone(),
                                federation::RelayHandle {
                                    outgoing_tx: cmd_tx,
                                    node_name: relay_key.clone(),
                                    connect_target: remote_host.to_owned(),
                                    channels,
                                    mesh_connected: false,
                                    is_bootstrap: false,
                                    last_rtt_ms: None,
                                },
                            );
                        }

                        let names = if let Some(relay) = st.federation.relays.get(&relay_key) {
                            if let Some(fed_ch) = relay.channels.get(&channel) {
                                let mut parts: Vec<String> = fed_ch
                                    .local_users
                                    .iter()
                                    .map(|k| st.clients.get(k).map(|h| h.nick.clone()).unwrap_or_else(|| k.clone()))
                                    .collect();
                                for rn in &fed_ch.remote_users {
                                    if rn.contains('@') {
                                        parts.push(rn.clone());
                                    } else {
                                        parts.push(format!("{rn}@{}", relay.connect_target));
                                    }
                                }
                                parts.join(" ")
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        drop(st);

                        let join_msg = Message {
                            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                            command: "JOIN".into(),
                            params: vec![channel.clone()],
                        };
                        framed.send(join_msg).await?;

                        let names_msg = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "353".into(),
                            params: vec![nick.into(), "=".into(), channel.clone(), names],
                        };
                        framed.send(names_msg).await?;

                        let end_msg = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "366".into(),
                            params: vec![
                                nick.into(),
                                channel,
                                "End of /NAMES list".into(),
                            ],
                        };
                        framed.send(end_msg).await?;
                    } else {
                        // Local channel.
                        let mut st = state.write().await;

                        // Already in channel — skip silently.
                        if st.channels.get(&channel).is_some_and(|m| m.contains_key(&nick_key)) {
                            continue;
                        }

                        // Parse key from JOIN params (JOIN #chan key).
                        let supplied_key = msg.params.get(1).cloned();

                        // Enforce channel modes on join.
                        let chan_modes = st.channel_modes.get(&channel);
                        if let Some(modes) = chan_modes {
                            // +b — check ban list.
                            let user_ident = st.clients.get(&nick_key)
                                .map(|h| h.user.as_deref().unwrap_or(&h.nick))
                                .unwrap_or(nick);
                            let full_hostmask = format!("{nick}!{user_ident}@{}", *SERVER_NAME);
                            if let Some(bans) = st.channel_bans.get(&channel) {
                                if bans.iter().any(|b| modes::match_hostmask(&b.mask, &full_hostmask)) {
                                    // Check if invited (overrides ban).
                                    let invited = st.channel_invites.get(&channel)
                                        .is_some_and(|inv| inv.contains(&nick_key));
                                    if !invited {
                                        drop(st);
                                        let err = Message {
                                            prefix: Some(SERVER_NAME.clone()),
                                            command: "474".into(),
                                            params: vec![nick.into(), channel.clone(), "Cannot join channel (+b)".into()],
                                        };
                                        framed.send(err).await?;
                                        continue;
                                    }
                                }
                            }

                            // +k — check key.
                            if let Some(ref required_key) = modes.key {
                                let ok = supplied_key.as_deref() == Some(required_key.as_str());
                                if !ok {
                                    drop(st);
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "475".into(),
                                        params: vec![nick.into(), channel.clone(), "Cannot join channel (+k)".into()],
                                    };
                                    framed.send(err).await?;
                                    continue;
                                }
                            }

                            // +i — invite only.
                            if modes.invite_only {
                                let invited = st.channel_invites.get(&channel)
                                    .is_some_and(|inv| inv.contains(&nick_key));
                                if !invited {
                                    drop(st);
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "473".into(),
                                        params: vec![nick.into(), channel.clone(), "Cannot join channel (+i)".into()],
                                    };
                                    framed.send(err).await?;
                                    continue;
                                }
                            }

                            // +l — user limit.
                            if let Some(limit) = modes.limit {
                                let current = st.channels.get(&channel).map(|m| m.len()).unwrap_or(0);
                                if current >= limit {
                                    drop(st);
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "471".into(),
                                        params: vec![nick.into(), channel.clone(), "Cannot join channel (+l)".into()],
                                    };
                                    framed.send(err).await?;
                                    continue;
                                }
                            }
                        }

                        let prefix = st
                            .channel_roles
                            .get(&channel)
                            .and_then(|r| r.get(&nick_key).copied())
                            .unwrap_or(MemberPrefix::Normal);

                        // Create channel modes with defaults (+n) for new channels.
                        st.channel_modes
                            .entry(channel.clone())
                            .or_insert_with(ChannelModes::default);

                        let is_new_channel = !st.channels.contains_key(&channel);
                        st.channels
                            .entry(channel.clone())
                            .or_default()
                            .insert(nick_key.clone(), prefix);

                        // Subscribe to gossip cluster topic for new local channels.
                        if is_new_channel {
                            st.mesh.gossip.subscribe_cluster_channel(&channel);
                        }

                        // Clear invite on successful join.
                        if let Some(inv) = st.channel_invites.get_mut(&channel) {
                            inv.remove(&nick_key);
                        }

                        let join_msg = Message {
                            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                            command: "JOIN".into(),
                            params: vec![channel.clone()],
                        };

                        // Always echo JOIN back to the joiner (relays need this).
                        framed.send(join_msg.clone()).await?;

                        // Relay nicks are invisible — don't notify others.
                        if !federation::is_relay_nick(nick) {
                            let other_nicks: Vec<_> = st
                                .channels
                                .get(&channel)
                                .map(|m| m.keys().filter(|n| *n != &nick_key).cloned().collect())
                                .unwrap_or_default();

                            broadcast(&st, &other_nicks, &join_msg);
                        }

                        let names = st
                            .channels
                            .get(&channel)
                            .map(|m| {
                                m.iter()
                                    .filter(|(n, _)| !federation::is_relay_nick(n))
                                    .map(|(n, p)| {
                                        let display = st.clients.get(n).map(|h| h.nick.as_str()).unwrap_or(n);
                                        format!("{}{display}", p.symbol())
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            })
                            .unwrap_or_default();
                        let topic = st.channel_topics.get(&channel).cloned();
                        drop(st);

                        // Send topic (332/333) if set.
                        if let Some((text, set_by, timestamp)) = topic {
                            let r332 = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "332".into(),
                                params: vec![nick.into(), channel.clone(), text],
                            };
                            framed.send(r332).await?;
                            let r333 = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "333".into(),
                                params: vec![nick.into(), channel.clone(), set_by, timestamp.to_string()],
                            };
                            framed.send(r333).await?;
                        }

                        let names_msg = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "353".into(),
                            params: vec![nick.into(), "=".into(), channel.clone(), names],
                        };
                        framed.send(names_msg).await?;

                        let end_msg = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "366".into(),
                            params: vec![
                                nick.into(),
                                channel,
                                "End of /NAMES list".into(),
                            ],
                        };
                        framed.send(end_msg).await?;
                    }
                }
            } else {
                let err = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "461".into(),
                    params: vec![nick.into(), "JOIN".into(), "Not enough parameters".into()],
                };
                framed.send(err).await?;
            }
        }

        "PART" => {
            if let Some(raw_channel) = msg.params.first() {
                let channel = irc_lower(raw_channel);
                let nick_key = irc_lower(nick);
                let reason = msg.params.get(1).cloned().unwrap_or_default();

                if let Some((remote_chan, remote_host)) =
                    federation::parse_federated_channel(&channel)
                {
                    // Federated channel — remove user, maybe tear down relay.
                    let mut st = state.write().await;
                    let relay_key = derive_node_name(remote_host);

                    // Collect nicks for broadcast before mutating.
                    let local_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&relay_key)
                        .and_then(|r| r.channels.get(&channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();

                    let part_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                        command: "PART".into(),
                        params: vec![channel.clone(), reason.clone()],
                    };
                    broadcast(&st, &local_nicks, &part_msg);

                    let mut remove_relay = false;
                    if let Some(relay) = st.federation.relays.get_mut(&relay_key) {
                        // Notify remote that this user is leaving.
                        let _ = relay.outgoing_tx.send(
                            federation::RelayCommand::Part {
                                nick: nick.to_owned(),
                                remote_channel: remote_chan.to_owned(),
                                reason,
                            },
                        );
                        let mut remove_channel = false;
                        if let Some(fed_ch) = relay.channels.get_mut(&channel) {
                            fed_ch.local_users.remove(&nick_key);
                            if fed_ch.local_users.is_empty() {
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::PartChannel {
                                        remote_channel: remote_chan.to_owned(),
                                    },
                                );
                                remove_channel = true;
                            }
                        }
                        if remove_channel {
                            relay.channels.remove(&channel);
                        }
                        if relay.channels.is_empty() && !relay.mesh_connected {
                            let _ = relay
                                .outgoing_tx
                                .send(federation::RelayCommand::Shutdown);
                            remove_relay = true;
                        }
                    }

                    if remove_relay {
                        if let Some(relay) =
                            st.federation.relays.remove(&relay_key)
                        {
                            let _ = relay.outgoing_tx.send(federation::RelayCommand::Shutdown);
                        }
                    }
                } else {
                    // Local channel.
                    let mut st = state.write().await;

                    // Relay nicks are invisible — suppress PART broadcast.
                    if !federation::is_relay_nick(nick) {
                        let part_msg = Message {
                            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                            command: "PART".into(),
                            params: vec![channel.clone(), reason],
                        };
                        if let Some(members) = st.channels.get(&channel) {
                            let member_list: Vec<_> = members.keys().cloned().collect();
                            broadcast(&st, &member_list, &part_msg);
                        }
                    }

                    // Remove nick from channel.
                    if let Some(members) = st.channels.get_mut(&channel) {
                        members.remove(&nick_key);
                        if members.is_empty() {
                            st.channels.remove(&channel);
                            st.channel_modes.remove(&channel);
                            st.channel_bans.remove(&channel);
                            st.channel_invites.remove(&channel);
                            st.mesh.gossip.unsubscribe_cluster_channel(&channel);
                        }
                    }
                }
            }
        }

        "PRIVMSG" | "NOTICE" => {
            if msg.params.len() < 2 {
                let err = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "461".into(),
                    params: vec![nick.into(), msg.command.clone(), "Not enough parameters".into()],
                };
                framed.send(err).await?;
            } else {
                let target = &msg.params[0];
                let target_lower = irc_lower(target);
                let nick_key = irc_lower(nick);
                let text = &msg.params[1];

                if let Some((remote_chan, remote_host)) = {
                    if target.starts_with('#') || target.starts_with('&') {
                        federation::parse_federated_channel(&target_lower)
                    } else {
                        None
                    }
                } {
                    // Federated channel — route through relay.
                    let st = state.read().await;
                    let relay_key = derive_node_name(remote_host);
                    if let Some(relay) = st.federation.relays.get(&relay_key) {
                        // Send to the remote via relay.
                        let _ = relay.outgoing_tx.send(
                            federation::RelayCommand::Privmsg {
                                nick: nick.to_owned(),
                                remote_channel: remote_chan.to_owned(),
                                text: text.clone(),
                            },
                        );
                        // Echo to other local users in the federated channel.
                        if let Some(fed_ch) = relay.channels.get(&target_lower) {
                            let echo = Message {
                                prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                command: msg.command.clone(),
                                params: vec![target_lower.clone(), text.clone()],
                            };
                            let others: Vec<_> = fed_ch
                                .local_users
                                .iter()
                                .filter(|n| *n != &nick_key)
                                .cloned()
                                .collect();
                            broadcast(&st, &others, &echo);
                        }
                    }
                } else if target.starts_with('#') || target.starts_with('&') {
                    // Local channel message — enforce +n and +m modes.
                    let st = state.read().await;

                    // 403: channel doesn't exist.
                    if !st.channels.contains_key(&target_lower) {
                        drop(st);
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "403".into(),
                            params: vec![nick.into(), target_lower.clone(), "No such channel".into()],
                        };
                        framed.send(err).await?;
                    } else {

                    // +n: no external messages — sender must be in channel.
                    let in_channel = st.channels.get(&target_lower)
                        .is_some_and(|m| m.contains_key(&nick_key));
                    if !in_channel {
                        let no_ext = st.channel_modes.get(&target_lower)
                            .is_some_and(|m| m.no_external);
                        if no_ext {
                            drop(st);
                            let err = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "404".into(),
                                params: vec![nick.into(), target_lower.clone(), "Cannot send to channel (+n)".into()],
                            };
                            framed.send(err).await?;
                        }
                    } else {
                        // +m: moderated — sender must be Voice+ to speak.
                        let moderated = st.channel_modes.get(&target_lower)
                            .is_some_and(|m| m.moderated);
                        if moderated {
                            let sender_prefix = st.channels.get(&target_lower)
                                .and_then(|m| m.get(&nick_key).copied())
                                .unwrap_or(MemberPrefix::Normal);
                            if sender_prefix < MemberPrefix::Voice {
                                drop(st);
                                let err = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "404".into(),
                                    params: vec![nick.into(), target_lower.clone(), "Cannot send to channel (+m)".into()],
                                };
                                framed.send(err).await?;
                            } else {
                                let relay_msg = Message {
                                    prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                    command: msg.command.clone(),
                                    params: vec![target_lower.clone(), text.clone()],
                                };
                                if let Some(members) = st.channels.get(&target_lower) {
                                    let others: Vec<_> = members
                                        .keys()
                                        .filter(|n| *n != &nick_key)
                                        .cloned()
                                        .collect();
                                    broadcast(&st, &others, &relay_msg);
                                }
                                // Gossip broadcast to mesh peers.
                                let _ = st.federation_event_tx.send(
                                    RelayEvent::GossipBroadcast {
                                        event: super::gossip::GossipIrcEvent::Message {
                                            nick: nick.to_owned(),
                                            origin: SERVER_NAME.clone(),
                                            channel: target_lower.clone(),
                                            text: text.clone(),
                                            command: msg.command.clone(),
                                        },
                                    },
                                );
                            }
                        } else {
                            let relay_msg = Message {
                                prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                command: msg.command.clone(),
                                params: vec![target_lower.clone(), text.clone()],
                            };
                            if let Some(members) = st.channels.get(&target_lower) {
                                let others: Vec<_> = members
                                    .keys()
                                    .filter(|n| *n != &nick_key)
                                    .cloned()
                                    .collect();
                                broadcast(&st, &others, &relay_msg);
                            }
                            // Gossip broadcast to mesh peers.
                            let _ = st.federation_event_tx.send(
                                RelayEvent::GossipBroadcast {
                                    event: super::gossip::GossipIrcEvent::Message {
                                        nick: nick.to_owned(),
                                        origin: SERVER_NAME.clone(),
                                        channel: target_lower.clone(),
                                        text: text.clone(),
                                        command: msg.command.clone(),
                                    },
                                },
                            );
                        }
                    }
                    } // close the 403/exists else
                } else if target.contains('@') {
                    // Federated DM: nick@remote.host
                    if let Some((target_nick, remote_host)) = target.split_once('@') {
                        if remote_host.contains('.') {
                            let st = state.read().await;
                            let relay_key = derive_node_name(remote_host);
                            if let Some(relay) = st.federation.relays.get(&relay_key) {
                                // Route DM through existing relay connection.
                                let dm = Message {
                                    prefix: None,
                                    command: "FRELAY".into(),
                                    params: vec![
                                        "DM".into(),
                                        nick.to_owned(),
                                        SERVER_NAME.clone(),
                                        target_nick.to_owned(),
                                        text.clone(),
                                    ],
                                };
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::Raw(dm),
                                );
                            } else {
                                drop(st);
                                let err = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "401".into(),
                                    params: vec![
                                        nick.into(),
                                        target.clone(),
                                        "No federation relay to that server".into(),
                                    ],
                                };
                                framed.send(err).await?;
                            }
                        } else {
                            let err = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "401".into(),
                                params: vec![nick.into(), target.clone(), "No such nick/channel".into()],
                            };
                            framed.send(err).await?;
                        }
                    }
                } else {
                    // Direct message to a local user.
                    let relay_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                        command: msg.command.clone(),
                        params: vec![target.clone(), text.clone()],
                    };
                    let st = state.read().await;
                    if let Some(handle) = st.clients.get(&target_lower) {
                        let _ = handle.tx.send(relay_msg);
                        // RPL_AWAY (301) — notify sender if target is away.
                        if let Some(ref away_msg) = handle.away_message {
                            let r301 = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "301".into(),
                                params: vec![nick.into(), handle.nick.clone(), away_msg.clone()],
                            };
                            drop(st);
                            framed.send(r301).await?;
                        }
                    } else {
                        drop(st);
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "401".into(),
                            params: vec![nick.into(), target.clone(), "No such nick/channel".into()],
                        };
                        framed.send(err).await?;
                    }
                }
            }
        }

        "TOPIC" => {
            if let Some(raw_channel) = msg.params.first() {
                let channel = irc_lower(raw_channel);
                if msg.params.len() >= 2 {
                    let nick_key = irc_lower(nick);

                    // Check user is in channel (442 ERR_NOTONCHANNEL).
                    let st = state.read().await;
                    let in_channel = st.channels.get(&channel)
                        .is_some_and(|m| m.contains_key(&nick_key));
                    if !in_channel {
                        drop(st);
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "442".into(),
                            params: vec![nick.into(), channel.clone(), "You're not on that channel".into()],
                        };
                        framed.send(err).await?;
                    } else {
                        // Enforce +t: only Op+ can set topic.
                        let topic_locked = st.channel_modes.get(&channel)
                            .is_some_and(|m| m.topic_locked);
                        if topic_locked {
                            let sender_prefix = st.channels.get(&channel)
                                .and_then(|m| m.get(&nick_key).copied())
                                .unwrap_or(MemberPrefix::Normal);
                            if sender_prefix < MemberPrefix::Op {
                                drop(st);
                                let err = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "482".into(),
                                    params: vec![nick.into(), channel.clone(), "You're not channel operator".into()],
                                };
                                framed.send(err).await?;
                            } else {
                                drop(st);
                                // Enforce TOPICLEN=390.
                                let raw_topic = &msg.params[1];
                                let topic: &str = if raw_topic.len() > 390 { &raw_topic[..390] } else { raw_topic };
                                let topic_msg = Message {
                                    prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                    command: "TOPIC".into(),
                                    params: vec![channel.clone(), topic.to_owned()],
                                };
                                let mut st = state.write().await;
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs();
                                st.channel_topics.insert(
                                    channel.clone(),
                                    (topic.to_owned(), nick.to_owned(), now),
                                );
                                if let Some(members) = st.channels.get(&channel) {
                                    let member_list: Vec<_> = members.keys().cloned().collect();
                                    broadcast(&st, &member_list, &topic_msg);
                                }
                            }
                        } else {
                            drop(st);
                            // Enforce TOPICLEN=390.
                            let raw_topic = &msg.params[1];
                            let topic: &str = if raw_topic.len() > 390 { &raw_topic[..390] } else { raw_topic };
                            let topic_msg = Message {
                                prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                command: "TOPIC".into(),
                                params: vec![channel.clone(), topic.to_owned()],
                            };
                            let mut st = state.write().await;
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            st.channel_topics.insert(
                                channel.clone(),
                                (topic.to_owned(), nick.to_owned(), now),
                            );
                            if let Some(members) = st.channels.get(&channel) {
                                let member_list: Vec<_> = members.keys().cloned().collect();
                                broadcast(&st, &member_list, &topic_msg);
                            }
                        }
                    }
                } else {
                    // Topic query — return stored topic or 331.
                    let st = state.read().await;
                    if let Some((text, set_by, timestamp)) = st.channel_topics.get(&channel) {
                        let r332 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "332".into(),
                            params: vec![nick.into(), channel.clone(), text.clone()],
                        };
                        let r333 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "333".into(),
                            params: vec![nick.into(), channel.clone(), set_by.clone(), timestamp.to_string()],
                        };
                        drop(st);
                        framed.send(r332).await?;
                        framed.send(r333).await?;
                    } else {
                        drop(st);
                        let reply = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "331".into(),
                            params: vec![nick.into(), channel.clone(), "No topic is set".into()],
                        };
                        framed.send(reply).await?;
                    }
                }
            }
        }

        "KICK" => {
            // KICK #channel target :reason
            if msg.params.len() >= 2 {
                let channel = irc_lower(&msg.params[0]);
                let target_nick = &msg.params[1];
                let target_key = irc_lower(target_nick);
                let nick_key = irc_lower(nick);
                let reason = msg.params.get(2).cloned().unwrap_or_else(|| nick.to_owned());
                // Enforce KICKLEN=390.
                let reason: String = if reason.len() > 390 { reason[..390].to_owned() } else { reason };

                let mut st = state.write().await;

                // Verify sender is in channel.
                let sender_prefix = st
                    .channels
                    .get(&channel)
                    .and_then(|m| m.get(&nick_key).copied());

                let Some(sender_prefix) = sender_prefix else {
                    drop(st);
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "442".into(),
                        params: vec![nick.into(), channel.clone(), "You're not on that channel".into()],
                    };
                    framed.send(err).await?;
                    return Ok(CommandResult::Ok);
                };

                // Verify sender has Op+ privileges.
                if sender_prefix < MemberPrefix::Op {
                    drop(st);
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "482".into(),
                        params: vec![nick.into(), channel.clone(), "You're not channel operator".into()],
                    };
                    framed.send(err).await?;
                    return Ok(CommandResult::Ok);
                }

                // Verify target is in channel.
                let target_in_channel = st
                    .channels
                    .get(&channel)
                    .is_some_and(|m| m.contains_key(&target_key));

                if !target_in_channel {
                    // Get display nick for the error.
                    let display_target = st.clients.get(&target_key)
                        .map(|h| h.nick.clone())
                        .unwrap_or_else(|| target_nick.clone());
                    drop(st);
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "441".into(),
                        params: vec![nick.into(), display_target, channel.clone(), "They aren't on that channel".into()],
                    };
                    framed.send(err).await?;
                    return Ok(CommandResult::Ok);
                }

                // Get display nick for kick message.
                let display_target = st.clients.get(&target_key)
                    .map(|h| h.nick.clone())
                    .unwrap_or_else(|| target_nick.clone());

                // Broadcast KICK to all channel members (including the target).
                let kick_msg = Message {
                    prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                    command: "KICK".into(),
                    params: vec![channel.clone(), display_target, reason],
                };
                if let Some(members) = st.channels.get(&channel) {
                    let member_list: Vec<_> = members.keys().cloned().collect();
                    broadcast(&st, &member_list, &kick_msg);
                }

                // Remove target from channel.
                if let Some(members) = st.channels.get_mut(&channel) {
                    members.remove(&target_key);
                    if members.is_empty() {
                        st.channels.remove(&channel);
                        st.channel_modes.remove(&channel);
                        st.channel_bans.remove(&channel);
                        st.channel_invites.remove(&channel);
                    }
                }
            } else {
                let err = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "461".into(),
                    params: vec![nick.into(), "KICK".into(), "Not enough parameters".into()],
                };
                framed.send(err).await?;
            }
        }

        "WHO" => {
            if let Some(raw_target) = msg.params.first() {
                let target = irc_lower(raw_target);
                let st = state.read().await;
                if target.starts_with('#') || target.starts_with('&') {
                    // WHO for a channel — list local members (hide relay nicks).
                    if let Some(members) = st.channels.get(&target) {
                        for (member_key, prefix) in members.iter().filter(|(n, _)| !federation::is_relay_nick(n)) {
                            let display = st.clients.get(member_key).map(|h| h.nick.as_str()).unwrap_or(member_key);
                            let flags = format!("H{}", prefix.symbol());
                            let reply = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "352".into(),
                                params: vec![
                                    nick.into(),
                                    target.clone(),
                                    display.to_owned(),
                                    "lagoon".into(),
                                    SERVER_NAME.clone(),
                                    display.to_owned(),
                                    flags,
                                    format!("0 {display}"),
                                ],
                            };
                            framed.send(reply).await?;
                        }
                    }
                    // Include remote users from federation relays.
                    for relay in st.federation.relays.values() {
                        if let Some(fed_ch) = relay.channels.get(&target) {
                            for rn in &fed_ch.remote_users {
                                let display_nick = if rn.contains('@') {
                                    rn.clone()
                                } else {
                                    format!("{rn}@{}", relay.connect_target)
                                };
                                let reply = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "352".into(),
                                    params: vec![
                                        nick.into(),
                                        target.clone(),
                                        display_nick.clone(),
                                        relay.connect_target.clone(),
                                        relay.connect_target.clone(),
                                        display_nick.clone(),
                                        "H".into(),
                                        format!("1 {display_nick}"),
                                    ],
                                };
                                framed.send(reply).await?;
                            }
                        }
                    }
                }
                drop(st);
                // End of WHO.
                let end = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "315".into(),
                    params: vec![nick.into(), target.clone(), "End of /WHO list".into()],
                };
                framed.send(end).await?;
            }
        }

        "LIST" => {
            let nick_key = irc_lower(nick);
            let st = state.read().await;
            // RPL_LISTSTART (321)
            let start = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "321".into(),
                params: vec![nick.into(), "Channel".into(), "Users  Name".into()],
            };
            framed.send(start).await?;

            for (channel, members) in &st.channels {
                // +s: skip secret channels unless requester is a member.
                let secret = st.channel_modes.get(channel)
                    .is_some_and(|m| m.secret);
                if secret && !members.contains_key(&nick_key) {
                    continue;
                }
                // RPL_LIST (322): channel, visible member count, topic
                let topic_text = st.channel_topics.get(channel)
                    .map(|(t, _, _)| t.clone())
                    .unwrap_or_default();
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "322".into(),
                    params: vec![
                        nick.into(),
                        channel.clone(),
                        members.len().to_string(),
                        topic_text,
                    ],
                };
                framed.send(reply).await?;
            }
            drop(st);

            // RPL_LISTEND (323)
            let end = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "323".into(),
                params: vec![nick.into(), "End of /LIST".into()],
            };
            framed.send(end).await?;
        }

        "NAMES" => {
            if let Some(raw_channel) = msg.params.first() {
                let channel = irc_lower(raw_channel);
                if let Some((_remote_chan, remote_host)) =
                    federation::parse_federated_channel(&channel)
                {
                    // Federated channel — combine local + remote users.
                    let st = state.read().await;
                    let relay_key = derive_node_name(remote_host);
                    let names = if let Some(relay) = st.federation.relays.get(&relay_key) {
                        if let Some(fed_ch) = relay.channels.get(&channel) {
                            let mut parts: Vec<String> = fed_ch
                                .local_users
                                .iter()
                                .map(|k| st.clients.get(k).map(|h| h.nick.clone()).unwrap_or_else(|| k.clone()))
                                .collect();
                            for rn in &fed_ch.remote_users {
                                if rn.contains('@') {
                                    parts.push(rn.clone());
                                } else {
                                    parts.push(format!("{rn}@{}", relay.connect_target));
                                }
                            }
                            parts.join(" ")
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    };
                    drop(st);

                    let names_msg = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "353".into(),
                        params: vec![nick.into(), "=".into(), channel.clone(), names],
                    };
                    framed.send(names_msg).await?;

                    let end_msg = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "366".into(),
                        params: vec![nick.into(), channel.clone(), "End of /NAMES list".into()],
                    };
                    framed.send(end_msg).await?;
                } else {
                    // Local channel — local users only (relay nicks hidden).
                    let st = state.read().await;
                    let names = st
                        .channels
                        .get(&channel)
                        .map(|m| {
                            m.iter()
                                .filter(|(n, _)| !federation::is_relay_nick(n))
                                .map(|(n, p)| {
                                    let display = st.clients.get(n).map(|h| h.nick.as_str()).unwrap_or(n);
                                    format!("{}{display}", p.symbol())
                                })
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();
                    drop(st);

                    let names_msg = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "353".into(),
                        params: vec![nick.into(), "=".into(), channel.clone(), names],
                    };
                    framed.send(names_msg).await?;

                    let end_msg = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "366".into(),
                        params: vec![nick.into(), channel.clone(), "End of /NAMES list".into()],
                    };
                    framed.send(end_msg).await?;
                }
            }
        }

        "MODE" => {
            if let Some(raw_target) = msg.params.first() {
                let target = irc_lower(raw_target);
                if target.starts_with('#') || target.starts_with('&') {
                    if msg.params.len() >= 2 {
                        // Channel mode change.
                        let mode_str = &msg.params[1];
                        let mode_params: Vec<String> = msg.params[2..].to_vec();
                        let nick_key = irc_lower(nick);

                        let changes = modes::parse_mode_string(mode_str, &mode_params);

                        let mut st = state.write().await;
                        let sender_prefix = st
                            .channels
                            .get(&target)
                            .and_then(|m| m.get(&nick_key).copied())
                            .unwrap_or(MemberPrefix::Normal);

                        // Track applied changes for broadcast.
                        let mut applied_modes = String::new();
                        let mut applied_params: Vec<String> = Vec::new();
                        let mut last_setting: Option<bool> = None;

                        for change in &changes {
                            match change.mode {
                                // Membership modes (q/a/o/v).
                                'q' | 'a' | 'o' | 'v' => {
                                    if sender_prefix < MemberPrefix::Op {
                                        continue;
                                    }
                                    let new_prefix = if change.setting {
                                        match change.mode {
                                            'q' => MemberPrefix::Owner,
                                            'a' => MemberPrefix::Admin,
                                            'o' => MemberPrefix::Op,
                                            'v' => MemberPrefix::Voice,
                                            _ => unreachable!(),
                                        }
                                    } else {
                                        MemberPrefix::Normal
                                    };
                                    if let Some(ref target_nick) = change.param {
                                        let target_key = irc_lower(target_nick);
                                        if let Some(members) = st.channels.get_mut(&target) {
                                            if let Some(p) = members.get_mut(&target_key) {
                                                *p = new_prefix;
                                            }
                                        }
                                        st.channel_roles
                                            .entry(target.clone())
                                            .or_default()
                                            .insert(target_key, new_prefix);
                                        if last_setting != Some(change.setting) {
                                            applied_modes.push(if change.setting { '+' } else { '-' });
                                            last_setting = Some(change.setting);
                                        }
                                        applied_modes.push(change.mode);
                                        applied_params.push(target_nick.clone());
                                    }
                                }
                                // Ban mode (b) — handled in Phase 4 (Step 8).
                                'b' => {
                                    if change.param.is_none() && change.setting {
                                        // +b with no param = list bans.
                                        let bans = st.channel_bans.get(&target);
                                        let ban_list: Vec<_> = bans
                                            .map(|b| b.iter().map(|e| (e.mask.clone(), e.set_by.clone(), e.set_at)).collect())
                                            .unwrap_or_default();
                                        for (mask, set_by, set_at) in ban_list {
                                            let r367 = Message {
                                                prefix: Some(SERVER_NAME.clone()),
                                                command: "367".into(),
                                                params: vec![
                                                    nick.into(),
                                                    target.clone(),
                                                    mask,
                                                    set_by,
                                                    set_at.to_string(),
                                                ],
                                            };
                                            framed.send(r367).await?;
                                        }
                                        let r368 = Message {
                                            prefix: Some(SERVER_NAME.clone()),
                                            command: "368".into(),
                                            params: vec![nick.into(), target.clone(), "End of Channel Ban List".into()],
                                        };
                                        framed.send(r368).await?;
                                        continue;
                                    }
                                    if sender_prefix < MemberPrefix::Op {
                                        continue;
                                    }
                                    if let Some(ref mask) = change.param {
                                        if change.setting {
                                            let now = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_secs())
                                                .unwrap_or(0);
                                            st.channel_bans
                                                .entry(target.clone())
                                                .or_default()
                                                .push(BanEntry {
                                                    mask: mask.clone(),
                                                    set_by: nick.to_owned(),
                                                    set_at: now,
                                                });
                                        } else {
                                            if let Some(bans) = st.channel_bans.get_mut(&target) {
                                                bans.retain(|b| b.mask != *mask);
                                            }
                                        }
                                        if last_setting != Some(change.setting) {
                                            applied_modes.push(if change.setting { '+' } else { '-' });
                                            last_setting = Some(change.setting);
                                        }
                                        applied_modes.push('b');
                                        applied_params.push(mask.clone());
                                    }
                                }
                                // Channel flag modes (i/m/n/s/t/k/l).
                                'i' | 'm' | 'n' | 's' | 't' | 'k' | 'l' => {
                                    if sender_prefix < MemberPrefix::Op {
                                        continue;
                                    }
                                    let chan_modes = st.channel_modes
                                        .entry(target.clone())
                                        .or_insert_with(ChannelModes::default);

                                    match change.mode {
                                        'i' => chan_modes.invite_only = change.setting,
                                        'm' => chan_modes.moderated = change.setting,
                                        'n' => chan_modes.no_external = change.setting,
                                        's' => chan_modes.secret = change.setting,
                                        't' => chan_modes.topic_locked = change.setting,
                                        'k' => {
                                            if change.setting {
                                                chan_modes.key = change.param.clone();
                                            } else {
                                                chan_modes.key = None;
                                            }
                                        }
                                        'l' => {
                                            if change.setting {
                                                chan_modes.limit = change.param
                                                    .as_ref()
                                                    .and_then(|p| p.parse().ok());
                                            } else {
                                                chan_modes.limit = None;
                                            }
                                        }
                                        _ => unreachable!(),
                                    }

                                    if last_setting != Some(change.setting) {
                                        applied_modes.push(if change.setting { '+' } else { '-' });
                                        last_setting = Some(change.setting);
                                    }
                                    applied_modes.push(change.mode);
                                    if let Some(ref p) = change.param {
                                        applied_params.push(p.clone());
                                    }
                                }
                                // Unknown mode.
                                unknown => {
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "472".into(),
                                        params: vec![
                                            nick.into(),
                                            unknown.to_string(),
                                            "is unknown mode char to me".into(),
                                        ],
                                    };
                                    framed.send(err).await?;
                                }
                            }
                        }

                        // Broadcast applied changes to all members.
                        if !applied_modes.is_empty() {
                            let mut mode_params_out = vec![target.clone(), applied_modes];
                            mode_params_out.extend(applied_params);
                            let mode_msg = Message {
                                prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                command: "MODE".into(),
                                params: mode_params_out,
                            };
                            if let Some(members) = st.channels.get(&target) {
                                let member_list: Vec<_> =
                                    members.keys().cloned().collect();
                                broadcast(&st, &member_list, &mode_msg);
                            }
                        }
                    } else {
                        // Channel mode query — return current mode string.
                        let st = state.read().await;
                        let mode_string = st.channel_modes.get(&target)
                            .map(|m| m.to_mode_string())
                            .unwrap_or_else(|| "+".into());
                        drop(st);
                        let reply = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "324".into(),
                            params: vec![nick.into(), target.clone(), mode_string],
                        };
                        framed.send(reply).await?;
                    }
                } else {
                    // User mode query.
                    let reply = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "221".into(),
                        params: vec![nick.into(), "+".into()],
                    };
                    framed.send(reply).await?;
                }
            }
        }

        "MOTD" => {
            let motd_lines = [
                &format!("Welcome to {} — decentralized chat for everyone.", *DISPLAY_NAME),
                "Powered by Lagoon IRC server.",
            ];
            let start = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "375".into(),
                params: vec![nick.into(), format!("- {} Message of the Day -", *SERVER_NAME)],
            };
            framed.send(start).await?;
            for line in motd_lines {
                let msg = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "372".into(),
                    params: vec![nick.into(), format!("- {line}")],
                };
                framed.send(msg).await?;
            }
            let end = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "376".into(),
                params: vec![nick.into(), "End of /MOTD command".into()],
            };
            framed.send(end).await?;
        }

        // FRELAY — federation relay command (Lagoon extension).
        // Lets a relay connection send messages on behalf of remote users.
        // Format: FRELAY PRIVMSG <nick> <origin_host> <channel> :<text>
        //         FRELAY JOIN <nick> <origin_host> <channel>
        //         FRELAY PART <nick> <origin_host> <channel> :<reason>
        "FRELAY" => {
            if msg.params.len() >= 4 {
                let sub_cmd = &msg.params[0];
                let origin_nick = &msg.params[1];
                let origin_host = &msg.params[2];
                let raw_channel = &msg.params[3];
                let channel = irc_lower(raw_channel);
                let nick_key = irc_lower(nick);

                // Build the virtual nick: nick@origin_host
                let virtual_nick = format!("{origin_nick}@{origin_host}");
                let virtual_nick_key = irc_lower(&virtual_nick);
                let virtual_prefix =
                    format!("{virtual_nick}!{origin_nick}@{origin_host}");

                match sub_cmd.as_str() {
                    "PRIVMSG" => {
                        if let Some(text) = msg.params.get(4) {
                            let relay_msg = Message {
                                prefix: Some(virtual_prefix),
                                command: "PRIVMSG".into(),
                                params: vec![channel.clone(), text.clone()],
                            };
                            let st = state.read().await;
                            if let Some(members) = st.channels.get(&channel) {
                                let others: Vec<_> = members
                                    .keys()
                                    .filter(|n| *n != &nick_key)
                                    .cloned()
                                    .collect();
                                broadcast(&st, &others, &relay_msg);
                            }
                        }
                    }
                    "JOIN" => {
                        let join_msg = Message {
                            prefix: Some(virtual_prefix),
                            command: "JOIN".into(),
                            params: vec![channel.clone()],
                        };
                        let mut st = state.write().await;
                        if let Some(members) = st.channels.get_mut(&channel) {
                            members.insert(virtual_nick_key.clone(), MemberPrefix::Normal);
                            let others: Vec<_> = members
                                .keys()
                                .filter(|n| *n != &nick_key && *n != &virtual_nick_key)
                                .cloned()
                                .collect();
                            broadcast(&st, &others, &join_msg);
                        }
                    }
                    "PART" => {
                        let reason = msg.params.get(4).cloned().unwrap_or_default();
                        let part_msg = Message {
                            prefix: Some(virtual_prefix),
                            command: "PART".into(),
                            params: vec![channel.clone(), reason],
                        };
                        let mut st = state.write().await;
                        let others: Vec<_> = st
                            .channels
                            .get(&channel)
                            .map(|members| {
                                members
                                    .keys()
                                    .filter(|n| *n != &nick_key && *n != &virtual_nick_key)
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        broadcast(&st, &others, &part_msg);
                        // Remove virtual user from channel membership.
                        if let Some(members) = st.channels.get_mut(&channel) {
                            members.remove(&virtual_nick_key);
                        }
                    }
                    "DM" => {
                        // FRELAY DM <sender> <origin_host> <target_nick> :<text>
                        // channel (params[3]) is repurposed as target_nick (already lowered).
                        let target_key = &channel;
                        if let Some(text) = msg.params.get(4) {
                            let st = state.read().await;
                            if let Some(handle) = st.clients.get(target_key) {
                                let dm_msg = Message {
                                    prefix: Some(virtual_prefix),
                                    command: "PRIVMSG".into(),
                                    params: vec![handle.nick.clone(), text.clone()],
                                };
                                let _ = handle.tx.send(dm_msg);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        "WHOIS" => {
            if let Some(raw_target) = msg.params.last() {
                let target_key = irc_lower(raw_target);
                let st = state.read().await;
                if let Some(handle) = st.clients.get(&target_key) {
                    let display_nick = &handle.nick;
                    let user = handle.user.as_deref().unwrap_or(display_nick);
                    let realname = handle.realname.as_deref().unwrap_or("");
                    // 311 RPL_WHOISUSER
                    let r311 = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "311".into(),
                        params: vec![
                            nick.into(),
                            display_nick.clone(),
                            user.into(),
                            "lagoon".into(),
                            "*".into(),
                            realname.into(),
                        ],
                    };
                    framed.send(r311).await?;
                    // 312 RPL_WHOISSERVER
                    let r312 = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "312".into(),
                        params: vec![
                            nick.into(),
                            display_nick.clone(),
                            SERVER_NAME.clone(),
                            DISPLAY_NAME.clone(),
                        ],
                    };
                    framed.send(r312).await?;
                    // 319 RPL_WHOISCHANNELS (skip +s channels unless requester is a member)
                    let requester_key = irc_lower(nick);
                    let mut chans = Vec::new();
                    for (ch_name, members) in &st.channels {
                        if let Some(prefix) = members.get(&target_key) {
                            // Hide +s channels from non-members.
                            let secret = st.channel_modes.get(ch_name)
                                .is_some_and(|m| m.secret);
                            if secret && !members.contains_key(&requester_key) {
                                continue;
                            }
                            chans.push(format!("{}{ch_name}", prefix.symbol()));
                        }
                    }
                    if !chans.is_empty() {
                        let r319 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "319".into(),
                            params: vec![nick.into(), display_nick.clone(), chans.join(" ")],
                        };
                        framed.send(r319).await?;
                    }
                    // 301 RPL_AWAY (if away)
                    if let Some(ref away_msg) = handle.away_message {
                        let r301 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "301".into(),
                            params: vec![nick.into(), display_nick.clone(), away_msg.clone()],
                        };
                        framed.send(r301).await?;
                    }
                } else {
                    // 401 ERR_NOSUCHNICK
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "401".into(),
                        params: vec![nick.into(), raw_target.clone(), "No such nick/channel".into()],
                    };
                    framed.send(err).await?;
                }
                drop(st);
                // 318 RPL_ENDOFWHOIS (always sent)
                let r318 = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "318".into(),
                    params: vec![nick.into(), raw_target.clone(), "End of /WHOIS list".into()],
                };
                framed.send(r318).await?;
            }
        }

        // MESH — mesh networking protocol (Lagoon extension).
        // Received from relay nicks — forwarded to federation event processor.
        "MESH" => {
            if msg.params.first().map(|s| s.as_str()) == Some("SPIRAL") {
                // MESH SPIRAL — show our SPIRAL topology status.
                let st = state.read().await;
                let sn = &*SERVER_NAME;
                let mut replies = Vec::new();
                if let (Some(idx), Some(coord)) = (st.mesh.spiral.our_index(), st.mesh.spiral.our_coord()) {
                    let shell = idx.shell();
                    let neighbor_count = st.mesh.spiral.neighbors().len();
                    let occupied = st.mesh.spiral.occupied_count();
                    replies.push(format!("SPIRAL slot {}, shell {}", idx.value(), shell));
                    replies.push(format!("Coordinate ({}, {}, {})", coord.q, coord.r, coord.z));
                    replies.push(format!("{} occupied slots, {} SPIRAL neighbors", occupied, neighbor_count));
                    for neighbor_id in st.mesh.spiral.neighbors() {
                        let server = st.mesh.known_peers.get(neighbor_id)
                            .map(|p| p.server_name.as_str())
                            .unwrap_or("?");
                        let peer_idx = st.mesh.spiral.peer_index(neighbor_id)
                            .map(|i| i.value().to_string())
                            .unwrap_or_else(|| "?".into());
                        replies.push(format!("  neighbor: {} (slot {}, {})", neighbor_id, peer_idx, server));
                    }
                } else {
                    replies.push("SPIRAL: no position claimed yet".into());
                }
                drop(st);
                for line in replies {
                    let notice = Message {
                        prefix: Some(sn.clone()),
                        command: "NOTICE".into(),
                        params: vec![nick.to_owned(), line],
                    };
                    framed.send(notice).await?;
                }
            } else if msg.params.first().map(|s| s.as_str()) == Some("VDF") {
                // MESH VDF — show our VDF engine status.
                let st = state.read().await;
                let sn = &*SERVER_NAME;
                let mut replies = Vec::new();
                if let Some(ref rx) = st.mesh.vdf_state_rx {
                    let vdf = rx.borrow().clone();
                    replies.push(format!("VDF Genesis:      {}", lagoon_vdf::to_hex_short(&vdf.genesis, 16)));
                    replies.push(format!("VDF Current:      {}", lagoon_vdf::to_hex_short(&vdf.current_hash, 16)));
                    replies.push(format!("Session Steps:    {}", vdf.session_steps));
                    replies.push(format!("Total Steps:      {}", vdf.total_steps));
                    let tick_rate: u64 = std::env::var("LAGOON_VDF_RATE")
                        .ok().and_then(|v| v.parse().ok()).unwrap_or(10);
                    replies.push(format!("Tick Rate:        {} Hz", tick_rate));
                    if let Some(ref chain) = st.mesh.vdf_chain {
                        let chain_len = chain.read().await.hashes.len();
                        let bytes = chain_len * 32;
                        replies.push(format!("Chain Size:       {} hashes (~{} KB)", chain_len, bytes / 1024));
                    }
                } else {
                    replies.push("VDF: engine not active".into());
                }
                drop(st);
                for line in replies {
                    let notice = Message {
                        prefix: Some(sn.clone()),
                        command: "NOTICE".into(),
                        params: vec![nick.to_owned(), line],
                    };
                    framed.send(notice).await?;
                }
            } else if msg.params.first().map(|s| s.as_str()) == Some("SYNC") {
                // MESH SYNC — request full peer table from all connected mesh relays.
                let st = state.read().await;
                let sn = &*SERVER_NAME;
                let relay_count = st.federation.relays.values()
                    .filter(|r| r.mesh_connected)
                    .count();
                for relay in st.federation.relays.values() {
                    if relay.mesh_connected {
                        let _ = relay.outgoing_tx.send(federation::RelayCommand::SendMesh(
                            super::wire::MeshMessage::Sync,
                        ));
                    }
                }
                drop(st);
                let notice = Message {
                    prefix: Some(sn.clone()),
                    command: "NOTICE".into(),
                    params: vec![
                        nick.to_owned(),
                        format!("MESH SYNC requested from {} peer(s)", relay_count),
                    ],
                };
                framed.send(notice).await?;
            } else if msg.params.len() >= 2 {
                let sub_cmd = &msg.params[0];
                let json = &msg.params[1];
                let st = state.read().await;

                match sub_cmd.as_str() {
                    "HELLO" => {
                        #[derive(serde::Deserialize)]
                        struct HelloPayload {
                            peer_id: String,
                            server_name: String,
                            public_key_hex: String,
                            #[serde(default)]
                            spiral_index: Option<u64>,
                            #[serde(default)]
                            vdf_genesis: Option<String>,
                            #[serde(default)]
                            vdf_hash: Option<String>,
                            #[serde(default)]
                            vdf_step: Option<u64>,
                            #[serde(default)]
                            yggdrasil_addr: Option<String>,
                            #[serde(default)]
                            site_name: String,
                            #[serde(default)]
                            node_name: String,
                            #[serde(default)]
                            vdf_resonance_credit: Option<f64>,
                            #[serde(default)]
                            vdf_actual_rate_hz: Option<f64>,
                            #[serde(default)]
                            vdf_cumulative_credit: Option<f64>,
                            #[serde(default)]
                            ygg_peer_uri: Option<String>,
                            #[serde(default)]
                            cvdf_height: Option<u64>,
                            #[serde(default)]
                            cvdf_weight: Option<u64>,
                            #[serde(default)]
                            cvdf_tip_hex: Option<String>,
                            #[serde(default)]
                            cvdf_genesis_hex: Option<String>,
                            #[serde(default)]
                            cluster_vdf_work: Option<f64>,
                            #[serde(default)]
                            assigned_slot: Option<u64>,
                            #[serde(default)]
                            cluster_chain_value: Option<String>,
                            #[serde(default)]
                            cluster_chain_round: Option<u64>,
                        }
                        if let Ok(hello) = serde_json::from_str::<HelloPayload>(json) {
                            // Use node_name from HELLO if present, else derive from server_name.
                            let node_name = if hello.node_name.is_empty() {
                                derive_node_name(&hello.server_name)
                            } else {
                                hello.node_name
                            };
                            let site_name = if hello.site_name.is_empty() {
                                derive_site_name(&hello.server_name)
                            } else {
                                hello.site_name
                            };
                            let _ = st.federation_event_tx.send(
                                federation::RelayEvent::MeshHello {
                                    remote_host: node_name.clone(),
                                    peer_id: hello.peer_id,
                                    server_name: hello.server_name.clone(),
                                    public_key_hex: hello.public_key_hex,
                                    spiral_index: hello.spiral_index,
                                    vdf_genesis: hello.vdf_genesis,
                                    vdf_hash: hello.vdf_hash,
                                    vdf_step: hello.vdf_step,
                                    yggdrasil_addr: hello.yggdrasil_addr,
                                    site_name,
                                    node_name,
                                    vdf_resonance_credit: hello.vdf_resonance_credit,
                                    vdf_actual_rate_hz: hello.vdf_actual_rate_hz,
                                    vdf_cumulative_credit: hello.vdf_cumulative_credit,
                                    ygg_peer_uri: hello.ygg_peer_uri,
                                    // Inbound: they connected to us, so we don't
                                    // have a meaningful TCP peer addr for APE
                                    // underlay derivation (they initiated).
                                    relay_peer_addr: None,
                                    cvdf_height: hello.cvdf_height,
                                    cvdf_weight: hello.cvdf_weight,
                                    cvdf_tip_hex: hello.cvdf_tip_hex,
                                    cvdf_genesis_hex: hello.cvdf_genesis_hex,
                                    cluster_vdf_work: hello.cluster_vdf_work,
                                    assigned_slot: hello.assigned_slot,
                                    cluster_chain_value: hello.cluster_chain_value,
                                    cluster_chain_round: hello.cluster_chain_round,
                                },
                            );

                            // Respond with our own HELLO (include SPIRAL + VDF + resonance + APE).
                            let (our_vdf_genesis, our_vdf_hash, our_vdf_step, our_vdf_credit, our_vdf_rate, our_vdf_rolling) = st
                                .mesh
                                .vdf_state_rx
                                .as_ref()
                                .map(|rx| {
                                    let vdf = rx.borrow();
                                    let (credit, rate, rolling) = vdf
                                        .resonance
                                        .as_ref()
                                        .map(|r| (Some(r.credit), Some(r.actual_rate_hz), Some(r.rolling_credit_3c)))
                                        .unwrap_or((None, None, None));
                                    (
                                        Some(hex::encode(vdf.genesis)),
                                        Some(hex::encode(vdf.current_hash)),
                                        Some(vdf.total_steps),
                                        credit,
                                        rate,
                                        rolling,
                                    )
                                })
                                .unwrap_or((None, None, None, None, None, None));

                            // Ygg overlay address (identity/routing).
                            let our_ygg_addr = st.transport_config.ygg_node
                                .as_ref()
                                .map(|n| n.address().to_string());
                            // Ygg peer URI = UNDERLAY address. You don't tunnel Ygg through Ygg.
                            let our_ygg_peer_uri = super::transport::detect_underlay_addr().map(|addr| match addr {
                                std::net::IpAddr::V6(v6) => format!("tcp://[{v6}]:9443"),
                                std::net::IpAddr::V4(v4) => format!("tcp://{v4}:9443"),
                            });

                            // Concierge: if we're established, compute first empty
                            // slot so the joiner can take it from our HELLO.
                            let our_assigned_slot: Option<u64> = if st.mesh.spiral.is_claimed() {
                                let occupied = st.mesh.spiral.all_occupied();
                                let mut slot = 0u64;
                                loop {
                                    if !occupied.iter().any(|(_, idx)| idx.value() == slot) {
                                        break Some(slot);
                                    }
                                    slot += 1;
                                }
                            } else {
                                None
                            };

                            let our_hello = serde_json::json!({
                                "peer_id": st.lens.peer_id,
                                "server_name": st.lens.server_name,
                                "public_key_hex": st.lens.public_key_hex,
                                "spiral_index": st.lens.spiral_index,
                                "vdf_genesis": our_vdf_genesis,
                                "vdf_hash": our_vdf_hash,
                                "vdf_step": our_vdf_step,
                                "vdf_resonance_credit": our_vdf_credit,
                                "vdf_actual_rate_hz": our_vdf_rate,
                                "vdf_cumulative_credit": our_vdf_rolling,
                                "yggdrasil_addr": our_ygg_addr,
                                "ygg_peer_uri": our_ygg_peer_uri,
                                "site_name": st.lens.site_name,
                                "node_name": st.lens.node_name,
                                "assigned_slot": our_assigned_slot,
                                "cluster_chain_value": st.mesh.cluster_chain.as_ref().map(|cc| cc.value_hex()),
                                "cluster_chain_round": st.mesh.cluster_chain.as_ref().map(|cc| cc.round),
                            });

                            // Collect peer list for MESH PEERS exchange.
                            let peers_list: Vec<MeshPeerInfo> =
                                st.mesh.known_peers.values().cloned().collect();

                            // Prepare LATENCY_HAVE payload while we still hold the read lock.
                            let spore_bytes = bincode::serialize(st.mesh.proof_store.spore())
                                .unwrap_or_default();
                            let sync_msg = super::latency_gossip::SyncMessage::HaveList {
                                spore_bytes,
                            };
                            let latency_have_b64 = base64::engine::general_purpose::STANDARD
                                .encode(bincode::serialize(&sync_msg).unwrap_or_default());

                            drop(st);

                            let reply = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "MESH".into(),
                                params: vec!["HELLO".into(), our_hello.to_string()],
                            };
                            framed.send(reply).await?;

                            // Send MESH PEERS — share our known peer list.
                            if !peers_list.is_empty() {
                                if let Ok(peers_json) = serde_json::to_string(&peers_list) {
                                    let peers_msg = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "MESH".into(),
                                        params: vec!["PEERS".into(), peers_json],
                                    };
                                    framed.send(peers_msg).await?;
                                }
                            }

                            // Send MESH LATENCY_HAVE — our proof SPORE for delta sync.
                            // (replaces monolithic MESH TOPOLOGY which overflows at 10+ nodes)
                            let have_msg = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "MESH".into(),
                                params: vec!["LATENCY_HAVE".into(), latency_have_b64],
                            };
                            framed.send(have_msg).await?;
                        }
                    }
                    "PEERS" => {
                        if let Ok(peers) =
                            serde_json::from_str::<Vec<MeshPeerInfo>>(json)
                        {
                            let _ = st.federation_event_tx.send(
                                federation::RelayEvent::MeshPeers {
                                    remote_host: nick.to_owned(),
                                    peers,
                                },
                            );
                        }
                    }
                    "TOPOLOGY" => {
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::MeshTopology {
                                remote_host: nick.to_owned(),
                                json: json.clone(),
                            },
                        );
                    }
                    "GOSSIP" => {
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::GossipReceive {
                                remote_host: nick.to_owned(),
                                message_json: json.clone(),
                            },
                        );
                    }
                    "GOSSIP_SPORE" => {
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::GossipSpore {
                                remote_host: nick.to_owned(),
                                spore_json: json.clone(),
                            },
                        );
                    }
                    "GOSSIP_DIFF" => {
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::GossipDiff {
                                remote_host: nick.to_owned(),
                                messages_json: json.clone(),
                            },
                        );
                    }
                    "LATENCY_HAVE" => {
                        // Resolve nick → node_name (strip ~relay suffix).
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::LatencyHaveList {
                                remote_host: node_name,
                                payload_b64: json.clone(),
                            },
                        );
                    }
                    "LATENCY_DELTA" => {
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::LatencyProofDelta {
                                remote_host: node_name,
                                payload_b64: json.clone(),
                            },
                        );
                    }
                    "PROFILE_QUERY" => {
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                            if let Some(username) = v.get("username").and_then(|u| u.as_str()) {
                                let _ = st.federation_event_tx.send(
                                    federation::RelayEvent::ProfileQuery {
                                        remote_host: node_name,
                                        username: username.to_string(),
                                    },
                                );
                            }
                        }
                    }
                    "PROFILE_RESPONSE" => {
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                            let username = v.get("username")
                                .and_then(|u| u.as_str())
                                .unwrap_or_default()
                                .to_string();
                            let profile = v.get("profile")
                                .and_then(|p| serde_json::from_value(p.clone()).ok());
                            let _ = st.federation_event_tx.send(
                                federation::RelayEvent::ProfileResponse {
                                    remote_host: node_name,
                                    username,
                                    profile,
                                },
                            );
                        }
                    }
                    "PROFILE_HAVE" => {
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::ProfileHave {
                                remote_host: node_name,
                                payload_b64: json.to_string(),
                            },
                        );
                    }
                    "PROFILE_DELTA" => {
                        let node_name = nick.strip_suffix("~relay")
                            .unwrap_or(nick).to_owned();
                        let _ = st.federation_event_tx.send(
                            federation::RelayEvent::ProfileDelta {
                                remote_host: node_name,
                                payload_b64: json.to_string(),
                            },
                        );
                    }
                    _ => {}
                }
            }
        }

        // INVITE — invite code management commands.
        "INVITE" => {
            // Disambiguate: if params[1] starts with # or &, it's standard IRC INVITE.
            // Otherwise, fall through to the Lagoon invite subcommand system.
            let is_irc_invite = msg.params.get(1)
                .is_some_and(|p| p.starts_with('#') || p.starts_with('&'));

            if is_irc_invite {
                // Standard IRC INVITE: INVITE <nick> <#channel>
                let target_nick = &msg.params[0];
                let raw_channel = &msg.params[1];
                let channel = irc_lower(raw_channel);
                let nick_key = irc_lower(nick);
                let target_key = irc_lower(target_nick);

                let st = state.read().await;

                // 442: sender must be in channel.
                let in_channel = st.channels.get(&channel)
                    .is_some_and(|m| m.contains_key(&nick_key));
                if !in_channel {
                    drop(st);
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "442".into(),
                        params: vec![nick.into(), channel.clone(), "You're not on that channel".into()],
                    };
                    framed.send(err).await?;
                } else {
                    // 482: if +i, sender must be Op+.
                    let invite_only = st.channel_modes.get(&channel)
                        .is_some_and(|m| m.invite_only);
                    let sender_prefix = st.channels.get(&channel)
                        .and_then(|m| m.get(&nick_key).copied())
                        .unwrap_or(MemberPrefix::Normal);

                    if invite_only && sender_prefix < MemberPrefix::Op {
                        drop(st);
                        let err = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "482".into(),
                            params: vec![nick.into(), channel.clone(), "You're not channel operator".into()],
                        };
                        framed.send(err).await?;
                    } else {
                        // 443: target must not already be in channel.
                        let target_in_channel = st.channels.get(&channel)
                            .is_some_and(|m| m.contains_key(&target_key));
                        if target_in_channel {
                            drop(st);
                            let err = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "443".into(),
                                params: vec![nick.into(), target_nick.clone(), channel.clone(), "is already on channel".into()],
                            };
                            framed.send(err).await?;
                        } else if let Some(target_handle) = st.clients.get(&target_key) {
                            // Send INVITE to target.
                            let invite_msg = Message {
                                prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                command: "INVITE".into(),
                                params: vec![target_handle.nick.clone(), channel.clone()],
                            };
                            let _ = target_handle.tx.send(invite_msg);
                            drop(st);

                            // Track in channel_invites.
                            let mut st = state.write().await;
                            st.channel_invites
                                .entry(channel.clone())
                                .or_default()
                                .insert(target_key);

                            // 341 RPL_INVITING to sender.
                            drop(st);
                            let r341 = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "341".into(),
                                params: vec![nick.into(), target_nick.clone(), channel],
                            };
                            framed.send(r341).await?;
                        } else {
                            drop(st);
                            // 401: target doesn't exist.
                            let err = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "401".into(),
                                params: vec![nick.into(), target_nick.clone(), "No such nick/channel".into()],
                            };
                            framed.send(err).await?;
                        }
                    }
                }
            } else if let Some(sub_cmd) = msg.params.first() {
                match sub_cmd.to_uppercase().as_str() {
                    "CREATE" => {
                        // INVITE CREATE <kind> <target> [privileges] [max_uses] [expires]
                        if msg.params.len() >= 3 {
                            let kind_str = &msg.params[1];
                            let target = &msg.params[2];
                            let kind = match kind_str.to_lowercase().as_str() {
                                "community" | "communitylink" => {
                                    super::invite::InviteKind::CommunityLink
                                }
                                "peering" | "serverpeering" => {
                                    super::invite::InviteKind::ServerPeering
                                }
                                _ => {
                                    let err = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            "Unknown invite kind. Use: community, peering"
                                                .into(),
                                        ],
                                    };
                                    framed.send(err).await?;
                                    return Ok(CommandResult::Ok);
                                }
                            };

                            let privileges: Vec<super::invite::Privilege> = msg
                                .params
                                .get(3)
                                .map(|p| {
                                    p.split(',')
                                        .filter_map(|s| s.parse().ok())
                                        .collect()
                                })
                                .unwrap_or_else(|| {
                                    vec![
                                        super::invite::Privilege::Read,
                                        super::invite::Privilege::Write,
                                    ]
                                });

                            let max_uses: Option<u32> = msg
                                .params
                                .get(4)
                                .and_then(|s| s.parse().ok());

                            let expires_at: Option<chrono::DateTime<chrono::Utc>> = msg
                                .params
                                .get(5)
                                .and_then(|s| s.parse().ok());

                            let mut st = state.write().await;
                            let creator_peer_id = st.lens.peer_id.clone();
                            let invite = st.invites.create(
                                kind,
                                creator_peer_id,
                                target.clone(),
                                privileges,
                                max_uses,
                                expires_at,
                            );
                            let reply = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "NOTICE".into(),
                                params: vec![
                                    nick.into(),
                                    format!(
                                        "Invite code created: {} (target: {}, uses: {}/{})",
                                        invite.code,
                                        invite.target,
                                        invite.uses,
                                        invite
                                            .max_uses
                                            .map(|m| m.to_string())
                                            .unwrap_or_else(|| "unlimited".into()),
                                    ),
                                ],
                            };
                            framed.send(reply).await?;
                        }
                    }
                    "USE" => {
                        if let Some(code) = msg.params.get(1) {
                            let mut st = state.write().await;
                            match st.invites.use_code(code) {
                                Ok(invite) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!(
                                                "Invite code used: {} (target: {})",
                                                invite.code, invite.target
                                            ),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                                Err(e) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Invite code error: {e}"),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                            }
                        }
                    }
                    "LIST" => {
                        let filter = msg.params.get(1).map(|s| s.as_str());
                        let st = state.read().await;
                        let invites = st.invites.list(filter);
                        if invites.is_empty() {
                            let reply = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "NOTICE".into(),
                                params: vec![nick.into(), "No invite codes found.".into()],
                            };
                            framed.send(reply).await?;
                        } else {
                            for inv in invites {
                                let reply = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "NOTICE".into(),
                                    params: vec![
                                        nick.into(),
                                        format!(
                                            "[{}] target={} uses={}/{} active={} expires={}",
                                            inv.code,
                                            inv.target,
                                            inv.uses,
                                            inv.max_uses
                                                .map(|m| m.to_string())
                                                .unwrap_or_else(|| "unlimited".into()),
                                            inv.active,
                                            inv.expires_at
                                                .map(|e| e.to_rfc3339())
                                                .unwrap_or_else(|| "never".into()),
                                        ),
                                    ],
                                };
                                framed.send(reply).await?;
                            }
                        }
                    }
                    "MODIFY" => {
                        // INVITE MODIFY <code> <field> <value>
                        if msg.params.len() >= 4 {
                            let code = &msg.params[1];
                            let field = &msg.params[2];
                            let value = &msg.params[3];
                            let mut st = state.write().await;
                            let result = match field.to_lowercase().as_str() {
                                "privileges" => {
                                    let privs: Vec<super::invite::Privilege> = value
                                        .split(',')
                                        .filter_map(|s| s.parse().ok())
                                        .collect();
                                    st.invites.modify(code, Some(privs), None, None)
                                }
                                "max_uses" => {
                                    let max: Option<u32> = value.parse().ok();
                                    st.invites.modify(code, None, Some(max), None)
                                }
                                "expires" => {
                                    let exp: Option<chrono::DateTime<chrono::Utc>> =
                                        value.parse().ok();
                                    st.invites.modify(code, None, None, Some(exp))
                                }
                                _ => Err("Unknown field. Use: privileges, max_uses, expires"
                                    .to_string()),
                            };
                            match result {
                                Ok(inv) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Invite {} modified.", inv.code),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                                Err(e) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Modify error: {e}"),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                            }
                        }
                    }
                    "REVOKE" => {
                        if let Some(code) = msg.params.get(1) {
                            let mut st = state.write().await;
                            match st.invites.revoke(code) {
                                Ok(()) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Invite {code} revoked."),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                                Err(e) => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Revoke error: {e}"),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                            }
                        }
                    }
                    "INFO" => {
                        if let Some(code) = msg.params.get(1) {
                            let st = state.read().await;
                            match st.invites.get(code) {
                                Some(inv) => {
                                    let privs: Vec<String> = inv
                                        .privileges
                                        .iter()
                                        .map(|p| p.to_string())
                                        .collect();
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!(
                                                "Invite {}: kind={:?} target={} privileges=[{}] uses={}/{} active={} created={} expires={}",
                                                inv.code,
                                                inv.kind,
                                                inv.target,
                                                privs.join(","),
                                                inv.uses,
                                                inv.max_uses.map(|m| m.to_string()).unwrap_or_else(|| "unlimited".into()),
                                                inv.active,
                                                inv.created_at.to_rfc3339(),
                                                inv.expires_at.map(|e| e.to_rfc3339()).unwrap_or_else(|| "never".into()),
                                            ),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                                None => {
                                    let reply = Message {
                                        prefix: Some(SERVER_NAME.clone()),
                                        command: "NOTICE".into(),
                                        params: vec![
                                            nick.into(),
                                            format!("Unknown invite code: {code}"),
                                        ],
                                    };
                                    framed.send(reply).await?;
                                }
                            }
                        }
                    }
                    _ => {
                        let reply = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "NOTICE".into(),
                            params: vec![
                                nick.into(),
                                "Usage: INVITE CREATE|USE|LIST|MODIFY|REVOKE|INFO".into(),
                            ],
                        };
                        framed.send(reply).await?;
                    }
                }
            }
        }

        // DEFEDERATE — block a peer by LensID or server name.
        "DEFEDERATE" => {
            if let Some(target) = msg.params.first() {
                let mut st = state.write().await;
                st.mesh.defederated.insert(target.clone());

                // Disconnect active relay if any.
                let mut to_remove = Vec::new();
                for (host, relay) in &st.federation.relays {
                    if host == target {
                        let _ = relay.outgoing_tx.send(federation::RelayCommand::Shutdown);
                        to_remove.push(host.clone());
                    }
                }
                // Also check by mesh_key in known_peers.
                // Relays are keyed by peer_id (mkey), not node_name.
                let mut connection_ids_to_remove = Vec::new();
                for (mkey, peer_info) in &st.mesh.known_peers {
                    if mkey == target || peer_info.server_name == *target
                        || peer_info.node_name == *target
                        || peer_info.peer_id == *target
                    {
                        if let Some(relay) = st.federation.relays.get(mkey) {
                            let _ = relay.outgoing_tx.send(federation::RelayCommand::Shutdown);
                            to_remove.push(mkey.clone());
                        }
                        connection_ids_to_remove.push(mkey.clone());
                    }
                }
                for key in &to_remove {
                    st.federation.relays.remove(key);
                }
                for id in &connection_ids_to_remove {
                    st.mesh.connections.remove(id);
                }

                // Persist defederated set.
                let defed_path = st.data_dir.join("defederated.json");
                if let Ok(json) = serde_json::to_string_pretty(&st.mesh.defederated) {
                    let _ = std::fs::write(&defed_path, json);
                }

                st.notify_topology_change();
                drop(st);

                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "NOTICE".into(),
                    params: vec![
                        nick.into(),
                        format!("Defederated: {target}"),
                    ],
                };
                framed.send(reply).await?;
            }
        }

        // REFEDERATE — unblock a previously defederated peer.
        "REFEDERATE" => {
            if let Some(target) = msg.params.first() {
                let mut st = state.write().await;
                let removed = st.mesh.defederated.remove(target);

                if removed {
                    // Persist defederated set.
                    let defed_path = st.data_dir.join("defederated.json");
                    if let Ok(json) = serde_json::to_string_pretty(&st.mesh.defederated) {
                        let _ = std::fs::write(&defed_path, json);
                    }
                    st.notify_topology_change();
                    drop(st);

                    let reply = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "NOTICE".into(),
                        params: vec![
                            nick.into(),
                            format!("Refederated: {target}"),
                        ],
                    };
                    framed.send(reply).await?;
                } else {
                    drop(st);
                    let reply = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "NOTICE".into(),
                        params: vec![
                            nick.into(),
                            format!("{target} was not defederated."),
                        ],
                    };
                    framed.send(reply).await?;
                }
            }
        }

        "LUSERS" => {
            let st = state.read().await;
            let total_users = st.clients.len();
            let total_channels = st.channels.len();
            let mesh_peers = st.mesh.connections.values()
                .filter(|s| **s == MeshConnectionState::Connected)
                .count();
            drop(st);

            // 251 RPL_LUSERCLIENT
            let r251 = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "251".into(),
                params: vec![
                    nick.into(),
                    format!("There are {total_users} users and 0 invisible on {servers} servers",
                        servers = mesh_peers + 1),
                ],
            };
            framed.send(r251).await?;

            // 252 RPL_LUSEROP
            let r252 = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "252".into(),
                params: vec![nick.into(), "0".into(), "operator(s) online".into()],
            };
            framed.send(r252).await?;

            // 254 RPL_LUSERCHANNELS
            let r254 = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "254".into(),
                params: vec![nick.into(), total_channels.to_string(), "channels formed".into()],
            };
            framed.send(r254).await?;

            // 255 RPL_LUSERME
            let r255 = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "255".into(),
                params: vec![
                    nick.into(),
                    format!("I have {total_users} clients and {mesh_peers} servers"),
                ],
            };
            framed.send(r255).await?;
        }

        "AWAY" => {
            if let Some(away_text) = msg.params.first().filter(|t| !t.is_empty()) {
                // Set away (enforce AWAYLEN=200).
                let truncated: String = away_text.chars().take(200).collect();
                let nick_key = irc_lower(nick);
                let mut st = state.write().await;
                if let Some(handle) = st.clients.get_mut(&nick_key) {
                    handle.away_message = Some(truncated);
                }
                drop(st);
                // 306 RPL_NOWAWAY
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "306".into(),
                    params: vec![nick.into(), "You have been marked as being away".into()],
                };
                framed.send(reply).await?;
            } else {
                // Unset away.
                let nick_key = irc_lower(nick);
                let mut st = state.write().await;
                if let Some(handle) = st.clients.get_mut(&nick_key) {
                    handle.away_message = None;
                }
                drop(st);
                // 305 RPL_UNAWAY
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "305".into(),
                    params: vec![nick.into(), "You are no longer marked as being away".into()],
                };
                framed.send(reply).await?;
            }
        }

        "WHOWAS" => {
            if let Some(target_nick) = msg.params.first() {
                let st = state.read().await;
                let entries = st.whowas.lookup(target_nick);
                if entries.is_empty() {
                    drop(st);
                    // 406 ERR_WASNOSUCHNICK
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "406".into(),
                        params: vec![nick.into(), target_nick.clone(), "There was no such nickname".into()],
                    };
                    framed.send(err).await?;
                } else {
                    // Send up to 5 most recent entries.
                    let to_send: Vec<_> = entries.into_iter().take(5).map(|e| {
                        (e.nick.clone(), e.user.clone(), e.host.clone(), e.realname.clone())
                    }).collect();
                    drop(st);
                    for (e_nick, e_user, e_host, e_realname) in to_send {
                        // 314 RPL_WHOWASUSER
                        let r314 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "314".into(),
                            params: vec![
                                nick.into(),
                                e_nick,
                                e_user,
                                e_host,
                                "*".into(),
                                e_realname,
                            ],
                        };
                        framed.send(r314).await?;
                    }
                }
                // 369 RPL_ENDOFWHOWAS (always sent)
                let end = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "369".into(),
                    params: vec![nick.into(), target_nick.clone(), "End of WHOWAS".into()],
                };
                framed.send(end).await?;
            }
        }

        "QUIT" => {
            let reason = msg.params.first().cloned().unwrap_or_else(|| "Client Quit".into());
            return Ok(CommandResult::Quit(reason));
        }

        other => {
            warn!(nick, command = other, "unknown command");
            let err = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "421".into(),
                params: vec![nick.into(), other.into(), "Unknown command".into()],
            };
            framed.send(err).await?;
        }
    }

    Ok(CommandResult::Ok)
}

/// Broadcast a message to a list of nicks via their channel handles.
pub fn broadcast(state: &ServerState, nicks: &[String], msg: &Message) {
    for nick in nicks {
        if let Some(handle) = state.clients.get(nick) {
            let _ = handle.tx.send(msg.clone());
        }
    }
}

/// Clean up when a client disconnects.
async fn cleanup_client(nick: &str, reason: &str, state: &SharedState) {
    let nick_key = irc_lower(nick);
    let mut st = state.write().await;

    // Relay nicks are invisible — suppress QUIT broadcast.
    if !federation::is_relay_nick(nick) {
        let quit_msg = Message {
            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
            command: "QUIT".into(),
            params: vec![reason.to_owned()],
        };

        let mut notified: HashSet<String> = HashSet::new();
        for (_channel, members) in st.channels.iter() {
            if members.contains_key(&nick_key) {
                for member in members.keys() {
                    if *member != nick_key && !notified.contains(member) {
                        if let Some(handle) = st.clients.get(member) {
                            let _ = handle.tx.send(quit_msg.clone());
                        }
                        notified.insert(member.clone());
                    }
                }
            }
        }
    }

    // Remove from all local channels; clean up modes/bans/invites for emptied channels.
    let mut emptied_channels = Vec::new();
    st.channels.retain(|name, members| {
        members.remove(&nick_key);
        if members.is_empty() {
            emptied_channels.push(name.clone());
            false
        } else {
            true
        }
    });
    for ch in &emptied_channels {
        st.channel_modes.remove(ch);
        st.channel_bans.remove(ch);
        st.channel_invites.remove(ch);
        st.mesh.gossip.unsubscribe_cluster_channel(ch);
    }

    // Remove from all federated channels. Shut down relays with no channels left.
    let mut empty_relays = Vec::new();
    for (host, relay) in st.federation.relays.iter_mut() {
        let mut empty_channels = Vec::new();
        for (local_ch, fed_ch) in relay.channels.iter_mut() {
            if fed_ch.local_users.remove(&nick_key) {
                let _ = relay.outgoing_tx.send(federation::RelayCommand::Part {
                    nick: nick.to_owned(),
                    remote_channel: fed_ch.remote_channel.clone(),
                    reason: reason.to_owned(),
                });
                if fed_ch.local_users.is_empty() {
                    let _ = relay.outgoing_tx.send(
                        federation::RelayCommand::PartChannel {
                            remote_channel: fed_ch.remote_channel.clone(),
                        },
                    );
                    empty_channels.push(local_ch.clone());
                }
            }
        }
        for ch in empty_channels {
            relay.channels.remove(&ch);
        }
        if relay.channels.is_empty() && !relay.mesh_connected {
            let _ = relay.outgoing_tx.send(federation::RelayCommand::Shutdown);
            empty_relays.push(host.clone());
        }
    }
    for host in empty_relays {
        // Shutdown already sent above; removing drops the channel → task exits.
        st.federation.relays.remove(&host);
    }

    // Record WHOWAS entry before removing.
    let whowas_entry = st.clients.get(&nick_key).map(|handle| {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        modes::WhowasEntry {
            nick: handle.nick.clone(),
            user: handle.user.clone().unwrap_or_default(),
            host: SERVER_NAME.clone(),
            realname: handle.realname.clone().unwrap_or_default(),
            disconnect_time: now,
        }
    });
    if let Some(entry) = whowas_entry {
        st.whowas.push(entry);
    }

    // Remove from clients.
    st.clients.remove(&nick_key);

    // Remove from web client tracking if applicable.
    if st.mesh.web_clients.remove(&nick_key) {
        st.notify_topology_change();
    }

    info!(nick, "cleaned up");
}
