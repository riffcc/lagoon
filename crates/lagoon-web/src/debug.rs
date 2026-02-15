/// Debug API endpoints — comprehensive mesh introspection.
///
/// These endpoints expose the raw internal state of each node's mesh view,
/// federation relay connections, Yggdrasil overlay peers, and gossip state.
/// Designed for operational debugging of the anycast mesh deployment.
use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use lagoon_server::irc::server::MeshConnectionState;

use crate::state::AppState;

// ── Response types ───────────────────────────────────────────────────

/// Top-level debug report for this node's complete mesh view.
#[derive(Serialize)]
pub struct DebugMeshReport {
    /// This node's identity.
    pub identity: NodeIdentity,
    /// VDF engine state and resonance curve metrics.
    pub vdf: Option<VdfReport>,
    /// All federation relay connections (IRC layer).
    pub relays: Vec<RelayReport>,
    /// All known mesh peers and their connection state.
    pub peers: Vec<PeerReport>,
    /// SPIRAL topology view (our neighbors + full occupancy map).
    pub spiral: SpiralReport,
    /// Yggdrasil overlay peers (live from admin socket).
    pub ygg_peers: Vec<YggPeerReport>,
    /// Gossip subsystem stats.
    pub gossip: GossipReport,
    /// Yggdrasil metrics cache.
    pub ygg_metrics: Vec<YggMetricsReport>,
    /// Runtime health metrics.
    pub runtime: RuntimeReport,
}

/// This node's identity information.
#[derive(Serialize)]
pub struct NodeIdentity {
    pub node_name: String,
    pub site_name: String,
    pub server_name: String,
    pub mesh_key: String,
    pub peer_id: String,
    pub ygg_addr: Option<String>,
    /// Our Yggdrasil peer URI — what other nodes use to APE-peer with us.
    pub ygg_peer_uri: Option<String>,
    /// Our claimed SPIRAL slot.
    pub spiral_index: Option<u64>,
}

/// A single federation relay connection.
#[derive(Serialize)]
pub struct RelayReport {
    /// The relay map key (peer_id).
    pub relay_key: String,
    /// Human-readable node name.
    pub node_name: String,
    /// The host:port used to reach this peer.
    pub connect_target: String,
    /// Whether this relay was created by the mesh connector.
    pub mesh_connected: bool,
    /// Whether this relay was created from LAGOON_PEERS (bootstrap).
    pub is_bootstrap: bool,
    /// Last IRC-layer PING/PONG round-trip time in ms.
    pub last_rtt_ms: Option<f64>,
    /// Channels active on this relay.
    pub channels: Vec<RelayChannelReport>,
}

/// A channel on a relay connection.
#[derive(Serialize)]
pub struct RelayChannelReport {
    pub local_channel: String,
    pub remote_channel: String,
    pub local_users: usize,
    pub remote_users: usize,
}

/// A known mesh peer.
#[derive(Serialize)]
pub struct PeerReport {
    pub mesh_key: String,
    pub peer_id: String,
    pub server_name: String,
    pub node_name: String,
    pub site_name: String,
    pub connection_state: String,
    pub ygg_addr: Option<String>,
    pub last_seen: u64,
    pub port: u16,
    pub tls: bool,
    /// Whether any relay connection exists for this peer.
    pub has_relay: bool,
    /// The relay key used for this peer's connection (if any).
    pub relay_key: Option<String>,
    /// Peer's resonance credit [0, 1] (from last MESH HELLO).
    pub vdf_resonance_credit: Option<f64>,
    /// Peer's actual VDF tick rate in Hz (from last MESH HELLO).
    pub vdf_actual_rate_hz: Option<f64>,
    /// Rolling resonance credit (last 3 cycles) — used for SPIRAL collision resolution.
    pub vdf_cumulative_credit: Option<f64>,
    /// Peer's Yggdrasil peer URI for APE overlay peering.
    pub ygg_peer_uri: Option<String>,
    /// Peer's claimed SPIRAL slot (from HELLO/gossip).
    pub spiral_index: Option<u64>,
}

/// A Yggdrasil overlay peer (live from admin socket query).
#[derive(Serialize)]
pub struct YggPeerReport {
    pub address: String,
    pub remote: String,
    pub key: String,
    pub up: bool,
    pub inbound: bool,
    pub latency_ms: f64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
    pub uptime: f64,
}

/// Cached Yggdrasil metrics for a peer.
#[derive(Serialize)]
pub struct YggMetricsReport {
    pub address: String,
    pub upload_bps: f64,
    pub download_bps: f64,
    pub latency_ms: f64,
}

/// SPIRAL topology view for this node.
#[derive(Serialize)]
pub struct SpiralReport {
    /// Our SPIRAL neighbors (peer_ids).
    pub neighbors: Vec<String>,
    /// Full occupancy map: slot -> peer_id.
    pub occupied_slots: Vec<SpiralSlotReport>,
}

/// A single SPIRAL slot assignment.
#[derive(Serialize)]
pub struct SpiralSlotReport {
    pub slot: u64,
    pub peer_id: String,
}

/// Gossip subsystem statistics.
#[derive(Serialize)]
pub struct GossipReport {
    /// Number of cached gossip messages (for SPORE diff catch-up).
    pub cache_size: usize,
    /// Our SPORE sender identity (hex).
    pub sender_id: String,
}

/// VDF engine state and resonance curve metrics.
#[derive(Serialize)]
pub struct VdfReport {
    /// Genesis hash (hex-encoded).
    pub genesis: String,
    /// Current chain tip hash (hex-encoded).
    pub current_hash: String,
    /// Steps computed in this session.
    pub session_steps: u64,
    /// Cumulative steps across all sessions.
    pub total_steps: u64,
    /// Resonance curve metrics (None until 2+ ticks measured).
    pub resonance: Option<ResonanceReport>,
}

/// Resonance curve metrics for the debug endpoint.
#[derive(Serialize)]
pub struct ResonanceReport {
    /// Target tick rate (Hz).
    pub target_rate_hz: f64,
    /// Actual measured tick rate — exponential moving average (Hz).
    pub actual_rate_hz: f64,
    /// Current resonance credit [0, 1] — 1.0 = perfect precision.
    pub credit: f64,
    /// Gaussian sigma parameter (Hz).
    pub sigma: f64,
    /// Last measured tick interval (seconds).
    pub last_interval_secs: f64,
    /// Deviation from target (Hz). Positive = running fast.
    pub deviation_hz: f64,
    /// Cumulative credit earned since boot.
    pub cumulative_credit: f64,
    /// Average credit per tick (cumulative / measured_ticks).
    pub average_credit: f64,
    /// Number of ticks with timing data.
    pub measured_ticks: u64,
}

/// Runtime health metrics for diagnosing leaks.
#[derive(Serialize)]
pub struct RuntimeReport {
    /// Reserved (was: goroutine count from Go yggbridge, now pure Rust).
    pub go_goroutines: i32,
    /// Number of relay tasks currently in-flight (spawned, not yet HELLO'd).
    pub pending_dials: usize,
    /// Number of active relay connections (post-HELLO).
    pub active_relays: usize,
    /// Total relay tasks alive (including backoff between reconnects).
    pub active_dial_count: usize,
}

// ── Handlers ─────────────────────────────────────────────────────────

/// GET /api/debug/mesh — comprehensive mesh debug view.
///
/// Returns this node's complete internal state: identity, relay connections,
/// known peers, Yggdrasil overlay peers, and gossip stats. Each node in the
/// mesh exposes this independently — compare responses from different nodes
/// to diagnose connectivity issues.
pub async fn get_debug_mesh(
    State(state): State<AppState>,
) -> Result<Json<DebugMeshReport>, StatusCode> {
    let irc_state = state
        .irc_state
        .as_ref()
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let st = irc_state.read().await;

    // ── Identity ──
    let ygg_addr = st
        .transport_config
        .ygg_node
        .as_ref()
        .map(|n| n.address().to_string())
        .or_else(|| {
            lagoon_server::irc::transport::detect_yggdrasil_addr().map(|a| a.to_string())
        });
    let ygg_peer_uri = lagoon_server::irc::transport::detect_underlay_addr().map(|addr| match addr {
        std::net::IpAddr::V6(v6) => format!("tcp://[{v6}]:9443"),
        std::net::IpAddr::V4(v4) => format!("tcp://{v4}:9443"),
    });
    let identity = NodeIdentity {
        node_name: st.lens.node_name.clone(),
        site_name: st.lens.site_name.clone(),
        server_name: st.lens.server_name.clone(),
        mesh_key: st.lens.peer_id.clone(),
        peer_id: st.lens.peer_id.clone(),
        ygg_addr,
        ygg_peer_uri,
        spiral_index: st.lens.spiral_index,
    };

    // ── Relays ──
    let relays: Vec<RelayReport> = st
        .federation
        .relays
        .iter()
        .map(|(key, handle)| {
            let channels: Vec<RelayChannelReport> = handle
                .channels
                .iter()
                .map(|(local_ch, fed_ch)| RelayChannelReport {
                    local_channel: local_ch.clone(),
                    remote_channel: fed_ch.remote_channel.clone(),
                    local_users: fed_ch.local_users.len(),
                    remote_users: fed_ch.remote_users.len(),
                })
                .collect();
            RelayReport {
                relay_key: key.clone(),
                node_name: handle.node_name.clone(),
                connect_target: handle.connect_target.clone(),
                mesh_connected: handle.mesh_connected,
                is_bootstrap: handle.is_bootstrap,
                last_rtt_ms: handle.last_rtt_ms,
                channels,
            }
        })
        .collect();

    // ── Known peers ──
    let peers: Vec<PeerReport> = st
        .mesh
        .known_peers
        .iter()
        .map(|(mkey, info)| {
            let conn_state = st
                .mesh
                .connections
                .get(mkey)
                .copied()
                .unwrap_or(MeshConnectionState::Known);
            let connection_state = match conn_state {
                MeshConnectionState::Known => "known",
                MeshConnectionState::Connected => "connected",
            }
            .to_string();

            // Relay key IS peer_id — direct lookup.
            let relay_key = if st.federation.relays.contains_key(mkey) {
                Some(mkey.clone())
            } else {
                None
            };

            PeerReport {
                mesh_key: mkey.clone(),
                peer_id: info.peer_id.clone(),
                server_name: info.server_name.clone(),
                node_name: info.node_name.clone(),
                site_name: info.site_name.clone(),
                connection_state,
                ygg_addr: info.yggdrasil_addr.clone(),
                last_seen: info.last_seen,
                port: info.port,
                tls: info.tls,
                has_relay: relay_key.is_some(),
                relay_key,
                vdf_resonance_credit: info.vdf_resonance_credit,
                vdf_actual_rate_hz: info.vdf_actual_rate_hz,
                vdf_cumulative_credit: info.vdf_cumulative_credit,
                ygg_peer_uri: info.ygg_peer_uri.clone(),
                spiral_index: info.spiral_index,
            }
        })
        .collect();

    // ── VDF + resonance ──
    let vdf = st.mesh.vdf_state_rx.as_ref().map(|rx| {
        let vdf = rx.borrow();
        VdfReport {
            genesis: hex::encode(vdf.genesis),
            current_hash: hex::encode(vdf.current_hash),
            session_steps: vdf.session_steps,
            total_steps: vdf.total_steps,
            resonance: vdf.resonance.as_ref().map(|r| ResonanceReport {
                target_rate_hz: r.target_rate_hz,
                actual_rate_hz: r.actual_rate_hz,
                credit: r.credit,
                sigma: r.sigma,
                last_interval_secs: r.last_interval_secs,
                deviation_hz: r.deviation_hz,
                cumulative_credit: r.cumulative_credit,
                average_credit: if r.measured_ticks > 0 {
                    r.cumulative_credit / r.measured_ticks as f64
                } else {
                    0.0
                },
                measured_ticks: r.measured_ticks,
            }),
        }
    });

    // ── Yggdrasil metrics cache ──
    let ygg_metrics: Vec<YggMetricsReport> = st
        .mesh
        .known_peers
        .values()
        .filter_map(|info| {
            info.yggdrasil_addr.as_ref().and_then(|addr| {
                st.mesh.ygg_metrics.get(addr).map(|m| YggMetricsReport {
                    address: m.address.clone(),
                    upload_bps: m.upload_bps,
                    download_bps: m.download_bps,
                    latency_ms: m.latency_ms,
                })
            })
        })
        .collect();

    // ── SPIRAL topology ──
    let spiral = SpiralReport {
        neighbors: st.mesh.spiral.all_neighbor_ids(),
        occupied_slots: st
            .mesh
            .spiral
            .occupied_slots()
            .into_iter()
            .map(|(slot, peer_id)| SpiralSlotReport { slot, peer_id })
            .collect(),
    };

    // ── Gossip stats ──
    let gossip = GossipReport {
        cache_size: st.mesh.gossip.cache_len(),
        sender_id: hex::encode(st.mesh.gossip.sender_id.to_be_bytes()),
    };

    // ── Runtime health ──
    let runtime = RuntimeReport {
        go_goroutines: 0, // No Go runtime — yggdrasil-rs is pure Rust
        pending_dials: st.federation.pending_dials.len(),
        active_relays: st.federation.relays.len(),
        active_dial_count: st.federation.active_dial_count,
    };

    // ── Live Yggdrasil peer query ──
    let ygg_node = st.transport_config.ygg_node.clone();
    drop(st);

    let ygg_peers = if let Some(ref node) = ygg_node {
        node.peers()
            .await
            .into_iter()
            .map(|p| YggPeerReport {
                address: p.addr.to_string(),
                remote: p.uri,
                key: hex::encode(p.key),
                up: true, // Connected peers are always up in yggdrasil-rs
                inbound: p.inbound,
                latency_ms: 0.0,
                bytes_sent: 0,
                bytes_recvd: 0,
                uptime: 0.0,
            })
            .collect()
    } else {
        Vec::new()
    };

    Ok(Json(DebugMeshReport {
        identity,
        vdf,
        relays,
        peers,
        spiral,
        ygg_peers,
        gossip,
        ygg_metrics,
        runtime,
    }))
}
