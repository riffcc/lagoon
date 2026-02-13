/// Channel federation — Matrix-style `#room:server` relay over Yggdrasil mesh.
///
/// When a user joins `#lagoon:per.lagun.co`, the local server connects to
/// `per.lagun.co:6667` as an IRC client, joins `#lagoon`, and relays messages
/// bidirectionally. One relay connection per remote host — multiple federated
/// channels to the same host share a single TCP connection.
///
/// Also handles MESH protocol for topology exchange between peers.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use futures::SinkExt;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::lens;
use super::message::Message;
use super::server::{broadcast, derive_node_name, MeshConnectionState, MeshPeerInfo, SharedState, NODE_NAME, SERVER_NAME, SITE_NAME};
use super::transport::{self, TransportConfig};
use super::wire::{MeshMessage, HelloPayload};
use base64::Engine as _;

/// Maximum disconnected peers retained per SITE_NAME before dedup eviction.
const MAX_DISCONNECTED_PER_SITE: usize = 5;

/// Build the Yggdrasil underlay peer URI for APE (Anycast Peer Entry).
///
/// Strategy: prefer the **underlay address** derived from the relay's TCP peer
/// address (confirmed-different node via MESH HELLO peer_id verification)
/// over the overlay address from `ygg_peer_uri`.
///
/// Why: The overlay address (`tcp://[200:xxxx::]:9443`) only works if we're
/// already ON the Ygg overlay.  For a fresh node bootstrapping via anycast,
/// we're NOT on the overlay yet.  But the relay already has a TCP connection
/// to a confirmed-different node — use that IP as the underlay Ygg peer.
///
/// Returns `None` if neither source is available.
pub fn ape_peer_uri(
    relay_peer_addr: Option<SocketAddr>,
    ygg_peer_uri: Option<&str>,
) -> Option<String> {
    // First try: underlay address from relay TCP peer (confirmed-different node).
    let underlay_uri = relay_peer_addr.map(|addr| {
        format!("tcp://[{}]:9443", addr.ip())
    });

    underlay_uri.or_else(|| ygg_peer_uri.map(|s| s.to_string()))
}

/// Dispatch a received `MeshMessage` into the appropriate `RelayEvent`.
///
/// Single code path for all mesh message processing — called from both
/// the inbound WebSocket handler and the outbound relay_task.
///
/// Returns the `HelloPayload` if the message was a Hello (needed by callers
/// to extract identity and set `remote_mesh_key`).
pub fn dispatch_mesh_message(
    msg: MeshMessage,
    remote_host: &str,
    relay_peer_addr: Option<SocketAddr>,
    remote_mesh_key: &Option<String>,
    event_tx: &mpsc::UnboundedSender<RelayEvent>,
) -> Option<HelloPayload> {
    match msg {
        MeshMessage::Hello(hello) => {
            let site_name = if hello.site_name.is_empty() {
                super::server::derive_site_name(&hello.server_name)
            } else {
                hello.site_name.clone()
            };
            let node_name = if hello.node_name.is_empty() {
                derive_node_name(&hello.server_name)
            } else {
                hello.node_name.clone()
            };
            let _ = event_tx.send(RelayEvent::MeshHello {
                remote_host: remote_host.to_string(),
                peer_id: hello.peer_id.clone(),
                server_name: hello.server_name.clone(),
                public_key_hex: hello.public_key_hex.clone(),
                spiral_index: hello.spiral_index,
                vdf_genesis: hello.vdf_genesis.clone(),
                vdf_hash: hello.vdf_hash.clone(),
                vdf_step: hello.vdf_step,
                yggdrasil_addr: hello.yggdrasil_addr.clone(),
                site_name,
                node_name,
                vdf_resonance_credit: hello.vdf_resonance_credit,
                vdf_actual_rate_hz: hello.vdf_actual_rate_hz,
                ygg_peer_uri: hello.ygg_peer_uri.clone(),
                relay_peer_addr,
            });
            Some(hello)
        }
        MeshMessage::Peers { peers } => {
            let _ = event_tx.send(RelayEvent::MeshPeers {
                remote_host: remote_host.to_string(),
                peers,
            });
            None
        }
        MeshMessage::VdfProofReq => {
            let _ = event_tx.send(RelayEvent::MeshVdfProofReq {
                remote_host: remote_host.to_string(),
            });
            None
        }
        MeshMessage::VdfProof { proof } => {
            let _ = event_tx.send(RelayEvent::MeshVdfProof {
                remote_host: remote_host.to_string(),
                proof_json: proof.to_string(),
                mesh_key: remote_mesh_key.clone(),
            });
            None
        }
        MeshMessage::Sync => {
            let _ = event_tx.send(RelayEvent::MeshSync {
                remote_host: remote_host.to_string(),
            });
            None
        }
        MeshMessage::Gossip { message } => {
            let _ = event_tx.send(RelayEvent::GossipReceive {
                remote_host: remote_host.to_string(),
                message_json: message.to_string(),
            });
            None
        }
        MeshMessage::GossipSpore { data } => {
            let _ = event_tx.send(RelayEvent::GossipSpore {
                remote_host: remote_host.to_string(),
                spore_json: data,
            });
            None
        }
        MeshMessage::GossipDiff { data } => {
            let _ = event_tx.send(RelayEvent::GossipDiff {
                remote_host: remote_host.to_string(),
                messages_json: data,
            });
            None
        }
        MeshMessage::LatencyHave { data } => {
            let _ = event_tx.send(RelayEvent::LatencyHaveList {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::LatencyDelta { data } => {
            let _ = event_tx.send(RelayEvent::LatencyProofDelta {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
    }
}

/// Prune relay connections to non-SPIRAL peers.
///
/// SPIRAL is the sole authority on which direct connections we maintain.
/// Non-neighbors are reachable transitively via Yggdrasil forwarding.
fn prune_non_spiral_relays(st: &mut super::server::ServerState) {
    if !st.mesh.spiral.is_claimed() {
        return;
    }

    let to_prune: Vec<String> = st.federation.relays.iter()
        .filter(|(_, handle)| {
            // Never prune bootstrap peers — they're the network backbone.
            if handle.is_bootstrap {
                return false;
            }
            let is_neighbor = st.mesh.known_peers.iter()
                .find(|(_, p)| p.node_name == handle.remote_host)
                .map(|(pid, _)| st.mesh.spiral.is_neighbor(pid))
                .unwrap_or(false);
            !is_neighbor
        })
        .map(|(key, _)| key.clone())
        .collect();

    for node_name in to_prune {
        if let Some(handle) = st.federation.relays.remove(&node_name) {
            info!(node = %node_name, "mesh: pruned non-SPIRAL relay");
            handle.task_handle.abort();
        }
    }
}

/// Evict excess disconnected peers per SITE_NAME, keeping the most recently
/// seen ones up to `MAX_DISCONNECTED_PER_SITE`. Returns evicted mesh keys.
fn dedup_peers_per_site(
    mesh: &mut super::server::MeshState,
    our_mesh_key: &str,
) -> Vec<String> {
    // Group disconnected mesh keys by site_name.
    let mut by_site: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for (mkey, peer) in mesh.known_peers.iter() {
        if mkey == our_mesh_key {
            continue;
        }
        let connected = mesh.connections.get(mkey).copied()
            == Some(MeshConnectionState::Connected);
        if connected {
            continue;
        }
        by_site
            .entry(peer.site_name.clone())
            .or_default()
            .push((mkey.clone(), peer.last_seen));
    }

    let mut evicted = Vec::new();
    for (_site, mut peers) in by_site {
        if peers.len() <= MAX_DISCONNECTED_PER_SITE {
            continue;
        }
        // Sort by last_seen descending — keep the freshest.
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        for (mkey, _) in peers.into_iter().skip(MAX_DISCONNECTED_PER_SITE) {
            if let Some(peer) = mesh.known_peers.remove(&mkey) {
                info!(
                    mesh_key = %mkey,
                    site_name = %peer.site_name,
                    last_seen = peer.last_seen,
                    "mesh: evicting excess disconnected peer for site dedup"
                );
                mesh.spiral.remove_peer(&mkey);
            }
            evicted.push(mkey);
        }
    }
    evicted
}

/// Check if a nick belongs to relay infrastructure.
///
/// Relay nicks follow the pattern `{prefix}~relay` with optional trailing
/// characters from nick collision resolution (e.g. `lon~relay_`).
pub fn is_relay_nick(nick: &str) -> bool {
    nick.contains("~relay")
}

/// Parse a federated channel name into (remote_channel, remote_host).
///
/// Returns `Some(("#lagoon", "per.lagun.co"))` for `"#lagoon:per.lagun.co"`.
/// Returns `None` for local channels (no colon) or invalid formats.
pub fn parse_federated_channel(channel: &str) -> Option<(&str, &str)> {
    if !channel.starts_with('#') && !channel.starts_with('&') {
        return None;
    }

    let colon_pos = channel[1..].find(':')?;
    let colon_pos = colon_pos + 1;

    let local_name = &channel[..colon_pos];
    let remote_host = &channel[colon_pos + 1..];

    if remote_host.is_empty() || !remote_host.contains('.') {
        return None;
    }

    if local_name.len() < 2 {
        return None;
    }

    Some((local_name, remote_host))
}

/// Per-channel state within a relay connection.
#[derive(Debug)]
pub struct FederatedChannel {
    /// The channel name on the remote server (e.g. "#lagoon").
    pub remote_channel: String,
    /// Local users subscribed to this federated channel.
    pub local_users: HashSet<String>,
    /// Remote users we know about from the remote channel.
    pub remote_users: HashSet<String>,
}

/// Handle for communicating with a running relay task.
#[derive(Debug)]
pub struct RelayHandle {
    /// Send outgoing commands to the relay task.
    pub outgoing_tx: mpsc::UnboundedSender<RelayCommand>,
    /// The remote hostname (e.g. "per.lagun.co").
    pub remote_host: String,
    /// Channels active on this relay: local_channel → per-channel state.
    pub channels: HashMap<String, FederatedChannel>,
    /// Handle to abort the relay task on cleanup.
    pub task_handle: tokio::task::JoinHandle<()>,
    /// Whether this relay was created by the mesh connector (kept alive even with no channels).
    pub mesh_connected: bool,
    /// Whether this relay was created from LAGOON_PEERS (bootstrap peer).
    pub is_bootstrap: bool,
    /// Last measured IRC-layer round-trip time in milliseconds (from PING/PONG).
    pub last_rtt_ms: Option<f64>,
    /// The node_name of the remote peer, set after MESH HELLO exchange.
    /// Used to detect duplicate connections to the same node under different relay keys.
    pub remote_node_name: Option<String>,
}

/// Commands sent from the server to a relay task.
#[derive(Debug)]
pub enum RelayCommand {
    /// Send a PRIVMSG to a remote channel on behalf of a local user.
    Privmsg { nick: String, remote_channel: String, text: String },
    /// Notify the remote that a local user joined a federated channel.
    Join { nick: String, remote_channel: String },
    /// Notify the remote that a local user parted a federated channel.
    Part { nick: String, remote_channel: String, reason: String },
    /// Tell the relay to JOIN a new channel on the remote server.
    JoinChannel { remote_channel: String, local_channel: String },
    /// Tell the relay to PART a channel on the remote server.
    PartChannel { remote_channel: String },
    /// Send a raw pre-formatted message on the relay connection (e.g. FRELAY DM).
    Raw(Message),
    /// Send a native mesh protocol message (JSON over WebSocket).
    ///
    /// Used by the event processor for all mesh-related sends. Native inbound
    /// handlers serialize directly to JSON; legacy outbound relay_tasks translate
    /// to IRC `MESH {subcommand} {json}` lines.
    SendMesh(MeshMessage),
    /// Send MESH HELLO after registration.
    MeshHello { json: String },
    /// Shut down the relay connection entirely.
    Shutdown,
    /// Drop the current connection and reconnect (e.g. self-connection detected
    /// via anycast DNS — next resolution may hit a different machine).
    Reconnect,
}

/// Events sent from a relay task back to the server for local dispatch.
#[derive(Debug)]
pub enum RelayEvent {
    /// A remote user sent a message to the channel.
    RemotePrivmsg {
        local_channel: String,
        remote_nick: String,
        remote_host: String,
        text: String,
    },
    /// A remote user joined the channel.
    RemoteJoin {
        local_channel: String,
        remote_nick: String,
        remote_host: String,
    },
    /// A remote user parted or quit the channel.
    RemotePart {
        local_channel: String,
        remote_nick: String,
        remote_host: String,
        reason: String,
    },
    /// Received NAMES list from remote — set of nicks in the channel.
    RemoteNames {
        local_channel: String,
        remote_host: String,
        nicks: Vec<String>,
    },
    /// The relay connection to a remote host was lost.
    Disconnected { remote_host: String },
    /// A specific channel's relay has been established.
    Connected { local_channel: String },
    /// Received MESH HELLO from a remote peer.
    MeshHello {
        remote_host: String,
        /// Cryptographic peer identity (`"b3b3/{hex}"`), NOT the lens/domain.
        peer_id: String,
        server_name: String,
        public_key_hex: String,
        spiral_index: Option<u64>,
        vdf_genesis: Option<String>,
        vdf_hash: Option<String>,
        vdf_step: Option<u64>,
        yggdrasil_addr: Option<String>,
        site_name: String,
        node_name: String,
        vdf_resonance_credit: Option<f64>,
        vdf_actual_rate_hz: Option<f64>,
        ygg_peer_uri: Option<String>,
        /// TCP peer address of the relay connection — used by APE to derive
        /// an underlay Ygg peer URI (`tcp://[ip]:9443`). This is a known-good
        /// address to a confirmed-different node (peer_id verified).
        relay_peer_addr: Option<SocketAddr>,
    },
    /// Received MESH PEERS from a remote peer.
    MeshPeers {
        remote_host: String,
        peers: Vec<MeshPeerInfo>,
    },
    /// Received MESH TOPOLOGY from a remote peer.
    MeshTopology {
        remote_host: String,
        json: String,
    },
    /// Received MESH VDFPROOF_REQ — a peer wants us to prove our VDF chain.
    MeshVdfProofReq {
        remote_host: String,
    },
    /// Received MESH VDFPROOF — a peer sent us a ZK proof of their VDF chain.
    MeshVdfProof {
        remote_host: String,
        proof_json: String,
        /// Mesh key from HELLO — O(1) lookup into known_peers.
        mesh_key: Option<String>,
    },
    /// Received MESH SYNC — a peer wants our full peer table.
    MeshSync {
        remote_host: String,
    },
    /// A local IRC event to broadcast into the gossip mesh.
    GossipBroadcast {
        event: super::gossip::GossipIrcEvent,
    },
    /// Received MESH GOSSIP from a remote peer — a single gossip message.
    GossipReceive {
        remote_host: String,
        message_json: String,
    },
    /// Received MESH GOSSIP_SPORE from a remote peer — their SPORE HaveList.
    GossipSpore {
        remote_host: String,
        spore_json: String,
    },
    /// Received MESH GOSSIP_DIFF from a remote peer — batch catch-up messages.
    GossipDiff {
        remote_host: String,
        messages_json: String,
    },
    /// Measured RTT to a remote peer (from PING/PONG round-trip).
    LatencyMeasured {
        remote_host: String,
        rtt_ms: f64,
        /// Mesh key from HELLO — O(1) lookup into known_peers.
        mesh_key: Option<String>,
    },
    /// Received MESH LATENCY_HAVE — remote peer's latency proof SPORE.
    LatencyHaveList {
        remote_host: String,
        payload_b64: String,
    },
    /// Received MESH LATENCY_DELTA — proof entries we're missing.
    LatencyProofDelta {
        remote_host: String,
        payload_b64: String,
    },
}

/// Manages all federated channel relay connections.
#[derive(Debug)]
pub struct FederationManager {
    /// Active relays: remote_host → relay handle.
    pub relays: HashMap<String, RelayHandle>,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
        }
    }
}

/// Format an IRC prefix for a remote user.
///
/// The `@server` must be in the nick part (before `!`) for IRC clients to
/// display it. If the nick already contains `@` (virtual user from another
/// federation), use it as-is. Otherwise suffix with `@remote_host`.
fn format_remote_prefix(nick: &str, remote_host: &str) -> String {
    if nick.contains('@') {
        // Already qualified (e.g. "zorlin@lon.lagun.co").
        format!("{nick}!{nick}")
    } else {
        // Bare nick — put @remote_host IN the nick, before the `!`.
        format!("{nick}@{remote_host}!{nick}@{remote_host}")
    }
}

/// Spawn the federation event processor that listens for relay events
/// and dispatches them to local users.
/// Query Yggdrasil peer metrics from the embedded node (if available).
fn refresh_ygg_metrics_embedded(
    ygg_node: &Option<Arc<yggbridge::YggNode>>,
) -> Option<Vec<super::yggdrasil::YggPeer>> {
    let node = ygg_node.as_ref()?;
    let peers = node.peers();
    Some(
        peers
            .into_iter()
            .map(|p| {
                let address = super::yggdrasil::key_to_address(&p.key)
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                super::yggdrasil::YggPeer {
                    address,
                    remote: p.uri,
                    bytes_sent: p.tx_bytes,
                    bytes_recvd: p.rx_bytes,
                    latency: p.latency_ms * 1_000_000.0, // ms → ns
                    key: p.key,
                    port: 0,
                    uptime: p.uptime,
                    up: p.up,
                    inbound: p.inbound,
                }
            })
            .collect(),
    )
}

pub fn spawn_event_processor(
    state: SharedState,
    mut event_rx: mpsc::UnboundedReceiver<RelayEvent>,
) {
    tokio::spawn(async move {
        // Get a reference to the embedded Ygg node for metrics queries.
        let ygg_node = {
            let st = state.read().await;
            st.transport_config.ygg_node.clone()
        };

        while let Some(event) = event_rx.recv().await {
            match event {
                RelayEvent::RemotePrivmsg {
                    local_channel,
                    remote_nick,
                    remote_host,
                    text,
                } => {
                    let st = state.read().await;
                    let local_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
                    if !local_nicks.is_empty() {
                        let display =
                            format_remote_prefix(&remote_nick, &remote_host);
                        let msg = Message {
                            prefix: Some(display),
                            command: "PRIVMSG".into(),
                            params: vec![local_channel, text],
                        };
                        broadcast(&st, &local_nicks, &msg);
                    }
                }
                RelayEvent::RemoteJoin {
                    local_channel,
                    remote_nick,
                    remote_host,
                } => {
                    let mut st = state.write().await;
                    // Update remote_users.
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        if let Some(fed_ch) = relay.channels.get_mut(&local_channel) {
                            fed_ch.remote_users.insert(remote_nick.clone());
                        }
                    }
                    // Notify local subscribers of this federated channel.
                    let notify_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
                    let display = format_remote_prefix(&remote_nick, &remote_host);
                    let msg = Message {
                        prefix: Some(display),
                        command: "JOIN".into(),
                        params: vec![local_channel],
                    };
                    broadcast(&st, &notify_nicks, &msg);
                }
                RelayEvent::RemotePart {
                    local_channel,
                    remote_nick,
                    remote_host,
                    reason,
                } => {
                    let mut st = state.write().await;
                    // Update remote_users.
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        if let Some(fed_ch) = relay.channels.get_mut(&local_channel) {
                            fed_ch.remote_users.remove(&remote_nick);
                        }
                    }
                    // Notify local subscribers of this federated channel.
                    let notify_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
                    let display = format_remote_prefix(&remote_nick, &remote_host);
                    let msg = Message {
                        prefix: Some(display),
                        command: "PART".into(),
                        params: vec![local_channel, reason],
                    };
                    broadcast(&st, &notify_nicks, &msg);
                }
                RelayEvent::RemoteNames {
                    local_channel,
                    remote_host,
                    nicks,
                } => {
                    let mut st = state.write().await;
                    // Update remote_users for this relay.
                    let tracked = if let Some(relay) =
                        st.federation.relays.get_mut(&remote_host)
                    {
                        if let Some(fed_ch) = relay.channels.get_mut(&local_channel)
                        {
                            fed_ch.remote_users = nicks.into_iter().collect();
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    };
                    if !tracked {
                        continue;
                    }

                    // Build NAMES: local subscribers + remote users from this relay.
                    let relay = st.federation.relays.get(&remote_host).unwrap();
                    let fed_ch = relay.channels.get(&local_channel).unwrap();
                    let mut parts: Vec<String> =
                        fed_ch.local_users.iter().cloned().collect();
                    for rn in &fed_ch.remote_users {
                        if rn.contains('@') {
                            parts.push(rn.clone());
                        } else {
                            parts.push(format!(
                                "{rn}@{}",
                                relay.remote_host
                            ));
                        }
                    }
                    let names_str = parts.join(" ");
                    let local_nicks: Vec<_> =
                        fed_ch.local_users.iter().cloned().collect();

                    // Push updated NAMES to recipients.
                    for ln in &local_nicks {
                        let r353 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "353".into(),
                            params: vec![
                                ln.clone(),
                                "=".into(),
                                local_channel.clone(),
                                names_str.clone(),
                            ],
                        };
                        let r366 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "366".into(),
                            params: vec![
                                ln.clone(),
                                local_channel.clone(),
                                "End of /NAMES list".into(),
                            ],
                        };
                        if let Some(handle) = st.clients.get(ln) {
                            let _ = handle.tx.send(r353);
                            let _ = handle.tx.send(r366);
                        }
                    }
                }
                RelayEvent::Disconnected { remote_host } => {
                    // Query Ygg metrics before acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node);

                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_metrics.update(yp);
                    }

                    // Broadcast disconnect notice to federated channel users.
                    if let Some(relay) = st.federation.relays.get(&remote_host) {
                        for (local_channel, fed_ch) in &relay.channels {
                            let msg = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "NOTICE".into(),
                                params: vec![
                                    local_channel.clone(),
                                    format!(
                                        "Federation relay to {} disconnected",
                                        relay.remote_host
                                    ),
                                ],
                            };
                            let local_nicks: Vec<_> =
                                fed_ch.local_users.iter().cloned().collect();
                            broadcast(&st, &local_nicks, &msg);
                        }
                    }

                    // Clean up relay handle — grab remote_node_name before removing.
                    let actual_node_name = st.federation.relays.get(&remote_host)
                        .and_then(|r| r.remote_node_name.clone());
                    if let Some(relay) = st.federation.relays.remove(&remote_host) {
                        relay.task_handle.abort();
                    }

                    // Find and remove connection state by mesh_key.
                    // Use the actual node_name from the relay's HELLO exchange,
                    // NOT the relay_key — with anycast, relay_key is "anycast-mesh"
                    // which doesn't match any node's node_name.
                    let match_name = actual_node_name.as_deref().unwrap_or(&remote_host);
                    let disconnected_ids: Vec<String> = st
                        .mesh
                        .known_peers
                        .iter()
                        .filter(|(_, p)| p.node_name == match_name)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in &disconnected_ids {
                        st.mesh.connections.remove(id);
                        // Remove from SPIRAL — gap-and-wrap will reassign
                        // neighbor slots to the next occupied node.
                        st.mesh.spiral.remove_peer(id);
                        st.mesh.latency_gossip.remove_peer(id);
                    }
                    if !disconnected_ids.is_empty() {
                        let neighbors = st.mesh.spiral.neighbors().clone();
                        st.mesh.latency_gossip.set_spiral_neighbors(neighbors);
                        st.notify_topology_change();
                    }
                }
                RelayEvent::Connected { local_channel } => {
                    let st = state.read().await;
                    // Find which relay owns this channel.
                    for relay in st.federation.relays.values() {
                        if let Some(fed_ch) = relay.channels.get(&local_channel) {
                            let msg = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "NOTICE".into(),
                                params: vec![
                                    local_channel.clone(),
                                    format!(
                                        "Federation relay to {} established",
                                        relay.remote_host
                                    ),
                                ],
                            };
                            let local_nicks: Vec<_> =
                                fed_ch.local_users.iter().cloned().collect();
                            broadcast(&st, &local_nicks, &msg);
                            break;
                        }
                    }
                }

                RelayEvent::MeshHello {
                    remote_host,
                    peer_id,
                    server_name,
                    public_key_hex,
                    spiral_index,
                    vdf_genesis,
                    vdf_hash,
                    vdf_step,
                    yggdrasil_addr,
                    site_name,
                    node_name,
                    vdf_resonance_credit,
                    vdf_actual_rate_hz,
                    ygg_peer_uri,
                    relay_peer_addr,
                } => {
                    // Backfill node_name/site_name for old peers that don't send them.
                    let node_name = if node_name.is_empty() {
                        derive_node_name(&server_name)
                    } else {
                        node_name
                    };
                    let site_name = if site_name.is_empty() {
                        super::server::derive_site_name(&server_name)
                    } else {
                        site_name
                    };

                    // peer_id (public key) = the node's identity.
                    let mkey = peer_id.clone();

                    // Verify PeerID matches public key.
                    if let Ok(pubkey_bytes) = hex::decode(&public_key_hex) {
                        if pubkey_bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&pubkey_bytes);
                            if !lens::verify_peer_id(&peer_id, &key) {
                                warn!(
                                    remote_host,
                                    "mesh: rejected HELLO — PeerID doesn't match pubkey"
                                );
                                continue;
                            }
                        }
                    }

                    // Query Yggdrasil metrics BEFORE acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node);

                    let mut st = state.write().await;

                    // Update Ygg metrics store if we got data.
                    if let Some(peers) = ygg_peers {
                        st.mesh.ygg_metrics.update(peers);
                    }

                    // Detect self-connection via peer_id (public key).
                    //
                    // With anycast DNS (e.g. `anycast-mesh.internal`), self-connection
                    // is transient — the next DNS resolution may hit a different machine.
                    // Send Reconnect (not Shutdown) so the relay retries with backoff.
                    let our_pid = st.lens.peer_id.clone();
                    if mkey == our_pid {
                        warn!(
                            remote_host,
                            mesh_key = %mkey,
                            "mesh: self-connection detected — will reconnect (anycast)"
                        );
                        // DON'T remove the relay — it stays in state for reconnection.
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::Reconnect);
                        }
                        st.mesh.connections.remove(&mkey);
                        continue;
                    }

                    // Check defederation.
                    if st.mesh.defederated.contains(&peer_id)
                        || st.mesh.defederated.contains(&server_name)
                    {
                        warn!(
                            remote_host,
                            peer_id,
                            "mesh: rejected HELLO — peer is defederated"
                        );
                        continue;
                    }

                    info!(
                        remote_host,
                        mesh_key = %mkey,
                        peer_id,
                        server_name,
                        "mesh: received HELLO"
                    );

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    // Determine transport hints from our config for this peer.
                    let (peer_port, peer_tls) = st
                        .transport_config
                        .peers
                        .get(&remote_host)
                        .map(|p| (p.port, p.tls))
                        .unwrap_or((6667, false));

                    if let Some(step) = vdf_step {
                        info!(
                            remote_host,
                            mesh_key = %mkey,
                            vdf_step = step,
                            "mesh: peer VDF state"
                        );
                    }

                    // With 2D mesh keying, same (site_name, node_name) = same key.
                    // No stale identity eviction needed — insert just overwrites
                    // the existing entry if the node restarted with a new key.
                    st.mesh.known_peers.insert(
                        mkey.clone(),
                        MeshPeerInfo {
                            peer_id: peer_id.clone(),
                            server_name: server_name.clone(),
                            public_key_hex,
                            port: peer_port,
                            tls: peer_tls,
                            last_seen: now,
                            spiral_index,
                            vdf_genesis,
                            vdf_hash,
                            vdf_step,
                            yggdrasil_addr,
                            site_name: site_name.clone(),
                            node_name: node_name.clone(),
                            vdf_resonance_credit,
                            vdf_actual_rate_hz,
                            ygg_peer_uri: ygg_peer_uri.clone(),
                        },
                    );
                    st.mesh
                        .connections
                        .insert(mkey.clone(), MeshConnectionState::Connected);

                    // APE: dynamically peer with this node's Yggdrasil overlay.
                    if let Some(ref ygg) = st.transport_config.ygg_node {
                        if let Some(uri) = ape_peer_uri(relay_peer_addr, ygg_peer_uri.as_deref()) {
                            match ygg.add_peer(&uri) {
                                Ok(()) => info!(
                                    uri,
                                    peer_id,
                                    "APE: added Yggdrasil peer from MESH HELLO"
                                ),
                                Err(e) => warn!(
                                    uri,
                                    peer_id,
                                    error = %e,
                                    "APE: failed to add Yggdrasil peer"
                                ),
                            }
                        }
                    }

                    // Register SPIRAL position if the peer has claimed one.
                    if let Some(idx) = spiral_index {
                        st.mesh.spiral.add_peer(
                            &mkey,
                            citadel_topology::Spiral3DIndex::new(idx),
                        );
                    }

                    // Register peer with latency gossip + update SPIRAL neighbor set.
                    st.mesh.latency_gossip.register_peer(
                        mkey.clone(), node_name.clone(),
                    );
                    let neighbors = st.mesh.spiral.neighbors().clone();
                    st.mesh.latency_gossip.set_spiral_neighbors(neighbors);

                    // Prune relay connections to non-SPIRAL peers now that the
                    // neighbor set may have changed.
                    prune_non_spiral_relays(&mut st);

                    st.notify_topology_change();

                    // Staleness eviction: remove disconnected peers we haven't
                    // heard from in 5 minutes. Event-driven — runs on every HELLO.
                    // Future: VDF-advancement tracking (proof-challenge-response)
                    // will replace this with cryptographic liveness detection.
                    const STALE_PEER_SECS: u64 = 10;
                    {
                        let mut evicted = Vec::new();

                        for (peer_mkey, peer) in &st.mesh.known_peers {
                            if *peer_mkey == our_pid {
                                continue;
                            }
                            if st.mesh.connections.contains_key(peer_mkey) {
                                continue;
                            }
                            if now.saturating_sub(peer.last_seen) < STALE_PEER_SECS {
                                continue;
                            }
                            evicted.push(peer_mkey.clone());
                        }

                        for evicted_key in &evicted {
                            if let Some(peer) = st.mesh.known_peers.remove(evicted_key) {
                                info!(
                                    mesh_key = %evicted_key,
                                    server_name = %peer.server_name,
                                    vdf_step = ?peer.vdf_step,
                                    last_seen = peer.last_seen,
                                    stale_secs = STALE_PEER_SECS,
                                    "mesh: evicting stale peer — not seen recently"
                                );
                                st.mesh.spiral.remove_peer(evicted_key);
                                st.mesh.latency_gossip.remove_peer(evicted_key);
                            }
                        }

                        if !evicted.is_empty() {
                            let neighbors = st.mesh.spiral.neighbors().clone();
                            st.mesh.latency_gossip.set_spiral_neighbors(neighbors);
                            st.notify_topology_change();
                        }
                    }

                    // Per-site dedup: cap disconnected peers per SITE_NAME.
                    let site_evicted = dedup_peers_per_site(&mut st.mesh, &our_pid);
                    if !site_evicted.is_empty() {
                        st.notify_topology_change();
                    }

                    // Track which node each relay is connected to.
                    // This lets us detect when two relay keys reach the same node
                    // (e.g. LAGOON_PEERS key "iad" and inbound node "node-XXXX").
                    //
                    // CRITICAL: When a relay reconnects via anycast and lands on
                    // a DIFFERENT node, we must clear the old node's Connected
                    // state — otherwise ghost entries accumulate forever.
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        if let Some(old_node) = relay.remote_node_name.replace(node_name.clone()) {
                            if old_node != node_name {
                                // Relay was connected to a different node before.
                                // Clear the old node's Connected state.
                                let ghost_ids: Vec<String> = st.mesh.known_peers.iter()
                                    .filter(|(_, p)| p.node_name == old_node)
                                    .map(|(id, _)| id.clone())
                                    .collect();
                                for id in &ghost_ids {
                                    info!(
                                        relay_key = %remote_host,
                                        old_node = %old_node,
                                        new_node = %node_name,
                                        mesh_key = %id,
                                        "mesh: clearing ghost Connected state — relay reconnected to different node"
                                    );
                                    st.mesh.connections.remove(id);
                                    st.mesh.spiral.remove_peer(id);
                                    st.mesh.latency_gossip.remove_peer(id);
                                }
                                if !ghost_ids.is_empty() {
                                    let neighbors = st.mesh.spiral.neighbors().clone();
                                    st.mesh.latency_gossip.set_spiral_neighbors(neighbors);
                                    st.notify_topology_change();
                                }
                            }
                        }
                    }

                    // Connection reciprocity: if this peer connected to us and
                    // we don't have an outbound relay to them, establish one.
                    // This ensures bidirectional connectivity in the mesh.
                    // NOTE: must happen BEFORE sending MESH PEERS/TOPOLOGY/SPORE,
                    // because those sends go via st.federation.relays.
                    //
                    // Skip if we already reach this peer via any existing relay:
                    // - By node_name key (direct match)
                    // - By remote_host key (outbound relay, e.g. "lhr" from LAGOON_PEERS)
                    // - By node_name (another relay already identified this node)
                    let already_reached =
                        st.federation.relays.contains_key(&node_name)
                        || (remote_host != node_name
                            && st.federation.relays.contains_key(&remote_host))
                        || st.federation.relays.values().any(|r|
                            r.remote_node_name.as_deref() == Some(node_name.as_str()));
                    if !already_reached {
                        let should_connect = !st.mesh.spiral.is_claimed()
                            || st.mesh.spiral.is_neighbor(&mkey);

                        if should_connect {
                            info!(
                                peer = %node_name,
                                server = %server_name,
                                "mesh: reciprocal connect to inbound peer"
                            );

                            let hello_json =
                                serde_json::to_string(&build_hello_payload(&st))
                                    .unwrap_or_default();
                            let event_tx = st.federation_event_tx.clone();

                            let peer_ygg_addr = st
                                .mesh
                                .known_peers
                                .get(&mkey)
                                .and_then(|p| p.yggdrasil_addr.as_deref())
                                .and_then(|s| s.parse().ok());

                            // connect_key: use node_name if Ygg-reachable, else server_name for DNS.
                            let connect_key = if peer_ygg_addr.is_some() {
                                node_name.clone()
                            } else {
                                server_name.clone()
                            };

                            let mut tc_with_peer = (*st.transport_config).clone();
                            tc_with_peer
                                .peers
                                .entry(connect_key.clone())
                                .or_insert(transport::PeerEntry {
                                    yggdrasil_addr: peer_ygg_addr,
                                    port: peer_port,
                                    tls: peer_tls,
                                });
                            let tc_arc = Arc::new(tc_with_peer);

                            let (cmd_tx, task_handle) = spawn_relay(
                                node_name.clone(),
                                connect_key,
                                event_tx,
                                tc_arc,
                            );
                            let _ = cmd_tx.send(RelayCommand::MeshHello {
                                json: hello_json,
                            });

                            st.federation.relays.insert(
                                node_name.clone(),
                                RelayHandle {
                                    outgoing_tx: cmd_tx,
                                    remote_host: node_name.clone(),
                                    channels: HashMap::new(),
                                    task_handle,
                                    mesh_connected: true,
                                    is_bootstrap: false,
                                    last_rtt_ms: None,
                                    remote_node_name: Some(node_name.clone()),
                                },
                            );
                        }
                    }

                    // Send PEERS to the newly connected peer.
                    // No chunking needed — WebSocket has no size limit.
                    let peers_list: Vec<MeshPeerInfo> =
                        st.mesh.known_peers.values().cloned().collect();
                    if !peers_list.is_empty() {
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::Peers { peers: peers_list },
                            ));
                        }
                    }

                    // Send LATENCY_HAVE — our proof SPORE for efficient delta sync.
                    {
                        let spore_bytes = bincode::serialize(
                            st.mesh.proof_store.spore(),
                        ).unwrap_or_default();
                        let sync_msg = super::latency_gossip::SyncMessage::HaveList {
                            spore_bytes,
                        };
                        let b64 = base64::engine::general_purpose::STANDARD
                            .encode(bincode::serialize(&sync_msg).unwrap_or_default());
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::LatencyHave { data: b64 },
                            ));
                        }
                    }

                    // SPORE gossip catch-up: send our HaveList so the peer can
                    // diff and send us anything we missed while disconnected.
                    if super::gossip::is_cluster_peer(&SITE_NAME, &site_name) {
                        let our_spore = st.mesh.gossip.seen_messages();
                        if let Ok(spore_json) = serde_json::to_string(our_spore) {
                            if let Some(relay) = st.federation.relays.get(&remote_host) {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::GossipSpore { data: spore_json },
                                ));
                                info!(
                                    remote_host,
                                    "gossip: sent SPORE HaveList to cluster peer for catch-up"
                                );
                            }
                        }
                    }

                    // Dedup: if two relays now point to the same node (same
                    // remote_node_name), shut down the non-bootstrap one.
                    // Handles the race where an inbound HELLO created a reciprocal
                    // before the outbound relay's HELLO identified the same node.
                    let dupe_key: Option<String> = st.federation.relays.iter()
                        .find(|(k, r)| {
                            *k != &remote_host
                                && r.remote_node_name.as_deref() == Some(node_name.as_str())
                        })
                        .map(|(k, _)| k.clone());
                    if let Some(dupe) = dupe_key {
                        let dupe_is_bootstrap = st.federation.relays
                            .get(&dupe).map_or(false, |r| r.is_bootstrap);
                        let this_is_bootstrap = st.federation.relays
                            .get(&remote_host).map_or(false, |r| r.is_bootstrap);
                        // Keep the bootstrap relay; remove the reciprocal.
                        let remove_key = if dupe_is_bootstrap && !this_is_bootstrap {
                            remote_host.clone()
                        } else {
                            dupe
                        };
                        if let Some(removed) = st.federation.relays.remove(&remove_key) {
                            info!(
                                removed = %remove_key,
                                node_name,
                                "mesh: deduplicating — two connections to same node"
                            );
                            let _ = removed.outgoing_tx.send(RelayCommand::Shutdown);
                        }
                    }
                }

                RelayEvent::MeshPeers {
                    remote_host,
                    peers,
                } => {
                    // Query Yggdrasil metrics before acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node);

                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_metrics.update(yp);
                    }
                    let mut changed = false;
                    let mut new_peer_servers = Vec::new();
                    let mut newly_discovered: Vec<MeshPeerInfo> = Vec::new();

                    for mut peer in peers {
                        // Backfill node_name/site_name for peers from old
                        // software that doesn't include these fields.
                        if peer.node_name.is_empty() {
                            peer.node_name = derive_node_name(&peer.server_name);
                        }
                        if peer.site_name.is_empty() {
                            peer.site_name = super::server::derive_site_name(&peer.server_name);
                        }

                        // Identity = peer_id (public key).
                        let mkey = peer.peer_id.clone();

                        if st.mesh.defederated.contains(&peer.peer_id)
                            || st.mesh.defederated.contains(&peer.server_name)
                        {
                            continue;
                        }
                        // Don't add ourselves.
                        let our_pid = st.lens.peer_id.clone();
                        if mkey == our_pid {
                            continue;
                        }

                        // Register SPIRAL position from gossiped peer info.
                        if let Some(idx) = peer.spiral_index {
                            st.mesh.spiral.add_peer(
                                &mkey,
                                citadel_topology::Spiral3DIndex::new(idx),
                            );
                        }

                        // Register with latency gossip (mesh_key → node_name routing).
                        st.mesh.latency_gossip.register_peer(
                            mkey.clone(), peer.node_name.clone(),
                        );

                        if !st.mesh.known_peers.contains_key(&mkey) {
                            // With 2D mesh keying, same (site, node) = same key.
                            // If a CONNECTED entry already exists for this key,
                            // the live connection is authoritative — don't overwrite.
                            if st.mesh.connections.get(&mkey).copied()
                                == Some(MeshConnectionState::Connected)
                            {
                                continue;
                            }

                            info!(
                                remote_host,
                                mesh_key = %mkey,
                                peer_id = %peer.peer_id,
                                server = %peer.server_name,
                                node = %peer.node_name,
                                port = peer.port,
                                tls = peer.tls,
                                spiral_index = ?peer.spiral_index,
                                "mesh: discovered peer via gossip"
                            );
                            let peer_node_name = peer.node_name.clone();
                            let server_name = peer.server_name.clone();
                            let port = peer.port;
                            let tls = peer.tls;
                            newly_discovered.push(peer.clone());
                            st.mesh.known_peers.insert(mkey.clone(), peer);
                            changed = true;
                            new_peer_servers.push((peer_node_name, server_name, port, tls));
                        } else if let Some(existing) = st.mesh.known_peers.get_mut(&mkey) {
                            // Update telemetry if incoming data is fresher.
                            if peer.last_seen > existing.last_seen {
                                existing.last_seen = peer.last_seen;
                                existing.peer_id = peer.peer_id.clone();
                                existing.public_key_hex = peer.public_key_hex.clone();
                                existing.vdf_hash = peer.vdf_hash.clone();
                                existing.vdf_step = peer.vdf_step;
                                // SPIRAL slot: first-writer-wins.
                                if existing.spiral_index.is_none() && peer.spiral_index.is_some() {
                                    existing.spiral_index = peer.spiral_index;
                                    if let Some(idx) = peer.spiral_index {
                                        st.mesh.spiral.add_peer(
                                            &mkey,
                                            citadel_topology::Spiral3DIndex::new(idx),
                                        );
                                    }
                                    changed = true;
                                }
                            }
                        }
                    }

                    // Per-site dedup BEFORE re-gossip — prevents evict/re-discover loops
                    // where evicted peers get re-gossiped, re-inserted, evicted again.
                    let our_pid = st.lens.peer_id.clone();
                    let site_evicted = dedup_peers_per_site(&mut st.mesh, &our_pid);
                    if !site_evicted.is_empty() {
                        changed = true;
                        // Remove evicted peers from newly_discovered so we don't
                        // re-gossip entries that were just evicted.
                        let evicted_pids: HashSet<String> = site_evicted.iter().cloned().collect();
                        newly_discovered.retain(|p| {
                            !evicted_pids.contains(&p.peer_id)
                        });
                        // Also remove from new_peer_servers (matched by node_name).
                        let evicted_nodes: HashSet<String> = site_evicted.iter()
                            .filter_map(|id| st.mesh.known_peers.get(id))
                            .map(|p| p.node_name.clone())
                            .collect();
                        new_peer_servers.retain(|(node, _, _, _)| !evicted_nodes.contains(node));
                    }

                    // Multi-hop gossip: re-broadcast newly discovered peers to
                    // all connected relays except the source. Only includes peers
                    // that survived dedup.
                    if !newly_discovered.is_empty() {
                        for (host, relay) in &st.federation.relays {
                            if *host != remote_host && relay.mesh_connected {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::Peers { peers: newly_discovered.clone() },
                                ));
                            }
                        }
                        info!(
                            count = newly_discovered.len(),
                            "mesh: re-gossiped newly discovered peers to neighbors"
                        );
                    }

                    // If we haven't claimed a SPIRAL position yet, claim one now
                    // that we have occupancy data from the network.
                    if !st.mesh.spiral.is_claimed() {
                        let our_pid = st.lens.peer_id.clone();
                        let idx = st.mesh.spiral.claim_position(&our_pid);
                        info!(
                            spiral_index = idx.value(),
                            peer_id = %our_pid,
                            "mesh: claimed SPIRAL slot"
                        );

                        // Persist to LensIdentity on disk (SPIRAL + VDF checkpoint).
                        let mut updated_lens = (*st.lens).clone();
                        updated_lens.spiral_index = Some(idx.value());
                        if let Some(ref rx) = st.mesh.vdf_state_rx {
                            updated_lens.vdf_total_steps = rx.borrow().total_steps;
                        }
                        super::lens::persist_identity(&st.data_dir, &updated_lens);
                        st.lens = std::sync::Arc::new(updated_lens);
                        changed = true;

                        // Re-send MESH HELLO with our spiral_index to all
                        // connected relays so they know our position.
                        let hello_json = serde_json::to_string(&build_hello_payload(&st))
                            .unwrap_or_default();
                        for relay in st.federation.relays.values() {
                            let _ = relay.outgoing_tx.send(RelayCommand::MeshHello {
                                json: hello_json.clone(),
                            });
                        }

                        // Now that SPIRAL is active, drop all non-SPIRAL relays.
                        // Bootstrap connections served their purpose — discovery is done.
                        prune_non_spiral_relays(&mut st);
                    }

                    if changed {
                        // Update SPIRAL neighbor set for latency gossip.
                        let neighbors = st.mesh.spiral.neighbors().clone();
                        st.mesh.latency_gossip.set_spiral_neighbors(neighbors);
                        st.notify_topology_change();
                    }

                    // Connect to newly discovered peers — SPIRAL-guided.
                    //
                    // If we have a SPIRAL position, only connect to peers that
                    // are in our 20-neighbor set. If we haven't claimed yet
                    // (fresh node), connect to all so we can receive MESH PEERS
                    // and claim a position.
                    if !new_peer_servers.is_empty() {
                        let spiral_active = st.mesh.spiral.is_claimed();
                        let hello_json =
                            serde_json::to_string(&build_hello_payload(&st))
                                .unwrap_or_default();
                        let event_tx = st.federation_event_tx.clone();
                        let tc = st.transport_config.clone();

                        for (node_name, server_name, port, tls) in new_peer_servers {
                            // Skip if we already have a relay to this node.
                            if st.federation.relays.contains_key(&node_name) {
                                continue;
                            }
                            // Skip self.
                            if node_name == *NODE_NAME {
                                continue;
                            }
                            // Skip defederated.
                            if st.mesh.defederated.contains(&node_name)
                                || st.mesh.defederated.contains(&server_name)
                            {
                                continue;
                            }

                            // SPIRAL gate: if we have a position, only connect
                            // to SPIRAL neighbors. Non-SPIRAL peers are reachable
                            // transitively through the overlay.
                            if spiral_active {
                                let is_neighbor = st.mesh.known_peers.iter()
                                    .find(|(_, p)| p.node_name == node_name)
                                    .map(|(pid, _)| st.mesh.spiral.is_neighbor(pid))
                                    .unwrap_or(false);
                                if !is_neighbor {
                                    tracing::debug!(
                                        peer = %node_name,
                                        "mesh: skipping non-SPIRAL-neighbor (reachable via overlay)"
                                    );
                                    continue;
                                }
                            }

                            // Look up Yggdrasil address from known_peers for
                            // overlay routing — the key to multi-hop connectivity.
                            let peer_ygg_addr = st
                                .mesh
                                .known_peers
                                .values()
                                .find(|p| p.node_name == node_name)
                                .and_then(|p| p.yggdrasil_addr.as_deref())
                                .and_then(|s| s.parse().ok());

                            info!(
                                peer = %node_name,
                                server = %server_name,
                                port,
                                tls,
                                yggdrasil = peer_ygg_addr.is_some(),
                                spiral_neighbor = spiral_active,
                                "mesh: auto-connecting to gossip-discovered peer"
                            );

                            // connect_key: use node_name if Ygg-reachable, else
                            // server_name for DNS fallback.
                            let connect_key = if peer_ygg_addr.is_some() {
                                node_name.clone()
                            } else {
                                server_name
                            };

                            // Add transport hints for this peer so connect() knows
                            // how to reach it.
                            //
                            // When peer_ygg_addr is set, connect() takes the overlay
                            // WebSocket path (ws://[ygg_addr]:8080/api/federation/ws)
                            // automatically — no DNS, no TLS, Ygg encrypts transport.
                            // The port/tls fields are irrelevant for overlay peers
                            // because the transport layer overrides them.
                            let mut tc_with_peer = (*tc).clone();
                            tc_with_peer.peers.entry(connect_key.clone()).or_insert(
                                transport::PeerEntry {
                                    yggdrasil_addr: peer_ygg_addr,
                                    port,
                                    tls,
                                },
                            );
                            let tc_arc = Arc::new(tc_with_peer);

                            let (cmd_tx, task_handle) = spawn_relay(
                                node_name.clone(),
                                connect_key,
                                event_tx.clone(),
                                tc_arc,
                            );
                            let _ = cmd_tx.send(RelayCommand::MeshHello {
                                json: hello_json.clone(),
                            });

                            st.federation.relays.insert(
                                node_name.clone(),
                                RelayHandle {
                                    outgoing_tx: cmd_tx,
                                    remote_host: node_name,
                                    channels: HashMap::new(),
                                    task_handle,
                                    mesh_connected: true,
                                    is_bootstrap: false,
                                    last_rtt_ms: None,
                                    remote_node_name: None,
                                },
                            );
                        }
                    }

                    // --- Bootstrap pruning (always runs, even in full_telemetry) ---
                    // Once SPIRAL is established and we have ≥1 Ygg-connected SPIRAL
                    // neighbor that is NOT a bootstrap peer, disconnect bootstrap peers
                    // that aren't SPIRAL neighbors.
                    if st.mesh.spiral.is_claimed() {
                        let has_ygg_spiral_neighbor = st.federation.relays.iter()
                            .filter(|(_, relay)| relay.mesh_connected && !relay.is_bootstrap)
                            .any(|(host, _)| {
                                st.mesh.known_peers.iter()
                                    .find(|(_, p)| p.node_name == **host)
                                    .map(|(pid, p)| {
                                        st.mesh.spiral.is_neighbor(pid)
                                            && p.yggdrasil_addr.is_some()
                                    })
                                    .unwrap_or(false)
                            });

                        if has_ygg_spiral_neighbor {
                            let to_prune: Vec<String> = st.federation.relays.iter()
                                .filter(|(_, relay)| relay.is_bootstrap)
                                .filter(|(host, _)| {
                                    st.mesh.known_peers.iter()
                                        .find(|(_, p)| p.node_name == **host)
                                        .map(|(pid, _)| {
                                            !st.mesh.spiral.is_neighbor(pid)
                                        })
                                        .unwrap_or(false)
                                })
                                .map(|(host, _)| host.clone())
                                .collect();

                            for host in to_prune {
                                info!(
                                    peer = %host,
                                    "mesh: disconnecting bootstrap peer (not a SPIRAL neighbor)"
                                );
                                if let Some(relay) = st.federation.relays.remove(&host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                                }
                            }
                        }
                    }

                    // Prune non-SPIRAL relays. SPIRAL is the sole authority
                    // on which direct connections we maintain.
                    prune_non_spiral_relays(&mut st);
                }

                RelayEvent::MeshTopology {
                    remote_host, ..
                } => {
                    // Legacy: TOPOLOGY messages from old peers are ignored.
                    // Proof-derived latency gossip has replaced monolithic topology broadcast.
                    tracing::debug!(remote_host, "mesh: ignoring legacy TOPOLOGY (use LATENCY_HAVE)");
                }

                RelayEvent::MeshVdfProofReq { remote_host } => {
                    // A peer wants us to prove our VDF chain.
                    let st = state.read().await;
                    if let Some(ref chain) = st.mesh.vdf_chain {
                        let c = chain.read().await;
                        if c.steps() > 0 {
                            let spiral_slot = st.lens.spiral_index;
                            let proof =
                                lagoon_vdf::VdfProof::generate_with_slot(&c, 3, spiral_slot);
                            drop(c);
                            if let Ok(proof_val) = serde_json::to_value(&proof) {
                                if let Some(relay) = st.federation.relays.get(&remote_host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                        MeshMessage::VdfProof { proof: proof_val },
                                    ));
                                    info!(
                                        remote_host,
                                        steps = proof.steps,
                                        spiral_slot = ?spiral_slot,
                                        "mesh: sent VDF proof with SPIRAL slot"
                                    );
                                }
                            }
                        }
                    }
                }

                RelayEvent::MeshVdfProof {
                    remote_host,
                    proof_json,
                    mesh_key,
                } => {
                    match serde_json::from_str::<lagoon_vdf::VdfProof>(&proof_json) {
                        Ok(proof) => {
                            if proof.verify() {
                                // VDF proof verified = this peer is alive and doing work.
                                // Update vdf_step — VDF IS the heartbeat.
                                if let Some(ref mkey) = mesh_key {
                                    let mut st = state.write().await;
                                    if let Some(peer) = st.mesh.known_peers.get_mut(mkey) {
                                        peer.vdf_step = Some(proof.steps);
                                    }
                                }
                                info!(
                                    remote_host,
                                    mesh_key = ?mesh_key,
                                    steps = proof.steps,
                                    "mesh: VDF proof VERIFIED — heartbeat"
                                );
                            } else {
                                warn!(remote_host, "mesh: VDF proof FAILED verification");
                            }
                        }
                        Err(e) => {
                            warn!(remote_host, error = %e, "mesh: invalid VDF proof JSON");
                        }
                    }
                }

                RelayEvent::MeshSync { remote_host } => {
                    // Query Ygg metrics before responding.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node);

                    // A peer wants our full peer table — respond with MESH PEERS.
                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_metrics.update(yp);
                        st.notify_topology_change();
                    }
                    let peers: Vec<MeshPeerInfo> =
                        st.mesh.known_peers.values().cloned().collect();
                    if !peers.is_empty() {
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::Peers { peers: peers.clone() },
                            ));
                            info!(
                                remote_host,
                                peer_count = peers.len(),
                                "mesh: sent full peer table (SYNC response)"
                            );
                        }
                    }
                }

                // ── Gossip events ─────────────────────────────────

                RelayEvent::GossipBroadcast { event } => {
                    let mut st = state.write().await;
                    let our_site = SITE_NAME.clone();
                    let id_bytes = st.mesh.gossip.broadcast_event(&event, &our_site);
                    let outbox = st.mesh.gossip.drain_outbox();

                    // Send to all mesh-connected relays.
                    for relay in st.federation.relays.values() {
                        if relay.mesh_connected {
                            for msg in &outbox {
                                if let Ok(val) = serde_json::to_value(msg) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                        MeshMessage::Gossip { message: val },
                                    ));
                                }
                            }
                        }
                    }
                    info!(
                        channel = %event.channel(),
                        nick = %event.nick(),
                        content_id = %hex::encode(&id_bytes[..8]),
                        "gossip: broadcast event to mesh"
                    );
                }

                RelayEvent::GossipReceive { remote_host, message_json } => {
                    if let Ok(gossip_msg) = serde_json::from_str::<citadel_gossip::GossipMessage>(&message_json) {
                        let mut st = state.write().await;
                        if let Some(event) = st.mesh.gossip.receive_message(gossip_msg) {
                            // Deliver to local channel members.
                            deliver_gossip_event(&st, &event);

                            // Re-gossip: forward to all OTHER connected relays.
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&message_json) {
                                for (host, relay) in &st.federation.relays {
                                    if relay.mesh_connected && *host != remote_host {
                                        let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                            MeshMessage::Gossip { message: val.clone() },
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse MESH GOSSIP JSON");
                    }
                }

                RelayEvent::GossipSpore { remote_host, spore_json } => {
                    if let Ok(peer_spore) = serde_json::from_str::<citadel_spore::Spore>(&spore_json) {
                        let st = state.read().await;
                        let diff_msgs = st.mesh.gossip.diff_messages(&peer_spore);
                        if !diff_msgs.is_empty() {
                            if let Ok(batch_json) = serde_json::to_string(&diff_msgs) {
                                if let Some(relay) = st.federation.relays.get(&remote_host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                        MeshMessage::GossipDiff { data: batch_json },
                                    ));
                                    info!(
                                        remote_host,
                                        diff_count = diff_msgs.len(),
                                        "gossip: sent SPORE catch-up diff"
                                    );
                                }
                            }
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse GOSSIP_SPORE JSON");
                    }
                }

                RelayEvent::GossipDiff { remote_host, messages_json } => {
                    if let Ok(messages) = serde_json::from_str::<Vec<citadel_gossip::GossipMessage>>(&messages_json) {
                        let mut st = state.write().await;
                        let mut accepted = 0usize;
                        for msg in messages {
                            if let Some(event) = st.mesh.gossip.receive_message(msg) {
                                deliver_gossip_event(&st, &event);
                                accepted += 1;
                            }
                        }
                        if accepted > 0 {
                            info!(
                                remote_host,
                                accepted,
                                "gossip: processed SPORE catch-up diff"
                            );
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse GOSSIP_DIFF JSON");
                    }
                }

                RelayEvent::LatencyMeasured { remote_host, rtt_ms, mesh_key } => {
                    let mut st = state.write().await;

                    // Store on relay handle (backward compat / direct lookup).
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        relay.last_rtt_ms = Some(rtt_ms);
                    }

                    if let Some(peer_id) = mesh_key {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let our_pid = st.lens.peer_id.clone();
                        let edge = super::proof_store::ProofStore::edge_key(
                            &our_pid, &peer_id,
                        );

                        // Simple measurement payload (full PoLP crypto is Phase 3).
                        let proof_bytes = format!(
                            "{}:{}:{}:{}", edge.0, edge.1, rtt_ms, now_ms,
                        ).into_bytes();

                        let entry = super::proof_store::ProofStore::make_entry(
                            edge, rtt_ms, now_ms, proof_bytes,
                        );

                        if st.mesh.proof_store.insert(entry) {
                            tracing::info!(
                                remote_host,
                                rtt_ms,
                                proofs = st.mesh.proof_store.len(),
                                "polp: proof inserted into store",
                            );

                            // Proof was new/updated — trigger gossip to SPIRAL neighbors.
                            let spore_bytes = bincode::serialize(
                                st.mesh.proof_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.latency_gossip
                                .on_proof_updated(now_ms, &spore_bytes);
                            if !actions.is_empty() {
                                tracing::info!(
                                    count = actions.len(),
                                    "polp: sending LATENCY_HAVE to SPIRAL neighbors",
                                );
                            }
                            execute_latency_gossip_actions(&st, actions);

                            // Event-driven prune (no polling).
                            let pruned = st.mesh.proof_store.prune_stale(now_ms);
                            if pruned > 0 {
                                tracing::info!(pruned, "polp: pruned stale proofs");
                            }
                        }
                    }

                    st.notify_topology_change();
                }

                RelayEvent::LatencyHaveList { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "latency_gossip: invalid base64 in LATENCY_HAVE");
                            continue;
                        }
                    };
                    let sync_msg: super::latency_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "latency_gossip: invalid bincode in LATENCY_HAVE");
                                continue;
                            }
                        };

                    if let super::latency_gossip::SyncMessage::HaveList {
                        spore_bytes,
                    } = sync_msg
                    {
                        tracing::info!(remote_host, "polp: received LATENCY_HAVE from peer");

                        let st = state.read().await;

                        let from_mkey = st.mesh.known_peers.iter()
                            .find(|(_, p)| p.node_name == remote_host)
                            .map(|(id, _)| id.clone())
                            .unwrap_or_default();

                        let our_spore = st.mesh.proof_store.spore();
                        let our_proof_data = st.mesh.proof_store.proof_data_for_gossip();

                        if let Some(action) = st.mesh.latency_gossip.on_have_list_received(
                            &from_mkey,
                            &spore_bytes,
                            our_spore,
                            &our_proof_data,
                        ) {
                            tracing::info!(remote_host, "polp: sending LATENCY_DELTA in response");
                            execute_latency_gossip_actions(&st, vec![action]);
                        } else {
                            tracing::debug!(remote_host, "polp: peer is up-to-date, no delta needed");
                        }
                    }
                }

                RelayEvent::LatencyProofDelta { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "latency_gossip: invalid base64 in LATENCY_DELTA");
                            continue;
                        }
                    };
                    let sync_msg: super::latency_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "latency_gossip: invalid bincode in LATENCY_DELTA");
                                continue;
                            }
                        };

                    if let super::latency_gossip::SyncMessage::ProofDelta {
                        entries,
                    } = sync_msg
                    {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let mut st = state.write().await;

                        let proof_entries: Vec<super::proof_store::ProofEntry> = entries
                            .iter()
                            .filter_map(|bytes| bincode::deserialize(bytes).ok())
                            .collect();

                        let accepted = st.mesh.proof_store.merge(proof_entries, now_ms);
                        if accepted > 0 {
                            info!(
                                remote_host, accepted,
                                "latency_gossip: merged proof delta",
                            );

                            // Re-gossip to our SPIRAL neighbors.
                            let spore_bytes = bincode::serialize(
                                st.mesh.proof_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.latency_gossip
                                .on_proof_updated(now_ms, &spore_bytes);
                            execute_latency_gossip_actions(&st, actions);

                            st.mesh.proof_store.prune_stale(now_ms);
                            st.notify_topology_change();
                        }
                    }
                }
            }
        }
    });
}

/// Execute latency gossip sync actions by sending MESH subcommands to relay peers.
fn execute_latency_gossip_actions(
    st: &super::server::ServerState,
    actions: Vec<super::latency_gossip::SyncAction>,
) {
    for action in actions {
        let (node_name, message) = match action {
            super::latency_gossip::SyncAction::SendHaveList {
                neighbor_node_name, message,
            } => (neighbor_node_name, message),
            super::latency_gossip::SyncAction::SendProofDelta {
                neighbor_node_name, message,
            } => (neighbor_node_name, message),
        };
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&message).unwrap_or_default());
        let mesh_msg = match &message {
            super::latency_gossip::SyncMessage::HaveList { .. } => {
                MeshMessage::LatencyHave { data: b64 }
            }
            super::latency_gossip::SyncMessage::ProofDelta { .. } => {
                MeshMessage::LatencyDelta { data: b64 }
            }
        };
        if let Some(relay) = st.federation.relays.get(&node_name) {
            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(mesh_msg));
        }
    }
}

/// Deliver a gossip IRC event to local channel members.
///
/// Display rules:
/// - Same SITE_NAME origin → bare nick (transparent cluster)
/// - Different SITE_NAME → `nick@origin` (foreign supernode)
/// - Skip the original sender if they're a local user (already saw their own message)
fn deliver_gossip_event(
    st: &super::server::ServerState,
    event: &super::gossip::GossipIrcEvent,
) {
    use super::gossip::GossipIrcEvent;

    let our_site = &*SITE_NAME;
    let is_cluster = super::gossip::is_cluster_peer(our_site, &super::server::derive_site_name(event.origin()));

    // Format the display nick based on cluster vs federation.
    let display_nick = if is_cluster {
        event.nick().to_string()
    } else {
        format!("{}@{}", event.nick(), event.origin())
    };
    let prefix = format!("{}!{}@{}", display_nick, event.nick(), event.origin());

    let channel = super::server::irc_lower(event.channel());

    // Get local members of this channel.
    let members: Vec<String> = st
        .channels
        .get(&channel)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    if members.is_empty() {
        return;
    }

    // Build the IRC message to deliver.
    let irc_msg = match event {
        GossipIrcEvent::Message { text, command, .. } => Message {
            prefix: Some(prefix),
            command: command.clone(),
            params: vec![event.channel().to_string(), text.clone()],
        },
        GossipIrcEvent::Join { .. } => Message {
            prefix: Some(prefix),
            command: "JOIN".into(),
            params: vec![event.channel().to_string()],
        },
        GossipIrcEvent::Part { reason, .. } => Message {
            prefix: Some(prefix),
            command: "PART".into(),
            params: vec![event.channel().to_string(), reason.clone()],
        },
        GossipIrcEvent::Topic { text, .. } => Message {
            prefix: Some(prefix),
            command: "TOPIC".into(),
            params: vec![event.channel().to_string(), text.clone()],
        },
    };

    // Deliver to each local channel member.
    // Skip the original sender if they're local (cluster case: they already
    // saw their own message from the local broadcast).
    let sender_key = if is_cluster {
        Some(super::server::irc_lower(event.nick()))
    } else {
        None
    };

    for nick_key in &members {
        // Skip the sender if they're a local user in the cluster.
        if sender_key.as_deref() == Some(nick_key.as_str()) {
            continue;
        }
        if let Some(handle) = st.clients.get(nick_key) {
            let _ = handle.tx.send(irc_msg.clone());
        }
    }
}

/// Spawn a relay connection to a remote server.
///
/// `relay_key` is the unique node identity (node_name) used for keying
/// `federation.relays` and identifying events.
///
/// `connect_target` is the hostname/address passed to `transport::connect()`.
/// For LAGOON_PEERS entries this is the FQDN; for gossip-discovered peers
/// this may be the node_name (with Ygg address in the transport config).
pub fn spawn_relay(
    relay_key: String,
    connect_target: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) -> (mpsc::UnboundedSender<RelayCommand>, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(relay_task(
        relay_key,
        connect_target,
        cmd_rx,
        event_tx,
        transport_config,
    ));

    (cmd_tx, handle)
}

/// Per-channel state within the relay task.
struct TaskChannel {
    local_channel: String,
    joined: bool,
    pending: Vec<RelayCommand>,
}

/// Wait with exponential backoff while draining commands from the relay channel.
///
/// Returns `true` to continue reconnecting, `false` to exit (Shutdown or
/// channel closed — the relay handle was removed from state).
async fn backoff_drain(
    cmd_rx: &mut mpsc::UnboundedReceiver<RelayCommand>,
    saved_mesh_hello: &mut Option<String>,
    failures: u32,
) -> bool {
    let secs = (2u64.pow(failures)).min(60);
    let backoff = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(backoff);
    loop {
        tokio::select! {
            _ = &mut backoff => return true,
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::Shutdown) => return false,
                    Some(RelayCommand::Reconnect) => {} // Already reconnecting.
                    Some(RelayCommand::MeshHello { json }) => {
                        *saved_mesh_hello = Some(json);
                    }
                    Some(_) => {} // Drop other commands during backoff.
                    None => return false, // Channel closed — relay handle removed.
                }
            }
        }
    }
}

/// The relay task — connects to a remote Lagoon server, registers, and
/// relays messages bidirectionally for multiple channels using FRELAY.
///
/// `relay_key` is the node_name used as identity in events.
/// `connect_target` is the hostname/address for `transport::connect()`.
async fn relay_task(
    relay_key: String,
    connect_target: String,
    mut cmd_rx: mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) {
    let node = &*super::server::NODE_NAME;
    let our_name = &*SERVER_NAME;
    let base_relay_nick = format!("{node}~relay");
    let our_suffix = format!("@{our_name}");
    // relay_key is used in events; connect_target is used for transport.
    // Alias for backward compat with log and event field names.
    let remote_host = relay_key;

    let mut consecutive_failures: u32 = 0;
    let mut saved_mesh_hello: Option<String> = None;
    // Peer identity — set once MESH HELLO is received. Threaded into
    // subsequent events so handlers can do O(1) lookup by mesh_key.
    let mut remote_mesh_key: Option<String> = None;
    // When true, don't reset consecutive_failures on next successful connect
    // (self-connection via anycast — TCP connect succeeds but MESH HELLO detects
    // same node, so we need escalating backoff not constant 2s retries).
    let mut self_connect_backoff = false;

    'reconnect: loop {
    let mut relay_nick = base_relay_nick.clone();

    let (stream, relay_peer_addr) = match transport::connect(&connect_target, &transport_config).await {
        Ok(r) => {
            if self_connect_backoff {
                self_connect_backoff = false;
                // Don't reset — let backoff escalate across self-connections.
            } else {
                consecutive_failures = 0;
            }
            (r.stream, r.peer_addr)
        }
        Err(e) => {
            consecutive_failures += 1;
            // Log at warn for first few failures, then demote to debug to
            // avoid log spam for persistently-unreachable peers.
            if consecutive_failures <= 3 {
                warn!(%remote_host, %connect_target, attempt = consecutive_failures,
                    "federation: connect failed, will retry: {e}");
            } else if consecutive_failures % 30 == 0 {
                warn!(%remote_host, %connect_target, attempt = consecutive_failures,
                    "federation: still failing to connect: {e}");
            }
            if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
                return;
            }
            continue 'reconnect;
        }
    };

    info!(%remote_host, %connect_target, "federation: connected");
    let mut framed = Framed::new(stream, IrcCodec::default());

    // Register on remote.
    if framed
        .send(Message {
            prefix: None,
            command: "NICK".into(),
            params: vec![relay_nick.clone()],
        })
        .await
        .is_err()
        || framed
            .send(Message {
                prefix: None,
                command: "USER".into(),
                params: vec![
                    "relay".into(),
                    "0".into(),
                    "*".into(),
                    format!("Lagoon Federation Relay from {our_name}"),
                ],
            })
            .await
            .is_err()
    {
        consecutive_failures += 1;
        warn!(remote_host, attempt = consecutive_failures,
            "federation: registration send failed, will retry");
        if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
            return;
        }
        continue 'reconnect;
    }

    info!(remote_host, "federation: registration sent, waiting for 001");
    let mut registered = false;
    // remote_channel → per-channel task state.
    let mut channels: HashMap<String, TaskChannel> = HashMap::new();
    // Commands received before registration completes.
    let mut pre_reg_cmds: Vec<RelayCommand> = Vec::new();

    // Re-queue saved MESH HELLO so it's sent after registration on reconnection.
    if let Some(ref json) = saved_mesh_hello {
        pre_reg_cmds.push(RelayCommand::MeshHello { json: json.clone() });
    }

    // Keepalive: send PING every 30s to prevent proxy idle timeouts (Cloudflare: 60s).
    // Also used for PONG-based liveness detection (safety net for WebSocket paths
    // where TCP keepalive can't be set).
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    // Skip the first immediate tick.
    keepalive.tick().await;
    let mut last_pong = tokio::time::Instant::now();
    let mut last_ping_sent = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if registered {
                    // 3 missed PINGs (30s × 3 = 90s) without a PONG → dead.
                    // TCP keepalive catches most cases in ~8s; this is the
                    // safety net for WebSocket connections and app-level hangs.
                    if last_pong.elapsed() > std::time::Duration::from_secs(90) {
                        warn!(remote_host, elapsed = ?last_pong.elapsed(),
                            "federation: peer unresponsive (no PONG), disconnecting");
                        break;
                    }
                    last_ping_sent = tokio::time::Instant::now();
                    let ping = Message {
                        prefix: None,
                        command: "PING".into(),
                        params: vec![our_name.to_string()],
                    };
                    if framed.send(ping).await.is_err() {
                        break;
                    }
                }
            }
            frame = framed.next() => {
                let msg = match frame {
                    Some(Ok(msg)) => msg,
                    Some(Err(e)) => {
                        warn!(remote_host, "federation: parse error: {e}");
                        break;
                    }
                    None => {
                        info!(remote_host, "federation: remote closed connection");
                        break;
                    }
                };

                match msg.command.as_str() {
                    "001" if !registered => {
                        registered = true;
                        info!(remote_host, "federation: registered on remote");
                        // Process any queued commands.
                        for cmd in pre_reg_cmds.drain(..) {
                            match cmd {
                                RelayCommand::JoinChannel { remote_channel, local_channel } => {
                                    channels.insert(remote_channel.clone(), TaskChannel {
                                        local_channel,
                                        joined: false,
                                        pending: Vec::new(),
                                    });
                                    let join_msg = Message {
                                        prefix: None,
                                        command: "JOIN".into(),
                                        params: vec![remote_channel],
                                    };
                                    if framed.send(join_msg).await.is_err() {
                                        break;
                                    }
                                }
                                RelayCommand::MeshHello { json } => {
                                    let mesh_msg = Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["HELLO".into(), json],
                                    };
                                    if framed.send(mesh_msg).await.is_err() {
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    "PING" => {
                        let token = msg.params.first().cloned().unwrap_or_default();
                        let pong = Message {
                            prefix: None,
                            command: "PONG".into(),
                            params: vec![relay_nick.clone(), token],
                        };
                        if framed.send(pong).await.is_err() {
                            break;
                        }
                    }

                    "PONG" => {
                        last_pong = tokio::time::Instant::now();
                        // PoLP: measure IRC-layer RTT from PING→PONG round-trip.
                        let rtt_ms = last_ping_sent.elapsed().as_secs_f64() * 1000.0;
                        info!(remote_host, rtt_ms, "polp: measured RTT");
                        let _ = event_tx.send(RelayEvent::LatencyMeasured {
                            remote_host: remote_host.clone(),
                            rtt_ms,
                            mesh_key: remote_mesh_key.clone(),
                        });
                    }

                    "JOIN" => {
                        if let Some(prefix) = &msg.prefix {
                            let nick = prefix.split('!').next().unwrap_or(prefix);
                            let chan = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                            if nick == relay_nick {
                                // Our own JOIN echo — mark channel as joined.
                                if let Some(tc) = channels.get_mut(chan) {
                                    if !tc.joined {
                                        tc.joined = true;
                                        info!(remote_host, local_channel = %tc.local_channel,
                                            "federation: joined {chan}");
                                        let _ = event_tx.send(RelayEvent::Connected {
                                            local_channel: tc.local_channel.clone(),
                                        });
                                        // Replay buffered commands for this channel.
                                        for cmd in tc.pending.drain(..) {
                                            if !send_frelay(&mut framed, cmd, our_name).await {
                                                break;
                                            }
                                        }
                                    }
                                }
                            } else if !nick.ends_with(&our_suffix)
                                && !is_relay_nick(nick)
                            {
                                if let Some(tc) = channels.get(chan) {
                                    let _ = event_tx.send(RelayEvent::RemoteJoin {
                                        local_channel: tc.local_channel.clone(),
                                        remote_nick: nick.to_string(),
                                        remote_host: remote_host.clone(),
                                    });
                                }
                            }
                        }
                    }

                    "PRIVMSG" => {
                        if let Some(prefix) = &msg.prefix {
                            let nick = prefix.split('!').next().unwrap_or(prefix);
                            if nick != relay_nick
                                && !nick.ends_with(&our_suffix)
                                && !is_relay_nick(nick)
                            {
                                let chan = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                                if let Some(tc) = channels.get(chan) {
                                    if let Some(text) = msg.params.get(1) {
                                        let _ = event_tx.send(RelayEvent::RemotePrivmsg {
                                            local_channel: tc.local_channel.clone(),
                                            remote_nick: nick.to_string(),
                                            remote_host: remote_host.clone(),
                                            text: text.clone(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    "PART" => {
                        if let Some(prefix) = &msg.prefix {
                            let nick = prefix.split('!').next().unwrap_or(prefix);
                            if nick != relay_nick
                                && !nick.ends_with(&our_suffix)
                                && !is_relay_nick(nick)
                            {
                                let chan = msg.params.first().map(|s| s.as_str()).unwrap_or("");
                                if let Some(tc) = channels.get(chan) {
                                    let reason = msg.params.get(1).cloned().unwrap_or_default();
                                    let _ = event_tx.send(RelayEvent::RemotePart {
                                        local_channel: tc.local_channel.clone(),
                                        remote_nick: nick.to_string(),
                                        remote_host: remote_host.clone(),
                                        reason,
                                    });
                                }
                            }
                        }
                    }

                    "QUIT" => {
                        if let Some(prefix) = &msg.prefix {
                            let nick = prefix.split('!').next().unwrap_or(prefix);
                            if nick != relay_nick
                                && !nick.ends_with(&our_suffix)
                                && !is_relay_nick(nick)
                            {
                                let reason = msg.params.first().cloned().unwrap_or_default();
                                // QUIT affects all channels this user was in.
                                for tc in channels.values() {
                                    let _ = event_tx.send(RelayEvent::RemotePart {
                                        local_channel: tc.local_channel.clone(),
                                        remote_nick: nick.to_string(),
                                        remote_host: remote_host.clone(),
                                        reason: reason.clone(),
                                    });
                                }
                            }
                        }
                    }

                    "353" => {
                        // NAMES reply: channel = params[2], names = params[3].
                        if let (Some(chan), Some(names_str)) =
                            (msg.params.get(2), msg.params.get(3))
                        {
                            if let Some(tc) = channels.get(chan.as_str()) {
                                let nicks: Vec<String> = names_str
                                    .split_whitespace()
                                    .map(|n| {
                                        n.trim_start_matches(['~', '&', '@', '%', '+'])
                                            .to_string()
                                    })
                                    .filter(|n| {
                                        n != &relay_nick
                                            && !n.ends_with(&our_suffix)
                                            && !is_relay_nick(n)
                                    })
                                    .collect();
                                let _ = event_tx.send(RelayEvent::RemoteNames {
                                    local_channel: tc.local_channel.clone(),
                                    remote_host: remote_host.clone(),
                                    nicks,
                                });
                            }
                        }
                    }

                    "MESH" => {
                        // MESH HELLO <json>
                        // MESH PEERS <json>
                        // MESH TOPOLOGY <json>
                        if let Some(sub_cmd) = msg.params.first() {
                            let json = msg.params.get(1).cloned().unwrap_or_default();
                            match sub_cmd.as_str() {
                                "HELLO" => {
                                    if let Ok(hello) = serde_json::from_str::<MeshHelloPayload>(&json) {
                                        // Backfill site_name/node_name for old peers
                                        // that don't send these fields yet.
                                        let site_name = if hello.site_name.is_empty() {
                                            super::server::derive_site_name(&hello.server_name)
                                        } else {
                                            hello.site_name
                                        };
                                        let node_name = if hello.node_name.is_empty() {
                                            super::server::derive_node_name(&hello.server_name)
                                        } else {
                                            hello.node_name
                                        };
                                        // Store mesh_key for this relay so subsequent
                                        // events can carry it (O(1) peer lookup).
                                        let mkey = format!("{site_name}/{node_name}");
                                        remote_mesh_key = Some(mkey);
                                        let _ = event_tx.send(RelayEvent::MeshHello {
                                            remote_host: remote_host.clone(),
                                            peer_id: hello.peer_id,
                                            server_name: hello.server_name,
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
                                            ygg_peer_uri: hello.ygg_peer_uri,
                                            relay_peer_addr,
                                        });
                                    } else {
                                        warn!(remote_host, "mesh: invalid HELLO payload");
                                    }
                                }
                                "PEERS" => {
                                    if let Ok(peers) = serde_json::from_str::<Vec<MeshPeerInfo>>(&json) {
                                        let _ = event_tx.send(RelayEvent::MeshPeers {
                                            remote_host: remote_host.clone(),
                                            peers,
                                        });
                                    }
                                }
                                "TOPOLOGY" => {
                                    let _ = event_tx.send(RelayEvent::MeshTopology {
                                        remote_host: remote_host.clone(),
                                        json,
                                    });
                                }
                                "VDFPROOF_REQ" => {
                                    let _ = event_tx.send(RelayEvent::MeshVdfProofReq {
                                        remote_host: remote_host.clone(),
                                    });
                                }
                                "VDFPROOF" => {
                                    let _ = event_tx.send(RelayEvent::MeshVdfProof {
                                        remote_host: remote_host.clone(),
                                        proof_json: json,
                                        mesh_key: remote_mesh_key.clone(),
                                    });
                                }
                                "SYNC" => {
                                    let _ = event_tx.send(RelayEvent::MeshSync {
                                        remote_host: remote_host.clone(),
                                    });
                                }
                                "GOSSIP" => {
                                    let _ = event_tx.send(RelayEvent::GossipReceive {
                                        remote_host: remote_host.clone(),
                                        message_json: json,
                                    });
                                }
                                "GOSSIP_SPORE" => {
                                    let _ = event_tx.send(RelayEvent::GossipSpore {
                                        remote_host: remote_host.clone(),
                                        spore_json: json,
                                    });
                                }
                                "GOSSIP_DIFF" => {
                                    let _ = event_tx.send(RelayEvent::GossipDiff {
                                        remote_host: remote_host.clone(),
                                        messages_json: json,
                                    });
                                }
                                "LATENCY_HAVE" => {
                                    let _ = event_tx.send(RelayEvent::LatencyHaveList {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                "LATENCY_DELTA" => {
                                    let _ = event_tx.send(RelayEvent::LatencyProofDelta {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                _ => {}
                            }
                        }
                    }

                    "433" => {
                        warn!(remote_host, "federation: nick collision, retrying with suffix");
                        relay_nick = format!("{relay_nick}_");
                        let nick_msg = Message {
                            prefix: None,
                            command: "NICK".into(),
                            params: vec![relay_nick.clone()],
                        };
                        if framed.send(nick_msg).await.is_err() {
                            break;
                        }
                    }

                    _ => {}
                }
            }

            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    RelayCommand::Shutdown => {
                        let quit = Message {
                            prefix: None,
                            command: "QUIT".into(),
                            params: vec!["Federation relay shutting down".into()],
                        };
                        let _ = framed.send(quit).await;
                        return;
                    }
                    RelayCommand::Reconnect => {
                        info!(remote_host, "federation: reconnect requested (self-connection via anycast)");
                        self_connect_backoff = true; // Escalate backoff across retries
                        let quit = Message {
                            prefix: None,
                            command: "QUIT".into(),
                            params: vec!["Reconnecting".into()],
                        };
                        let _ = framed.send(quit).await;
                        break; // Break inner loop → reconnect loop with backoff
                    }
                    RelayCommand::JoinChannel { remote_channel, local_channel } => {
                        if registered {
                            channels.insert(remote_channel.clone(), TaskChannel {
                                local_channel,
                                joined: false,
                                pending: Vec::new(),
                            });
                            let join_msg = Message {
                                prefix: None,
                                command: "JOIN".into(),
                                params: vec![remote_channel],
                            };
                            if framed.send(join_msg).await.is_err() {
                                break;
                            }
                        } else {
                            pre_reg_cmds.push(RelayCommand::JoinChannel {
                                remote_channel,
                                local_channel,
                            });
                        }
                    }
                    RelayCommand::PartChannel { remote_channel } => {
                        channels.remove(&remote_channel);
                        if registered {
                            let part_msg = Message {
                                prefix: None,
                                command: "PART".into(),
                                params: vec![remote_channel, "No more local users".into()],
                            };
                            let _ = framed.send(part_msg).await;
                        }
                    }
                    RelayCommand::MeshHello { json } => {
                        saved_mesh_hello = Some(json.clone());
                        if registered {
                            let mesh_msg = Message {
                                prefix: None,
                                command: "MESH".into(),
                                params: vec!["HELLO".into(), json],
                            };
                            if framed.send(mesh_msg).await.is_err() {
                                break;
                            }
                        } else {
                            pre_reg_cmds.push(RelayCommand::MeshHello { json });
                        }
                    }
                    RelayCommand::SendMesh(mesh_msg) => {
                        if registered {
                            let irc_msg = mesh_message_to_irc(&mesh_msg);
                            if framed.send(irc_msg).await.is_err() {
                                break;
                            }
                        }
                    }
                    RelayCommand::Raw(raw_msg) => {
                        if registered {
                            if framed.send(raw_msg).await.is_err() {
                                break;
                            }
                        }
                        // If not registered, silently drop — DMs require an active relay.
                    }
                    other => {
                        // Privmsg, Join, or Part — route to a specific channel.
                        let remote_channel = match &other {
                            RelayCommand::Privmsg { remote_channel, .. } => remote_channel,
                            RelayCommand::Join { remote_channel, .. } => remote_channel,
                            RelayCommand::Part { remote_channel, .. } => remote_channel,
                            _ => unreachable!(),
                        };
                        if let Some(tc) = channels.get_mut(remote_channel.as_str()) {
                            if tc.joined {
                                if !send_frelay(&mut framed, other, our_name).await {
                                    break;
                                }
                            } else {
                                tc.pending.push(other);
                            }
                        }
                    }
                }
            }
        }
    }

    // Inner loop broke — connection lost. Try to reconnect.
    consecutive_failures += 1;
    info!(remote_host, attempt = consecutive_failures,
        "federation: connection lost, will reconnect");
    if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
        return;
    }

    } // end 'reconnect loop
}

/// JSON payload for MESH HELLO.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MeshHelloPayload {
    pub peer_id: String,
    pub server_name: String,
    pub public_key_hex: String,
    /// Claimed SPIRAL slot index (None = unclaimed fresh node).
    #[serde(default)]
    pub spiral_index: Option<u64>,
    /// VDF genesis hash (hex-encoded, derived from public key).
    #[serde(default)]
    pub vdf_genesis: Option<String>,
    /// VDF current chain tip hash (hex-encoded).
    #[serde(default)]
    pub vdf_hash: Option<String>,
    /// VDF total steps (cumulative across sessions).
    #[serde(default)]
    pub vdf_step: Option<u64>,
    /// This node's Yggdrasil IPv6 address (None if no Yggdrasil).
    #[serde(default)]
    pub yggdrasil_addr: Option<String>,
    /// Site identity for supernode clustering.
    #[serde(default)]
    pub site_name: String,
    /// Node identity within site.
    #[serde(default)]
    pub node_name: String,
    /// Resonance credit — how precisely this node tracks its target VDF rate [0, 1].
    #[serde(default)]
    pub vdf_resonance_credit: Option<f64>,
    /// Actual measured VDF tick rate (Hz, exponential moving average).
    #[serde(default)]
    pub vdf_actual_rate_hz: Option<f64>,
    /// Yggdrasil peer URI for overlay peering (e.g. `tcp://[200:xxxx::]:9443`).
    #[serde(default)]
    pub ygg_peer_uri: Option<String>,
}

/// Build a native `wire::HelloPayload` from server state (use inside read lock).
///
/// Public so that the inbound mesh handler (lagoon-web) can send our Hello.
pub fn build_wire_hello(st: &super::server::ServerState) -> HelloPayload {
    let hp = build_hello_payload(st);
    HelloPayload {
        peer_id: hp.peer_id,
        server_name: hp.server_name,
        public_key_hex: hp.public_key_hex,
        spiral_index: hp.spiral_index,
        vdf_genesis: hp.vdf_genesis,
        vdf_hash: hp.vdf_hash,
        vdf_step: hp.vdf_step,
        yggdrasil_addr: hp.yggdrasil_addr,
        site_name: hp.site_name,
        node_name: hp.node_name,
        vdf_resonance_credit: hp.vdf_resonance_credit,
        vdf_actual_rate_hz: hp.vdf_actual_rate_hz,
        ygg_peer_uri: hp.ygg_peer_uri,
    }
}

/// Build a MeshHelloPayload from server state (use inside read lock).
fn build_hello_payload(st: &super::server::ServerState) -> MeshHelloPayload {
    let (vdf_genesis, vdf_hash, vdf_step, vdf_resonance_credit, vdf_actual_rate_hz) = st
        .mesh
        .vdf_state_rx
        .as_ref()
        .map(|rx| {
            let vdf = rx.borrow();
            let (credit, rate) = vdf
                .resonance
                .as_ref()
                .map(|r| (Some(r.credit), Some(r.actual_rate_hz)))
                .unwrap_or((None, None));
            (
                Some(hex::encode(vdf.genesis)),
                Some(hex::encode(vdf.current_hash)),
                Some(vdf.total_steps),
                credit,
                rate,
            )
        })
        .unwrap_or((None, None, None, None, None));

    // Ygg overlay address (for identity/routing, NOT for peering).
    let yggdrasil_addr = st
        .transport_config
        .ygg_node
        .as_ref()
        .map(|n| n.address().to_string())
        .or_else(|| transport::detect_yggdrasil_addr().map(|a| a.to_string()));
    // Ygg peer URI = UNDERLAY address.  You don't tunnel Ygg through Ygg.
    // The underlay is the real network (public internet, Fly 6PN, LAN).
    let ygg_peer_uri = transport::detect_underlay_addr().map(|addr| match addr {
        std::net::IpAddr::V6(v6) => format!("tcp://[{v6}]:9443"),
        std::net::IpAddr::V4(v4) => format!("tcp://{v4}:9443"),
    });

    MeshHelloPayload {
        peer_id: st.lens.peer_id.clone(),
        server_name: st.lens.server_name.clone(),
        public_key_hex: st.lens.public_key_hex.clone(),
        spiral_index: st.lens.spiral_index,
        vdf_genesis,
        vdf_hash,
        vdf_step,
        yggdrasil_addr,
        site_name: st.lens.site_name.clone(),
        node_name: st.lens.node_name.clone(),
        vdf_resonance_credit,
        vdf_actual_rate_hz,
        ygg_peer_uri,
    }
}

/// Spawn the mesh connector — proactively connects to all LAGOON_PEERS
/// and sends MESH HELLO to establish identity exchange.
///
/// Mesh connections are metadata-only — they exchange MESH commands but
/// create NO channels and inject NO users into rooms.
pub fn spawn_mesh_connector(state: SharedState, transport_config: Arc<TransportConfig>) {
    let peers: Vec<String> = transport_config.peers.keys().cloned().collect();
    if peers.is_empty() {
        // No peers configured. If we haven't claimed a SPIRAL position,
        // claim origin (slot 0) — we're the first node in the mesh.
        tokio::spawn(async move {
            let mut st = state.write().await;
            if !st.mesh.spiral.is_claimed() {
                let our_pid = st.lens.peer_id.clone();
                let idx = st.mesh.spiral.claim_position(&our_pid);
                info!(
                    spiral_index = idx.value(),
                    "mesh: claimed SPIRAL slot (no peers configured)"
                );
                let mut updated_lens = (*st.lens).clone();
                updated_lens.spiral_index = Some(idx.value());
                if let Some(ref rx) = st.mesh.vdf_state_rx {
                    updated_lens.vdf_total_steps = rx.borrow().total_steps;
                }
                super::lens::persist_identity(&st.data_dir, &updated_lens);
                st.lens = std::sync::Arc::new(updated_lens);
            }
        });
        return;
    }

    info!(peer_count = peers.len(), "mesh: initiating connections to peers");

    tokio::spawn(async move {
        let st = state.read().await;
        let hello_json = serde_json::to_string(&build_hello_payload(&st))
            .unwrap_or_default();
        let event_tx = st.federation_event_tx.clone();
        let tc = st.transport_config.clone();
        drop(st);

        for peer_host in peers {
            // Derive node_name for relay keying; peer_host (FQDN) for transport.
            let node = derive_node_name(&peer_host);

            // Skip self — don't connect to our own node.
            if node == *NODE_NAME {
                info!(peer = %peer_host, node = %node, "mesh: skipping self");
                continue;
            }

            let mut st = state.write().await;

            // Skip if already connected (e.g. from a user JOIN).
            if st.federation.relays.contains_key(&node) {
                // Send MESH HELLO on existing relay.
                if let Some(relay) = st.federation.relays.get(&node) {
                    let _ = relay.outgoing_tx.send(RelayCommand::MeshHello {
                        json: hello_json.clone(),
                    });
                }
                continue;
            }

            // Skip defederated peers.
            if st.mesh.defederated.contains(&peer_host) {
                info!(peer = %peer_host, "mesh: skipping defederated peer");
                continue;
            }

            info!(peer = %peer_host, node = %node, "mesh: connecting");

            let (cmd_tx, task_handle) = spawn_relay(
                node.clone(),
                peer_host.clone(),
                event_tx.clone(),
                Arc::clone(&tc),
            );

            // Send MESH HELLO (will be queued until registered).
            let _ = cmd_tx.send(RelayCommand::MeshHello {
                json: hello_json.clone(),
            });

            st.federation.relays.insert(
                node.clone(),
                RelayHandle {
                    outgoing_tx: cmd_tx,
                    remote_host: node,
                    channels: HashMap::new(),
                    task_handle,
                    mesh_connected: true,
                    is_bootstrap: true,
                    last_rtt_ms: None,
                    remote_node_name: None,
                },
            );
        }
    });
}

/// Translate a native `MeshMessage` into an IRC `MESH {subcommand} {json}` line.
///
/// Temporary backward compatibility for the old IRC-framed relay_task.
/// This is deleted when the relay_task is rewritten for native WebSocket.
fn mesh_message_to_irc(msg: &MeshMessage) -> Message {
    let (sub, payload) = match msg {
        MeshMessage::Hello(hello) => {
            ("HELLO".into(), serde_json::to_string(hello).unwrap_or_default())
        }
        MeshMessage::Peers { peers } => {
            ("PEERS".into(), serde_json::to_string(peers).unwrap_or_default())
        }
        MeshMessage::VdfProofReq => ("VDFPROOF_REQ".into(), String::new()),
        MeshMessage::VdfProof { proof } => {
            ("VDFPROOF".into(), proof.to_string())
        }
        MeshMessage::Sync => ("SYNC".into(), String::new()),
        MeshMessage::Gossip { message } => {
            ("GOSSIP".into(), message.to_string())
        }
        MeshMessage::GossipSpore { data } => ("GOSSIP_SPORE".into(), data.clone()),
        MeshMessage::GossipDiff { data } => ("GOSSIP_DIFF".into(), data.clone()),
        MeshMessage::LatencyHave { data } => ("LATENCY_HAVE".into(), data.clone()),
        MeshMessage::LatencyDelta { data } => ("LATENCY_DELTA".into(), data.clone()),
    };
    let mut params = vec![sub];
    if !payload.is_empty() {
        params.push(payload);
    }
    Message {
        prefix: None,
        command: "MESH".into(),
        params,
    }
}

/// Send a FRELAY command to the remote server. Returns true on success.
async fn send_frelay(
    framed: &mut Framed<transport::RelayStream, IrcCodec>,
    cmd: RelayCommand,
    our_name: &str,
) -> bool {
    let msg = match cmd {
        RelayCommand::Privmsg { nick, remote_channel, text } => Message {
            prefix: None,
            command: "FRELAY".into(),
            params: vec!["PRIVMSG".into(), nick, our_name.to_string(), remote_channel, text],
        },
        RelayCommand::Join { nick, remote_channel } => Message {
            prefix: None,
            command: "FRELAY".into(),
            params: vec!["JOIN".into(), nick, our_name.to_string(), remote_channel],
        },
        RelayCommand::Part { nick, remote_channel, reason } => Message {
            prefix: None,
            command: "FRELAY".into(),
            params: vec!["PART".into(), nick, our_name.to_string(), remote_channel, reason],
        },
        _ => return true,
    };
    framed.send(msg).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_federated_channel() {
        assert_eq!(
            parse_federated_channel("#lagoon:per.lagun.co"),
            Some(("#lagoon", "per.lagun.co"))
        );
    }

    #[test]
    fn parse_ampersand_channel() {
        assert_eq!(
            parse_federated_channel("&local:nyc.lagun.co"),
            Some(("&local", "nyc.lagun.co"))
        );
    }

    #[test]
    fn parse_local_channel_returns_none() {
        assert_eq!(parse_federated_channel("#lagoon"), None);
    }

    #[test]
    fn parse_empty_host_returns_none() {
        assert_eq!(parse_federated_channel("#lagoon:"), None);
    }

    #[test]
    fn parse_host_without_dot_returns_none() {
        assert_eq!(parse_federated_channel("#lagoon:localhost"), None);
    }

    #[test]
    fn parse_no_channel_prefix_returns_none() {
        assert_eq!(parse_federated_channel("lagoon:per.lagun.co"), None);
    }

    #[test]
    fn parse_bare_prefix_returns_none() {
        assert_eq!(parse_federated_channel("#:per.lagun.co"), None);
    }

    #[test]
    fn parse_ipv6_host() {
        assert_eq!(
            parse_federated_channel("#chat:200.fcf.205.9dec"),
            Some(("#chat", "200.fcf.205.9dec"))
        );
    }

    #[test]
    fn parse_deep_subdomain() {
        assert_eq!(
            parse_federated_channel("#dev:staging.lon.lagun.co"),
            Some(("#dev", "staging.lon.lagun.co"))
        );
    }

    #[test]
    fn is_relay_nick_matches_base() {
        assert!(is_relay_nick("lon~relay"));
    }

    #[test]
    fn is_relay_nick_matches_collision() {
        assert!(is_relay_nick("lon~relay_"));
        assert!(is_relay_nick("lon~relay__"));
    }

    #[test]
    fn is_relay_nick_rejects_normal() {
        assert!(!is_relay_nick("zorlin"));
        assert!(!is_relay_nick("relay_bot"));
        assert!(!is_relay_nick("LagoonBot"));
    }
}
