/// Channel federation — Matrix-style `#room:server` relay over Yggdrasil mesh.
///
/// When a user joins `#lagoon:per.lagun.co`, the local server connects to
/// `per.lagun.co:6667` as an IRC client, joins `#lagoon`, and relays messages
/// bidirectionally. One relay connection per remote host — multiple federated
/// channels to the same host share a single TCP connection.
///
/// Also handles MESH protocol for topology exchange between peers.
use std::collections::{HashMap, HashSet};
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
use base64::Engine as _;

/// Peers with VDF steps below this fraction of our own are eviction candidates.
const VDF_EVICTION_RATIO: f64 = 0.1;
/// Peers not seen for this many seconds are considered stale for eviction.
/// ~3 VDF rounds (each ~8s) — pods don't reconnect, so clean up fast.
const VDF_STALE_SECS: u64 = 24;
/// Maximum disconnected peers retained per SITE_NAME before dedup eviction.
const MAX_DISCONNECTED_PER_SITE: usize = 5;
/// Maximum safe JSON payload bytes for a single IRC MESH message.
/// IRC max line is 8191; reserve room for "MESH PEERS " prefix + \r\n.
const MAX_MESH_PAYLOAD: usize = 7000;

/// Send a list of serializable items as MESH messages, splitting into chunks
/// if the JSON payload would exceed `MAX_MESH_PAYLOAD`.
fn send_chunked_mesh<T: serde::Serialize>(
    relay: &RelayHandle,
    subcommand: &str,
    items: &[T],
) {
    if items.is_empty() {
        return;
    }
    // Fast path: try everything at once.
    if let Ok(json) = serde_json::to_string(items) {
        if json.len() <= MAX_MESH_PAYLOAD {
            let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                prefix: None,
                command: "MESH".into(),
                params: vec![subcommand.into(), json],
            }));
            return;
        }
    }
    // Slow path: accumulate items into size-capped chunks.
    let mut chunk: Vec<&T> = Vec::new();
    let mut chunk_bytes: usize = 2; // "[]"
    for item in items {
        let item_json = match serde_json::to_string(item) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let added = if chunk.is_empty() { item_json.len() } else { item_json.len() + 1 };
        if chunk_bytes + added > MAX_MESH_PAYLOAD && !chunk.is_empty() {
            if let Ok(json) = serde_json::to_string(&chunk) {
                let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                    prefix: None,
                    command: "MESH".into(),
                    params: vec![subcommand.into(), json],
                }));
            }
            chunk.clear();
            chunk_bytes = 2;
        }
        chunk.push(item);
        chunk_bytes += added;
    }
    if !chunk.is_empty() {
        if let Ok(json) = serde_json::to_string(&chunk) {
            let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                prefix: None,
                command: "MESH".into(),
                params: vec![subcommand.into(), json],
            }));
        }
    }
}

/// Evict excess disconnected peers per SITE_NAME, keeping the most recently
/// seen ones up to `MAX_DISCONNECTED_PER_SITE`. Returns evicted peer IDs.
fn dedup_peers_per_site(
    mesh: &mut super::server::MeshState,
    our_peer_id: &str,
) -> Vec<String> {
    // Group disconnected peer IDs by site_name.
    let mut by_site: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for (peer_id, peer) in mesh.known_peers.iter() {
        if peer_id == our_peer_id {
            continue;
        }
        let connected = mesh.connections.get(peer_id).copied()
            == Some(MeshConnectionState::Connected);
        if connected {
            continue;
        }
        by_site
            .entry(peer.site_name.clone())
            .or_default()
            .push((peer_id.clone(), peer.last_seen));
    }

    let mut evicted = Vec::new();
    for (_site, mut peers) in by_site {
        if peers.len() <= MAX_DISCONNECTED_PER_SITE {
            continue;
        }
        // Sort by last_seen descending — keep the freshest.
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        for (peer_id, _) in peers.into_iter().skip(MAX_DISCONNECTED_PER_SITE) {
            if let Some(peer) = mesh.known_peers.remove(&peer_id) {
                info!(
                    peer_id = %peer_id,
                    site_name = %peer.site_name,
                    last_seen = peer.last_seen,
                    "mesh: evicting excess disconnected peer for site dedup"
                );
                mesh.spiral.remove_peer(&peer_id);
            }
            evicted.push(peer_id);
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
    /// Send MESH HELLO after registration.
    MeshHello { json: String },
    /// Shut down the relay connection entirely.
    Shutdown,
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
        lens_id: String,
        server_name: String,
        public_key_hex: String,
        spiral_index: Option<u64>,
        vdf_genesis: Option<String>,
        vdf_hash: Option<String>,
        vdf_step: Option<u64>,
        yggdrasil_addr: Option<String>,
        site_name: String,
        node_name: String,
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
/// Query Yggdrasil metrics if admin socket is available (async, non-blocking).
async fn refresh_ygg_metrics(
    socket: &Option<String>,
) -> Option<Vec<super::yggdrasil::YggPeer>> {
    let path = socket.as_ref()?;
    match super::yggdrasil::query_peers(path).await {
        Ok(peers) => Some(peers),
        Err(e) => {
            tracing::debug!("yggdrasil admin socket query failed: {e}");
            None
        }
    }
}

pub fn spawn_event_processor(
    state: SharedState,
    mut event_rx: mpsc::UnboundedReceiver<RelayEvent>,
) {
    tokio::spawn(async move {
        // Detect Yggdrasil admin socket once at startup.
        let ygg_socket = super::yggdrasil::detect_admin_socket();

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
                    let ygg_peers = refresh_ygg_metrics(&ygg_socket).await;

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

                    // Clean up relay handle.
                    if let Some(relay) = st.federation.relays.remove(&remote_host) {
                        relay.task_handle.abort();
                    }

                    // Find and remove connection state by lens_id.
                    let disconnected_ids: Vec<String> = st
                        .mesh
                        .known_peers
                        .iter()
                        .filter(|(_, p)| p.node_name == remote_host)
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
                    lens_id,
                    server_name,
                    public_key_hex,
                    spiral_index,
                    vdf_genesis,
                    vdf_hash,
                    vdf_step,
                    yggdrasil_addr,
                    site_name,
                    node_name,
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

                    // Verify PeerID matches public key.
                    if let Ok(pubkey_bytes) = hex::decode(&public_key_hex) {
                        if pubkey_bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&pubkey_bytes);
                            if !lens::verify_peer_id(&lens_id, &key) {
                                warn!(
                                    remote_host,
                                    "mesh: rejected HELLO — PeerID doesn't match pubkey"
                                );
                                continue;
                            }
                        }
                    }

                    // Query Yggdrasil metrics BEFORE acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics(&ygg_socket).await;

                    let mut st = state.write().await;

                    // Update Ygg metrics store if we got data.
                    if let Some(peers) = ygg_peers {
                        st.mesh.ygg_metrics.update(peers);
                    }

                    // Detect self-connection (DNS alias, misconfigured peer, etc).
                    if lens_id == st.lens.peer_id {
                        warn!(
                            remote_host,
                            "mesh: self-connection detected — disconnecting"
                        );
                        if let Some(relay) = st.federation.relays.remove(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                        }
                        st.mesh.connections.remove(&lens_id);
                        st.notify_topology_change();
                        continue;
                    }

                    // Check defederation.
                    if st.mesh.defederated.contains(&lens_id)
                        || st.mesh.defederated.contains(&server_name)
                    {
                        warn!(
                            remote_host,
                            lens_id,
                            "mesh: rejected HELLO — peer is defederated"
                        );
                        continue;
                    }

                    info!(
                        remote_host,
                        lens_id,
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
                            lens_id = %lens_id,
                            vdf_step = step,
                            "mesh: peer VDF state"
                        );
                    }

                    st.mesh.known_peers.insert(
                        lens_id.clone(),
                        MeshPeerInfo {
                            lens_id: lens_id.clone(),
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
                        },
                    );
                    st.mesh
                        .connections
                        .insert(lens_id.clone(), MeshConnectionState::Connected);

                    // Register SPIRAL position if the peer has claimed one.
                    if let Some(idx) = spiral_index {
                        st.mesh.spiral.add_peer(
                            &lens_id,
                            citadel_topology::Spiral3DIndex::new(idx),
                        );
                    }

                    // Register peer with latency gossip + update SPIRAL neighbor set.
                    st.mesh.latency_gossip.register_peer(
                        lens_id.clone(), node_name.clone(),
                    );
                    let neighbors = st.mesh.spiral.neighbors().clone();
                    st.mesh.latency_gossip.set_spiral_neighbors(neighbors);

                    st.notify_topology_change();

                    // VDF slot eviction: scan for stale peers whose VDF work
                    // is below threshold. Event-driven — runs on every HELLO.
                    let our_vdf_step = st
                        .mesh
                        .vdf_state_rx
                        .as_ref()
                        .map(|rx| rx.borrow().total_steps)
                        .unwrap_or(0);

                    if our_vdf_step > 0 {
                        let eviction_threshold =
                            (our_vdf_step as f64 * VDF_EVICTION_RATIO) as u64;
                        let mut evicted = Vec::new();

                        for (peer_id, peer) in &st.mesh.known_peers {
                            // Skip self.
                            if *peer_id == st.lens.peer_id {
                                continue;
                            }
                            // Skip currently connected peers.
                            if st.mesh.connections.contains_key(peer_id) {
                                continue;
                            }
                            // Check VDF threshold (slotless peers have vdf_step=0,
                            // so they're evicted once stale — prevents ephemeral
                            // pod identities from accumulating without bound).
                            let peer_vdf = peer.vdf_step.unwrap_or(0);
                            if peer_vdf >= eviction_threshold {
                                continue;
                            }
                            // Check staleness.
                            if now.saturating_sub(peer.last_seen) < VDF_STALE_SECS {
                                continue;
                            }

                            evicted.push(peer_id.clone());
                        }

                        for peer_id in &evicted {
                            if let Some(peer) = st.mesh.known_peers.remove(peer_id) {
                                info!(
                                    peer_id,
                                    server_name = %peer.server_name,
                                    vdf_step = ?peer.vdf_step,
                                    last_seen = peer.last_seen,
                                    threshold = eviction_threshold,
                                    "mesh: evicting stale peer — VDF below threshold"
                                );
                                st.mesh.spiral.remove_peer(peer_id);
                                st.mesh.latency_gossip.remove_peer(peer_id);
                            }
                        }

                        if !evicted.is_empty() {
                            let neighbors = st.mesh.spiral.neighbors().clone();
                            st.mesh.latency_gossip.set_spiral_neighbors(neighbors);
                            st.notify_topology_change();
                        }
                    }

                    // Per-site dedup: cap disconnected peers per SITE_NAME.
                    let our_id = st.lens.peer_id.clone();
                    let site_evicted = dedup_peers_per_site(&mut st.mesh, &our_id);
                    if !site_evicted.is_empty() {
                        st.notify_topology_change();
                    }

                    // Connection reciprocity: if this peer connected to us and
                    // we don't have an outbound relay to them, establish one.
                    // This ensures bidirectional connectivity in the mesh.
                    // NOTE: must happen BEFORE sending MESH PEERS/TOPOLOGY/SPORE,
                    // because those sends go via st.federation.relays.
                    if !st.federation.relays.contains_key(&node_name) {
                        let should_connect = !st.mesh.spiral.is_claimed()
                            || st.full_telemetry
                            || st.mesh.spiral.is_neighbor(&lens_id);

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
                                .get(&lens_id)
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
                                },
                            );
                        }
                    }

                    // Send MESH PEERS to the newly connected peer (chunked).
                    // Uses the relay handle (which now exists after reciprocal connect above).
                    let peers_list: Vec<MeshPeerInfo> =
                        st.mesh.known_peers.values().cloned().collect();
                    if !peers_list.is_empty() {
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            send_chunked_mesh(relay, "PEERS", &peers_list);
                        }
                    }

                    // Send MESH LATENCY_HAVE — our proof SPORE for efficient delta sync.
                    // Replaces monolithic MESH TOPOLOGY which overflows at 10+ nodes.
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
                            let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                prefix: None,
                                command: "MESH".into(),
                                params: vec!["LATENCY_HAVE".into(), b64],
                            }));
                        }
                    }

                    // SPORE gossip catch-up: send our HaveList so the peer can
                    // diff and send us anything we missed while disconnected.
                    if super::gossip::is_cluster_peer(&SITE_NAME, &site_name) {
                        let our_spore = st.mesh.gossip.seen_messages();
                        if let Ok(spore_json) = serde_json::to_string(our_spore) {
                            if let Some(relay) = st.federation.relays.get(&remote_host) {
                                let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                    prefix: None,
                                    command: "MESH".into(),
                                    params: vec!["GOSSIP_SPORE".into(), spore_json],
                                }));
                                info!(
                                    remote_host,
                                    "gossip: sent SPORE HaveList to cluster peer for catch-up"
                                );
                            }
                        }
                    }
                }

                RelayEvent::MeshPeers {
                    remote_host,
                    peers,
                } => {
                    // Query Yggdrasil metrics before acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics(&ygg_socket).await;

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

                        if st.mesh.defederated.contains(&peer.lens_id)
                            || st.mesh.defederated.contains(&peer.server_name)
                        {
                            continue;
                        }
                        if peer.lens_id == st.lens.peer_id {
                            continue; // Don't add ourselves.
                        }

                        // Register SPIRAL position from gossiped peer info.
                        if let Some(idx) = peer.spiral_index {
                            st.mesh.spiral.add_peer(
                                &peer.lens_id,
                                citadel_topology::Spiral3DIndex::new(idx),
                            );
                        }

                        // Register with latency gossip (peer_id → node_name routing).
                        st.mesh.latency_gossip.register_peer(
                            peer.lens_id.clone(), peer.node_name.clone(),
                        );

                        if !st.mesh.known_peers.contains_key(&peer.lens_id) {
                            info!(
                                remote_host,
                                peer_id = %peer.lens_id,
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
                            st.mesh.known_peers.insert(peer.lens_id.clone(), peer);
                            changed = true;
                            new_peer_servers.push((peer_node_name, server_name, port, tls));
                        } else if let Some(existing) = st.mesh.known_peers.get_mut(&peer.lens_id) {
                            // Update telemetry if incoming data is fresher.
                            if peer.last_seen > existing.last_seen {
                                existing.last_seen = peer.last_seen;
                                existing.vdf_hash = peer.vdf_hash.clone();
                                existing.vdf_step = peer.vdf_step;
                                // SPIRAL slot: first-writer-wins.
                                if existing.spiral_index.is_none() && peer.spiral_index.is_some() {
                                    existing.spiral_index = peer.spiral_index;
                                    if let Some(idx) = peer.spiral_index {
                                        st.mesh.spiral.add_peer(
                                            &peer.lens_id,
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
                    let our_id = st.lens.peer_id.clone();
                    let site_evicted = dedup_peers_per_site(&mut st.mesh, &our_id);
                    if !site_evicted.is_empty() {
                        changed = true;
                        // Remove evicted peers from newly_discovered so we don't
                        // re-gossip entries that were just evicted.
                        newly_discovered.retain(|p| !site_evicted.contains(&p.lens_id));
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
                                send_chunked_mesh(relay, "PEERS", &newly_discovered);
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
                        let our_peer_id = st.lens.peer_id.clone();
                        let idx = st.mesh.spiral.claim_position(&our_peer_id);
                        info!(
                            spiral_index = idx.value(),
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
                            // to SPIRAL neighbors. Override: full_telemetry
                            // connects to ALL peers regardless of SPIRAL.
                            if spiral_active && !st.full_telemetry {
                                let is_neighbor = st.mesh.known_peers.values()
                                    .find(|p| p.node_name == node_name)
                                    .map(|p| st.mesh.spiral.is_neighbor(&p.lens_id))
                                    .unwrap_or(false);
                                if !is_neighbor {
                                    info!(
                                        peer = %node_name,
                                        "mesh: skipping non-SPIRAL-neighbor"
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
                            // how to reach it. If we have a Yggdrasil address,
                            // resolve() will use it directly — no DNS needed.
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
                                st.mesh.known_peers.values()
                                    .find(|p| p.node_name == **host)
                                    .map(|p| {
                                        st.mesh.spiral.is_neighbor(&p.lens_id)
                                            && p.yggdrasil_addr.is_some()
                                    })
                                    .unwrap_or(false)
                            });

                        if has_ygg_spiral_neighbor {
                            let to_prune: Vec<String> = st.federation.relays.iter()
                                .filter(|(_, relay)| relay.is_bootstrap)
                                .filter(|(host, _)| {
                                    st.mesh.known_peers.values()
                                        .find(|p| p.node_name == **host)
                                        .map(|p| !st.mesh.spiral.is_neighbor(&p.lens_id))
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

                    // --- General non-neighbor pruning (only when NOT full_telemetry) ---
                    // User-initiated relays (mesh_connected=false) are never pruned.
                    if st.mesh.spiral.is_claimed() && !st.full_telemetry {
                        let to_prune: Vec<String> = st.federation.relays.iter()
                            .filter(|(_, relay)| relay.mesh_connected && !relay.is_bootstrap)
                            .filter(|(host, _)| {
                                st.mesh.known_peers.values()
                                    .find(|p| p.node_name == **host)
                                    .map(|p| !st.mesh.spiral.is_neighbor(&p.lens_id))
                                    .unwrap_or(false)
                            })
                            .map(|(host, _)| host.clone())
                            .collect();

                        for host in to_prune {
                            info!(
                                peer = %host,
                                "mesh: disconnecting non-SPIRAL-neighbor relay"
                            );
                            if let Some(relay) = st.federation.relays.remove(&host) {
                                let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                            }
                        }
                    }
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
                            if let Ok(proof_json) = serde_json::to_string(&proof) {
                                if let Some(relay) = st.federation.relays.get(&remote_host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["VDFPROOF".into(), proof_json],
                                    }));
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
                } => {
                    // A peer sent us a ZK proof of their VDF chain.
                    match serde_json::from_str::<lagoon_vdf::VdfProof>(&proof_json) {
                        Ok(proof) => {
                            if proof.verify() {
                                info!(
                                    remote_host,
                                    steps = proof.steps,
                                    spiral_slot = ?proof.spiral_slot,
                                    genesis = lagoon_vdf::to_hex_short(&proof.genesis, 8),
                                    "mesh: VDF proof VERIFIED"
                                );
                            } else {
                                warn!(
                                    remote_host,
                                    "mesh: VDF proof FAILED verification"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(remote_host, error = %e, "mesh: invalid VDF proof JSON");
                        }
                    }
                }

                RelayEvent::MeshSync { remote_host } => {
                    // Query Ygg metrics before responding.
                    let ygg_peers = refresh_ygg_metrics(&ygg_socket).await;

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
                            send_chunked_mesh(relay, "PEERS", &peers);
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
                                if let Ok(json) = serde_json::to_string(msg) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["GOSSIP".into(), json],
                                    }));
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
                            for (host, relay) in &st.federation.relays {
                                if relay.mesh_connected && *host != remote_host {
                                    let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["GOSSIP".into(), message_json.clone()],
                                    }));
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
                                    let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["GOSSIP_DIFF".into(), batch_json],
                                    }));
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

                RelayEvent::LatencyMeasured { remote_host, rtt_ms } => {
                    let mut st = state.write().await;

                    // Store on relay handle (backward compat / direct lookup).
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        relay.last_rtt_ms = Some(rtt_ms);
                    }

                    // Find peer_id for this node_name so we can key the proof.
                    let peer_id = st.mesh.known_peers.iter()
                        .find(|(_, p)| p.node_name == remote_host)
                        .map(|(id, _)| id.clone());

                    if let Some(peer_id) = peer_id {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let our_peer_id = st.lens.peer_id.clone();
                        let edge = super::proof_store::ProofStore::edge_key(
                            &our_peer_id, &peer_id,
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

                        let from_peer_id = st.mesh.known_peers.iter()
                            .find(|(_, p)| p.node_name == remote_host)
                            .map(|(id, _)| id.clone())
                            .unwrap_or_default();

                        let our_spore = st.mesh.proof_store.spore();
                        let our_proof_data = st.mesh.proof_store.proof_data_for_gossip();

                        if let Some(action) = st.mesh.latency_gossip.on_have_list_received(
                            &from_peer_id,
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
        let sub = match &message {
            super::latency_gossip::SyncMessage::HaveList { .. } => "LATENCY_HAVE",
            super::latency_gossip::SyncMessage::ProofDelta { .. } => "LATENCY_DELTA",
        };
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&message).unwrap_or_default());
        if let Some(relay) = st.federation.relays.get(&node_name) {
            let _ = relay.outgoing_tx.send(RelayCommand::Raw(Message {
                prefix: None,
                command: "MESH".into(),
                params: vec![sub.into(), b64],
            }));
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

    let max_attempts: u32 = 10;
    let mut consecutive_failures: u32 = 0;
    let mut saved_mesh_hello: Option<String> = None;

    'reconnect: loop {
    let mut relay_nick = base_relay_nick.clone();

    let stream = match transport::connect(&connect_target, &transport_config).await {
        Ok(s) => {
            consecutive_failures = 0;
            s
        }
        Err(e) => {
            consecutive_failures += 1;
            if consecutive_failures >= max_attempts {
                warn!(%remote_host, %connect_target, attempts = consecutive_failures,
                    "federation: giving up after repeated connect failures: {e}");
                break 'reconnect;
            }
            warn!(%remote_host, %connect_target, attempt = consecutive_failures,
                "federation: connect failed, will retry: {e}");
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
        if consecutive_failures >= max_attempts {
            warn!(remote_host, "federation: giving up after registration failure");
            break 'reconnect;
        }
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
                                        let _ = event_tx.send(RelayEvent::MeshHello {
                                            remote_host: remote_host.clone(),
                                            lens_id: hello.peer_id,
                                            server_name: hello.server_name,
                                            public_key_hex: hello.public_key_hex,
                                            spiral_index: hello.spiral_index,
                                            vdf_genesis: hello.vdf_genesis,
                                            vdf_hash: hello.vdf_hash,
                                            vdf_step: hello.vdf_step,
                                            yggdrasil_addr: hello.yggdrasil_addr,
                                            site_name,
                                            node_name,
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
    if consecutive_failures >= max_attempts {
        warn!(remote_host, attempts = consecutive_failures,
            "federation: giving up after repeated disconnections");
        break 'reconnect;
    }
    info!(remote_host, attempt = consecutive_failures,
        "federation: connection lost, will reconnect");
    if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
        return;
    }

    } // end 'reconnect loop

    let _ = event_tx.send(RelayEvent::Disconnected { remote_host });
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
}

/// Build a MeshHelloPayload from server state (use inside read lock).
fn build_hello_payload(st: &super::server::ServerState) -> MeshHelloPayload {
    let (vdf_genesis, vdf_hash, vdf_step) = st
        .mesh
        .vdf_state_rx
        .as_ref()
        .map(|rx| {
            let vdf = rx.borrow();
            (
                Some(hex::encode(vdf.genesis)),
                Some(hex::encode(vdf.current_hash)),
                Some(vdf.total_steps),
            )
        })
        .unwrap_or((None, None, None));

    MeshHelloPayload {
        peer_id: st.lens.peer_id.clone(),
        server_name: st.lens.server_name.clone(),
        public_key_hex: st.lens.public_key_hex.clone(),
        spiral_index: st.lens.spiral_index,
        vdf_genesis,
        vdf_hash,
        vdf_step,
        yggdrasil_addr: transport::detect_yggdrasil_addr().map(|a| a.to_string()),
        site_name: st.lens.site_name.clone(),
        node_name: st.lens.node_name.clone(),
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
                let our_peer_id = st.lens.peer_id.clone();
                let idx = st.mesh.spiral.claim_position(&our_peer_id);
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
                },
            );
        }
    });
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
