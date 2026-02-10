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
use super::server::{broadcast, MeshConnectionState, MeshPeerInfo, SharedState, SERVER_NAME};
use super::transport::{self, TransportConfig};

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
pub fn spawn_event_processor(
    state: SharedState,
    mut event_rx: mpsc::UnboundedReceiver<RelayEvent>,
) {
    tokio::spawn(async move {
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
                    let mut st = state.write().await;

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
                        .filter(|(_, p)| p.server_name == remote_host)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in &disconnected_ids {
                        st.mesh.connections.remove(id);
                    }
                    if !disconnected_ids.is_empty() {
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
                } => {
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

                    let mut st = state.write().await;

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

                    st.mesh.known_peers.insert(
                        lens_id.clone(),
                        MeshPeerInfo {
                            lens_id: lens_id.clone(),
                            server_name: server_name.clone(),
                            public_key_hex,
                            port: peer_port,
                            tls: peer_tls,
                            last_seen: now,
                        },
                    );
                    st.mesh
                        .connections
                        .insert(lens_id, MeshConnectionState::Connected);
                    st.notify_topology_change();

                    // Send MESH PEERS to the newly connected peer.
                    let peers_list: Vec<MeshPeerInfo> =
                        st.mesh.known_peers.values().cloned().collect();
                    if !peers_list.is_empty() {
                        if let Ok(peers_json) = serde_json::to_string(&peers_list) {
                            if let Some(relay) = st.federation.relays.get(&remote_host) {
                                let _ =
                                    relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["PEERS".into(), peers_json],
                                    }));
                            }
                        }
                    }

                    // Send MESH TOPOLOGY — our full mesh view.
                    let topo_snapshot = st.build_mesh_snapshot();
                    if let Some(relay) = st.federation.relays.get(&remote_host) {
                        if let Ok(topo_json) = serde_json::to_string(&topo_snapshot)
                        {
                            let _ =
                                relay.outgoing_tx.send(RelayCommand::Raw(Message {
                                    prefix: None,
                                    command: "MESH".into(),
                                    params: vec!["TOPOLOGY".into(), topo_json],
                                }));
                        }
                    }
                }

                RelayEvent::MeshPeers {
                    remote_host,
                    peers,
                } => {
                    let mut st = state.write().await;
                    let mut changed = false;
                    let mut new_peer_servers = Vec::new();

                    for peer in peers {
                        if st.mesh.defederated.contains(&peer.lens_id)
                            || st.mesh.defederated.contains(&peer.server_name)
                        {
                            continue;
                        }
                        if peer.lens_id == st.lens.peer_id {
                            continue; // Don't add ourselves.
                        }
                        if !st.mesh.known_peers.contains_key(&peer.lens_id) {
                            info!(
                                remote_host,
                                peer_id = %peer.lens_id,
                                server = %peer.server_name,
                                port = peer.port,
                                tls = peer.tls,
                                "mesh: discovered peer via gossip"
                            );
                            let server_name = peer.server_name.clone();
                            let port = peer.port;
                            let tls = peer.tls;
                            st.mesh.known_peers.insert(peer.lens_id.clone(), peer);
                            changed = true;
                            new_peer_servers.push((server_name, port, tls));
                        }
                    }
                    if changed {
                        st.notify_topology_change();
                    }

                    // Auto-connect to newly discovered peers.
                    if !new_peer_servers.is_empty() {
                        let hello_json =
                            serde_json::to_string(&MeshHelloPayload {
                                peer_id: st.lens.peer_id.clone(),
                                server_name: st.lens.server_name.clone(),
                                public_key_hex: st.lens.public_key_hex.clone(),
                            })
                            .unwrap_or_default();
                        let event_tx = st.federation_event_tx.clone();
                        let tc = st.transport_config.clone();

                        for (server_name, port, tls) in new_peer_servers {
                            // Skip if we already have a relay to this server.
                            if st.federation.relays.contains_key(&server_name) {
                                continue;
                            }
                            // Skip self.
                            if server_name == *SERVER_NAME {
                                continue;
                            }
                            // Skip defederated.
                            if st.mesh.defederated.contains(&server_name) {
                                continue;
                            }

                            info!(
                                peer = %server_name,
                                port,
                                tls,
                                "mesh: auto-connecting to gossip-discovered peer"
                            );

                            // Add transport hints for this peer so connect() knows
                            // how to reach it.
                            let mut tc_with_peer =
                                (*tc).clone();
                            tc_with_peer.peers.entry(server_name.clone()).or_insert(
                                transport::PeerEntry {
                                    yggdrasil_addr: None,
                                    port,
                                    tls,
                                },
                            );
                            let tc_arc = Arc::new(tc_with_peer);

                            let (cmd_tx, task_handle) = spawn_relay(
                                server_name.clone(),
                                event_tx.clone(),
                                tc_arc,
                            );
                            let _ = cmd_tx.send(RelayCommand::MeshHello {
                                json: hello_json.clone(),
                            });

                            st.federation.relays.insert(
                                server_name.clone(),
                                RelayHandle {
                                    outgoing_tx: cmd_tx,
                                    remote_host: server_name,
                                    channels: HashMap::new(),
                                    task_handle,
                                    mesh_connected: true,
                                },
                            );
                        }
                    }
                }

                RelayEvent::MeshTopology {
                    remote_host,
                    json,
                } => {
                    if let Ok(snapshot) =
                        serde_json::from_str::<super::server::MeshSnapshot>(&json)
                    {
                        let mut st = state.write().await;
                        st.mesh
                            .remote_topologies
                            .insert(remote_host, snapshot);
                        st.notify_topology_change();
                    }
                }
            }
        }
    });
}

/// Spawn a relay connection to a remote server.
pub fn spawn_relay(
    remote_host: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) -> (mpsc::UnboundedSender<RelayCommand>, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(relay_task(
        remote_host,
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
async fn relay_task(
    remote_host: String,
    mut cmd_rx: mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) {
    let our_name = &*SERVER_NAME;
    let base_relay_nick = if let Some(prefix) = our_name.split('.').next() {
        format!("{prefix}~relay")
    } else {
        "lagoon~relay".into()
    };
    let our_suffix = format!("@{our_name}");

    let max_attempts: u32 = 10;
    let mut consecutive_failures: u32 = 0;
    let mut saved_mesh_hello: Option<String> = None;

    'reconnect: loop {
    let mut relay_nick = base_relay_nick.clone();

    let stream = match transport::connect(&remote_host, &transport_config).await {
        Ok(s) => {
            consecutive_failures = 0;
            s
        }
        Err(e) => {
            consecutive_failures += 1;
            if consecutive_failures >= max_attempts {
                warn!(remote_host, attempts = consecutive_failures,
                    "federation: giving up after repeated connect failures: {e}");
                break 'reconnect;
            }
            warn!(remote_host, attempt = consecutive_failures,
                "federation: connect failed, will retry: {e}");
            if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
                return;
            }
            continue 'reconnect;
        }
    };

    info!(remote_host, "federation: connected");
    let mut framed = Framed::new(stream, IrcCodec);

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
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    // Skip the first immediate tick.
    keepalive.tick().await;

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if registered {
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
                                        let _ = event_tx.send(RelayEvent::MeshHello {
                                            remote_host: remote_host.clone(),
                                            lens_id: hello.peer_id,
                                            server_name: hello.server_name,
                                            public_key_hex: hello.public_key_hex,
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
}

/// Spawn the mesh connector — proactively connects to all LAGOON_PEERS
/// and sends MESH HELLO to establish identity exchange.
///
/// Mesh connections are metadata-only — they exchange MESH commands but
/// create NO channels and inject NO users into rooms.
pub fn spawn_mesh_connector(state: SharedState, transport_config: Arc<TransportConfig>) {
    let peers: Vec<String> = transport_config.peers.keys().cloned().collect();
    if peers.is_empty() {
        return;
    }

    info!(peer_count = peers.len(), "mesh: initiating connections to peers");

    tokio::spawn(async move {
        let st = state.read().await;
        let hello_json = serde_json::to_string(&MeshHelloPayload {
            peer_id: st.lens.peer_id.clone(),
            server_name: st.lens.server_name.clone(),
            public_key_hex: st.lens.public_key_hex.clone(),
        })
        .unwrap_or_default();
        let event_tx = st.federation_event_tx.clone();
        let tc = st.transport_config.clone();
        drop(st);

        for peer_host in peers {
            // Skip self — don't connect to our own server name.
            if peer_host == *SERVER_NAME {
                info!(peer = %peer_host, "mesh: skipping self");
                continue;
            }

            let mut st = state.write().await;

            // Skip if already connected (e.g. from a user JOIN).
            if st.federation.relays.contains_key(&peer_host) {
                // Send MESH HELLO on existing relay.
                if let Some(relay) = st.federation.relays.get(&peer_host) {
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

            info!(peer = %peer_host, "mesh: connecting");

            let (cmd_tx, task_handle) = spawn_relay(
                peer_host.clone(),
                event_tx.clone(),
                Arc::clone(&tc),
            );

            // Send MESH HELLO (will be queued until registered).
            let _ = cmd_tx.send(RelayCommand::MeshHello {
                json: hello_json.clone(),
            });

            st.federation.relays.insert(
                peer_host.clone(),
                RelayHandle {
                    outgoing_tx: cmd_tx,
                    remote_host: peer_host,
                    channels: HashMap::new(),
                    task_handle,
                    mesh_connected: true,
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
