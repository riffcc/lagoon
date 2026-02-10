/// IRC server core — state management, client handling, command dispatch.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};

use futures::SinkExt;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, RwLock};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::federation::{self, FederatedChannel, FederationManager, RelayEvent};
use super::invite::InviteStore;
use super::lens::LensIdentity;
use super::message::Message;
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

/// Human-friendly display name for the welcome message.
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
    /// Lens PeerID (`"b3b3/{hex}"`).
    pub lens_id: String,
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
}

fn default_peer_port() -> u16 {
    6667
}

impl Default for MeshPeerInfo {
    fn default() -> Self {
        Self {
            lens_id: String::new(),
            server_name: String::new(),
            public_key_hex: String::new(),
            port: 6667,
            tls: false,
            last_seen: 0,
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
    /// Known peers: LensID → peer info.
    pub known_peers: HashMap<String, MeshPeerInfo>,
    /// Connection state per lens_id (NOT server_name — multiple peers may share a name).
    pub connections: HashMap<String, MeshConnectionState>,
    /// Defederated LensIDs or server names — blocked from mesh.
    pub defederated: HashSet<String>,
    /// Currently connected web gateway users (nicks with `web~` ident).
    pub web_clients: HashSet<String>,
    /// Remote peers' topology snapshots — for debug composite view.
    pub remote_topologies: HashMap<String, MeshSnapshot>,
}

impl MeshState {
    pub fn new() -> Self {
        Self {
            known_peers: HashMap::new(),
            connections: HashMap::new(),
            defederated: HashSet::new(),
            web_clients: HashSet::new(),
            remote_topologies: HashMap::new(),
        }
    }
}

/// A single node in a mesh topology snapshot.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshNodeReport {
    pub lens_id: String,
    pub server_name: String,
    pub is_self: bool,
    pub connected: bool,
    pub node_type: String,
}

/// A single link in a mesh topology snapshot.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshLinkReport {
    pub source: String,
    pub target: String,
}

/// Complete mesh topology snapshot — pushed via watch channel.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MeshSnapshot {
    pub self_lens_id: String,
    pub self_server_name: String,
    pub nodes: Vec<MeshNodeReport>,
    pub links: Vec<MeshLinkReport>,
    pub timestamp: u64,
}

impl MeshSnapshot {
    pub fn empty() -> Self {
        Self {
            self_lens_id: String::new(),
            self_server_name: String::new(),
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
    /// Data directory for persistence.
    pub data_dir: PathBuf,
}

/// Handle to send messages to a connected client.
#[derive(Debug, Clone)]
pub struct ClientHandle {
    pub nick: String,
    pub user: Option<String>,
    pub realname: Option<String>,
    pub addr: SocketAddr,
    pub tx: mpsc::UnboundedSender<Message>,
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
        Self {
            clients: HashMap::new(),
            channels: HashMap::new(),
            channel_roles: HashMap::new(),
            channel_topics: HashMap::new(),
            federation: FederationManager::new(),
            federation_event_tx,
            transport_config,
            lens,
            mesh: MeshState::new(),
            mesh_topology_tx,
            invites,
            data_dir,
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

        // Add self.
        nodes.push(MeshNodeReport {
            lens_id: self.lens.peer_id.clone(),
            server_name: self.lens.server_name.clone(),
            is_self: true,
            connected: true,
            node_type: "server".into(),
        });

        // Add known peers.
        for (lens_id, peer_info) in &self.mesh.known_peers {
            let connected = self
                .mesh
                .connections
                .get(lens_id)
                .copied()
                == Some(MeshConnectionState::Connected);
            nodes.push(MeshNodeReport {
                lens_id: lens_id.clone(),
                server_name: peer_info.server_name.clone(),
                is_self: false,
                connected,
                node_type: "server".into(),
            });
            if connected {
                links.push(MeshLinkReport {
                    source: self.lens.peer_id.clone(),
                    target: lens_id.clone(),
                });
            }
        }

        // Add web gateway clients.
        for web_nick in &self.mesh.web_clients {
            nodes.push(MeshNodeReport {
                lens_id: format!("web/{web_nick}"),
                server_name: self.lens.server_name.clone(),
                is_self: false,
                connected: true,
                node_type: "browser".into(),
            });
            links.push(MeshLinkReport {
                source: self.lens.peer_id.clone(),
                target: format!("web/{web_nick}"),
            });
        }

        MeshSnapshot {
            self_lens_id: self.lens.peer_id.clone(),
            self_server_name: self.lens.server_name.clone(),
            nodes,
            links,
            timestamp: now,
        }
    }

    /// Build a debug topology snapshot with composite view from all peers.
    pub fn build_debug_snapshot(&self) -> MeshDebugSnapshot {
        let local = self.build_mesh_snapshot();

        // Merge all perspectives into a global view.
        let mut all_nodes: HashMap<String, MeshNodeReport> = HashMap::new();
        let mut all_links: HashSet<(String, String)> = HashSet::new();

        // Add our own view.
        for node in &local.nodes {
            all_nodes.entry(node.lens_id.clone()).or_insert_with(|| node.clone());
        }
        for link in &local.links {
            all_links.insert((link.source.clone(), link.target.clone()));
        }

        // Merge each remote peer's view.
        for snapshot in self.mesh.remote_topologies.values() {
            for node in &snapshot.nodes {
                all_nodes.entry(node.lens_id.clone()).or_insert_with(|| node.clone());
            }
            for link in &snapshot.links {
                all_links.insert((link.source.clone(), link.target.clone()));
            }
        }

        let global = MeshSnapshot {
            self_lens_id: self.lens.peer_id.clone(),
            self_server_name: self.lens.server_name.clone(),
            nodes: all_nodes.into_values().collect(),
            links: all_links
                .into_iter()
                .map(|(source, target)| MeshLinkReport { source, target })
                .collect(),
            timestamp: local.timestamp,
        };

        MeshDebugSnapshot {
            local,
            peer_views: self.mesh.remote_topologies.clone(),
            global,
        }
    }

    /// Update the topology watch channel with current state.
    pub fn notify_topology_change(&self) {
        let snapshot = self.build_mesh_snapshot();
        let _ = self.mesh_topology_tx.send(snapshot);
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
) -> Result<(SharedState, watch::Receiver<MeshSnapshot>, Vec<JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>>), Box<dyn std::error::Error + Send + Sync>> {
    let transport_config = Arc::new(transport::build_config());
    let (event_tx, event_rx) = mpsc::unbounded_channel::<RelayEvent>();

    // Load or create Lens identity.
    let data_dir = PathBuf::from(
        std::env::var("LAGOON_DATA_DIR").unwrap_or_else(|_| "./lagoon-data".to_string()),
    );
    let lens = Arc::new(super::lens::load_or_create(&data_dir, &SERVER_NAME));
    info!(
        peer_id = %lens.peer_id,
        server_name = %lens.server_name,
        "lens identity active"
    );

    let (topology_tx, topology_rx) = watch::channel(MeshSnapshot::empty());

    let state: SharedState = Arc::new(RwLock::new(ServerState::new(
        event_tx,
        transport_config.clone(),
        Arc::clone(&lens),
        topology_tx,
        data_dir,
    )));

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

    // Spawn federation event processor.
    federation::spawn_event_processor(Arc::clone(&state), event_rx);

    // Spawn LagoonBot.
    super::bot::spawn(Arc::clone(&state)).await;

    // Spawn mesh connector — proactively connects to all LAGOON_PEERS.
    federation::spawn_mesh_connector(Arc::clone(&state), transport_config);

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

    Ok((state, topology_rx, handles))
}

/// Run the IRC server on the given addresses.
///
/// Binds to every address in the slice and accepts connections on all of them.
/// This enables dual-stack: TCP on `0.0.0.0:6667` + Yggdrasil on `[200:...]:6667`.
pub async fn run(addrs: &[&str]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (_state, _topology_rx, handles) = start(addrs).await?;

    // Wait for any listener to exit (they shouldn't).
    for handle in handles {
        handle.await??;
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

/// Per-connection state during registration.
struct PendingRegistration {
    nick: Option<String>,
    user: Option<(String, String)>, // (username, realname)
}

/// Handle a single client connection.
async fn handle_client(
    socket: tokio::net::TcpStream,
    addr: SocketAddr,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut framed = Framed::new(socket, IrcCodec);
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let mut pending = PendingRegistration {
        nick: None,
        user: None,
    };
    let mut registered_nick: Option<String> = None;

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
                                });
                                if user.starts_with("web~") {
                                    st.mesh.web_clients.insert(irc_lower(&nick));
                                    st.notify_topology_change();
                                }
                            }

                            // Send welcome numerics.
                            send_welcome(&mut framed, &nick).await?;
                            registered_nick = Some(nick);
                        }
                    }
                    Some(ref nick) => {
                        // Registered — handle normal commands.
                        match handle_command(&mut framed, nick, &msg, &state).await? {
                            CommandResult::Ok => {}
                            CommandResult::Quit => break,
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
        cleanup_client(&nick, &state).await;
    }

    Ok(())
}

/// Handle NICK and USER commands during pre-registration.
async fn handle_registration(
    framed: &mut Framed<tokio::net::TcpStream, IrcCodec>,
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
    framed: &mut Framed<tokio::net::TcpStream, IrcCodec>,
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
                "o".into(),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.clone()),
            command: "005".into(),
            params: vec![
                nick.into(),
                "PREFIX=(qaov)~&@+".into(),
                "CHANTYPES=#&".into(),
                "CHANMODES=,,,o".into(),
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
    Quit,
    NickChanged(String),
}

/// Handle commands from a registered client.
async fn handle_command(
    framed: &mut Framed<tokio::net::TcpStream, IrcCodec>,
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
                        let relay_exists = st.federation.relays.contains_key(remote_host);

                        if relay_exists {
                            let relay = st.federation.relays.get_mut(remote_host).unwrap();
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
                            let (cmd_tx, task_handle) = federation::spawn_relay(
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
                                remote_host.to_owned(),
                                federation::RelayHandle {
                                    outgoing_tx: cmd_tx,
                                    remote_host: remote_host.to_owned(),
                                    channels,
                                    task_handle,
                                    mesh_connected: false,
                                },
                            );
                        }

                        let names = if let Some(relay) = st.federation.relays.get(remote_host) {
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
                                        parts.push(format!("{rn}@{}", relay.remote_host));
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

                        let prefix = st
                            .channel_roles
                            .get(&channel)
                            .and_then(|r| r.get(&nick_key).copied())
                            .unwrap_or(MemberPrefix::Normal);

                        st.channels
                            .entry(channel.clone())
                            .or_default()
                            .insert(nick_key.clone(), prefix);

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

                    // Collect nicks for broadcast before mutating.
                    let local_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(remote_host)
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
                    if let Some(relay) = st.federation.relays.get_mut(remote_host) {
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
                            st.federation.relays.remove(remote_host)
                        {
                            relay.task_handle.abort();
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
                        }
                    }
                }
            }
        }

        "PRIVMSG" | "NOTICE" => {
            if msg.params.len() >= 2 {
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
                    if let Some(relay) = st.federation.relays.get(remote_host) {
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
                    // Local channel message — broadcast to all members except sender.
                    let relay_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                        command: msg.command.clone(),
                        params: vec![target_lower.clone(), text.clone()],
                    };
                    let st = state.read().await;
                    if let Some(members) = st.channels.get(&target_lower) {
                        let others: Vec<_> = members
                            .keys()
                            .filter(|n| *n != &nick_key)
                            .cloned()
                            .collect();
                        broadcast(&st, &others, &relay_msg);
                    }
                } else if target.contains('@') {
                    // Federated DM: nick@remote.host
                    if let Some((target_nick, remote_host)) = target.split_once('@') {
                        if remote_host.contains('.') {
                            let st = state.read().await;
                            if let Some(relay) = st.federation.relays.get(remote_host) {
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
                    // Enforce TOPICLEN=390.
                    let raw_topic = &msg.params[1];
                    let topic: &str = if raw_topic.len() > 390 { &raw_topic[..390] } else { raw_topic };
                    let topic_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                        command: "TOPIC".into(),
                        params: vec![channel.clone(), topic.to_owned()],
                    };
                    let mut st = state.write().await;
                    // Store the topic.
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
                    }
                }
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
                                    format!("{rn}@{}", relay.remote_host)
                                };
                                let reply = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "352".into(),
                                    params: vec![
                                        nick.into(),
                                        target.clone(),
                                        display_nick.clone(),
                                        relay.remote_host.clone(),
                                        relay.remote_host.clone(),
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
            let st = state.read().await;
            // RPL_LISTSTART (321)
            let start = Message {
                prefix: Some(SERVER_NAME.clone()),
                command: "321".into(),
                params: vec![nick.into(), "Channel".into(), "Users  Name".into()],
            };
            framed.send(start).await?;

            for (channel, members) in &st.channels {
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
                    let names = if let Some(relay) = st.federation.relays.get(remote_host) {
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
                                    parts.push(format!("{rn}@{}", relay.remote_host));
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
                    if msg.params.len() >= 3 {
                        // Channel mode change — apply if sender is op or owner.
                        let mode_str = &msg.params[1];
                        let mode_target = &msg.params[2];
                        let mode_target_key = irc_lower(mode_target);
                        let nick_key = irc_lower(nick);
                        let st = state.read().await;
                        let sender_prefix = st
                            .channels
                            .get(&target)
                            .and_then(|m| m.get(&nick_key).copied())
                            .unwrap_or(MemberPrefix::Normal);
                        drop(st);

                        if sender_prefix >= MemberPrefix::Op {
                            let new_prefix = match mode_str.as_str() {
                                "+q" => Some(MemberPrefix::Owner),
                                "+a" => Some(MemberPrefix::Admin),
                                "+o" => Some(MemberPrefix::Op),
                                "+v" => Some(MemberPrefix::Voice),
                                "-q" | "-a" | "-o" | "-v" => Some(MemberPrefix::Normal),
                                _ => None,
                            };
                            if let Some(prefix) = new_prefix {
                                let mut st = state.write().await;
                                if let Some(members) = st.channels.get_mut(&target) {
                                    if let Some(p) = members.get_mut(&mode_target_key) {
                                        *p = prefix;
                                    }
                                }
                                // Persist role so it survives PART/QUIT.
                                st.channel_roles
                                    .entry(target.clone())
                                    .or_default()
                                    .insert(mode_target_key, prefix);
                                // Broadcast MODE change.
                                let mode_msg = Message {
                                    prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
                                    command: "MODE".into(),
                                    params: vec![
                                        target.clone(),
                                        mode_str.clone(),
                                        mode_target.clone(),
                                    ],
                                };
                                if let Some(members) = st.channels.get(&target) {
                                    let member_list: Vec<_> =
                                        members.keys().cloned().collect();
                                    broadcast(&st, &member_list, &mode_msg);
                                }
                            }
                        }
                    } else {
                        // Channel mode query — return current mode.
                        let reply = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "324".into(),
                            params: vec![nick.into(), target.clone(), "+".into()],
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
                    // 319 RPL_WHOISCHANNELS
                    let mut chans = Vec::new();
                    for (ch_name, members) in &st.channels {
                        if let Some(prefix) = members.get(&target_key) {
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
            if msg.params.len() >= 2 {
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
                        }
                        if let Ok(hello) = serde_json::from_str::<HelloPayload>(json) {
                            let _ = st.federation_event_tx.send(
                                federation::RelayEvent::MeshHello {
                                    remote_host: hello.server_name.clone(),
                                    lens_id: hello.peer_id,
                                    server_name: hello.server_name,
                                    public_key_hex: hello.public_key_hex,
                                },
                            );

                            // Respond with our own HELLO.
                            let our_hello = serde_json::json!({
                                "peer_id": st.lens.peer_id,
                                "server_name": st.lens.server_name,
                                "public_key_hex": st.lens.public_key_hex,
                            });

                            // Collect peer list for MESH PEERS exchange.
                            let peers_list: Vec<MeshPeerInfo> =
                                st.mesh.known_peers.values().cloned().collect();

                            // Collect topology snapshot for MESH TOPOLOGY exchange.
                            let topo_snapshot = st.build_mesh_snapshot();

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

                            // Send MESH TOPOLOGY — our full mesh view.
                            if let Ok(topo_json) = serde_json::to_string(&topo_snapshot) {
                                let topo_msg = Message {
                                    prefix: Some(SERVER_NAME.clone()),
                                    command: "MESH".into(),
                                    params: vec!["TOPOLOGY".into(), topo_json],
                                };
                                framed.send(topo_msg).await?;
                            }
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
                    _ => {}
                }
            }
        }

        // INVITE — invite code management commands.
        "INVITE" => {
            if let Some(sub_cmd) = msg.params.first() {
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
                            let lens_id = st.lens.peer_id.clone();
                            let invite = st.invites.create(
                                kind,
                                lens_id,
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
                // Also check by lens_id in known_peers.
                let mut connection_ids_to_remove = Vec::new();
                for (lens_id, peer_info) in &st.mesh.known_peers {
                    if lens_id == target || peer_info.server_name == *target {
                        if let Some(relay) = st.federation.relays.get(&peer_info.server_name) {
                            let _ = relay.outgoing_tx.send(federation::RelayCommand::Shutdown);
                            to_remove.push(peer_info.server_name.clone());
                        }
                        connection_ids_to_remove.push(lens_id.clone());
                    }
                }
                for host in &to_remove {
                    if let Some(relay) = st.federation.relays.remove(host) {
                        relay.task_handle.abort();
                    }
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

        "QUIT" => {
            return Ok(CommandResult::Quit);
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
async fn cleanup_client(nick: &str, state: &SharedState) {
    let nick_key = irc_lower(nick);
    let mut st = state.write().await;

    // Relay nicks are invisible — suppress QUIT broadcast.
    if !federation::is_relay_nick(nick) {
        let quit_msg = Message {
            prefix: Some(format!("{nick}!{nick}@{}", *SERVER_NAME)),
            command: "QUIT".into(),
            params: vec!["Connection closed".into()],
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

    // Remove from all local channels.
    st.channels.retain(|_name, members| {
        members.remove(&nick_key);
        !members.is_empty()
    });

    // Remove from all federated channels. Shut down relays with no channels left.
    let mut empty_relays = Vec::new();
    for (host, relay) in st.federation.relays.iter_mut() {
        let mut empty_channels = Vec::new();
        for (local_ch, fed_ch) in relay.channels.iter_mut() {
            if fed_ch.local_users.remove(&nick_key) {
                let _ = relay.outgoing_tx.send(federation::RelayCommand::Part {
                    nick: nick.to_owned(),
                    remote_channel: fed_ch.remote_channel.clone(),
                    reason: "Connection closed".into(),
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
        if let Some(relay) = st.federation.relays.remove(&host) {
            relay.task_handle.abort();
        }
    }

    // Remove from clients.
    st.clients.remove(&nick_key);

    // Remove from web client tracking if applicable.
    if st.mesh.web_clients.remove(&nick_key) {
        st.notify_topology_change();
    }

    info!(nick, "cleaned up");
}
