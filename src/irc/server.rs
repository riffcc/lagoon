/// IRC server core — state management, client handling, command dispatch.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use futures::SinkExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::federation::{self, FederatedChannel, FederationManager, RelayEvent};
use super::message::Message;

/// Server identity — derived from system hostname at startup.
pub static SERVER_NAME: LazyLock<String> = LazyLock::new(|| {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| h.contains('.'))
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
    /// Federation manager for `#room:server` relay connections.
    pub federation: FederationManager,
    /// Sender for federation relay events (relays send events here).
    pub federation_event_tx: mpsc::UnboundedSender<RelayEvent>,
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
    pub fn new(federation_event_tx: mpsc::UnboundedSender<RelayEvent>) -> Self {
        Self {
            clients: HashMap::new(),
            channels: HashMap::new(),
            channel_roles: HashMap::new(),
            federation: FederationManager::new(),
            federation_event_tx,
        }
    }
}

/// Shared, thread-safe server state.
pub type SharedState = Arc<RwLock<ServerState>>;

/// Run the IRC server on the given addresses.
///
/// Binds to every address in the slice and accepts connections on all of them.
/// This enables dual-stack: TCP on `0.0.0.0:6667` + Yggdrasil on `[200:...]:6667`.
pub async fn run(addrs: &[&str]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (event_tx, event_rx) = mpsc::unbounded_channel::<RelayEvent>();
    let state: SharedState = Arc::new(RwLock::new(ServerState::new(event_tx)));

    // Spawn federation event processor.
    federation::spawn_event_processor(Arc::clone(&state), event_rx);

    // Spawn LagoonBot.
    super::bot::spawn(Arc::clone(&state)).await;

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

                            // Check for nick collision.
                            {
                                let st = state.read().await;
                                if st.clients.contains_key(&nick) {
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

                            // Register the client.
                            {
                                let mut st = state.write().await;
                                st.clients.insert(nick.clone(), ClientHandle {
                                    nick: nick.clone(),
                                    user: Some(user.clone()),
                                    realname: Some(realname.clone()),
                                    addr,
                                    tx: tx.clone(),
                                });
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
                format!("NETWORK={}", *NETWORK_TAG),
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
                } else if new_nick == nick {
                    // Same nick — no-op.
                } else {
                    let mut st = state.write().await;

                    // Check for collision.
                    if st.clients.contains_key(new_nick) {
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
                            prefix: Some(format!("{nick}!{nick}@lagoon")),
                            command: "NICK".into(),
                            params: vec![new_nick.clone()],
                        };

                        // Collect every user who shares a channel with us (deduplicated).
                        let mut notify: HashSet<String> = HashSet::new();
                        notify.insert(nick.to_owned()); // notify self
                        for (_ch, members) in &st.channels {
                            if members.contains_key(nick) {
                                for member in members.keys() {
                                    notify.insert(member.clone());
                                }
                            }
                        }
                        let notify_list: Vec<_> = notify.into_iter().collect();
                        broadcast(&st, &notify_list, &nick_msg);

                        // Update client handle.
                        if let Some(mut handle) = st.clients.remove(nick) {
                            handle.nick = new_nick.clone();
                            st.clients.insert(new_nick.clone(), handle);
                        }

                        // Update channel memberships.
                        for members in st.channels.values_mut() {
                            if let Some(prefix) = members.remove(nick) {
                                members.insert(new_nick.clone(), prefix);
                            }
                        }

                        // Transfer persistent roles.
                        for roles in st.channel_roles.values_mut() {
                            if let Some(prefix) = roles.remove(nick) {
                                roles.insert(new_nick.clone(), prefix);
                            }
                        }

                        // Update federation relay local_users.
                        for (_host, relay) in st.federation.relays.iter_mut() {
                            for (_local_ch, fed_ch) in relay.channels.iter_mut() {
                                if fed_ch.local_users.remove(nick) {
                                    let _ = relay.outgoing_tx.send(
                                        federation::RelayCommand::Part {
                                            nick: nick.to_owned(),
                                            remote_channel: fed_ch.remote_channel.clone(),
                                            reason: format!("Nick changed to {new_nick}"),
                                        },
                                    );
                                    fed_ch.local_users.insert(new_nick.clone());
                                    let _ = relay.outgoing_tx.send(
                                        federation::RelayCommand::Join {
                                            nick: new_nick.clone(),
                                            remote_channel: fed_ch.remote_channel.clone(),
                                        },
                                    );
                                }
                            }
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
                                fed_ch.local_users.insert(nick.to_owned());
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::Join {
                                        nick: nick.to_owned(),
                                        remote_channel: remote_chan.to_owned(),
                                    },
                                );
                            } else {
                                // New channel on existing relay connection.
                                let mut local_users = HashSet::new();
                                local_users.insert(nick.to_owned());
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
                            );
                            let mut local_users = HashSet::new();
                            local_users.insert(nick.to_owned());
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
                                },
                            );
                        }

                        let names = if let Some(relay) = st.federation.relays.get(remote_host) {
                            if let Some(fed_ch) = relay.channels.get(&channel) {
                                let mut parts: Vec<String> =
                                    fed_ch.local_users.iter().cloned().collect();
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
                            prefix: Some(format!("{nick}!{nick}@lagoon")),
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
                            .and_then(|r| r.get(nick).copied())
                            .unwrap_or(MemberPrefix::Normal);

                        st.channels
                            .entry(channel.clone())
                            .or_default()
                            .insert(nick.to_owned(), prefix);

                        // Auto-federation: ensure relays to all peers for this channel.
                        if !federation::is_relay_nick(nick) && !federation::PEERS.is_empty() {
                            for peer in federation::PEERS.iter() {
                                if !st.federation.relays.contains_key(peer) {
                                    let event_tx = st.federation_event_tx.clone();
                                    let (cmd_tx, task_handle) =
                                        federation::spawn_relay(peer.clone(), event_tx);
                                    let _ = cmd_tx.send(
                                        federation::RelayCommand::JoinChannel {
                                            remote_channel: channel.clone(),
                                            local_channel: channel.clone(),
                                        },
                                    );
                                    let mut channels = HashMap::new();
                                    channels.insert(
                                        channel.clone(),
                                        FederatedChannel {
                                            remote_channel: channel.clone(),
                                            local_users: HashSet::new(),
                                            remote_users: HashSet::new(),
                                        },
                                    );
                                    st.federation.relays.insert(
                                        peer.clone(),
                                        federation::RelayHandle {
                                            outgoing_tx: cmd_tx,
                                            remote_host: peer.clone(),
                                            channels,
                                            task_handle,
                                        },
                                    );
                                } else {
                                    let relay =
                                        st.federation.relays.get_mut(peer).unwrap();
                                    if !relay.channels.contains_key(&channel) {
                                        relay.channels.insert(
                                            channel.clone(),
                                            FederatedChannel {
                                                remote_channel: channel.clone(),
                                                local_users: HashSet::new(),
                                                remote_users: HashSet::new(),
                                            },
                                        );
                                        let _ = relay.outgoing_tx.send(
                                            federation::RelayCommand::JoinChannel {
                                                remote_channel: channel.clone(),
                                                local_channel: channel.clone(),
                                            },
                                        );
                                    }
                                }
                            }
                        }

                        let join_msg = Message {
                            prefix: Some(format!("{nick}!{nick}@lagoon")),
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
                                .map(|m| m.keys().filter(|n| *n != nick).cloned().collect())
                                .unwrap_or_default();

                            broadcast(&st, &other_nicks, &join_msg);
                        }

                        let names =
                            federation::build_channel_names(&st, &channel);
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
            if let Some(channel) = msg.params.first() {
                let reason = msg.params.get(1).cloned().unwrap_or_default();

                if let Some((remote_chan, remote_host)) =
                    federation::parse_federated_channel(channel)
                {
                    // Federated channel — remove user, maybe tear down relay.
                    let mut st = state.write().await;

                    // Collect nicks for broadcast before mutating.
                    let local_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(remote_host)
                        .and_then(|r| r.channels.get(channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();

                    let part_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@lagoon")),
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
                        if let Some(fed_ch) = relay.channels.get_mut(channel) {
                            fed_ch.local_users.remove(nick);
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
                            relay.channels.remove(channel);
                        }
                        if relay.channels.is_empty() {
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
                            prefix: Some(format!("{nick}!{nick}@lagoon")),
                            command: "PART".into(),
                            params: vec![channel.clone(), reason],
                        };
                        if let Some(members) = st.channels.get(channel) {
                            let member_list: Vec<_> = members.keys().cloned().collect();
                            broadcast(&st, &member_list, &part_msg);
                        }
                    }

                    // Remove nick from channel.
                    if let Some(members) = st.channels.get_mut(channel) {
                        members.remove(nick);
                        if members.is_empty() {
                            st.channels.remove(channel);
                        }
                    }

                    // Auto-federation cleanup: if no real users left, PART relays.
                    let has_real_users = st
                        .channels
                        .get(channel)
                        .is_some_and(|m| m.keys().any(|n| !federation::is_relay_nick(n)));
                    if !has_real_users && !federation::PEERS.is_empty() {
                        let mut empty_relays = Vec::new();
                        for (host, relay) in st.federation.relays.iter_mut() {
                            if relay.channels.contains_key(channel) {
                                let _ = relay.outgoing_tx.send(
                                    federation::RelayCommand::PartChannel {
                                        remote_channel: channel.clone(),
                                    },
                                );
                                relay.channels.remove(channel);
                                if relay.channels.is_empty() {
                                    let _ = relay.outgoing_tx.send(
                                        federation::RelayCommand::Shutdown,
                                    );
                                    empty_relays.push(host.clone());
                                }
                            }
                        }
                        for host in empty_relays {
                            if let Some(relay) = st.federation.relays.remove(&host) {
                                relay.task_handle.abort();
                            }
                        }
                    }
                }
            }
        }

        "PRIVMSG" | "NOTICE" => {
            if msg.params.len() >= 2 {
                let target = &msg.params[0];
                let text = &msg.params[1];

                if let Some((remote_chan, remote_host)) = {
                    if target.starts_with('#') || target.starts_with('&') {
                        federation::parse_federated_channel(target)
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
                        if let Some(fed_ch) = relay.channels.get(target) {
                            let echo = Message {
                                prefix: Some(format!("{nick}!{nick}@lagoon")),
                                command: msg.command.clone(),
                                params: vec![target.clone(), text.clone()],
                            };
                            let others: Vec<_> = fed_ch
                                .local_users
                                .iter()
                                .filter(|n| *n != nick)
                                .cloned()
                                .collect();
                            broadcast(&st, &others, &echo);
                        }
                    }
                } else if target.starts_with('#') || target.starts_with('&') {
                    // Local channel message — broadcast to all members except sender.
                    let relay_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@lagoon")),
                        command: msg.command.clone(),
                        params: vec![target.clone(), text.clone()],
                    };
                    let st = state.read().await;
                    if let Some(members) = st.channels.get(target) {
                        let others: Vec<_> = members
                            .keys()
                            .filter(|n| *n != nick)
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
                        prefix: Some(format!("{nick}!{nick}@lagoon")),
                        command: msg.command.clone(),
                        params: vec![target.clone(), text.clone()],
                    };
                    let st = state.read().await;
                    if let Some(handle) = st.clients.get(target) {
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
            if let Some(channel) = msg.params.first() {
                // Just acknowledge — no persistent topic storage yet.
                if msg.params.len() >= 2 {
                    let topic = &msg.params[1];
                    let topic_msg = Message {
                        prefix: Some(format!("{nick}!{nick}@lagoon")),
                        command: "TOPIC".into(),
                        params: vec![channel.clone(), topic.clone()],
                    };
                    let st = state.read().await;
                    if let Some(members) = st.channels.get(channel) {
                        let member_list: Vec<_> = members.keys().cloned().collect();
                        broadcast(&st, &member_list, &topic_msg);
                    }
                } else {
                    // No topic set.
                    let reply = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "331".into(),
                        params: vec![nick.into(), channel.clone(), "No topic is set".into()],
                    };
                    framed.send(reply).await?;
                }
            }
        }

        "WHO" => {
            if let Some(target) = msg.params.first() {
                let st = state.read().await;
                if target.starts_with('#') || target.starts_with('&') {
                    // WHO for a channel — list local members (hide relay nicks).
                    if let Some(members) = st.channels.get(target) {
                        for (member, prefix) in members.iter().filter(|(n, _)| !federation::is_relay_nick(n)) {
                            let flags = format!("H{}", prefix.symbol());
                            let reply = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "352".into(),
                                params: vec![
                                    nick.into(),
                                    target.clone(),
                                    member.clone(),
                                    "lagoon".into(),
                                    SERVER_NAME.clone(),
                                    member.clone(),
                                    flags,
                                    format!("0 {member}"),
                                ],
                            };
                            framed.send(reply).await?;
                        }
                    }
                    // Include remote users from federation relays.
                    for relay in st.federation.relays.values() {
                        if let Some(fed_ch) = relay.channels.get(target) {
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
                let reply = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "322".into(),
                    params: vec![
                        nick.into(),
                        channel.clone(),
                        members.len().to_string(),
                        String::new(),
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
            if let Some(channel) = msg.params.first() {
                if let Some((_remote_chan, remote_host)) =
                    federation::parse_federated_channel(channel)
                {
                    // Federated channel — combine local + remote users.
                    let st = state.read().await;
                    let names = if let Some(relay) = st.federation.relays.get(remote_host) {
                        if let Some(fed_ch) = relay.channels.get(channel) {
                            let mut parts: Vec<String> = fed_ch
                                .local_users
                                .iter()
                                .cloned()
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
                    // Local channel (includes remote users from federation).
                    let st = state.read().await;
                    let names =
                        federation::build_channel_names(&st, channel);
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
            if let Some(target) = msg.params.first() {
                if target.starts_with('#') || target.starts_with('&') {
                    if msg.params.len() >= 3 {
                        // Channel mode change — apply if sender is op or owner.
                        let mode_str = &msg.params[1];
                        let mode_target = &msg.params[2];
                        let st = state.read().await;
                        let sender_prefix = st
                            .channels
                            .get(target)
                            .and_then(|m| m.get(nick).copied())
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
                                if let Some(members) = st.channels.get_mut(target) {
                                    if let Some(p) = members.get_mut(mode_target) {
                                        *p = prefix;
                                    }
                                }
                                // Persist role so it survives PART/QUIT.
                                st.channel_roles
                                    .entry(target.clone())
                                    .or_default()
                                    .insert(mode_target.clone(), prefix);
                                // Broadcast MODE change.
                                let mode_msg = Message {
                                    prefix: Some(format!("{nick}!{nick}@lagoon")),
                                    command: "MODE".into(),
                                    params: vec![
                                        target.clone(),
                                        mode_str.clone(),
                                        mode_target.clone(),
                                    ],
                                };
                                if let Some(members) = st.channels.get(target) {
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
                let channel = &msg.params[3];

                // Build the virtual nick: nick@origin_host
                let virtual_nick = format!("{origin_nick}@{origin_host}");
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
                            if let Some(members) = st.channels.get(channel) {
                                // Filter relay nicks to prevent loops in auto-federation.
                                let others: Vec<_> = members
                                    .keys()
                                    .filter(|n| {
                                        *n != nick
                                            && !federation::is_relay_nick(n)
                                    })
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
                        if let Some(members) = st.channels.get_mut(channel) {
                            // Add virtual user to channel membership.
                            members.insert(virtual_nick.clone(), MemberPrefix::Normal);
                            // Filter relay nicks to prevent loops in auto-federation.
                            let others: Vec<_> = members
                                .keys()
                                .filter(|n| {
                                    *n != nick
                                        && *n != &virtual_nick
                                        && !federation::is_relay_nick(n)
                                })
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
                        // Filter relay nicks to prevent loops in auto-federation.
                        let others: Vec<_> = st
                            .channels
                            .get(channel)
                            .map(|members| {
                                members
                                    .keys()
                                    .filter(|n| {
                                        *n != nick
                                            && *n != &virtual_nick
                                            && !federation::is_relay_nick(n)
                                    })
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        broadcast(&st, &others, &part_msg);
                        // Remove virtual user from channel membership.
                        if let Some(members) = st.channels.get_mut(channel) {
                            members.remove(&virtual_nick);
                        }
                    }
                    "DM" => {
                        // FRELAY DM <sender> <origin_host> <target_nick> :<text>
                        // channel (params[3]) is repurposed as target_nick.
                        let target_nick = channel; // params[3]
                        if let Some(text) = msg.params.get(4) {
                            let dm_msg = Message {
                                prefix: Some(virtual_prefix),
                                command: "PRIVMSG".into(),
                                params: vec![target_nick.clone(), text.clone()],
                            };
                            let st = state.read().await;
                            if let Some(handle) = st.clients.get(target_nick) {
                                let _ = handle.tx.send(dm_msg);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        "WHOIS" => {
            if let Some(target) = msg.params.last() {
                let st = state.read().await;
                if let Some(handle) = st.clients.get(target) {
                    let user = handle.user.as_deref().unwrap_or(target);
                    let realname = handle.realname.as_deref().unwrap_or("");
                    // 311 RPL_WHOISUSER
                    let r311 = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "311".into(),
                        params: vec![
                            nick.into(),
                            target.clone(),
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
                            target.clone(),
                            SERVER_NAME.clone(),
                            DISPLAY_NAME.clone(),
                        ],
                    };
                    framed.send(r312).await?;
                    // 319 RPL_WHOISCHANNELS
                    let mut chans = Vec::new();
                    for (ch_name, members) in &st.channels {
                        if let Some(prefix) = members.get(target) {
                            chans.push(format!("{}{ch_name}", prefix.symbol()));
                        }
                    }
                    if !chans.is_empty() {
                        let r319 = Message {
                            prefix: Some(SERVER_NAME.clone()),
                            command: "319".into(),
                            params: vec![nick.into(), target.clone(), chans.join(" ")],
                        };
                        framed.send(r319).await?;
                    }
                } else {
                    // 401 ERR_NOSUCHNICK
                    let err = Message {
                        prefix: Some(SERVER_NAME.clone()),
                        command: "401".into(),
                        params: vec![nick.into(), target.clone(), "No such nick/channel".into()],
                    };
                    framed.send(err).await?;
                }
                drop(st);
                // 318 RPL_ENDOFWHOIS (always sent)
                let r318 = Message {
                    prefix: Some(SERVER_NAME.clone()),
                    command: "318".into(),
                    params: vec![nick.into(), target.clone(), "End of /WHOIS list".into()],
                };
                framed.send(r318).await?;
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
    let mut st = state.write().await;

    // Relay nicks are invisible — suppress QUIT broadcast.
    if !federation::is_relay_nick(nick) {
        let quit_msg = Message {
            prefix: Some(format!("{nick}!{nick}@lagoon")),
            command: "QUIT".into(),
            params: vec!["Connection closed".into()],
        };

        let mut notified: HashSet<String> = HashSet::new();
        for (_channel, members) in st.channels.iter() {
            if members.contains_key(nick) {
                for member in members.keys() {
                    if member != nick && !notified.contains(member) {
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
    let mut emptied_channels: Vec<String> = Vec::new();
    st.channels.retain(|name, members| {
        members.remove(nick);
        if !members.is_empty() {
            // Check if only relay nicks remain (auto-federation cleanup).
            if !members.keys().any(|n| !federation::is_relay_nick(n)) {
                emptied_channels.push(name.clone());
            }
            true
        } else {
            false
        }
    });

    // Auto-federation cleanup: PART relays for channels with no real users.
    if !emptied_channels.is_empty() && !federation::PEERS.is_empty() {
        for ch in &emptied_channels {
            for relay in st.federation.relays.values() {
                if relay.channels.contains_key(ch) {
                    let _ = relay.outgoing_tx.send(
                        federation::RelayCommand::PartChannel {
                            remote_channel: ch.clone(),
                        },
                    );
                }
            }
            for relay in st.federation.relays.values_mut() {
                relay.channels.remove(ch);
            }
        }
    }

    // Remove from all federated channels. Shut down relays with no channels left.
    let mut empty_relays = Vec::new();
    for (host, relay) in st.federation.relays.iter_mut() {
        let mut empty_channels = Vec::new();
        for (local_ch, fed_ch) in relay.channels.iter_mut() {
            if fed_ch.local_users.remove(nick) {
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
        if relay.channels.is_empty() {
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
    st.clients.remove(nick);
    info!(nick, "cleaned up");
}
