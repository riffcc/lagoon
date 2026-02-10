/// IRC server core — state management, client handling, command dispatch.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use futures::SinkExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::message::Message;

/// The server's identity.
const SERVER_NAME: &str = "lagoon.lagun.co";

/// Shared server state.
#[derive(Debug)]
pub struct ServerState {
    /// Registered clients: nick → sender handle.
    pub clients: HashMap<String, ClientHandle>,
    /// Channels: channel name → set of nicks.
    pub channels: HashMap<String, HashSet<String>>,
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
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
            channels: HashMap::new(),
        }
    }
}

/// Shared, thread-safe server state.
pub type SharedState = Arc<RwLock<ServerState>>;

/// Run the IRC server on the given address.
pub async fn run(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let state: SharedState = Arc::new(RwLock::new(ServerState::new()));
    let listener = TcpListener::bind(addr).await?;
    info!("lagoon listening on {addr}");

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
                                        prefix: Some(SERVER_NAME.into()),
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
                        let quit = handle_command(&mut framed, nick, &msg, &state).await?;
                        if quit {
                            break;
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
                    prefix: Some(SERVER_NAME.into()),
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
                prefix: Some(SERVER_NAME.into()),
                command: "PONG".into(),
                params: vec![SERVER_NAME.into(), token],
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
            prefix: Some(SERVER_NAME.into()),
            command: "001".into(),
            params: vec![
                nick.into(),
                format!("Welcome to Lagun, {nick}"),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.into()),
            command: "002".into(),
            params: vec![
                nick.into(),
                format!("Your host is {SERVER_NAME}, running Lagoon"),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.into()),
            command: "003".into(),
            params: vec![
                nick.into(),
                "This server was created today".into(),
            ],
        },
        Message {
            prefix: Some(SERVER_NAME.into()),
            command: "004".into(),
            params: vec![
                nick.into(),
                SERVER_NAME.into(),
                "lagoon-0.1.0".into(),
                "o".into(),
                "o".into(),
            ],
        },
    ];

    for msg in welcome_msgs {
        framed.send(msg).await?;
    }

    Ok(())
}

/// Handle commands from a registered client.
async fn handle_command(
    framed: &mut Framed<tokio::net::TcpStream, IrcCodec>,
    nick: &str,
    msg: &Message,
    state: &SharedState,
) -> Result<bool, Box<dyn std::error::Error>> {
    match msg.command.to_uppercase().as_str() {
        "CAP" => {
            // Post-registration CAP — just acknowledge.
            if msg.params.first().is_some_and(|p| p == "LS") {
                let reply = Message {
                    prefix: Some(SERVER_NAME.into()),
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
                prefix: Some(SERVER_NAME.into()),
                command: "PONG".into(),
                params: vec![SERVER_NAME.into(), token],
            };
            framed.send(pong).await?;
        }

        "JOIN" => {
            if let Some(channel) = msg.params.first() {
                let channel = channel.clone();
                let mut st = state.write().await;

                // Add nick to channel.
                st.channels
                    .entry(channel.clone())
                    .or_default()
                    .insert(nick.to_owned());

                let join_msg = Message {
                    prefix: Some(format!("{nick}!{nick}@lagoon")),
                    command: "JOIN".into(),
                    params: vec![channel.clone()],
                };

                // Broadcast JOIN to all members (including sender).
                let members: Vec<_> = st
                    .channels
                    .get(&channel)
                    .map(|m| m.iter().cloned().collect())
                    .unwrap_or_default();

                broadcast(&st, &members, &join_msg);

                // Send NAMES list (353) and end (366).
                let names = members.join(" ");
                drop(st);

                let names_msg = Message {
                    prefix: Some(SERVER_NAME.into()),
                    command: "353".into(),
                    params: vec![nick.into(), "=".into(), channel.clone(), names],
                };
                framed.send(names_msg).await?;

                let end_msg = Message {
                    prefix: Some(SERVER_NAME.into()),
                    command: "366".into(),
                    params: vec![nick.into(), channel, "End of /NAMES list".into()],
                };
                framed.send(end_msg).await?;
            }
        }

        "PART" => {
            if let Some(channel) = msg.params.first() {
                let reason = msg.params.get(1).cloned().unwrap_or_default();
                let mut st = state.write().await;

                let part_msg = Message {
                    prefix: Some(format!("{nick}!{nick}@lagoon")),
                    command: "PART".into(),
                    params: vec![channel.clone(), reason],
                };

                // Broadcast PART to channel (including sender).
                if let Some(members) = st.channels.get(channel) {
                    let member_list: Vec<_> = members.iter().cloned().collect();
                    broadcast(&st, &member_list, &part_msg);
                }

                // Remove nick from channel.
                if let Some(members) = st.channels.get_mut(channel) {
                    members.remove(nick);
                    if members.is_empty() {
                        st.channels.remove(channel);
                    }
                }
            }
        }

        "PRIVMSG" | "NOTICE" => {
            if msg.params.len() >= 2 {
                let target = &msg.params[0];
                let text = &msg.params[1];

                let relay = Message {
                    prefix: Some(format!("{nick}!{nick}@lagoon")),
                    command: msg.command.clone(),
                    params: vec![target.clone(), text.clone()],
                };

                let st = state.read().await;
                if target.starts_with('#') || target.starts_with('&') {
                    // Channel message — broadcast to all members except sender.
                    if let Some(members) = st.channels.get(target) {
                        let others: Vec<_> = members
                            .iter()
                            .filter(|n| *n != nick)
                            .cloned()
                            .collect();
                        broadcast(&st, &others, &relay);
                    }
                } else {
                    // Direct message to a user.
                    if let Some(handle) = st.clients.get(target) {
                        let _ = handle.tx.send(relay);
                    } else {
                        drop(st);
                        let err = Message {
                            prefix: Some(SERVER_NAME.into()),
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
                        let member_list: Vec<_> = members.iter().cloned().collect();
                        broadcast(&st, &member_list, &topic_msg);
                    }
                } else {
                    // No topic set.
                    let reply = Message {
                        prefix: Some(SERVER_NAME.into()),
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
                    // WHO for a channel — list members.
                    if let Some(members) = st.channels.get(target) {
                        for member in members {
                            let reply = Message {
                                prefix: Some(SERVER_NAME.into()),
                                command: "352".into(),
                                params: vec![
                                    nick.into(),
                                    target.clone(),
                                    member.clone(),
                                    "lagoon".into(),
                                    SERVER_NAME.into(),
                                    member.clone(),
                                    "H :0".into(),
                                    member.clone(),
                                ],
                            };
                            framed.send(reply).await?;
                        }
                    }
                }
                drop(st);
                // End of WHO.
                let end = Message {
                    prefix: Some(SERVER_NAME.into()),
                    command: "315".into(),
                    params: vec![nick.into(), target.clone(), "End of /WHO list".into()],
                };
                framed.send(end).await?;
            }
        }

        "MODE" => {
            if let Some(target) = msg.params.first() {
                if target.starts_with('#') || target.starts_with('&') {
                    // Channel mode query — return empty mode.
                    let reply = Message {
                        prefix: Some(SERVER_NAME.into()),
                        command: "324".into(),
                        params: vec![nick.into(), target.clone(), "+".into()],
                    };
                    framed.send(reply).await?;
                } else {
                    // User mode query.
                    let reply = Message {
                        prefix: Some(SERVER_NAME.into()),
                        command: "221".into(),
                        params: vec![nick.into(), "+".into()],
                    };
                    framed.send(reply).await?;
                }
            }
        }

        "QUIT" => {
            return Ok(true);
        }

        other => {
            warn!(nick, command = other, "unknown command");
            let err = Message {
                prefix: Some(SERVER_NAME.into()),
                command: "421".into(),
                params: vec![nick.into(), other.into(), "Unknown command".into()],
            };
            framed.send(err).await?;
        }
    }

    Ok(false)
}

/// Broadcast a message to a list of nicks via their channel handles.
fn broadcast(state: &ServerState, nicks: &[String], msg: &Message) {
    for nick in nicks {
        if let Some(handle) = state.clients.get(nick) {
            let _ = handle.tx.send(msg.clone());
        }
    }
}

/// Clean up when a client disconnects.
async fn cleanup_client(nick: &str, state: &SharedState) {
    let mut st = state.write().await;

    // Build quit message.
    let quit_msg = Message {
        prefix: Some(format!("{nick}!{nick}@lagoon")),
        command: "QUIT".into(),
        params: vec!["Connection closed".into()],
    };

    // Notify all channels this user was in.
    let mut notified: HashSet<String> = HashSet::new();
    for (_channel, members) in st.channels.iter() {
        if members.contains(nick) {
            for member in members {
                if member != nick && !notified.contains(member) {
                    if let Some(handle) = st.clients.get(member) {
                        let _ = handle.tx.send(quit_msg.clone());
                    }
                    notified.insert(member.clone());
                }
            }
        }
    }

    // Remove from all channels.
    st.channels.retain(|_name, members| {
        members.remove(nick);
        !members.is_empty()
    });

    // Remove from clients.
    st.clients.remove(nick);
    info!(nick, "cleaned up");
}
