/// Channel federation — Matrix-style `#room:server` relay over Yggdrasil mesh.
///
/// When a user joins `#lagoon:per.lagun.co`, the local server connects to
/// `per.lagun.co:6667` as an IRC client, joins `#lagoon`, and relays messages
/// bidirectionally. One relay connection per remote host — multiple federated
/// channels to the same host share a single TCP connection.
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use futures::SinkExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::message::Message;
use super::server::{broadcast, ServerState, SharedState, SERVER_NAME};

/// Check if a nick belongs to relay infrastructure.
///
/// Relay nicks follow the pattern `{prefix}~relay` with optional trailing
/// characters from nick collision resolution (e.g. `lon~relay_`).
pub fn is_relay_nick(nick: &str) -> bool {
    nick.contains("~relay")
}

/// Peer servers for auto-federation (from `LAGOON_PEERS` env var).
///
/// When set, every local channel is automatically federated to all peers.
/// Format: comma-separated hostnames, e.g. "lon.lagun.co,per.lagun.co,nyc.lagun.co".
/// The local server's own hostname is automatically excluded.
pub static PEERS: LazyLock<Vec<String>> = LazyLock::new(|| {
    let our_name = &*SERVER_NAME;
    let peers: Vec<String> = std::env::var("LAGOON_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != our_name)
        .collect();
    if !peers.is_empty() {
        info!("auto-federation peers: {}", peers.join(", "));
    }
    peers
});

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

/// Build the NAMES string for a local channel, including remote federated users.
///
/// Combines local channel members (with prefix symbols, filtering relay nicks)
/// and remote users from all federation relays tracking this channel.
pub fn build_channel_names(st: &ServerState, channel: &str) -> String {
    let mut parts: Vec<String> = st
        .channels
        .get(channel)
        .map(|m| {
            m.iter()
                .filter(|(n, _)| !is_relay_nick(n))
                .map(|(n, p)| format!("{}{n}", p.symbol()))
                .collect()
        })
        .unwrap_or_default();
    for relay in st.federation.relays.values() {
        if let Some(fed_ch) = relay.channels.get(channel) {
            for rn in &fed_ch.remote_users {
                if rn.contains('@') {
                    parts.push(rn.clone());
                } else {
                    parts.push(format!("{rn}@{}", relay.remote_host));
                }
            }
        }
    }
    parts.join(" ")
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
                    let local_nicks: Vec<String> =
                        if parse_federated_channel(&local_channel).is_some() {
                            // Explicit federation — notify subscribers.
                            st.federation
                                .relays
                                .get(&remote_host)
                                .and_then(|r| r.channels.get(&local_channel))
                                .map(|fc| fc.local_users.iter().cloned().collect())
                                .unwrap_or_default()
                        } else {
                            // Auto-federation — notify real channel members.
                            st.channels
                                .get(&local_channel)
                                .map(|m| {
                                    m.keys()
                                        .filter(|n| !is_relay_nick(n))
                                        .cloned()
                                        .collect()
                                })
                                .unwrap_or_default()
                        };
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
                    // Determine who to notify.
                    let notify_nicks: Vec<String> =
                        if parse_federated_channel(&local_channel).is_some() {
                            st.federation
                                .relays
                                .get(&remote_host)
                                .and_then(|r| r.channels.get(&local_channel))
                                .map(|fc| fc.local_users.iter().cloned().collect())
                                .unwrap_or_default()
                        } else {
                            st.channels
                                .get(&local_channel)
                                .map(|m| {
                                    m.keys()
                                        .filter(|n| !is_relay_nick(n))
                                        .cloned()
                                        .collect()
                                })
                                .unwrap_or_default()
                        };
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
                    // Determine who to notify.
                    let notify_nicks: Vec<String> =
                        if parse_federated_channel(&local_channel).is_some() {
                            st.federation
                                .relays
                                .get(&remote_host)
                                .and_then(|r| r.channels.get(&local_channel))
                                .map(|fc| fc.local_users.iter().cloned().collect())
                                .unwrap_or_default()
                        } else {
                            st.channels
                                .get(&local_channel)
                                .map(|m| {
                                    m.keys()
                                        .filter(|n| !is_relay_nick(n))
                                        .cloned()
                                        .collect()
                                })
                                .unwrap_or_default()
                        };
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

                    // Build NAMES and determine recipients.
                    let is_explicit =
                        parse_federated_channel(&local_channel).is_some();
                    let (names_str, local_nicks) = if is_explicit {
                        // Explicit federation: local_users + this relay's remote_users.
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
                        let nicks: Vec<_> =
                            fed_ch.local_users.iter().cloned().collect();
                        (parts.join(" "), nicks)
                    } else {
                        // Auto-federation: local members + ALL relays' remote_users.
                        let names = build_channel_names(&st, &local_channel);
                        let nicks: Vec<_> = st
                            .channels
                            .get(&local_channel)
                            .map(|m| {
                                m.keys()
                                    .filter(|n| !is_relay_nick(n))
                                    .cloned()
                                    .collect()
                            })
                            .unwrap_or_default();
                        (names, nicks)
                    };

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
                    let st = state.read().await;
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
            }
        }
    });
}

/// Spawn a relay connection to a remote server.
pub fn spawn_relay(
    remote_host: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
) -> (mpsc::UnboundedSender<RelayCommand>, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(relay_task(
        remote_host,
        cmd_rx,
        event_tx,
    ));

    (cmd_tx, handle)
}

/// Per-channel state within the relay task.
struct TaskChannel {
    local_channel: String,
    joined: bool,
    pending: Vec<RelayCommand>,
}

/// The relay task — connects to a remote Lagoon server, registers, and
/// relays messages bidirectionally for multiple channels using FRELAY.
async fn relay_task(
    remote_host: String,
    mut cmd_rx: mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
) {
    let our_name = &*SERVER_NAME;
    let mut relay_nick = if let Some(prefix) = our_name.split('.').next() {
        format!("{prefix}~relay")
    } else {
        "lagoon~relay".into()
    };

    let our_suffix = format!("@{our_name}");

    let addr = format!("{remote_host}:6667");
    info!(remote_host, "federation: connecting to {addr}");

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(remote_host, "federation: failed to connect: {e}");
            let _ = event_tx.send(RelayEvent::Disconnected {
                remote_host,
            });
            return;
        }
    };

    info!(remote_host, "federation: TCP connected to {addr}");
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
        warn!(remote_host, "federation: failed to send registration");
        let _ = event_tx.send(RelayEvent::Disconnected { remote_host });
        return;
    }

    info!(remote_host, "federation: registration sent, waiting for 001");
    let mut registered = false;
    // remote_channel → per-channel task state.
    let mut channels: HashMap<String, TaskChannel> = HashMap::new();
    // Commands received before registration completes.
    let mut pre_reg_cmds: Vec<RelayCommand> = Vec::new();

    loop {
        tokio::select! {
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
                        // Process any JoinChannel commands queued before registration.
                        for cmd in pre_reg_cmds.drain(..) {
                            if let RelayCommand::JoinChannel { remote_channel, local_channel } = cmd {
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

    let _ = event_tx.send(RelayEvent::Disconnected { remote_host });
}

/// Send a FRELAY command to the remote server. Returns true on success.
async fn send_frelay(
    framed: &mut Framed<TcpStream, IrcCodec>,
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
