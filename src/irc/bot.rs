/// LagoonBot — virtual IRC client that bridges to a Unix domain socket.
///
/// Joins #lagoon on startup, promotes the first human to channel owner (~),
/// and forwards all channel activity to connected bridge clients. Commands
/// received from the bridge are sent to IRC as LagoonBot.
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use super::message::Message;
use super::server::{broadcast, ClientHandle, MemberPrefix, SharedState};

const BOT_NICK: &str = "LagoonBot";
const SOCKET_PATH: &str = "/tmp/lagoon-bot.sock";

/// Spawn LagoonBot into the server. Call after server state is initialized.
pub async fn spawn(state: SharedState) {
    let (tx, rx) = mpsc::unbounded_channel::<Message>();

    // Register bot as a virtual client and join #lagoon.
    {
        let mut st = state.write().await;
        st.clients.insert(
            BOT_NICK.into(),
            ClientHandle {
                nick: BOT_NICK.into(),
                user: Some("bot".into()),
                realname: Some("Lagoon Channel Services".into()),
                addr: ([0, 0, 0, 0], 0u16).into(),
                tx,
            },
        );

        // Create #lagoon if it doesn't exist, join as Op.
        st.channels
            .entry("#lagoon".into())
            .or_default()
            .insert(BOT_NICK.into(), MemberPrefix::Op);
    }

    // Broadcast JOIN to anyone already in #lagoon.
    {
        let st = state.read().await;
        let join_msg = Message {
            prefix: Some(format!("{BOT_NICK}!bot@lagoon")),
            command: "JOIN".into(),
            params: vec!["#lagoon".into()],
        };
        if let Some(members) = st.channels.get("#lagoon") {
            let others: Vec<_> = members
                .keys()
                .filter(|n| *n != BOT_NICK)
                .cloned()
                .collect();
            broadcast(&st, &others, &join_msg);
        }
    }

    info!("{BOT_NICK} joined #lagoon");
    tokio::spawn(run(state, rx));
}

/// Main bot event loop — bridges IRC ↔ Unix socket.
async fn run(state: SharedState, mut rx: mpsc::UnboundedReceiver<Message>) {
    // Clean up stale socket from previous run.
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = match UnixListener::bind(SOCKET_PATH) {
        Ok(l) => l,
        Err(e) => {
            warn!("LagoonBot: failed to bind {SOCKET_PATH}: {e}");
            return;
        }
    };

    // Make socket accessible.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            SOCKET_PATH,
            std::fs::Permissions::from_mode(0o666),
        );
    }

    info!("LagoonBot bridge listening on {SOCKET_PATH}");

    // Connected bridge clients get messages streamed to them.
    let bridges: Arc<RwLock<Vec<mpsc::UnboundedSender<String>>>> =
        Arc::new(RwLock::new(Vec::new()));

    loop {
        tokio::select! {
            // Accept new bridge connections.
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        info!("LagoonBot: bridge client connected");
                        let (read_half, write_half) = stream.into_split();
                        let (btx, brx) = mpsc::unbounded_channel::<String>();
                        bridges.write().await.push(btx);

                        // Writer: streams IRC messages to the bridge client.
                        tokio::spawn(bridge_writer(write_half, brx));

                        // Reader: accepts commands from the bridge client.
                        tokio::spawn(bridge_reader(read_half, Arc::clone(&state)));
                    }
                    Err(e) => warn!("LagoonBot: accept error: {e}"),
                }
            }

            // Process IRC messages the bot receives.
            Some(msg) = rx.recv() => {
                handle_irc_message(&msg, &state, &bridges).await;
            }
        }
    }
}

/// Process a message the bot received from IRC.
async fn handle_irc_message(
    msg: &Message,
    state: &SharedState,
    bridges: &Arc<RwLock<Vec<mpsc::UnboundedSender<String>>>>,
) {
    // When a user JOINs #lagoon, only promote to Owner if the channel has
    // no owner yet (first founder). Ownership persists in channel_roles —
    // no more "anyone can own a channel if the owner leaves" nonsense.
    if msg.command == "JOIN" {
        if let Some(channel) = msg.params.first() {
            if channel == "#lagoon" {
                if let Some(prefix) = &msg.prefix {
                    let joiner = prefix.split('!').next().unwrap_or(prefix);
                    if joiner != BOT_NICK && !super::federation::is_relay_nick(joiner) {
                        let has_owner = {
                            let st = state.read().await;
                            st.channel_roles
                                .get(channel.as_str())
                                .is_some_and(|roles| {
                                    roles.values().any(|p| *p >= MemberPrefix::Owner)
                                })
                        };
                        if !has_owner {
                            promote_owner(joiner, "#lagoon", state).await;
                        }
                    }
                }
            }
        }
    }

    // Determine sender's channel prefix for access control.
    let sender_nick = msg
        .prefix
        .as_ref()
        .map(|p| p.split('!').next().unwrap_or(p).to_string());

    let channel = msg.params.first().filter(|c| c.starts_with('#') || c.starts_with('&'));

    let sender_prefix = if let (Some(nick), Some(chan)) = (&sender_nick, channel) {
        let st = state.read().await;
        st.channels
            .get(chan)
            .and_then(|m| m.get(nick).copied())
            .unwrap_or(MemberPrefix::Normal)
    } else {
        MemberPrefix::Normal
    };

    // Check if this is an @LagoonBot mention from a non-admin — if so, ignore it.
    let mentions_bot = msg.command == "PRIVMSG"
        && msg.params.get(1).is_some_and(|text| {
            text.contains("LagoonBot") || text.contains("lagoonbot")
        });

    if mentions_bot && sender_prefix < MemberPrefix::Admin {
        // Non-admin @LagoonBot — silently ignore (don't forward to bridge).
        return;
    }

    // Forward to bridge clients. Tag with sender prefix so Claude knows access level.
    let prefix_tag = sender_prefix.symbol();
    let wire = msg.to_wire();
    let tagged = if prefix_tag.is_empty() {
        wire
    } else {
        format!("[{prefix_tag}] {wire}")
    };
    let mut txs = bridges.write().await;
    txs.retain(|btx| btx.send(tagged.clone()).is_ok());
}

/// Promote a nick to Owner (~) in a channel and broadcast the MODE change.
async fn promote_owner(nick: &str, channel: &str, state: &SharedState) {
    {
        let mut st = state.write().await;
        if let Some(members) = st.channels.get_mut(channel) {
            if let Some(prefix) = members.get_mut(nick) {
                if *prefix < MemberPrefix::Owner {
                    *prefix = MemberPrefix::Owner;
                }
            }
        }
        // Persist to channel_roles so ownership survives disconnect.
        st.channel_roles
            .entry(channel.into())
            .or_default()
            .insert(nick.into(), MemberPrefix::Owner);
    }

    // Broadcast MODE +q to the channel.
    let mode_msg = Message {
        prefix: Some(format!("{BOT_NICK}!bot@lagoon")),
        command: "MODE".into(),
        params: vec![channel.into(), "+q".into(), nick.into()],
    };

    let st = state.read().await;
    if let Some(members) = st.channels.get(channel) {
        let member_list: Vec<_> = members.keys().cloned().collect();
        broadcast(&st, &member_list, &mode_msg);
    }

    info!("{BOT_NICK}: promoted {nick} to owner on {channel}");
}

/// Stream IRC messages to a bridge client over the Unix socket.
async fn bridge_writer(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut rx: mpsc::UnboundedReceiver<String>,
) {
    while let Some(line) = rx.recv().await {
        let buf = format!("{line}\n");
        if writer.write_all(buf.as_bytes()).await.is_err() {
            break;
        }
    }
}

/// Read commands from a bridge client and send them to IRC channels.
async fn bridge_reader(reader: tokio::net::unix::OwnedReadHalf, state: SharedState) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        // Parse as IRC message (e.g. "PRIVMSG #lagoon :hello!")
        let msg = match Message::parse(&line) {
            Ok(m) => m,
            Err(e) => {
                warn!("LagoonBot bridge: bad command: {e}");
                continue;
            }
        };

        if msg.command.eq_ignore_ascii_case("PRIVMSG") && msg.params.len() >= 2 {
            let target = &msg.params[0];
            let text = &msg.params[1];

            let relay = Message {
                prefix: Some(format!("{BOT_NICK}!bot@lagoon")),
                command: "PRIVMSG".into(),
                params: vec![target.clone(), text.clone()],
            };

            let st = state.read().await;
            if target.starts_with('#') || target.starts_with('&') {
                if let Some(members) = st.channels.get(target) {
                    let others: Vec<_> = members
                        .keys()
                        .filter(|n| *n != BOT_NICK)
                        .cloned()
                        .collect();
                    broadcast(&st, &others, &relay);
                }
            } else {
                if let Some(handle) = st.clients.get(target) {
                    let _ = handle.tx.send(relay);
                }
            }
        } else if msg.command.eq_ignore_ascii_case("MODE") && msg.params.len() >= 3 {
            // MODE #channel +q nick — set mode as LagoonBot.
            let target = &msg.params[0];
            let mode_str = &msg.params[1];
            let mode_target = &msg.params[2];

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
                    if let Some(p) = members.get_mut(mode_target.as_str()) {
                        *p = prefix;
                    }
                }
                // Persist to channel_roles.
                st.channel_roles
                    .entry(target.clone())
                    .or_default()
                    .insert(mode_target.clone(), prefix);

                // Broadcast MODE change.
                let mode_msg = Message {
                    prefix: Some(format!("{BOT_NICK}!bot@lagoon")),
                    command: "MODE".into(),
                    params: vec![target.clone(), mode_str.clone(), mode_target.clone()],
                };
                if let Some(members) = st.channels.get(target) {
                    let member_list: Vec<_> = members.keys().cloned().collect();
                    broadcast(&st, &member_list, &mode_msg);
                }
            }
        }
    }
}
