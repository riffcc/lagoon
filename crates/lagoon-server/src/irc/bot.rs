/// LagoonBot — virtual IRC client providing channel services.
///
/// Joins #lagoon on startup, promotes the first human to channel owner (~),
/// and responds to help commands.
use tokio::sync::mpsc;
use tracing::info;

use super::message::Message;
use super::server::{broadcast, ClientHandle, MemberPrefix, SharedState};

const BOT_NICK: &str = "LagoonBot";

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

/// Main bot event loop.
async fn run(state: SharedState, mut rx: mpsc::UnboundedReceiver<Message>) {
    while let Some(msg) = rx.recv().await {
        handle_irc_message(&msg, &state).await;
    }
}

/// Process a message the bot received from IRC.
async fn handle_irc_message(msg: &Message, state: &SharedState) {
    let sender_nick = msg
        .prefix
        .as_ref()
        .map(|p| p.split('!').next().unwrap_or(p).to_string());

    match msg.command.as_str() {
        "JOIN" => {
            // When a user JOINs #lagoon, promote to Owner if no owner exists yet.
            if let Some(channel) = msg.params.first() {
                if channel == "#lagoon" {
                    if let Some(ref nick) = sender_nick {
                        if nick != BOT_NICK && !super::federation::is_relay_nick(nick) {
                            let has_owner = {
                                let st = state.read().await;
                                st.channel_roles
                                    .get(channel.as_str())
                                    .is_some_and(|roles| {
                                        roles.values().any(|p| *p >= MemberPrefix::Owner)
                                    })
                            };
                            if !has_owner {
                                promote_owner(nick, "#lagoon", state).await;
                            }
                        }
                    }
                }
            }
        }

        "PRIVMSG" => {
            let text = msg.params.get(1).map(|s| s.as_str()).unwrap_or("");
            let target = msg.params.first().map(|s| s.as_str()).unwrap_or("");

            // Respond to !help in channels, or any DM to the bot.
            let is_dm = target == BOT_NICK;
            let is_help = text.starts_with("!help");

            if is_dm || is_help {
                let reply_target = if is_dm {
                    sender_nick.as_deref().unwrap_or("*")
                } else {
                    target
                };
                send_help(reply_target, state).await;
            }
        }

        _ => {}
    }
}

const HELP_LINES: &[&str] = &[
    "LagoonBot \x02\x0312Lagoon Channel Services\x0F",
    " ",
    "  \x02!help\x02          Show this menu",
    " ",
    "Lagoon is a decentralized communication platform.",
    "More bot features coming soon: channel management,",
    "user verification, federation status, mesh network info.",
    " ",
    "\x0314https://github.com/riffcc/lagoon\x0F",
];

async fn send_help(target: &str, state: &SharedState) {
    let st = state.read().await;
    for line in HELP_LINES {
        let help_msg = Message {
            prefix: Some(format!("{BOT_NICK}!bot@lagoon")),
            command: "PRIVMSG".into(),
            params: vec![target.into(), (*line).into()],
        };
        if target.starts_with('#') || target.starts_with('&') {
            // Channel message — broadcast to all members.
            if let Some(members) = st.channels.get(target) {
                let member_list: Vec<_> = members.keys().cloned().collect();
                broadcast(&st, &member_list, &help_msg);
            }
        } else {
            // DM — send to the user directly.
            if let Some(handle) = st.clients.get(target) {
                let _ = handle.tx.send(help_msg);
            }
        }
    }
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
