//! Native mesh WebSocket handler — JSON over WebSocket, no IRC.
//!
//! Accepts inbound mesh connections on `/api/mesh/ws`. Remote nodes send
//! `MeshMessage` JSON text frames. First message must be `Hello`. We respond
//! with our Hello, create a `RelayHandle`, dispatch the remote Hello (which
//! triggers the event processor to send Peers/LatencyHave/GossipSpore back
//! through the relay handle), and enter the bidirectional message loop.
//!
//! This replaces the old `federation_ws_bridge` (WS → TCP → IRC → MESH dispatch)
//! with a single-layer handler: WS → `dispatch_mesh_message()` → `event_tx`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::{
    extract::{State, WebSocketUpgrade},
    extract::ws::{Message, WebSocket},
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use lagoon_server::irc::federation::{
    build_wire_hello, dispatch_mesh_message, RelayCommand, RelayEvent, RelayHandle,
};
use lagoon_server::irc::wire::{HelloPayload, MeshMessage};

use crate::state::AppState;

/// WebSocket upgrade handler for native mesh connections.
pub async fn mesh_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_mesh_ws(socket, state))
}

async fn handle_mesh_ws(ws: WebSocket, state: AppState) {
    let irc_state = match &state.irc_state {
        Some(st) => st.clone(),
        None => {
            warn!("mesh ws: no embedded IRC state — standalone mode cannot accept mesh");
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws.split();

    // ── Phase 1: Hello exchange ───────────────────────────────────────────

    // Read first message — must be Hello.
    let timeout = Duration::from_secs(30);
    let first_msg = match tokio::time::timeout(timeout, ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            match MeshMessage::from_json(&text) {
                Ok(msg) => msg,
                Err(e) => {
                    warn!("mesh ws: invalid first message: {e}");
                    return;
                }
            }
        }
        _ => {
            warn!("mesh ws: no Hello received within timeout");
            return;
        }
    };

    let remote_hello = match first_msg {
        MeshMessage::Hello(hello) => hello,
        other => {
            warn!("mesh ws: first message must be Hello, got {:?}", std::mem::discriminant(&other));
            return;
        }
    };

    let remote_peer_id = remote_hello.peer_id.clone();
    let remote_node_name = if remote_hello.node_name.is_empty() {
        lagoon_server::irc::server::derive_node_name(&remote_hello.server_name)
    } else {
        remote_hello.node_name.clone()
    };

    info!(
        peer_id = %remote_peer_id,
        node_name = %remote_node_name,
        server_name = %remote_hello.server_name,
        "mesh ws: received Hello"
    );

    // Send our Hello.
    let our_hello = {
        let st = irc_state.read().await;
        build_wire_hello(&st)
    };
    let our_hello_msg = MeshMessage::Hello(our_hello);
    if let Ok(json) = our_hello_msg.to_json() {
        if ws_tx.send(Message::Text(json.into())).await.is_err() {
            return;
        }
    }

    // ── Phase 2: Create relay handle BEFORE dispatching Hello ─────────────
    //
    // The event processor handles MeshHello by sending Peers + LatencyHave +
    // GossipSpore back through the relay handle. The handle must exist first.

    let event_tx = {
        let st = irc_state.read().await;
        st.federation_event_tx.clone()
    };

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<RelayCommand>();

    // Dummy task handle — the real work happens in this function.
    let task_handle = tokio::spawn(std::future::pending::<()>());

    {
        let mut st = irc_state.write().await;
        st.federation.relays.insert(
            remote_node_name.clone(),
            RelayHandle {
                outgoing_tx: cmd_tx,
                remote_host: remote_node_name.clone(),
                channels: HashMap::new(),
                task_handle,
                mesh_connected: true,
                is_bootstrap: false,
                last_rtt_ms: None,
                remote_node_name: Some(remote_node_name.clone()),
            },
        );
    }

    // Now dispatch the Hello — event processor will send Peers/LatencyHave/
    // GossipSpore via our cmd_rx.
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_node_name,
        None, // TODO: extract peer addr from WS connection
        &None,
        &event_tx,
    );

    // ── Phase 3: Bidirectional message loop ───────────────────────────────

    let mut remote_mesh_key: Option<String> = Some(remote_peer_id.clone());
    let mut last_ping = Instant::now();
    let ping_interval = Duration::from_secs(30);

    loop {
        let next_ping = last_ping + ping_interval;
        let ping_delay = tokio::time::sleep_until(next_ping.into());

        tokio::select! {
            // Incoming WS message from remote peer.
            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        match MeshMessage::from_json(&text) {
                            Ok(msg) => {
                                if let Some(hello) = dispatch_mesh_message(
                                    msg,
                                    &remote_node_name,
                                    None,
                                    &remote_mesh_key,
                                    &event_tx,
                                ) {
                                    remote_mesh_key = Some(hello.peer_id);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    node = %remote_node_name,
                                    error = %e,
                                    "mesh ws: failed to parse message"
                                );
                            }
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // RTT measurement opportunity.
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!(node = %remote_node_name, "mesh ws: connection closed");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(node = %remote_node_name, error = %e, "mesh ws: read error");
                        break;
                    }
                    _ => {} // Binary frames, Ping (auto-responded by axum)
                }
            }

            // Outbound commands from the server event processor.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::SendMesh(mesh_msg)) => {
                        if let Ok(json) = mesh_msg.to_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(RelayCommand::MeshHello { json: _ }) => {
                        // Re-send our Hello (e.g., after VDF state change).
                        let hello = {
                            let st = irc_state.read().await;
                            build_wire_hello(&st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(json) = msg.to_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(RelayCommand::Shutdown) => {
                        info!(node = %remote_node_name, "mesh ws: shutdown requested");
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                    Some(RelayCommand::Reconnect) => {
                        info!(node = %remote_node_name, "mesh ws: reconnect (closing inbound)");
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                    Some(RelayCommand::Raw(irc_msg)) => {
                        // Legacy compatibility: translate IRC MESH commands.
                        if irc_msg.command == "MESH" && !irc_msg.params.is_empty() {
                            if let Some(native) = irc_mesh_to_native(&irc_msg.params) {
                                if let Ok(json) = native.to_json() {
                                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Some(_) => {} // Channel-specific IRC commands — irrelevant for mesh relay.
                    None => break, // Channel closed — relay handle removed.
                }
            }

            // Periodic WS ping for keepalive.
            _ = ping_delay => {
                if ws_tx.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
                last_ping = Instant::now();
            }
        }
    }

    // ── Cleanup ───────────────────────────────────────────────────────────

    let _ = event_tx.send(RelayEvent::Disconnected {
        remote_host: remote_node_name.clone(),
    });

    {
        let mut st = irc_state.write().await;
        st.federation.relays.remove(&remote_node_name);
    }

    info!(node = %remote_node_name, "mesh ws: handler complete");
}

/// Translate legacy IRC `MESH {subcommand} {payload}` params to native `MeshMessage`.
///
/// Temporary shim for the transition period — deleted when all sends
/// use `RelayCommand::SendMesh` exclusively.
fn irc_mesh_to_native(params: &[String]) -> Option<MeshMessage> {
    let sub = params.first()?.as_str();
    let payload = params.get(1).map(|s| s.as_str()).unwrap_or("");
    match sub {
        "HELLO" => serde_json::from_str::<HelloPayload>(payload).ok().map(MeshMessage::Hello),
        "PEERS" => serde_json::from_str(payload).ok().map(|peers| MeshMessage::Peers { peers }),
        "VDFPROOF_REQ" => Some(MeshMessage::VdfProofReq),
        "VDFPROOF" => serde_json::from_str(payload).ok().map(|proof| MeshMessage::VdfProof { proof }),
        "SYNC" => Some(MeshMessage::Sync),
        "GOSSIP" => serde_json::from_str(payload).ok().map(|message| MeshMessage::Gossip { message }),
        "GOSSIP_SPORE" => Some(MeshMessage::GossipSpore { data: payload.to_string() }),
        "GOSSIP_DIFF" => Some(MeshMessage::GossipDiff { data: payload.to_string() }),
        "LATENCY_HAVE" => Some(MeshMessage::LatencyHave { data: payload.to_string() }),
        "LATENCY_DELTA" => Some(MeshMessage::LatencyDelta { data: payload.to_string() }),
        _ => None,
    }
}
