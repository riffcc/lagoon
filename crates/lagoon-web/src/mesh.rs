//! Native mesh WebSocket handler — JSON over WebSocket, no IRC.
//!
//! Accepts inbound mesh connections on `/api/mesh/ws`. Remote nodes send
//! `MeshMessage` JSON text frames. First message must be `Hello`.
//!
//! **Juggler architecture:** mesh.rs is many arms (concurrent I/O), the
//! federation loop is the single brain (sequential state).
//!
//! 1. Read remote Hello (pure I/O — many arms accept concurrently)
//! 2. Create RelayHandle (plumbing — gives federation loop a send channel)
//! 3. Dispatch MeshHello event (hand the ball to the brain)
//! 4. Enter bidirectional message loop (forward commands from brain to WS)
//!
//! The federation loop processes each Hello in order. Each merge sees the
//! result of all previous merges. Response Hello (with correct assigned_slot)
//! comes back through the relay handle's `outgoing_tx`.
//!
//! Single-layer handler: WS → `dispatch_mesh_message()` → `event_tx`.

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

    // Self-connection check — if remote peer_id matches ours, send Hello +
    // Redirect (known peers) so the outbound side can detect self-connection
    // and activate the flashlight protocol.
    {
        let mut st = irc_state.write().await;
        if st.lens.peer_id == remote_peer_id {
            info!("mesh ws: self-connection detected — sending Hello + Redirect before closing");

            // Send our Hello so the outbound relay can detect self-connection
            // (peer_id match) and set the flashlight flag.
            let our_hello = build_wire_hello(&mut st);
            let our_hello_msg = MeshMessage::Hello(our_hello);
            if let Ok(json) = our_hello_msg.to_json() {
                let _ = ws_tx.send(Message::Text(json.into())).await;
            }

            // Send Redirect with known peers — even on self-connection, the
            // stuck node can discover who else is in the mesh.
            let peers: Vec<lagoon_server::irc::server::MeshPeerInfo> =
                st.mesh.known_peers.values().cloned().collect();
            if !peers.is_empty() {
                let redirect = MeshMessage::Redirect { peers };
                if let Ok(json) = redirect.to_json() {
                    let _ = ws_tx.send(Message::Text(json.into())).await;
                }
            }

            drop(st);
            let _ = ws_tx.send(Message::Close(None)).await;
            return;
        }
    }

    // Response HELLO is NOT sent here. The federation loop builds and sends
    // it AFTER processing the remote's HELLO (evaluate_spiral_merge), so
    // the response carries correct spiral_index and assigned_slot reflecting
    // ALL previous merges. mesh.rs is just plumbing — accept, read, dispatch.

    // ── Phase 1.5: Handle existing relay to this peer ─────────────────
    //
    // If we already have a relay keyed by this peer_id, the new inbound
    // connection replaces it. The old relay's cmd_rx will see its sender
    // dropped and clean up naturally. This is correct: a fresh connection
    // is proof the remote is alive NOW; the old one may be stale.
    {
        let st = irc_state.read().await;
        if st.federation.relays.contains_key(&remote_peer_id) {
            info!(
                peer_id = %remote_peer_id,
                "mesh ws: replacing existing relay with fresh inbound connection"
            );
        }
        drop(st);
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

    {
        let mut st = irc_state.write().await;
        st.federation.relays.insert(
            remote_peer_id.clone(),
            RelayHandle {
                outgoing_tx: cmd_tx,
                node_name: remote_node_name.clone(),
                connect_target: String::new(), // inbound — no connect target
                channels: HashMap::new(),
                mesh_connected: false, // NOT ready yet — set true after federation loop sends response HELLO
                is_bootstrap: false,
                last_rtt_ms: None,
            },
        );
    }

    // Now dispatch the Hello — event processor will send Peers/LatencyHave/
    // GossipSpore via our cmd_rx. remote_host = peer_id (relay key).
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_peer_id,
        None, // TODO: extract peer addr from WS connection
        &None,
        &event_tx,
    );

    // ── Phase 3: Bidirectional message loop ───────────────────────────────

    let remote_mesh_key: Option<String> = Some(remote_peer_id.clone());
    let mut last_ping = Instant::now();
    let ping_interval = Duration::from_secs(30);
    // PoL challenge timing — nonce → when we sent it.
    let mut pol_pending: std::collections::HashMap<u64, Instant> = std::collections::HashMap::new();

    loop {
        let next_ping = last_ping + ping_interval;
        let ping_delay = tokio::time::sleep_until(next_ping.into());

        tokio::select! {
            // Incoming WS message from remote peer.
            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        match MeshMessage::from_json(&text) {
                            Ok(MeshMessage::PolChallenge { nonce }) => {
                                // Fast path — respond immediately, no dispatch.
                                let response = MeshMessage::PolResponse { nonce };
                                if let Ok(json) = response.to_json() {
                                    if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            Ok(MeshMessage::PolResponse { nonce }) => {
                                // Complete timing — relay-local, no dispatch.
                                if let Some(sent_at) = pol_pending.remove(&nonce) {
                                    let rtt_us = sent_at.elapsed().as_micros() as u64;
                                    let _ = event_tx.send(RelayEvent::PolCompleted {
                                        remote_host: remote_peer_id.clone(),
                                        rtt_us,
                                        mesh_key: remote_mesh_key.clone(),
                                    });
                                }
                            }
                            Ok(msg) => {
                                // remote_host = peer_id for relay lookup.
                                let _ = dispatch_mesh_message(
                                    msg,
                                    &remote_peer_id,
                                    None,
                                    &remote_mesh_key,
                                    &event_tx,
                                );
                            }
                            Err(e) => {
                                warn!(
                                    peer_id = %remote_peer_id,
                                    error = %e,
                                    "mesh ws: failed to parse message"
                                );
                            }
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Measure RTT from Ping→Pong round-trip.
                        let rtt_ms = last_ping.elapsed().as_secs_f64() * 1000.0;
                        let _ = event_tx.send(RelayEvent::LatencyMeasured {
                            remote_host: remote_peer_id.clone(),
                            rtt_ms,
                            mesh_key: remote_mesh_key.clone(),
                        });
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!(peer_id = %remote_peer_id, "mesh ws: connection closed");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(peer_id = %remote_peer_id, error = %e, "mesh ws: read error");
                        break;
                    }
                    _ => {} // Binary frames, Ping (auto-responded by axum)
                }
            }

            // Outbound commands from the server event processor.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::SendMesh(mesh_msg)) => {
                        // Record timing for outgoing PoL challenges.
                        if let MeshMessage::PolChallenge { nonce } = &mesh_msg {
                            pol_pending.insert(*nonce, Instant::now());
                        }
                        if let Ok(json) = mesh_msg.to_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(RelayCommand::MeshHello { json: _ }) => {
                        // Re-send our Hello (e.g., after VDF state change).
                        let hello = {
                            let mut st = irc_state.write().await;
                            build_wire_hello(&mut st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(json) = msg.to_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(RelayCommand::Shutdown) => {
                        info!(peer_id = %remote_peer_id, "mesh ws: shutdown requested");
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                    Some(RelayCommand::Reconnect) => {
                        info!(peer_id = %remote_peer_id, "mesh ws: reconnect (closing inbound)");
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
        remote_host: remote_peer_id.clone(),
    });

    {
        let mut st = irc_state.write().await;
        st.federation.relays.remove(&remote_peer_id);
    }

    info!(peer_id = %remote_peer_id, "mesh ws: handler complete");
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
