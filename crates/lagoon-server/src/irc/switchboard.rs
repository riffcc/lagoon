//! Anycast Switchboard Protocol (ASP) — half-dial + socket routing.
//!
//! Every node behind anycast is a switchboard. When a client dials the anycast
//! address, the node that answers routes the connection to the right peer.
//!
//! ## Port 9443 Multiplexer
//!
//! The switchboard listens on port 9443 (raw TCP, no HTTP proxy). Protocol
//! detection by first byte:
//! - `0x7B` (`{`) → switchboard half-dial (JSON lines)
//! - Anything else → proxy to internal Ygg listener at `127.0.0.1:19443`
//!
//! ## Self-Connection Avoidance
//!
//! Before dialing anycast, the mesh connector **pauses** the switchboard
//! listener (drops the listening socket). If the SYN routes back to us,
//! the kernel RSTs it (port closed) and Fly routes to the next machine.
//! After connecting, the listener is resumed (rebound). No application-level
//! self-detection needed — the kernel handles it.
//!
//! ## Half-Dial Protocol (client sends first)
//!
//! 1. Client sends `PeerRequest` (JSON line with `my_peer_id` + `want`)
//! 2. Server reads PeerRequest, sends `SwitchboardHello` (identity)
//! 3. Server sends `PeerReady` or `PeerRedirect`
//! 4. If PeerReady → raw TCP JSON-lines mesh session (no WebSocket)
//!
//! ## Redirect Strategies
//!
//! - **direct**: Target's underlay address included in `PeerRedirect`. Client
//!   dials the target directly via TCP on the underlay address.
//! - **repair**: TCP_REPAIR socket migration. Bare-metal BGP anycast only.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::federation::{
    build_wire_hello, dispatch_mesh_message, RelayCommand, RelayEvent, RelayHandle,
};
use super::server::ServerState;
use super::wire::{MeshMessage, SwitchboardMessage};

/// Internal Ygg listener address — the switchboard proxies non-switchboard
/// traffic here.
const YGG_INTERNAL_PORT: u16 = 19443;

/// Control messages for the switchboard listener.
///
/// The mesh connector sends `Pause` before dialing anycast (so our own port
/// is closed and the kernel RSTs self-routed SYNs) and `Resume` after.
pub enum SwitchboardCtl {
    /// Drop the listening socket. New SYNs get kernel RST.
    Pause,
    /// Rebind and resume accepting connections.
    Resume,
}

/// Start the switchboard listener on the given address.
///
/// Returns a control channel sender. The mesh connector uses this to
/// pause/resume the listener around anycast dials.
pub async fn start_switchboard(
    bind_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) -> Option<mpsc::UnboundedSender<SwitchboardCtl>> {
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => {
            info!(%bind_addr, "switchboard: listening");
            l
        }
        Err(e) => {
            warn!(%bind_addr, error = %e, "switchboard: failed to bind — disabled");
            return None;
        }
    };

    let (ctl_tx, mut ctl_rx) = mpsc::unbounded_channel::<SwitchboardCtl>();

    tokio::spawn(async move {
        let mut listener = listener;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            let state = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, peer_addr, state).await {
                                    debug!(%peer_addr, error = %e, "switchboard: connection error");
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "switchboard: accept error");
                        }
                    }
                }

                ctl = ctl_rx.recv() => {
                    match ctl {
                        Some(SwitchboardCtl::Pause) => {
                            // Drop the listener → port closed → kernel RSTs new SYNs.
                            drop(listener);
                            debug!("switchboard: paused (listener dropped)");

                            // Wait for Resume.
                            loop {
                                match ctl_rx.recv().await {
                                    Some(SwitchboardCtl::Resume) => break,
                                    Some(SwitchboardCtl::Pause) => {} // Already paused.
                                    None => return, // Channel closed.
                                }
                            }

                            // Rebind.
                            match TcpListener::bind(bind_addr).await {
                                Ok(l) => {
                                    listener = l;
                                    debug!("switchboard: resumed (listener rebound)");
                                }
                                Err(e) => {
                                    warn!(%bind_addr, error = %e,
                                        "switchboard: failed to rebind after pause");
                                    return;
                                }
                            }
                        }
                        Some(SwitchboardCtl::Resume) => {} // Already running.
                        None => return, // Channel closed.
                    }
                }
            }
        }
    });

    Some(ctl_tx)
}

/// Handle a single inbound connection — protocol detection and routing.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek at first byte for protocol detection.
    let mut buf = [0u8; 1];
    let n = stream.peek(&mut buf).await?;
    if n == 0 {
        return Err("switchboard: empty peek".into());
    }

    match buf[0] {
        b'{' => {
            // JSON → switchboard half-dial.
            debug!(%peer_addr, "switchboard: half-dial detected");
            half_dial(stream, peer_addr, state).await
        }
        _ => {
            // Anything else → proxy to internal Ygg listener.
            debug!(%peer_addr, "switchboard: proxying to Ygg");
            ygg_proxy(stream).await
        }
    }
}

/// Proxy a non-switchboard connection to the internal Ygg listener.
///
/// Bidirectional byte forwarding to `127.0.0.1:19443`.
async fn ygg_proxy(
    mut client: TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ygg_addr: SocketAddr = ([127, 0, 0, 1], YGG_INTERNAL_PORT).into();
    let mut ygg = TcpStream::connect(ygg_addr).await?;
    tokio::io::copy_bidirectional(&mut client, &mut ygg).await?;
    Ok(())
}

/// Run the responder side of the half-dial protocol (client sends first).
///
/// 1. Read `PeerRequest` from client (already peeked, now consume).
/// 2. Send `SwitchboardHello` with our identity.
/// 3. Resolve target via SPIRAL topology.
/// 4. If we ARE the target → `PeerReady` → raw TCP mesh session (JSON lines).
/// 5. If not → `PeerRedirect` with the target's underlay address.
async fn half_dial(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Step 1: Read client's PeerRequest (client sends first for multiplexer peek).
    let mut line = String::new();
    let timeout = tokio::time::timeout(
        Duration::from_secs(10),
        reader.read_line(&mut line),
    );
    match timeout.await {
        Ok(Ok(0)) | Err(_) => {
            return Err("switchboard: no PeerRequest received".into());
        }
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(_)) => {}
    }

    let request = SwitchboardMessage::from_line(&line)?;
    let (client_peer_id, want) = match request {
        SwitchboardMessage::PeerRequest { my_peer_id, want } => (my_peer_id, want),
        other => {
            return Err(format!("switchboard: expected PeerRequest, got {other:?}").into());
        }
    };

    // Step 2: Send our identity.
    let (our_peer_id, our_spiral_slot) = {
        let st = state.read().await;
        (
            st.lens.peer_id.clone(),
            st.mesh.spiral.our_index().map(|idx| idx.value()),
        )
    };

    let hello = SwitchboardMessage::SwitchboardHello {
        peer_id: our_peer_id.clone(),
        spiral_slot: our_spiral_slot,
    };
    writer.write_all(hello.to_line()?.as_bytes()).await?;

    info!(
        %peer_addr,
        client_peer_id,
        want,
        "switchboard: received PeerRequest"
    );

    // Step 3: Resolve target.
    let resolution = {
        let st = state.read().await;
        resolve_target(&want, &our_peer_id, &client_peer_id, &st)
    };

    match resolution {
        ResolveResult::IsSelf => {
            // We ARE the target. Send PeerReady, then enter raw mesh session.
            let ready = SwitchboardMessage::PeerReady {
                peer_id: our_peer_id.clone(),
            };
            writer.write_all(ready.to_line()?.as_bytes()).await?;

            info!(
                %peer_addr,
                client_peer_id,
                "switchboard: PeerReady — entering raw mesh session"
            );

            // Enter raw TCP mesh handler (JSON lines, no WebSocket).
            raw_mesh_handler(reader, writer, state).await?;
            Ok(())
        }
        ResolveResult::Redirect { peer_id, underlay_addr } => {
            if let Some(ref underlay) = underlay_addr {
                let redirect = SwitchboardMessage::PeerRedirect {
                    target_peer_id: peer_id.clone(),
                    method: "direct".into(),
                    ygg_addr: Some(underlay.clone()),
                };
                writer.write_all(redirect.to_line()?.as_bytes()).await?;
                info!(
                    %peer_addr,
                    client_peer_id,
                    target_peer_id = %peer_id,
                    %underlay,
                    "switchboard: redirect (direct, underlay)"
                );
            } else {
                return Err(format!(
                    "switchboard: redirect target {peer_id} has no underlay address"
                ).into());
            }
            Ok(())
        }
        ResolveResult::NotFound => {
            Err(format!("switchboard: no peer found for want={want}").into())
        }
    }
}

/// Result of resolving a `want` field against SPIRAL topology.
enum ResolveResult {
    /// We are the requested target.
    IsSelf,
    /// The target is a different node. `underlay_addr` is the target's
    /// reachable UNDERLAY address (e.g. `tcp://[fdaa::]:9443`) — a real IP,
    /// NOT an overlay address. The client dials this directly.
    Redirect {
        peer_id: String,
        underlay_addr: Option<String>,
    },
    /// No peer found matching the request.
    NotFound,
}

/// Resolve a `want` string to a target peer.
///
/// - `"any"` → pick any connected peer that isn't the client or us
/// - `"spiral_slot:N"` → look up who occupies slot N
/// - `"peer:ID"` → specific peer_id
fn resolve_target(
    want: &str,
    our_peer_id: &str,
    client_peer_id: &str,
    st: &ServerState,
) -> ResolveResult {
    if want == "any" {
        // Bootstrap: find any connected peer that isn't the client or us.
        for (peer_id, info) in &st.mesh.known_peers {
            if peer_id != our_peer_id && peer_id != client_peer_id {
                // Prefer underlay_uri (derived from TCP peer addr), fall back
                // to ygg_peer_uri (self-reported). Both are UNDERLAY addresses.
                let underlay = info.underlay_uri.clone()
                    .or_else(|| info.ygg_peer_uri.clone());
                return ResolveResult::Redirect {
                    peer_id: peer_id.clone(),
                    underlay_addr: underlay,
                };
            }
        }
        // No other peers known. We're the only node (or bootstrap hasn't completed).
        // Accept locally — the client will get our HELLO and can proceed.
        return ResolveResult::IsSelf;
    }

    if let Some(slot_str) = want.strip_prefix("spiral_slot:") {
        if let Ok(slot) = slot_str.parse::<u64>() {
            if let Some(mesh_key) = st.mesh.spiral.peer_at_index(slot) {
                if mesh_key == our_peer_id {
                    return ResolveResult::IsSelf;
                }
                let peer_id_str = mesh_key.to_string();
                let underlay = st.mesh.known_peers.get(&peer_id_str)
                    .and_then(|p| p.underlay_uri.clone().or_else(|| p.ygg_peer_uri.clone()));
                return ResolveResult::Redirect {
                    peer_id: peer_id_str,
                    underlay_addr: underlay,
                };
            }
        }
        return ResolveResult::NotFound;
    }

    if let Some(target_id) = want.strip_prefix("peer:") {
        if target_id == our_peer_id {
            return ResolveResult::IsSelf;
        }
        let underlay = st.mesh.known_peers.get(target_id)
            .and_then(|p| p.underlay_uri.clone().or_else(|| p.ygg_peer_uri.clone()));
        return ResolveResult::Redirect {
            peer_id: target_id.to_string(),
            underlay_addr: underlay,
        };
    }

    ResolveResult::NotFound
}

/// Raw TCP mesh handler — JSON-lines mesh session (no WebSocket).
///
/// After PeerReady, the TCP stream continues with newline-delimited JSON
/// MeshMessages. This is the inbound half of the mesh session — reads
/// incoming messages, dispatches them to the event processor, and sends
/// outgoing messages from the relay command channel.
async fn raw_mesh_handler(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ── Phase 1: Hello exchange ─────────────────────────────────────────

    // Read first message — must be Hello.
    let timeout = Duration::from_secs(30);
    let mut hello_line = String::new();
    match tokio::time::timeout(timeout, reader.read_line(&mut hello_line)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return Err("switchboard: no Hello received within timeout".into()),
    }

    let first_msg = MeshMessage::from_json(hello_line.trim_end())?;
    let remote_hello = match first_msg {
        MeshMessage::Hello(hello) => hello,
        _ => return Err("switchboard: first message must be Hello".into()),
    };

    let remote_peer_id = remote_hello.peer_id.clone();
    let remote_node_name = if remote_hello.node_name.is_empty() {
        super::server::derive_node_name(&remote_hello.server_name)
    } else {
        remote_hello.node_name.clone()
    };

    info!(
        peer_id = %remote_peer_id,
        node_name = %remote_node_name,
        "switchboard: received Hello"
    );

    // Do NOT send Hello here. The event processor sends the response Hello
    // AFTER evaluate_spiral_merge (the Juggler invariant). Sending it here
    // would give the remote stale topology — no assigned_slot, pre-merge
    // spiral_index. The correct Hello comes via RelayCommand::SendMesh
    // from the federation event loop after processing the MeshHello event.

    // ── Phase 2: Create relay handle ────────────────────────────────────

    let event_tx = {
        let st = state.read().await;
        st.federation_event_tx.clone()
    };

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<RelayCommand>();

    {
        let mut st = state.write().await;
        st.federation.relays.insert(
            remote_peer_id.clone(),
            RelayHandle {
                outgoing_tx: cmd_tx,
                node_name: remote_node_name.clone(),
                connect_target: String::new(), // inbound via switchboard
                channels: HashMap::new(),
                mesh_connected: false, // Set to true by event processor after sending post-merge Hello
                is_bootstrap: false,
                last_rtt_ms: None,
            },
        );
    }

    // Dispatch the Hello.
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_peer_id,
        None,
        &None,
        &event_tx,
    );

    // ── Phase 3: Bidirectional message loop (JSON lines) ────────────────

    let remote_mesh_key: Option<String> = Some(remote_peer_id.clone());
    let mut last_ping = Instant::now();
    let ping_interval = Duration::from_secs(30);
    let mut incoming_line = String::new();

    loop {
        let next_ping = last_ping + ping_interval;
        let ping_delay = tokio::time::sleep_until(next_ping.into());

        tokio::select! {
            // Read incoming JSON line.
            result = reader.read_line(&mut incoming_line) => {
                match result {
                    Ok(0) | Err(_) => {
                        info!(node = %remote_node_name, "switchboard: connection closed");
                        break;
                    }
                    Ok(_) => {
                        let trimmed = incoming_line.trim_end();
                        if !trimmed.is_empty() {
                            match MeshMessage::from_json(trimmed) {
                                Ok(msg) => {
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
                                        node = %remote_node_name,
                                        error = %e,
                                        "switchboard: failed to parse message"
                                    );
                                }
                            }
                        }
                        incoming_line.clear();
                    }
                }
            }

            // Send outgoing commands.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::SendMesh(mesh_msg)) => {
                        if let Ok(json) = mesh_msg.to_json() {
                            if writer.write_all(json.as_bytes()).await.is_err() { break; }
                            if writer.write_all(b"\n").await.is_err() { break; }
                        }
                    }
                    Some(RelayCommand::MeshHello { json: _ }) => {
                        let hello = {
                            let mut st = state.write().await;
                            build_wire_hello(&mut st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(json) = msg.to_json() {
                            if writer.write_all(json.as_bytes()).await.is_err() { break; }
                            if writer.write_all(b"\n").await.is_err() { break; }
                        }
                    }
                    Some(RelayCommand::Shutdown | RelayCommand::Reconnect) => {
                        break;
                    }
                    Some(_) => {}
                    None => break,
                }
            }

            // Keepalive — write an empty line so the remote knows we're alive.
            _ = ping_delay => {
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
                last_ping = Instant::now();
            }
        }
    }

    // Cleanup — relay keyed by peer_id.
    let _ = event_tx.send(RelayEvent::Disconnected {
        remote_host: remote_peer_id.clone(),
    });
    {
        let mut st = state.write().await;
        st.federation.relays.remove(&remote_peer_id);
    }

    info!(node = %remote_node_name, "switchboard: handler complete");
    Ok(())
}

/// Handle an incoming socket migration — restore a TCP_REPAIR'd socket and enter
/// the mesh handler.
///
/// Called when this node receives a `SocketMigrate` message from a switchboard node
/// that froze the client's TCP socket and sent us the state. We reconstruct the socket
/// with the original 4-tuple and proceed with the raw mesh handler.
pub async fn handle_socket_migration(
    migration_b64: &str,
    client_peer_id: &str,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;

    let bytes = base64::engine::general_purpose::STANDARD.decode(migration_b64)
        .map_err(|e| format!("switchboard: invalid base64 migration: {e}"))?;

    let migration: anymesh::SocketMigration = bincode::deserialize(&bytes)
        .map_err(|e| format!("switchboard: invalid bincode migration: {e}"))?;

    info!(
        client_peer_id,
        local = %migration.local_addr,
        remote = %migration.remote_addr,
        "switchboard: restoring migrated socket via TCP_REPAIR"
    );

    let std_stream = anymesh::restore(&migration)
        .map_err(|e| format!("switchboard: TCP_REPAIR restore failed: {e}"))?;

    std_stream.set_nonblocking(true)
        .map_err(|e| format!("switchboard: set_nonblocking failed: {e}"))?;

    let tcp_stream = tokio::net::TcpStream::from_std(std_stream)
        .map_err(|e| format!("switchboard: tokio TcpStream conversion failed: {e}"))?;

    info!(
        client_peer_id,
        "switchboard: socket restored — entering raw mesh handler"
    );

    let (read_half, write_half) = tcp_stream.into_split();
    let reader = BufReader::new(read_half);
    raw_mesh_handler(reader, write_half, state).await
}
