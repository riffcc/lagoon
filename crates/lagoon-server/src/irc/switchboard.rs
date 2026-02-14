//! Anycast Switchboard Protocol (ASP) — half-dial + socket routing.
//!
//! Every node behind anycast is a switchboard. When a client dials the anycast
//! address, the node that answers identifies itself immediately. The client
//! requests a specific target (SPIRAL neighbor), and the switchboard either
//! confirms readiness or redirects the connection.
//!
//! ## Port 9443 Multiplexer
//!
//! The switchboard listens on port 9443 (the same port previously used by Ygg
//! peering). Protocol detection by first byte:
//! - `0x7B` (`{`) → switchboard half-dial (JSON + newline)
//! - Anything else → proxy to internal Ygg listener at `127.0.0.1:19443`
//!
//! ## Redirect Strategies
//!
//! - **direct**: Target's Ygg address included in `PeerRedirect`. Client closes
//!   this connection and dials the target directly via Ygg overlay.
//! - **splice**: Switchboard opens a Ygg connection to the target and proxies
//!   bytes bidirectionally. Used during bootstrap when the client has no Ygg.
//! - **repair**: TCP_REPAIR socket migration. Bare-metal BGP anycast only.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::server::ServerState;
use super::wire::SwitchboardMessage;

/// Internal Ygg listener address — the switchboard proxies non-switchboard
/// traffic here.
const YGG_INTERNAL_PORT: u16 = 19443;

/// Web gateway port — for Ygg WebSocket connections to `/api/mesh/ws`.
const WEB_GATEWAY_PORT: u16 = 8080;

/// Start the switchboard listener on the given address.
///
/// Binds a raw TCP listener and spawns a task per connection. Each connection
/// goes through protocol detection: JSON (`{`) → half-dial, anything else → Ygg proxy.
pub async fn start_switchboard(
    bind_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) {
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(l) => {
            info!(%bind_addr, "switchboard: listening");
            l
        }
        Err(e) => {
            warn!(%bind_addr, error = %e, "switchboard: failed to bind — disabled");
            return;
        }
    };

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
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
    });
}

/// Handle a single inbound connection — protocol detection then routing.
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Peek at the first byte to detect protocol.
    let mut buf = [0u8; 1];
    stream.peek(&mut buf).await?;

    if buf[0] == b'{' {
        // JSON → switchboard half-dial.
        debug!(%peer_addr, "switchboard: half-dial detected");
        half_dial(stream, peer_addr, state).await
    } else {
        // Anything else → proxy to internal Ygg listener.
        debug!(%peer_addr, "switchboard: proxying to Ygg");
        ygg_proxy(stream).await
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

/// Run the responder side of the half-dial protocol.
///
/// 1. Send `SwitchboardHello` with our identity.
/// 2. Read `PeerRequest` from client.
/// 3. Resolve target via SPIRAL topology.
/// 4. If we ARE the target → `PeerReady` → WebSocket upgrade → mesh handler.
/// 5. If not → `PeerRedirect` with the target's Ygg address (direct) or splice.
async fn half_dial(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    // Step 1: Send our identity.
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

    // Step 2: Read client's PeerRequest.
    let mut line = String::new();
    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(10),
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

    let (target_peer_id, target_ygg_addr) = match resolution {
        ResolveResult::IsSelf => {
            // We ARE the target. Send PeerReady.
            let ready = SwitchboardMessage::PeerReady {
                peer_id: our_peer_id.clone(),
            };
            writer.write_all(ready.to_line()?.as_bytes()).await?;

            info!(
                %peer_addr,
                client_peer_id,
                "switchboard: we are the target — PeerReady, upgrading to WebSocket"
            );

            // Reunite the split stream for WebSocket upgrade.
            let stream = reader.into_inner().unsplit(writer);

            // Upgrade to WebSocket and enter mesh handler.
            upgrade_to_mesh(stream, state).await?;
            return Ok(());
        }
        ResolveResult::Redirect { peer_id, ygg_addr } => (peer_id, ygg_addr),
        ResolveResult::NotFound => {
            return Err(format!("switchboard: no peer found for want={want}").into());
        }
    };

    // Step 4: Redirect — decide method based on target reachability.
    if let Some(ref ygg_addr) = target_ygg_addr {
        // Target has a known Ygg address. Check if client can dial directly.
        // If the client already sent us a PeerRequest (meaning they dialed anycast),
        // they might not have Ygg yet (bootstrap). Check if they're already connected
        // to the mesh (have a relay to us or others).
        let client_has_ygg = {
            let st = state.read().await;
            // If the client's peer_id is in our known_peers AND has a ygg address,
            // they're probably on the overlay already.
            st.mesh.known_peers.get(&client_peer_id)
                .and_then(|p| p.yggdrasil_addr.as_ref())
                .is_some()
        };

        if client_has_ygg {
            // Client is on the overlay — just tell them where to go.
            let redirect = SwitchboardMessage::PeerRedirect {
                target_peer_id: target_peer_id.clone(),
                method: "direct".into(),
                ygg_addr: Some(ygg_addr.clone()),
            };
            writer.write_all(redirect.to_line()?.as_bytes()).await?;

            info!(
                %peer_addr,
                client_peer_id,
                target_peer_id,
                %ygg_addr,
                "switchboard: redirect (direct) — client has Ygg"
            );
            return Ok(());
        }
    }

    // Client doesn't have Ygg yet (bootstrap) or target has no Ygg address.
    // Choose redirect strategy: TCP_REPAIR if available, otherwise splice.
    let caps = anymesh::Capabilities::detect();
    if caps.tcp_repair {
        // TCP_REPAIR: freeze the socket and send migration to target via mesh relay.
        let redirect = SwitchboardMessage::PeerRedirect {
            target_peer_id: target_peer_id.clone(),
            method: "repair".into(),
            ygg_addr: target_ygg_addr.clone(),
        };
        writer.write_all(redirect.to_line()?.as_bytes()).await?;

        info!(
            %peer_addr,
            client_peer_id,
            target_peer_id,
            "switchboard: redirect (repair) — freezing socket for migration"
        );

        // Reunite the stream for freezing.
        let client_stream = reader.into_inner().unsplit(writer);

        redirect_repair(client_stream, &target_peer_id, &client_peer_id, state).await
    } else {
        // Splice: proxy bytes through us.
        let redirect = SwitchboardMessage::PeerRedirect {
            target_peer_id: target_peer_id.clone(),
            method: "splice".into(),
            ygg_addr: target_ygg_addr.clone(),
        };
        writer.write_all(redirect.to_line()?.as_bytes()).await?;

        info!(
            %peer_addr,
            client_peer_id,
            target_peer_id,
            "switchboard: redirect (splice) — proxying to target"
        );

        // Reunite the stream for splice.
        let client_stream = reader.into_inner().unsplit(writer);

        // Splice: connect to target via Ygg overlay and proxy bytes.
        redirect_splice(client_stream, &target_peer_id, target_ygg_addr.as_deref(), state).await
    }
}

/// Result of resolving a `want` field against SPIRAL topology.
enum ResolveResult {
    /// We are the requested target.
    IsSelf,
    /// The target is a different node.
    Redirect {
        peer_id: String,
        ygg_addr: Option<String>,
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
                return ResolveResult::Redirect {
                    peer_id: peer_id.clone(),
                    ygg_addr: info.yggdrasil_addr.clone(),
                };
            }
        }
        // No other peers known. We're the only node (or bootstrap hasn't completed).
        // Accept locally — the client will get our HELLO and can proceed.
        return ResolveResult::IsSelf;
    }

    if let Some(slot_str) = want.strip_prefix("spiral_slot:") {
        if let Ok(slot) = slot_str.parse::<u64>() {
            // Look up who occupies this SPIRAL slot.
            if let Some(mesh_key) = st.mesh.spiral.peer_at_index(slot) {
                if mesh_key == our_peer_id {
                    return ResolveResult::IsSelf;
                }
                let peer_id_str = mesh_key.to_string();
                let ygg_addr = st.mesh.known_peers.get(&peer_id_str)
                    .and_then(|p| p.yggdrasil_addr.clone());
                return ResolveResult::Redirect {
                    peer_id: peer_id_str,
                    ygg_addr,
                };
            }
        }
        return ResolveResult::NotFound;
    }

    if let Some(target_id) = want.strip_prefix("peer:") {
        if target_id == our_peer_id {
            return ResolveResult::IsSelf;
        }
        let ygg_addr = st.mesh.known_peers.get(target_id)
            .and_then(|p| p.yggdrasil_addr.clone());
        return ResolveResult::Redirect {
            peer_id: target_id.to_string(),
            ygg_addr,
        };
    }

    ResolveResult::NotFound
}

/// Splice: proxy bytes between the client and the target node via Ygg overlay.
///
/// Opens a WebSocket connection to the target's `/api/mesh/ws` via Ygg overlay,
/// then does bidirectional byte forwarding. The client sees a transparent pipe
/// to the target.
async fn redirect_splice(
    client: TcpStream,
    target_peer_id: &str,
    target_ygg_addr: Option<&str>,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Look up the target's Ygg address.
    let ygg_addr_str = match target_ygg_addr {
        Some(addr) => addr.to_string(),
        None => {
            let st = state.read().await;
            st.mesh.known_peers.get(target_peer_id)
                .and_then(|p| p.yggdrasil_addr.clone())
                .ok_or_else(|| format!("switchboard: no Ygg address for {target_peer_id}"))?
        }
    };

    let ygg_v6: Ipv6Addr = ygg_addr_str.parse()
        .map_err(|e| format!("switchboard: bad Ygg addr '{ygg_addr_str}': {e}"))?;

    // Get the Ygg node from transport config.
    let ygg_node = {
        let st = state.read().await;
        st.transport_config.ygg_node.clone()
            .ok_or("switchboard: no Ygg node available for splice")?
    };

    // Dial the target via Ygg overlay.
    let ygg_stream = ygg_node.dial(ygg_v6, WEB_GATEWAY_PORT).await
        .map_err(|e| format!("switchboard: Ygg dial to {ygg_v6} failed: {e}"))?;

    // Upgrade to WebSocket — the target expects HTTP WebSocket upgrade.
    let url = format!("ws://[{ygg_v6}]:{WEB_GATEWAY_PORT}/api/mesh/ws");
    let (ws_stream, _) = tokio_tungstenite::client_async(&url, ygg_stream).await
        .map_err(|e| format!("switchboard: WebSocket upgrade to {ygg_v6} failed: {e}"))?;

    info!(
        target_peer_id,
        %ygg_v6,
        "switchboard: splice established via Ygg"
    );

    // The client expects to speak WebSocket to the target after PeerReady/PeerRedirect.
    // But the client hasn't done a WebSocket upgrade yet on its side (it's still raw TCP).
    //
    // We need the client to send its HTTP Upgrade request. We accept it on our side,
    // then forward WebSocket frames bidirectionally.
    //
    // Accept WebSocket upgrade from the client.
    let client_ws = tokio_tungstenite::accept_async(client).await
        .map_err(|e| format!("switchboard: client WS upgrade failed: {e}"))?;

    // Forward WebSocket frames bidirectionally.
    ws_splice(client_ws, ws_stream).await;

    Ok(())
}

/// TCP_REPAIR redirect: freeze the client's socket and send the migration state
/// to the target node via an existing mesh relay.
///
/// The target receives a `SocketMigrate` mesh message and calls `handle_socket_migration()`
/// to reconstruct the socket and enter the mesh handler.
async fn redirect_repair(
    client: TcpStream,
    target_peer_id: &str,
    client_peer_id: &str,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;

    // Convert tokio TcpStream → std TcpStream for freeze.
    let std_stream = client.into_std()
        .map_err(|e| format!("switchboard: into_std failed: {e}"))?;

    // Freeze the socket — extracts ~40 bytes of TCP state.
    let migration = anymesh::freeze(&std_stream)
        .map_err(|e| format!("switchboard: TCP_REPAIR freeze failed: {e}"))?;

    // Close the socket silently (no RST, no FIN — it's in repair mode).
    anymesh::repair::close_silent(std_stream);

    // Encode migration state for wire transport.
    let migration_bytes = bincode::serialize(&migration)
        .map_err(|e| format!("switchboard: bincode serialize failed: {e}"))?;
    let migration_b64 = base64::engine::general_purpose::STANDARD.encode(&migration_bytes);

    info!(
        target_peer_id,
        client_peer_id,
        migration_size = migration_bytes.len(),
        "switchboard: socket frozen — sending migration to target"
    );

    // Send the migration to the target via their existing mesh relay.
    let msg = super::wire::MeshMessage::SocketMigrate {
        migration: migration_b64,
        client_peer_id: client_peer_id.to_string(),
    };

    // Find the target's relay and send the migration message.
    let sent = {
        let st = state.read().await;
        // Relays are keyed by peer_id — direct lookup.
        let found = if let Some(relay) = st.federation.relays.get(target_peer_id) {
            let _ = relay.outgoing_tx.send(super::federation::RelayCommand::SendMesh(msg.clone()));
            true
        } else {
            false
        };
        found
    };

    if sent {
        info!(
            target_peer_id,
            "switchboard: migration sent to target via mesh relay"
        );
    } else {
        warn!(
            target_peer_id,
            "switchboard: no relay found for target — migration dropped"
        );
    }

    Ok(())
}

/// Bidirectional WebSocket frame forwarding between two WebSocket streams.
async fn ws_splice<S1, S2>(client: S1, target: S2)
where
    S1: futures::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + futures::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
    S2: futures::Sink<tokio_tungstenite::tungstenite::Message, Error = tokio_tungstenite::tungstenite::Error>
        + futures::Stream<Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    use futures::{SinkExt, StreamExt};

    let (mut client_tx, mut client_rx) = client.split();
    let (mut target_tx, mut target_rx) = target.split();

    let client_to_target = async {
        while let Some(msg) = client_rx.next().await {
            match msg {
                Ok(msg) => {
                    if target_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    let target_to_client = async {
        while let Some(msg) = target_rx.next().await {
            match msg {
                Ok(msg) => {
                    if client_tx.send(msg).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    };

    // Run both directions concurrently. When either ends, both stop.
    tokio::select! {
        _ = client_to_target => {}
        _ = target_to_client => {}
    }
}

/// Upgrade a raw TCP stream to WebSocket and enter the mesh handler.
///
/// After `PeerReady`, the client sends an HTTP Upgrade request. We accept it
/// and enter the standard mesh message loop (same as `lagoon-web/src/mesh.rs`).
async fn upgrade_to_mesh(
    stream: TcpStream,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use futures::{SinkExt, StreamExt};
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message;

    use super::federation::{
        build_wire_hello, dispatch_mesh_message, RelayCommand, RelayEvent, RelayHandle,
    };
    use super::wire::MeshMessage;

    let ws = tokio_tungstenite::accept_async(stream).await
        .map_err(|e| format!("switchboard: WebSocket upgrade failed: {e}"))?;

    let (mut ws_tx, mut ws_rx) = ws.split();

    // ── Phase 1: Hello exchange ─────────────────────────────────────────

    // Read first message — must be Hello.
    let timeout = Duration::from_secs(30);
    let first_msg = match tokio::time::timeout(timeout, ws_rx.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
            MeshMessage::from_json(&text)?
        }
        _ => return Err("switchboard: no Hello received within timeout".into()),
    };

    let remote_hello = match first_msg {
        MeshMessage::Hello(hello) => hello,
        _ => return Err("switchboard: first WS message must be Hello".into()),
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
        "switchboard: received Hello via half-dial"
    );

    // Send our Hello.
    let our_hello = {
        let mut st = state.write().await;
        build_wire_hello(&mut st)
    };
    let hello_json = MeshMessage::Hello(our_hello).to_json()?;
    ws_tx.send(Message::Text(hello_json.into())).await
        .map_err(|e| format!("switchboard: failed to send Hello: {e}"))?;

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
                mesh_connected: true,
                is_bootstrap: false,
                last_rtt_ms: None,
            },
        );
    }

    // Dispatch the Hello — relay key = peer_id.
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_peer_id,
        None,
        &None,
        &event_tx,
    );

    // ── Phase 3: Bidirectional message loop ─────────────────────────────

    let remote_mesh_key: Option<String> = Some(remote_peer_id.clone());
    let mut last_ping = Instant::now();
    let ping_interval = Duration::from_secs(30);

    loop {
        let next_ping = last_ping + ping_interval;
        let ping_delay = tokio::time::sleep_until(next_ping.into());

        tokio::select! {
            ws_msg = ws_rx.next() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        match MeshMessage::from_json(&text) {
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
                    Some(Ok(Message::Close(_))) | None => {
                        info!(node = %remote_node_name, "switchboard: connection closed");
                        break;
                    }
                    Some(Err(e)) => {
                        warn!(node = %remote_node_name, error = %e, "switchboard: read error");
                        break;
                    }
                    _ => {}
                }
            }

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
                        let hello = {
                            let mut st = state.write().await;
                            build_wire_hello(&mut st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(json) = msg.to_json() {
                            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(RelayCommand::Shutdown | RelayCommand::Reconnect) => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                    Some(_) => {}
                    None => break,
                }
            }

            _ = ping_delay => {
                if ws_tx.send(Message::Ping(vec![].into())).await.is_err() {
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
/// with the original 4-tuple and proceed with the mesh WebSocket exchange.
pub async fn handle_socket_migration(
    migration_b64: &str,
    client_peer_id: &str,
    state: Arc<RwLock<ServerState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;

    // Decode the base64-encoded bincode SocketMigration.
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

    // TCP_REPAIR restore — reconstructs a live TCP socket with the original 4-tuple.
    let std_stream = anymesh::restore(&migration)
        .map_err(|e| format!("switchboard: TCP_REPAIR restore failed: {e}"))?;

    std_stream.set_nonblocking(true)
        .map_err(|e| format!("switchboard: set_nonblocking failed: {e}"))?;

    let tcp_stream = tokio::net::TcpStream::from_std(std_stream)
        .map_err(|e| format!("switchboard: tokio TcpStream conversion failed: {e}"))?;

    info!(
        client_peer_id,
        "switchboard: socket restored — upgrading to WebSocket mesh handler"
    );

    // Enter the standard mesh handler — same as PeerReady path.
    upgrade_to_mesh(tcp_stream, state).await
}
