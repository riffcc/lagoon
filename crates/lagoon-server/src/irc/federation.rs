/// Channel federation — Matrix-style `#room:server` relay over Yggdrasil mesh.
///
/// When a user joins `#lagoon:per.lagun.co`, the local server connects to
/// `per.lagun.co:6667` as an IRC client, joins `#lagoon`, and relays messages
/// bidirectionally. One relay connection per remote host — multiple federated
/// channels to the same host share a single TCP connection.
///
/// Also handles MESH protocol for topology exchange between peers.
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use futures::SinkExt;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;
use tracing::{info, warn};

use super::codec::IrcCodec;
use super::lens;
use super::message::Message;
use super::server::{broadcast, derive_node_name, MeshConnectionState, MeshPeerInfo, SharedState, SERVER_NAME, SITE_NAME};
use super::transport::{self, TransportConfig};
use super::wire::{MeshMessage, HelloPayload};
use base64::Engine as _;

/// Build the Yggdrasil underlay peer URI for APE (Anycast Peer Entry).
///
/// Strategy: prefer the **underlay address** derived from the relay's TCP peer
/// address (confirmed-different node via MESH HELLO peer_id verification)
/// over the overlay address from `ygg_peer_uri`.
///
/// Derive a Ygg underlay peer URI from the relay's TCP peer address.
///
/// The relay already has a TCP connection to a confirmed-different node.
/// That IP is a real underlay address (fdaa:: on Fly, LAN IP on bare metal).
///
/// NEVER falls back to overlay addresses (200:xxxx::). If we don't have
/// a relay_peer_addr, we don't peer — we wait until one arrives.
///
/// Returns `None` if no relay_peer_addr is available.
pub fn ape_peer_uri(
    relay_peer_addr: Option<SocketAddr>,
) -> Option<String> {
    relay_peer_addr.map(|addr| {
        format!("tcp://[{}]:9443", addr.ip())
    })
}

/// Construct a Ygg peer URI from a switchboard address.
///
/// The switchboard on port 9443 detects `meta` first bytes and routes
/// to `ygg_node.accept_inbound()`. This provides cross-provider Ygg
/// bootstrap when the underlay URI is unreachable (midlay path).
///
/// Handles IPv4, IPv6 (bracketed), and hostnames (DNS resolved by Tokio).
fn switchboard_ygg_uri(addr: &str) -> String {
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("tcp://[{}]:9443", addr)
    } else {
        format!("tcp://{}:9443", addr)
    }
}

/// Check that a peer URI is a real underlay address, NOT an Ygg overlay.
///
/// Ygg overlay addresses start with 02xx or 03xx (200:/300: in IPv6 notation).
/// Peering with an overlay address tunnels Ygg through Ygg — double
/// encapsulation, 1s+ latency, dies when the underlying path changes.
pub fn is_underlay_uri(uri: &str) -> bool {
    // Extract the address from tcp://[addr]:port format.
    if let Some(start) = uri.find('[') {
        if let Some(end) = uri.find(']') {
            let addr_str = &uri[start + 1..end];
            if let Ok(addr) = addr_str.parse::<std::net::Ipv6Addr>() {
                let first_byte = addr.octets()[0];
                // 0x02, 0x03 = Ygg overlay (200:/300:)
                if first_byte == 0x02 || first_byte == 0x03 {
                    warn!(
                        uri,
                        "BLOCKED: refusing to peer Ygg with overlay address — \
                         would tunnel Ygg through Ygg"
                    );
                    return false;
                }
            }
        }
    }
    true
}

/// Dispatch a received `MeshMessage` into the appropriate `RelayEvent`.
///
/// Single code path for all mesh message processing — called from both
/// the inbound WebSocket handler and the outbound relay_task.
///
/// Returns the `HelloPayload` if the message was a Hello (needed by callers
/// to extract identity and set `remote_mesh_key`).
pub fn dispatch_mesh_message(
    msg: MeshMessage,
    remote_host: &str,
    relay_peer_addr: Option<SocketAddr>,
    remote_mesh_key: &Option<String>,
    event_tx: &mpsc::UnboundedSender<RelayEvent>,
) -> Option<HelloPayload> {
    match msg {
        MeshMessage::Hello(hello) => {
            let site_name = if hello.site_name.is_empty() {
                super::server::derive_site_name(&hello.server_name)
            } else {
                hello.site_name.clone()
            };
            let node_name = if hello.node_name.is_empty() {
                derive_node_name(&hello.server_name)
            } else {
                hello.node_name.clone()
            };
            let _ = event_tx.send(RelayEvent::MeshHello {
                remote_host: remote_host.to_string(),
                peer_id: hello.peer_id.clone(),
                server_name: hello.server_name.clone(),
                public_key_hex: hello.public_key_hex.clone(),
                spiral_index: hello.spiral_index,
                vdf_genesis: hello.vdf_genesis.clone(),
                vdf_hash: hello.vdf_hash.clone(),
                vdf_step: hello.vdf_step,
                yggdrasil_addr: hello.yggdrasil_addr.clone(),
                site_name,
                node_name,
                vdf_resonance_credit: hello.vdf_resonance_credit,
                vdf_actual_rate_hz: hello.vdf_actual_rate_hz,
                vdf_cumulative_credit: hello.vdf_cumulative_credit,
                ygg_peer_uri: hello.ygg_peer_uri.clone(),
                relay_peer_addr,
                cvdf_height: hello.cvdf_height,
                cvdf_weight: hello.cvdf_weight,
                cvdf_tip_hex: hello.cvdf_tip_hex.clone(),
                cvdf_genesis_hex: hello.cvdf_genesis_hex.clone(),
                cluster_vdf_work: hello.cluster_vdf_work,
                assigned_slot: hello.assigned_slot,
                cluster_chain_value: hello.cluster_chain_value.clone(),
                cluster_chain_epoch_origin: hello.cluster_chain_epoch_origin.clone(),
                cluster_chain_round: hello.cluster_chain_round,
                cluster_chain_work: hello.cluster_chain_work,
                cluster_round_seed: hello.cluster_round_seed.clone(),
            });
            Some(hello)
        }
        MeshMessage::Peers { peers } => {
            let _ = event_tx.send(RelayEvent::MeshPeers {
                remote_host: remote_host.to_string(),
                peers,
            });
            None
        }
        MeshMessage::VdfProofReq => {
            // Legacy: old nodes send this. Respond with a window proof instead.
            let _ = event_tx.send(RelayEvent::MeshVdfProofReq {
                remote_host: remote_host.to_string(),
            });
            None
        }
        MeshMessage::VdfProof { proof } => {
            // Legacy: old nodes send full-chain proofs. Still accepted.
            let _ = event_tx.send(RelayEvent::MeshVdfProof {
                remote_host: remote_host.to_string(),
                proof_json: proof.to_string(),
                mesh_key: remote_mesh_key.clone(),
            });
            None
        }
        MeshMessage::VdfWindow { data } => {
            tracing::debug!(
                remote_host,
                mesh_key = ?remote_mesh_key,
                data_len = data.len(),
                "dispatch: received VdfWindow"
            );
            if let Err(e) = event_tx.send(RelayEvent::MeshVdfWindow {
                remote_host: remote_host.to_string(),
                data,
                mesh_key: remote_mesh_key.clone(),
            }) {
                tracing::error!("dispatch: event_tx.send(MeshVdfWindow) FAILED — event loop dead? err={e}");
            }
            None
        }
        MeshMessage::Sync => {
            let _ = event_tx.send(RelayEvent::MeshSync {
                remote_host: remote_host.to_string(),
            });
            None
        }
        MeshMessage::Gossip { message } => {
            let _ = event_tx.send(RelayEvent::GossipReceive {
                remote_host: remote_host.to_string(),
                message_json: message.to_string(),
            });
            None
        }
        MeshMessage::GossipSpore { data } => {
            let _ = event_tx.send(RelayEvent::GossipSpore {
                remote_host: remote_host.to_string(),
                spore_json: data,
            });
            None
        }
        MeshMessage::GossipDiff { data } => {
            let _ = event_tx.send(RelayEvent::GossipDiff {
                remote_host: remote_host.to_string(),
                messages_json: data,
            });
            None
        }
        MeshMessage::LatencyHave { data } => {
            let _ = event_tx.send(RelayEvent::LatencyHaveList {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::LatencyDelta { data } => {
            let _ = event_tx.send(RelayEvent::LatencyProofDelta {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::ProfileQuery { username } => {
            let _ = event_tx.send(RelayEvent::ProfileQuery {
                remote_host: remote_host.to_string(),
                username,
            });
            None
        }
        MeshMessage::ProfileResponse { username, profile } => {
            let _ = event_tx.send(RelayEvent::ProfileResponse {
                remote_host: remote_host.to_string(),
                username,
                profile,
            });
            None
        }
        MeshMessage::ProfileHave { data } => {
            let _ = event_tx.send(RelayEvent::ProfileHave {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::ProfileDelta { data } => {
            let _ = event_tx.send(RelayEvent::ProfileDelta {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::ConnectionHave { data } => {
            let _ = event_tx.send(RelayEvent::ConnectionHave {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::ConnectionDelta { data } => {
            let _ = event_tx.send(RelayEvent::ConnectionDelta {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::LivenessHave { data } => {
            let _ = event_tx.send(RelayEvent::LivenessHave {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::LivenessDelta { data } => {
            let _ = event_tx.send(RelayEvent::LivenessDelta {
                remote_host: remote_host.to_string(),
                payload_b64: data,
            });
            None
        }
        MeshMessage::SocketMigrate { migration, client_peer_id } => {
            let _ = event_tx.send(RelayEvent::SocketMigrate {
                remote_host: remote_host.to_string(),
                migration,
                client_peer_id,
            });
            None
        }
        MeshMessage::ChainUpdate { value, cumulative_work, round, proof, work_contributions, epoch_origin } => {
            let _ = event_tx.send(RelayEvent::ChainUpdate {
                remote_host: remote_host.to_string(),
                value,
                cumulative_work,
                round,
                proof,
                work_contributions,
                epoch_origin,
            });
            None
        }
        MeshMessage::Cvdf { data } => {
            let _ = event_tx.send(RelayEvent::CvdfMessage {
                remote_host: remote_host.to_string(),
                data,
            });
            None
        }
        MeshMessage::Redirect { peers } => {
            // Redirect = "I already know you, here are peers to connect to."
            // Dispatch peers for discovery. The caller handles the
            // "don't reconnect" signal — we just deliver the data.
            let _ = event_tx.send(RelayEvent::MeshPeers {
                remote_host: remote_host.to_string(),
                peers,
            });
            None
        }
        // PolChallenge is handled inline by the relay loop for minimal latency.
        // If it reaches dispatch, it's a no-op (e.g., unexpected path).
        MeshMessage::PolChallenge { .. } => None,
        // PolResponse is NOT handled inline — we don't have timing context here.
        // The relay loop handles it directly for timing precision.
        MeshMessage::PolResponse { .. } => None,
    }
}

/// Prune relay connections to non-SPIRAL peers.
///
/// SPIRAL is the sole authority on which direct connections we maintain.
/// Non-neighbors are reachable transitively via Yggdrasil forwarding.
fn prune_non_spiral_relays(st: &mut super::server::ServerState) {
    if !st.mesh.spiral.is_claimed() {
        return;
    }

    // Don't prune until we know enough peers for SPIRAL to be meaningful.
    // If known_peers < neighbor_count, the topology is still converging and
    // pruning would kill connections we need for gossip propagation.
    let neighbor_count = st.mesh.spiral.neighbors().len();
    if st.mesh.known_peers.len() < neighbor_count {
        return;
    }

    // Don't prune if we have very few connections. With a small mesh, every
    // connection is precious. Pruning is for shedding excess connections in a
    // large topology, not for killing the only links in a 3-node cluster.
    let non_bootstrap = st.federation.relays.values()
        .filter(|h| !h.is_bootstrap)
        .count();
    if non_bootstrap <= neighbor_count.max(2) {
        return;
    }

    let to_prune: Vec<String> = st.federation.relays.iter()
        .filter(|(peer_id, handle)| {
            // Never prune bootstrap peers — they're the network backbone.
            if handle.is_bootstrap {
                return false;
            }
            // Don't prune peers still bootstrapping (no SPIRAL slot yet).
            // They need this relay to receive their slot assignment.
            if !st.mesh.spiral.has_slot(peer_id) {
                return false;
            }
            // Peer HAS a slot — check if it's our neighbor.
            let is_neighbor = st.mesh.spiral.is_neighbor(peer_id);
            if !is_neighbor {
                info!(
                    peer_id = %peer_id,
                    node_name = %handle.node_name,
                    neighbor_count,
                    non_bootstrap,
                    "mesh: prune candidate — not a SPIRAL neighbor"
                );
            }
            !is_neighbor
        })
        .map(|(key, _)| key.clone())
        .collect();

    for pid in to_prune {
        if let Some(handle) = st.federation.relays.remove(&pid) {
            info!(peer_id = %pid, node_name = %handle.node_name, "mesh: pruned non-SPIRAL relay");
            let _ = handle.outgoing_tx.send(RelayCommand::Shutdown);
        }
    }
}

/// Dial any SPIRAL neighbors that we don't have a relay connection to.
///
/// Called after the SPIRAL neighbor set changes (HELLO, SPIRAL claim, disconnect).
/// For each neighbor with a known underlay address and no existing relay:
/// 1. Add them as a Ygg underlay peer (direct link, not routed through overlay)
/// 2. Spawn a WebSocket relay over that direct link
///
/// The mesh IS an Ygg mesh — every SPIRAL neighbor gets a direct underlay connection.
pub fn dial_missing_spiral_neighbors(
    st: &mut super::server::ServerState,
    state: super::server::SharedState,
) {
    if !st.mesh.spiral.is_claimed() {
        return;
    }

    let our_pid = st.lens.peer_id.clone();
    let neighbor_keys: Vec<String> = st.mesh.spiral.neighbors().iter().cloned().collect();
    let event_tx = st.federation_event_tx.clone();
    let tc = st.transport_config.clone();
    let ygg_node = st.transport_config.ygg_node.clone();

    let relay_count = st.federation.relays.len();
    let pending_count = st.federation.pending_dials.len();
    tracing::debug!(
        neighbor_count = neighbor_keys.len(),
        relay_count,
        pending_count,
        "dial_missing_spiral_neighbors: evaluating"
    );

    for neighbor_mkey in &neighbor_keys {
        if *neighbor_mkey == our_pid {
            continue;
        }

        let peer = match st.mesh.known_peers.get(neighbor_mkey) {
            Some(p) => p,
            None => {
                tracing::debug!(
                    neighbor = %neighbor_mkey,
                    "dial_missing: neighbor not in known_peers"
                );
                continue;
            }
        };

        let node_name = peer.node_name.clone();

        // Add a direct Ygg underlay link for SPIRAL neighbors — but only once.
        // After the first successful add (or "already configured" error), record
        // the URI so we don't spam add_peer on every cycle.
        //
        // CRITICAL: ONLY use confirmed underlay addresses. NEVER fall back to
        // ygg_peer_uri — that may be an overlay address (tcp://[200:xxxx::]:9443).
        // Peering with an overlay address tunnels Ygg through Ygg: double
        // encapsulation, 1s+ latency, dies when the anycast path changes.
        // If we don't have a real underlay address, we wait until gossip
        // delivers one.
        let peer_uri = peer.underlay_uri.as_ref()
            .filter(|uri| is_underlay_uri(uri));
        if let Some(ref uri) = peer_uri {
            if !st.mesh.ygg_peered_uris.contains(uri.as_str()) {
                if let Some(ref ygg) = ygg_node {
                    match ygg.add_peer(uri) {
                        Ok(()) => {
                            info!(
                                underlay_uri = %uri,
                                peer = %node_name,
                                "mesh: added SPIRAL neighbor as Ygg underlay peer"
                            );
                            st.mesh.ygg_peered_uris.insert(uri.to_string());
                        }
                        Err(e) => {
                            warn!(
                                underlay_uri = %uri,
                                peer = %node_name,
                                error = %e,
                                "mesh: failed to add SPIRAL neighbor as Ygg underlay peer"
                            );
                        }
                    }
                }
            }
        }

        // Skip relay spawn if we already have one to this peer.
        let has_relay = st.federation.relays.contains_key(neighbor_mkey);
        let has_pending = st.federation.pending_dials.contains(&node_name);
        if has_relay || has_pending {
            tracing::debug!(
                neighbor = %neighbor_mkey,
                node_name = %node_name,
                has_relay,
                has_pending,
                "dial_missing: skipping — already connected or pending"
            );
            continue;
        }

        // ── Route selection for SPIRAL neighbor connection ──────────
        //
        // Priority 1: Ygg overlay (if we have overlay connectivity).
        // Priority 2: Anycast switchboard with targeted want="peer:{id}".
        //
        // The switchboard is the key mechanism: dial the anycast entry
        // point, request a specific peer, and the switchboard routes the
        // TCP connection. No Ygg overlay needed. This is how the third
        // leg of the triangle forms — you learn about peer C from peer B,
        // then dial anycast requesting C specifically.
        let peer_ygg_addr: Option<std::net::Ipv6Addr> = peer
            .yggdrasil_addr
            .as_deref()
            .and_then(|s| s.parse().ok());

        // Find an anycast switchboard entry point.
        // Priority 1: explicit LAGOON_SWITCHBOARD_ADDR (e.g. Bunny anycast IP).
        // Priority 2: bootstrap peer with port 9443 (e.g. Fly anycast).
        let anycast_entry: Option<String> = tc.switchboard_addr.clone()
            .or_else(|| tc.peers.iter()
                .find(|(_, e)| e.port == transport::SWITCHBOARD_PORT && !e.tls)
                .map(|(host, _)| host.clone()));

        if peer_ygg_addr.is_none() && anycast_entry.is_none() {
            tracing::debug!(
                peer = %node_name,
                neighbor_mkey = %neighbor_mkey,
                "mesh: SPIRAL neighbor has no Ygg overlay and no anycast entry — cannot route"
            );
            continue;
        }

        // Choose route: switchboard (if configured) > Ygg overlay > anycast fallback.
        //
        // When LAGOON_SWITCHBOARD_ADDR is set, ALL SPIRAL dials go through the
        // switchboard. The server-side L4 splice handles cross-provider routing
        // transparently (Bunny→switchboard→Fly target). Without a switchboard
        // addr, direct dial via Ygg overlay/underlay (Fly→Fly).
        let (connect_key, peer_entry) = if let Some(ref sb_addr) = tc.switchboard_addr {
            info!(
                peer = %node_name,
                neighbor_mkey = %neighbor_mkey,
                switchboard = %sb_addr,
                "mesh: dialing SPIRAL neighbor via switchboard"
            );
            (sb_addr.clone(), transport::PeerEntry {
                yggdrasil_addr: None,
                port: transport::SWITCHBOARD_PORT,
                tls: false,
                want: Some(format!("peer:{}", neighbor_mkey)),
                dial_host: None,
            })
        } else if peer_ygg_addr.is_some() {
            // Ygg overlay — dial the peer's switchboard directly.
            // Port MUST be SWITCHBOARD_PORT (9443) — SPIRAL neighbors use the
            // switchboard protocol, not IRC. peer.port is the IRC listen port
            // (6667 etc.) which connect_native rejects as PlainTcp.
            //
            // Prefer underlay address (LAN IP like 10.7.1.37) over Ygg overlay
            // address (200:xxxx::). Underlay works immediately; overlay only
            // works when the Ygg mesh is fully established with peering.
            let underlay_host = peer_uri.map(|u| transport::extract_host_from_uri(u));
            (node_name.clone(), transport::PeerEntry {
                yggdrasil_addr: peer_ygg_addr,
                port: transport::SWITCHBOARD_PORT,
                tls: false,
                want: None,
                dial_host: underlay_host,
            })
        } else {
            // Anycast switchboard — dial the entry point, request this specific peer.
            let anycast = anycast_entry.unwrap();
            info!(
                peer = %node_name,
                neighbor_mkey = %neighbor_mkey,
                anycast = %anycast,
                "mesh: dialing SPIRAL neighbor via anycast switchboard"
            );
            (anycast, transport::PeerEntry {
                yggdrasil_addr: None,
                port: transport::SWITCHBOARD_PORT,
                tls: false,
                want: Some(format!("peer:{}", neighbor_mkey)),
                dial_host: None,
            })
        };

        info!(
            peer = %node_name,
            neighbor_mkey = %neighbor_mkey,
            connect_key = %connect_key,
            has_underlay = peer_uri.is_some(),
            has_ygg_overlay = peer_ygg_addr.is_some(),
            "mesh: dialing SPIRAL neighbor"
        );

        // Pre-insert BEFORE spawn — the spawned task needs the write lock
        // (which we hold via &mut st), so it can't insert until we release.
        // Without pre-insert, the loop spawns duplicates for the same peer.
        st.federation.pending_dials.insert(connect_key.clone());

        let mut tc_with_peer = (*tc).clone();
        tc_with_peer.peers.entry(connect_key.clone()).or_insert(peer_entry);
        let tc_arc = Arc::new(tc_with_peer);

        spawn_native_relay(
            connect_key,
            event_tx.clone(),
            tc_arc,
            state.clone(),
            false,
        );
    }
}

/// Check if a nick belongs to relay infrastructure.
///
/// Relay nicks follow the pattern `{prefix}~relay` with optional trailing
/// characters from nick collision resolution (e.g. `lon~relay_`).
pub fn is_relay_nick(nick: &str) -> bool {
    nick.contains("~relay")
}

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
///
/// Keyed by `peer_id` (cryptographic identity: `b3b3/` + hex of BLAKE3(BLAKE3(pubkey))).
/// Inserted by the relay task itself AFTER the HELLO exchange, when the remote's
/// peer_id is known. Removed by the relay task on disconnect, before sending
/// `RelayEvent::Disconnected`.
#[derive(Debug)]
pub struct RelayHandle {
    /// Send outgoing commands to the relay task.
    pub outgoing_tx: mpsc::UnboundedSender<RelayCommand>,
    /// Human-readable node name (for logs and display). NOT an identity key.
    pub node_name: String,
    /// The host:port used to establish this connection (e.g. "lagun.co:443").
    pub connect_target: String,
    /// Channels active on this relay: local_channel → per-channel state.
    pub channels: HashMap<String, FederatedChannel>,
    /// Whether this relay was created by the mesh connector (kept alive even with no channels).
    pub mesh_connected: bool,
    /// Whether this relay was created from LAGOON_PEERS (bootstrap peer).
    pub is_bootstrap: bool,
    /// Last measured IRC-layer round-trip time in milliseconds (from PING/PONG).
    pub last_rtt_ms: Option<f64>,
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
    /// Send a native mesh protocol message (JSON over WebSocket).
    ///
    /// Used by the event processor for all mesh-related sends. Native inbound
    /// handlers serialize directly to JSON; legacy outbound relay_tasks translate
    /// to IRC `MESH {subcommand} {json}` lines.
    SendMesh(MeshMessage),
    /// Send MESH HELLO after registration.
    MeshHello { json: String },
    /// Shut down the relay connection entirely.
    Shutdown,
    /// Drop the current connection and reconnect (connection lost by remote).
    Reconnect,
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
    /// Received MESH HELLO from a remote peer.
    MeshHello {
        remote_host: String,
        /// Cryptographic peer identity (`"b3b3/{hex}"`), NOT the lens/domain.
        peer_id: String,
        server_name: String,
        public_key_hex: String,
        spiral_index: Option<u64>,
        vdf_genesis: Option<String>,
        vdf_hash: Option<String>,
        vdf_step: Option<u64>,
        yggdrasil_addr: Option<String>,
        site_name: String,
        node_name: String,
        vdf_resonance_credit: Option<f64>,
        vdf_actual_rate_hz: Option<f64>,
        /// Cumulative resonance credit — total precision-weighted VDF work.
        vdf_cumulative_credit: Option<f64>,
        ygg_peer_uri: Option<String>,
        /// TCP peer address of the relay connection — used by APE to derive
        /// an underlay Ygg peer URI (`tcp://[ip]:9443`). This is a known-good
        /// address to a confirmed-different node (peer_id verified).
        relay_peer_addr: Option<SocketAddr>,
        /// CVDF cooperative chain height.
        cvdf_height: Option<u64>,
        /// CVDF cooperative chain weight.
        cvdf_weight: Option<u64>,
        /// CVDF chain tip hash (hex).
        cvdf_tip_hex: Option<String>,
        /// CVDF genesis seed (hex).
        cvdf_genesis_hex: Option<String>,
        /// Total VDF work of this node's entire connected graph.
        cluster_vdf_work: Option<f64>,
        /// Concierge slot assignment — first empty slot in sender's topology.
        assigned_slot: Option<u64>,
        /// Cluster identity chain value (hex-encoded blake3 hash, current tip).
        cluster_chain_value: Option<String>,
        /// Cluster epoch origin (hex-encoded blake3 hash).
        /// Stable across advances — only changes on merge/adopt.
        cluster_chain_epoch_origin: Option<String>,
        /// Cluster identity chain round number.
        cluster_chain_round: Option<u64>,
        /// Cluster chain cumulative work (advance steps across all epochs).
        cluster_chain_work: Option<u64>,
        /// Cluster round seed (hex-encoded [u8; 32]) from the FVDF chain.
        cluster_round_seed: Option<String>,
    },
    /// Received MESH PEERS from a remote peer.
    MeshPeers {
        remote_host: String,
        peers: Vec<MeshPeerInfo>,
    },
    /// Received MESH TOPOLOGY from a remote peer.
    MeshTopology {
        remote_host: String,
        json: String,
    },
    /// Received MESH VDFPROOF_REQ — a peer wants us to prove our VDF chain.
    MeshVdfProofReq {
        remote_host: String,
    },
    /// Received MESH VDFPROOF — a peer sent us a ZK proof of their VDF chain.
    MeshVdfProof {
        remote_host: String,
        proof_json: String,
        /// Mesh key from HELLO — O(1) lookup into known_peers.
        mesh_key: Option<String>,
    },
    /// Received VDF window proof — push-based sequential computation proof.
    MeshVdfWindow {
        remote_host: String,
        data: String,
        mesh_key: Option<String>,
    },
    /// Received MESH SYNC — a peer wants our full peer table.
    MeshSync {
        remote_host: String,
    },
    /// A local IRC event to broadcast into the gossip mesh.
    GossipBroadcast {
        event: super::gossip::GossipIrcEvent,
    },
    /// Received MESH GOSSIP from a remote peer — a single gossip message.
    GossipReceive {
        remote_host: String,
        message_json: String,
    },
    /// Received MESH GOSSIP_SPORE from a remote peer — their SPORE HaveList.
    GossipSpore {
        remote_host: String,
        spore_json: String,
    },
    /// Received MESH GOSSIP_DIFF from a remote peer — batch catch-up messages.
    GossipDiff {
        remote_host: String,
        messages_json: String,
    },
    /// Measured RTT to a remote peer (from PING/PONG round-trip).
    LatencyMeasured {
        remote_host: String,
        rtt_ms: f64,
        /// Mesh key from HELLO — O(1) lookup into known_peers.
        mesh_key: Option<String>,
    },
    /// PoL challenge-response completed — relay task measured the RTT.
    /// The main event loop creates a signed LatencyProof from this.
    PolCompleted {
        remote_host: String,
        rtt_us: u64,
        mesh_key: Option<String>,
    },
    /// Received MESH LATENCY_HAVE — remote peer's latency proof SPORE.
    LatencyHaveList {
        remote_host: String,
        payload_b64: String,
    },
    /// Received MESH LATENCY_DELTA — proof entries we're missing.
    LatencyProofDelta {
        remote_host: String,
        payload_b64: String,
    },
    /// Received a profile query from the mesh — "do you have this user?"
    ProfileQuery {
        remote_host: String,
        username: String,
    },
    /// Received a profile response from the mesh — profile data (or None).
    ProfileResponse {
        remote_host: String,
        username: String,
        profile: Option<super::profile::UserProfile>,
    },
    /// Received PROFILE_HAVE — remote cluster peer's profile SPORE.
    ProfileHave {
        remote_host: String,
        payload_b64: String,
    },
    /// Received PROFILE_DELTA — profiles we're missing from a cluster peer.
    ProfileDelta {
        remote_host: String,
        payload_b64: String,
    },
    /// Received CONNECTION_HAVE — remote peer's connection snapshot SPORE.
    ConnectionHave {
        remote_host: String,
        payload_b64: String,
    },
    /// Received CONNECTION_DELTA — connection snapshots we're missing.
    ConnectionDelta {
        remote_host: String,
        payload_b64: String,
    },
    /// Received LIVENESS_HAVE — remote peer's liveness attestation SPORE.
    LivenessHave {
        remote_host: String,
        payload_b64: String,
    },
    /// Received LIVENESS_DELTA — liveness attestations we're missing.
    LivenessDelta {
        remote_host: String,
        payload_b64: String,
    },
    /// Received SOCKET_MIGRATE — a switchboard node froze a TCP socket via TCP_REPAIR
    /// and is delivering the migration state so we can restore it.
    SocketMigrate {
        remote_host: String,
        /// Base64-encoded bincode `SocketMigration`.
        migration: String,
        /// The peer_id of the original client.
        client_peer_id: String,
    },
    /// Received CVDF cooperative VDF message from a peer.
    CvdfMessage {
        remote_host: String,
        /// Base64-encoded bincode `CvdfServiceMessage`.
        data: String,
    },
    /// Received cluster chain update from a peer (SPORE cascade after merge).
    /// If their cumulative_work > ours, adopt their chain state.
    ChainUpdate {
        remote_host: String,
        /// Chain value as hex string.
        value: String,
        /// Cumulative work across all epochs (derived from contributions).
        cumulative_work: u64,
        /// Current round number.
        round: u64,
        /// Base64-bincode-encoded `ClusterChainProof` (optional during rollout).
        proof: Option<String>,
        /// Work contributions ledger: genesis_hash(hex) → advance_steps.
        work_contributions: Option<std::collections::HashMap<String, u64>>,
        /// Epoch origin (hex string). Stable across advances — only changes on merge/adopt.
        epoch_origin: Option<String>,
    },
    /// Relay task has permanently exited — peer should be removed from topology.
    /// Sent ONCE, at task exit. Never on transient drops. This is THE signal
    /// that a peer is genuinely gone and its SPIRAL slot should be released.
    PeerGone { remote_host: String },
}

/// Manages all federated channel relay connections.
#[derive(Debug)]
pub struct FederationManager {
    /// Active relays: peer_id → relay handle.
    ///
    /// Keyed by the remote's cryptographic `peer_id` (`b3b3/hex(BLAKE3(BLAKE3(pubkey)))`).
    /// Relays are inserted by the relay task after HELLO exchange (when peer_id is known)
    /// and removed by the relay task on disconnect.
    pub relays: HashMap<String, RelayHandle>,
    /// Number of relay tasks currently alive (including those in backoff between reconnects).
    /// Used by the bootstrap retry to avoid spawning duplicate tasks.
    pub active_dial_count: usize,
    /// Peer IDs with relay tasks currently in-flight (spawned but not yet HELLO'd).
    /// Prevents the spawn cascade where PEERS gossip triggers duplicate relay tasks
    /// for the same peer before the first task completes its HELLO exchange.
    /// Key = connect_target (node_name or server_name), not peer_id (unknown until HELLO).
    pub pending_dials: HashSet<String>,
    /// Peer IDs with an active relay task (survives reconnect cycles).
    /// Inserted after first HELLO, removed at permanent task exit (PeerGone).
    /// evict_dead_peers() skips managed peers — the relay task handles lifecycle.
    pub managed_peers: HashSet<String>,
}

impl FederationManager {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
            active_dial_count: 0,
            pending_dials: HashSet::new(),
            managed_peers: HashSet::new(),
        }
    }
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
/// Query Yggdrasil peer metrics from the embedded node (if available).
async fn refresh_ygg_metrics_embedded(
    ygg_node: &Option<Arc<yggdrasil_rs::YggNode>>,
) -> Option<Vec<super::yggdrasil::YggPeer>> {
    let node = ygg_node.as_ref()?;
    let peers = node.peers().await;
    Some(
        peers
            .into_iter()
            .map(|p| {
                let address = yggdrasil_rs::crypto::address_for_key(&p.key).to_string();
                super::yggdrasil::YggPeer {
                    address,
                    remote: p.uri,
                    bytes_sent: 0,
                    bytes_recvd: 0,
                    latency: 0.0,
                    key: hex::encode(p.key),
                    port: 0,
                    uptime: 0.0,
                    up: true, // connected = up in yggdrasil-rs
                    inbound: p.inbound,
                }
            })
            .collect(),
    )
}

pub fn spawn_event_processor(
    state: SharedState,
    mut event_rx: mpsc::UnboundedReceiver<RelayEvent>,
) {
    let handle = tokio::spawn(async move {
        info!("federation event loop: starting");

        // Get a reference to the embedded Ygg node for metrics queries.
        let ygg_node = {
            let st = state.read().await;
            st.transport_config.ygg_node.clone()
        };

        // Initialize CVDF cooperative VDF service.
        // The transport buffers outbound messages; we drain them below.
        let (cvdf_transport, mut cvdf_outbound_rx) =
            super::cvdf_transport::LagoonCvdfTransport::new();
        {
            let mut st = state.write().await;
            let signing_key =
                ed25519_dalek::SigningKey::from_bytes(&st.lens.secret_seed);
            // Genesis seed = BLAKE3 of server_name — deterministic per network.
            let genesis_seed = blake3::hash(st.lens.server_name.as_bytes());
            let mut svc = citadel_lens::service::CvdfService::new_genesis(
                *genesis_seed.as_bytes(),
                signing_key,
                cvdf_transport,
            );
            // Register our SPIRAL slot if we have one.
            if let Some(idx) = st.lens.spiral_index {
                let pubkey = super::lens::pubkey_bytes(&st.lens)
                    .expect("valid lens identity");
                svc.set_our_slot(idx);
                svc.register_peer_slot(idx, pubkey);
            }
            st.mesh.cvdf_service = Some(svc);
        }

        // VDF liveness: broadcast window proof to SPIRAL neighbors every 3s.
        // Push-based: no challenge-response. Each proof covers ~30 VDF steps
        // (3s at 10 Hz) and is verified by neighbors for chain continuity.
        // Replaces the old 5s challenge-response VdfProofReq/VdfProof cycle.
        let mut vdf_window_interval = tokio::time::interval(
            std::time::Duration::from_secs(3),
        );
        vdf_window_interval.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Skip,
        );
        // Skip the first immediate tick — need chain steps to accumulate.
        vdf_window_interval.tick().await;

        // Bootstrap retry: if we have no real connections, periodically
        // re-attempt LAGOON_PEERS. Stops trying once real connections exist.
        let mut bootstrap_retry_interval = tokio::time::interval(
            std::time::Duration::from_secs(30),
        );
        bootstrap_retry_interval.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Skip,
        );
        // Skip the first immediate tick — spawn_mesh_connector handles initial connect.
        bootstrap_retry_interval.tick().await;

        // PoL challenge: send latency measurement challenges to all connected relays.
        // 10s interval — generates Ed25519-signed LatencyProofs via challenge/response.
        let mut pol_challenge_interval = tokio::time::interval(
            std::time::Duration::from_secs(10),
        );
        pol_challenge_interval.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Skip,
        );
        pol_challenge_interval.tick().await;
        // Nonce counter for PoL challenges (monotonically increasing).
        let mut pol_nonce_counter: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        // Latency swap: periodic deterministic swap round for topology optimization.
        // Every node computes the same swap decisions from shared PoLP latency data.
        // 30s matches the latency gossip sync window.
        let mut latency_swap_interval = tokio::time::interval(
            std::time::Duration::from_secs(30),
        );
        latency_swap_interval.set_missed_tick_behavior(
            tokio::time::MissedTickBehavior::Skip,
        );
        // Skip first tick — let topology stabilize before optimizing.
        latency_swap_interval.tick().await;

        loop {
        tokio::select! {
            Some(event) = event_rx.recv() => {
            match event {
                RelayEvent::RemotePrivmsg {
                    local_channel,
                    remote_nick,
                    remote_host,
                    text,
                } => {
                    let st = state.read().await;
                    let local_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
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
                    // Notify local subscribers of this federated channel.
                    let notify_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
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
                    // Notify local subscribers of this federated channel.
                    let notify_nicks: Vec<String> = st
                        .federation
                        .relays
                        .get(&remote_host)
                        .and_then(|r| r.channels.get(&local_channel))
                        .map(|fc| fc.local_users.iter().cloned().collect())
                        .unwrap_or_default();
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

                    // Build NAMES: local subscribers + remote users from this relay.
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
                                relay.connect_target
                            ));
                        }
                    }
                    let names_str = parts.join(" ");
                    let local_nicks: Vec<_> =
                        fed_ch.local_users.iter().cloned().collect();

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
                    // Query Ygg metrics before acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node).await;

                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_peer_count = yp.len() as u32;
                        st.mesh.ygg_metrics.update(yp);
                    }

                    // Broadcast disconnect notice to federated channel users.
                    if let Some(relay) = st.federation.relays.get(&remote_host) {
                        for (local_channel, fed_ch) in &relay.channels {
                            let msg = Message {
                                prefix: Some(SERVER_NAME.clone()),
                                command: "NOTICE".into(),
                                params: vec![
                                    local_channel.clone(),
                                    format!(
                                        "Federation relay to {} disconnected",
                                        relay.node_name
                                    ),
                                ],
                            };
                            let local_nicks: Vec<_> =
                                fed_ch.local_users.iter().cloned().collect();
                            broadcast(&st, &local_nicks, &msg);
                        }
                    }

                    // Clean up relay handle (may already be removed by the task itself).
                    if let Some(relay) = st.federation.relays.remove(&remote_host) {
                        let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                    }

                    // Remove from active connections — but PRESERVE SPIRAL slot.
                    // The relay task is still alive (reconnecting with backoff).
                    // SPIRAL slot is only released when PeerGone fires (permanent exit).
                    st.mesh.connections.remove(&remote_host);

                    // APE: if disconnection dropped us below threshold, recover.
                    attempt_mesh_rejoin(&mut st, state.clone());
                    publish_connection_snapshot(&mut st);
                    st.notify_topology_change();

                }
                RelayEvent::PeerGone { remote_host } => {
                    // Relay task has PERMANENTLY exited — this peer is genuinely gone.
                    // NOW we release the SPIRAL slot and reconverge (once).
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node).await;
                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_peer_count = yp.len() as u32;
                        st.mesh.ygg_metrics.update(yp);
                    }

                    // Final relay cleanup (may already be gone).
                    if let Some(relay) = st.federation.relays.remove(&remote_host) {
                        let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                    }
                    st.federation.managed_peers.remove(&remote_host);
                    st.mesh.connections.remove(&remote_host);
                    st.mesh.spiral.remove_peer(&remote_host);

                    if st.mesh.known_peers.contains_key(&remote_host) {
                        reconverge_spiral(&mut st, state.clone());
                        let neighbors = st.mesh.spiral.neighbors().clone();
                        st.mesh.latency_gossip.set_spiral_neighbors(neighbors.clone());
                        st.mesh.connection_gossip.set_spiral_neighbors(neighbors.clone());
                        st.mesh.liveness_gossip.set_spiral_neighbors(neighbors);
                        dial_missing_spiral_neighbors(&mut st, state.clone());
                        attempt_mesh_rejoin(&mut st, state.clone());
                        publish_connection_snapshot(&mut st);
                        st.notify_topology_change();
                    }

                    tracing::info!(
                        peer = %remote_host,
                        "PeerGone: relay task permanently exited, SPIRAL slot released"
                    );
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
                                        relay.connect_target
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

                RelayEvent::MeshHello {
                    remote_host,
                    peer_id,
                    server_name,
                    public_key_hex,
                    spiral_index,
                    vdf_genesis,
                    vdf_hash,
                    vdf_step,
                    yggdrasil_addr,
                    site_name,
                    node_name,
                    vdf_resonance_credit,
                    vdf_actual_rate_hz,
                    vdf_cumulative_credit,
                    ygg_peer_uri,
                    relay_peer_addr,
                    cvdf_height,
                    cvdf_weight,
                    cvdf_tip_hex,
                    cvdf_genesis_hex,
                    cluster_vdf_work,
                    assigned_slot,
                    cluster_chain_value,
                    cluster_chain_epoch_origin,
                    cluster_chain_round,
                    cluster_chain_work,
                    cluster_round_seed: _,
                } => {
                    // Backfill node_name/site_name for old peers that don't send them.
                    let node_name = if node_name.is_empty() {
                        derive_node_name(&server_name)
                    } else {
                        node_name
                    };
                    let site_name = if site_name.is_empty() {
                        super::server::derive_site_name(&server_name)
                    } else {
                        site_name
                    };

                    // peer_id (public key) = the node's identity.
                    let mkey = peer_id.clone();

                    // Verify PeerID matches public key.
                    if let Ok(pubkey_bytes) = hex::decode(&public_key_hex) {
                        if pubkey_bytes.len() == 32 {
                            let mut key = [0u8; 32];
                            key.copy_from_slice(&pubkey_bytes);
                            if !lens::verify_peer_id(&peer_id, &key) {
                                warn!(
                                    remote_host,
                                    "mesh: rejected HELLO — PeerID doesn't match pubkey"
                                );
                                continue;
                            }
                        }
                    }

                    // Query Yggdrasil metrics BEFORE acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node).await;

                    let mut st = state.write().await;

                    // Update Ygg metrics store if we got data.
                    if let Some(peers) = ygg_peers {
                        st.mesh.ygg_metrics.update(peers);
                    }

                    // Detect self-connection via peer_id (public key).
                    //
                    // Self-connection means we dialed anycast and reached ourselves.
                    // This is normal: we're either the only node or the nearest to
                    // ourselves. Shut down the relay — the bootstrap retry interval
                    // will periodically re-attempt LAGOON_PEERS, and other nodes
                    // will dial us when they start.
                    let our_pid = st.lens.peer_id.clone();
                    if mkey == our_pid {
                        info!(
                            remote_host,
                            mesh_key = %mkey,
                            "mesh: self-connection detected via HELLO — shutting down relay \
                             (transparent self should have caught this earlier)"
                        );
                        // remote_host IS the peer_id now — relay is keyed by peer_id.
                        if let Some(relay) = st.federation.relays.remove(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                        }
                        st.mesh.connections.remove(&mkey);
                        continue;
                    }

                    // Check defederation.
                    if st.mesh.defederated.contains(&peer_id)
                        || st.mesh.defederated.contains(&server_name)
                    {
                        warn!(
                            remote_host,
                            peer_id,
                            "mesh: rejected HELLO — peer is defederated"
                        );
                        continue;
                    }

                    info!(
                        remote_host,
                        mesh_key = %mkey,
                        peer_id,
                        server_name,
                        "mesh: received HELLO"
                    );

                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);

                    // Determine transport hints from our config for this peer.
                    let (peer_port, peer_tls) = st
                        .transport_config
                        .peers
                        .get(&remote_host)
                        .map(|p| (p.port, p.tls))
                        .unwrap_or((6667, false));

                    if let Some(step) = vdf_step {
                        info!(
                            remote_host,
                            mesh_key = %mkey,
                            vdf_step = step,
                            "mesh: peer VDF state"
                        );
                    }

                    // Mesh key = peer_id (public key). Unique per node.
                    // Derive underlay URI from relay's TCP peer address.
                    // This is a real IP (not an overlay address) — confirmed
                    // different node via peer_id verification in HELLO.
                    let underlay_uri = ygg_peer_uri.clone()
                        .or_else(|| relay_peer_addr.map(|addr| format!("tcp://[{}]:9443", addr.ip())))
                        .filter(|u| is_underlay_uri(u));

                    // Clone vdf_hash before moving into known_peers — needed for merge tiebreak.
                    let remote_vdf_hash_for_merge = vdf_hash.clone();

                    // Direct HELLO = proof of life. Clear any eviction tombstone —
                    // tombstones only block gossip-based resurrection, not live peers.
                    st.mesh.eviction_tombstones.remove(&mkey);

                    // Track whether this peer was already in our clump before this HELLO.
                    // If they were, no cluster merge needed — same clump.
                    let already_in_clump = st.mesh.known_peers.contains_key(&mkey);

                    // Preserve VDF liveness state from previous entry:
                    // - Only update last_vdf_advance if the VDF step ACTUALLY advanced
                    // - Preserve prev_vdf_step for stagnation detection
                    // A peer with a frozen VDF (same step in every HELLO) must not
                    // refresh last_vdf_advance — that hides the frozen VDF behind
                    // the grace period. (Lean: invariant_dead_detection requires
                    // isDead to be purely a function of VDF silence duration.)
                    let (prev_vdf_step, last_vdf_advance) = if let Some(existing) = st.mesh.known_peers.get(&mkey) {
                        let step_advanced = match (existing.vdf_step, vdf_step) {
                            (Some(old), Some(new)) => new > old,
                            (None, Some(_)) => true, // first step seen
                            _ => false,
                        };
                        let advance_ts = if step_advanced { now } else { existing.last_vdf_advance };
                        (existing.vdf_step, advance_ts)
                    } else {
                        // First HELLO from this peer — vdf_step presence = first proof of life.
                        (None, if vdf_step.is_some() { now } else { 0 })
                    };

                    st.mesh.known_peers.insert(
                        mkey.clone(),
                        MeshPeerInfo {
                            peer_id: peer_id.clone(),
                            server_name: server_name.clone(),
                            public_key_hex,
                            port: peer_port,
                            tls: peer_tls,
                            last_seen: now,
                            spiral_index,
                            vdf_genesis,
                            vdf_hash,
                            vdf_step,
                            yggdrasil_addr,
                            site_name: site_name.clone(),
                            node_name: node_name.clone(),
                            vdf_resonance_credit,
                            vdf_actual_rate_hz,
                            vdf_cumulative_credit,
                            ygg_peer_uri: ygg_peer_uri.clone(),
                            underlay_uri,
                            prev_vdf_step,
                            last_vdf_advance,
                            cluster_chain_value: cluster_chain_value.clone(),
                            cluster_chain_epoch_origin: cluster_chain_epoch_origin.clone(),
                            cluster_chain_round,
                        },
                    );
                    st.mesh
                        .connections
                        .insert(mkey.clone(), MeshConnectionState::Connected);

                    // APE: dynamically peer with this node's Yggdrasil underlay.
                    // Prefer ygg_peer_uri (self-reported from HELLO) over
                    // relay_peer_addr (TCP peer, may be a proxy IP on Fly).
                    if let Some(ygg) = st.transport_config.ygg_node.clone() {
                        // Try direct underlay URI (works when on same provider).
                        if let Some(uri) = ygg_peer_uri.clone()
                            .or_else(|| ape_peer_uri(relay_peer_addr))
                            .filter(|u| is_underlay_uri(u))
                        {
                            if !st.mesh.ygg_peered_uris.contains(uri.as_str()) {
                                match ygg.add_peer(&uri) {
                                    Ok(()) => {
                                        info!(uri, peer_id, "APE: added Yggdrasil peer (underlay)");
                                        st.mesh.ygg_peered_uris.insert(uri.clone());
                                    }
                                    Err(e) => {
                                        warn!(uri, peer_id, error = %e, "APE: failed to add Yggdrasil peer");
                                    }
                                }
                            }
                        }

                        // Midlay Ygg bootstrap via switchboard. The switchboard on
                        // :9443 detects 'meta' first bytes and routes to
                        // ygg_node.accept_inbound(). Provides cross-provider Ygg
                        // bootstrap when the underlay URI above is unreachable
                        // (e.g. Bunny → Fly fdaa::). add_peer is fire-and-forget:
                        // both underlay and switchboard attempts run concurrently.
                        if let Some(ref sb_addr) = st.transport_config.switchboard_addr {
                            let sb_uri = switchboard_ygg_uri(sb_addr);
                            if !st.mesh.ygg_peered_uris.contains(sb_uri.as_str()) {
                                match ygg.add_peer(&sb_uri) {
                                    Ok(()) => {
                                        info!(uri = %sb_uri, peer_id, "APE: Ygg bootstrap via switchboard (midlay)");
                                        st.mesh.ygg_peered_uris.insert(sb_uri);
                                    }
                                    Err(e) => {
                                        warn!(uri = %sb_uri, error = %e, "APE: switchboard Ygg bootstrap failed");
                                    }
                                }
                            }
                        }
                    }

                    // SPIRAL merge protocol: negotiate topology with the remote peer.
                    // Compares cluster VDF work. Winner keeps topology, loser re-slots.
                    // Concierge: if remote is established and we're not, assigned_slot
                    // tells us which slot to take immediately. O(1). No waiting for PEERS.
                    let spiral_changed = evaluate_spiral_merge(
                        &mut st,
                        &mkey,
                        spiral_index,
                        cluster_vdf_work,
                        vdf_cumulative_credit,
                        remote_vdf_hash_for_merge.as_deref(),
                        already_in_clump,
                        assigned_slot,
                        state.clone(),
                    );

                    // Cluster identity chain: merge / adopt protocol.
                    //
                    // No clock source. No round seed propagation. Every node
                    // independently derives the round seed from the quantized
                    // VDF height (Universal Clock). HELLO carries chain value
                    // and round for COMPARISON only.

                    // If WE have no chain but remote does, adopt theirs (fresh join).
                    if st.mesh.cluster_chain.is_none() {
                        if let Some(ref hex_val) = cluster_chain_value {
                            if let Ok(bytes) = hex::decode(hex_val) {
                                if let Ok(value) = <[u8; 32]>::try_from(bytes.as_slice()) {
                                    let round = cluster_chain_round.unwrap_or(0);
                                    let work = cluster_chain_work.unwrap_or(0);
                                    // Synthesize single-entry contributions from HELLO.
                                    let mut contribs = std::collections::BTreeMap::new();
                                    contribs.insert(value, work);
                                    let origin = cluster_chain_epoch_origin.as_ref()
                                        .and_then(|h| hex::decode(h).ok())
                                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
                                    let mut cc = super::cluster_chain::ClusterChain::genesis(value, round, 1);
                                    cc.adopt(value, round, contribs, origin);
                                    st.mesh.cluster_chain = Some(cc);
                                    info!(chain = &hex_val[..8.min(hex_val.len())], work, "cluster chain: adopted from first peer (fresh join)");
                                    broadcast_chain_update(&st);
                                }
                            }
                        }
                    }

                    // F-VDF epoch reset: both sides compute blake3(sort(A, B)).
                    // The merged value becomes the new epoch genesis — both nodes
                    // restart their chain from this seed and advance in lockstep.
                    // Work is additive: cumulative_work sums across merges.
                    //
                    // Extract context before mutable borrow on cluster_chain.
                    // Use QUANTIZED height as timestamp — this gates the advance
                    // so neither node re-advances until the NEXT quantum boundary.
                    // Both nodes are within one quantum of each other (they just
                    // exchanged HELLO), so they gate on the same next boundary.
                    use super::cluster_chain::ROUND_QUANTUM;
                    let merge_quantum = st.mesh.vdf_state_rx.as_ref()
                        .map(|rx| {
                            let total = rx.borrow().total_steps;
                            (total / ROUND_QUANTUM) * ROUND_QUANTUM
                        }).unwrap_or(0);
                    let merge_size = (st.mesh.known_peers.len() + 1) as u32;
                    let remote_chain_bytes = cluster_chain_value.as_ref().and_then(|hex_str| {
                        hex::decode(hex_str).ok().and_then(|bytes| {
                            <[u8; 32]>::try_from(bytes.as_slice()).ok()
                        })
                    });
                    // Use epoch_origin for comparison (stable across advances).
                    // Fall back to chain_value for old nodes that don't send it.
                    let remote_origin_bytes = cluster_chain_epoch_origin.as_ref()
                        .and_then(|hex_str| {
                            hex::decode(hex_str).ok().and_then(|bytes| {
                                <[u8; 32]>::try_from(bytes.as_slice()).ok()
                            })
                        })
                        .or(remote_chain_bytes);

                    if let Some(ref mut cc) = st.mesh.cluster_chain {
                        let comparison = cc.compare(remote_origin_bytes.as_ref());
                        match comparison {
                            super::cluster_chain::ChainComparison::SameCluster => {
                                // Chains match. Nothing to do — Universal Clock
                                // keeps them in sync independently.
                            }
                            super::cluster_chain::ChainComparison::DifferentCluster => {
                                // EPOCH GUARD: skip merge if we just merged/adopted
                                // (epoch_steps=0). ChainUpdate from the contact-point
                                // merge will propagate within one advance cycle (10s).
                                if !cc.can_merge() {
                                    info!(peer = %mkey,
                                          "cluster chain: skipping merge — epoch_steps=0, waiting for advance");
                                } else if let Some(remote_value) = remote_chain_bytes {
                                    let their_work = cluster_chain_work.unwrap_or(0);
                                    let their_round = cluster_chain_round.unwrap_or(0);

                                    // Symmetric merge with idempotent work union.
                                    // Synthesize contributions from HELLO (single entry).
                                    // Full ledger propagates via ChainUpdate for adoption.
                                    let mut their_contributions = std::collections::BTreeMap::new();
                                    their_contributions.insert(remote_value, their_work);

                                    let pre_work = cc.cumulative_work;
                                    cc.fungible_adopt(
                                        &remote_value, their_round, &their_contributions,
                                        merge_quantum, merge_size);
                                    info!(merged = %cc.value_short(),
                                          pre_work, their_work,
                                          combined_work = cc.cumulative_work,
                                          contributions = cc.work_contributions.len(),
                                          "cluster chain: symmetric merge — work union, new epoch");
                                    // SPORE cascade: broadcast to all peers so
                                    // army members adopt without re-merging.
                                    broadcast_chain_update(&st);
                                }
                            }
                            super::cluster_chain::ChainComparison::FreshJoin => {
                                info!(peer = %mkey, our_chain = %cc.value_short(),
                                      "cluster chain: fresh node joining — they will adopt our chain");
                            }
                        }
                    }

                    // Reconverge: repack fills gaps left by stale peers so the
                    // neighbor set is correct BEFORE any prune decision runs.
                    // SKIP if we just changed position (VDF race, concierge, or
                    // reslot). Our position is correct by construction — reconverge
                    // with incomplete topology would move us to a "lower" slot
                    // that's actually occupied by peers we haven't heard about yet.
                    if !spiral_changed {
                        reconverge_spiral(&mut st, state.clone());
                    }
                    // Always update SPIRAL neighbor set for gossip coordinators
                    // (remote may have been added even without our position changing).
                    update_spiral_neighbors(&mut st);

                    if !spiral_changed && spiral_index.is_some() {
                        // Remote registered at a slot — may be our new SPIRAL neighbor.
                        dial_missing_spiral_neighbors(&mut st, state.clone());
                    }

                    // CVDF: register peer's SPIRAL slot and evaluate their chain.
                    // Extract pubkey from known_peers first to avoid borrow conflict
                    // with cvdf_service (both fields of st.mesh).
                    let cvdf_peer_info: Option<([u8; 32], Option<u64>)> =
                        st.mesh.known_peers.get(&mkey).and_then(|peer| {
                            let bytes = hex::decode(&peer.public_key_hex).ok()?;
                            if bytes.len() != 32 { return None; }
                            let mut pk = [0u8; 32];
                            pk.copy_from_slice(&bytes);
                            Some((pk, peer.spiral_index))
                        });
                    if let (Some(svc), Some((pk, slot))) =
                        (st.mesh.cvdf_service.as_mut(), cvdf_peer_info)
                    {
                        if let Some(idx) = slot {
                            svc.register_peer_slot(idx, pk);
                        }
                        // Evaluate their cooperative chain — sync if heavier.
                        if let (Some(height), Some(weight), Some(tip), Some(genesis)) =
                            (cvdf_height, cvdf_weight, cvdf_tip_hex, cvdf_genesis_hex)
                        {
                            let peer_status = citadel_lens::service::CvdfStatus {
                                height,
                                weight,
                                tip_hex: tip,
                                genesis_hex: genesis,
                                active_slots: 0,
                            };
                            let action = svc.evaluate_hello(&pk, &peer_status);
                            svc.execute_action(&action);
                        }
                    }

                    // Dial any SPIRAL neighbors we don't have a relay to yet.
                    // Always dial BEFORE pruning — atomic reslot: establish new
                    // connections first, then shed excess in the prune step.
                    dial_missing_spiral_neighbors(&mut st, state.clone());

                    // Prune relay connections to non-SPIRAL peers now that the
                    // neighbor set may have changed.
                    prune_non_spiral_relays(&mut st);

                    // Publish connection snapshot — we just connected to a new peer.
                    publish_connection_snapshot(&mut st);
                    st.notify_topology_change();

                    // VDF-based liveness eviction. 10s. One rule. No exceptions.
                    {
                        let evicted = evict_dead_peers(&mut st);
                        if !evicted.is_empty() {
                            // Do NOT reconverge here. The eviction is a side-effect
                            // sweep during HELLO — the evicted peers are unrelated
                            // to this HELLO's topology data. Reconverge with
                            // incomplete topology moves us to "false gaps."
                            // The event-driven reconverge at line 1326 (after
                            // evaluate_spiral_merge) already handles convergence
                            // with fresh topology from this HELLO.
                            let neighbors = st.mesh.spiral.neighbors().clone();
                            st.mesh.latency_gossip.set_spiral_neighbors(neighbors.clone());
                            st.mesh.connection_gossip.set_spiral_neighbors(neighbors.clone());
                            st.mesh.liveness_gossip.set_spiral_neighbors(neighbors);
                            dial_missing_spiral_neighbors(&mut st, state.clone());
                            // APE: if eviction killed all our relays, rejoin the mesh.
                            attempt_mesh_rejoin(&mut st, state.clone());
                            publish_connection_snapshot(&mut st);
                            st.notify_topology_change();
                        }
                    }

                    // Ghost cleanup is no longer needed — relays are keyed by peer_id.
                    // If a relay task reconnects via anycast and reaches a different
                    // node, relay_task_native removes the old relay (keyed by old
                    // peer_id) and inserts a new one under the new peer_id.

                    // Connection reciprocity: if this peer connected to us and
                    // we don't have an outbound relay to them, establish one.
                    // This ensures bidirectional connectivity in the mesh.
                    // NOTE: must happen BEFORE sending MESH PEERS/TOPOLOGY/SPORE,
                    // because those sends go via st.federation.relays.
                    //
                    // Skip if we already have a relay to this peer (keyed by peer_id)
                    // or if there's already a relay task in-flight for this connect target.
                    if !st.federation.relays.contains_key(&remote_host)
                        && !st.federation.pending_dials.contains(&node_name)
                        && !st.federation.pending_dials.contains(&server_name)
                    {
                        // SPIRAL gate: only reciprocate if we haven't claimed
                        // a slot yet (still bootstrapping) or they're a SPIRAL
                        // neighbor. 20 connections max — that's the invariant.
                        let should_connect = !st.mesh.spiral.is_claimed()
                            || st.mesh.spiral.is_neighbor(&mkey);

                        if should_connect {
                            info!(
                                peer = %node_name,
                                peer_id = %remote_host,
                                server = %server_name,
                                "mesh: reciprocal connect to inbound peer"
                            );

                            let event_tx = st.federation_event_tx.clone();

                            let peer_ygg_addr = st
                                .mesh
                                .known_peers
                                .get(&mkey)
                                .and_then(|p| p.yggdrasil_addr.as_deref())
                                .and_then(|s| s.parse().ok());

                            // connect_key: use node_name if Ygg-reachable, else server_name for DNS.
                            let connect_key = if peer_ygg_addr.is_some() {
                                node_name.clone()
                            } else {
                                server_name.clone()
                            };

                            // Pre-insert before spawn — caller holds write lock.
                            st.federation.pending_dials.insert(connect_key.clone());

                            let mut tc_with_peer = (*st.transport_config).clone();
                            tc_with_peer
                                .peers
                                .entry(connect_key.clone())
                                .or_insert(transport::PeerEntry {
                                    yggdrasil_addr: peer_ygg_addr,
                                    port: peer_port,
                                    tls: peer_tls,
                                    want: None,
                                    dial_host: None,
                                });
                            let tc_arc = Arc::new(tc_with_peer);

                            spawn_native_relay(
                                connect_key,
                                event_tx,
                                tc_arc,
                                state.clone(),
                                false,
                            );
                        }
                    }

                    // ── Connection ceremony: first HELLO only ────────────
                    // Gate the full ceremony (response HELLO, PEERS dump, gossip
                    // catch-up, VDF challenge) on first contact. Re-HELLOs from
                    // announce_hello_to_all_relays() update state (known_peers,
                    // SPIRAL topology — handled above) but must NOT trigger the
                    // ceremony again. Without this gate:
                    //   A announces → B echoes HELLO → A echoes back → infinite
                    //   ping-pong, each echo also sending PEERS + LATENCY_HAVE +
                    //   CONNECTION_HAVE + SPORE + VdfProofReq = network flood.
                    let first_hello = st.federation.relays.get(&remote_host)
                        .map(|r| !r.mesh_connected)
                        .unwrap_or(true);

                    if first_hello {
                    // ── Juggler: send response HELLO after merge ────────────
                    // Built AFTER evaluate_spiral_merge + reconverge, so it
                    // carries correct spiral_index AND assigned_slot reflecting
                    // ALL previous merges processed by the federation loop.
                    //
                    // Concierge slot: computed ONLY here, not in build_hello_payload.
                    // build_hello_payload is called for announcements, outbound
                    // connections, and re-sends — computing assigned_slot there
                    // created phantom pending reservations that pushed real
                    // assignments to slot 654+.
                    {
                        let mut our_hello = build_wire_hello(&mut st);

                        // Concierge: if remote is unclaimed, assign them a slot.
                        if !spiral_changed && spiral_index.is_none() {
                            if let Some(slot) = compute_concierge_slot(&mut st) {
                                our_hello.assigned_slot = Some(slot);
                                st.mesh.spiral.add_peer(
                                    &mkey,
                                    citadel_topology::Spiral3DIndex::new(slot),
                                );
                                if let Some(peer) = st.mesh.known_peers.get_mut(&mkey) {
                                    peer.spiral_index = Some(slot);
                                }
                                // Real registration supersedes pending reservation.
                                st.mesh.pending_assigned_slots.remove(&slot);
                                info!(
                                    slot,
                                    remote = %mkey,
                                    "SPIRAL concierge: eagerly registered joiner at assigned slot"
                                );
                            }
                        }
                        if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::Hello(our_hello),
                            ));
                            // Mark relay as Hello-exchanged. Broadcast patterns
                            // (announce-to-all PEERS, gossip re-gossip) check this
                            // flag. Without it, PEERS from a DIFFERENT peer's HELLO
                            // processing leaks into this relay before the response
                            // HELLO, causing the outbound side to see PEERS as the
                            // first message → "first message must be Hello" → reconnect.
                            relay.mesh_connected = true;
                        }
                    }

                    // Send PEERS to the newly connected peer.
                    // Include: self + connected peers + non-stale peers with SPIRAL slots.
                    // Peers with spiral_index are valuable topology data — gossiping them
                    // enables transitive topology propagation (A knows C through B, tells D).
                    // The 300s staleness filter prevents ghost amplification of dead peers.
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let peers_list: Vec<MeshPeerInfo> = st.mesh.known_peers.iter()
                        .filter(|(mkey, p)| {
                            *mkey == &our_pid
                                || st.mesh.connections.get(*mkey)
                                    .copied() == Some(MeshConnectionState::Connected)
                                || (p.spiral_index.is_some() && p.last_seen + 300 > now_secs)
                        })
                        .map(|(_, p)| p.clone())
                        .collect();
                    if !peers_list.is_empty() {
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::Peers { peers: peers_list },
                            ));
                        }
                    }

                    // Notify ALL existing peers about the new arrival.
                    // Without this, only the new peer learns about existing peers
                    // (via the PEERS we just sent above). Existing peers never
                    // hear about the newcomer → star topology instead of triangle.
                    if let Some(new_peer_info) = st.mesh.known_peers.get(&mkey).cloned() {
                        let announce = vec![new_peer_info];
                        for (host, relay) in &st.federation.relays {
                            if *host != remote_host && relay.mesh_connected {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::Peers { peers: announce.clone() },
                                ));
                            }
                        }
                    }

                    // Send LATENCY_HAVE — our proof SPORE for efficient delta sync.
                    {
                        let spore_bytes = bincode::serialize(
                            st.mesh.proof_store.spore(),
                        ).unwrap_or_default();
                        let sync_msg = super::latency_gossip::SyncMessage::HaveList {
                            spore_bytes,
                        };
                        let b64 = base64::engine::general_purpose::STANDARD
                            .encode(bincode::serialize(&sync_msg).unwrap_or_default());
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::LatencyHave { data: b64 },
                            ));
                        }
                    }

                    // Send CONNECTION_HAVE — our connection snapshot SPORE.
                    {
                        let spore_bytes = bincode::serialize(
                            st.mesh.connection_store.spore(),
                        ).unwrap_or_default();
                        let sync_msg = super::connection_gossip::SyncMessage::HaveList {
                            spore_bytes,
                        };
                        let b64 = base64::engine::general_purpose::STANDARD
                            .encode(bincode::serialize(&sync_msg).unwrap_or_default());
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::ConnectionHave { data: b64 },
                            ));
                        }
                    }

                    // Send LIVENESS_HAVE — our liveness bitmap SPORE.
                    {
                        let spore_bytes = bincode::serialize(
                            st.mesh.liveness_bitmap.spore(),
                        ).unwrap_or_default();
                        let sync_msg = super::liveness_gossip::SyncMessage::HaveList {
                            spore_bytes,
                        };
                        let b64 = base64::engine::general_purpose::STANDARD
                            .encode(bincode::serialize(&sync_msg).unwrap_or_default());
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::LivenessHave { data: b64 },
                            ));
                        }
                    }

                    // SPORE gossip catch-up: send our HaveList so the peer can
                    // diff and send us anything we missed while disconnected.
                    if super::gossip::is_cluster_peer(&SITE_NAME, &site_name) {
                        let our_spore = st.mesh.gossip.seen_messages();
                        if let Ok(spore_json) = serde_json::to_string(our_spore) {
                            if let Some(relay) = st.federation.relays.get(&remote_host) {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::GossipSpore { data: spore_json },
                                ));
                                info!(
                                    remote_host,
                                    "gossip: sent SPORE HaveList to cluster peer for catch-up"
                                );
                            }
                        }

                        // Profile SPORE catch-up: send our profile HaveList so
                        // the peer can diff and push any profiles we're missing.
                        let spore_bytes = bincode::serialize(st.profile_store.spore())
                            .unwrap_or_default();
                        let b64 = base64::engine::general_purpose::STANDARD
                            .encode(&spore_bytes);
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::ProfileHave { data: b64 },
                            ));
                            info!(
                                remote_host,
                                "profile_gossip: sent SPORE HaveList to cluster peer for catch-up"
                            );
                        }
                    }

                    // VDF liveness is now push-based: the 3s window proof
                    // broadcast handles liveness.  No immediate challenge needed.
                    // The peer's first window proof will update last_vdf_advance.

                    } // end first_hello gate

                    // ── Concierge fallback ──────────────────────────────
                    // The first_hello gate blocks response Hellos on re-contact.
                    // But the concierge MUST send assigned_slot even on
                    // subsequent Hellos — e.g. when an outbound relay's
                    // mesh_connected=true suppressed the ceremony and the
                    // remote is still unclaimed.  No PEERS/SPORE/gossip here,
                    // just the bare concierge Hello.
                    if !first_hello
                        && !spiral_changed
                        && spiral_index.is_none()
                        && st.mesh.spiral.is_claimed()
                    {
                        if let Some(slot) = compute_concierge_slot(&mut st) {
                            let mut our_hello = build_wire_hello(&mut st);
                            our_hello.assigned_slot = Some(slot);
                            st.mesh.spiral.add_peer(
                                &mkey,
                                citadel_topology::Spiral3DIndex::new(slot),
                            );
                            if let Some(peer) = st.mesh.known_peers.get_mut(&mkey) {
                                peer.spiral_index = Some(slot);
                            }
                            st.mesh.pending_assigned_slots.remove(&slot);
                            if let Some(relay) = st.federation.relays.get(&remote_host) {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::Hello(our_hello),
                                ));
                            }
                            info!(
                                slot,
                                remote = %mkey,
                                "SPIRAL concierge: assigned slot on re-hello (fallback)"
                            );
                        }
                    }

                    // Dedup is automatic: relays are keyed by peer_id. If both an
                    // inbound and outbound connection exist to the same peer, the
                    // second insert overwrites the first (newer connection wins).
                    // The overwritten relay's cmd_tx is dropped, cmd_rx returns None,
                    // and the old task exits cleanly.
                }

                RelayEvent::MeshPeers {
                    remote_host,
                    peers,
                } => {
                    // Query Yggdrasil metrics before acquiring write lock.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node).await;

                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_peer_count = yp.len() as u32;
                        st.mesh.ygg_metrics.update(yp);
                    }
                    let mut changed = false;
                    let mut new_peer_servers: Vec<(String, String, String, u16, bool)> = Vec::new();
                    let mut newly_discovered: Vec<MeshPeerInfo> = Vec::new();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();

                    // Collect incoming peers with SPIRAL positions for batch merge.
                    let mut incoming_spiral_peers: Vec<(String, citadel_topology::Spiral3DIndex)> = Vec::new();

                    for mut peer in peers {
                        // Backfill node_name/site_name for peers from old
                        // software that doesn't include these fields.
                        if peer.node_name.is_empty() {
                            peer.node_name = derive_node_name(&peer.server_name);
                        }
                        if peer.site_name.is_empty() {
                            peer.site_name = super::server::derive_site_name(&peer.server_name);
                        }

                        // Identity = peer_id (public key).
                        let mkey = peer.peer_id.clone();

                        if st.mesh.defederated.contains(&peer.peer_id)
                            || st.mesh.defederated.contains(&peer.server_name)
                        {
                            continue;
                        }
                        // Don't add ourselves.
                        let our_pid = st.lens.peer_id.clone();
                        if mkey == our_pid {
                            continue;
                        }
                        // Don't resurrect tombstoned peers — they were evicted
                        // for VDF non-advancement and gossip is carrying stale info.
                        if st.mesh.eviction_tombstones.contains_key(&mkey) {
                            continue;
                        }
                        // Reject stale gossip at the door. If last_seen is older
                        // than GHOST_DEAD_SECS, this peer would be immediately
                        // evicted anyway. Don't waste a SPIRAL slot on a ghost.
                        if peer.last_seen > 0 && now.saturating_sub(peer.last_seen) >= 20 {
                            continue;
                        }

                        // Collect SPIRAL positions for batch merge (replaces one-by-one add).
                        if let Some(idx) = peer.spiral_index {
                            incoming_spiral_peers.push((
                                mkey.clone(),
                                citadel_topology::Spiral3DIndex::new(idx),
                            ));
                        }

                        // Register with latency + connection gossip (mesh_key → node_name routing).
                        if !st.mesh.known_peers.contains_key(&mkey) {
                            // With 2D mesh keying, same (site, node) = same key.
                            // If a CONNECTED entry already exists for this key,
                            // the live connection is authoritative — don't overwrite.
                            if st.mesh.connections.get(&mkey).copied()
                                == Some(MeshConnectionState::Connected)
                            {
                                continue;
                            }

                            info!(
                                remote_host,
                                mesh_key = %mkey,
                                peer_id = %peer.peer_id,
                                server = %peer.server_name,
                                node = %peer.node_name,
                                port = peer.port,
                                tls = peer.tls,
                                spiral_index = ?peer.spiral_index,
                                "mesh: discovered peer via gossip"
                            );
                            let peer_node_name = peer.node_name.clone();
                            let server_name = peer.server_name.clone();
                            let port = peer.port;
                            let tls = peer.tls;
                            newly_discovered.push(peer.clone());
                            // last_vdf_advance is #[serde(skip)] — always 0
                            // from deserialization.  Seed it from last_seen so
                            // the peer survives the VDF liveness sweep until a
                            // real VDF proof arrives.
                            let mut peer_to_insert = peer;
                            if peer_to_insert.vdf_step.is_some() {
                                peer_to_insert.last_vdf_advance = peer_to_insert.last_seen;
                            }
                            st.mesh.known_peers.insert(mkey.clone(), peer_to_insert);
                            changed = true;
                            new_peer_servers.push((mkey.clone(), peer_node_name, server_name, port, tls));
                        } else if let Some(existing) = st.mesh.known_peers.get_mut(&mkey) {
                            // Update telemetry if incoming data is fresher.
                            if peer.last_seen > existing.last_seen {
                                existing.last_seen = peer.last_seen;
                                existing.peer_id = peer.peer_id.clone();
                                existing.public_key_hex = peer.public_key_hex.clone();
                                existing.vdf_hash = peer.vdf_hash.clone();
                                existing.vdf_step = peer.vdf_step;
                                existing.vdf_cumulative_credit = peer.vdf_cumulative_credit;
                                // Propagate network addresses from gossip.
                                // Critical for Ygg underlay peering — without these,
                                // dial_missing_spiral_neighbors can't establish direct links.
                                // ALWAYS overwrite if the incoming data is newer (last_seen
                                // guard above). After a rolling deploy, pods get new Ygg
                                // keypairs → new overlay addresses. Stale addresses must
                                // be replaced, not preserved.
                                if peer.underlay_uri.is_some() {
                                    existing.underlay_uri = peer.underlay_uri.clone();
                                }
                                if peer.ygg_peer_uri.is_some() {
                                    existing.ygg_peer_uri = peer.ygg_peer_uri.clone();
                                }
                                if peer.yggdrasil_addr.is_some() {
                                    existing.yggdrasil_addr = peer.yggdrasil_addr.clone();
                                }
                                // SPIRAL slot: update known_peers record if changed.
                                // Topology registration is handled by the universal
                                // merge loop below — it does proper conflict resolution
                                // instead of first-writer-wins add_peer.
                                if peer.spiral_index.is_some() && existing.spiral_index != peer.spiral_index {
                                    existing.spiral_index = peer.spiral_index;
                                    changed = true;
                                }
                                // Cluster chain: propagate via gossip so all
                                // nodes see every peer's cluster identity.
                                if peer.cluster_chain_value.is_some() {
                                    existing.cluster_chain_value = peer.cluster_chain_value.clone();
                                    existing.cluster_chain_epoch_origin = peer.cluster_chain_epoch_origin.clone();
                                    existing.cluster_chain_round = peer.cluster_chain_round;
                                }
                            }
                        }
                    }

                    // ── Gossip topology learning ──────────────────────────
                    // Fill EMPTY slots from gossip. Gossip informs, HELLO decides.
                    // Slot CONFLICTS are NOT resolved here — only direct HELLO
                    // exchanges have matching VDF hash pairs for deterministic
                    // tiebreaking. Gossip is hearsay; you don't evict a live peer
                    // because a third party claimed someone else is at their slot.
                    if !incoming_spiral_peers.is_empty() {
                        for (incoming_pid, incoming_idx) in &incoming_spiral_peers {
                            let slot = incoming_idx.value();

                            // Who's currently at this slot in our topology?
                            let current_occupant = st.mesh.spiral.peer_at_index(slot)
                                .map(|s| s.to_string());

                            match current_occupant {
                                None => {
                                    // Slot empty — incoming peer takes it.
                                    st.mesh.spiral.add_peer(incoming_pid, *incoming_idx);
                                    changed = true;
                                }
                                Some(ref existing) if existing == incoming_pid => {
                                    // Same peer already there. No conflict.
                                }
                                Some(ref existing) => {
                                    // Conflict: different peer claims same slot.
                                    // Do NOT resolve from gossip. Wait for direct HELLO
                                    // where both sides have matching VDF hash snapshots.
                                    tracing::debug!(
                                        slot,
                                        existing = %existing,
                                        incoming = %incoming_pid,
                                        "SPIRAL gossip: slot conflict noted (deferred to HELLO)"
                                    );
                                }
                            }
                        }
                    }

                    // Concierge claiming happens in HELLO (assigned_slot), not here.
                    // If we're still unclaimed after processing MESH PEERS, the
                    // concierge was broken — we'll reconnect to a working one.

                    // Multi-hop gossip: re-broadcast newly discovered peers to
                    // all connected relays except the source. Only includes peers
                    // that survived dedup.
                    if !newly_discovered.is_empty() {
                        for (host, relay) in &st.federation.relays {
                            if *host != remote_host && relay.mesh_connected {
                                let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                    MeshMessage::Peers { peers: newly_discovered.clone() },
                                ));
                            }
                        }
                        info!(
                            count = newly_discovered.len(),
                            "mesh: re-gossiped newly discovered peers to neighbors"
                        );
                    }

                    if changed {
                        // SPIRAL convergence: re-evaluate our position after
                        // learning new topology. If there's a lower slot available,
                        // move there. This is the iterative convergence protocol
                        // from the SPIRAL paper — nodes fill holes naturally.
                        reconverge_spiral(&mut st, state.clone());
                        // Update SPIRAL neighbor set for latency + connection gossip.
                        update_spiral_neighbors(&mut st);
                        // Dial any SPIRAL neighbors we don't have a relay to.
                        dial_missing_spiral_neighbors(&mut st, state.clone());
                        st.notify_topology_change();
                    }

                    // Connect to newly discovered SPIRAL neighbors only.
                    // SPIRAL is a bounded-degree topology — 20 neighbors max.
                    // Non-neighbors are reachable transitively via the overlay.
                    let spiral_active = st.mesh.spiral.is_claimed();
                    if !new_peer_servers.is_empty() {
                        let event_tx = st.federation_event_tx.clone();
                        let tc = st.transport_config.clone();

                        for (mkey, node_name, server_name, port, tls) in new_peer_servers {
                            // Skip if we already have a relay to this peer (keyed by peer_id)
                            // or if there's already a relay task in-flight for this connect target.
                            if st.federation.relays.contains_key(&mkey)
                                || st.federation.pending_dials.contains(&node_name)
                                || st.federation.pending_dials.contains(&server_name)
                            {
                                continue;
                            }
                            // Skip self.
                            let our_pid = st.lens.peer_id.clone();
                            if mkey == our_pid {
                                continue;
                            }
                            // Skip defederated.
                            if st.mesh.defederated.contains(&mkey)
                                || st.mesh.defederated.contains(&server_name)
                            {
                                continue;
                            }

                            // SPIRAL gate: if we have a position, only connect
                            // to SPIRAL neighbors. Non-SPIRAL peers are reachable
                            // transitively through the overlay.
                            if spiral_active && !st.mesh.spiral.is_neighbor(&mkey) {
                                tracing::debug!(
                                    peer = %node_name,
                                    peer_id = %mkey,
                                    "mesh: skipping non-SPIRAL-neighbor (reachable via overlay)"
                                );
                                continue;
                            }

                            // Look up Yggdrasil address from known_peers for
                            // overlay routing — the key to multi-hop connectivity.
                            let peer_ygg_addr = st
                                .mesh
                                .known_peers
                                .get(&mkey)
                                .and_then(|p| p.yggdrasil_addr.as_deref())
                                .and_then(|s| s.parse().ok());

                            info!(
                                peer = %node_name,
                                peer_id = %mkey,
                                server = %server_name,
                                port,
                                tls,
                                yggdrasil = peer_ygg_addr.is_some(),
                                spiral_neighbor = spiral_active,
                                "mesh: auto-connecting to gossip-discovered peer"
                            );

                            // connect_key: use node_name if Ygg-reachable, else
                            // server_name for DNS fallback.
                            let connect_key = if peer_ygg_addr.is_some() {
                                node_name
                            } else {
                                server_name
                            };

                            // Pre-insert before spawn — caller holds write lock.
                            st.federation.pending_dials.insert(connect_key.clone());

                            let mut tc_with_peer = (*tc).clone();
                            tc_with_peer.peers.entry(connect_key.clone()).or_insert(
                                transport::PeerEntry {
                                    yggdrasil_addr: peer_ygg_addr,
                                    port,
                                    tls,
                                    want: None,
                                    dial_host: None,
                                },
                            );
                            let tc_arc = Arc::new(tc_with_peer);

                            spawn_native_relay(
                                connect_key,
                                event_tx.clone(),
                                tc_arc,
                                state.clone(),
                                false,
                            );
                        }
                    }

                    // --- Bootstrap pruning (always runs, even in full_telemetry) ---
                    // Once SPIRAL is established and we have ≥1 Ygg-connected SPIRAL
                    // neighbor that is NOT a bootstrap peer, disconnect bootstrap peers
                    // that aren't SPIRAL neighbors.
                    if st.mesh.spiral.is_claimed() {
                        let has_ygg_spiral_neighbor = st.federation.relays.iter()
                            .filter(|(_, relay)| relay.mesh_connected && !relay.is_bootstrap)
                            .any(|(host, _)| {
                                st.mesh.known_peers.iter()
                                    .find(|(_, p)| p.node_name == **host)
                                    .map(|(pid, p)| {
                                        st.mesh.spiral.is_neighbor(pid)
                                            && p.yggdrasil_addr.is_some()
                                    })
                                    .unwrap_or(false)
                            });

                        if has_ygg_spiral_neighbor {
                            let to_prune: Vec<String> = st.federation.relays.iter()
                                .filter(|(_, relay)| relay.is_bootstrap)
                                .filter(|(host, _)| {
                                    st.mesh.known_peers.iter()
                                        .find(|(_, p)| p.node_name == **host)
                                        .map(|(pid, _)| {
                                            !st.mesh.spiral.is_neighbor(pid)
                                        })
                                        .unwrap_or(false)
                                })
                                .map(|(host, _)| host.clone())
                                .collect();

                            for host in to_prune {
                                info!(
                                    peer = %host,
                                    "mesh: disconnecting bootstrap peer (not a SPIRAL neighbor)"
                                );
                                if let Some(relay) = st.federation.relays.remove(&host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::Shutdown);
                                }
                            }
                        }
                    }

                    // Prune non-SPIRAL relays. SPIRAL is the sole authority
                    // on which direct connections we maintain.
                    prune_non_spiral_relays(&mut st);
                }

                RelayEvent::MeshTopology {
                    remote_host, ..
                } => {
                    // Legacy: TOPOLOGY messages from old peers are ignored.
                    // Proof-derived latency gossip has replaced monolithic topology broadcast.
                    tracing::debug!(remote_host, "mesh: ignoring legacy TOPOLOGY (use LATENCY_HAVE)");
                }

                RelayEvent::MeshVdfProofReq { remote_host } => {
                    // Legacy: old peers may still send VdfProofReq.
                    // Ignore — window proofs replaced challenge-response.
                    tracing::debug!(remote_host, "mesh: ignoring legacy VdfProofReq (use window proofs)");
                }

                RelayEvent::MeshVdfProof {
                    remote_host,
                    proof_json: _,
                    mesh_key: _,
                } => {
                    // Legacy: old peers may still send VdfProof.
                    // Ignore — window proofs replaced challenge-response.
                    tracing::debug!(remote_host, "mesh: ignoring legacy VdfProof (use window proofs)");
                }

                RelayEvent::MeshVdfWindow {
                    remote_host,
                    data,
                    mesh_key,
                } => {
                    info!(
                        remote_host,
                        mesh_key = ?mesh_key,
                        data_len = data.len(),
                        "event: MeshVdfWindow handler entered"
                    );

                    // Decode: base64 → bincode → VdfWindowProof.
                    // Explicit error handling — no silent .ok() swallowing.
                    let b64_bytes = match base64::engine::general_purpose::STANDARD.decode(&data) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!(remote_host, error = %e, "mesh: VDF window proof base64 decode failed");
                            continue;
                        }
                    };
                    let proof = match bincode::deserialize::<lagoon_vdf::VdfWindowProof>(&b64_bytes) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(remote_host, error = %e, bytes_len = b64_bytes.len(),
                                "mesh: VDF window proof bincode deserialize failed");
                            continue;
                        }
                    };

                    if !proof.verify() {
                        warn!(
                            remote_host,
                            height_start = proof.height_start,
                            height_end = proof.height_end,
                            challenges = proof.proof.challenges.len(),
                            "mesh: VDF window proof FAILED verification"
                        );
                        continue;
                    }

                    // Check chain continuity if we have a previous tip.
                    let mut st = state.write().await;
                    if let Some(ref mkey) = mesh_key {
                        let chain_ok = if let Some(tip) =
                            st.mesh.verified_vdf_tips.get(mkey)
                        {
                            if proof.continues_from(tip) {
                                true
                            } else {
                                // Chain fork — node restarted or
                                // equivocated. Accept new chain.
                                info!(
                                    remote_host,
                                    mesh_key = mkey,
                                    "mesh: VDF chain fork detected, accepting new chain"
                                );
                                true
                            }
                        } else {
                            // First proof from this peer — accept.
                            true
                        };

                        if chain_ok {
                            // Update verified tip.
                            st.mesh
                                .verified_vdf_tips
                                .insert(mkey.clone(), proof.h_end());

                            // Update peer liveness — same as old
                            // VdfProof handler.
                            if let Some(peer) =
                                st.mesh.known_peers.get_mut(mkey)
                            {
                                let now = std::time::SystemTime::now()
                                    .duration_since(
                                        std::time::UNIX_EPOCH,
                                    )
                                    .unwrap_or_default()
                                    .as_secs();
                                let old_step = peer.vdf_step;
                                if old_step != Some(proof.height_end)
                                {
                                    peer.prev_vdf_step = old_step;
                                }
                                peer.vdf_step =
                                    Some(proof.height_end);
                                peer.last_vdf_advance = now;
                            }

                            info!(
                                remote_host,
                                mesh_key = mkey,
                                height_end = proof.height_end,
                                steps = proof.window_steps(),
                                "mesh: VDF window proof VERIFIED"
                            );

                            // Set neighbor alive in bitmap — we directly
                            // observed their VDF advancing.
                            if let Some(slot) = st.mesh.known_peers.get(mkey)
                                .and_then(|p| p.spiral_index)
                            {
                                let now_secs = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs()).unwrap_or(0);
                                st.mesh.liveness_bitmap.set_alive(slot, now_secs);
                            }
                            // Propagate the entire bitmap.
                            propagate_liveness(&st);
                        }
                    }
                }

                RelayEvent::MeshSync { remote_host } => {
                    // Query Ygg metrics before responding.
                    let ygg_peers = refresh_ygg_metrics_embedded(&ygg_node).await;

                    // A peer wants our full peer table — respond with MESH PEERS.
                    let mut st = state.write().await;

                    if let Some(yp) = ygg_peers {
                        st.mesh.ygg_metrics.update(yp);
                        st.notify_topology_change();
                    }
                    let peers: Vec<MeshPeerInfo> =
                        st.mesh.known_peers.values().cloned().collect();
                    if !peers.is_empty() {
                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::Peers { peers: peers.clone() },
                            ));
                            info!(
                                remote_host,
                                peer_count = peers.len(),
                                "mesh: sent full peer table (SYNC response)"
                            );
                        }
                    }
                }

                // ── Gossip events ─────────────────────────────────

                RelayEvent::GossipBroadcast { event } => {
                    let mut st = state.write().await;
                    let our_site = SITE_NAME.clone();
                    let id_bytes = st.mesh.gossip.broadcast_event(&event, &our_site);
                    let outbox = st.mesh.gossip.drain_outbox();

                    // Send to all mesh-connected relays.
                    for relay in st.federation.relays.values() {
                        if relay.mesh_connected {
                            for msg in &outbox {
                                if let Ok(val) = serde_json::to_value(msg) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                        MeshMessage::Gossip { message: val },
                                    ));
                                }
                            }
                        }
                    }
                    info!(
                        channel = %event.channel(),
                        nick = %event.nick(),
                        content_id = %hex::encode(&id_bytes[..8]),
                        "gossip: broadcast event to mesh"
                    );
                }

                RelayEvent::GossipReceive { remote_host, message_json } => {
                    if let Ok(gossip_msg) = serde_json::from_str::<citadel_gossip::GossipMessage>(&message_json) {
                        let mut st = state.write().await;
                        if let Some(event) = st.mesh.gossip.receive_message(gossip_msg) {
                            // Deliver to local channel members.
                            deliver_gossip_event(&st, &event);

                            // Re-gossip: forward to all OTHER connected relays.
                            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&message_json) {
                                for (host, relay) in &st.federation.relays {
                                    if relay.mesh_connected && *host != remote_host {
                                        let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                            MeshMessage::Gossip { message: val.clone() },
                                        ));
                                    }
                                }
                            }
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse MESH GOSSIP JSON");
                    }
                }

                RelayEvent::GossipSpore { remote_host, spore_json } => {
                    if let Ok(peer_spore) = serde_json::from_str::<citadel_spore::Spore>(&spore_json) {
                        let st = state.read().await;
                        let diff_msgs = st.mesh.gossip.diff_messages(&peer_spore);
                        if !diff_msgs.is_empty() {
                            if let Ok(batch_json) = serde_json::to_string(&diff_msgs) {
                                if let Some(relay) = st.federation.relays.get(&remote_host) {
                                    let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                        MeshMessage::GossipDiff { data: batch_json },
                                    ));
                                    info!(
                                        remote_host,
                                        diff_count = diff_msgs.len(),
                                        "gossip: sent SPORE catch-up diff"
                                    );
                                }
                            }
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse GOSSIP_SPORE JSON");
                    }
                }

                RelayEvent::GossipDiff { remote_host, messages_json } => {
                    if let Ok(messages) = serde_json::from_str::<Vec<citadel_gossip::GossipMessage>>(&messages_json) {
                        let mut st = state.write().await;
                        let mut accepted = 0usize;
                        for msg in messages {
                            if let Some(event) = st.mesh.gossip.receive_message(msg) {
                                deliver_gossip_event(&st, &event);
                                accepted += 1;
                            }
                        }
                        if accepted > 0 {
                            info!(
                                remote_host,
                                accepted,
                                "gossip: processed SPORE catch-up diff"
                            );
                        }
                    } else {
                        warn!(remote_host, "gossip: failed to parse GOSSIP_DIFF JSON");
                    }
                }

                RelayEvent::LatencyMeasured { remote_host, rtt_ms, mesh_key } => {
                    let mut st = state.write().await;

                    // Store on relay handle (backward compat / direct lookup).
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        relay.last_rtt_ms = Some(rtt_ms);
                    }

                    if let Some(peer_id) = mesh_key {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let our_pid = st.lens.peer_id.clone();
                        let edge = super::proof_store::ProofStore::edge_key(
                            &our_pid, &peer_id,
                        );

                        // Simple measurement payload (full PoLP crypto is Phase 3).
                        let proof_bytes = format!(
                            "{}:{}:{}:{}", edge.0, edge.1, rtt_ms, now_ms,
                        ).into_bytes();

                        let entry = super::proof_store::ProofStore::make_entry(
                            edge, rtt_ms, now_ms, proof_bytes,
                        );

                        if st.mesh.proof_store.insert(entry) {
                            tracing::info!(
                                remote_host,
                                rtt_ms,
                                proofs = st.mesh.proof_store.len(),
                                "polp: proof inserted into store",
                            );

                            // Proof was new/updated — trigger gossip to SPIRAL neighbors.
                            let spore_bytes = bincode::serialize(
                                st.mesh.proof_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.latency_gossip
                                .on_proof_updated(now_ms, &spore_bytes);
                            if !actions.is_empty() {
                                tracing::info!(
                                    count = actions.len(),
                                    "polp: sending LATENCY_HAVE to SPIRAL neighbors",
                                );
                            }
                            execute_latency_gossip_actions(&st, actions);

                            // Event-driven prune (no polling).
                            let pruned = st.mesh.proof_store.prune_stale(now_ms);
                            if pruned > 0 {
                                tracing::info!(pruned, "polp: pruned stale proofs");
                            }
                        }
                    }

                    st.notify_topology_change();
                }

                RelayEvent::PolCompleted { remote_host, rtt_us, mesh_key } => {
                    let mut st = state.write().await;

                    let rtt_ms = rtt_us as f64 / 1000.0;

                    // Store on relay handle for direct lookup.
                    if let Some(relay) = st.federation.relays.get_mut(&remote_host) {
                        relay.last_rtt_ms = Some(rtt_ms);
                    }

                    if let Some(peer_id) = mesh_key {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let our_pid = st.lens.peer_id.clone();
                        let edge = super::proof_store::ProofStore::edge_key(
                            &our_pid, &peer_id,
                        );

                        // Create a real Ed25519-signed LatencyProof from citadel-lens.
                        let signing_key = ed25519_dalek::SigningKey::from_bytes(
                            &st.lens.secret_seed,
                        );
                        let our_pubkey = signing_key.verifying_key().to_bytes();
                        let remote_pubkey = hex::decode(&st.mesh.known_peers
                            .get(&peer_id)
                            .map(|p| p.public_key_hex.clone())
                            .unwrap_or_default())
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b).ok())
                            .unwrap_or([0u8; 32]);

                        // VDF height and output for proof anchoring.
                        let (vdf_height, vdf_output) = st.mesh.vdf_state_rx
                            .as_ref()
                            .map(|rx| {
                                let vdf = rx.borrow();
                                (vdf.total_steps, vdf.current_hash)
                            })
                            .unwrap_or((0, [0u8; 32]));

                        let latency_proof = citadel_lens::proof_of_latency::LatencyProof::new(
                            our_pubkey,
                            remote_pubkey,
                            rtt_us,
                            vdf_height,
                            vdf_output,
                            &signing_key,
                        );

                        let proof_bytes = bincode::serialize(&latency_proof)
                            .unwrap_or_default();

                        let entry = super::proof_store::ProofStore::make_entry(
                            edge, rtt_ms, now_ms, proof_bytes,
                        );

                        if st.mesh.proof_store.insert(entry) {
                            tracing::info!(
                                remote_host,
                                rtt_us,
                                rtt_ms,
                                vdf_height,
                                proofs = st.mesh.proof_store.len(),
                                "pol: Ed25519-signed proof inserted",
                            );

                            // Proof was new/updated — trigger gossip to SPIRAL neighbors.
                            let spore_bytes = bincode::serialize(
                                st.mesh.proof_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.latency_gossip
                                .on_proof_updated(now_ms, &spore_bytes);
                            if !actions.is_empty() {
                                tracing::info!(
                                    count = actions.len(),
                                    "pol: sending LATENCY_HAVE to SPIRAL neighbors",
                                );
                            }
                            execute_latency_gossip_actions(&st, actions);

                            // Event-driven prune (no polling).
                            let pruned = st.mesh.proof_store.prune_stale(now_ms);
                            if pruned > 0 {
                                tracing::info!(pruned, "pol: pruned stale proofs");
                            }
                        }
                    }

                    st.notify_topology_change();
                }

                RelayEvent::LatencyHaveList { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "latency_gossip: invalid base64 in LATENCY_HAVE");
                            continue;
                        }
                    };
                    let sync_msg: super::latency_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "latency_gossip: invalid bincode in LATENCY_HAVE");
                                continue;
                            }
                        };

                    if let super::latency_gossip::SyncMessage::HaveList {
                        spore_bytes,
                    } = sync_msg
                    {
                        tracing::info!(remote_host, "polp: received LATENCY_HAVE from peer");

                        let st = state.read().await;

                        // remote_host IS the peer_id (relay key) since the peer_id refactor.
                        let from_mkey = remote_host.clone();

                        let our_spore = st.mesh.proof_store.spore();
                        let our_proof_data = st.mesh.proof_store.proof_data_for_gossip();

                        if let Some(action) = st.mesh.latency_gossip.on_have_list_received(
                            &from_mkey,
                            &spore_bytes,
                            our_spore,
                            &our_proof_data,
                        ) {
                            tracing::info!(remote_host, "polp: sending LATENCY_DELTA in response");
                            execute_latency_gossip_actions(&st, vec![action]);
                        } else {
                            tracing::debug!(remote_host, "polp: peer is up-to-date, no delta needed");
                        }
                    }
                }

                RelayEvent::LatencyProofDelta { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "latency_gossip: invalid base64 in LATENCY_DELTA");
                            continue;
                        }
                    };
                    let sync_msg: super::latency_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "latency_gossip: invalid bincode in LATENCY_DELTA");
                                continue;
                            }
                        };

                    if let super::latency_gossip::SyncMessage::ProofDelta {
                        entries,
                    } = sync_msg
                    {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let mut st = state.write().await;

                        let proof_entries: Vec<super::proof_store::ProofEntry> = entries
                            .iter()
                            .filter_map(|bytes| bincode::deserialize(bytes).ok())
                            .collect();

                        let accepted = st.mesh.proof_store.merge(proof_entries, now_ms);
                        if accepted > 0 {
                            info!(
                                remote_host, accepted,
                                "latency_gossip: merged proof delta",
                            );

                            // Re-gossip to our SPIRAL neighbors.
                            let spore_bytes = bincode::serialize(
                                st.mesh.proof_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.latency_gossip
                                .on_proof_updated(now_ms, &spore_bytes);
                            execute_latency_gossip_actions(&st, actions);

                            st.mesh.proof_store.prune_stale(now_ms);
                            st.notify_topology_change();
                        }
                    }
                }

                RelayEvent::ProfileQuery { remote_host, username } => {
                    info!(remote_host, username, "profile: received query");
                    let st = state.read().await;
                    let profile = st.profile_store.get(&username).cloned();
                    // Send response back to the querying peer.
                    if let Some(relay) = st.federation.relays.get(&remote_host) {
                        let response = MeshMessage::ProfileResponse {
                            username: username.clone(),
                            profile,
                        };
                        let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(response));
                    }
                }

                RelayEvent::ProfileResponse { remote_host, username, profile } => {
                    info!(remote_host, username, found = profile.is_some(), "profile: received response");
                    if let Some(profile) = profile {
                        let mut st = state.write().await;
                        let changed = st.profile_store.put(profile.clone());
                        if changed {
                            info!(username, "profile: merged into local store");
                            broadcast_profile_have_to_cluster(&st, Some(&remote_host));
                        }
                        // Resolve all pending queries — profile found!
                        st.profile_store.resolve_query(&username, Some(profile));
                    }
                    // None responses: don't resolve — let the caller's timeout
                    // handle the "no peer has this profile" case. Another peer
                    // might still respond with Some.
                }

                RelayEvent::ProfileHave { remote_host, payload_b64 } => {
                    let spore_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "profile_gossip: invalid base64 in PROFILE_HAVE");
                            continue;
                        }
                    };
                    let peer_spore: citadel_spore::Spore = match bincode::deserialize(&spore_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            warn!(remote_host, "profile_gossip: invalid bincode in PROFILE_HAVE");
                            continue;
                        }
                    };

                    let st = state.read().await;
                    let missing = st.profile_store.profiles_missing_from(&peer_spore);

                    if !missing.is_empty() {
                        let count = missing.len();
                        let delta_bytes = bincode::serialize(&missing).unwrap_or_default();
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&delta_bytes);

                        if let Some(relay) = st.federation.relays.get(&remote_host) {
                            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(
                                MeshMessage::ProfileDelta { data: b64 },
                            ));
                            info!(remote_host, count, "profile_gossip: sent PROFILE_DELTA in response");
                        }
                    } else {
                        tracing::debug!(remote_host, "profile_gossip: peer is up-to-date");
                    }
                }

                RelayEvent::ProfileDelta { remote_host, payload_b64 } => {
                    let delta_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "profile_gossip: invalid base64 in PROFILE_DELTA");
                            continue;
                        }
                    };
                    let profiles: Vec<super::profile::UserProfile> =
                        match bincode::deserialize(&delta_bytes) {
                            Ok(p) => p,
                            Err(_) => {
                                warn!(remote_host, "profile_gossip: invalid bincode in PROFILE_DELTA");
                                continue;
                            }
                        };

                    let mut st = state.write().await;
                    let mut merged = 0usize;
                    for profile in profiles {
                        if st.profile_store.put(profile) {
                            merged += 1;
                        }
                    }

                    if merged > 0 {
                        info!(remote_host, merged, "profile_gossip: merged profile delta");
                        // Re-gossip to other cluster peers (transitive propagation).
                        broadcast_profile_have_to_cluster(&st, Some(&remote_host));
                    }
                }

                RelayEvent::ConnectionHave { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "connection_gossip: invalid base64 in CONNECTION_HAVE");
                            continue;
                        }
                    };
                    let sync_msg: super::connection_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "connection_gossip: invalid bincode in CONNECTION_HAVE");
                                continue;
                            }
                        };

                    if let super::connection_gossip::SyncMessage::HaveList {
                        spore_bytes,
                    } = sync_msg
                    {
                        tracing::info!(remote_host, "connection_gossip: received CONNECTION_HAVE");

                        let st = state.read().await;

                        // remote_host IS the peer_id (relay key) since the peer_id refactor.
                        let from_mkey = remote_host.clone();

                        let our_spore = st.mesh.connection_store.spore();
                        let our_data = st.mesh.connection_store.snapshot_data_for_gossip();

                        if let Some(action) = st.mesh.connection_gossip.on_have_list_received(
                            &from_mkey,
                            &spore_bytes,
                            our_spore,
                            &our_data,
                        ) {
                            tracing::info!(remote_host, "connection_gossip: sending CONNECTION_DELTA");
                            execute_connection_gossip_actions(&st, vec![action]);
                        }
                    }
                }

                RelayEvent::ConnectionDelta { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "connection_gossip: invalid base64 in CONNECTION_DELTA");
                            continue;
                        }
                    };
                    let sync_msg: super::connection_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "connection_gossip: invalid bincode in CONNECTION_DELTA");
                                continue;
                            }
                        };

                    if let super::connection_gossip::SyncMessage::SnapshotDelta {
                        entries,
                    } = sync_msg
                    {
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis() as i64)
                            .unwrap_or(0);

                        let mut st = state.write().await;

                        let snapshots: Vec<super::connection_store::ConnectionSnapshot> = entries
                            .iter()
                            .filter_map(|bytes| bincode::deserialize(bytes).ok())
                            .collect();

                        let accepted = st.mesh.connection_store.merge(snapshots, now_ms);
                        if accepted > 0 {
                            info!(
                                remote_host, accepted,
                                "connection_gossip: merged snapshot delta",
                            );

                            let spore_bytes = bincode::serialize(
                                st.mesh.connection_store.spore(),
                            ).unwrap_or_default();
                            let actions = st.mesh.connection_gossip
                                .on_snapshot_updated(now_ms, &spore_bytes);
                            execute_connection_gossip_actions(&st, actions);

                            st.mesh.connection_store.prune_stale(now_ms);
                            st.notify_topology_change();
                        }
                    }
                }


                RelayEvent::LivenessHave { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "liveness_gossip: invalid base64 in LIVENESS_HAVE");
                            continue;
                        }
                    };
                    let sync_msg: super::liveness_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "liveness_gossip: invalid bincode in LIVENESS_HAVE");
                                continue;
                            }
                        };

                    if let super::liveness_gossip::SyncMessage::HaveList {
                        spore_bytes,
                    } = sync_msg
                    {
                        tracing::debug!(remote_host, "liveness_gossip: received LIVENESS_HAVE");

                        let st = state.read().await;

                        let from_mkey = remote_host.clone();
                        let our_spore = st.mesh.liveness_bitmap.spore();
                        let our_data = st.mesh.liveness_bitmap.slot_data();

                        if let Some(action) = st.mesh.liveness_gossip.on_have_list_received(
                            &from_mkey,
                            &spore_bytes,
                            our_spore,
                            &our_data,
                        ) {
                            tracing::debug!(remote_host, "liveness_gossip: sending LIVENESS_DELTA");
                            execute_liveness_gossip_actions(&st, vec![action]);
                        }
                    }
                }

                RelayEvent::LivenessDelta { remote_host, payload_b64 } => {
                    let msg_bytes = match base64::engine::general_purpose::STANDARD
                        .decode(&payload_b64)
                    {
                        Ok(b) => b,
                        Err(_) => {
                            warn!(remote_host, "liveness_gossip: invalid base64 in LIVENESS_DELTA");
                            continue;
                        }
                    };
                    let sync_msg: super::liveness_gossip::SyncMessage =
                        match bincode::deserialize(&msg_bytes) {
                            Ok(m) => m,
                            Err(_) => {
                                warn!(remote_host, "liveness_gossip: invalid bincode in LIVENESS_DELTA");
                                continue;
                            }
                        };

                    if let super::liveness_gossip::SyncMessage::LivenessDelta {
                        entries,
                    } = sync_msg
                    {
                        let now_secs = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);

                        let mut st = state.write().await;

                        // OR-merge: each entry is a bincode-serialized u64 slot.
                        let accepted = st.mesh.liveness_bitmap.merge_slots(&entries, now_secs);
                        if accepted > 0 {
                            tracing::info!(
                                remote_host, accepted,
                                "liveness_bitmap: merged liveness delta (new alive slots)",
                            );

                            // Update last_seen for peers whose slots are now alive.
                            // Slot → mesh_key lookup via known_peers' spiral_index.
                            let received_slots: Vec<u64> = entries
                                .iter()
                                .filter_map(|b| bincode::deserialize::<u64>(b).ok())
                                .collect();
                            for (_mkey, peer) in st.mesh.known_peers.iter_mut() {
                                if let Some(slot) = peer.spiral_index {
                                    if received_slots.contains(&slot) && now_secs > peer.last_seen {
                                        peer.last_seen = now_secs;
                                    }
                                }
                            }

                            // Propagate the entire bitmap to neighbors.
                            propagate_liveness(&st);
                        }
                    }
                }

                RelayEvent::CvdfMessage { remote_host, data } => {
                    use base64::Engine as _;
                    // Decode: base64 → bincode → CvdfServiceMessage
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(&data)
                        .ok()
                        .and_then(|bytes| bincode::deserialize::<
                            citadel_lens::service::CvdfServiceMessage,
                        >(&bytes).ok());
                    let Some(payload) = decoded else {
                        warn!(remote_host, "cvdf: failed to decode message");
                        continue;
                    };
                    // Look up the sender's pubkey — remote_host IS peer_id since relay refactor.
                    let mut st = state.write().await;
                    let sender_pubkey = st.mesh.known_peers.get(&remote_host)
                        .and_then(|p| hex::decode(&p.public_key_hex).ok())
                        .and_then(|b| if b.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&b);
                            Some(arr)
                        } else {
                            None
                        });
                    if let (Some(svc), Some(pubkey)) =
                        (st.mesh.cvdf_service.as_mut(), sender_pubkey)
                    {
                        svc.receive(&pubkey, payload);
                    }
                }

                RelayEvent::ChainUpdate { remote_host, value, cumulative_work, round, proof, work_contributions, epoch_origin } => {
                    // SPORE cascade: a peer merged and is broadcasting the result.
                    // If their work > ours, adopt — no re-merge, no double-counting.
                    //
                    // PROOF VERIFICATION: if a proof is present, verify it before
                    // adopting. Without a valid proof, reject the update — the
                    // cumulative_work claim is just a number someone made up.
                    let chain_bytes = hex::decode(&value).ok().and_then(|b| {
                        <[u8; 32]>::try_from(b.as_slice()).ok()
                    });
                    if let Some(new_value) = chain_bytes {
                        // Verify proof if present.
                        let proof_valid = if let Some(ref proof_b64) = proof {
                            use base64::Engine as _;
                            let decoded = base64::engine::general_purpose::STANDARD
                                .decode(proof_b64)
                                .ok()
                                .and_then(|bytes| bincode::deserialize::<
                                    super::cluster_chain::ClusterChainProof
                                >(&bytes).ok());
                            match decoded {
                                Some(p) => {
                                    let ok = p.verify() && p.tip == new_value
                                        && p.cumulative_work == cumulative_work;
                                    if !ok {
                                        warn!(
                                            from = %remote_host,
                                            "cluster chain: REJECTED ChainUpdate — proof verification failed"
                                        );
                                    }
                                    ok
                                }
                                None => {
                                    warn!(from = %remote_host, "cluster chain: REJECTED — proof decode failed");
                                    false
                                }
                            }
                        } else {
                            // No proof attached — accept during rollout.
                            true
                        };

                        if !proof_valid { continue; }

                        // Decode work contributions from hex keys → [u8;32] keys.
                        // If absent (old nodes during rollout), synthesize single-entry map.
                        let peer_contributions: std::collections::BTreeMap<[u8; 32], u64> =
                            work_contributions.as_ref()
                                .map(|wc| {
                                    wc.iter().filter_map(|(hex_key, &steps)| {
                                        hex::decode(hex_key).ok()
                                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                                            .map(|k| (k, steps))
                                    }).collect()
                                })
                                .unwrap_or_else(|| {
                                    let mut m = std::collections::BTreeMap::new();
                                    m.insert(new_value, cumulative_work);
                                    m
                                });

                        // Decode epoch_origin from hex → [u8; 32].
                        let epoch_origin_bytes: Option<[u8; 32]> = epoch_origin.as_ref()
                            .and_then(|hex_str| {
                                hex::decode(hex_str).ok()
                                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                            });

                        let mut st = state.write().await;
                        let adopted = if let Some(ref mut cc) = st.mesh.cluster_chain {
                            if cumulative_work > cc.cumulative_work {
                                cc.adopt(new_value, round, peer_contributions, epoch_origin_bytes);
                                true
                            } else {
                                false
                            }
                        } else {
                            // We have no chain — adopt theirs.
                            let mut cc = super::cluster_chain::ClusterChain::genesis(
                                new_value, round, 1);
                            cc.adopt(new_value, round, peer_contributions, epoch_origin_bytes);
                            st.mesh.cluster_chain = Some(cc);
                            true
                        };
                        if adopted {
                            info!(
                                from = %remote_host,
                                chain = &value[..8.min(value.len())],
                                cumulative_work,
                                proof_verified = proof.is_some(),
                                "cluster chain: adopted via SPORE cascade"
                            );
                            // Re-broadcast to our peers so the cascade continues.
                            broadcast_chain_update(&st);
                        }
                    }
                }

                RelayEvent::SocketMigrate { remote_host, migration, client_peer_id } => {
                    tracing::info!(
                        remote_host,
                        client_peer_id,
                        "switchboard: received socket migration — restoring"
                    );
                    let state_clone = Arc::clone(&state);
                    let client_id = client_peer_id.clone();
                    let mig = migration.clone();
                    tokio::spawn(async move {
                        if let Err(e) = super::switchboard::handle_socket_migration(
                            &mig,
                            &client_id,
                            state_clone,
                        ).await {
                            tracing::warn!(
                                client_peer_id = %client_id,
                                error = %e,
                                "switchboard: socket migration restore failed"
                            );
                        }
                    });
                }
            } // match event
            } // Some(event) => {

            // VDF liveness: broadcast window proof to SPIRAL neighbors and
            // sweep for dead peers whose VDF stopped advancing.
            //
            // Push-based: generate a VdfWindowProof covering the last ~30
            // VDF steps (3 seconds at 10 Hz), broadcast it to all SPIRAL
            // neighbors, then trim the chain.  Merkle+Fiat-Shamir: ~500
            // bytes constant-size regardless of window length.
            // O(1) per node (≤20 neighbors), not O(N) flooding.
            _ = vdf_window_interval.tick() => {
                // Generate window proof from accumulated chain steps.
                // IMPORTANT: Extract the quantum boundary VDF hash BEFORE
                // trim_to(1) discards historical hashes.
                let mut st = state.write().await;
                let mut quantized_height: Option<u64> = None;
                let window_msg = if let Some(ref chain) = st.mesh.vdf_chain {
                    let mut c = chain.write().await;
                    if c.window_len() >= 2 {
                        // Universal Clock: compute quantized VDF height.
                        //
                        // Every node independently observes the same quantum
                        // boundary. No leader. No propagation. The VDF height
                        // IS the clock — quantizing eliminates minor drift.
                        use super::cluster_chain::ROUND_QUANTUM;
                        let chain_height = c.height();
                        quantized_height = Some((chain_height / ROUND_QUANTUM) * ROUND_QUANTUM);

                        let spiral_slot = st.lens.spiral_index;
                        let proof = c.generate_window_proof(spiral_slot, 3);
                        c.trim_to(1);
                        drop(c);
                        if let Ok(bytes) = bincode::serialize(&proof) {
                            let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
                            Some((
                                MeshMessage::VdfWindow { data: encoded },
                                proof.height_end,
                                proof.window_steps(),
                            ))
                        } else {
                            None
                        }
                    } else {
                        drop(c);
                        None
                    }
                } else {
                    None
                };

                // Advance cluster identity chain on each VDF window tick.
                //
                // The round seed is derived from the QUANTIZED VDF HEIGHT.
                // Every node independently computes the same seed because
                // every node observes the same quantum boundary. No clock
                // source. No HELLO propagation. The Universal Clock is the
                // quantized VDF height — deterministic, agreed-upon, sovereign.
                //
                // The chain value provides accumulated entropy from merges.
                // The height provides the shared, changing input each round.
                // advance_chain(prev, seed) = blake3(blake3(prev || seed)).
                if let Some(quantized) = quantized_height {
                    let round_seed = *blake3::hash(&quantized.to_le_bytes()).as_bytes();
                    st.mesh.cluster_round_seed = Some(round_seed);
                    let cluster_size = (st.mesh.known_peers.len() + 1) as u32;
                    if let Some(ref mut cc) = st.mesh.cluster_chain {
                        if quantized > cc.last_timestamp_round() {
                            cc.advance(&round_seed, quantized, cluster_size);
                        }
                    }
                }

                // HACK(TODO: remove): Re-broadcast HELLO so cluster chain values propagate.
                // Without this, chains only compare on initial connection —
                // nodes that connected before merge never re-compare.
                // The 5s debounce in announce_hello_to_all_relays prevents flooding.
                //
                // The real fix: piggyback chain_value + chain_round on VdfWindow
                // messages (already sent to all SPIRAL neighbors every tick) or
                // add a lightweight CHAIN_SYNC gossip message. Full HELLO re-broadcast
                // is wasteful — it carries the entire payload every 5s.
                announce_hello_to_all_relays(&mut st);

                // Broadcast to SPIRAL neighbors.
                if let Some((msg, height, steps)) = window_msg {
                    let neighbor_keys: Vec<String> = st.mesh.spiral.neighbors()
                        .iter().cloned().collect();
                    let mut sent = 0usize;
                    let mut dead_relays: Vec<String> = Vec::new();
                    for nkey in &neighbor_keys {
                        if let Some(relay) = st.federation.relays.get(nkey) {
                            if !relay.mesh_connected { continue; }
                            if relay.outgoing_tx.send(RelayCommand::SendMesh(
                                msg.clone(),
                            )).is_err() {
                                // Receiver dropped — handler exited.
                                dead_relays.push(nkey.clone());
                            } else {
                                sent += 1;
                            }
                        }
                    }
                    // Reap zombie relays whose handlers already exited.
                    for dead in &dead_relays {
                        st.federation.relays.remove(dead);
                        tracing::warn!(
                            relay = dead.as_str(),
                            "mesh: reaped zombie relay (handler exited)"
                        );
                    }
                    if sent > 0 {
                        tracing::debug!(
                            height,
                            steps,
                            sent,
                            "mesh: broadcast VDF window proof"
                        );
                    }
                }

                // Self-attestation: set our own bit alive on every VDF tick.
                // Propagation happens with the entire bitmap, not per-slot.
                if let Some(our_slot) = st.mesh.spiral.our_index().map(|i| i.value()) {
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs()).unwrap_or(0);
                    st.mesh.liveness_bitmap.set_alive(our_slot, now_secs);
                }
                propagate_liveness(&st);

                // VDF dead-peer sweep. 10s. One rule. No exceptions.
                let evicted = evict_dead_peers(&mut st);
                if !evicted.is_empty() {
                    // Do NOT reconverge here. Timer-driven reconverge has no
                    // accompanying topology update — we see "empty" slots that
                    // may actually be occupied by peers whose gossip hasn't
                    // arrived yet. Moving to those slots causes collisions.
                    // Reconverge is safe only after processing fresh topology
                    // data (HELLO, PEERS, Disconnected).
                    // (Lean: reconverge_requires_complete_topology)
                    let neighbors = st.mesh.spiral.neighbors().clone();
                    st.mesh.latency_gossip.set_spiral_neighbors(neighbors.clone());
                    st.mesh.connection_gossip.set_spiral_neighbors(neighbors.clone());
                    st.mesh.liveness_gossip.set_spiral_neighbors(neighbors);
                    dial_missing_spiral_neighbors(&mut st, state.clone());
                    // APE: if eviction killed all our relays, rejoin the mesh.
                    attempt_mesh_rejoin(&mut st, state.clone());
                    publish_connection_snapshot(&mut st);
                    st.notify_topology_change();
                }

                // CVDF cooperative tick — attest + produce (if our duty).
                if let Some(ref mut svc) = st.mesh.cvdf_service {
                    svc.tick();
                }
            }

            // Drain CVDF outbound messages — SPIRAL-neighbor-scoped.
            //
            // VDF proofs are a handshake with your direct SPIRAL neighbors
            // and nodes you contact. They are NOT gossiped further.
            // Only your direct neighbors can disconnect you, so only they
            // need your proof. A node three hops away can't act on it.
            // O(1) per node (≤20 neighbors), not O(N) flooding.
            Some((target, msg)) = cvdf_outbound_rx.recv() => {
                let data = super::cvdf_transport::encode_cvdf_message(&msg);
                let mesh_msg = MeshMessage::Cvdf { data };
                let st = state.read().await;
                match target {
                    None => {
                        // Send to direct SPIRAL neighbors only.
                        let neighbor_keys: Vec<String> = st.mesh.spiral
                            .neighbors().iter().cloned().collect();
                        for nkey in &neighbor_keys {
                            if let Some(peer) = st.mesh.known_peers.get(nkey) {
                                if let Some(relay) = st.federation.relays
                                    .get(&peer.node_name)
                                {
                                    if !relay.mesh_connected { continue; }
                                    let _ = relay.outgoing_tx.send(
                                        RelayCommand::SendMesh(mesh_msg.clone()),
                                    );
                                }
                            }
                        }
                    }
                    Some(pubkey) => {
                        // Send to specific peer by pubkey.
                        let target_hex = hex::encode(pubkey);
                        if let Some(peer) = st.mesh.known_peers.values()
                            .find(|p| p.public_key_hex == target_hex)
                        {
                            if let Some(relay) = st.federation.relays
                                .get(&peer.node_name)
                            {
                                if relay.mesh_connected {
                                    let _ = relay.outgoing_tx.send(
                                        RelayCommand::SendMesh(mesh_msg),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Bootstrap retry: if we have no relay connections and no active
            // dials, re-attempt LAGOON_PEERS. Self-connections are handled by
            // transparent self-rejection at the TCP level — the listener drops
            // connections from ourselves, so the proxy retries on another machine.
            // No beacon toggling, no flashlight, no state machine. Just retry.
            _ = bootstrap_retry_interval.tick() => {
                let st = state.read().await;
                if !st.federation.relays.is_empty() || st.federation.active_dial_count > 0 {
                    continue;
                }
                let tc = st.transport_config.clone();
                let peers: Vec<String> = tc.peers.keys().cloned().collect();
                if peers.is_empty() {
                    continue;
                }
                let event_tx = st.federation_event_tx.clone();
                drop(st);
                for peer_host in peers {
                    if state.read().await.mesh.defederated.contains(&peer_host) {
                        continue;
                    }
                    info!(
                        peer = %peer_host,
                        "mesh: bootstrap retry — no connections, re-attempting"
                    );
                    spawn_native_relay(
                        peer_host,
                        event_tx.clone(),
                        Arc::clone(&tc),
                        state.clone(),
                        true,
                    );
                }
            }

            // PoL challenge round: send PolChallenge to every connected relay.
            // Relay tasks record timing; PolResponse creates Ed25519 LatencyProof.
            _ = pol_challenge_interval.tick() => {
                let st = state.read().await;
                let relay_count = st.federation.relays.len();
                if relay_count == 0 { continue; }
                for (_peer_id, relay) in st.federation.relays.iter() {
                    if !relay.mesh_connected { continue; }
                    pol_nonce_counter += 1;
                    let _ = relay.outgoing_tx.send(
                        RelayCommand::SendMesh(
                            MeshMessage::PolChallenge { nonce: pol_nonce_counter },
                        ),
                    );
                }
            }

            // Latency swap round: deterministic topology optimization.
            // Every node independently computes the same swap decisions from
            // shared PoLP latency data (proof_store). Swaps that improve
            // combined neighbor latency are applied atomically.
            _ = latency_swap_interval.tick() => {
                // LAGOON_ENABLE_SWAPS=1 to opt in. Off by default — swap
                // decisions require identical latency maps on every node,
                // which gossip can't guarantee. Causes oscillation.
                if std::env::var("LAGOON_ENABLE_SWAPS").as_deref() != Ok("1") {
                    continue;
                }
                let mut st = state.write().await;
                if !st.mesh.spiral.is_claimed() || st.mesh.spiral.occupied_count() < 3 {
                    continue;
                }

                // Build latency map from PoLP proof store.
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let latency_map = st.mesh.proof_store.latency_map(now_ms);

                if latency_map.is_empty() {
                    continue;
                }

                // Compute deterministic swap round.
                let decisions = st.mesh.spiral.compute_swap_round(|a, b| {
                    // Canonical key: smaller peer_id first.
                    let key = if a < b {
                        (a.to_string(), b.to_string())
                    } else {
                        (b.to_string(), a.to_string())
                    };
                    latency_map.get(&key).copied().unwrap_or(100.0)
                });

                if decisions.is_empty() {
                    continue;
                }

                // Apply all swaps.
                let our_pid = st.lens.peer_id.clone();
                let mut we_moved = false;
                for swap in &decisions {
                    st.mesh.spiral.apply_swap(&swap.peer_a, &swap.peer_b);
                    if swap.peer_a == our_pid || swap.peer_b == our_pid {
                        we_moved = true;
                    }
                }

                info!(
                    swaps = decisions.len(),
                    we_moved,
                    "SPIRAL latency swap: round complete"
                );

                if we_moved {
                    if let Some(idx) = st.mesh.spiral.our_index().map(|i| i.value()) {
                        persist_spiral_position(&mut st, idx);
                    }
                    announce_hello_to_all_relays(&mut st);
                }
                update_spiral_neighbors(&mut st);
                dial_missing_spiral_neighbors(&mut st, state.clone());
                st.notify_topology_change();
                // Atomic reslot: new connections first, prune later (via HELLO or MeshPeers).
            }

            else => break,
        } // select!
        } // loop
    });
    // Monitor the event loop task — if it panics, log the panic message.
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => info!("federation event loop: exited normally"),
            Err(e) => {
                if e.is_panic() {
                    let panic_msg = if let Some(s) = e.into_panic().downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "(non-string panic payload)".to_string()
                    };
                    tracing::error!(
                        panic_msg,
                        "CRITICAL: federation event loop PANICKED — all mesh processing stopped"
                    );
                } else {
                    tracing::error!(error = %e, "CRITICAL: federation event loop task aborted");
                }
            }
        }
    });
}

/// Broadcast our profile SPORE HaveList to all connected cluster peers.
///
/// Called after a profile change (registration, merge from delta) so that
/// other same-site nodes can diff and pull any profiles they're missing.
/// `exclude` skips a specific relay (the one that just sent us the delta).
pub fn broadcast_profile_have_to_cluster(
    st: &super::server::ServerState,
    exclude: Option<&str>,
) {
    let spore_bytes = bincode::serialize(st.profile_store.spore()).unwrap_or_default();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&spore_bytes);
    let msg = MeshMessage::ProfileHave { data: b64 };
    let our_site = &*SITE_NAME;

    for (key, relay) in &st.federation.relays {
        if exclude == Some(key.as_str()) {
            continue;
        }
        // Relay key IS peer_id — look up in known_peers directly.
        let is_cluster = st.mesh.known_peers.get(key)
            .map(|p| super::gossip::is_cluster_peer(our_site, &p.site_name))
            .unwrap_or(false);

        if is_cluster {
            if !relay.mesh_connected { continue; }
            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(msg.clone()));
        }
    }
}

/// Broadcast current cluster chain state to ALL connected peers.
///
/// Called after a merge or SPORE adoption. Every connected peer receives the
/// new chain value + cumulative work. Receivers with lower work adopt it.
/// This is the SPORE cascade path — cluster-mates see higher work and adopt
/// without re-merging (preventing double-counting).
///
/// Broadcasts to ALL peers (not just same-site) because after a cross-cluster
/// merge, the old army members on both sides need the update.
pub fn broadcast_chain_update(st: &super::server::ServerState) {
    let Some(ref cc) = st.mesh.cluster_chain else { return };
    // Generate ZK proof — 3 Fiat-Shamir challenges, ~500 bytes constant-size.
    let proof_b64 = {
        let proof = cc.generate_proof(3);
        bincode::serialize(&proof).ok().map(|bytes| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        })
    };
    let msg = MeshMessage::ChainUpdate {
        value: cc.value_hex(),
        cumulative_work: cc.cumulative_work,
        round: cc.round,
        proof: proof_b64,
        work_contributions: Some(cc.contributions_hex()),
        epoch_origin: Some(hex::encode(cc.epoch_origin)),
    };
    for (_key, relay) in &st.federation.relays {
        // Skip relays that haven't completed Hello handshake.
        // Without this, ChainUpdate can arrive before our Hello response,
        // causing "first message must be Hello" on the remote.
        if !relay.mesh_connected { continue; }
        let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(msg.clone()));
    }
}

/// Execute latency gossip sync actions by sending MESH subcommands to relay peers.
fn execute_latency_gossip_actions(
    st: &super::server::ServerState,
    actions: Vec<super::latency_gossip::SyncAction>,
) {
    for action in actions {
        let (peer_id, message) = match action {
            super::latency_gossip::SyncAction::SendHaveList {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
            super::latency_gossip::SyncAction::SendProofDelta {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
        };
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&message).unwrap_or_default());
        let mesh_msg = match &message {
            super::latency_gossip::SyncMessage::HaveList { .. } => {
                MeshMessage::LatencyHave { data: b64 }
            }
            super::latency_gossip::SyncMessage::ProofDelta { .. } => {
                MeshMessage::LatencyDelta { data: b64 }
            }
        };
        if let Some(relay) = st.federation.relays.get(&peer_id) {
            if !relay.mesh_connected { continue; }
            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(mesh_msg));
        }
    }
}

/// Execute connection gossip sync actions by sending MESH subcommands to relay peers.
fn execute_connection_gossip_actions(
    st: &super::server::ServerState,
    actions: Vec<super::connection_gossip::SyncAction>,
) {
    for action in actions {
        let (peer_id, message) = match action {
            super::connection_gossip::SyncAction::SendHaveList {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
            super::connection_gossip::SyncAction::SendSnapshotDelta {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
        };
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&message).unwrap_or_default());
        let mesh_msg = match &message {
            super::connection_gossip::SyncMessage::HaveList { .. } => {
                MeshMessage::ConnectionHave { data: b64 }
            }
            super::connection_gossip::SyncMessage::SnapshotDelta { .. } => {
                MeshMessage::ConnectionDelta { data: b64 }
            }
        };
        if let Some(relay) = st.federation.relays.get(&peer_id) {
            if !relay.mesh_connected { continue; }
            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(mesh_msg));
        }
    }
}

/// Execute liveness gossip sync actions by sending MESH subcommands to relay peers.
fn execute_liveness_gossip_actions(
    st: &super::server::ServerState,
    actions: Vec<super::liveness_gossip::SyncAction>,
) {
    for action in actions {
        let (peer_id, message) = match action {
            super::liveness_gossip::SyncAction::SendHaveList {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
            super::liveness_gossip::SyncAction::SendLivenessDelta {
                neighbor_peer_id, message,
            } => (neighbor_peer_id, message),
        };
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&message).unwrap_or_default());
        let mesh_msg = match &message {
            super::liveness_gossip::SyncMessage::HaveList { .. } => {
                MeshMessage::LivenessHave { data: b64 }
            }
            super::liveness_gossip::SyncMessage::LivenessDelta { .. } => {
                MeshMessage::LivenessDelta { data: b64 }
            }
        };
        if let Some(relay) = st.federation.relays.get(&peer_id) {
            if !relay.mesh_connected { continue; }
            let _ = relay.outgoing_tx.send(RelayCommand::SendMesh(mesh_msg));
        }
    }
}

/// Propagate the entire liveness bitmap to SPIRAL neighbors via SPORE.
///
/// Push-push protocol — no request step:
///   1. We send our HaveList (SPORE ranges) to each neighbor
///   2. Each neighbor XORs against their own → computes the difference set
///   3. Each neighbor sends us a Delta with entries we're missing
///
/// Convergence = MIN_LATENCY × HOPS (one-way per hop, not RTT).
/// Only difference sets flow — O(churn), not O(mesh_size).
fn propagate_liveness(st: &super::server::ServerState) {
    let spore_bytes = bincode::serialize(
        st.mesh.liveness_bitmap.spore(),
    ).unwrap_or_default();
    let actions = st.mesh.liveness_gossip
        .propagate(&spore_bytes);
    if !actions.is_empty() {
        tracing::debug!(
            neighbors = actions.len(),
            alive = st.mesh.liveness_bitmap.alive_count(),
            "liveness_bitmap: propagating difference sets to SPIRAL neighbors",
        );
    }
    execute_liveness_gossip_actions(st, actions);
}

/// Publish a connection snapshot to the ConnectionStore and trigger SPORE gossip.
///
/// Call this after any change to `st.mesh.connections` (connect/disconnect).
fn publish_connection_snapshot(st: &mut super::server::ServerState) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    let our_pid = st.lens.peer_id.clone();
    let connected_peers: Vec<String> = st.mesh.connections.iter()
        .filter(|entry| *entry.1 == super::server::MeshConnectionState::Connected)
        .map(|(mkey, _)| mkey.clone())
        .collect();

    let snapshot = super::connection_store::ConnectionStore::make_snapshot(
        our_pid,
        connected_peers,
        now_ms,
    );

    if st.mesh.connection_store.insert(snapshot) {
        let spore_bytes = bincode::serialize(
            st.mesh.connection_store.spore(),
        ).unwrap_or_default();
        let actions = st.mesh.connection_gossip
            .on_snapshot_updated(now_ms, &spore_bytes);
        if !actions.is_empty() {
            tracing::info!(
                count = actions.len(),
                "connection_gossip: sending CONNECTION_HAVE to SPIRAL neighbors",
            );
        }
        execute_connection_gossip_actions(st, actions);

        st.mesh.connection_store.prune_stale(now_ms);
    }
}

/// Deliver a gossip IRC event to local channel members.
///
/// Display rules:
/// - Same SITE_NAME origin → bare nick (transparent cluster)
/// - Different SITE_NAME → `nick@origin` (foreign supernode)
/// - Skip the original sender if they're a local user (already saw their own message)
fn deliver_gossip_event(
    st: &super::server::ServerState,
    event: &super::gossip::GossipIrcEvent,
) {
    use super::gossip::GossipIrcEvent;

    let our_site = &*SITE_NAME;
    let is_cluster = super::gossip::is_cluster_peer(our_site, &super::server::derive_site_name(event.origin()));

    // Format the display nick based on cluster vs federation.
    let display_nick = if is_cluster {
        event.nick().to_string()
    } else {
        format!("{}@{}", event.nick(), event.origin())
    };
    let prefix = format!("{}!{}@{}", display_nick, event.nick(), event.origin());

    let channel = super::server::irc_lower(event.channel());

    // Get local members of this channel.
    let members: Vec<String> = st
        .channels
        .get(&channel)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    if members.is_empty() {
        return;
    }

    // Build the IRC message to deliver.
    let irc_msg = match event {
        GossipIrcEvent::Message { text, command, .. } => Message {
            prefix: Some(prefix),
            command: command.clone(),
            params: vec![event.channel().to_string(), text.clone()],
        },
        GossipIrcEvent::Join { .. } => Message {
            prefix: Some(prefix),
            command: "JOIN".into(),
            params: vec![event.channel().to_string()],
        },
        GossipIrcEvent::Part { reason, .. } => Message {
            prefix: Some(prefix),
            command: "PART".into(),
            params: vec![event.channel().to_string(), reason.clone()],
        },
        GossipIrcEvent::Topic { text, .. } => Message {
            prefix: Some(prefix),
            command: "TOPIC".into(),
            params: vec![event.channel().to_string(), text.clone()],
        },
    };

    // Deliver to each local channel member.
    // Skip the original sender if they're local (cluster case: they already
    // saw their own message from the local broadcast).
    let sender_key = if is_cluster {
        Some(super::server::irc_lower(event.nick()))
    } else {
        None
    };

    for nick_key in &members {
        // Skip the sender if they're a local user in the cluster.
        if sender_key.as_deref() == Some(nick_key.as_str()) {
            continue;
        }
        if let Some(handle) = st.clients.get(nick_key) {
            let _ = handle.tx.send(irc_msg.clone());
        }
    }
}

/// Spawn a relay connection to a remote server.
///
/// `relay_key` is the unique node identity (node_name) used for keying
/// `federation.relays` and identifying events.
///
/// `connect_target` is the hostname/address passed to `transport::connect()`.
/// For LAGOON_PEERS entries this is the FQDN; for gossip-discovered peers
/// this may be the node_name (with Ygg address in the transport config).
pub fn spawn_relay(
    relay_key: String,
    connect_target: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) -> (mpsc::UnboundedSender<RelayCommand>, tokio::task::JoinHandle<()>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

    let handle = tokio::spawn(relay_task(
        relay_key,
        connect_target,
        cmd_rx,
        event_tx,
        transport_config,
    ));

    (cmd_tx, handle)
}

// ---------------------------------------------------------------------------
// Native mesh relay — JSON over WebSocket, no IRC framing
// ---------------------------------------------------------------------------

/// Outcome of a native WebSocket relay loop iteration.
enum NativeLoopOutcome {
    /// Connection lost or closed by remote — reconnect with backoff.
    Reconnect,
    /// Explicit shutdown requested — exit permanently.
    Shutdown,
}

/// Spawn a native mesh relay task (JSON over WebSocket).
///
/// Spawn a native mesh relay task (JSON over WebSocket).
///
/// The task manages its own lifecycle:
/// - Creates its own command channel
/// - Inserts itself into `federation.relays` AFTER HELLO exchange (keyed by peer_id)
/// - Removes itself on disconnect, sends `RelayEvent::Disconnected`
/// - Reconnects with exponential backoff
///
/// Callers just spawn and move on — no pre-insertion needed.
pub fn spawn_native_relay(
    connect_target: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
    state: Arc<tokio::sync::RwLock<super::server::ServerState>>,
    is_bootstrap: bool,
) {
    tokio::spawn(relay_task_native(
        connect_target,
        event_tx,
        transport_config,
        state,
        is_bootstrap,
    ));
}

/// Native mesh relay task — connects to `/api/mesh/ws`, exchanges JSON
/// `MeshMessage` frames. Reconnects on failure with exponential backoff.
///
/// Self-managing: creates its own command channel, inserts itself into the relay
/// map after HELLO (keyed by peer_id), removes itself on disconnect.
async fn relay_task_native(
    connect_target: String,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
    state: Arc<tokio::sync::RwLock<super::server::ServerState>>,
    is_bootstrap: bool,
) {
    // Track this task in the dial count so bootstrap retry doesn't spawn duplicates.
    // Also register in pending_dials so gossip-driven spawn_native_relay() calls
    // don't create duplicates while we're still in the HELLO exchange window.
    {
        let mut st = state.write().await;
        st.federation.active_dial_count += 1;
        st.federation.pending_dials.insert(connect_target.clone());
    }

    // One command channel for the lifetime of this task — survives reconnects.
    // cmd_tx clones go into the RelayHandle after each HELLO. cmd_rx stays here
    // so we can drain Shutdown commands during backoff.
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();

    let mut consecutive_failures: u32 = 0;
    let mut self_hits: u32 = 0;
    let mut current_peer_id: Option<String> = None;
    // Persists across reconnect iterations — carries identity forward for
    // should_keep_retrying and PeerGone even after current_peer_id is cleared.
    let mut last_known_peer_id: Option<String> = None;

    'reconnect: loop {
        let connected_at = std::time::Instant::now();

        // Include our peer_id in the URL so the remote listener can detect
        // self-connections at the TCP level (transparent self — drops without
        // responding, causing the proxy to retry on another machine).
        let (our_pid, switchboard_ctl) = {
            let st = state.read().await;
            let ctl = if is_bootstrap {
                st.mesh.switchboard_ctl.clone()
            } else {
                None
            };
            (st.lens.peer_id.clone(), ctl)
        };

        // Pause switchboard before dialing anycast — drops the listening
        // socket so the kernel RSTs self-routed SYNs. Fly routes to the
        // next machine. Only needed for bootstrap (anycast) dials.
        if let Some(ref ctl) = switchboard_ctl {
            let _ = ctl.send(super::switchboard::SwitchboardCtl::Pause);
        }

        let connect_result = transport::connect_native(&connect_target, &transport_config, Some(&our_pid)).await;

        // Resume switchboard — rebind the listener regardless of outcome.
        if let Some(ref ctl) = switchboard_ctl {
            let _ = ctl.send(super::switchboard::SwitchboardCtl::Resume);
        }

        let outcome = match connect_result {
            Ok(transport::NativeWs::Tls(ws)) => {
                self_hits = 0;
                info!(%connect_target, "native relay: connected via TLS WebSocket");
                native_ws_loop(
                    ws, &connect_target, &cmd_tx, &mut cmd_rx, &event_tx,
                    &state, is_bootstrap, &mut current_peer_id,
                ).await
            }
            Ok(transport::NativeWs::Switchboard { reader, writer }) => {
                self_hits = 0;
                info!(%connect_target, "native relay: connected via switchboard (raw TCP)");
                native_raw_loop(
                    reader, writer, &connect_target, &cmd_tx, &mut cmd_rx, &event_tx,
                    &state, is_bootstrap, &mut current_peer_id,
                ).await
            }
            Err(e) => {
                // Self-connection via anycast — another machine on the
                // anycast address will answer the next attempt. Retry a
                // few times immediately, then back off (we may be the
                // only machine in this region).
                if e.to_string().contains("self-connection") {
                    self_hits += 1;
                    if self_hits <= 3 {
                        info!(%connect_target, self_hits,
                            "native relay: self via anycast — redial");
                        continue 'reconnect;
                    }
                    // Backed off self-hits — use normal backoff.
                    consecutive_failures = self_hits;
                }
                consecutive_failures += 1;
                if consecutive_failures <= 3 {
                    warn!(%connect_target, attempt = consecutive_failures,
                        "native relay: connect failed, will retry: {e}");
                } else if consecutive_failures % 30 == 0 {
                    warn!(%connect_target, attempt = consecutive_failures,
                        "native relay: still failing to connect: {e}");
                }
                if !backoff_drain_native(&mut cmd_rx, consecutive_failures).await {
                    break;
                }
                // Check if we should still be trying to reach this peer.
                // Use last_known_peer_id — current_peer_id may be None if we never connected.
                let retry_pid = last_known_peer_id.as_ref().or(current_peer_id.as_ref()).cloned();
                // Bootstrap peers also stop retrying once we know the peer_id and VDF is stale.
                // Without this, bootstrap tasks retry forever even after the target is dead
                // (was the root cause of the attempt=925350 connection storm).
                // Exception: if we've NEVER successfully connected (retry_pid is None),
                // a bootstrap peer keeps trying — it might just be temporarily down.
                let never_connected_bootstrap = is_bootstrap && retry_pid.is_none();
                if !never_connected_bootstrap
                    && !should_keep_retrying(&state, &retry_pid, &connect_target).await
                {
                    info!(%connect_target, peer_id = ?retry_pid,
                        "native relay: peer dead or stale, stopping retries");
                    break;
                }
                continue 'reconnect;
            }
        };

        // Clean up relay from the map (task inserted it after HELLO).
        // Sends Disconnected (transient) — SPIRAL slot is PRESERVED.
        if let Some(ref pid) = current_peer_id {
            let mut st = state.write().await;
            if st.federation.relays.remove(pid).is_some() {
                drop(st);
                let _ = event_tx.send(RelayEvent::Disconnected {
                    remote_host: pid.clone(),
                });
            }
        }
        // Carry identity forward for should_keep_retrying and PeerGone.
        if current_peer_id.is_some() {
            last_known_peer_id = current_peer_id.take();
        } else {
            current_peer_id = None;
        }

        // Only reset failure counter if the connection lived long enough to be
        // productive. Self-connections (anycast routes to self) succeed at the
        // WebSocket level but die immediately at Hello exchange. Without this
        // guard, failures resets to 0 on every self-connect → backoff never
        // escalates → rapid reconnect churn.
        let connection_lived = connected_at.elapsed() > std::time::Duration::from_secs(10);

        match outcome {
            NativeLoopOutcome::Shutdown => break,
            NativeLoopOutcome::Reconnect => {
                if connection_lived {
                    consecutive_failures = 0;
                } else {
                    consecutive_failures += 1;
                }
                info!(%connect_target, attempt = consecutive_failures,
                    lived_secs = connected_at.elapsed().as_secs(),
                    "native relay: connection lost, will reconnect");
                if !backoff_drain_native(&mut cmd_rx, consecutive_failures).await {
                    break;
                }
                // Check if we should still be trying to reach this peer.
                // current_peer_id was moved to last_known_peer_id above.
                // In Reconnect: we just had a successful connection, so last_known_peer_id
                // is always Some. Check VDF staleness for all peer types (bootstrap too).
                if !should_keep_retrying(&state, &last_known_peer_id, &connect_target).await {
                    info!(%connect_target, peer_id = ?last_known_peer_id,
                        "native relay: peer dead or stale, stopping retries");
                    break;
                }
            }
        }
    }

    // Final cleanup: relay task permanently exiting.
    // Send PeerGone (not Disconnected) — this triggers SPIRAL slot release.
    {
        let peer_id_for_gone = last_known_peer_id.or(current_peer_id);
        if let Some(ref pid) = peer_id_for_gone {
            let mut st = state.write().await;
            st.federation.managed_peers.remove(pid);
            st.federation.relays.remove(pid);
            drop(st);
            let _ = event_tx.send(RelayEvent::PeerGone {
                remote_host: pid.clone(),
            });
        }
    }

    // Decrement dial count and remove from pending_dials.
    {
        let mut st = state.write().await;
        st.federation.active_dial_count = st.federation.active_dial_count.saturating_sub(1);
        st.federation.pending_dials.remove(&connect_target);
    }
}

/// Inner WebSocket loop — generic over the underlying stream type.
///
/// After HELLO exchange, inserts itself into `federation.relays` keyed by the
/// remote's `peer_id`. Sets `current_peer_id` so the caller can clean up on exit.
///
/// The `cmd_tx` clone goes into the RelayHandle; `cmd_rx` is used for the
/// bidirectional message loop.
async fn native_ws_loop<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    connect_target: &str,
    cmd_tx: &mpsc::UnboundedSender<RelayCommand>,
    cmd_rx: &mut mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: &mpsc::UnboundedSender<RelayEvent>,
    state: &Arc<tokio::sync::RwLock<super::server::ServerState>>,
    is_bootstrap: bool,
    current_peer_id: &mut Option<String>,
) -> NativeLoopOutcome {
    use futures::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message as TungsMsg;

    let (mut ws_tx, mut ws_rx) = futures::StreamExt::split(ws);

    // ── Hello exchange ──────────────────────────────────────────────────

    // Send our Hello.
    let our_hello = {
        let mut st = state.write().await;
        build_wire_hello(&mut st)
    };
    let hello_msg = MeshMessage::Hello(our_hello);
    let hello_json = match hello_msg.to_json() {
        Ok(j) => j,
        Err(e) => {
            warn!(%connect_target, "native relay: failed to serialize Hello: {e}");
            return NativeLoopOutcome::Reconnect;
        }
    };
    if ws_tx.send(TungsMsg::Text(hello_json.into())).await.is_err() {
        warn!(%connect_target, "native relay: failed to send Hello");
        return NativeLoopOutcome::Reconnect;
    }

    // Receive their Hello (30s timeout).
    //
    // Non-Hello messages (PEERS, LatencyHave, etc.) may arrive first when
    // the remote's federation loop announces OTHER peers through our relay
    // handle before processing our HELLO. Skip them and keep waiting.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let remote_hello = loop {
        match tokio::time::timeout_at(deadline, futures::StreamExt::next(&mut ws_rx)).await {
            Ok(Some(Ok(TungsMsg::Text(text)))) => match MeshMessage::from_json(&text) {
                Ok(MeshMessage::Hello(hello)) => break hello,
                Ok(_other) => {
                    // Not a Hello — skip. We don't know the remote's peer_id yet
                    // so we can't properly dispatch. These messages are redundant
                    // anyway (we'll get the same data after Hello exchange).
                    tracing::debug!(
                        %connect_target,
                        "native relay: skipping pre-Hello message"
                    );
                    continue;
                }
                Err(e) => {
                    warn!(%connect_target, "native relay: invalid message while waiting for Hello: {e}");
                    return NativeLoopOutcome::Reconnect;
                }
            },
            Ok(Some(Ok(TungsMsg::Close(_)))) | Ok(None) => {
                warn!(%connect_target, "native relay: connection closed before Hello");
                return NativeLoopOutcome::Reconnect;
            }
            Ok(Some(Err(e))) => {
                warn!(%connect_target, "native relay: read error waiting for Hello: {e}");
                return NativeLoopOutcome::Reconnect;
            }
            Err(_) => {
                warn!(%connect_target, "native relay: no Hello received within timeout");
                return NativeLoopOutcome::Reconnect;
            }
            _ => { continue; } // Binary, Ping, Pong — skip
        }
    };

    let remote_peer_id = remote_hello.peer_id.clone();
    let remote_node_name = if remote_hello.node_name.is_empty() {
        super::server::derive_node_name(&remote_hello.server_name)
    } else {
        remote_hello.node_name.clone()
    };

    // remote_mesh_key = peer_id — matches known_peers key exactly.
    // Previous bug: was `site_name/node_name` which never matched known_peers,
    // causing VDF proof updates to be silently dropped.
    let remote_mesh_key: Option<String> = Some(remote_peer_id.clone());

    info!(
        %connect_target,
        peer_id = %remote_peer_id,
        node_name = %remote_node_name,
        server_name = %remote_hello.server_name,
        "native relay: received Hello"
    );

    // ── Self-connection detection ───────────────────────────────────────
    //
    // If the remote peer_id matches ours, we dialed anycast and reached
    // ourselves. This is a fallback — transparent self-rejection at the TCP
    // level (via `?from=` in the URL) should have caught this earlier.
    //
    // The inbound handler may also send a Redirect with known peers —
    // drain the buffer to pick it up so we can discover the mesh even
    // from a self-connection.
    {
        let st = state.read().await;
        if remote_peer_id == st.lens.peer_id {
            info!(
                %connect_target,
                peer_id = %remote_peer_id,
                "native relay: self-connection detected via HELLO \
                 (transparent self should have caught this at TCP level)"
            );
            drop(st);

            // Drain buffer — inbound side may have sent a Redirect with
            // known peers right after the Hello.
            if let Ok(Some(Ok(TungsMsg::Text(text)))) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                futures::StreamExt::next(&mut ws_rx),
            ).await {
                if let Ok(msg) = MeshMessage::from_json(&text) {
                    let _ = dispatch_mesh_message(
                        msg,
                        &remote_peer_id,
                        None,
                        &remote_mesh_key,
                        event_tx,
                    );
                }
            }

            return NativeLoopOutcome::Reconnect;
        }
    }

    // ── Insert relay handle keyed by peer_id ────────────────────────────
    //
    // Inbound (mesh.rs) and outbound (us) connections to the same peer
    // coexist — they're a bidirectional pair, not duplicates. If there's
    // already a relay for this peer_id, we keep running as a receive-only
    // connection: dispatching incoming messages but not claiming the map
    // entry. The existing relay keeps the map entry (for sending commands).
    //
    // Only set current_peer_id if we OWN the map entry — cleanup at the
    // caller removes the entry and sends Disconnected only for owned entries.
    {
        let mut st = state.write().await;
        if st.federation.relays.contains_key(&remote_peer_id) {
            info!(
                %connect_target,
                peer_id = %remote_peer_id,
                "native relay: inbound relay exists — running as receive-only"
            );
            // Don't insert. Don't set current_peer_id.
            // Our cmd_rx stays open (cmd_tx held by caller) so the
            // select loop works fine — just no commands arrive.
        } else {
            st.federation.relays.insert(
                remote_peer_id.clone(),
                RelayHandle {
                    outgoing_tx: cmd_tx.clone(),
                    node_name: remote_node_name.clone(),
                    connect_target: connect_target.to_string(),
                    channels: HashMap::new(),
                    mesh_connected: true,
                    is_bootstrap,
                    last_rtt_ms: None,
                },
            );
            *current_peer_id = Some(remote_peer_id.clone());
            // Track in managed_peers — survives reconnect cycles.
            // evict_dead_peers() skips managed peers; only PeerGone clears this.
            st.federation.managed_peers.insert(remote_peer_id.clone());
        }
        // NOTE: do NOT remove from pending_dials here. The entry must persist
        // for the entire relay_task_native lifetime. Otherwise, when the WS drops
        // and the relay is removed from the map, gossip-driven spawns see neither
        // relays nor pending_dials containing this peer — spawning a duplicate
        // relay task while the original is still in its reconnect backoff loop.
        // The entry is removed on task exit (relay_task_native cleanup).
    }

    // Dispatch their Hello to the event processor — relay handle exists,
    // so the event processor can send responses (Peers, LatencyHave, etc.)
    // back through the relay's cmd_tx.
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_peer_id,
        None, // no peer_addr for WebSocket
        &remote_mesh_key,
        event_tx,
    );

    // ── Bidirectional message loop ──────────────────────────────────────

    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    keepalive.tick().await; // skip first immediate tick
    let mut last_ping_sent = tokio::time::Instant::now();
    // PoL challenge timing — nonce → when we sent it.
    let mut pol_pending: HashMap<u64, std::time::Instant> = HashMap::new();

    loop {
        tokio::select! {
            // Incoming WebSocket messages from remote peer.
            ws_msg = futures::StreamExt::next(&mut ws_rx) => {
                match ws_msg {
                    Some(Ok(TungsMsg::Text(text))) => {
                        match MeshMessage::from_json(&text) {
                            Ok(MeshMessage::PolChallenge { nonce }) => {
                                // Fast path — respond immediately, no dispatch.
                                let response = MeshMessage::PolResponse { nonce };
                                if let Ok(json) = response.to_json() {
                                    if ws_tx.send(TungsMsg::Text(json.into())).await.is_err() {
                                        return NativeLoopOutcome::Reconnect;
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
                                // Redirect = informational peer list. Dispatch
                                // for discovery but do NOT kill the connection.
                                // The remote may close the WS after sending
                                // Redirect — that triggers Reconnect naturally
                                // via the Close/None branch below.
                                if matches!(&msg, MeshMessage::Redirect { .. }) {
                                    info!(
                                        %connect_target,
                                        peer_id = %remote_peer_id,
                                        "native relay: received redirect — dispatching peers"
                                    );
                                }
                                let _ = dispatch_mesh_message(
                                    msg,
                                    &remote_peer_id,
                                    None,
                                    &remote_mesh_key,
                                    event_tx,
                                );

                                // Shadow promotion: if we don't own the map
                                // entry and it's gone (inbound died), claim it.
                                if current_peer_id.is_none() {
                                    let mut st = state.write().await;
                                    if !st.federation.relays.contains_key(&remote_peer_id) {
                                        info!(
                                            %connect_target,
                                            peer_id = %remote_peer_id,
                                            "native relay: promoting shadow to primary"
                                        );
                                        st.federation.relays.insert(
                                            remote_peer_id.clone(),
                                            RelayHandle {
                                                outgoing_tx: cmd_tx.clone(),
                                                node_name: remote_node_name.clone(),
                                                connect_target: connect_target.to_string(),
                                                channels: HashMap::new(),
                                                mesh_connected: true,
                                                is_bootstrap,
                                                last_rtt_ms: None,
                                            },
                                        );
                                        *current_peer_id = Some(remote_peer_id.clone());
                                        st.federation.managed_peers.insert(remote_peer_id.clone());
                                    }
                                }
                            }
                            Err(e) => {
                                let preview: String = text.chars().take(200).collect();
                                warn!(
                                    %connect_target,
                                    peer_id = %remote_peer_id,
                                    error = %e,
                                    len = text.len(),
                                    preview = %preview,
                                    "native relay: failed to parse message"
                                );
                            }
                        }
                    }
                    Some(Ok(TungsMsg::Pong(_))) => {
                        // Measure RTT from Ping→Pong round-trip.
                        let rtt_ms = last_ping_sent.elapsed().as_secs_f64() * 1000.0;
                        let _ = event_tx.send(RelayEvent::LatencyMeasured {
                            remote_host: remote_peer_id.clone(),
                            rtt_ms,
                            mesh_key: remote_mesh_key.clone(),
                        });
                    }
                    Some(Ok(TungsMsg::Close(_))) | None => {
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay: connection closed by remote");
                        return NativeLoopOutcome::Reconnect;
                    }
                    Some(Err(e)) => {
                        warn!(%connect_target, peer_id = %remote_peer_id,
                            error = %e, "native relay: read error");
                        return NativeLoopOutcome::Reconnect;
                    }
                    _ => {} // Binary, Ping (tungstenite auto-responds)
                }
            }

            // Outgoing commands from the server event processor.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::SendMesh(mesh_msg)) => {
                        // Record timing for outgoing PoL challenges.
                        if let MeshMessage::PolChallenge { nonce } = &mesh_msg {
                            pol_pending.insert(*nonce, std::time::Instant::now());
                        }
                        if let Ok(json) = mesh_msg.to_json() {
                            if ws_tx.send(TungsMsg::Text(json.into())).await.is_err() {
                                return NativeLoopOutcome::Reconnect;
                            }
                        }
                    }
                    Some(RelayCommand::MeshHello { json: _ }) => {
                        // Re-send our Hello (e.g., VDF state change).
                        let hello = {
                            let mut st = state.write().await;
                            build_wire_hello(&mut st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(j) = msg.to_json() {
                            if ws_tx.send(TungsMsg::Text(j.into())).await.is_err() {
                                return NativeLoopOutcome::Reconnect;
                            }
                        }
                    }
                    Some(RelayCommand::Shutdown) => {
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay: shutdown requested");
                        let _ = ws_tx.send(TungsMsg::Close(None)).await;
                        return NativeLoopOutcome::Shutdown;
                    }
                    Some(RelayCommand::Reconnect) => {
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay: reconnect requested");
                        let _ = ws_tx.send(TungsMsg::Close(None)).await;
                        return NativeLoopOutcome::Reconnect;
                    }
                    Some(_) => {
                        // Channel ops (JoinChannel, Privmsg, etc.) — not
                        // supported in native mesh mode.
                    }
                    None => {
                        // Command channel closed — relay handle removed.
                        return NativeLoopOutcome::Shutdown;
                    }
                }
            }

            // Periodic keepalive ping (also measures RTT on Pong).
            _ = keepalive.tick() => {
                last_ping_sent = tokio::time::Instant::now();
                if ws_tx.send(TungsMsg::Ping(vec![].into())).await.is_err() {
                    return NativeLoopOutcome::Reconnect;
                }
            }
        }
    }
}

/// Inner raw TCP loop — JSON-lines over a switchboard connection.
///
/// Equivalent to `native_ws_loop` but for raw TCP connections via the
/// switchboard half-dial. After the half-dial PeerReady exchange, the TCP
/// stream continues with newline-delimited JSON MeshMessages.
///
/// No WebSocket framing, no HTTP upgrade — just `{...}\n` lines.
async fn native_raw_loop(
    mut reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    connect_target: &str,
    cmd_tx: &mpsc::UnboundedSender<RelayCommand>,
    cmd_rx: &mut mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: &mpsc::UnboundedSender<RelayEvent>,
    state: &Arc<tokio::sync::RwLock<super::server::ServerState>>,
    is_bootstrap: bool,
    current_peer_id: &mut Option<String>,
) -> NativeLoopOutcome {
    use super::wire;

    // ── Hello exchange (length-prefixed frames) ─────────────────────────

    // Send our Hello.
    let our_hello = {
        let mut st = state.write().await;
        build_wire_hello(&mut st)
    };
    let hello_msg = MeshMessage::Hello(our_hello);
    let hello_json = match hello_msg.to_json() {
        Ok(j) => j,
        Err(e) => {
            warn!(%connect_target, "native relay (raw): failed to serialize Hello: {e}");
            return NativeLoopOutcome::Reconnect;
        }
    };
    if wire::write_mesh_frame(&mut writer, hello_json.as_bytes()).await.is_err() {
        warn!(%connect_target, "native relay (raw): failed to send Hello");
        return NativeLoopOutcome::Reconnect;
    }

    // Receive their Hello (30s timeout).
    let remote_hello = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wire::read_mesh_frame(&mut reader),
    )
    .await
    {
        Ok(Ok(Some(text))) => match MeshMessage::from_json(&text) {
            Ok(MeshMessage::Hello(hello)) => hello,
            Ok(other) => {
                warn!(%connect_target, ?other, "native relay (raw): first message must be Hello");
                return NativeLoopOutcome::Reconnect;
            }
            Err(e) => {
                warn!(%connect_target, "native relay (raw): invalid first message: {e}");
                return NativeLoopOutcome::Reconnect;
            }
        },
        _ => {
            warn!(%connect_target, "native relay (raw): no Hello received within timeout");
            return NativeLoopOutcome::Reconnect;
        }
    };

    let remote_peer_id = remote_hello.peer_id.clone();
    let remote_node_name = if remote_hello.node_name.is_empty() {
        super::server::derive_node_name(&remote_hello.server_name)
    } else {
        remote_hello.node_name.clone()
    };

    let remote_mesh_key: Option<String> = Some(remote_peer_id.clone());

    info!(
        %connect_target,
        peer_id = %remote_peer_id,
        node_name = %remote_node_name,
        server_name = %remote_hello.server_name,
        "native relay (raw): received Hello"
    );

    // ── Self-connection detection ───────────────────────────────────────
    //
    // Transparent self-rejection at the switchboard level should have caught
    // this already (peer_id in peeked PeerRequest → drop → RST). This is
    // the fallback for when the peek missed it.
    {
        let st = state.read().await;
        if remote_peer_id == st.lens.peer_id {
            info!(
                %connect_target,
                peer_id = %remote_peer_id,
                "native relay (raw): self-connection detected via HELLO \
                 (transparent self should have caught this at TCP level)"
            );
            drop(st);

            // Drain buffer — inbound side may have sent a Redirect.
            if let Ok(Ok(Some(text))) = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                wire::read_mesh_frame(&mut reader),
            ).await {
                if let Ok(msg) = MeshMessage::from_json(&text) {
                    let _ = dispatch_mesh_message(
                        msg,
                        &remote_peer_id,
                        None,
                        &remote_mesh_key,
                        event_tx,
                    );
                }
            }

            return NativeLoopOutcome::Reconnect;
        }
    }

    // ── Insert relay handle keyed by peer_id ────────────────────────────
    //
    // Same coexistence logic as the WS path: if there's already a relay
    // for this peer_id (inbound), we run as receive-only shadow.
    {
        let mut st = state.write().await;
        if st.federation.relays.contains_key(&remote_peer_id) {
            info!(
                %connect_target,
                peer_id = %remote_peer_id,
                "native relay (raw): inbound relay exists — running as receive-only"
            );
        } else {
            st.federation.relays.insert(
                remote_peer_id.clone(),
                RelayHandle {
                    outgoing_tx: cmd_tx.clone(),
                    node_name: remote_node_name.clone(),
                    connect_target: connect_target.to_string(),
                    channels: HashMap::new(),
                    mesh_connected: true,
                    is_bootstrap,
                    last_rtt_ms: None,
                },
            );
            *current_peer_id = Some(remote_peer_id.clone());
            st.federation.managed_peers.insert(remote_peer_id.clone());
        }
    }

    // Dispatch their Hello to the event processor.
    dispatch_mesh_message(
        MeshMessage::Hello(remote_hello),
        &remote_peer_id,
        None,
        &remote_mesh_key,
        event_tx,
    );

    // ── Bidirectional message loop (length-prefixed frames) ─────────────
    //
    // CRITICAL: read_exact is NOT cancellation-safe. If tokio::select! drops
    // a read_mesh_frame future mid-flight (because a cmd or timer fired),
    // any bytes already consumed by read_exact are LOST — desynchronising
    // the stream. We solve this by running all reads in a dedicated task
    // that never gets cancelled, sending complete frames over a channel.
    // Channel recv() IS cancellation-safe.

    // Spawn reader task — owns the BufReader, never cancelled mid-read.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::unbounded_channel::<Result<Option<String>, String>>();
    let reader_task = tokio::spawn(async move {
        loop {
            match wire::read_mesh_frame(&mut reader).await {
                Ok(frame) => {
                    if frame_tx.send(Ok(frame)).is_err() { break; }
                }
                Err(e) => {
                    let _ = frame_tx.send(Err(e.to_string()));
                    break;
                }
            }
        }
    });

    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    keepalive.tick().await; // skip first immediate tick
    // PoL challenge timing — nonce → when we sent it.
    let mut pol_pending: HashMap<u64, std::time::Instant> = HashMap::new();

    let outcome = loop {
        tokio::select! {
            // Receive complete frames from the reader task (cancel-safe).
            frame = frame_rx.recv() => {
                match frame {
                    Some(Err(e)) => {
                        warn!(%connect_target, peer_id = %remote_peer_id,
                            error = %e, "native relay (raw): read error");
                        break NativeLoopOutcome::Reconnect;
                    }
                    Some(Ok(None)) => {} // keepalive
                    Some(Ok(Some(text))) => {
                        match MeshMessage::from_json(&text) {
                            Ok(MeshMessage::PolChallenge { nonce }) => {
                                // Fast path — respond immediately, no dispatch.
                                let response = MeshMessage::PolResponse { nonce };
                                if let Ok(json) = response.to_json() {
                                    if wire::write_mesh_frame(&mut writer, json.as_bytes()).await.is_err() {
                                        break NativeLoopOutcome::Reconnect;
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
                                if matches!(&msg, MeshMessage::Redirect { .. }) {
                                    info!(
                                        %connect_target,
                                        peer_id = %remote_peer_id,
                                        "native relay (raw): received redirect — dispatching peers"
                                    );
                                }
                                let _ = dispatch_mesh_message(
                                    msg,
                                    &remote_peer_id,
                                    None,
                                    &remote_mesh_key,
                                    event_tx,
                                );

                                // Shadow promotion (same as WS path).
                                if current_peer_id.is_none() {
                                    let mut st = state.write().await;
                                    if !st.federation.relays.contains_key(&remote_peer_id) {
                                        info!(
                                            %connect_target,
                                            peer_id = %remote_peer_id,
                                            "native relay (raw): promoting shadow to primary"
                                        );
                                        st.federation.relays.insert(
                                            remote_peer_id.clone(),
                                            RelayHandle {
                                                outgoing_tx: cmd_tx.clone(),
                                                node_name: remote_node_name.clone(),
                                                connect_target: connect_target.to_string(),
                                                channels: HashMap::new(),
                                                mesh_connected: true,
                                                is_bootstrap,
                                                last_rtt_ms: None,
                                            },
                                        );
                                        *current_peer_id = Some(remote_peer_id.clone());
                                        st.federation.managed_peers.insert(remote_peer_id.clone());
                                    }
                                }
                            }
                            Err(e) => {
                                let preview: String = text.chars().take(200).collect();
                                warn!(
                                    %connect_target,
                                    peer_id = %remote_peer_id,
                                    error = %e,
                                    len = text.len(),
                                    preview = %preview,
                                    "native relay (raw): failed to parse message"
                                );
                            }
                        }
                    }
                    None => {
                        // Reader task exited without sending an error.
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay (raw): reader task closed");
                        break NativeLoopOutcome::Reconnect;
                    }
                }
            }

            // Outgoing commands from the server event processor.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::SendMesh(mesh_msg)) => {
                        // Record timing for outgoing PoL challenges.
                        if let MeshMessage::PolChallenge { nonce } = &mesh_msg {
                            pol_pending.insert(*nonce, std::time::Instant::now());
                        }
                        if let Ok(json) = mesh_msg.to_json() {
                            if wire::write_mesh_frame(&mut writer, json.as_bytes()).await.is_err() {
                                break NativeLoopOutcome::Reconnect;
                            }
                        }
                    }
                    Some(RelayCommand::MeshHello { json: _ }) => {
                        let hello = {
                            let mut st = state.write().await;
                            build_wire_hello(&mut st)
                        };
                        let msg = MeshMessage::Hello(hello);
                        if let Ok(j) = msg.to_json() {
                            if wire::write_mesh_frame(&mut writer, j.as_bytes()).await.is_err() {
                                break NativeLoopOutcome::Reconnect;
                            }
                        }
                    }
                    Some(RelayCommand::Shutdown) => {
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay (raw): shutdown requested");
                        break NativeLoopOutcome::Shutdown;
                    }
                    Some(RelayCommand::Reconnect) => {
                        info!(%connect_target, peer_id = %remote_peer_id,
                            "native relay (raw): reconnect requested");
                        break NativeLoopOutcome::Reconnect;
                    }
                    Some(_) => {}
                    None => {
                        break NativeLoopOutcome::Shutdown;
                    }
                }
            }

            // Keepalive — zero-length frame.
            _ = keepalive.tick() => {
                if wire::write_mesh_keepalive(&mut writer).await.is_err() {
                    break NativeLoopOutcome::Reconnect;
                }
            }
        }
    };

    // Stop the reader task — it may be blocked on read_mesh_frame.
    reader_task.abort();

    outcome
}

/// Backoff drain for the native relay task.
///
/// Waits with exponential backoff while consuming commands. Returns `true` to
/// continue reconnecting, `false` to exit (Shutdown or channel closed).
async fn backoff_drain_native(
    cmd_rx: &mut mpsc::UnboundedReceiver<RelayCommand>,
    failures: u32,
) -> bool {
    let secs = (2u64.pow(failures)).min(60);
    let backoff = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(backoff);
    loop {
        tokio::select! {
            _ = &mut backoff => return true,
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::Shutdown) => return false,
                    Some(RelayCommand::Reconnect) => {} // Already reconnecting.
                    Some(_) => {} // Drop other commands during backoff.
                    None => return false, // Channel closed — relay handle removed.
                }
            }
        }
    }
}

/// Check if a relay task should keep retrying or if the peer has been evicted.
///
/// Returns `true` if the peer is still known to the mesh AND its VDF is fresh.
/// Returns `false` if the peer has been removed or its VDF has been silent
/// for 60 seconds (genuinely dead — relay task should exit, sending PeerGone).
async fn should_keep_retrying(
    state: &Arc<tokio::sync::RwLock<super::server::ServerState>>,
    current_peer_id: &Option<String>,
    connect_target: &str,
) -> bool {
    let st = state.read().await;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // If we know the peer_id (from a previous successful HELLO), check
    // if it's still in known_peers or is a SPIRAL neighbor.
    if let Some(pid) = current_peer_id {
        if let Some(peer) = st.mesh.known_peers.get(pid) {
            // VDF staleness check: if the peer's VDF hasn't advanced in 60s,
            // they're dead. Give up retrying — PeerGone will release the slot.
            let fresh_at = if peer.last_vdf_advance > 0 {
                peer.last_vdf_advance
            } else {
                peer.last_seen
            };
            if now_secs.saturating_sub(fresh_at) >= 60 {
                info!(
                    peer_id = %pid,
                    vdf_stale_secs = now_secs.saturating_sub(fresh_at),
                    "should_keep_retrying: VDF stale 60s, giving up"
                );
                return false;
            }
            return true;
        }
        if st.mesh.spiral.is_neighbor(pid) {
            return true;
        }
        // Peer has been evicted from both known_peers and SPIRAL.
        return false;
    }

    // No peer_id yet (never completed HELLO). Check if connect_target
    // matches any known peer's node_name.
    let target_known = st.mesh.known_peers.values()
        .any(|p| p.node_name == connect_target);
    target_known
}

/// Per-channel state within the relay task.
struct TaskChannel {
    local_channel: String,
    joined: bool,
    pending: Vec<RelayCommand>,
}

/// Wait with exponential backoff while draining commands from the relay channel.
///
/// Returns `true` to continue reconnecting, `false` to exit (Shutdown or
/// channel closed — the relay handle was removed from state).
async fn backoff_drain(
    cmd_rx: &mut mpsc::UnboundedReceiver<RelayCommand>,
    saved_mesh_hello: &mut Option<String>,
    failures: u32,
) -> bool {
    let secs = (2u64.pow(failures)).min(60);
    let backoff = tokio::time::sleep(std::time::Duration::from_secs(secs));
    tokio::pin!(backoff);
    loop {
        tokio::select! {
            _ = &mut backoff => return true,
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(RelayCommand::Shutdown) => return false,
                    Some(RelayCommand::Reconnect) => {} // Already reconnecting.
                    Some(RelayCommand::MeshHello { json }) => {
                        *saved_mesh_hello = Some(json);
                    }
                    Some(_) => {} // Drop other commands during backoff.
                    None => return false, // Channel closed — relay handle removed.
                }
            }
        }
    }
}

/// The relay task — connects to a remote Lagoon server, registers, and
/// relays messages bidirectionally for multiple channels using FRELAY.
///
/// `relay_key` is the node_name used as identity in events.
/// `connect_target` is the hostname/address for `transport::connect()`.
async fn relay_task(
    relay_key: String,
    connect_target: String,
    mut cmd_rx: mpsc::UnboundedReceiver<RelayCommand>,
    event_tx: mpsc::UnboundedSender<RelayEvent>,
    transport_config: Arc<TransportConfig>,
) {
    let node = &*super::server::NODE_NAME;
    let our_name = &*SERVER_NAME;
    let base_relay_nick = format!("{node}~relay");
    let our_suffix = format!("@{our_name}");
    // relay_key is used in events; connect_target is used for transport.
    // Alias for backward compat with log and event field names.
    let remote_host = relay_key;

    let mut consecutive_failures: u32 = 0;
    let mut saved_mesh_hello: Option<String> = None;
    // Peer identity — set once MESH HELLO is received. Threaded into
    // subsequent events so handlers can do O(1) lookup by mesh_key.
    let mut remote_mesh_key: Option<String> = None;
    // When true, don't reset consecutive_failures on next successful connect.
    let mut self_connect_backoff = false;

    'reconnect: loop {
    let mut relay_nick = base_relay_nick.clone();

    let (stream, relay_peer_addr) = match transport::connect(&connect_target, &transport_config).await {
        Ok(r) => {
            if self_connect_backoff {
                self_connect_backoff = false;
                // Don't reset — let backoff escalate across self-connections.
            } else {
                consecutive_failures = 0;
            }
            (r.stream, r.peer_addr)
        }
        Err(e) => {
            consecutive_failures += 1;
            // Log at warn for first few failures, then demote to debug to
            // avoid log spam for persistently-unreachable peers.
            if consecutive_failures <= 3 {
                warn!(%remote_host, %connect_target, attempt = consecutive_failures,
                    "federation: connect failed, will retry: {e}");
            } else if consecutive_failures % 30 == 0 {
                warn!(%remote_host, %connect_target, attempt = consecutive_failures,
                    "federation: still failing to connect: {e}");
            }
            if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
                return;
            }
            continue 'reconnect;
        }
    };

    info!(%remote_host, %connect_target, "federation: connected");
    let mut framed = Framed::new(stream, IrcCodec::default());

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
        consecutive_failures += 1;
        warn!(remote_host, attempt = consecutive_failures,
            "federation: registration send failed, will retry");
        if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
            return;
        }
        continue 'reconnect;
    }

    info!(remote_host, "federation: registration sent, waiting for 001");
    let mut registered = false;
    // remote_channel → per-channel task state.
    let mut channels: HashMap<String, TaskChannel> = HashMap::new();
    // Commands received before registration completes.
    let mut pre_reg_cmds: Vec<RelayCommand> = Vec::new();

    // Re-queue saved MESH HELLO so it's sent after registration on reconnection.
    if let Some(ref json) = saved_mesh_hello {
        pre_reg_cmds.push(RelayCommand::MeshHello { json: json.clone() });
    }

    // Keepalive: send PING every 30s to prevent proxy idle timeouts (Cloudflare: 60s).
    // Also used for PONG-based liveness detection (safety net for WebSocket paths
    // where TCP keepalive can't be set).
    let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(30));
    // Skip the first immediate tick.
    keepalive.tick().await;
    let mut last_pong = tokio::time::Instant::now();
    let mut last_ping_sent = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = keepalive.tick() => {
                if registered {
                    // 3 missed PINGs (30s × 3 = 90s) without a PONG → dead.
                    // TCP keepalive catches most cases in ~8s; this is the
                    // safety net for WebSocket connections and app-level hangs.
                    if last_pong.elapsed() > std::time::Duration::from_secs(90) {
                        warn!(remote_host, elapsed = ?last_pong.elapsed(),
                            "federation: peer unresponsive (no PONG), disconnecting");
                        break;
                    }
                    last_ping_sent = tokio::time::Instant::now();
                    let ping = Message {
                        prefix: None,
                        command: "PING".into(),
                        params: vec![our_name.to_string()],
                    };
                    if framed.send(ping).await.is_err() {
                        break;
                    }
                }
            }
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
                        // Process any queued commands.
                        for cmd in pre_reg_cmds.drain(..) {
                            match cmd {
                                RelayCommand::JoinChannel { remote_channel, local_channel } => {
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
                                RelayCommand::MeshHello { json } => {
                                    let mesh_msg = Message {
                                        prefix: None,
                                        command: "MESH".into(),
                                        params: vec!["HELLO".into(), json],
                                    };
                                    if framed.send(mesh_msg).await.is_err() {
                                        break;
                                    }
                                }
                                _ => {}
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

                    "PONG" => {
                        last_pong = tokio::time::Instant::now();
                        // PoLP: measure IRC-layer RTT from PING→PONG round-trip.
                        let rtt_ms = last_ping_sent.elapsed().as_secs_f64() * 1000.0;
                        info!(remote_host, rtt_ms, "polp: measured RTT");
                        let _ = event_tx.send(RelayEvent::LatencyMeasured {
                            remote_host: remote_host.clone(),
                            rtt_ms,
                            mesh_key: remote_mesh_key.clone(),
                        });
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

                    "MESH" => {
                        // MESH HELLO <json>
                        // MESH PEERS <json>
                        // MESH TOPOLOGY <json>
                        if let Some(sub_cmd) = msg.params.first() {
                            let json = msg.params.get(1).cloned().unwrap_or_default();
                            match sub_cmd.as_str() {
                                "HELLO" => {
                                    if let Ok(hello) = serde_json::from_str::<MeshHelloPayload>(&json) {
                                        // Backfill site_name/node_name for old peers
                                        // that don't send these fields yet.
                                        let site_name = if hello.site_name.is_empty() {
                                            super::server::derive_site_name(&hello.server_name)
                                        } else {
                                            hello.site_name
                                        };
                                        let node_name = if hello.node_name.is_empty() {
                                            super::server::derive_node_name(&hello.server_name)
                                        } else {
                                            hello.node_name
                                        };
                                        // Store mesh_key for this relay so subsequent
                                        // events can carry it (O(1) peer lookup).
                                        let mkey = format!("{site_name}/{node_name}");
                                        remote_mesh_key = Some(mkey);
                                        let _ = event_tx.send(RelayEvent::MeshHello {
                                            remote_host: remote_host.clone(),
                                            peer_id: hello.peer_id,
                                            server_name: hello.server_name,
                                            public_key_hex: hello.public_key_hex,
                                            spiral_index: hello.spiral_index,
                                            vdf_genesis: hello.vdf_genesis,
                                            vdf_hash: hello.vdf_hash,
                                            vdf_step: hello.vdf_step,
                                            yggdrasil_addr: hello.yggdrasil_addr,
                                            site_name,
                                            node_name,
                                            vdf_resonance_credit: hello.vdf_resonance_credit,
                                            vdf_actual_rate_hz: hello.vdf_actual_rate_hz,
                                            vdf_cumulative_credit: hello.vdf_cumulative_credit,
                                            ygg_peer_uri: hello.ygg_peer_uri,
                                            relay_peer_addr,
                                            cvdf_height: hello.cvdf_height,
                                            cvdf_weight: hello.cvdf_weight,
                                            cvdf_tip_hex: hello.cvdf_tip_hex,
                                            cvdf_genesis_hex: hello.cvdf_genesis_hex,
                                            cluster_vdf_work: hello.cluster_vdf_work,
                                            assigned_slot: hello.assigned_slot,
                                            cluster_chain_value: hello.cluster_chain_value,
                                            cluster_chain_epoch_origin: hello.cluster_chain_epoch_origin,
                                            cluster_chain_round: hello.cluster_chain_round,
                                            cluster_chain_work: hello.cluster_chain_work,
                                            cluster_round_seed: hello.cluster_round_seed,
                                        });
                                    } else {
                                        warn!(remote_host, "mesh: invalid HELLO payload");
                                    }
                                }
                                "PEERS" => {
                                    if let Ok(peers) = serde_json::from_str::<Vec<MeshPeerInfo>>(&json) {
                                        let _ = event_tx.send(RelayEvent::MeshPeers {
                                            remote_host: remote_host.clone(),
                                            peers,
                                        });
                                    }
                                }
                                "TOPOLOGY" => {
                                    let _ = event_tx.send(RelayEvent::MeshTopology {
                                        remote_host: remote_host.clone(),
                                        json,
                                    });
                                }
                                "VDFPROOF_REQ" => {
                                    let _ = event_tx.send(RelayEvent::MeshVdfProofReq {
                                        remote_host: remote_host.clone(),
                                    });
                                }
                                "VDFPROOF" => {
                                    let _ = event_tx.send(RelayEvent::MeshVdfProof {
                                        remote_host: remote_host.clone(),
                                        proof_json: json,
                                        mesh_key: remote_mesh_key.clone(),
                                    });
                                }
                                "SYNC" => {
                                    let _ = event_tx.send(RelayEvent::MeshSync {
                                        remote_host: remote_host.clone(),
                                    });
                                }
                                "GOSSIP" => {
                                    let _ = event_tx.send(RelayEvent::GossipReceive {
                                        remote_host: remote_host.clone(),
                                        message_json: json,
                                    });
                                }
                                "GOSSIP_SPORE" => {
                                    let _ = event_tx.send(RelayEvent::GossipSpore {
                                        remote_host: remote_host.clone(),
                                        spore_json: json,
                                    });
                                }
                                "GOSSIP_DIFF" => {
                                    let _ = event_tx.send(RelayEvent::GossipDiff {
                                        remote_host: remote_host.clone(),
                                        messages_json: json,
                                    });
                                }
                                "LATENCY_HAVE" => {
                                    let _ = event_tx.send(RelayEvent::LatencyHaveList {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                "LATENCY_DELTA" => {
                                    let _ = event_tx.send(RelayEvent::LatencyProofDelta {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                "PROFILE_QUERY" => {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                                        if let Some(username) = v.get("username").and_then(|u| u.as_str()) {
                                            let _ = event_tx.send(RelayEvent::ProfileQuery {
                                                remote_host: remote_host.clone(),
                                                username: username.to_string(),
                                            });
                                        }
                                    }
                                }
                                "PROFILE_RESPONSE" => {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                                        let username = v.get("username")
                                            .and_then(|u| u.as_str())
                                            .unwrap_or_default()
                                            .to_string();
                                        let profile = v.get("profile")
                                            .and_then(|p| serde_json::from_value(p.clone()).ok());
                                        let _ = event_tx.send(RelayEvent::ProfileResponse {
                                            remote_host: remote_host.clone(),
                                            username,
                                            profile,
                                        });
                                    }
                                }
                                "PROFILE_HAVE" => {
                                    let _ = event_tx.send(RelayEvent::ProfileHave {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                "PROFILE_DELTA" => {
                                    let _ = event_tx.send(RelayEvent::ProfileDelta {
                                        remote_host: remote_host.clone(),
                                        payload_b64: json,
                                    });
                                }
                                _ => {}
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
                    RelayCommand::Reconnect => {
                        info!(remote_host, "federation: reconnect requested");
                        self_connect_backoff = true; // Escalate backoff across retries
                        let quit = Message {
                            prefix: None,
                            command: "QUIT".into(),
                            params: vec!["Reconnecting".into()],
                        };
                        let _ = framed.send(quit).await;
                        break; // Break inner loop → reconnect loop with backoff
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
                    RelayCommand::MeshHello { json } => {
                        saved_mesh_hello = Some(json.clone());
                        if registered {
                            let mesh_msg = Message {
                                prefix: None,
                                command: "MESH".into(),
                                params: vec!["HELLO".into(), json],
                            };
                            if framed.send(mesh_msg).await.is_err() {
                                break;
                            }
                        } else {
                            pre_reg_cmds.push(RelayCommand::MeshHello { json });
                        }
                    }
                    RelayCommand::SendMesh(mesh_msg) => {
                        if registered {
                            let irc_msg = mesh_message_to_irc(&mesh_msg);
                            if framed.send(irc_msg).await.is_err() {
                                break;
                            }
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

    // Inner loop broke — connection lost. Try to reconnect.
    consecutive_failures += 1;
    info!(remote_host, attempt = consecutive_failures,
        "federation: connection lost, will reconnect");
    if !backoff_drain(&mut cmd_rx, &mut saved_mesh_hello, consecutive_failures).await {
        return;
    }

    } // end 'reconnect loop
}

/// JSON payload for MESH HELLO.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MeshHelloPayload {
    pub peer_id: String,
    pub server_name: String,
    pub public_key_hex: String,
    /// Claimed SPIRAL slot index (None = unclaimed fresh node).
    #[serde(default)]
    pub spiral_index: Option<u64>,
    /// VDF genesis hash (hex-encoded, derived from public key).
    #[serde(default)]
    pub vdf_genesis: Option<String>,
    /// VDF current chain tip hash (hex-encoded).
    #[serde(default)]
    pub vdf_hash: Option<String>,
    /// VDF total steps (cumulative across sessions).
    #[serde(default)]
    pub vdf_step: Option<u64>,
    /// This node's Yggdrasil IPv6 address (None if no Yggdrasil).
    #[serde(default)]
    pub yggdrasil_addr: Option<String>,
    /// Site identity for supernode clustering.
    #[serde(default)]
    pub site_name: String,
    /// Node identity within site.
    #[serde(default)]
    pub node_name: String,
    /// Resonance credit — how precisely this node tracks its target VDF rate [0, 1].
    #[serde(default)]
    pub vdf_resonance_credit: Option<f64>,
    /// Actual measured VDF tick rate (Hz, exponential moving average).
    #[serde(default)]
    pub vdf_actual_rate_hz: Option<f64>,
    /// Rolling resonance credit over last 3 cycles (30s). Used for SPIRAL
    /// slot collision resolution — measures *current* precision.
    #[serde(default)]
    pub vdf_cumulative_credit: Option<f64>,
    /// Yggdrasil peer URI for overlay peering (e.g. `tcp://[200:xxxx::]:9443`).
    #[serde(default)]
    pub ygg_peer_uri: Option<String>,
    /// CVDF cooperative chain height.
    #[serde(default)]
    pub cvdf_height: Option<u64>,
    /// CVDF cooperative chain weight.
    #[serde(default)]
    pub cvdf_weight: Option<u64>,
    /// CVDF chain tip hash (hex-encoded).
    #[serde(default)]
    pub cvdf_tip_hex: Option<String>,
    /// CVDF genesis seed (hex-encoded).
    #[serde(default)]
    pub cvdf_genesis_hex: Option<String>,
    /// Total VDF work of this node's entire connected graph.
    /// Sum of cumulative_credit across all known peers + self.
    /// Used for SPIRAL merge negotiation — cluster with more work wins.
    #[serde(default)]
    pub cluster_vdf_work: Option<f64>,
    /// Concierge slot assignment — first empty slot in sender's topology.
    /// Included when the sender has a claimed SPIRAL slot. Joiner takes it.
    #[serde(default)]
    pub assigned_slot: Option<u64>,
    /// Cluster identity chain value (hex-encoded blake3 hash, current tip).
    #[serde(default)]
    pub cluster_chain_value: Option<String>,
    /// Cluster epoch origin (hex-encoded blake3 hash).
    /// Stable across advances — only changes on merge/adopt.
    /// Same origin → same cluster. Different → merge trigger.
    #[serde(default)]
    pub cluster_chain_epoch_origin: Option<String>,
    /// Cluster identity chain round number.
    #[serde(default)]
    pub cluster_chain_round: Option<u64>,
    /// Cluster chain cumulative work (advance steps across all epochs).
    #[serde(default)]
    pub cluster_chain_work: Option<u64>,
    /// Cluster round seed (hex-encoded [u8; 32]) — the FVDF chain hash used
    /// as the advance seed for the cluster chain. Comes from the cluster's
    /// cooperative VDF; losers adopt it on merge, don't generate their own.
    #[serde(default)]
    pub cluster_round_seed: Option<String>,
}

/// Build a native `wire::HelloPayload` from server state (use inside read lock).
///
/// Public so that the inbound mesh handler (lagoon-web) can send our Hello.
pub fn build_wire_hello(st: &mut super::server::ServerState) -> HelloPayload {
    let hp = build_hello_payload(st);
    HelloPayload {
        peer_id: hp.peer_id,
        server_name: hp.server_name,
        public_key_hex: hp.public_key_hex,
        spiral_index: hp.spiral_index,
        vdf_genesis: hp.vdf_genesis,
        vdf_hash: hp.vdf_hash,
        vdf_step: hp.vdf_step,
        yggdrasil_addr: hp.yggdrasil_addr,
        site_name: hp.site_name,
        node_name: hp.node_name,
        vdf_resonance_credit: hp.vdf_resonance_credit,
        vdf_actual_rate_hz: hp.vdf_actual_rate_hz,
        vdf_cumulative_credit: hp.vdf_cumulative_credit,
        ygg_peer_uri: hp.ygg_peer_uri,
        cvdf_height: hp.cvdf_height,
        cvdf_weight: hp.cvdf_weight,
        cvdf_tip_hex: hp.cvdf_tip_hex,
        cvdf_genesis_hex: hp.cvdf_genesis_hex,
        cluster_vdf_work: hp.cluster_vdf_work,
        assigned_slot: hp.assigned_slot,
        cluster_chain_value: hp.cluster_chain_value,
        cluster_chain_epoch_origin: hp.cluster_chain_epoch_origin,
        cluster_chain_round: hp.cluster_chain_round,
        cluster_chain_work: hp.cluster_chain_work,
        cluster_round_seed: hp.cluster_round_seed,
    }
}

/// VDF tiebreak: ungameable coin flip from VDF chain tips.
///
/// `b3(b3(our_vdf_hash XOR their_vdf_hash))` — both sides compute the same
/// shared value. Bit 0 picks direction: 0 = lower peer_id wins, 1 = higher.
/// peer_id only identifies which side is which; the randomness comes entirely
/// from VDF hashes which are sequential computation outputs (ungameable).
///
/// Falls back to peer_id comparison if either VDF hash is unavailable.
fn vdf_tiebreak_wins(
    our_pid: &str,
    their_pid: &str,
    our_vdf_hash: Option<&[u8]>,
    their_vdf_hash: Option<&[u8]>,
) -> bool {
    if let (Some(ours), Some(theirs)) = (our_vdf_hash, their_vdf_hash) {
        // XOR the two VDF chain tips (pad shorter with zeros).
        let len = ours.len().max(theirs.len());
        let mut xored = vec![0u8; len];
        for (i, b) in ours.iter().enumerate() {
            xored[i] ^= b;
        }
        for (i, b) in theirs.iter().enumerate() {
            xored[i] ^= b;
        }
        // Double-hash: b3(b3(xor))
        let shared = blake3::hash(blake3::hash(&xored).as_bytes());
        // Bit 0 picks direction.
        let lower_wins = shared.as_bytes()[0] & 1 == 0;
        let we_are_lower = our_pid < their_pid;
        return if lower_wins { we_are_lower } else { !we_are_lower };
    }
    // Fallback: no VDF hashes available — raw peer_id comparison.
    our_pid > their_pid
}

/// Evaluate SPIRAL merge protocol when a new peer is encountered.
///
/// When two nodes (or clusters) meet, they negotiate SPIRAL topology:
/// - Compare total VDF work across their entire connected graph
/// - Higher total work wins (peer_id tiebreak if equal)
/// - Winner keeps all SPIRAL slots unchanged
/// - Loser re-slots: remove_peer(self) → claim_position(self) (fills first hole)
///
/// Returns true if our SPIRAL position changed.
fn evaluate_spiral_merge(
    st: &mut super::server::ServerState,
    remote_peer_id: &str,
    remote_spiral_index: Option<u64>,
    _remote_cluster_vdf_work: Option<f64>,
    remote_vdf_cumulative_credit: Option<f64>,
    remote_vdf_hash: Option<&str>,
    already_in_clump: bool,
    remote_assigned_slot: Option<u64>,
    shared_state: SharedState,
) -> bool {
    let our_pid = st.lens.peer_id.clone();
    let our_spiral = st.lens.spiral_index;
    let we_are_claimed = st.mesh.spiral.is_claimed();

    // Extract our VDF hash for tiebreaking.
    let our_vdf_hash_bytes: Option<Vec<u8>> = st.mesh.vdf_state_rx.as_ref()
        .map(|rx| rx.borrow().current_hash.to_vec());
    let their_vdf_hash_bytes: Option<Vec<u8>> = remote_vdf_hash
        .and_then(|h| hex::decode(h).ok());

    let tiebreak = |their_pid: &str| -> bool {
        vdf_tiebreak_wins(
            &our_pid,
            their_pid,
            our_vdf_hash_bytes.as_deref(),
            their_vdf_hash_bytes.as_deref(),
        )
    };

    // ── VDF Race: two unslotted nodes meet ───────────────────────
    // Both sides run the SAME comparison with the SAME inputs.
    // Both independently arrive at the SAME answer.
    // No assignment. No authority. Just math.
    // Genesis requires two witnesses agreeing on the same algorithm.
    //
    // CRITICAL: uses vdf_tiebreak_wins (VDF hash XOR + blake3) as the
    // SOLE determinant. cumulative_credit is a moving target — reading
    // it live introduces asymmetry where both sides think they win
    // (Lean: snapshot_immutability_required). VDF hash chain tips are
    // exchanged in HELLO and immutable. Both sides compute the same XOR,
    // the same blake3, and deterministically agree on the winner.
    if remote_spiral_index.is_none() && !we_are_claimed {
        let we_win = tiebreak(remote_peer_id);

        // Register the remote at their deterministic slot.
        let remote_slot = if we_win { 1u64 } else { 0u64 };
        let our_slot = if we_win { 0u64 } else { 1u64 };

        st.mesh.spiral.add_peer(
            remote_peer_id,
            citadel_topology::Spiral3DIndex::new(remote_slot),
        );
        st.mesh.spiral.claim_specific_position(&our_pid, our_slot);

        info!(
            our_slot,
            remote_slot,
            we_win,
            remote = %remote_peer_id,
            "SPIRAL VDF race: deterministic slot assignment (VDF hash tiebreak)"
        );
        persist_spiral_position(st, our_slot);
        announce_hello_to_all_relays(st);
        update_spiral_neighbors(st);
        dial_missing_spiral_neighbors(st, shared_state);
        st.notify_topology_change();
        return true;
    }

    // Remote is unclaimed but we ARE claimed — nothing to do on our side.
    // Our HELLO carries assigned_slot — they'll take it immediately.
    if remote_spiral_index.is_none() {
        return false;
    }

    let remote_idx = remote_spiral_index.unwrap();

    // Register the remote's SPIRAL position.
    let added = st.mesh.spiral.add_peer(
        remote_peer_id,
        citadel_topology::Spiral3DIndex::new(remote_idx),
    );

    // ── Concierge: unslotted node meets established mesh ─────────
    // Remote is established (has a slot). Two possibilities:
    // 1. They sent assigned_slot → take it immediately. O(1).
    // 2. They didn't → broken concierge. We have no authority to
    //    self-claim. Disconnect. Redial. Anycast gives us a different
    //    concierge that does its job.
    if !we_are_claimed {
        if !added {
            st.mesh.spiral.force_add_peer(
                remote_peer_id,
                citadel_topology::Spiral3DIndex::new(remote_idx),
            );
        }

        if let Some(slot) = remote_assigned_slot {
            // Concierge: remote computed the first empty slot in their topology
            // and told us. Take it. If it's wrong (stale topology, conflict),
            // collision resolution handles it. If it's garbage, disconnect and
            // redial — anycast gives us a different concierge.
            st.mesh.spiral.claim_specific_position(&our_pid, slot);
            info!(
                assigned_slot = slot,
                remote = %remote_peer_id,
                "SPIRAL concierge: took assigned slot from HELLO"
            );
            persist_spiral_position(st, slot);
            announce_hello_to_all_relays(st);
            update_spiral_neighbors(st);
            dial_missing_spiral_neighbors(st, shared_state);
            st.notify_topology_change();
            return true;
        }

        // No assigned_slot — broken concierge. Can't self-claim without
        // authority. The relay will be pruned or we'll reconnect to a
        // concierge that actually sends assigned_slot.
        warn!(
            remote = %remote_peer_id,
            remote_slot = remote_idx,
            "SPIRAL: established peer sent no assigned_slot — broken concierge"
        );
        return false;
    }

    // Both sides are claimed from here on.

    // Case 3: Same slot collision — deterministic VDF hash tiebreak.
    //
    // CRITICAL: Do NOT use cumulative_credit for this comparison.
    // cumulative_credit is a moving target — both sides read their own
    // live value (which keeps growing) while comparing against the
    // remote's frozen HELLO snapshot. Both independently conclude they
    // win → conflict. (Lean: snapshot_immutability_required)
    //
    // VDF hash tiebreak uses chain tips from HELLO — immutable, both
    // sides compute the same XOR → deterministic agreement.
    if our_spiral == Some(remote_idx) {
        let we_yield = !tiebreak(remote_peer_id);

        if we_yield {
            info!(
                slot = remote_idx,
                winner = %remote_peer_id,
                "SPIRAL merge: slot collision — we yield (VDF hash tiebreak)"
            );
            return reslot_around_winner(st, remote_peer_id, remote_idx, shared_state);
        }
        // We keep our slot. Remote will discover collision from our HELLO and yield.
        if !added {
            // Re-assert our claim. claim_specific_position sets our_index/our_coord/our_mesh_key
            // consistently — force_add_peer would only update the occupied map, leaving
            // the self-identity fields stale if they somehow drifted.
            st.mesh.spiral.claim_specific_position(
                &our_pid,
                remote_idx,
            );
        }
        return false;
    }

    // Case 4: Different slots — cluster merge.
    // Only triggers when two SEPARATE clumps meet for the first time.
    // If the remote was already in our known_peers, they're in our clump —
    // no merge needed, just register their updated slot.
    if already_in_clump {
        return added; // topology may have changed from add_peer, that's it
    }

    // Compare total VDF work across each clump. Loser re-slots around winner.
    if !added {
        // Remote's slot conflicts with a THIRD peer. Force-add the remote
        // if VDF hash tiebreak favors the incoming peer over the existing occupant.
        // Both values (existing + incoming VDF hashes) are from HELLO snapshots —
        // no moving-target issue.
        if let Some(existing_key) = st.mesh.spiral.peer_at_index(remote_idx).map(|s| s.to_string()) {
            let existing_vdf_hash: Option<Vec<u8>> = st.mesh.known_peers.get(&existing_key)
                .and_then(|p| p.vdf_hash.as_deref())
                .and_then(|h| hex::decode(h).ok());
            let incoming_wins = vdf_tiebreak_wins(
                remote_peer_id,
                &existing_key,
                their_vdf_hash_bytes.as_deref(),
                existing_vdf_hash.as_deref(),
            );
            if incoming_wins {
                st.mesh.spiral.force_add_peer(
                    remote_peer_id,
                    citadel_topology::Spiral3DIndex::new(remote_idx),
                );
            }
        }
    }

    // Compare cluster VDF work to determine merge winner.
    // Use our CACHED cluster_vdf_work (computed when we built our HELLO) —
    // NOT recomputed, because by now known_peers includes the remote's credit.
    // Two independently-computed values: ours (cached) vs theirs (from HELLO).
    let our_cluster_work = st.mesh.our_cluster_vdf_work;
    let their_cluster_work = _remote_cluster_vdf_work
        .or(remote_vdf_cumulative_credit)
        .unwrap_or(0.0);

    let we_lose = their_cluster_work > our_cluster_work
        || (their_cluster_work == our_cluster_work && !tiebreak(remote_peer_id));

    if we_lose {
        info!(
            our_work = our_cluster_work,
            their_work = their_cluster_work,
            our_slot = ?our_spiral,
            their_slot = remote_idx,
            winner = %remote_peer_id,
            "SPIRAL merge: cluster merge — we re-slot (lower total VDF work)"
        );
        return reslot_around_winner(st, remote_peer_id, remote_idx, shared_state);
    }

    // We win. Remote processes OUR HELLO (which carries our cluster_vdf_work),
    // compares against their own cached value, sees they lose, and re-slots.
    false
}

/// Evict stale peers. Only evict peers we're connected to (neighbor or relay).
/// Ghosts (no connection) are left alone — they're harmless HashMap entries
/// and gossip doesn't refresh last_seen periodically, so any timeout would
/// incorrectly evict alive peers we simply can't directly observe.
///
/// Returns the list of evicted peer keys.
fn evict_dead_peers(st: &mut super::server::ServerState) -> Vec<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let our_pid = st.lens.peer_id.clone();
    let mut evicted = Vec::new();

    // Run bitmap decay — stale bits flip to 0, SPORE rebuilt.
    // The bitmap is the mesh's collective liveness signal: each node's SPIRAL
    // neighbors attest its liveness → SPORE propagates → bit stays 1.
    // When nobody attests → bit decays to 0 → the mesh says they're dead.
    st.mesh.liveness_bitmap.decay(now);

    // Prune expired tombstones. 30s = bitmap decay (20s) + propagation margin.
    st.mesh.eviction_tombstones.retain(|_, ts| ts.elapsed() < std::time::Duration::from_secs(30));

    for (peer_mkey, _peer) in &st.mesh.known_peers {
        if *peer_mkey == our_pid {
            continue;
        }

        // Relay task manages this peer's lifecycle — never timer-evict.
        // The relay task will send PeerGone when it permanently exits.
        if st.federation.managed_peers.contains(peer_mkey) {
            continue;
        }

        // Live relay in map = alive. Period.
        if st.federation.relays.contains_key(peer_mkey) {
            continue;
        }

        // Ghost peer: no relay, no relay task.
        // We can't observe their liveness directly — we rely on their SPIRAL
        // neighbors to attest via the liveness bitmap (SPORE gossip).
        // Bitmap bit=1 means SOMEONE in the mesh can see them. Trust the mesh.
        // Bitmap bit=0 (decayed) means nobody can see them. Then evict.
        if let Some(idx) = st.mesh.spiral.peer_index(peer_mkey) {
            if st.mesh.liveness_bitmap.get(idx.value()) {
                continue; // Mesh says alive — not our call.
            }
        }
        evicted.push(peer_mkey.clone());
    }

    for evicted_key in &evicted {
        // Tombstone: prevent stale gossip from resurrecting this peer.
        st.mesh.eviction_tombstones.insert(evicted_key.clone(), std::time::Instant::now());
        if let Some(peer) = st.mesh.known_peers.remove(evicted_key) {
            tracing::debug!(
                mesh_key = %evicted_key,
                node_name = %peer.node_name,
                vdf_step = ?peer.vdf_step,
                "mesh: removing ghost peer from local view (bitmap decayed)"
            );
            // Local view cleanup only. We have no connection to this peer,
            // so there's nothing to shut down. The SPIRAL slot is released
            // so reconverge can reclaim it. If the peer comes back (new gossip
            // or direct HELLO), tombstone clears and they re-enter.
            st.mesh.connections.remove(evicted_key);
            st.mesh.spiral.remove_peer(evicted_key);
        }
    }

    evicted
}

/// APE (Any Point of Entry) mesh recovery — threshold-based, fires when active
/// relay count falls below the desired connection count.
///
/// The invariant: "I need N connections to function." N = max(SPIRAL neighbors, 1).
/// When active connections drop below N, scan known_peers for peers we're NOT
/// currently connected to or pending, and dial them to fill the deficit.
///
/// Recovery hierarchy:
/// 1. Known peers from gossip — any of them is an entry point back into the mesh
/// 2. Seed addresses from config (LAGOON_PEERS) — the bootstrap fallback
///
/// No peer is immortal. No relay is privileged. The bootstrap address is just
/// the seed entry in known_peers — the one you knew before you knew anyone else.
/// The system routes around stuck state: if a pending dial is stuck, the next
/// recovery sweep skips it and tries another peer.
fn attempt_mesh_rejoin(
    st: &mut super::server::ServerState,
    shared_state: super::server::SharedState,
) {
    let active_relays = st.federation.relays.len();
    let spiral_neighbors = st.mesh.spiral.neighbors().len();
    let desired = spiral_neighbors.max(1);

    if active_relays >= desired {
        return; // Enough connections — nothing to recover.
    }

    let deficit = desired - active_relays;
    let our_pid = st.lens.peer_id.clone();
    let event_tx = st.federation_event_tx.clone();
    let tc = st.transport_config.clone();

    // Collect peer_ids (relay map keys) we're already connected to.
    let connected_keys: std::collections::HashSet<&str> = st
        .federation
        .relays
        .keys()
        .map(|k| k.as_str())
        .collect();

    let mut dialed = 0usize;

    // Phase 1: Try known peers. Any of them is an entry point.
    for (mkey, peer) in &st.mesh.known_peers {
        if dialed >= deficit {
            break;
        }
        if *mkey == our_pid {
            continue;
        }
        // Skip peers we're already connected to (by mesh key).
        if connected_keys.contains(mkey.as_str()) {
            continue;
        }
        // Skip peers we're already dialing (by node_name).
        let node_name = &peer.node_name;
        if st.federation.pending_dials.contains(node_name) {
            continue;
        }

        // Need either an underlay URI or a Ygg overlay address for a route.
        let peer_uri = peer.underlay_uri.as_ref().filter(|u| is_underlay_uri(u));
        let peer_ygg: Option<std::net::Ipv6Addr> = peer
            .yggdrasil_addr
            .as_deref()
            .and_then(|s| s.parse().ok());

        if peer_uri.is_none() && peer_ygg.is_none() {
            continue;
        }

        info!(
            peer = %node_name,
            mesh_key = %mkey,
            active = active_relays,
            desired,
            deficit,
            "APE recovery: connection deficit — dialing known peer"
        );

        let underlay_host = peer_uri.map(|u| transport::extract_host_from_uri(u));
        let peer_entry = transport::PeerEntry {
            yggdrasil_addr: peer_ygg,
            port: transport::SWITCHBOARD_PORT,
            tls: false,
            want: None,
            dial_host: underlay_host,
        };

        st.federation.pending_dials.insert(node_name.clone());
        let mut tc_with_peer = (*tc).clone();
        tc_with_peer
            .peers
            .entry(node_name.clone())
            .or_insert(peer_entry);
        spawn_native_relay(
            node_name.clone(),
            event_tx.clone(),
            Arc::new(tc_with_peer),
            shared_state.clone(),
            false,
        );
        dialed += 1;
    }

    if dialed > 0 {
        return; // Got some known peers dialing, wait for gossip to fill the rest.
    }

    // Phase 2: No reachable known peers. Fall back to seed addresses (LAGOON_PEERS).
    for (host, _entry) in &tc.peers {
        if dialed >= deficit {
            break;
        }
        if st.federation.pending_dials.contains(host) {
            continue;
        }
        // Skip seeds we're already connected to (check by node_name match).
        let already_connected = st.federation.relays.values().any(|r| r.connect_target == *host);
        if already_connected {
            continue;
        }

        info!(
            seed = %host,
            active = active_relays,
            desired,
            "APE recovery: no known peers reachable — falling back to seed"
        );

        st.federation.pending_dials.insert(host.clone());
        spawn_native_relay(
            host.clone(),
            event_tx.clone(),
            tc.clone(),
            shared_state.clone(),
            true,
        );
        dialed += 1;
    }
}

fn evict_stale_spiral_peers(st: &mut super::server::ServerState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    const VDF_FRESHNESS_SECS: u64 = 300; // 5 minutes

    let mut live_keys: std::collections::HashSet<String> = st
        .federation
        .relays
        .iter()
        .filter(|(_, r)| r.mesh_connected)
        .map(|(key, _)| key.clone())
        .collect();

    // Also keep peers from known_peers with recent VDF activity.
    // These are peers we learned about via PEERS gossip — they're real
    // nodes even if we don't have a direct relay connection to them yet.
    for (key, info) in &st.mesh.known_peers {
        if info.spiral_index.is_some()
            && info.last_vdf_advance > 0
            && now.saturating_sub(info.last_vdf_advance) < VDF_FRESHNESS_SECS
        {
            live_keys.insert(key.clone());
        }
    }

    let before = st.mesh.spiral.occupied_count();
    st.mesh.spiral.retain_peers(&live_keys);
    let after = st.mesh.spiral.occupied_count();
    if before != after {
        info!(
            before,
            after,
            live_keys = live_keys.len(),
            "SPIRAL: evicted stale peers before claiming"
        );
    }
}

/// Claim the first available SPIRAL slot, persist, announce, update neighbors, prune.
/// Returns true (always changes topology).
/// Remove ourselves from our current slot, register the winner, claim first hole.
/// Returns true (always changes topology).
fn reslot_around_winner(
    st: &mut super::server::ServerState,
    winner_peer_id: &str,
    winner_slot: u64,
    shared_state: SharedState,
) -> bool {
    let our_pid = st.lens.peer_id.clone();
    // Remove ourselves from the contested slot.
    st.mesh.spiral.remove_peer(&our_pid);
    // Evict stale peers so we don't skip over dead slots.
    evict_stale_spiral_peers(st);
    // Accept the winner's claim.
    st.mesh.spiral.force_add_peer(
        winner_peer_id,
        citadel_topology::Spiral3DIndex::new(winner_slot),
    );
    // Claim first available hole. claim_position sets our_index/our_coord/our_mesh_key.
    // No apply_repack — we only move ourselves, other peers decide for themselves.
    let new_idx = st.mesh.spiral.claim_position(&our_pid);
    info!(
        old_slot = ?st.lens.spiral_index,
        new_slot = new_idx.value(),
        winner = %winner_peer_id,
        "SPIRAL merge: re-slotted around winner"
    );
    persist_spiral_position(st, new_idx.value());
    announce_hello_to_all_relays(st);
    update_spiral_neighbors(st);
    dial_missing_spiral_neighbors(st, shared_state);
    st.notify_topology_change();
    true
}

/// SPIRAL convergence: deterministic repack fills all holes in `[0..N)`.
///
/// Single-pass O(N), conflict-free. Every node independently computes the
/// same result from the same topology state. Replaces the old single-step
/// `evaluate_position()` approach.
///
/// Called after PEERS gossip processing, stale peer eviction, and merges.
/// Returns true if our position changed.
fn reconverge_spiral(
    st: &mut super::server::ServerState,
    shared_state: SharedState,
) -> bool {
    // Only converge if we have a position.
    if !st.mesh.spiral.is_claimed() {
        return false;
    }

    // Grace window: after a concierge assignment, VDF race, collision
    // resolution, or reslot, skip reconverge for 30s. The assigning node
    // had a more complete topology view. Local reconverge with incomplete
    // gossip sees "empty" slots that are actually occupied by peers we
    // haven't heard about yet → moves us to slot 0 → thundering herd.
    // 30s is enough for PEERS gossip to propagate the full topology.
    const SETTLE_GRACE_SECS: u64 = 30;
    if let Some(settled) = st.mesh.spiral_settled_at {
        if settled.elapsed() < std::time::Duration::from_secs(SETTLE_GRACE_SECS) {
            return false;
        }
    }

    // Evict stale peers first — frees slots held by dead nodes.
    evict_stale_spiral_peers(st);

    // Knowledge gate: if we're at slot N but our spiral occupied map has
    // fewer than N entries, our topology view is incomplete — gossip hasn't
    // propagated all assignments yet. Moving to a "lower empty" slot causes
    // thundering herd: every node with incomplete knowledge independently
    // moves to slot 1. Wait until we know about enough peers.
    if let Some(our_idx) = st.mesh.spiral.our_index() {
        let occupied_count = st.mesh.spiral.all_occupied().len() as u64;
        if occupied_count < our_idx.value() {
            tracing::debug!(
                our_slot = our_idx.value(),
                known_peers = occupied_count,
                "SPIRAL reconverge: skipped — incomplete topology (need {} peers, have {})",
                our_idx.value(),
                occupied_count,
            );
            return false;
        }
    }

    // Self-only convergence: check if there's a lower slot available.
    // Each node moves only ITSELF. Remote peers decide for themselves
    // when they receive gossip. Never repack remote peers locally —
    // that moves them into slots that might be occupied by peers we
    // haven't learned about yet.
    let better = st.mesh.spiral.evaluate_position();
    if let Some(better_idx) = better {
        let our_pid = st.lens.peer_id.clone();
        let old_slot = st.mesh.spiral.our_index().map(|i| i.value());
        st.mesh.spiral.claim_specific_position(&our_pid, better_idx.value());
        info!(
            old_slot = ?old_slot,
            new_slot = better_idx.value(),
            "SPIRAL reconverge: moved to lower slot"
        );
        persist_spiral_position(st, better_idx.value());
        announce_hello_to_all_relays(st);
        update_spiral_neighbors(st);
        dial_missing_spiral_neighbors(st, shared_state);
        st.notify_topology_change();
        // Atomic reslot: dial new SPIRAL neighbors FIRST, prune old ones LATER.
        // prune_non_spiral_relays runs in the periodic sweep and after HELLO —
        // by then the new connections are established. Pruning here would cut
        // old connections before replacements are ready, causing disconnection.
        return true;
    }

    false
}

/// Persist SPIRAL position to LensIdentity on disk.
fn persist_spiral_position(st: &mut super::server::ServerState, slot: u64) {
    let mut updated_lens = (*st.lens).clone();
    updated_lens.spiral_index = Some(slot);
    if let Some(ref rx) = st.mesh.vdf_state_rx {
        updated_lens.vdf_total_steps = rx.borrow().total_steps;
    }
    super::lens::persist_identity(&st.data_dir, &updated_lens);
    st.lens = std::sync::Arc::new(updated_lens);
    // Mark settlement time — reconverge_spiral skips within grace window.
    st.mesh.spiral_settled_at = Some(std::time::Instant::now());
}

/// Re-send MESH HELLO to all connected relays (after position change).
///
/// Debounced: skips if < 5 s since the last broadcast. SPIRAL instability
/// (reconverge, merge, collision) can trigger this at >30 Hz without the
/// guard, flooding the mesh with HELLOs that each trigger VdfProofReq +
/// PEERS processing on every remote. Position changes are persisted to disk
/// immediately — the broadcast can safely be delayed.
fn announce_hello_to_all_relays(st: &mut super::server::ServerState) {
    const DEBOUNCE_SECS: u64 = 5;
    let now = std::time::Instant::now();
    if let Some(last) = st.mesh.last_hello_broadcast {
        if now.duration_since(last) < std::time::Duration::from_secs(DEBOUNCE_SECS) {
            return;
        }
    }
    st.mesh.last_hello_broadcast = Some(now);

    let hello_json = serde_json::to_string(&build_hello_payload(st)).unwrap_or_default();
    for relay in st.federation.relays.values() {
        if !relay.mesh_connected { continue; }
        let _ = relay.outgoing_tx.send(RelayCommand::MeshHello {
            json: hello_json.clone(),
        });
    }
}

/// Update SPIRAL neighbor set for latency + connection gossip coordinators.
fn update_spiral_neighbors(st: &mut super::server::ServerState) {
    let neighbors = st.mesh.spiral.neighbors().clone();
    st.mesh.latency_gossip.set_spiral_neighbors(neighbors.clone());
    st.mesh.connection_gossip.set_spiral_neighbors(neighbors.clone());
    st.mesh.liveness_gossip.set_spiral_neighbors(neighbors);
}

fn build_hello_payload(st: &mut super::server::ServerState) -> MeshHelloPayload {
    let (vdf_genesis, vdf_hash, vdf_step, vdf_resonance_credit, vdf_actual_rate_hz, vdf_cumulative_credit) = st
        .mesh
        .vdf_state_rx
        .as_ref()
        .map(|rx| {
            let vdf = rx.borrow();
            let (credit, rate, cumulative) = vdf
                .resonance
                .as_ref()
                .map(|r| (Some(r.credit), Some(r.actual_rate_hz), Some(r.cumulative_credit)))
                .unwrap_or((None, None, None));
            (
                Some(hex::encode(vdf.genesis)),
                Some(hex::encode(vdf.current_hash)),
                Some(vdf.total_steps),
                credit,
                rate,
                cumulative,
            )
        })
        .unwrap_or((None, None, None, None, None, None));

    // Snapshot our VDF hash for deterministic tiebreaking in PEERS merges.
    // The PEERS universal merge must NOT read live vdf_state_rx.current_hash
    // because it changes every VDF tick — causing oscillation when our slot
    // is challenged. By snapshotting at HELLO build time, the hash used for
    // tiebreaking matches what we sent in our HELLO (which is what remote
    // nodes see). Both sides use the same pair of frozen hashes.
    if let Some(ref hash_hex) = vdf_hash {
        if let Ok(hash_bytes) = hex::decode(hash_hex) {
            st.mesh.our_vdf_hash_snapshot = Some(hash_bytes);
        }
    }

    // Cluster VDF work = our cumulative + all known peers' cumulative.
    // This is the value we SEND in our HELLO — represents our clump's
    // independent weight. Cached in MeshState so merge evaluation can
    // compare two independently-computed values (ours vs theirs).
    let cluster_vdf_work = {
        let our_cumulative = st.mesh.vdf_state_rx.as_ref()
            .and_then(|rx| rx.borrow().resonance.as_ref()
                .map(|r| r.cumulative_credit))
            .unwrap_or(0.0);
        let peers_cumulative: f64 = st.mesh.known_peers.values()
            .filter_map(|p| p.vdf_cumulative_credit)
            .sum();
        let total = our_cumulative + peers_cumulative;
        st.mesh.our_cluster_vdf_work = total;
        Some(total)
    };

    // Ygg overlay address (for identity/routing, NOT for peering).
    let yggdrasil_addr = st
        .transport_config
        .ygg_node
        .as_ref()
        .map(|n| n.address().to_string())
        .or_else(|| transport::detect_yggdrasil_addr().map(|a| a.to_string()));
    // Ygg peer URI = UNDERLAY address.  You don't tunnel Ygg through Ygg.
    // The underlay is the real network (public internet, Fly 6PN, LAN).
    let ygg_peer_uri = transport::detect_underlay_addr().map(|addr| match addr {
        std::net::IpAddr::V6(v6) => format!("tcp://[{v6}]:9443"),
        std::net::IpAddr::V4(v4) => format!("tcp://{v4}:9443"),
    });

    // CVDF cooperative chain status (if service is running).
    let (cvdf_height, cvdf_weight, cvdf_tip_hex, cvdf_genesis_hex) =
        st.mesh.cvdf_service.as_ref().map(|svc| {
            let status = svc.status();
            (Some(status.height), Some(status.weight), Some(status.tip_hex), Some(status.genesis_hex))
        }).unwrap_or((None, None, None, None));

    // Concierge slot assignment is NOT done here. build_hello_payload is
    // called for announcements, outbound connections, re-sends — only ONE
    // call site (the inbound HELLO response) needs assigned_slot. Computing
    // it here created phantom pending_assigned_slots reservations that pushed
    // real assignments to slot 654+ (thundering herd on pending slots).
    // See: compute_concierge_slot() called at the response HELLO site.
    let assigned_slot = None;

    MeshHelloPayload {
        peer_id: st.lens.peer_id.clone(),
        server_name: st.lens.server_name.clone(),
        public_key_hex: st.lens.public_key_hex.clone(),
        spiral_index: st.lens.spiral_index,
        vdf_genesis,
        vdf_hash,
        vdf_step,
        yggdrasil_addr,
        site_name: st.lens.site_name.clone(),
        node_name: st.lens.node_name.clone(),
        vdf_resonance_credit,
        vdf_actual_rate_hz,
        vdf_cumulative_credit,
        ygg_peer_uri,
        cvdf_height,
        cvdf_weight,
        cvdf_tip_hex,
        cvdf_genesis_hex,
        cluster_vdf_work,
        assigned_slot,
        cluster_chain_value: st.mesh.cluster_chain.as_ref().map(|cc| cc.value_hex()),
        cluster_chain_epoch_origin: st.mesh.cluster_chain.as_ref().map(|cc| hex::encode(cc.epoch_origin)),
        cluster_chain_round: st.mesh.cluster_chain.as_ref().map(|cc| cc.round),
        cluster_chain_work: st.mesh.cluster_chain.as_ref().map(|cc| cc.cumulative_work),
        cluster_round_seed: st.mesh.cluster_round_seed.map(|s| hex::encode(s)),
    }
}

/// Concierge: compute the first empty SPIRAL slot for an unclaimed joiner.
///
/// ONLY called at the inbound HELLO response site when the remote peer has
/// no spiral_index (unclaimed joiner). Reserves the slot in
/// `pending_assigned_slots` so back-to-back joiners get different slots.
///
/// This was previously inlined in `build_hello_payload()`, which caused
/// phantom reservations on every HELLO (announcements, re-sends, outbound
/// connections) — pushing real assignments to slot 654+.
fn compute_concierge_slot(st: &mut super::server::ServerState) -> Option<u64> {
    if !st.mesh.spiral.is_claimed() {
        return None;
    }

    let now = std::time::Instant::now();
    st.mesh.pending_assigned_slots.retain(|_, ts| {
        now.duration_since(*ts) < std::time::Duration::from_secs(30)
    });

    let occupied = st.mesh.spiral.all_occupied();
    let mut slot = 0u64;
    loop {
        let slot_occupied = occupied.iter().any(|(_, idx)| idx.value() == slot);
        let slot_pending = st.mesh.pending_assigned_slots.contains_key(&slot);
        if !slot_occupied && !slot_pending {
            break;
        }
        slot += 1;
    }
    st.mesh.pending_assigned_slots.insert(slot, now);
    Some(slot)
}

/// Spawn the mesh connector — proactively connects to all LAGOON_PEERS
/// and sends MESH HELLO to establish identity exchange.
///
/// Mesh connections are metadata-only — they exchange MESH commands but
/// create NO channels and inject NO users into rooms.
pub fn spawn_mesh_connector(state: SharedState, transport_config: Arc<TransportConfig>) {
    let peers: Vec<String> = transport_config.peers.keys().cloned().collect();
    if peers.is_empty() {
        // No peers configured. Do NOT self-claim a SPIRAL slot.
        // Genesis requires two witnesses agreeing on the same math.
        // A node with no peers has no authority to claim anything.
        info!("mesh: no peers configured, waiting for inbound connections");
        return;
    }

    info!(peer_count = peers.len(), "mesh: initiating connections to peers");

    tokio::spawn(async move {
        let st = state.read().await;
        let event_tx = st.federation_event_tx.clone();
        let tc = st.transport_config.clone();
        drop(st);

        for peer_host in peers {
            // Skip defederated peers.
            if state.read().await.mesh.defederated.contains(&peer_host) {
                info!(peer = %peer_host, "mesh: skipping defederated peer");
                continue;
            }

            info!(peer = %peer_host, "mesh: connecting to bootstrap peer");

            // The relay task handles everything: connect, HELLO, self-insert,
            // self-connection detection, reconnect with backoff.
            spawn_native_relay(
                peer_host,
                event_tx.clone(),
                Arc::clone(&tc),
                state.clone(),
                true,
            );
        }
    });
}

/// Translate a native `MeshMessage` into an IRC `MESH {subcommand} {json}` line.
///
/// Temporary backward compatibility for the old IRC-framed relay_task.
/// This is deleted when the relay_task is rewritten for native WebSocket.
fn mesh_message_to_irc(msg: &MeshMessage) -> Message {
    let (sub, payload) = match msg {
        MeshMessage::Hello(hello) => {
            ("HELLO".into(), serde_json::to_string(hello).unwrap_or_default())
        }
        MeshMessage::Peers { peers } => {
            ("PEERS".into(), serde_json::to_string(peers).unwrap_or_default())
        }
        MeshMessage::VdfProofReq => ("VDFPROOF_REQ".into(), String::new()),
        MeshMessage::VdfProof { proof } => {
            ("VDFPROOF".into(), proof.to_string())
        }
        MeshMessage::Sync => ("SYNC".into(), String::new()),
        MeshMessage::Gossip { message } => {
            ("GOSSIP".into(), message.to_string())
        }
        MeshMessage::GossipSpore { data } => ("GOSSIP_SPORE".into(), data.clone()),
        MeshMessage::GossipDiff { data } => ("GOSSIP_DIFF".into(), data.clone()),
        MeshMessage::LatencyHave { data } => ("LATENCY_HAVE".into(), data.clone()),
        MeshMessage::LatencyDelta { data } => ("LATENCY_DELTA".into(), data.clone()),
        MeshMessage::ProfileQuery { username } => {
            ("PROFILE_QUERY".into(), serde_json::json!({ "username": username }).to_string())
        }
        MeshMessage::ProfileResponse { username, profile } => {
            ("PROFILE_RESPONSE".into(), serde_json::json!({ "username": username, "profile": profile }).to_string())
        }
        MeshMessage::ProfileHave { data } => ("PROFILE_HAVE".into(), data.clone()),
        MeshMessage::ProfileDelta { data } => ("PROFILE_DELTA".into(), data.clone()),
        MeshMessage::ConnectionHave { data } => ("CONNECTION_HAVE".into(), data.clone()),
        MeshMessage::ConnectionDelta { data } => ("CONNECTION_DELTA".into(), data.clone()),
        MeshMessage::LivenessHave { data } => ("LIVENESS_HAVE".into(), data.clone()),
        MeshMessage::LivenessDelta { data } => ("LIVENESS_DELTA".into(), data.clone()),
        MeshMessage::SocketMigrate { migration, client_peer_id } => {
            ("SOCKET_MIGRATE".into(), serde_json::json!({ "migration": migration, "client_peer_id": client_peer_id }).to_string())
        }
        MeshMessage::Cvdf { data } => ("CVDF".into(), data.clone()),
        MeshMessage::Redirect { peers } => {
            ("REDIRECT".into(), serde_json::to_string(peers).unwrap_or_default())
        }
        MeshMessage::PolChallenge { nonce } => {
            ("POL_CHALLENGE".into(), nonce.to_string())
        }
        MeshMessage::PolResponse { nonce } => {
            ("POL_RESPONSE".into(), nonce.to_string())
        }
        MeshMessage::VdfWindow { .. } => {
            ("VDF_WINDOW".into(), String::new())
        }
        MeshMessage::ChainUpdate { value, cumulative_work, round, proof, work_contributions, epoch_origin } => {
            ("CHAIN_UPDATE".into(), serde_json::json!({
                "value": value, "cumulative_work": cumulative_work, "round": round,
                "proof": proof, "work_contributions": work_contributions,
                "epoch_origin": epoch_origin,
            }).to_string())
        }
    };
    let mut params = vec![sub];
    if !payload.is_empty() {
        params.push(payload);
    }
    Message {
        prefix: None,
        command: "MESH".into(),
        params,
    }
}

/// Send a FRELAY command to the remote server. Returns true on success.
async fn send_frelay(
    framed: &mut Framed<transport::RelayStream, IrcCodec>,
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

    // ── Ygg underlay/overlay address validation ─────────────────────────

    #[test]
    fn is_underlay_uri_accepts_fly_6pn() {
        // Fly.io 6PN addresses (fdaa::/32) are ULA — real underlay.
        assert!(is_underlay_uri("tcp://[fdaa:47:35ee:a7b:16a:7de5:43b9:2]:9443"));
    }

    #[test]
    fn is_underlay_uri_accepts_lan_ipv4() {
        assert!(is_underlay_uri("tcp://10.7.1.37:9443"));
    }

    #[test]
    fn is_underlay_uri_accepts_ula() {
        // fd00::/8 — private IPv6.
        assert!(is_underlay_uri("tcp://[fd00::1]:9443"));
    }

    #[test]
    fn is_underlay_uri_rejects_ygg_200() {
        // 200: addresses = Ygg overlay. NEVER peer with these.
        assert!(!is_underlay_uri("tcp://[200:ee10:28e8:6927:2f00:87fc:2e81:3be7]:9443"));
    }

    #[test]
    fn is_underlay_uri_rejects_ygg_201() {
        assert!(!is_underlay_uri("tcp://[201:6456:33da:ad57:e160:97a0:80e8:1a0e]:9443"));
    }

    #[test]
    fn is_underlay_uri_rejects_ygg_300() {
        // 300: addresses = Ygg subnet overlay.
        assert!(!is_underlay_uri("tcp://[300:ee10:28e8:6927::1]:9443"));
    }

    #[test]
    fn is_underlay_uri_accepts_global_unicast() {
        // 2001:db8:: = documentation prefix, but any non-02/03 global is fine.
        assert!(is_underlay_uri("tcp://[2001:db8::1]:9443"));
    }

    #[test]
    fn ape_peer_uri_uses_relay_addr() {
        let addr: SocketAddr = "[fdaa:47:35ee:a7b:16a:7de5:43b9:2]:9443".parse().unwrap();
        let uri = ape_peer_uri(Some(addr));
        assert_eq!(uri, Some("tcp://[fdaa:47:35ee:a7b:16a:7de5:43b9:2]:9443".into()));
        // Verify it's underlay.
        assert!(is_underlay_uri(uri.as_ref().unwrap()));
    }

    #[test]
    fn ape_peer_uri_returns_none_without_relay() {
        // No relay_peer_addr = no peering. Never fall back to overlay.
        assert_eq!(ape_peer_uri(None), None);
    }

    // ── Switchboard Ygg URI construction ──────────────────────────────

    #[test]
    fn switchboard_ygg_uri_ipv4() {
        assert_eq!(
            switchboard_ygg_uri("109.224.228.162"),
            "tcp://109.224.228.162:9443"
        );
    }

    #[test]
    fn switchboard_ygg_uri_ipv6() {
        assert_eq!(
            switchboard_ygg_uri("fdaa:47:35ee:a7b:16a:7de5:43b9:2"),
            "tcp://[fdaa:47:35ee:a7b:16a:7de5:43b9:2]:9443"
        );
    }

    #[test]
    fn switchboard_ygg_uri_hostname() {
        assert_eq!(
            switchboard_ygg_uri("anycast-mesh.fly.dev"),
            "tcp://anycast-mesh.fly.dev:9443"
        );
    }
}
