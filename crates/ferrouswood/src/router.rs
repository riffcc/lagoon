//! SPIRAL-based packet router.
//!
//! Receives ironwood frames from yggdrasil-rs peers and routes them:
//! - KeepAlive: handled by the peer layer (yggdrasil-rs), never reaches here
//! - Tree protocol (SigReq/SigRes/Announce/Bloom): acknowledged, not forwarded
//!   (SPIRAL IS the topology — we don't need spanning tree construction)
//! - PathLookup/PathNotify/PathBroken: handled via SPIRAL neighbor knowledge
//! - Traffic: routed to destination via SPIRAL neighbors

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use yggdrasil_rs::wire::PacketType;
use yggdrasil_rs::YggNode;

/// Packet routing decisions.
#[derive(Debug)]
pub enum RouteAction {
    /// Deliver to the local application.
    Local(Vec<u8>),
    /// Forward to a specific peer (by public key).
    Forward { peer_key: [u8; 32], payload: Vec<u8> },
    /// Drop the packet (tree protocol messages we don't participate in).
    Drop,
}

/// SPIRAL-based router.
///
/// Sits on top of yggdrasil-rs, receives raw ironwood frames, and routes them
/// using SPIRAL topology instead of ironwood's spanning tree.
pub struct Router {
    /// Mapping from Ygg overlay address → peer public key.
    /// Populated from SPIRAL neighbor knowledge.
    address_table: Arc<RwLock<HashMap<std::net::Ipv6Addr, [u8; 32]>>>,
    /// Channel for delivering locally-addressed traffic to the application.
    local_tx: mpsc::Sender<Vec<u8>>,
    local_rx: Option<mpsc::Receiver<Vec<u8>>>,
}

impl Router {
    pub fn new() -> Self {
        let (local_tx, local_rx) = mpsc::channel(256);
        Self {
            address_table: Arc::new(RwLock::new(HashMap::new())),
            local_tx,
            local_rx: Some(local_rx),
        }
    }

    /// Take the receiver for locally-addressed traffic.
    /// Can only be called once.
    pub fn take_local_rx(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.local_rx.take()
    }

    /// Register a SPIRAL neighbor's overlay address → public key mapping.
    pub async fn register_peer(&self, addr: std::net::Ipv6Addr, key: [u8; 32]) {
        self.address_table.write().await.insert(addr, key);
    }

    /// Remove a peer from the routing table.
    pub async fn unregister_peer(&self, addr: &std::net::Ipv6Addr) {
        self.address_table.write().await.remove(addr);
    }

    /// Route an incoming ironwood frame.
    ///
    /// Called by the application's event loop when it receives a frame from
    /// a yggdrasil-rs peer.
    pub fn route_frame(
        &self,
        packet_type: PacketType,
        payload: &[u8],
    ) -> RouteAction {
        match packet_type {
            // ── Tree protocol: SPIRAL replaces these ──────────────────
            // Stock Ygg peers will send these. We accept them gracefully
            // but don't participate in tree construction.
            PacketType::ProtoSigReq
            | PacketType::ProtoSigRes
            | PacketType::ProtoAnnounce
            | PacketType::ProtoBloomFilter => {
                tracing::trace!(
                    ?packet_type,
                    len = payload.len(),
                    "ferrouswood: dropping tree protocol message (SPIRAL replaces)"
                );
                RouteAction::Drop
            }

            // ── Path discovery: handled via SPIRAL knowledge ─────────
            PacketType::ProtoPathLookup => {
                // A stock Ygg peer is asking "who has key X?"
                // If we know (via SPIRAL), we could respond.
                // For now, drop — SPIRAL peers don't need path discovery.
                tracing::trace!("ferrouswood: dropping PathLookup (SPIRAL handles routing)");
                RouteAction::Drop
            }
            PacketType::ProtoPathNotify | PacketType::ProtoPathBroken => {
                tracing::trace!(?packet_type, "ferrouswood: dropping path message");
                RouteAction::Drop
            }

            // ── Traffic: the real payload ────────────────────────────
            PacketType::Traffic => {
                // Traffic packets contain encrypted application data.
                // In a full implementation, we'd parse the source/dest keys
                // from the ironwood traffic header and route accordingly.
                // For now, deliver everything locally.
                RouteAction::Local(payload.to_vec())
            }

            // ── Keepalive: should never reach here ───────────────────
            PacketType::KeepAlive => RouteAction::Drop,

            // ── Dummy: ignore ────────────────────────────────────────
            PacketType::Dummy => RouteAction::Drop,
        }
    }

    /// Process a frame from a yggdrasil-rs peer event and act on it.
    ///
    /// Convenience method that combines `route_frame` with sending.
    pub async fn handle_frame(
        &self,
        node: &YggNode,
        _peer_key: [u8; 32],
        packet_type: PacketType,
        payload: Vec<u8>,
    ) {
        match self.route_frame(packet_type, &payload) {
            RouteAction::Local(data) => {
                let _ = self.local_tx.send(data).await;
            }
            RouteAction::Forward {
                peer_key: target,
                payload: data,
            } => {
                if let Err(e) = node.send_to(&target, PacketType::Traffic, data).await {
                    tracing::debug!(
                        target = %hex::encode(target),
                        error = %e,
                        "ferrouswood: forward failed"
                    );
                }
            }
            RouteAction::Drop => {}
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_protocol_dropped() {
        let router = Router::new();
        assert!(matches!(
            router.route_frame(PacketType::ProtoAnnounce, &[]),
            RouteAction::Drop
        ));
        assert!(matches!(
            router.route_frame(PacketType::ProtoBloomFilter, &[]),
            RouteAction::Drop
        ));
        assert!(matches!(
            router.route_frame(PacketType::ProtoSigReq, &[]),
            RouteAction::Drop
        ));
    }

    #[test]
    fn traffic_delivered_locally() {
        let router = Router::new();
        let payload = b"hello mesh";
        match router.route_frame(PacketType::Traffic, payload) {
            RouteAction::Local(data) => assert_eq!(data, payload),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn keepalive_dropped() {
        let router = Router::new();
        assert!(matches!(
            router.route_frame(PacketType::KeepAlive, &[]),
            RouteAction::Drop
        ));
    }
}
