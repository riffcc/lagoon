//! SPIRAL-scoped connection snapshot gossip coordinator.
//!
//! Mirrors [`super::latency_gossip::LatencyGossip`] but for connection
//! snapshots instead of latency proofs. Coordinates WHICH SPIRAL neighbors
//! to gossip with and WHEN. Produces [`SyncAction`]s that the federation
//! layer executes by sending wire messages.

use std::collections::{HashMap, HashSet};

use citadel_spore::{Spore, U256};
use serde::{Deserialize, Serialize};

/// Wire message for connection snapshot gossip between SPIRAL neighbors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// "Here's my SPORE state — send me what I'm missing"
    HaveList { spore_bytes: Vec<u8> },
    /// "Here are the snapshots you're missing"
    SnapshotDelta { entries: Vec<Vec<u8>> },
}

/// Action for federation.rs to execute.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// Send a HaveList to this neighbor to initiate reconciliation.
    SendHaveList {
        neighbor_node_name: String,
        message: SyncMessage,
    },
    /// Send snapshot deltas to this neighbor.
    SendSnapshotDelta {
        neighbor_node_name: String,
        message: SyncMessage,
    },
}

/// SPIRAL-scoped connection gossip coordinator.
#[derive(Debug)]
pub struct ConnectionGossip {
    spiral_neighbors: HashSet<String>,
    peer_to_node: HashMap<String, String>,
    last_sync: HashMap<String, i64>,
    sync_interval_ms: i64,
}

impl ConnectionGossip {
    /// Create a new connection gossip coordinator.
    pub fn new(sync_interval_ms: i64) -> Self {
        Self {
            spiral_neighbors: HashSet::new(),
            peer_to_node: HashMap::new(),
            last_sync: HashMap::new(),
            sync_interval_ms,
        }
    }

    /// Replace the SPIRAL neighbor set (called when topology changes).
    pub fn set_spiral_neighbors(&mut self, neighbors: HashSet<String>) {
        self.last_sync.retain(|peer, _| neighbors.contains(peer));
        self.spiral_neighbors = neighbors;
    }

    /// Register a peer_id -> node_name mapping.
    pub fn register_peer(&mut self, peer_id: String, node_name: String) {
        self.peer_to_node.insert(peer_id, node_name);
    }

    /// Remove a peer mapping on disconnect.
    pub fn remove_peer(&mut self, peer_id: &str) {
        self.peer_to_node.remove(peer_id);
    }

    /// Called when a connection snapshot changes (connect/disconnect).
    ///
    /// Returns [`SyncAction`]s for SPIRAL neighbors that are due for sync.
    pub fn on_snapshot_updated(
        &mut self,
        now_ms: i64,
        our_spore_bytes: &[u8],
    ) -> Vec<SyncAction> {
        let due = self.neighbors_needing_sync(now_ms);
        let mut actions = Vec::with_capacity(due.len());

        for peer_id in due {
            if let Some(node_name) = self.peer_to_node.get(&peer_id) {
                actions.push(SyncAction::SendHaveList {
                    neighbor_node_name: node_name.clone(),
                    message: SyncMessage::HaveList {
                        spore_bytes: our_spore_bytes.to_vec(),
                    },
                });
                self.mark_synced(&peer_id, now_ms);
            }
        }

        actions
    }

    /// Called when we receive a `HaveList` from a neighbor.
    ///
    /// Returns a `SendSnapshotDelta` action if we have snapshots they're missing.
    pub fn on_have_list_received(
        &self,
        from_peer_id: &str,
        their_spore_bytes: &[u8],
        our_spore: &Spore,
        our_snapshot_data: &[(Vec<u8>, [u8; 32])],
    ) -> Option<SyncAction> {
        let their_spore: Spore = match bincode::deserialize(their_spore_bytes) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let diff = our_spore.subtract(&their_spore);
        if diff.is_empty() {
            return None;
        }

        let entries: Vec<Vec<u8>> = our_snapshot_data
            .iter()
            .filter(|(_, content_id)| {
                let u = U256::from_be_bytes(content_id);
                diff.covers(&u)
            })
            .map(|(bytes, _)| bytes.clone())
            .collect();

        if entries.is_empty() {
            return None;
        }

        let node_name = self.peer_to_node.get(from_peer_id)?;

        Some(SyncAction::SendSnapshotDelta {
            neighbor_node_name: node_name.clone(),
            message: SyncMessage::SnapshotDelta { entries },
        })
    }

    /// Return peers due for a sync round.
    fn neighbors_needing_sync(&self, now_ms: i64) -> Vec<String> {
        self.spiral_neighbors
            .iter()
            .filter(|peer| match self.last_sync.get(*peer) {
                Some(&last) => now_ms - last >= self.sync_interval_ms,
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Mark a neighbor as synced at the given timestamp.
    fn mark_synced(&mut self, peer_id: &str, now_ms: i64) {
        if self.spiral_neighbors.contains(peer_id) {
            self.last_sync.insert(peer_id.to_owned(), now_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_spore::{Range256, Spore, U256};

    fn make_gossip() -> ConnectionGossip {
        ConnectionGossip::new(5000)
    }

    fn neighbors_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn test_new_empty() {
        let g = make_gossip();
        assert!(g.spiral_neighbors.is_empty());
        assert!(g.peer_to_node.is_empty());
        assert!(g.last_sync.is_empty());
    }

    #[test]
    fn test_set_spiral_neighbors() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        assert_eq!(g.spiral_neighbors.len(), 2);

        g.set_spiral_neighbors(neighbors_set(&["x"]));
        assert_eq!(g.spiral_neighbors.len(), 1);
        assert!(g.spiral_neighbors.contains("x"));
    }

    #[test]
    fn test_register_remove_peer() {
        let mut g = make_gossip();
        g.register_peer("p1".into(), "node-a".into());
        assert_eq!(g.peer_to_node.get("p1").unwrap(), "node-a");

        g.remove_peer("p1");
        assert!(g.peer_to_node.get("p1").is_none());
    }

    #[test]
    fn test_on_snapshot_updated_sends_to_due() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        g.register_peer("a".into(), "node-a".into());
        g.register_peer("b".into(), "node-b".into());

        let actions = g.on_snapshot_updated(10_000, b"fake-spore");
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_on_snapshot_updated_skips_recent() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a"]));
        g.register_peer("a".into(), "node-a".into());

        let _ = g.on_snapshot_updated(0, b"s");
        let actions = g.on_snapshot_updated(3000, b"s");
        assert!(actions.is_empty());

        let actions = g.on_snapshot_updated(5000, b"s");
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_on_have_list_with_diff() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["peer_x"]));
        g.register_peer("peer_x".into(), "node-x".into());

        let content_id: [u8; 32] = blake3::hash(b"test data").into();
        let u = U256::from_be_bytes(&content_id);
        let next = u.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
        let our_spore = Spore::from_range(Range256::new(u, next));

        let their_spore = Spore::empty();
        let their_bytes = bincode::serialize(&their_spore).unwrap();

        let our_data: Vec<(Vec<u8>, [u8; 32])> = vec![(b"snapshot-data".to_vec(), content_id)];

        let action = g
            .on_have_list_received("peer_x", &their_bytes, &our_spore, &our_data)
            .expect("should produce a SnapshotDelta");

        match action {
            SyncAction::SendSnapshotDelta {
                neighbor_node_name,
                message,
            } => {
                assert_eq!(neighbor_node_name, "node-x");
                match message {
                    SyncMessage::SnapshotDelta { entries } => {
                        assert_eq!(entries.len(), 1);
                    }
                    _ => panic!("expected SnapshotDelta"),
                }
            }
            _ => panic!("expected SendSnapshotDelta"),
        }
    }

    #[test]
    fn test_on_have_list_synced() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["peer_x"]));
        g.register_peer("peer_x".into(), "node-x".into());

        let content_id: [u8; 32] = blake3::hash(b"data").into();
        let u = U256::from_be_bytes(&content_id);
        let next = u.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
        let our_spore = Spore::from_range(Range256::new(u, next));

        let their_bytes = bincode::serialize(&our_spore).unwrap();
        let our_data: Vec<(Vec<u8>, [u8; 32])> = vec![(b"entry".to_vec(), content_id)];

        let result = g.on_have_list_received("peer_x", &their_bytes, &our_spore, &our_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_set_neighbors_clears_stale_sync() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        let _ = g.on_snapshot_updated(0, b"s");

        g.set_spiral_neighbors(neighbors_set(&["a"]));
        assert!(!g.last_sync.contains_key("b"));
    }
}
