//! Connection Store: SPORE-indexed storage for mesh connection snapshots.
//!
//! Each node publishes a snapshot of which peers it is connected to. These
//! snapshots are gossiped via SPORE diff-sync so that every node eventually
//! knows the full mesh connectivity graph — enabling the topology visualization
//! to show ALL edges, not just local ones.
//!
//! ## Design Decisions
//!
//! - **Keyed by reporter_id (peer_id)**: each node publishes exactly one snapshot.
//!   Newer snapshots replace older ones (by timestamp).
//!
//! - **Monotonic SPORE growth**: same as ProofStore — replaced snapshots leave
//!   their old content_id in the SPORE. Harmless: stale content IDs just mean
//!   a peer skips re-requesting data we already replaced.
//!
//! - **TTL-based pruning**: snapshots older than `ttl_ms` are removed on
//!   `prune_stale()`. No polling, no background tasks.

use std::collections::HashMap;

use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};

/// A connection snapshot from a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSnapshot {
    /// The peer_id of the node reporting its connections.
    pub reporter_id: String,
    /// peer_ids this node is currently connected to.
    pub connected_peers: Vec<String>,
    /// When this snapshot was created (milliseconds since epoch).
    pub timestamp_ms: i64,
    /// BLAKE3 hash of the serialized snapshot data, used as SPORE content ID.
    pub content_id: [u8; 32],
}

/// SPORE-indexed store for mesh connection snapshots.
#[derive(Debug)]
pub struct ConnectionStore {
    snapshots: HashMap<String, ConnectionSnapshot>,
    spore: Spore,
    ttl_ms: i64,
}

/// Create a SPORE point range for a single U256 value.
fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

impl ConnectionStore {
    /// Create a new connection store with the given TTL.
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            snapshots: HashMap::new(),
            spore: Spore::empty(),
            ttl_ms,
        }
    }

    /// Build a `ConnectionSnapshot` for the local node.
    pub fn make_snapshot(
        reporter_id: String,
        connected_peers: Vec<String>,
        timestamp_ms: i64,
    ) -> ConnectionSnapshot {
        let hash_input = format!("{reporter_id}:{timestamp_ms}:{connected_peers:?}");
        let content_id: [u8; 32] = *blake3::hash(hash_input.as_bytes()).as_bytes();
        ConnectionSnapshot {
            reporter_id,
            connected_peers,
            timestamp_ms,
            content_id,
        }
    }

    /// Insert a snapshot. Returns `true` if the snapshot was new or replaced an
    /// older one; `false` if the existing snapshot has a newer-or-equal timestamp.
    pub fn insert(&mut self, snapshot: ConnectionSnapshot) -> bool {
        if let Some(existing) = self.snapshots.get(&snapshot.reporter_id) {
            if snapshot.timestamp_ms <= existing.timestamp_ms {
                return false;
            }
        }

        let content_u256 = U256::from_be_bytes(&snapshot.content_id);
        let point = Spore::from_range(point_range(content_u256));
        self.spore = self.spore.union(&point);

        self.snapshots
            .insert(snapshot.reporter_id.clone(), snapshot);
        true
    }

    /// Reference to the internal SPORE.
    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    /// Compute snapshots a peer is missing based on their SPORE.
    pub fn diff_for_peer(&self, peer_spore: &Spore) -> Vec<ConnectionSnapshot> {
        let missing = self.spore.subtract(peer_spore);
        self.snapshots
            .values()
            .filter(|snap| {
                let cid = U256::from_be_bytes(&snap.content_id);
                missing.covers(&cid)
            })
            .cloned()
            .collect()
    }

    /// Merge incoming snapshots, rejecting stale or older-than-existing ones.
    /// Returns the number of snapshots accepted.
    pub fn merge(&mut self, snapshots: Vec<ConnectionSnapshot>, now_ms: i64) -> usize {
        let mut accepted = 0;
        for snap in snapshots {
            if now_ms - snap.timestamp_ms > self.ttl_ms {
                continue;
            }
            if self.insert(snap) {
                accepted += 1;
            }
        }
        accepted
    }

    /// Remove snapshots older than TTL. Does NOT shrink the SPORE.
    pub fn prune_stale(&mut self, now_ms: i64) -> usize {
        let before = self.snapshots.len();
        self.snapshots
            .retain(|_, snap| now_ms - snap.timestamp_ms <= self.ttl_ms);
        before - self.snapshots.len()
    }

    /// All edges from all snapshots: `(reporter_id, connected_peer_id)` pairs.
    pub fn all_edges(&self) -> Vec<(String, String)> {
        let mut edges = Vec::new();
        for snap in self.snapshots.values() {
            for peer in &snap.connected_peers {
                edges.push((snap.reporter_id.clone(), peer.clone()));
            }
        }
        edges
    }

    /// Serialized snapshot data with content_id, for gossip diff.
    pub fn snapshot_data_for_gossip(&self) -> Vec<(Vec<u8>, [u8; 32])> {
        self.snapshots
            .values()
            .map(|snap| {
                let serialized = bincode::serialize(snap).unwrap_or_default();
                (serialized, snap.content_id)
            })
            .collect()
    }

    /// Number of snapshots stored.
    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot(reporter: &str, peers: &[&str], ts: i64) -> ConnectionSnapshot {
        ConnectionStore::make_snapshot(
            reporter.to_owned(),
            peers.iter().map(|s| (*s).to_owned()).collect(),
            ts,
        )
    }

    #[test]
    fn test_insert_new() {
        let mut store = ConnectionStore::new(120_000);
        let snap = test_snapshot("node-a", &["node-b", "node-c"], 1000);
        assert!(store.insert(snap));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_older_rejected() {
        let mut store = ConnectionStore::new(120_000);
        let newer = test_snapshot("node-a", &["node-b"], 2000);
        let older = test_snapshot("node-a", &["node-c"], 1000);
        assert!(store.insert(newer));
        assert!(!store.insert(older));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_newer_replaces() {
        let mut store = ConnectionStore::new(120_000);
        let older = test_snapshot("node-a", &["node-b"], 1000);
        let newer = test_snapshot("node-a", &["node-b", "node-c"], 2000);
        assert!(store.insert(older));
        assert!(store.insert(newer));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_prune_stale() {
        let mut store = ConnectionStore::new(60_000);
        let fresh = test_snapshot("node-a", &["node-b"], 50_000);
        let stale = test_snapshot("node-b", &["node-c"], 1000);
        store.insert(fresh);
        store.insert(stale);
        assert_eq!(store.len(), 2);

        let pruned = store.prune_stale(70_000);
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_merge_new() {
        let mut store = ConnectionStore::new(120_000);
        let snaps = vec![
            test_snapshot("node-a", &["node-b"], 5000),
            test_snapshot("node-b", &["node-a", "node-c"], 5000),
        ];
        let accepted = store.merge(snaps, 10_000);
        assert_eq!(accepted, 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_merge_stale_rejected() {
        let mut store = ConnectionStore::new(60_000);
        let snaps = vec![test_snapshot("node-a", &["node-b"], 1000)];
        let accepted = store.merge(snaps, 200_000);
        assert_eq!(accepted, 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_diff_empty_peer() {
        let mut store = ConnectionStore::new(120_000);
        store.insert(test_snapshot("node-a", &["node-b"], 5000));
        store.insert(test_snapshot("node-b", &["node-a"], 5000));

        let diff = store.diff_for_peer(&Spore::empty());
        assert_eq!(diff.len(), 2);
    }

    #[test]
    fn test_diff_synced_peer() {
        let mut store = ConnectionStore::new(120_000);
        store.insert(test_snapshot("node-a", &["node-b"], 5000));

        let diff = store.diff_for_peer(store.spore());
        assert_eq!(diff.len(), 0);
    }

    #[test]
    fn test_all_edges() {
        let mut store = ConnectionStore::new(120_000);
        store.insert(test_snapshot("node-a", &["node-b", "node-c"], 5000));
        store.insert(test_snapshot("node-b", &["node-a"], 5000));

        let edges = store.all_edges();
        assert_eq!(edges.len(), 3);
    }

    #[test]
    fn test_snapshot_data_for_gossip() {
        let mut store = ConnectionStore::new(120_000);
        store.insert(test_snapshot("node-a", &["node-b"], 5000));

        let data = store.snapshot_data_for_gossip();
        assert_eq!(data.len(), 1);
        assert!(!data[0].0.is_empty());
        assert_ne!(data[0].1, [0u8; 32]);
    }

    #[test]
    fn test_content_id_deterministic() {
        let s1 = ConnectionStore::make_snapshot("a".into(), vec!["b".into()], 1000);
        let s2 = ConnectionStore::make_snapshot("a".into(), vec!["b".into()], 1000);
        assert_eq!(s1.content_id, s2.content_id);
    }

    #[test]
    fn test_content_id_changes_with_peers() {
        let s1 = ConnectionStore::make_snapshot("a".into(), vec!["b".into()], 1000);
        let s2 = ConnectionStore::make_snapshot("a".into(), vec!["b".into(), "c".into()], 1000);
        assert_ne!(s1.content_id, s2.content_id);
    }
}
