//! SPIRAL-scoped latency proof gossip coordinator.
//!
//! This module coordinates WHICH SPIRAL neighbors to gossip latency proofs with
//! and WHEN. It does not own proof storage — callers pass in serialized SPORE
//! state and proof data. The module produces [`SyncAction`]s that the federation
//! layer executes by sending wire messages to the named neighbor.

use std::collections::{HashMap, HashSet};

use citadel_spore::{Spore, U256};
use serde::{Deserialize, Serialize};

/// Wire message for latency proof gossip between SPIRAL neighbors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// "Here's my SPORE state — send me what I'm missing"
    HaveList { spore_bytes: Vec<u8> },
    /// "Here are the proofs you're missing"
    ProofDelta { entries: Vec<Vec<u8>> },
}

/// Action for federation.rs to execute.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// Send a HaveList to this neighbor to initiate reconciliation.
    SendHaveList {
        neighbor_peer_id: String,
        message: SyncMessage,
    },
    /// Send proof deltas to this neighbor.
    SendProofDelta {
        neighbor_peer_id: String,
        message: SyncMessage,
    },
}

/// SPIRAL-scoped gossip coordinator.
///
/// Tracks which SPIRAL neighbors exist and enforces a minimum sync interval
/// so we don't flood the mesh with redundant reconciliation rounds.
/// Routing (relay lookup by peer_id) is handled by the federation layer.
#[derive(Debug)]
pub struct LatencyGossip {
    our_peer_id: String,
    spiral_neighbors: HashSet<String>,
    last_sync: HashMap<String, i64>,
    sync_interval_ms: i64,
}

impl LatencyGossip {
    /// Create a new gossip coordinator.
    ///
    /// `our_peer_id` identifies us in the SPIRAL ring.
    /// `sync_interval_ms` is the minimum milliseconds between sync rounds
    /// with the same neighbor.
    pub fn new(our_peer_id: String, sync_interval_ms: i64) -> Self {
        Self {
            our_peer_id,
            spiral_neighbors: HashSet::new(),
            last_sync: HashMap::new(),
            sync_interval_ms,
        }
    }

    /// Replace the SPIRAL neighbor set (called when topology changes).
    ///
    /// Clears sync-tracking state for peers no longer in the neighbor set.
    pub fn set_spiral_neighbors(&mut self, neighbors: HashSet<String>) {
        // Prune last_sync entries for peers that are no longer neighbors.
        self.last_sync.retain(|peer, _| neighbors.contains(peer));
        self.spiral_neighbors = neighbors;
    }

    /// Called when a new proof arrives (locally measured or received).
    ///
    /// Returns [`SyncAction`]s for SPIRAL neighbors that are due for sync.
    /// Each action is a `SendHaveList` to initiate SPORE reconciliation.
    /// `our_spore_bytes` is the bincode-serialized SPORE from the proof store.
    ///
    /// Actions are emitted for all due neighbors. The federation layer
    /// filters by relay availability (can't route → skip).
    pub fn on_proof_updated(
        &mut self,
        now_ms: i64,
        our_spore_bytes: &[u8],
    ) -> Vec<SyncAction> {
        let due = self.neighbors_needing_sync(now_ms);
        let mut actions = Vec::with_capacity(due.len());

        for peer_id in due {
            actions.push(SyncAction::SendHaveList {
                neighbor_peer_id: peer_id.clone(),
                message: SyncMessage::HaveList {
                    spore_bytes: our_spore_bytes.to_vec(),
                },
            });
            self.mark_synced(&peer_id, now_ms);
        }

        actions
    }

    /// Called when we receive a `HaveList` from a neighbor.
    ///
    /// Computes which of our proofs they're missing and returns a
    /// `SendProofDelta` action, or `None` if they already have everything.
    ///
    /// * `from_peer_id` — the SPIRAL peer that sent the HaveList (also relay key).
    /// * `their_spore_bytes` — bincode-serialized SPORE from the wire message.
    /// * `our_spore` — our current proof SPORE (caller owns the proof store).
    /// * `our_proof_data` — `(serialized_entry, content_id)` pairs from the store.
    pub fn on_have_list_received(
        &self,
        from_peer_id: &str,
        their_spore_bytes: &[u8],
        our_spore: &Spore,
        our_proof_data: &[(Vec<u8>, [u8; 32])],
    ) -> Option<SyncAction> {
        let their_spore: Spore = match bincode::deserialize(their_spore_bytes) {
            Ok(s) => s,
            Err(_) => return None, // Malformed message — nothing to do.
        };

        // Ranges we cover that they don't.
        let diff = our_spore.subtract(&their_spore);
        if diff.is_empty() {
            return None;
        }

        let entries: Vec<Vec<u8>> = our_proof_data
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

        Some(SyncAction::SendProofDelta {
            neighbor_peer_id: from_peer_id.to_owned(),
            message: SyncMessage::ProofDelta { entries },
        })
    }

    /// Check whether `peer_id` is in the current SPIRAL neighbor set.
    pub fn is_spiral_neighbor(&self, peer_id: &str) -> bool {
        self.spiral_neighbors.contains(peer_id)
    }

    /// How many SPIRAL neighbors we currently track.
    pub fn neighbor_count(&self) -> usize {
        self.spiral_neighbors.len()
    }

    /// Return peers due for a sync round.
    ///
    /// A neighbor is "due" if we have never synced with it, or if at least
    /// `sync_interval_ms` has elapsed since the last sync.
    pub fn neighbors_needing_sync(&self, now_ms: i64) -> Vec<String> {
        self.spiral_neighbors
            .iter()
            .filter(|peer| {
                match self.last_sync.get(*peer) {
                    Some(&last) => now_ms - last >= self.sync_interval_ms,
                    None => true, // Never synced → due immediately.
                }
            })
            .cloned()
            .collect()
    }

    /// Mark a neighbor as synced at the given timestamp.
    pub fn mark_synced(&mut self, peer_id: &str, now_ms: i64) {
        if self.spiral_neighbors.contains(peer_id) {
            self.last_sync.insert(peer_id.to_owned(), now_ms);
        }
    }

    /// Our peer ID in the SPIRAL ring.
    #[allow(dead_code)]
    pub fn our_peer_id(&self) -> &str {
        &self.our_peer_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_spore::{Range256, Spore, U256};

    fn make_gossip() -> LatencyGossip {
        LatencyGossip::new("b3b3/our_id".into(), 5000)
    }

    fn neighbors_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    // 1. Empty on construction
    #[test]
    fn test_new_empty() {
        let g = make_gossip();
        assert_eq!(g.neighbor_count(), 0);
        assert!(g.spiral_neighbors.is_empty());
        assert!(g.last_sync.is_empty());
    }

    // 2. set_spiral_neighbors replaces the set
    #[test]
    fn test_set_spiral_neighbors() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b", "c"]));
        assert_eq!(g.neighbor_count(), 3);
        assert!(g.is_spiral_neighbor("a"));
        assert!(g.is_spiral_neighbor("b"));
        assert!(g.is_spiral_neighbor("c"));

        // Replace with smaller set
        g.set_spiral_neighbors(neighbors_set(&["x"]));
        assert_eq!(g.neighbor_count(), 1);
        assert!(!g.is_spiral_neighbor("a"));
        assert!(g.is_spiral_neighbor("x"));
    }

    // 3. is_spiral_neighbor
    #[test]
    fn test_is_spiral_neighbor() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["alpha"]));
        assert!(g.is_spiral_neighbor("alpha"));
        assert!(!g.is_spiral_neighbor("beta"));
    }

    // 5. neighbor_count
    #[test]
    fn test_neighbor_count() {
        let mut g = make_gossip();
        assert_eq!(g.neighbor_count(), 0);
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        assert_eq!(g.neighbor_count(), 2);
    }

    // 6. on_proof_updated sends HaveList to all due neighbors
    #[test]
    fn test_on_proof_updated_sends_to_all_due() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));

        let spore_bytes = b"fake-spore";
        let actions = g.on_proof_updated(10_000, spore_bytes);

        assert_eq!(actions.len(), 2);
        let mut peer_ids: Vec<&str> = actions
            .iter()
            .map(|a| match a {
                SyncAction::SendHaveList {
                    neighbor_peer_id, ..
                } => neighbor_peer_id.as_str(),
                _ => panic!("expected SendHaveList"),
            })
            .collect();
        peer_ids.sort();
        assert_eq!(peer_ids, vec!["a", "b"]);
    }

    // 7. on_proof_updated skips recently-synced neighbors
    #[test]
    fn test_on_proof_updated_skips_recent() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));

        // First round syncs both at t=0
        let _ = g.on_proof_updated(0, b"s");

        // Second round at t=3000 — within 5000ms interval, both skipped.
        let actions = g.on_proof_updated(3000, b"s");
        assert!(actions.is_empty());

        // Third round at t=5000 — exactly at interval, both due.
        let actions = g.on_proof_updated(5000, b"s");
        assert_eq!(actions.len(), 2);
    }

    // 8. on_proof_updated returns empty when no neighbors
    #[test]
    fn test_on_proof_updated_no_neighbors() {
        let mut g = make_gossip();
        let actions = g.on_proof_updated(0, b"s");
        assert!(actions.is_empty());
    }

    // 9. neighbors_needing_sync — all returned if never synced
    #[test]
    fn test_neighbors_needing_sync_all() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b", "c"]));
        let mut due = g.neighbors_needing_sync(0);
        due.sort();
        assert_eq!(due, vec!["a", "b", "c"]);
    }

    // 11. neighbors_needing_sync — none if all recently synced
    #[test]
    fn test_neighbors_needing_sync_none() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        g.mark_synced("a", 1000);
        g.mark_synced("b", 1000);

        let due = g.neighbors_needing_sync(2000);
        assert!(due.is_empty());
    }

    // 12. neighbors_needing_sync — partial mix
    #[test]
    fn test_neighbors_needing_sync_partial() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        g.mark_synced("a", 1000);
        // "b" never synced

        // At t=2000, only "b" is due (a synced 1s ago, interval is 5s)
        let due = g.neighbors_needing_sync(2000);
        assert_eq!(due, vec!["b"]);
    }

    // 13. mark_synced updates timestamp
    #[test]
    fn test_mark_synced() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a"]));
        g.mark_synced("a", 42);
        assert_eq!(*g.last_sync.get("a").unwrap(), 42);

        g.mark_synced("a", 99);
        assert_eq!(*g.last_sync.get("a").unwrap(), 99);
    }

    // 14. set_neighbors_clears_stale_sync
    #[test]
    fn test_set_neighbors_clears_stale_sync() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        g.mark_synced("a", 100);
        g.mark_synced("b", 100);

        // Remove "b" from neighbors
        g.set_spiral_neighbors(neighbors_set(&["a"]));
        assert!(g.last_sync.contains_key("a"));
        assert!(!g.last_sync.contains_key("b"));
    }

    // 15. on_have_list_received returns ProofDelta with missing proofs
    #[test]
    fn test_on_have_list_with_diff() {
        let g = make_gossip();

        // Build a SPORE covering a specific content_id
        let content_id: [u8; 32] = blake3::hash(b"test proof data").into();
        let u = U256::from_be_bytes(&content_id);
        let next = u
            .checked_add(&U256::from_u64(1))
            .unwrap_or(U256::MAX);
        let our_spore =
            Spore::from_range(Range256::new(u, next));

        // Their SPORE is empty — they have nothing.
        let their_spore = Spore::empty();
        let their_bytes = bincode::serialize(&their_spore).unwrap();

        let proof_entry = b"serialized-proof-entry".to_vec();
        let our_proof_data: Vec<(Vec<u8>, [u8; 32])> =
            vec![(proof_entry.clone(), content_id)];

        let action = g
            .on_have_list_received("peer_x", &their_bytes, &our_spore, &our_proof_data)
            .expect("should produce a ProofDelta");

        match action {
            SyncAction::SendProofDelta {
                neighbor_peer_id,
                message,
            } => {
                assert_eq!(neighbor_peer_id, "peer_x");
                match message {
                    SyncMessage::ProofDelta { entries } => {
                        assert_eq!(entries.len(), 1);
                        assert_eq!(entries[0], proof_entry);
                    }
                    _ => panic!("expected ProofDelta message"),
                }
            }
            _ => panic!("expected SendProofDelta action"),
        }
    }

    // 16. on_have_list_received returns None when peer already has everything
    #[test]
    fn test_on_have_list_synced() {
        let g = make_gossip();

        let content_id: [u8; 32] = blake3::hash(b"another proof").into();
        let u = U256::from_be_bytes(&content_id);
        let next = u
            .checked_add(&U256::from_u64(1))
            .unwrap_or(U256::MAX);
        let our_spore =
            Spore::from_range(Range256::new(u, next));

        // Their SPORE covers the same range — they already have it.
        let their_bytes = bincode::serialize(&our_spore).unwrap();

        let our_proof_data: Vec<(Vec<u8>, [u8; 32])> =
            vec![(b"entry".to_vec(), content_id)];

        let result = g.on_have_list_received(
            "peer_x",
            &their_bytes,
            &our_spore,
            &our_proof_data,
        );
        assert!(result.is_none());
    }

    // 17. SyncMessage serde roundtrip (JSON)
    #[test]
    fn test_sync_message_serde_roundtrip() {
        let msg = SyncMessage::HaveList {
            spore_bytes: vec![1, 2, 3, 4],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let decoded: SyncMessage = serde_json::from_str(&json).unwrap();
        match decoded {
            SyncMessage::HaveList { spore_bytes } => {
                assert_eq!(spore_bytes, vec![1, 2, 3, 4]);
            }
            _ => panic!("expected HaveList"),
        }

        let msg2 = SyncMessage::ProofDelta {
            entries: vec![vec![10, 20], vec![30]],
        };
        let json2 = serde_json::to_string(&msg2).unwrap();
        let decoded2: SyncMessage = serde_json::from_str(&json2).unwrap();
        match decoded2 {
            SyncMessage::ProofDelta { entries } => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], vec![10, 20]);
                assert_eq!(entries[1], vec![30]);
            }
            _ => panic!("expected ProofDelta"),
        }
    }
}
