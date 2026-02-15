//! Event-driven SPIRAL-scoped liveness gossip coordinator.
//!
//! Unlike latency/connection gossip which use periodic sync intervals,
//! liveness gossip is FULLY EVENT-DRIVEN. Every state change pushes
//! immediately to ALL SPIRAL neighbors. No timer. No rate limit.
//!
//! Propagation speed = MIN_LATENCY × HOPS, not RTT × HOPS.
//! Each hop is one-way: push bitmap → merge → push to next neighbor.
//! A 5-hop mesh converges in ~250ms cross-continent.

use std::collections::HashSet;

use citadel_spore::{Spore, U256};
use serde::{Deserialize, Serialize};

/// Wire message for liveness gossip between SPIRAL neighbors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SyncMessage {
    /// "Here's my SPORE state — send me attestations I'm missing"
    HaveList { spore_bytes: Vec<u8> },
    /// "Here are the liveness attestations you're missing"
    LivenessDelta { entries: Vec<Vec<u8>> },
}

/// Action for federation.rs to execute.
#[derive(Debug, Clone)]
pub enum SyncAction {
    /// Send a HaveList to this neighbor to initiate reconciliation.
    SendHaveList {
        neighbor_peer_id: String,
        message: SyncMessage,
    },
    /// Send liveness attestation deltas to this neighbor.
    SendLivenessDelta {
        neighbor_peer_id: String,
        message: SyncMessage,
    },
}

/// Event-driven SPIRAL-scoped liveness gossip coordinator.
///
/// No timers. No sync intervals. Every state change pushes immediately
/// to ALL SPIRAL neighbors. Convergence = MIN_LATENCY × HOPS.
#[derive(Debug)]
pub struct LivenessGossip {
    spiral_neighbors: HashSet<String>,
}

impl LivenessGossip {
    /// Create a new liveness gossip coordinator.
    ///
    /// The `_sync_interval_ms` parameter is accepted for API compatibility
    /// but ignored — liveness gossip is fully event-driven.
    pub fn new(_sync_interval_ms: i64) -> Self {
        Self {
            spiral_neighbors: HashSet::new(),
        }
    }

    /// Replace the SPIRAL neighbor set (called when topology changes).
    pub fn set_spiral_neighbors(&mut self, neighbors: HashSet<String>) {
        self.spiral_neighbors = neighbors;
    }

    /// Build propagation actions for the current bitmap state.
    ///
    /// Returns [`SyncAction`]s for ALL SPIRAL neighbors — no rate limit.
    /// Every state change propagates immediately.
    pub fn propagate(
        &self,
        our_spore_bytes: &[u8],
    ) -> Vec<SyncAction> {
        self.spiral_neighbors
            .iter()
            .map(|peer_id| SyncAction::SendHaveList {
                neighbor_peer_id: peer_id.clone(),
                message: SyncMessage::HaveList {
                    spore_bytes: our_spore_bytes.to_vec(),
                },
            })
            .collect()
    }

    /// Called when we receive a `HaveList` from a neighbor.
    ///
    /// Returns a `SendLivenessDelta` action if we have attestations they're missing.
    pub fn on_have_list_received(
        &self,
        from_peer_id: &str,
        their_spore_bytes: &[u8],
        our_spore: &Spore,
        our_attestation_data: &[(Vec<u8>, [u8; 32])],
    ) -> Option<SyncAction> {
        let their_spore: Spore = match bincode::deserialize(their_spore_bytes) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let diff = our_spore.subtract(&their_spore);
        if diff.is_empty() {
            return None;
        }

        let entries: Vec<Vec<u8>> = our_attestation_data
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

        Some(SyncAction::SendLivenessDelta {
            neighbor_peer_id: from_peer_id.to_owned(),
            message: SyncMessage::LivenessDelta { entries },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_spore::{Range256, Spore, U256};

    fn make_gossip() -> LivenessGossip {
        LivenessGossip::new(0) // interval ignored — event-driven
    }

    fn neighbors_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn test_new_empty() {
        let g = make_gossip();
        assert!(g.spiral_neighbors.is_empty());
    }

    #[test]
    fn test_set_spiral_neighbors() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        assert_eq!(g.spiral_neighbors.len(), 2);

        g.set_spiral_neighbors(neighbors_set(&["x"]));
        assert_eq!(g.spiral_neighbors.len(), 1);
    }

    #[test]
    fn test_propagate_sends_to_all() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));

        let actions = g.propagate(b"fake-spore");
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_propagate_no_rate_limit() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a"]));

        // Event-driven: EVERY call propagates to ALL neighbors. No rate limit.
        let actions = g.propagate(b"s");
        assert_eq!(actions.len(), 1);
        let actions = g.propagate(b"s");
        assert_eq!(actions.len(), 1);
        let actions = g.propagate(b"s");
        assert_eq!(actions.len(), 1);
    }

    #[test]
    fn test_on_have_list_with_diff() {
        let g = make_gossip();

        let content_id: [u8; 32] = blake3::hash(b"test data").into();
        let u = U256::from_be_bytes(&content_id);
        let next = u.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
        let our_spore = Spore::from_range(Range256::new(u, next));

        let their_spore = Spore::empty();
        let their_bytes = bincode::serialize(&their_spore).unwrap();

        let our_data: Vec<(Vec<u8>, [u8; 32])> = vec![(b"attestation".to_vec(), content_id)];

        let action = g
            .on_have_list_received("peer_x", &their_bytes, &our_spore, &our_data)
            .expect("should produce a LivenessDelta");

        match action {
            SyncAction::SendLivenessDelta { neighbor_peer_id, message } => {
                assert_eq!(neighbor_peer_id, "peer_x");
                match message {
                    SyncMessage::LivenessDelta { entries } => {
                        assert_eq!(entries.len(), 1);
                    }
                    _ => panic!("expected LivenessDelta"),
                }
            }
            _ => panic!("expected SendLivenessDelta"),
        }
    }

    #[test]
    fn test_on_have_list_synced() {
        let g = make_gossip();

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
    fn test_set_neighbors_replaces() {
        let mut g = make_gossip();
        g.set_spiral_neighbors(neighbors_set(&["a", "b"]));
        assert_eq!(g.spiral_neighbors.len(), 2);

        g.set_spiral_neighbors(neighbors_set(&["a"]));
        assert_eq!(g.spiral_neighbors.len(), 1);
        assert!(g.spiral_neighbors.contains("a"));
        assert!(!g.spiral_neighbors.contains("b"));
    }
}
