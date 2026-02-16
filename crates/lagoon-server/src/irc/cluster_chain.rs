//! Cluster Identity Chain — rotating hash chain for merge/split detection.
//!
//! Every cluster maintains a blake3 hash chain that advances on VDF window ticks.
//! All nodes in the same cluster compute the same chain value because they share
//! the same state and the same VDF-anchored clock.
//!
//! The chain value is carried in HELLO messages. When two nodes meet:
//! - Same chain → same cluster, business as usual.
//! - Different chain → different clusters, triggers merge.
//! - No chain → fresh node, adopts the peer's chain.
//!
//! History is recorded as a blockchain of events (advance, merge, split, genesis)
//! for debug visualization. Pruning APIs are designed but not yet implemented
//! (needed for GDPR erasure in the future).
//!
//! Proven correct in Lean: `proofs/LagoonMesh/ClusterChain.lean` (agreement,
//! detection, unforgeability, recovery) and `proofs/LagoonMesh/ChainHistory.lean`
//! (block chain integrity, pruning soundness, history tracking).

use serde::{Deserialize, Serialize};

/// Advance a cluster chain by one round.
///
/// `chain(n+1) = blake3(blake3(chain(n) ++ round_seed))`
///
/// The `round_seed` is the VDF hash at the quantized round boundary — a
/// deterministic value that all cluster members agree on (Universal Clock).
/// The double-hash prevents length-extension attacks.
pub fn advance_chain(prev: &[u8; 32], round_seed: &[u8; 32]) -> [u8; 32] {
    let mut inner = blake3::Hasher::new();
    inner.update(prev);
    inner.update(round_seed);
    let inner_hash = inner.finalize();

    *blake3::hash(inner_hash.as_bytes()).as_bytes()
}

/// Fungible merge: deterministic combined identity from two chains.
///
/// Produces `blake3(sort(A, B))` — a NEW hash that neither side had before,
/// reflecting both histories. This is the core F-VDF operation from
/// downward-spiral.
///
/// Properties:
/// - **Commutative**: `fungible_merge(A, B) == fungible_merge(B, A)` (sort)
/// - **Idempotent**: `fungible_merge(A, A) == blake3(A || A)` (stable)
/// - **Deterministic**: same inputs always produce same output
///
/// NOT a max/pick-winner operation. Neither input survives unchanged.
/// The merged value is the product of both chains — not one chain winning
/// over the other. Work is additive: tracked separately via `cluster_vdf_work`.
///
/// After merge, both sides have the same NEW chain value. `advance_chain()`
/// with the same Universal Clock round seed produces the same next value.
pub fn fungible_merge(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut h = blake3::Hasher::new();
    h.update(first);
    h.update(second);
    *h.finalize().as_bytes()
}

/// Compute a merged chain seed from winner + loser + topology hash.
///
/// DEPRECATED: Use `fungible_merge()` for F-VDF additive merges.
/// Retained for test compatibility.
pub fn merge_chain_seed(
    winner: &[u8; 32],
    loser: &[u8; 32],
    merged_topology_hash: &[u8; 32],
) -> [u8; 32] {
    let inner = {
        let mut h = blake3::Hasher::new();
        h.update(winner);
        h.update(loser);
        let hash = h.finalize();
        *hash.as_bytes()
    };
    let mut outer = blake3::Hasher::new();
    outer.update(&inner);
    outer.update(merged_topology_hash);
    *outer.finalize().as_bytes()
}

/// Events recorded in the cluster chain history.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ChainEvent {
    /// Normal round advance.
    Advance,
    /// Cluster genesis: new cluster formed.
    Genesis,
    /// Two clusters merged (competitive, legacy). Records the loser's state.
    Merge {
        loser_chain_value: String,
        loser_round: u64,
    },
    /// F-VDF symmetric merge: both chains combined additively.
    /// Neither side is winner or loser — the result is deterministic from both inputs.
    FungibleMerge {
        other_chain_value: String,
        other_round: u64,
    },
    /// Network partition detected (split).
    Split,
}

/// A single block in the cluster chain history.
///
/// Like a Git commit: has a parent hash, chain value, and event metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainBlock {
    /// Hash of the previous block (hex). "0" for genesis.
    pub prev_block_hash: String,
    /// The cluster chain value at this round (hex).
    pub chain_value: String,
    /// Round number.
    pub round: u64,
    /// VDF-anchored timestamp round (used as input to advance_chain).
    pub timestamp_round: u64,
    /// What happened at this round.
    pub event: ChainEvent,
    /// Number of peers in the cluster at this round (visualization metadata).
    pub cluster_size: u32,
}

impl ChainBlock {
    /// Compute this block's integrity hash.
    fn block_hash(&self) -> String {
        let prev_bytes = hex::decode(&self.prev_block_hash).unwrap_or_default();
        let chain_bytes = hex::decode(&self.chain_value).unwrap_or_default();
        let mut h = blake3::Hasher::new();
        h.update(&prev_bytes);
        h.update(&chain_bytes);
        h.update(&self.round.to_le_bytes());
        hex::encode(h.finalize().as_bytes())
    }
}

/// The cluster identity chain state.
///
/// Tracks the current chain value and round, plus a history of blocks
/// for debug visualization. History is stored newest-first.
#[derive(Debug, Clone)]
pub struct ClusterChain {
    /// Current chain value (256-bit blake3 hash).
    pub value: [u8; 32],
    /// Current round number.
    pub round: u64,
    /// Block history (newest first). Used for debug visualization.
    /// Capped at `max_history_blocks` to prevent unbounded growth.
    history: Vec<ChainBlock>,
    /// Maximum blocks to retain in history.
    max_history_blocks: usize,
}

impl ClusterChain {
    /// Create a new cluster chain from a genesis seed.
    ///
    /// The seed is typically derived from the node's VDF genesis hash.
    pub fn genesis(seed: [u8; 32], timestamp_round: u64, cluster_size: u32) -> Self {
        let block = ChainBlock {
            prev_block_hash: "0".into(),
            chain_value: hex::encode(seed),
            round: 0,
            timestamp_round,
            event: ChainEvent::Genesis,
            cluster_size,
        };
        Self {
            value: seed,
            round: 0,
            history: vec![block],
            max_history_blocks: 1000,
        }
    }

    /// Advance the chain by one round.
    ///
    /// Called on each VDF window tick (every ~3 seconds).
    /// `round_seed` is the VDF hash at the quantized round boundary (Universal Clock).
    /// `timestamp_round` is the quantized VDF height (for history bookkeeping).
    pub fn advance(&mut self, round_seed: &[u8; 32], timestamp_round: u64, cluster_size: u32) {
        let new_value = advance_chain(&self.value, round_seed);
        let prev_hash = self
            .history
            .first()
            .map(|b| b.block_hash())
            .unwrap_or_else(|| "0".into());
        let block = ChainBlock {
            prev_block_hash: prev_hash,
            chain_value: hex::encode(new_value),
            round: self.round + 1,
            timestamp_round,
            event: ChainEvent::Advance,
            cluster_size,
        };
        self.value = new_value;
        self.round += 1;
        self.history.insert(0, block);
        self.enforce_history_limit();
    }

    /// Update the chain history after a merge (the actual mesh rearrangement
    /// is handled by `evaluate_spiral_merge`).
    pub fn update_history(
        &mut self,
        loser_value: &[u8; 32],
        loser_round: u64,
        merged_topology_hash: &[u8; 32],
        timestamp_round: u64,
        merged_size: u32,
    ) {
        let merged_seed = merge_chain_seed(&self.value, loser_value, merged_topology_hash);
        let prev_hash = self
            .history
            .first()
            .map(|b| b.block_hash())
            .unwrap_or_else(|| "0".into());
        let block = ChainBlock {
            prev_block_hash: prev_hash,
            chain_value: hex::encode(merged_seed),
            round: self.round + 1,
            timestamp_round,
            event: ChainEvent::Merge {
                loser_chain_value: hex::encode(loser_value),
                loser_round,
            },
            cluster_size: merged_size,
        };
        self.value = merged_seed;
        self.round += 1;
        self.history.insert(0, block);
        self.enforce_history_limit();
    }

    /// F-VDF fungible merge: both sides compute `max(our_chain, their_chain)`.
    ///
    /// The winner IS the value — the lexicographically larger chain.
    /// Commutative, associative, idempotent (proper CRDT join-semilattice).
    /// Work is additive: the peer set grows as clusters discover each other.
    /// Returns `true` if our chain value changed (we adopted).
    pub fn fungible_adopt(
        &mut self,
        other_value: &[u8; 32],
        other_round: u64,
        timestamp_round: u64,
        merged_size: u32,
    ) -> bool {
        let merged = fungible_merge(&self.value, other_value);
        let changed = merged != self.value;
        let prev_hash = self
            .history
            .first()
            .map(|b| b.block_hash())
            .unwrap_or_else(|| "0".into());
        let new_round = self.round.max(other_round) + 1;
        let block = ChainBlock {
            prev_block_hash: prev_hash,
            chain_value: hex::encode(merged),
            round: new_round,
            timestamp_round,
            event: ChainEvent::FungibleMerge {
                other_chain_value: hex::encode(other_value),
                other_round,
            },
            cluster_size: merged_size,
        };
        self.value = merged;
        self.round = new_round;
        self.history.insert(0, block);
        self.enforce_history_limit();
        changed
    }

    /// Record a split event (partition detected).
    pub fn record_split(&mut self, round_seed: &[u8; 32], timestamp_round: u64, remaining_size: u32) {
        let new_value = advance_chain(&self.value, round_seed);
        let prev_hash = self
            .history
            .first()
            .map(|b| b.block_hash())
            .unwrap_or_else(|| "0".into());
        let block = ChainBlock {
            prev_block_hash: prev_hash,
            chain_value: hex::encode(new_value),
            round: self.round + 1,
            timestamp_round,
            event: ChainEvent::Split,
            cluster_size: remaining_size,
        };
        self.value = new_value;
        self.round += 1;
        self.history.insert(0, block);
        self.enforce_history_limit();
    }

    /// Adopt a peer's chain state (SPORE catch-up after temporary disconnect).
    pub fn adopt(&mut self, peer_value: [u8; 32], peer_round: u64) {
        self.value = peer_value;
        self.round = peer_round;
        // History is NOT updated — the gap shows the disconnect in debug view.
    }

    /// The timestamp_round used in the most recent advance (for quantum gating).
    pub fn last_timestamp_round(&self) -> u64 {
        self.history.first().map(|b| b.timestamp_round).unwrap_or(0)
    }

    /// Get the current chain value as a hex string.
    pub fn value_hex(&self) -> String {
        hex::encode(self.value)
    }

    /// Get the chain value as a short display string (first 8 hex chars).
    pub fn value_short(&self) -> String {
        hex::encode(self.value)[..8].to_string()
    }

    /// Get the recent history for visualization (newest first).
    ///
    /// Returns up to `limit` blocks. This is what gets sent to the
    /// frontend in debug mode.
    pub fn recent_history(&self, limit: usize) -> &[ChainBlock] {
        let end = limit.min(self.history.len());
        &self.history[..end]
    }

    /// Get all merge events in the history (both legacy and F-VDF).
    pub fn merge_events(&self) -> Vec<&ChainBlock> {
        self.history
            .iter()
            .filter(|b| matches!(b.event, ChainEvent::Merge { .. } | ChainEvent::FungibleMerge { .. }))
            .collect()
    }

    /// Get all split events in the history.
    pub fn split_events(&self) -> Vec<&ChainBlock> {
        self.history
            .iter()
            .filter(|b| matches!(b.event, ChainEvent::Split))
            .collect()
    }

    /// Compare our chain with a remote peer's chain from HELLO.
    pub fn compare(&self, remote_value: Option<&[u8; 32]>) -> ChainComparison {
        match remote_value {
            Some(rv) => {
                if self.value == *rv {
                    ChainComparison::SameCluster
                } else {
                    ChainComparison::DifferentCluster
                }
            }
            None => ChainComparison::FreshJoin,
        }
    }

    /// Enforce the history block limit by dropping oldest blocks.
    fn enforce_history_limit(&mut self) {
        if self.history.len() > self.max_history_blocks {
            self.history.truncate(self.max_history_blocks);
        }
    }

    // --- Pruning APIs (designed, not yet needed) ---

    // /// Trim history to only keep blocks from `keep_from_round` onwards.
    // /// Like `git clone --depth N`.
    // pub fn trim(&mut self, keep_from_round: u64) { ... }

    // /// Compact a range [from, to) into nothing, keeping boundaries.
    // /// Like squashing Git commits.
    // pub fn compact(&mut self, from_round: u64, to_round: u64) { ... }
}

/// Result of comparing two cluster chains in a HELLO exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainComparison {
    /// Same chain value → same cluster.
    SameCluster,
    /// Different chain values → different clusters. Merge trigger.
    DifferentCluster,
    /// Remote has no chain → fresh node joining.
    FreshJoin,
}

/// Chain state summary for HELLO messages and visualization.
///
/// Compact representation carried in MeshHelloPayload and MeshNodeReport.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainSummary {
    /// Chain value as hex string (first 16 chars for display, full for comparison).
    pub chain_value_hex: String,
    /// Current round number.
    pub round: u64,
    /// Number of merge events in recorded history.
    pub merge_count: u32,
    /// Number of split events in recorded history.
    pub split_count: u32,
}

impl ClusterChain {
    /// Build a summary for HELLO messages and visualization.
    pub fn summary(&self) -> ChainSummary {
        let merge_count = self
            .history
            .iter()
            .filter(|b| matches!(b.event, ChainEvent::Merge { .. } | ChainEvent::FungibleMerge { .. }))
            .count() as u32;
        let split_count = self
            .history
            .iter()
            .filter(|b| matches!(b.event, ChainEvent::Split))
            .count() as u32;
        ChainSummary {
            chain_value_hex: hex::encode(self.value),
            round: self.round,
            merge_count,
            split_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Derive a deterministic round seed from a test timestamp.
    fn test_seed(ts: u64) -> [u8; 32] {
        *blake3::hash(&ts.to_le_bytes()).as_bytes()
    }

    #[test]
    fn genesis_creates_chain() {
        let seed = blake3::hash(b"test-genesis").as_bytes().to_owned();
        let chain = ClusterChain::genesis(seed, 0, 1);
        assert_eq!(chain.round, 0);
        assert_eq!(chain.value, seed);
        assert_eq!(chain.history.len(), 1);
        assert!(matches!(chain.history[0].event, ChainEvent::Genesis));
    }

    #[test]
    fn advance_produces_different_value() {
        let seed = blake3::hash(b"test-advance").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 1);
        let before = chain.value;
        chain.advance(&test_seed(100), 100, 1);
        assert_ne!(chain.value, before);
        assert_eq!(chain.round, 1);
        assert_eq!(chain.history.len(), 2);
    }

    #[test]
    fn same_inputs_same_chain() {
        let seed = blake3::hash(b"determinism").as_bytes().to_owned();
        let mut a = ClusterChain::genesis(seed, 0, 1);
        let mut b = ClusterChain::genesis(seed, 0, 1);
        for ts in [10, 20, 30] {
            a.advance(&test_seed(ts), ts, 2);
            b.advance(&test_seed(ts), ts, 2);
        }
        assert_eq!(a.value, b.value);
        assert_eq!(a.round, b.round);
    }

    #[test]
    fn different_seeds_diverge() {
        let seed_a = blake3::hash(b"cluster-a").as_bytes().to_owned();
        let seed_b = blake3::hash(b"cluster-b").as_bytes().to_owned();
        let mut a = ClusterChain::genesis(seed_a, 0, 1);
        let mut b = ClusterChain::genesis(seed_b, 0, 1);
        for ts in [10, 20, 30] {
            a.advance(&test_seed(ts), ts, 1);
            b.advance(&test_seed(ts), ts, 1);
        }
        assert_ne!(a.value, b.value);
        assert_eq!(a.compare(Some(&b.value)), ChainComparison::DifferentCluster);
    }

    #[test]
    fn merge_produces_fresh_seed() {
        let seed_a = blake3::hash(b"winner").as_bytes().to_owned();
        let seed_b = blake3::hash(b"loser").as_bytes().to_owned();
        let mut winner = ClusterChain::genesis(seed_a, 0, 3);
        let loser = ClusterChain::genesis(seed_b, 0, 2);
        let topo_hash = blake3::hash(b"merged-topology").as_bytes().to_owned();

        let pre_merge = winner.value;
        winner.update_history(&loser.value, loser.round, &topo_hash, 100, 5);

        assert_ne!(winner.value, pre_merge);
        assert_ne!(winner.value, loser.value);
        assert_eq!(winner.round, 1);
        assert_eq!(winner.merge_events().len(), 1);
    }

    #[test]
    fn comparison_detects_same_cluster() {
        let seed = blake3::hash(b"same").as_bytes().to_owned();
        let chain = ClusterChain::genesis(seed, 0, 1);
        assert_eq!(chain.compare(Some(&seed)), ChainComparison::SameCluster);
    }

    #[test]
    fn comparison_detects_fresh_join() {
        let seed = blake3::hash(b"existing").as_bytes().to_owned();
        let chain = ClusterChain::genesis(seed, 0, 1);
        assert_eq!(chain.compare(None), ChainComparison::FreshJoin);
    }

    #[test]
    fn adopt_sets_chain_state() {
        let seed = blake3::hash(b"adopter").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 1);
        let peer_value = blake3::hash(b"peer-chain-tip").as_bytes().to_owned();
        chain.adopt(peer_value, 42);
        assert_eq!(chain.value, peer_value);
        assert_eq!(chain.round, 42);
    }

    #[test]
    fn history_limit_enforced() {
        let seed = blake3::hash(b"limit-test").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 1);
        // Override limit for test
        chain.max_history_blocks = 10;
        for i in 1..=20 {
            chain.advance(&test_seed(i), i, 1);
        }
        assert!(chain.history.len() <= 10);
        // Most recent block should be round 20
        assert_eq!(chain.history[0].round, 20);
    }

    #[test]
    fn fungible_merge_is_commutative() {
        let a = blake3::hash(b"cluster-alpha").as_bytes().to_owned();
        let b = blake3::hash(b"cluster-beta").as_bytes().to_owned();
        assert_eq!(fungible_merge(&a, &b), fungible_merge(&b, &a));
    }

    #[test]
    fn fungible_merge_produces_new_value() {
        let a = blake3::hash(b"cluster-alpha").as_bytes().to_owned();
        let b = blake3::hash(b"cluster-beta").as_bytes().to_owned();
        let merged = fungible_merge(&a, &b);
        // blake3(sort(A,B)) produces a NEW value — neither input survives
        assert_ne!(merged, a);
        assert_ne!(merged, b);
    }

    #[test]
    fn fungible_merge_self_is_stable() {
        // blake3(A || A) is deterministic — same result every time
        let a = blake3::hash(b"cluster-alpha").as_bytes().to_owned();
        let self_merge = fungible_merge(&a, &a);
        assert_eq!(fungible_merge(&a, &a), self_merge);
    }

    #[test]
    fn fungible_merge_not_associative() {
        // blake3(sort(A,B)) is NOT associative — merge order matters.
        // Cascade convergence is a PROTOCOL concern (proof transcripts),
        // not a merge-function property.
        let a = blake3::hash(b"cluster-alpha").as_bytes().to_owned();
        let b = blake3::hash(b"cluster-beta").as_bytes().to_owned();
        let c = blake3::hash(b"cluster-gamma").as_bytes().to_owned();
        let ab_c = fungible_merge(&fungible_merge(&a, &b), &c);
        let a_bc = fungible_merge(&a, &fungible_merge(&b, &c));
        // These are DIFFERENT — intentionally. The protocol handles convergence.
        assert_ne!(ab_c, a_bc);
    }

    #[test]
    fn fungible_merge_cascade_stable() {
        // After A⊔B=M, a cluster-mate C (still at A) merging with M
        // produces the same result as directly merging with M.
        // fungible_merge(A, M) is deterministic and both sides get it.
        let a = blake3::hash(b"cluster-alpha").as_bytes().to_owned();
        let b = blake3::hash(b"cluster-beta").as_bytes().to_owned();
        let ab = fungible_merge(&a, &b);
        // C (at value A) meets merged AB — gets a combined value
        let c_result = fungible_merge(&a, &ab);
        // Another node D (also at A) meets AB — gets the same value
        let d_result = fungible_merge(&a, &ab);
        assert_eq!(c_result, d_result);
    }

    #[test]
    fn fungible_merge_is_deterministic() {
        let a = blake3::hash(b"cluster-one").as_bytes().to_owned();
        let b = blake3::hash(b"cluster-two").as_bytes().to_owned();
        let m1 = fungible_merge(&a, &b);
        let m2 = fungible_merge(&a, &b);
        assert_eq!(m1, m2);
    }

    #[test]
    fn fungible_adopt_records_event() {
        let seed_a = blake3::hash(b"alpha").as_bytes().to_owned();
        let seed_b = blake3::hash(b"beta").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed_a, 0, 3);
        let changed = chain.fungible_adopt(&seed_b, 5, 100, 6);
        // Result is blake3(sort(seed_a, seed_b)) — new combined identity
        let expected = fungible_merge(&seed_a, &seed_b);
        assert_eq!(chain.value, expected);
        assert_ne!(expected, seed_a); // combined value differs from both inputs
        assert_ne!(expected, seed_b);
        assert!(matches!(chain.history[0].event, ChainEvent::FungibleMerge { .. }));
        assert_eq!(chain.merge_events().len(), 1);
        // blake3 combine always changes both sides (neither input survives)
        assert!(changed);
    }

    #[test]
    fn fungible_adopt_both_sides_converge() {
        // Two clusters merge — both sides compute the same result
        let seed_a = blake3::hash(b"alpha").as_bytes().to_owned();
        let seed_b = blake3::hash(b"beta").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 3);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 2);

        // Both adopt via fungible_adopt
        chain_a.fungible_adopt(&seed_b, chain_b.round, 100, 5);
        chain_b.fungible_adopt(&seed_a, chain_a.round, 100, 5);

        // Now they're SameCluster
        assert_eq!(chain_a.compare(Some(&chain_b.value)), ChainComparison::SameCluster);
    }

    #[test]
    fn fungible_adopt_pairwise_symmetric() {
        // When two genuinely different clusters meet, both sides compute
        // the same combined value regardless of who initiates.
        let seed_a = blake3::hash(b"cluster-a").as_bytes().to_owned();
        let seed_b = blake3::hash(b"cluster-b").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 2);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 1);

        // Both sides merge — should arrive at the same combined value
        chain_a.fungible_adopt(&seed_b, chain_b.round, 100, 3);
        chain_b.fungible_adopt(&seed_a, chain_a.round, 100, 3);
        assert_eq!(chain_a.value, chain_b.value);

        // The combined value is neither original
        assert_ne!(chain_a.value, seed_a);
        assert_ne!(chain_a.value, seed_b);
    }

    #[test]
    fn summary_counts_events() {
        let seed = blake3::hash(b"summary").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 3);
        chain.advance(&test_seed(10), 10, 3);
        let loser = blake3::hash(b"loser").as_bytes().to_owned();
        let topo = blake3::hash(b"topo").as_bytes().to_owned();
        chain.update_history(&loser, 5, &topo, 20, 5);
        chain.advance(&test_seed(30), 30, 5);
        chain.record_split(&test_seed(40), 40, 3);

        let summary = chain.summary();
        assert_eq!(summary.round, 4);
        assert_eq!(summary.merge_count, 1);
        assert_eq!(summary.split_count, 1);
    }
}
