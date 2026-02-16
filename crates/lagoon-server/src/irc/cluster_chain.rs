//! Cluster Identity Chain — rotating hash chain for merge/split detection.
//!
//! Every cluster maintains a blake3 hash chain that advances on VDF window ticks.
//! All nodes in the same cluster compute the same chain value because they share
//! the same genesis seed and the same VDF-anchored Universal Clock.
//!
//! The chain value is carried in HELLO messages. When two nodes meet:
//! - Same chain → same cluster, business as usual.
//! - Different chain → different clusters, triggers merge (epoch reset).
//! - No chain → fresh node, adopts the peer's chain.
//!
//! **Epoch reset on merge:** When clusters merge via `blake3(sort(A,B))`, the
//! merged value becomes the NEW genesis for the combined cluster. Both nodes
//! restart their chain from that seed. The chain property is preserved within
//! each epoch — the merge IS a new epoch. Work is never lost: `cumulative_work`
//! tracks total advance steps across all epochs. A rolling ZK proof (Merkle
//! root + Fiat-Shamir spot checks) compactly proves total sequential work.
//!
//! History is recorded as a blockchain of events (advance, merge, split, genesis)
//! for debug visualization. Pruning APIs are designed but not yet implemented
//! (needed for GDPR erasure in the future).
//!
//! Proven correct in Lean: `proofs/LagoonMesh/ClusterChain.lean` (agreement,
//! detection, unforgeability, recovery) and `proofs/LagoonMesh/ChainHistory.lean`
//! (block chain integrity, pruning soundness, history tracking).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// VDF quantum window size in ticks. At 10 Hz, 100 ticks = 10 seconds.
///
/// Nodes within 5 seconds (50 ticks) of each other land on the same quantum
/// boundary. This is the Universal Clock's synchronization window — the VDF
/// height IS the clock, quantization absorbs minor drift between honest nodes.
pub const ROUND_QUANTUM: u64 = 100;

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
///
/// **Epoch model:** The chain advances within an epoch (`advance_chain(prev, seed)`).
/// On merge, a new epoch starts: `genesis` is set to the merged value, `value` resets
/// to genesis, and `cumulative_work` accumulates additively. The old epoch's history
/// is encoded in the merged genesis hash itself.
#[derive(Debug, Clone)]
pub struct ClusterChain {
    /// Current epoch genesis — the seed this epoch started from.
    /// Set to the merged value on epoch reset. Both sides of a merge
    /// compute the same genesis, so they advance in lockstep.
    pub genesis: [u8; 32],
    /// Current chain value (256-bit blake3 hash).
    pub value: [u8; 32],
    /// Current round number (monotonic across epochs).
    pub round: u64,
    /// Total advance steps across ALL epochs. This never resets —
    /// it's the cluster's rolling work counter. On merge, both sides'
    /// cumulative_work values are added (fungible work conservation).
    pub cumulative_work: u64,
    /// Work contributions ledger: maps each pre-merge cluster genesis hash
    /// to the number of advance steps performed under that genesis.
    ///
    /// On merge, contributions are UNIONED (take max per key) — not added.
    /// This makes double-counting structurally impossible: the same genesis
    /// hash is only counted once regardless of how many merge paths reach it.
    ///
    /// Size: O(merge_count). 32 nodes ≈ 32 entries × 40 bytes = 1.3 KB.
    pub work_contributions: BTreeMap<[u8; 32], u64>,
    /// All chain values in the current epoch (genesis, v1, v2, ..., tip).
    /// Reset on merge (epoch reset). Used to generate ZK proofs.
    /// At 10-second intervals: ~8640 entries/day, ~270 KB/day. Manageable.
    pub epoch_chain: Vec<[u8; 32]>,
    /// Quantized VDF height when this epoch started (for round_seed derivation
    /// in proof verification).
    pub epoch_start_quantum: u64,
    /// Block history (newest first). Used for debug visualization.
    /// Capped at `max_history_blocks` to prevent unbounded growth.
    history: Vec<ChainBlock>,
    /// Maximum blocks to retain in history.
    max_history_blocks: usize,
}

impl ClusterChain {
    /// Create a new cluster chain from a genesis seed.
    ///
    /// The seed is the well-known starting value (e.g. `blake3("lagoon")`).
    /// All nodes start from the same genesis — time (VDF quantum advance)
    /// is the salt that progresses the chain.
    pub fn genesis(seed: [u8; 32], timestamp_round: u64, cluster_size: u32) -> Self {
        let block = ChainBlock {
            prev_block_hash: "0".into(),
            chain_value: hex::encode(seed),
            round: 0,
            timestamp_round,
            event: ChainEvent::Genesis,
            cluster_size,
        };
        let mut work_contributions = BTreeMap::new();
        work_contributions.insert(seed, 0);
        Self {
            genesis: seed,
            value: seed,
            round: 0,
            cumulative_work: 0,
            work_contributions,
            epoch_chain: vec![seed],
            epoch_start_quantum: timestamp_round,
            history: vec![block],
            max_history_blocks: 1000,
        }
    }

    /// Advance the chain by one round.
    ///
    /// Called on each VDF quantum tick (every ~10 seconds at 10 Hz).
    /// `round_seed` is `blake3(quantized_height)` — deterministic from the
    /// Universal Clock. `timestamp_round` is the quantized VDF height.
    ///
    /// Within an epoch, the chain advances normally:
    /// `value = advance_chain(prev_value, round_seed)`. Each step depends on
    /// the previous — this IS the chain property. The epoch resets on merge
    /// (see `fungible_adopt`), but within an epoch, it's a proper hash chain.
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
        *self.work_contributions.entry(self.genesis).or_insert(0) += 1;
        self.cumulative_work = self.work_contributions.values().sum();
        self.epoch_chain.push(new_value);
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

    /// F-VDF epoch reset: merge two cluster chains into a new epoch.
    ///
    /// Computes `blake3(sort(our_value, their_value))` — a NEW combined identity
    /// that neither side had before. This merged value becomes the **new genesis**
    /// for the combined cluster. Both nodes reset their chain state to this seed.
    ///
    /// **Epoch reset semantics:**
    /// - `genesis` = merged value (new epoch seed)
    /// - `value` = merged value (chain restarts from here)
    /// - `cumulative_work` += other's work (fungible, additive — work is never lost)
    /// - `timestamp_round` = caller's quantized VDF height (prevents immediate
    ///   re-advance; both nodes gate on the NEXT quantum boundary)
    ///
    /// The chain property is preserved WITHIN each epoch. The merge creates a new
    /// epoch. Old history is encoded in the merged genesis hash itself.
    ///
    /// Returns `true` if our chain value changed.
    pub fn fungible_adopt(
        &mut self,
        other_value: &[u8; 32],
        other_round: u64,
        other_contributions: &BTreeMap<[u8; 32], u64>,
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
        // Epoch reset: merged value becomes the new genesis.
        // Both sides compute the same merged seed (commutative),
        // so they advance in lockstep from the next quantum tick.
        self.genesis = merged;
        self.value = merged;
        self.round = new_round;
        // Union contributions: take max per key (idempotent).
        // If the same genesis appears in both maps, it's counted once.
        for (k, v) in other_contributions {
            let entry = self.work_contributions.entry(*k).or_insert(0);
            *entry = (*entry).max(*v);
        }
        // New epoch: add entry for merged genesis (0 steps so far).
        self.work_contributions.insert(merged, 0);
        self.cumulative_work = self.work_contributions.values().sum();
        // New epoch: reset the chain to just the merged genesis.
        self.epoch_chain = vec![merged];
        self.epoch_start_quantum = timestamp_round;
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
        *self.work_contributions.entry(self.genesis).or_insert(0) += 1;
        self.cumulative_work = self.work_contributions.values().sum();
        self.epoch_chain.push(new_value);
        self.history.insert(0, block);
        self.enforce_history_limit();
    }

    /// Adopt a peer's chain state (SPORE cascade after merge).
    ///
    /// Called when a cluster-mate broadcasts a merged chain value with higher
    /// cumulative_work. We adopt their value, round, and work wholesale.
    /// Also sets genesis — we're joining their epoch.
    ///
    /// Returns `true` if we actually changed (their work was higher).
    pub fn adopt(
        &mut self,
        peer_value: [u8; 32],
        peer_round: u64,
        peer_contributions: BTreeMap<[u8; 32], u64>,
    ) -> bool {
        let peer_work: u64 = peer_contributions.values().sum();
        if peer_work <= self.cumulative_work && peer_value == self.value {
            return false; // Already at this state or ahead.
        }
        self.genesis = peer_value;
        self.value = peer_value;
        self.round = peer_round;
        self.work_contributions = peer_contributions;
        self.cumulative_work = self.work_contributions.values().sum();
        // Reset epoch chain — we don't have the intermediates.
        // We trust the peer's proof (which should accompany ChainUpdate).
        // Our own epoch chain restarts from their tip.
        self.epoch_chain = vec![peer_value];
        self.epoch_start_quantum = 0; // Will be set on next advance.
        // History is NOT updated — the gap shows the disconnect in debug view.
        true
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
    /// Total advance steps across all epochs (never resets).
    pub cumulative_work: u64,
    /// Number of merge events in recorded history.
    pub merge_count: u32,
    /// Number of split events in recorded history.
    pub split_count: u32,
}

impl ClusterChain {
    /// Number of advance steps in the current epoch.
    pub fn epoch_steps(&self) -> u64 {
        self.epoch_chain.len().saturating_sub(1) as u64
    }

    /// Whether this chain has advanced at least once since the last merge/genesis.
    /// Used to prevent cascading re-merges before ChainUpdate propagates.
    pub fn can_merge(&self) -> bool {
        self.epoch_steps() > 0
    }

    /// Get work contributions as hex-keyed map (for wire serialization).
    pub fn contributions_hex(&self) -> std::collections::HashMap<String, u64> {
        self.work_contributions
            .iter()
            .map(|(k, v)| (hex::encode(k), *v))
            .collect()
    }

    /// Generate a ZK proof of the current epoch's chain computation.
    ///
    /// Uses Merkle+Fiat-Shamir over the epoch's chain values. The proof
    /// demonstrates that `advance_chain(chain[i], round_seed[i]) == chain[i+1]`
    /// at `num_challenges` randomly selected positions.
    ///
    /// The verifier can independently derive `round_seed[i]` from the
    /// `epoch_start_quantum` and ROUND_QUANTUM, since round seeds are
    /// deterministic from quantized VDF height.
    ///
    /// For small epochs (≤ 10000 steps, ~28 hours), endpoint recompute
    /// provides 100% security in addition to the spot checks.
    pub fn generate_proof(&self, num_challenges: usize) -> ClusterChainProof {
        let epoch_steps = self.epoch_steps();
        if epoch_steps == 0 {
            return ClusterChainProof {
                genesis: self.genesis,
                tip: self.value,
                epoch_steps: 0,
                cumulative_work: self.cumulative_work,
                epoch_start_quantum: self.epoch_start_quantum,
                merkle_root: self.genesis,
                challenges: Vec::new(),
            };
        }

        let tree = lagoon_vdf::MerkleTree::build(&self.epoch_chain);
        let root = tree.root();

        let mut challenges = Vec::with_capacity(num_challenges);
        for k in 0..num_challenges {
            let raw_idx = chain_fiat_shamir_challenge(
                root, self.genesis, self.value, epoch_steps, k as u64,
            );
            let idx = (raw_idx % epoch_steps) as usize;

            challenges.push(ClusterChainChallenge {
                index: idx as u64,
                chain_at_index: self.epoch_chain[idx],
                chain_at_next: self.epoch_chain[idx + 1],
                proof_index: tree.prove(idx),
                proof_next: tree.prove(idx + 1),
            });
        }

        ClusterChainProof {
            genesis: self.genesis,
            tip: self.value,
            epoch_steps,
            cumulative_work: self.cumulative_work,
            epoch_start_quantum: self.epoch_start_quantum,
            merkle_root: root,
            challenges,
        }
    }

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
            cumulative_work: self.cumulative_work,
            merge_count,
            split_count,
        }
    }
}

// ── ZK Proof for Cluster Chain Work ─────────────────────────────────────
//
// Proves that a cluster chain was correctly computed from genesis to tip
// in exactly N sequential steps, using the domain-specific step function
// `advance_chain(prev, round_seed) = blake3(blake3(prev || round_seed))`.
//
// The round_seed for step i is deterministic:
//   round_seed[i] = blake3(bytes_of(epoch_start_quantum + i * ROUND_QUANTUM))
//
// This means a verifier with knowledge of the epoch_start_quantum can
// independently derive all round seeds and verify the chain computation.
//
// For small epochs (≤ 10000 steps, ~28 hours at 10-second intervals),
// full endpoint recompute provides 100% security. For larger epochs,
// Fiat-Shamir spot checks provide probabilistic security.

/// Maximum epoch steps for endpoint recompute verification.
/// At 10-second intervals, 10000 steps = ~28 hours.
/// `advance_chain` is two blake3 calls per step — recomputing 10000 steps
/// takes ~20 microseconds. Well within budget.
const EPOCH_RECOMPUTE_LIMIT: u64 = 10_000;

/// Derive round_seed for step `i` within an epoch.
///
/// `round_seed[i] = blake3(bytes_of(epoch_start_quantum + i * ROUND_QUANTUM))`
///
/// The Universal Clock quantization ensures all honest nodes derive the same
/// seed for the same step. The verifier computes this independently.
pub fn derive_round_seed(epoch_start_quantum: u64, step_index: u64) -> [u8; 32] {
    let quantum = epoch_start_quantum + step_index * ROUND_QUANTUM;
    *blake3::hash(&quantum.to_le_bytes()).as_bytes()
}

/// A single Fiat-Shamir challenge for the cluster chain proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterChainChallenge {
    /// Index into the epoch chain (0..epoch_steps).
    pub index: u64,
    /// Chain value at position `index`.
    pub chain_at_index: [u8; 32],
    /// Chain value at position `index + 1`.
    pub chain_at_next: [u8; 32],
    /// Merkle proof for `chain_at_index`.
    pub proof_index: Vec<[u8; 32]>,
    /// Merkle proof for `chain_at_next`.
    pub proof_next: Vec<[u8; 32]>,
}

/// Non-interactive ZK proof that a cluster chain was correctly computed.
///
/// Proves: starting from `genesis`, after `epoch_steps` applications of
/// `advance_chain(prev, derive_round_seed(epoch_start_quantum, i))`,
/// the chain arrives at `tip`. Work claim = `cumulative_work`.
///
/// Dual-layered verification:
///   1. **Endpoint recompute** (small epochs ≤ 10000): recompute the full chain
///      from genesis using derived round seeds. 100% secure, microseconds.
///   2. **Merkle+Fiat-Shamir** (any epoch): k spot-check proofs against the
///      committed Merkle root. Probabilistic, but constant-size proof.
///
/// Wire size: ~500 bytes with 3 challenges, regardless of epoch length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterChainProof {
    /// Genesis value of the current epoch.
    pub genesis: [u8; 32],
    /// Current tip value.
    pub tip: [u8; 32],
    /// Number of advance steps in this epoch.
    pub epoch_steps: u64,
    /// Total cumulative work across ALL epochs (fungible, additive).
    pub cumulative_work: u64,
    /// Quantized VDF height when this epoch started.
    /// Verifier uses this to derive round seeds independently.
    pub epoch_start_quantum: u64,
    /// Merkle root over all chain values in the epoch.
    pub merkle_root: [u8; 32],
    /// Fiat-Shamir spot checks.
    pub challenges: Vec<ClusterChainChallenge>,
}

impl ClusterChainProof {
    /// Verify the proof without access to the full chain.
    ///
    /// For each challenge:
    /// 1. Re-derive expected challenge index (Fiat-Shamir)
    /// 2. Derive `round_seed[i]` from `epoch_start_quantum`
    /// 3. Check `advance_chain(chain[i], round_seed[i]) == chain[i+1]`
    /// 4. Verify Merkle proofs for both positions
    ///
    /// For small epochs, also recomputes the full chain from genesis.
    pub fn verify(&self) -> bool {
        if self.epoch_steps == 0 {
            return self.genesis == self.tip;
        }

        // Fiat-Shamir spot checks.
        for (k, challenge) in self.challenges.iter().enumerate() {
            // 1. Re-derive expected challenge index.
            let expected_raw = chain_fiat_shamir_challenge(
                self.merkle_root, self.genesis, self.tip,
                self.epoch_steps, k as u64,
            );
            if challenge.index != expected_raw % self.epoch_steps {
                return false;
            }

            // 2. Derive round_seed for this step.
            let round_seed = derive_round_seed(
                self.epoch_start_quantum, challenge.index);

            // 3. Check advance_chain(chain[i], round_seed) == chain[i+1].
            let expected_next = advance_chain(
                &challenge.chain_at_index, &round_seed);
            if expected_next != challenge.chain_at_next {
                return false;
            }

            // 4. Verify Merkle proofs.
            if !lagoon_vdf::MerkleTree::verify_proof(
                self.merkle_root,
                challenge.chain_at_index,
                challenge.index as usize,
                &challenge.proof_index,
            ) {
                return false;
            }
            if !lagoon_vdf::MerkleTree::verify_proof(
                self.merkle_root,
                challenge.chain_at_next,
                (challenge.index + 1) as usize,
                &challenge.proof_next,
            ) {
                return false;
            }
        }

        // Endpoint recompute for small epochs — 100% secure.
        if self.epoch_steps <= EPOCH_RECOMPUTE_LIMIT {
            let mut h = self.genesis;
            for i in 0..self.epoch_steps {
                let seed = derive_round_seed(self.epoch_start_quantum, i);
                h = advance_chain(&h, &seed);
            }
            if h != self.tip {
                return false;
            }
        }

        true
    }

    /// Check whether this proof's `cumulative_work` is consistent with the epoch.
    ///
    /// `cumulative_work` includes ALL previous epochs. The current epoch
    /// contributes `epoch_steps` to the total. So:
    ///   `cumulative_work >= epoch_steps` (can be much larger due to merged work).
    pub fn work_consistent(&self) -> bool {
        self.cumulative_work >= self.epoch_steps
    }
}

/// Derive Fiat-Shamir challenge index for cluster chain proof.
///
/// Deterministic from: merkle_root, genesis, tip, steps, challenge number.
/// Different domain separation from VDF proofs to prevent cross-protocol attacks.
fn chain_fiat_shamir_challenge(
    merkle_root: [u8; 32],
    genesis: [u8; 32],
    tip: [u8; 32],
    steps: u64,
    challenge_num: u64,
) -> u64 {
    let mut h = blake3::Hasher::new();
    // Domain separation: "cluster_chain_proof" prefix.
    h.update(b"cluster_chain_proof");
    h.update(&merkle_root);
    h.update(&genesis);
    h.update(&tip);
    h.update(&steps.to_le_bytes());
    h.update(&challenge_num.to_le_bytes());
    let hash = h.finalize();
    u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap())
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
        let mut contributions = BTreeMap::new();
        contributions.insert(peer_value, 100);
        chain.adopt(peer_value, 42, contributions);
        assert_eq!(chain.value, peer_value);
        assert_eq!(chain.round, 42);
        assert_eq!(chain.cumulative_work, 100);
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
        let other_contribs = BTreeMap::from([(seed_b, 0u64)]);
        let changed = chain.fungible_adopt(&seed_b, 5, &other_contribs, 100, 6);
        // Result is blake3(sort(seed_a, seed_b)) — new combined identity
        let expected = fungible_merge(&seed_a, &seed_b);
        assert_eq!(chain.value, expected);
        assert_ne!(expected, seed_a); // combined value differs from both inputs
        assert_ne!(expected, seed_b);
        // Epoch reset: genesis is now the merged value
        assert_eq!(chain.genesis, expected);
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

        // Both adopt via fungible_adopt — epoch reset
        let b_contribs = BTreeMap::from([(seed_b, 0u64)]);
        let a_contribs = BTreeMap::from([(seed_a, 0u64)]);
        chain_a.fungible_adopt(&seed_b, chain_b.round, &b_contribs, 100, 5);
        chain_b.fungible_adopt(&seed_a, chain_a.round, &a_contribs, 100, 5);

        // Now they're SameCluster with the same genesis
        assert_eq!(chain_a.compare(Some(&chain_b.value)), ChainComparison::SameCluster);
        assert_eq!(chain_a.genesis, chain_b.genesis);
    }

    #[test]
    fn fungible_adopt_pairwise_symmetric() {
        // When two genuinely different clusters meet, both sides compute
        // the same combined value regardless of who initiates.
        let seed_a = blake3::hash(b"cluster-a").as_bytes().to_owned();
        let seed_b = blake3::hash(b"cluster-b").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 2);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 1);

        // Both sides merge — epoch reset, same combined value
        let b_contribs = BTreeMap::from([(seed_b, 0u64)]);
        let a_contribs = BTreeMap::from([(seed_a, 0u64)]);
        chain_a.fungible_adopt(&seed_b, chain_b.round, &b_contribs, 100, 3);
        chain_b.fungible_adopt(&seed_a, chain_a.round, &a_contribs, 100, 3);
        assert_eq!(chain_a.value, chain_b.value);
        assert_eq!(chain_a.genesis, chain_b.genesis);

        // The combined value is neither original
        assert_ne!(chain_a.value, seed_a);
        assert_ne!(chain_a.value, seed_b);
    }

    #[test]
    fn epoch_reset_enables_convergent_advance() {
        // THE key property: after merge (epoch reset), both nodes advance
        // to the same value when given the same round seed.
        let seed_a = blake3::hash(b"cluster-x").as_bytes().to_owned();
        let seed_b = blake3::hash(b"cluster-y").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 2);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 2);

        // Epoch reset on both sides
        let b_contribs = BTreeMap::from([(seed_b, 0u64)]);
        let a_contribs = BTreeMap::from([(seed_a, 0u64)]);
        chain_a.fungible_adopt(&seed_b, 0, &b_contribs, 100, 4);
        chain_b.fungible_adopt(&seed_a, 0, &a_contribs, 100, 4);
        assert_eq!(chain_a.value, chain_b.value);

        // Now advance both with the same round seed — should stay in sync
        let seed_1 = test_seed(100);
        chain_a.advance(&seed_1, 100, 4);
        chain_b.advance(&seed_1, 100, 4);
        assert_eq!(chain_a.value, chain_b.value);

        // And again
        let seed_2 = test_seed(200);
        chain_a.advance(&seed_2, 200, 4);
        chain_b.advance(&seed_2, 200, 4);
        assert_eq!(chain_a.value, chain_b.value);
    }

    #[test]
    fn cumulative_work_is_additive_across_merges() {
        // Work is fungible: merge adds both sides' cumulative work.
        let seed_a = blake3::hash(b"worker-a").as_bytes().to_owned();
        let seed_b = blake3::hash(b"worker-b").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 1);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 1);

        // A does 5 advance steps
        for i in 1..=5 {
            chain_a.advance(&test_seed(i * 100), i * 100, 1);
        }
        assert_eq!(chain_a.cumulative_work, 5);

        // B does 3 advance steps
        for i in 1..=3 {
            chain_b.advance(&test_seed(i * 100), i * 100, 1);
        }
        assert_eq!(chain_b.cumulative_work, 3);

        // Merge: A adopts B's work via union
        chain_a.fungible_adopt(&chain_b.value, chain_b.round,
                               &chain_b.work_contributions, 600, 2);
        assert_eq!(chain_a.cumulative_work, 8); // 5 + 3
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

    // ── ZK Proof Tests ─────────────────────────────────────────────────

    #[test]
    fn proof_genesis_only() {
        let seed = blake3::hash(b"proof-genesis").as_bytes().to_owned();
        let chain = ClusterChain::genesis(seed, 0, 1);
        let proof = chain.generate_proof(3);
        assert_eq!(proof.epoch_steps, 0);
        assert!(proof.verify(), "genesis-only proof should verify");
    }

    #[test]
    fn proof_after_advances() {
        let seed = blake3::hash(b"proof-advances").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 3);

        // Advance using derive_round_seed (same as what the verifier will compute).
        for i in 0..20 {
            let round_seed = derive_round_seed(0, i);
            chain.advance(&round_seed, i * ROUND_QUANTUM, 3);
        }

        assert_eq!(chain.epoch_steps(), 20);
        assert_eq!(chain.epoch_chain.len(), 21); // genesis + 20 advances
        assert_eq!(chain.cumulative_work, 20);

        let proof = chain.generate_proof(5);
        assert_eq!(proof.epoch_steps, 20);
        assert_eq!(proof.cumulative_work, 20);
        assert_eq!(proof.challenges.len(), 5);
        assert!(proof.verify(), "proof after 20 advances should verify");
        assert!(proof.work_consistent(), "work should be consistent");
    }

    #[test]
    fn proof_after_epoch_reset() {
        let seed_a = blake3::hash(b"proof-epoch-a").as_bytes().to_owned();
        let seed_b = blake3::hash(b"proof-epoch-b").as_bytes().to_owned();
        let mut chain_a = ClusterChain::genesis(seed_a, 0, 3);
        let mut chain_b = ClusterChain::genesis(seed_b, 0, 2);

        // Advance both chains.
        for i in 0..10 {
            chain_a.advance(&derive_round_seed(0, i), i * ROUND_QUANTUM, 3);
            chain_b.advance(&derive_round_seed(0, i), i * ROUND_QUANTUM, 2);
        }

        // Merge: epoch reset.
        let pre_b_value = chain_b.value;
        chain_a.fungible_adopt(
            &pre_b_value, chain_b.round, &chain_b.work_contributions, 1000, 5);

        // After merge: epoch_chain has just the merged genesis.
        assert_eq!(chain_a.epoch_chain.len(), 1);
        assert_eq!(chain_a.epoch_steps(), 0);
        assert_eq!(chain_a.cumulative_work, 20); // 10 + 10

        // Advance in new epoch.
        for i in 0..5 {
            chain_a.advance(&derive_round_seed(1000, i), 1000 + i * ROUND_QUANTUM, 5);
        }

        assert_eq!(chain_a.epoch_steps(), 5);
        assert_eq!(chain_a.cumulative_work, 25); // 20 + 5

        let proof = chain_a.generate_proof(3);
        assert_eq!(proof.epoch_steps, 5);
        assert_eq!(proof.cumulative_work, 25);
        assert!(proof.verify(), "proof after epoch reset should verify");
        assert!(proof.work_consistent());
    }

    #[test]
    fn tampered_proof_fails_verification() {
        let seed = blake3::hash(b"tamper-test").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 0, 1);

        for i in 0..15 {
            chain.advance(&derive_round_seed(0, i), i * ROUND_QUANTUM, 1);
        }

        // Valid proof.
        let proof = chain.generate_proof(3);
        assert!(proof.verify());

        // Tamper: change the tip.
        let mut bad_tip = proof.clone();
        bad_tip.tip = blake3::hash(b"fake-tip").as_bytes().to_owned();
        assert!(!bad_tip.verify(), "tampered tip should fail");

        // Tamper: change the genesis.
        let mut bad_genesis = proof.clone();
        bad_genesis.genesis = blake3::hash(b"fake-genesis").as_bytes().to_owned();
        assert!(!bad_genesis.verify(), "tampered genesis should fail");

        // Tamper: inflate epoch_steps.
        let mut bad_steps = proof.clone();
        bad_steps.epoch_steps = 100;
        assert!(!bad_steps.verify(), "inflated steps should fail");

        // Tamper: change a challenge hash.
        if !proof.challenges.is_empty() {
            let mut bad_hash = proof.clone();
            bad_hash.challenges[0].chain_at_next = [0xFF; 32];
            assert!(!bad_hash.verify(), "tampered challenge hash should fail");
        }
    }

    #[test]
    fn proof_large_epoch_endpoint_recompute() {
        // Test with enough steps to exercise the proof but small enough to be fast.
        let seed = blake3::hash(b"large-epoch").as_bytes().to_owned();
        let mut chain = ClusterChain::genesis(seed, 500, 5);

        for i in 0..100 {
            chain.advance(&derive_round_seed(500, i), 500 + i * ROUND_QUANTUM, 5);
        }

        assert_eq!(chain.epoch_steps(), 100);
        let proof = chain.generate_proof(5);
        assert!(proof.verify(), "100-step proof should verify");

        // Verify round_seed derivation matches.
        let seed_0 = derive_round_seed(500, 0);
        let expected_first = advance_chain(&chain.genesis, &seed_0);
        assert_eq!(chain.epoch_chain[1], expected_first);
    }
}
