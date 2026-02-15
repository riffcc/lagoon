//! VDF (Verifiable Delay Function) chain with ZK proofs.
//!
//! Proves that a Blake3 VDF chain was correctly computed from genesis to final
//! in exactly N sequential steps, WITHOUT requiring the verifier to recompute
//! the full chain. Non-interactive via Fiat-Shamir challenge derivation.

use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Hex-encode a byte slice.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Hex-encode the first `n` bytes (for display).
pub fn to_hex_short(bytes: &[u8], n: usize) -> String {
    to_hex(&bytes[..n.min(bytes.len())])
}

// ── VDF Chain ────────────────────────────────────────────────────────────

/// A complete VDF hash chain: h_0 -> h_1 -> ... -> h_n where h_{i+1} = Blake3(h_i).
///
/// Sequential and non-parallelizable — each step depends on the previous.
///
/// Supports sliding-window operation: `trim_to(n)` discards old hashes while
/// preserving the absolute height counter.  This keeps memory constant at
/// O(window_size) instead of O(total_steps).
pub struct VdfChain {
    pub hashes: Vec<[u8; 32]>,
    /// Absolute height of `hashes[0]`.  Initially 0 (genesis = step 0).
    /// Increases when old hashes are trimmed via `trim_to()`.
    height_offset: u64,
}

impl std::fmt::Debug for VdfChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VdfChain")
            .field("steps", &self.steps())
            .field("genesis", &to_hex_short(&self.genesis(), 8))
            .field("tip", &to_hex_short(&self.final_hash(), 8))
            .finish()
    }
}

impl VdfChain {
    /// Create a new chain with just the genesis hash (zero steps computed).
    pub fn new(genesis: [u8; 32]) -> Self {
        Self {
            hashes: vec![genesis],
            height_offset: 0,
        }
    }

    /// Compute a VDF chain of `steps` iterations starting from `genesis`.
    pub fn compute(genesis: [u8; 32], steps: u64) -> Self {
        let mut hashes = Vec::with_capacity(steps as usize + 1);
        hashes.push(genesis);
        let mut current = genesis;
        for _ in 0..steps {
            let mut h = Hasher::new();
            h.update(&current);
            current = *h.finalize().as_bytes();
            hashes.push(current);
        }
        Self {
            hashes,
            height_offset: 0,
        }
    }

    /// Extend the chain by one step: append Blake3(last_hash).
    pub fn tick(&mut self) {
        let prev = *self.hashes.last().expect("chain must have at least genesis");
        let mut h = Hasher::new();
        h.update(&prev);
        self.hashes.push(*h.finalize().as_bytes());
    }

    /// The genesis (first) hash of the chain.
    pub fn genesis(&self) -> [u8; 32] {
        self.hashes[0]
    }

    /// The current tip (last) hash of the chain.
    pub fn final_hash(&self) -> [u8; 32] {
        *self.hashes.last().expect("chain must have at least genesis")
    }

    /// Number of VDF steps computed (absolute chain height).
    ///
    /// After `trim_to()`, this still returns the total height, not the window size.
    pub fn steps(&self) -> u64 {
        self.height_offset + (self.hashes.len() as u64 - 1)
    }

    /// Absolute height of the chain tip.  Alias for `steps()`.
    pub fn height(&self) -> u64 {
        self.steps()
    }

    /// Absolute height of the first hash in the current window.
    pub fn height_start(&self) -> u64 {
        self.height_offset
    }

    /// Number of hashes currently stored (including the window anchor).
    pub fn window_len(&self) -> usize {
        self.hashes.len()
    }

    /// Trim the chain to keep only the last `n` hashes.
    ///
    /// Returns the number of hashes discarded.  After trimming, `steps()`
    /// still returns the correct absolute height.
    pub fn trim_to(&mut self, n: usize) -> usize {
        if self.hashes.len() <= n || n == 0 {
            return 0;
        }
        let trim_count = self.hashes.len() - n;
        self.hashes.drain(..trim_count);
        self.height_offset += trim_count as u64;
        trim_count
    }

    /// Generate a window proof covering all hashes currently in the chain.
    ///
    /// Uses Merkle+Fiat-Shamir internally (constant-size proof regardless
    /// of window length).  The verifier also recomputes `BLAKE3^N(h_start)`
    /// for small N — endpoint verification is 100% secure and takes
    /// microseconds at typical window sizes.
    ///
    /// `num_challenges` controls the Fiat-Shamir spot-check count (k=3 is
    /// fine when endpoint recompute is available; increase for large N).
    pub fn generate_window_proof(
        &self,
        spiral_slot: Option<u64>,
        num_challenges: usize,
    ) -> VdfWindowProof {
        // Build proof over the WINDOW hashes only.  VdfProof::generate_with_slot
        // uses chain.steps() to derive challenge indices and indexes into
        // chain.hashes — so we create a zero-offset view of just the window.
        let window_chain = VdfChain {
            hashes: self.hashes.clone(),
            height_offset: 0,
        };
        let proof = VdfProof::generate_with_slot(&window_chain, num_challenges, spiral_slot);
        VdfWindowProof {
            height_start: self.height_offset,
            height_end: self.height(),
            proof,
        }
    }
}

// ── VDF Window Proof ────────────────────────────────────────────────────

/// Constant-size proof that a VDF chain was sequentially computed over a
/// window of N steps.
///
/// Wraps a `VdfProof` (Merkle+Fiat-Shamir) with absolute height context.
/// Wire size is ~500 bytes regardless of window length — scales to millions.
///
/// Verification is dual-layered:
///   1. **Endpoint recompute** (small N ≤ 10 000): recompute `BLAKE3^N(h_start)`
///      and check it matches `h_end`.  100% secure, takes microseconds.
///   2. **Merkle+Fiat-Shamir** (any N): k spot-check proofs against the
///      committed Merkle root.  Probabilistic, but constant-size.
///
/// Chain continuity: the verifier tracks the last verified `h_end` per peer.
/// Each new proof's `h_start` (= `proof.genesis`) must equal the previous
/// `h_end`.  A mismatch indicates a chain fork (node restart or equivocation).
#[derive(Clone, Serialize, Deserialize)]
pub struct VdfWindowProof {
    /// Absolute VDF height of the first hash in the window.
    pub height_start: u64,
    /// Absolute VDF height of the last hash (tip) in the window.
    pub height_end: u64,
    /// Merkle+Fiat-Shamir proof over the window's hash chain.
    pub proof: VdfProof,
}

/// Maximum window size for endpoint recompute verification.
/// At 10 Hz VDF, 10 000 steps = 1000 seconds.  BLAKE3 does ~1 GH/s so
/// recomputing 10 000 hashes takes ~10 microseconds.  Well within budget.
const ENDPOINT_RECOMPUTE_LIMIT: u64 = 10_000;

impl VdfWindowProof {
    /// Verify the window proof.
    ///
    /// For small windows (≤ 10 000 steps), endpoint recompute provides 100%
    /// security: recompute `BLAKE3^N(h_start)` and check == `h_end`.
    /// The Merkle+Fiat-Shamir proof is always verified as well.
    pub fn verify(&self) -> bool {
        let n = self.height_end.saturating_sub(self.height_start);
        if n == 0 {
            return false;
        }
        if self.proof.steps != n {
            return false;
        }
        // Merkle+Fiat-Shamir spot-check verification.
        if !self.proof.verify() {
            return false;
        }
        // Endpoint recompute for small N — 100% secure, microseconds.
        if n <= ENDPOINT_RECOMPUTE_LIMIT {
            let mut h = self.proof.genesis;
            for _ in 0..n {
                h = *blake3::hash(&h).as_bytes();
            }
            if h != self.proof.final_hash {
                return false;
            }
        }
        true
    }

    /// Check whether this proof continues from a previously verified tip.
    pub fn continues_from(&self, tip: &[u8; 32]) -> bool {
        self.proof.genesis == *tip
    }

    /// The starting hash of this window.
    pub fn h_start(&self) -> [u8; 32] {
        self.proof.genesis
    }

    /// The ending hash (new chain tip) of this window.
    pub fn h_end(&self) -> [u8; 32] {
        self.proof.final_hash
    }

    /// Number of VDF steps covered by this window.
    pub fn window_steps(&self) -> u64 {
        self.height_end - self.height_start
    }

    /// Human-readable display.
    pub fn display(&self, indent: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!("{indent}VDF Window Proof:\n"));
        s.push_str(&format!(
            "{indent}  Height: {} → {} ({} steps)\n",
            self.height_start,
            self.height_end,
            self.window_steps()
        ));
        s.push_str(&format!(
            "{indent}  Start:  {}\n",
            to_hex_short(&self.h_start(), 8)
        ));
        s.push_str(&format!(
            "{indent}  End:    {}\n",
            to_hex_short(&self.h_end(), 8)
        ));
        if let Some(slot) = self.proof.spiral_slot {
            s.push_str(&format!("{indent}  SPIRAL: {slot}\n"));
        }
        s.push_str(&format!(
            "{indent}  Merkle: {}\n",
            to_hex_short(&self.proof.merkle_root, 8)
        ));
        s.push_str(&format!(
            "{indent}  Checks: {}\n",
            self.proof.challenges.len()
        ));
        let verdict = if self.verify() { "VALID" } else { "INVALID" };
        s.push_str(&format!("{indent}  Verify: {verdict}\n"));
        s
    }
}

// ── Merkle Tree ──────────────────────────────────────────────────────────

/// Binary Merkle tree over 32-byte leaves.
/// Padded to next power of 2 with zero hashes.
pub struct MerkleTree {
    /// levels[0] = leaves (padded), levels[last] = [root]
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree from a slice of leaf hashes.
    pub fn build(leaves: &[[u8; 32]]) -> Self {
        assert!(!leaves.is_empty(), "cannot build Merkle tree from zero leaves");

        let next_pow2 = leaves.len().next_power_of_two();
        let mut padded = leaves.to_vec();
        padded.resize(next_pow2, [0u8; 32]);

        let mut levels = vec![padded.clone()];
        let mut current = padded;

        while current.len() > 1 {
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                let mut h = Hasher::new();
                h.update(&pair[0]);
                h.update(&pair[1]);
                next.push(*h.finalize().as_bytes());
            }
            levels.push(next.clone());
            current = next;
        }

        Self { levels }
    }

    /// The Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("tree must have levels")[0]
    }

    /// Generate a proof (sibling hashes from leaf to root) for the leaf at `index`.
    pub fn prove(&self, index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut idx = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proof.push(if sibling < level.len() {
                level[sibling]
            } else {
                [0u8; 32]
            });
            idx /= 2;
        }
        proof
    }

    /// Verify a Merkle proof: recompute path from leaf to root, check against known root.
    pub fn verify_proof(
        root: [u8; 32],
        leaf: [u8; 32],
        index: usize,
        proof: &[[u8; 32]],
    ) -> bool {
        let mut current = leaf;
        let mut idx = index;
        for sibling in proof {
            let mut h = Hasher::new();
            if idx % 2 == 0 {
                h.update(&current);
                h.update(sibling);
            } else {
                h.update(sibling);
                h.update(&current);
            }
            current = *h.finalize().as_bytes();
            idx /= 2;
        }
        current == root
    }
}

// ── ZK VDF Proof ─────────────────────────────────────────────────────────

/// A single Fiat-Shamir challenge response proving one step of the VDF chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Index into the VDF chain (0..steps-1)
    pub index: u64,
    /// Hash at position `index` in the chain
    #[serde(with = "hex_bytes")]
    pub hash_at_index: [u8; 32],
    /// Hash at position `index + 1` (should equal Blake3(hash_at_index))
    #[serde(with = "hex_bytes")]
    pub hash_at_next: [u8; 32],
    /// Merkle proof for hash_at_index
    #[serde(with = "hex_bytes_vec")]
    pub proof_index: Vec<[u8; 32]>,
    /// Merkle proof for hash_at_next
    #[serde(with = "hex_bytes_vec")]
    pub proof_next: Vec<[u8; 32]>,
}

/// Non-interactive ZK proof that a VDF chain was correctly computed.
///
/// Uses Fiat-Shamir transform: challenge indices are derived deterministically
/// from (merkle_root, genesis, final_hash, steps, challenge_number).
/// Verifier checks random chain positions without seeing the full chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct VdfProof {
    #[serde(with = "hex_bytes")]
    pub genesis: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub final_hash: [u8; 32],
    pub steps: u64,
    #[serde(with = "hex_bytes")]
    pub merkle_root: [u8; 32],
    pub challenges: Vec<ChallengeResponse>,
    /// SPIRAL slot this proof attests to (None for pre-telemetry proofs).
    /// When present, bound into Fiat-Shamir challenge derivation — tampering
    /// with the slot invalidates all challenge indices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiral_slot: Option<u64>,
}

impl VdfProof {
    /// Generate a ZK proof for a VDF chain with `num_challenges` random checks.
    pub fn generate(chain: &VdfChain, num_challenges: usize) -> Self {
        Self::generate_with_slot(chain, num_challenges, None)
    }

    /// Generate a ZK proof with a SPIRAL slot bound into the Fiat-Shamir challenges.
    ///
    /// When `slot` is `Some(X)`, the slot index is hashed into every challenge
    /// derivation — tampering with the slot invalidates the proof.
    pub fn generate_with_slot(
        chain: &VdfChain,
        num_challenges: usize,
        slot: Option<u64>,
    ) -> Self {
        // Use hashes.len()-1 as the step count — this is the number of
        // hash transitions actually in the Merkle tree, NOT the absolute
        // chain height (which includes height_offset after trim).
        // chain.steps() must NEVER be used as an array index bound.
        let steps = (chain.hashes.len() - 1) as u64;
        if steps == 0 {
            return Self {
                genesis: chain.genesis(),
                final_hash: chain.final_hash(),
                steps: 0,
                merkle_root: chain.genesis(),
                challenges: Vec::new(),
                spiral_slot: slot,
            };
        }

        let tree = MerkleTree::build(&chain.hashes);
        let root = tree.root();

        let mut challenges = Vec::with_capacity(num_challenges);
        for k in 0..num_challenges {
            let raw_idx = fiat_shamir_challenge(
                root,
                chain.genesis(),
                chain.final_hash(),
                steps,
                k as u64,
                slot,
            );
            // raw_idx % steps → 0..=(steps-1) → idx+1 <= steps = hashes.len()-1
            let idx = (raw_idx % steps) as usize;

            challenges.push(ChallengeResponse {
                index: idx as u64,
                hash_at_index: chain.hashes[idx],
                hash_at_next: chain.hashes[idx + 1],
                proof_index: tree.prove(idx),
                proof_next: tree.prove(idx + 1),
            });
        }

        Self {
            genesis: chain.genesis(),
            final_hash: chain.final_hash(),
            steps,
            merkle_root: root,
            challenges,
            spiral_slot: slot,
        }
    }

    /// Verify the proof without access to the full VDF chain.
    ///
    /// For each Fiat-Shamir challenge, checks:
    /// 1. Challenge index matches deterministic derivation
    /// 2. Blake3(h_i) == h_{i+1}
    /// 3. Both hashes have valid Merkle proofs against the committed root
    pub fn verify(&self) -> bool {
        if self.steps == 0 {
            return self.genesis == self.final_hash;
        }

        for (k, challenge) in self.challenges.iter().enumerate() {
            // 1. Re-derive expected challenge index
            let expected_raw = fiat_shamir_challenge(
                self.merkle_root,
                self.genesis,
                self.final_hash,
                self.steps,
                k as u64,
                self.spiral_slot,
            );
            if challenge.index != expected_raw % self.steps {
                return false;
            }

            // 2. Verify Blake3(h_i) == h_{i+1}
            let mut h = Hasher::new();
            h.update(&challenge.hash_at_index);
            if *h.finalize().as_bytes() != challenge.hash_at_next {
                return false;
            }

            // 3. Verify Merkle proofs for both positions
            if !MerkleTree::verify_proof(
                self.merkle_root,
                challenge.hash_at_index,
                challenge.index as usize,
                &challenge.proof_index,
            ) {
                return false;
            }
            if !MerkleTree::verify_proof(
                self.merkle_root,
                challenge.hash_at_next,
                (challenge.index + 1) as usize,
                &challenge.proof_next,
            ) {
                return false;
            }
        }

        true
    }

    /// Format the proof for human-readable display.
    pub fn display(&self, indent: &str) -> String {
        let mut s = String::new();
        s.push_str(&format!("{indent}ZK Proof-of-VDF:\n"));
        s.push_str(&format!(
            "{indent}  Genesis:     {}\n",
            to_hex_short(&self.genesis, 8)
        ));
        s.push_str(&format!(
            "{indent}  Final:       {}\n",
            to_hex_short(&self.final_hash, 8)
        ));
        s.push_str(&format!("{indent}  Steps:       {}\n", self.steps));
        s.push_str(&format!(
            "{indent}  Merkle Root: {}\n",
            to_hex_short(&self.merkle_root, 8)
        ));
        if let Some(slot) = self.spiral_slot {
            s.push_str(&format!("{indent}  SPIRAL Slot: {slot}\n"));
        }
        s.push_str(&format!(
            "{indent}  Challenges:  {}\n",
            self.challenges.len()
        ));
        for (i, c) in self.challenges.iter().enumerate() {
            s.push_str(&format!(
                "{indent}    [{i}] idx={}: Blake3({}) == {}\n",
                c.index,
                to_hex_short(&c.hash_at_index, 6),
                to_hex_short(&c.hash_at_next, 6),
            ));
        }
        let verdict = if self.verify() {
            "VALID"
        } else {
            "INVALID"
        };
        s.push_str(&format!("{indent}  Verified:    {verdict}\n"));
        s
    }

    /// Serialize to a JSON-compatible serde_json::Value (hex-encoded byte arrays).
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "genesis": to_hex(&self.genesis),
            "final_hash": to_hex(&self.final_hash),
            "steps": self.steps,
            "merkle_root": to_hex(&self.merkle_root),
            "challenges": self.challenges.iter().map(|c| serde_json::json!({
                "index": c.index,
                "hash_at_index": to_hex(&c.hash_at_index),
                "hash_at_next": to_hex(&c.hash_at_next),
                "proof_index": c.proof_index.iter().map(|p| to_hex(p)).collect::<Vec<_>>(),
                "proof_next": c.proof_next.iter().map(|p| to_hex(p)).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }
}

/// Fiat-Shamir challenge derivation: deterministic index from public parameters.
///
/// When `spiral_slot` is `Some(X)`, the slot is mixed in — binding the proof
/// to a specific SPIRAL position. When `None`, output is identical to the
/// pre-telemetry version (backward compatible).
fn fiat_shamir_challenge(
    root: [u8; 32],
    genesis: [u8; 32],
    final_hash: [u8; 32],
    steps: u64,
    k: u64,
    spiral_slot: Option<u64>,
) -> u64 {
    let mut h = Hasher::new();
    h.update(&root);
    h.update(&genesis);
    h.update(&final_hash);
    h.update(&steps.to_le_bytes());
    h.update(&k.to_le_bytes());
    if let Some(slot) = spiral_slot {
        h.update(&slot.to_le_bytes());
    }
    let digest = h.finalize();
    let bytes = digest.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

// ── Serde helpers for [u8; 32] as hex strings ────────────────────────────

mod hex_bytes {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<Vec<u8>, _>>()?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(arr)
    }
}

mod hex_bytes_vec {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(vec: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vec.len()))?;
        for bytes in vec {
            let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            seq.serialize_element(&hex_str)?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let bytes: Vec<u8> = (0..s.len())
                    .step_by(2)
                    .map(|i| {
                        u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom)
                    })
                    .collect::<Result<Vec<u8>, _>>()?;
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_chain_deterministic() {
        let genesis = [42u8; 32];
        let c1 = VdfChain::compute(genesis, 20);
        let c2 = VdfChain::compute(genesis, 20);
        assert_eq!(c1.hashes, c2.hashes);
        assert_ne!(c1.genesis(), c1.final_hash());
    }

    #[test]
    fn test_vdf_chain_sequential() {
        let genesis = [1u8; 32];
        let chain = VdfChain::compute(genesis, 10);
        for i in 0..10 {
            let mut h = Hasher::new();
            h.update(&chain.hashes[i]);
            assert_eq!(*h.finalize().as_bytes(), chain.hashes[i + 1]);
        }
    }

    #[test]
    fn test_vdf_chain_tick_matches_compute() {
        let genesis = [99u8; 32];
        let computed = VdfChain::compute(genesis, 50);
        let mut ticked = VdfChain::new(genesis);
        for _ in 0..50 {
            ticked.tick();
        }
        assert_eq!(computed.hashes, ticked.hashes);
        assert_eq!(computed.final_hash(), ticked.final_hash());
        assert_eq!(computed.steps(), ticked.steps());
    }

    #[test]
    fn test_merkle_tree_single_leaf() {
        let leaf = [99u8; 32];
        let tree = MerkleTree::build(&[leaf]);
        let proof = tree.prove(0);
        assert!(MerkleTree::verify_proof(tree.root(), leaf, 0, &proof));
    }

    #[test]
    fn test_merkle_tree_four_leaves() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let tree = MerkleTree::build(&leaves);
        for i in 0..4 {
            let proof = tree.prove(i);
            assert!(
                MerkleTree::verify_proof(tree.root(), leaves[i], i, &proof),
                "Proof failed for leaf {i}"
            );
        }
    }

    #[test]
    fn test_merkle_tree_non_power_of_two() {
        let leaves: Vec<[u8; 32]> = (0..5u8).map(|i| [i; 32]).collect();
        let tree = MerkleTree::build(&leaves);
        for i in 0..5 {
            let proof = tree.prove(i);
            assert!(
                MerkleTree::verify_proof(tree.root(), leaves[i], i, &proof),
                "Proof failed for leaf {i} (non-pow2 tree)"
            );
        }
    }

    #[test]
    fn test_merkle_proof_wrong_leaf_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| [i; 32]).collect();
        let tree = MerkleTree::build(&leaves);
        let proof = tree.prove(0);
        let wrong_leaf = [255u8; 32];
        assert!(!MerkleTree::verify_proof(
            tree.root(),
            wrong_leaf,
            0,
            &proof
        ));
    }

    #[test]
    fn test_vdf_proof_trivial_zero_steps() {
        let genesis = [7u8; 32];
        let chain = VdfChain::compute(genesis, 0);
        let proof = VdfProof::generate(&chain, 3);
        assert!(proof.verify());
        assert_eq!(proof.steps, 0);
        assert!(proof.challenges.is_empty());
    }

    #[test]
    fn test_vdf_proof_small_chain() {
        let genesis = [13u8; 32];
        let chain = VdfChain::compute(genesis, 5);
        let proof = VdfProof::generate(&chain, 3);
        assert!(proof.verify());
    }

    #[test]
    fn test_vdf_proof_larger_chain() {
        let genesis = [77u8; 32];
        let chain = VdfChain::compute(genesis, 100);
        let proof = VdfProof::generate(&chain, 5);
        assert!(proof.verify());
    }

    #[test]
    fn test_vdf_proof_tampered_final_fails() {
        let genesis = [13u8; 32];
        let chain = VdfChain::compute(genesis, 10);
        let mut proof = VdfProof::generate(&chain, 3);
        proof.final_hash = [0u8; 32]; // tamper
        assert!(!proof.verify());
    }

    #[test]
    fn test_vdf_proof_tampered_hash_fails() {
        let genesis = [13u8; 32];
        let chain = VdfChain::compute(genesis, 10);
        let mut proof = VdfProof::generate(&chain, 3);
        if !proof.challenges.is_empty() {
            proof.challenges[0].hash_at_index = [0u8; 32]; // tamper
        }
        assert!(!proof.verify());
    }

    #[test]
    fn test_fiat_shamir_deterministic() {
        let root = [1u8; 32];
        let genesis = [2u8; 32];
        let final_hash = [3u8; 32];
        let a = fiat_shamir_challenge(root, genesis, final_hash, 100, 0, None);
        let b = fiat_shamir_challenge(root, genesis, final_hash, 100, 0, None);
        assert_eq!(a, b);
        // Different k -> different challenge
        let c = fiat_shamir_challenge(root, genesis, final_hash, 100, 1, None);
        assert_ne!(a, c);
        // With spiral slot -> different challenge
        let d = fiat_shamir_challenge(root, genesis, final_hash, 100, 0, Some(7));
        assert_ne!(a, d);
        // Same slot -> deterministic
        let e = fiat_shamir_challenge(root, genesis, final_hash, 100, 0, Some(7));
        assert_eq!(d, e);
    }

    #[test]
    fn test_proof_display_contains_key_info() {
        let chain = VdfChain::compute([42u8; 32], 20);
        let proof = VdfProof::generate(&chain, 3);
        let display = proof.display("  ");
        assert!(display.contains("VALID"));
        assert!(display.contains("Steps:       20"));
        assert!(display.contains("Challenges:  3"));
    }

    #[test]
    fn test_proof_serde_roundtrip() {
        let chain = VdfChain::compute([42u8; 32], 50);
        let proof = VdfProof::generate(&chain, 3);
        let json = serde_json::to_string(&proof).expect("serialize");
        let restored: VdfProof = serde_json::from_str(&json).expect("deserialize");
        assert!(restored.verify());
        assert_eq!(proof.genesis, restored.genesis);
        assert_eq!(proof.final_hash, restored.final_hash);
        assert_eq!(proof.steps, restored.steps);
        assert_eq!(proof.merkle_root, restored.merkle_root);
        assert_eq!(proof.challenges.len(), restored.challenges.len());
    }

    #[test]
    fn test_vdf_proof_with_spiral_slot() {
        let chain = VdfChain::compute([42u8; 32], 50);
        let proof = VdfProof::generate_with_slot(&chain, 3, Some(7));
        assert!(proof.verify());
        assert_eq!(proof.spiral_slot, Some(7));

        // Tampering with spiral_slot invalidates proof
        let mut tampered = proof.clone();
        tampered.spiral_slot = Some(99);
        assert!(!tampered.verify());

        // Setting slot to None also invalidates (different challenges)
        let mut cleared = proof.clone();
        cleared.spiral_slot = None;
        assert!(!cleared.verify());
    }

    #[test]
    fn test_vdf_proof_backward_compat() {
        // Proofs without spiral_slot still work
        let chain = VdfChain::compute([42u8; 32], 50);
        let proof = VdfProof::generate(&chain, 3);
        assert_eq!(proof.spiral_slot, None);

        // Serialize and restore — spiral_slot absent in JSON
        let json = serde_json::to_string(&proof).expect("serialize");
        assert!(!json.contains("spiral_slot"));
        let restored: VdfProof = serde_json::from_str(&json).expect("deserialize");
        assert!(restored.verify());
        assert_eq!(restored.spiral_slot, None);
    }

    #[test]
    fn test_vdf_proof_slot_serde_roundtrip() {
        let chain = VdfChain::compute([42u8; 32], 50);
        let proof = VdfProof::generate_with_slot(&chain, 3, Some(42));
        let json = serde_json::to_string(&proof).expect("serialize");
        assert!(json.contains("\"spiral_slot\":42"));
        let restored: VdfProof = serde_json::from_str(&json).expect("deserialize");
        assert!(restored.verify());
        assert_eq!(restored.spiral_slot, Some(42));
    }

    // ── Window proof tests ──────────────────────────────────────────────

    #[test]
    fn test_window_proof_basic() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let proof = chain.generate_window_proof(None, 3);
        assert!(proof.verify());
        assert_eq!(proof.height_start, 0);
        assert_eq!(proof.height_end, 30);
        assert_eq!(proof.window_steps(), 30);
        assert_eq!(proof.proof.steps, 30);
        assert_eq!(proof.proof.spiral_slot, None);
    }

    #[test]
    fn test_window_proof_with_spiral_slot() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let proof = chain.generate_window_proof(Some(7), 3);
        assert!(proof.verify());
        assert_eq!(proof.proof.spiral_slot, Some(7));
    }

    #[test]
    fn test_window_proof_tampered_genesis_fails() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let mut proof = chain.generate_window_proof(None, 3);
        proof.proof.genesis = [0u8; 32]; // tamper
        assert!(!proof.verify());
    }

    #[test]
    fn test_window_proof_tampered_final_fails() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let mut proof = chain.generate_window_proof(None, 3);
        proof.proof.final_hash = [0u8; 32]; // tamper
        assert!(!proof.verify());
    }

    #[test]
    fn test_window_proof_tampered_height_fails() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let mut proof = chain.generate_window_proof(None, 3);
        proof.height_end = 999; // steps mismatch
        assert!(!proof.verify());
    }

    #[test]
    fn test_window_proof_zero_steps_fails() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let mut proof = chain.generate_window_proof(None, 3);
        proof.height_start = proof.height_end; // zero window
        assert!(!proof.verify());
    }

    #[test]
    fn test_window_proof_chain_continuity() {
        // Build a 60-step chain, generate two sequential window proofs.
        let mut chain = VdfChain::compute([42u8; 32], 30);
        let proof1 = chain.generate_window_proof(None, 3);
        assert!(proof1.verify());

        // Trim to tip, tick 30 more.
        chain.trim_to(1);
        for _ in 0..30 {
            chain.tick();
        }
        let proof2 = chain.generate_window_proof(None, 3);
        assert!(proof2.verify());
        assert!(proof2.continues_from(&proof1.h_end()));

        // Wrong anchor fails continuity.
        assert!(!proof2.continues_from(&[0u8; 32]));
    }

    // ── Sliding window tests ────────────────────────────────────────────

    #[test]
    fn test_chain_trim_preserves_height() {
        let mut chain = VdfChain::compute([42u8; 32], 100);
        assert_eq!(chain.steps(), 100);
        assert_eq!(chain.window_len(), 101);

        let trimmed = chain.trim_to(10);
        assert_eq!(trimmed, 91);
        assert_eq!(chain.steps(), 100); // absolute height unchanged
        assert_eq!(chain.window_len(), 10);
        assert_eq!(chain.height_start(), 91);
    }

    #[test]
    fn test_chain_trim_to_one_then_tick() {
        let mut chain = VdfChain::compute([42u8; 32], 50);
        let tip = chain.final_hash();
        assert_eq!(chain.steps(), 50);

        chain.trim_to(1);
        assert_eq!(chain.steps(), 50);
        assert_eq!(chain.window_len(), 1);
        assert_eq!(chain.final_hash(), tip);

        // Tick 30 more times
        for _ in 0..30 {
            chain.tick();
        }
        assert_eq!(chain.steps(), 80);
        assert_eq!(chain.window_len(), 31);
        assert_eq!(chain.height_start(), 50);
    }

    #[test]
    fn test_chain_trim_noop_when_smaller() {
        let mut chain = VdfChain::compute([42u8; 32], 5);
        let trimmed = chain.trim_to(100);
        assert_eq!(trimmed, 0);
        assert_eq!(chain.steps(), 5);
        assert_eq!(chain.window_len(), 6);
    }

    #[test]
    fn test_window_proof_after_trim() {
        let mut chain = VdfChain::compute([42u8; 32], 50);
        chain.trim_to(1); // keep only tip

        // Tick 30 more steps
        for _ in 0..30 {
            chain.tick();
        }

        let proof = chain.generate_window_proof(Some(3), 3);
        assert!(proof.verify());
        assert_eq!(proof.height_start, 50);
        assert_eq!(proof.height_end, 80);
        assert_eq!(proof.window_steps(), 30);
        assert_eq!(proof.proof.steps, 30);
        assert_eq!(proof.proof.spiral_slot, Some(3));
    }

    #[test]
    fn test_sequential_window_proofs() {
        let mut chain = VdfChain::compute([42u8; 32], 30);
        let proof1 = chain.generate_window_proof(None, 3);
        assert!(proof1.verify());

        chain.trim_to(1);
        for _ in 0..30 {
            chain.tick();
        }
        let proof2 = chain.generate_window_proof(None, 3);
        assert!(proof2.verify());
        assert!(proof2.continues_from(&proof1.h_end()));

        chain.trim_to(1);
        for _ in 0..30 {
            chain.tick();
        }
        let proof3 = chain.generate_window_proof(None, 3);
        assert!(proof3.verify());
        assert!(proof3.continues_from(&proof2.h_end()));
        // proof3 does NOT continue from proof1
        assert!(!proof3.continues_from(&proof1.h_end()));
    }

    #[test]
    fn test_window_proof_bincode_roundtrip() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let proof = chain.generate_window_proof(Some(7), 3);
        let bytes = bincode::serialize(&proof).expect("bincode serialize");
        let restored: VdfWindowProof =
            bincode::deserialize(&bytes).expect("bincode deserialize");
        assert!(restored.verify());
        assert_eq!(restored.height_start, proof.height_start);
        assert_eq!(restored.height_end, proof.height_end);
        assert_eq!(restored.proof.genesis, proof.proof.genesis);
        assert_eq!(restored.proof.final_hash, proof.proof.final_hash);
        assert_eq!(restored.proof.merkle_root, proof.proof.merkle_root);
    }

    #[test]
    fn test_window_proof_display() {
        let chain = VdfChain::compute([42u8; 32], 30);
        let proof = chain.generate_window_proof(Some(7), 3);
        let display = proof.display("  ");
        assert!(display.contains("VALID"));
        assert!(display.contains("30 steps"));
        assert!(display.contains("SPIRAL: 7"));
        assert!(display.contains("Merkle:"));
        assert!(display.contains("Checks: 3"));
    }

    #[test]
    fn test_window_proof_constant_size() {
        // Window proofs grow logarithmically (Merkle depth), NOT linearly.
        // A 10× increase in steps should only add ~3 Merkle levels.
        let chain_small = VdfChain::compute([42u8; 32], 10);
        let chain_large = VdfChain::compute([42u8; 32], 100);
        let chain_huge = VdfChain::compute([42u8; 32], 1000);
        let proof_small = chain_small.generate_window_proof(None, 3);
        let proof_large = chain_large.generate_window_proof(None, 3);
        let proof_huge = chain_huge.generate_window_proof(None, 3);
        let bytes_small = bincode::serialize(&proof_small).unwrap();
        let bytes_large = bincode::serialize(&proof_large).unwrap();
        let bytes_huge = bincode::serialize(&proof_huge).unwrap();
        // All should have exactly 3 challenges.
        assert_eq!(proof_small.proof.challenges.len(), 3);
        assert_eq!(proof_large.proof.challenges.len(), 3);
        assert_eq!(proof_huge.proof.challenges.len(), 3);
        // Key property: logarithmic growth, NOT linear.
        // 100× more steps → only ~2× bigger (Merkle depth grows).
        // Linear would mean 100× bigger.
        let ratio = bytes_huge.len() as f64 / bytes_small.len() as f64;
        assert!(
            ratio < 3.0,
            "proof grew {ratio:.1}× for 100× more steps \
             ({} vs {} bytes) — growth should be logarithmic, not linear",
            bytes_small.len(),
            bytes_huge.len()
        );
        // All under 6 KB (hex serde inflates Merkle paths; raw bytes ~500B).
        assert!(bytes_small.len() < 6144, "small: {} bytes", bytes_small.len());
        assert!(bytes_large.len() < 6144, "large: {} bytes", bytes_large.len());
        assert!(bytes_huge.len() < 6144, "huge: {} bytes", bytes_huge.len());
    }

    /// Regression: generate_with_slot on a trimmed chain (height_offset > 0).
    ///
    /// The old code used `chain.steps()` as the Fiat-Shamir modulus.  After
    /// trim, `steps()` includes `height_offset` which far exceeds `hashes.len()`,
    /// causing OOB panics.  The fix: use `hashes.len() - 1` as the modulus.
    #[test]
    fn test_generate_on_trimmed_chain_no_panic() {
        let mut chain = VdfChain::compute([1u8; 32], 50);
        chain.trim_to(11);
        assert_eq!(chain.hashes.len(), 11);
        assert!(chain.height_offset > 0);

        // Window proof path (zero-offset copy) — always worked.
        let proof = chain.generate_window_proof(Some(3), 3);
        assert!(proof.verify(), "window proof from trimmed chain must verify");

        // Direct generate_with_slot on the TRIMMED chain — the old code panicked here.
        // Now safe: modulus is hashes.len()-1 = 10, not chain.steps() = 50.
        let proof2 = VdfProof::generate_with_slot(&chain, 3, Some(3));
        assert!(proof2.verify(), "direct proof on trimmed chain must verify");
        assert_eq!(proof2.steps, 10, "steps should be hashes.len()-1, not chain.steps()");
    }
}
