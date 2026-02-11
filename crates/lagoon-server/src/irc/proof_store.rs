//! Proof Store: SPORE-indexed storage for network latency proofs.
//!
//! Stores `ProofEntry` records keyed by sorted peer-pair edges, using a
//! monotonically-growing SPORE to track which content IDs we possess. This
//! enables efficient diff-based sync: a remote peer sends its SPORE, we
//! subtract it from ours, and return only the proofs they are missing.
//!
//! ## Design Decisions
//!
//! - **Monotonic SPORE growth**: When a proof is replaced (newer timestamp for
//!   the same edge), the old content_id remains in the SPORE. This is harmless:
//!   worst case, a peer skips re-requesting a proof we already replaced, and
//!   they will receive the newer version on the next diff cycle.
//!
//! - **TTL-based pruning**: Stale proofs (older than `ttl_ms`) are removed from
//!   the HashMap but NOT from the SPORE (monotonic growth). Pruning is explicit
//!   via `prune_stale()` — no polling, no background tasks.

use std::collections::{HashMap, HashSet};

use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};

/// A single latency proof between two peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofEntry {
    /// Sorted peer IDs (lexicographic order).
    pub edge: (String, String),
    /// Round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// When this proof was created (milliseconds since epoch).
    pub timestamp_ms: i64,
    /// Opaque serialized proof data.
    pub proof_bytes: Vec<u8>,
    /// BLAKE3 hash of `proof_bytes`, used as the SPORE content ID.
    pub content_id: [u8; 32],
}

/// SPORE-indexed store for network latency proofs.
///
/// Each proof is keyed by a sorted peer-pair edge `(A, B)` where `A < B`
/// lexicographically. The SPORE tracks content IDs (BLAKE3 hashes) of all
/// proofs ever inserted, enabling efficient set-difference sync with peers.
#[derive(Debug)]
pub struct ProofStore {
    proofs: HashMap<(String, String), ProofEntry>,
    spore: Spore,
    ttl_ms: i64,
}

/// Create a SPORE point range for a single U256 value.
///
/// A point range `[v, v+1)` contains exactly the value `v`.
fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

impl ProofStore {
    /// Create a new proof store with the given TTL for proof freshness.
    pub fn new(ttl_ms: i64) -> Self {
        ProofStore {
            proofs: HashMap::new(),
            spore: Spore::empty(),
            ttl_ms,
        }
    }

    /// Produce a canonical edge key by sorting peer IDs lexicographically.
    pub fn edge_key(peer_a: &str, peer_b: &str) -> (String, String) {
        if peer_a <= peer_b {
            (peer_a.to_owned(), peer_b.to_owned())
        } else {
            (peer_b.to_owned(), peer_a.to_owned())
        }
    }

    /// Create a `ProofEntry`, computing the BLAKE3 content_id from proof_bytes.
    pub fn make_entry(
        edge: (String, String),
        rtt_ms: f64,
        timestamp_ms: i64,
        proof_bytes: Vec<u8>,
    ) -> ProofEntry {
        let content_id: [u8; 32] = *blake3::hash(&proof_bytes).as_bytes();
        ProofEntry {
            edge,
            rtt_ms,
            timestamp_ms,
            proof_bytes,
            content_id,
        }
    }

    /// Insert a proof entry. Returns `true` if the entry was new or replaced an
    /// older one; `false` if the existing entry has a newer-or-equal timestamp.
    pub fn insert(&mut self, entry: ProofEntry) -> bool {
        if let Some(existing) = self.proofs.get(&entry.edge) {
            if entry.timestamp_ms <= existing.timestamp_ms {
                return false;
            }
        }

        // Add the new content_id to the SPORE (monotonic growth).
        let content_u256 = U256::from_be_bytes(&entry.content_id);
        let point = Spore::from_range(point_range(content_u256));
        self.spore = self.spore.union(&point);

        self.proofs.insert(entry.edge.clone(), entry);
        true
    }

    /// Look up a proof by peer pair (order-independent).
    pub fn get(&self, peer_a: &str, peer_b: &str) -> Option<&ProofEntry> {
        let key = Self::edge_key(peer_a, peer_b);
        self.proofs.get(&key)
    }

    /// Iterate over all stored proofs.
    pub fn all_proofs(&self) -> impl Iterator<Item = &ProofEntry> {
        self.proofs.values()
    }

    /// Number of proofs currently stored.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Remove proofs older than TTL relative to `now_ms`. Returns the number
    /// of proofs removed. Does NOT shrink the SPORE (monotonic growth).
    pub fn prune_stale(&mut self, now_ms: i64) -> usize {
        let before = self.proofs.len();
        self.proofs
            .retain(|_, entry| now_ms - entry.timestamp_ms <= self.ttl_ms);
        before - self.proofs.len()
    }

    /// Reference to the internal SPORE (content ID coverage set).
    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    /// Compute the proofs a peer is missing based on their SPORE.
    ///
    /// Subtracts `peer_spore` from ours to find content IDs we have that they
    /// lack, then returns the corresponding proof entries.
    pub fn diff_for_peer(&self, peer_spore: &Spore) -> Vec<ProofEntry> {
        let missing = self.spore.subtract(peer_spore);
        self.proofs
            .values()
            .filter(|entry| {
                let cid = U256::from_be_bytes(&entry.content_id);
                missing.covers(&cid)
            })
            .cloned()
            .collect()
    }

    /// Merge incoming proof entries, rejecting stale or older-than-existing ones.
    /// Returns the number of entries accepted.
    pub fn merge(&mut self, entries: Vec<ProofEntry>, now_ms: i64) -> usize {
        let mut accepted = 0;
        for entry in entries {
            if now_ms - entry.timestamp_ms > self.ttl_ms {
                continue;
            }
            if self.insert(entry) {
                accepted += 1;
            }
        }
        accepted
    }

    /// Build an edge-to-RTT map containing only fresh proofs (within TTL).
    pub fn latency_map(&self, now_ms: i64) -> HashMap<(String, String), f64> {
        self.proofs
            .iter()
            .filter(|(_, entry)| now_ms - entry.timestamp_ms <= self.ttl_ms)
            .map(|(key, entry)| (key.clone(), entry.rtt_ms))
            .collect()
    }

    /// Collect the set of all peer IDs mentioned in stored proofs.
    pub fn known_peers(&self) -> HashSet<String> {
        let mut peers = HashSet::new();
        for (a, b) in self.proofs.keys() {
            peers.insert(a.clone());
            peers.insert(b.clone());
        }
        peers
    }

    /// Serialized proof data with content_id, for gossip diff.
    pub fn proof_data_for_gossip(&self) -> Vec<(Vec<u8>, [u8; 32])> {
        self.proofs
            .values()
            .map(|entry| {
                let serialized = bincode::serialize(entry).unwrap_or_default();
                (serialized, entry.content_id)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entry(peer_a: &str, peer_b: &str, rtt_ms: f64, ts: i64) -> ProofEntry {
        let edge = ProofStore::edge_key(peer_a, peer_b);
        let proof_bytes = format!("{}-{}-{}-{}", edge.0, edge.1, rtt_ms, ts).into_bytes();
        ProofStore::make_entry(edge, rtt_ms, ts, proof_bytes)
    }

    #[test]
    fn test_edge_key_sorts() {
        let (a, b) = ProofStore::edge_key("B", "A");
        assert_eq!(a, "A");
        assert_eq!(b, "B");
    }

    #[test]
    fn test_edge_key_symmetric() {
        let ab = ProofStore::edge_key("alpha", "beta");
        let ba = ProofStore::edge_key("beta", "alpha");
        assert_eq!(ab, ba);
    }

    #[test]
    fn test_insert_new() {
        let mut store = ProofStore::new(60_000);
        let entry = test_entry("lon", "per", 12.5, 1000);
        assert!(store.insert(entry));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_older_rejected() {
        let mut store = ProofStore::new(60_000);
        let newer = test_entry("lon", "per", 12.5, 2000);
        let older = test_entry("lon", "per", 15.0, 1000);
        assert!(store.insert(newer));
        assert!(!store.insert(older));
        assert_eq!(store.get("lon", "per").unwrap().rtt_ms, 12.5);
    }

    #[test]
    fn test_insert_newer_replaces() {
        let mut store = ProofStore::new(60_000);
        let older = test_entry("lon", "per", 15.0, 1000);
        let newer = test_entry("lon", "per", 10.0, 2000);
        assert!(store.insert(older));
        assert!(store.insert(newer));
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("lon", "per").unwrap().rtt_ms, 10.0);
    }

    #[test]
    fn test_get_existing() {
        let mut store = ProofStore::new(60_000);
        let entry = test_entry("lon", "per", 12.5, 1000);
        store.insert(entry);
        let found = store.get("lon", "per").unwrap();
        assert_eq!(found.rtt_ms, 12.5);
        assert_eq!(found.timestamp_ms, 1000);
    }

    #[test]
    fn test_get_missing() {
        let store = ProofStore::new(60_000);
        assert!(store.get("lon", "per").is_none());
    }

    #[test]
    fn test_prune_stale() {
        let mut store = ProofStore::new(60_000);
        let fresh = test_entry("lon", "per", 10.0, 50_000);
        let stale = test_entry("nyc", "per", 20.0, 1000);
        store.insert(fresh);
        store.insert(stale);
        assert_eq!(store.len(), 2);

        let pruned = store.prune_stale(70_000);
        assert_eq!(pruned, 1);
        assert_eq!(store.len(), 1);
        assert!(store.get("lon", "per").is_some());
        assert!(store.get("nyc", "per").is_none());
    }

    #[test]
    fn test_merge_new() {
        let mut store = ProofStore::new(60_000);
        let entries = vec![
            test_entry("lon", "per", 10.0, 5000),
            test_entry("nyc", "per", 20.0, 5000),
        ];
        let accepted = store.merge(entries, 10_000);
        assert_eq!(accepted, 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_merge_stale_rejected() {
        let mut store = ProofStore::new(60_000);
        let entries = vec![test_entry("lon", "per", 10.0, 1000)];
        let accepted = store.merge(entries, 200_000);
        assert_eq!(accepted, 0);
        assert!(store.is_empty());
    }

    #[test]
    fn test_merge_older_rejected() {
        let mut store = ProofStore::new(60_000);
        let newer = test_entry("lon", "per", 10.0, 5000);
        store.insert(newer);

        let entries = vec![test_entry("lon", "per", 15.0, 3000)];
        let accepted = store.merge(entries, 10_000);
        assert_eq!(accepted, 0);
        assert_eq!(store.get("lon", "per").unwrap().rtt_ms, 10.0);
    }

    #[test]
    fn test_diff_empty_peer() {
        let mut store = ProofStore::new(60_000);
        store.insert(test_entry("lon", "per", 10.0, 5000));
        store.insert(test_entry("nyc", "per", 20.0, 5000));

        let diff = store.diff_for_peer(&Spore::empty());
        assert_eq!(diff.len(), 2);
    }

    #[test]
    fn test_diff_synced_peer() {
        let mut store = ProofStore::new(60_000);
        store.insert(test_entry("lon", "per", 10.0, 5000));
        store.insert(test_entry("nyc", "per", 20.0, 5000));

        let diff = store.diff_for_peer(store.spore());
        assert_eq!(diff.len(), 0);
    }

    #[test]
    fn test_latency_map() {
        let mut store = ProofStore::new(60_000);
        store.insert(test_entry("lon", "per", 10.0, 50_000));
        store.insert(test_entry("nyc", "per", 20.0, 1000));

        let map = store.latency_map(70_000);
        assert_eq!(map.len(), 1);
        let key = ProofStore::edge_key("lon", "per");
        assert_eq!(*map.get(&key).unwrap(), 10.0);
    }

    #[test]
    fn test_known_peers() {
        let mut store = ProofStore::new(60_000);
        store.insert(test_entry("lon", "per", 10.0, 5000));
        store.insert(test_entry("nyc", "per", 20.0, 5000));

        let peers = store.known_peers();
        assert_eq!(peers.len(), 3);
        assert!(peers.contains("lon"));
        assert!(peers.contains("per"));
        assert!(peers.contains("nyc"));
    }

    #[test]
    fn test_make_entry_content_id() {
        let proof_bytes = b"hello world".to_vec();
        let expected = *blake3::hash(&proof_bytes).as_bytes();
        let entry = ProofStore::make_entry(
            ("a".to_owned(), "b".to_owned()),
            5.0,
            1000,
            proof_bytes,
        );
        assert_eq!(entry.content_id, expected);
    }

    #[test]
    fn test_proof_data_for_gossip() {
        let mut store = ProofStore::new(60_000);
        store.insert(test_entry("lon", "per", 10.0, 5000));
        store.insert(test_entry("nyc", "per", 20.0, 5000));

        let data = store.proof_data_for_gossip();
        assert_eq!(data.len(), 2);
        for (bytes, cid) in &data {
            assert!(!bytes.is_empty());
            // content_id should be BLAKE3 of the proof_bytes, not the serialized entry
            assert_ne!(*cid, [0u8; 32]);
        }
    }
}
