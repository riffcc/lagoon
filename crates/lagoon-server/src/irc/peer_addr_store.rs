//! Peer address store: SPORE-indexed storage for mesh peer address records.
//!
//! Every known peer's address info (peer_id, server_name, underlay_uri, etc.)
//! is stored here and gossiped to SPIRAL neighbors via SPORE diff-sync.
//! This ensures eventual consistency: all nodes eventually learn about all
//! peers' connection addresses even if they weren't connected at the time of
//! initial peer discovery.
//!
//! ## Design Decisions
//!
//! - **Keyed by peer_id**: each peer has exactly one address record.
//!   Newer records (higher timestamp_ms) replace older ones.
//!
//! - **Monotonic SPORE growth**: replaced records leave their old content_id
//!   in the SPORE. Harmless: stale content IDs just mean a peer skips
//!   re-requesting data we already replaced.
//!
//! - **TTL-based pruning**: records older than `ttl_ms` are removed on
//!   `prune_stale()`. No polling, no background tasks.
//!
//! - **Volatile fields excluded**: VDF hashes, SPIRAL index, and cluster chain
//!   change every tick — they're not address info and don't affect dialing.

use std::collections::HashMap;

use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};

/// A peer address record — the minimum info needed to dial a peer.
///
/// Serialized and gossiped via SPORE diff-sync. Excludes volatile VDF/SPIRAL
/// fields which change every tick and aren't relevant to connection dialing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddrRecord {
    /// Cryptographic peer identity (`"b3b3/{hex}"`).
    pub peer_id: String,
    /// The peer's server name (e.g. `"per.lagun.co"`).
    pub server_name: String,
    /// Node identity within site (e.g. `"per"`).
    pub node_name: String,
    /// Site identity (e.g. `"lagun.co"`).
    pub site_name: String,
    /// Hex-encoded ed25519 public key.
    pub public_key_hex: String,
    /// Port the peer listens on.
    pub port: u16,
    /// Whether the peer uses TLS/WSS.
    pub tls: bool,
    /// Yggdrasil overlay IPv6 address (None if no Ygg).
    pub yggdrasil_addr: Option<String>,
    /// Yggdrasil underlay peer URI for direct peering (e.g. `tcp://[10.7.1.37]:9443`).
    pub underlay_uri: Option<String>,
    /// Self-reported Yggdrasil peer URI (e.g. `tcp://[fdaa::...]:9443`).
    pub ygg_peer_uri: Option<String>,
    /// When this record was created (milliseconds since epoch).
    pub timestamp_ms: i64,
    /// BLAKE3 hash of key fields, used as SPORE content ID.
    pub content_id: [u8; 32],
}

/// SPORE-indexed store for peer address records.
#[derive(Debug)]
pub struct PeerAddrStore {
    records: HashMap<String, PeerAddrRecord>,
    spore: Spore,
    ttl_ms: i64,
}

/// Create a SPORE point range for a single U256 value.
fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

impl PeerAddrRecord {
    /// Build a record from component fields, computing content_id.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_id: String,
        server_name: String,
        node_name: String,
        site_name: String,
        public_key_hex: String,
        port: u16,
        tls: bool,
        yggdrasil_addr: Option<String>,
        underlay_uri: Option<String>,
        ygg_peer_uri: Option<String>,
        timestamp_ms: i64,
    ) -> Self {
        // content_id depends on addressing fields — changes when address changes
        let hash_input = format!(
            "{}:{}:{}:{}:{}",
            peer_id,
            timestamp_ms,
            underlay_uri.as_deref().unwrap_or(""),
            ygg_peer_uri.as_deref().unwrap_or(""),
            yggdrasil_addr.as_deref().unwrap_or(""),
        );
        let content_id: [u8; 32] = *blake3::hash(hash_input.as_bytes()).as_bytes();
        Self {
            peer_id,
            server_name,
            node_name,
            site_name,
            public_key_hex,
            port,
            tls,
            yggdrasil_addr,
            underlay_uri,
            ygg_peer_uri,
            timestamp_ms,
            content_id,
        }
    }

    /// Build a record from a `MeshPeerInfo`, computing content_id.
    pub fn from_mesh_peer_info(peer: &super::server::MeshPeerInfo, timestamp_ms: i64) -> Self {
        Self::new(
            peer.peer_id.clone(),
            peer.server_name.clone(),
            peer.node_name.clone(),
            peer.site_name.clone(),
            peer.public_key_hex.clone(),
            peer.port,
            peer.tls,
            peer.yggdrasil_addr.clone(),
            peer.underlay_uri.clone(),
            peer.ygg_peer_uri.clone(),
            timestamp_ms,
        )
    }
}

impl PeerAddrStore {
    /// Create a new peer address store with the given TTL.
    pub fn new(ttl_ms: i64) -> Self {
        Self {
            records: HashMap::new(),
            spore: Spore::empty(),
            ttl_ms,
        }
    }

    /// Insert a record. Returns `true` if new or replaces an older record.
    ///
    /// Records are keyed by `peer_id`. A record is accepted only if its
    /// `timestamp_ms` is strictly newer than any existing record for that peer.
    pub fn insert(&mut self, record: PeerAddrRecord) -> bool {
        if let Some(existing) = self.records.get(&record.peer_id) {
            if record.timestamp_ms <= existing.timestamp_ms {
                return false;
            }
        }

        let content_u256 = U256::from_be_bytes(&record.content_id);
        let point = Spore::from_range(point_range(content_u256));
        self.spore = self.spore.union(&point);

        self.records.insert(record.peer_id.clone(), record);
        true
    }

    /// Reference to the internal SPORE.
    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    /// Compute records a peer is missing based on their SPORE.
    pub fn diff_for_peer(&self, peer_spore: &Spore) -> Vec<PeerAddrRecord> {
        let missing = self.spore.subtract(peer_spore);
        self.records
            .values()
            .filter(|r| {
                let cid = U256::from_be_bytes(&r.content_id);
                missing.covers(&cid)
            })
            .cloned()
            .collect()
    }

    /// Merge incoming records, rejecting stale or older-than-existing ones.
    ///
    /// Returns the records that were actually accepted (new or fresher).
    /// Callers use this to determine which peers to dial.
    pub fn merge(&mut self, records: Vec<PeerAddrRecord>, now_ms: i64) -> Vec<PeerAddrRecord> {
        let mut accepted = Vec::new();
        for rec in records {
            if now_ms - rec.timestamp_ms > self.ttl_ms {
                continue; // too stale
            }
            if self.insert(rec.clone()) {
                accepted.push(rec);
            }
        }
        accepted
    }

    /// Remove records older than TTL. Does NOT shrink the SPORE.
    pub fn prune_stale(&mut self, now_ms: i64) {
        self.records
            .retain(|_, r| now_ms - r.timestamp_ms <= self.ttl_ms);
    }

    /// Get a record by peer_id.
    pub fn get(&self, peer_id: &str) -> Option<&PeerAddrRecord> {
        self.records.get(peer_id)
    }

    /// Serialized record data with content_id, for gossip diff.
    pub fn record_data_for_gossip(&self) -> Vec<(Vec<u8>, [u8; 32])> {
        self.records
            .values()
            .map(|r| {
                let serialized = bincode::serialize(r).unwrap_or_default();
                (serialized, r.content_id)
            })
            .collect()
    }

    /// Number of records stored.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(peer_id: &str, ts: i64) -> PeerAddrRecord {
        PeerAddrRecord::new(
            peer_id.to_owned(),
            format!("{peer_id}.lagun.co"),
            peer_id.to_owned(),
            "lagun.co".to_owned(),
            "aabbccdd".to_owned(),
            9443,
            false,
            None,
            None,
            None,
            ts,
        )
    }

    fn make_record_with_addr(peer_id: &str, ts: i64, underlay: &str) -> PeerAddrRecord {
        PeerAddrRecord::new(
            peer_id.to_owned(),
            format!("{peer_id}.lagun.co"),
            peer_id.to_owned(),
            "lagun.co".to_owned(),
            "aabbccdd".to_owned(),
            9443,
            false,
            None,
            Some(underlay.to_owned()),
            None,
            ts,
        )
    }

    #[test]
    fn test_insert_new() {
        let mut store = PeerAddrStore::new(120_000);
        assert!(store.insert(make_record("node-a", 1000)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_older_rejected() {
        let mut store = PeerAddrStore::new(120_000);
        assert!(store.insert(make_record("node-a", 2000)));
        assert!(!store.insert(make_record("node-a", 1000)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_insert_newer_replaces() {
        let mut store = PeerAddrStore::new(120_000);
        assert!(store.insert(make_record("node-a", 1000)));
        assert!(store.insert(make_record("node-a", 2000)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_prune_stale() {
        let mut store = PeerAddrStore::new(60_000);
        store.insert(make_record("node-a", 50_000)); // fresh
        store.insert(make_record("node-b", 1000));   // stale at 70_000
        assert_eq!(store.len(), 2);
        store.prune_stale(70_000);
        assert_eq!(store.len(), 1);
        assert!(store.get("node-a").is_some());
    }

    #[test]
    fn test_merge_accepts_fresh() {
        let mut store = PeerAddrStore::new(120_000);
        let records = vec![make_record("node-a", 5000), make_record("node-b", 5000)];
        let accepted = store.merge(records, 10_000);
        assert_eq!(accepted.len(), 2);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_merge_rejects_stale() {
        let mut store = PeerAddrStore::new(60_000);
        let records = vec![make_record("node-a", 1000)];
        let accepted = store.merge(records, 200_000); // 199s old > 60s TTL
        assert!(accepted.is_empty());
        assert!(store.is_empty());
    }

    #[test]
    fn test_merge_returns_newly_accepted() {
        let mut store = PeerAddrStore::new(120_000);
        // Pre-populate with a record
        store.insert(make_record("node-a", 5000));
        // Merge includes both an existing (stale) and a new one
        let records = vec![
            make_record("node-a", 4000), // older — rejected
            make_record("node-b", 5000), // new — accepted
        ];
        let accepted = store.merge(records, 10_000);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].peer_id, "node-b");
    }

    #[test]
    fn test_diff_empty_peer() {
        let mut store = PeerAddrStore::new(120_000);
        store.insert(make_record("node-a", 5000));
        store.insert(make_record("node-b", 5000));
        let diff = store.diff_for_peer(&Spore::empty());
        assert_eq!(diff.len(), 2);
    }

    #[test]
    fn test_diff_synced_peer() {
        let mut store = PeerAddrStore::new(120_000);
        store.insert(make_record("node-a", 5000));
        let diff = store.diff_for_peer(store.spore());
        assert_eq!(diff.len(), 0);
    }

    #[test]
    fn test_record_data_for_gossip() {
        let mut store = PeerAddrStore::new(120_000);
        store.insert(make_record("node-a", 5000));
        let data = store.record_data_for_gossip();
        assert_eq!(data.len(), 1);
        assert!(!data[0].0.is_empty());
        assert_ne!(data[0].1, [0u8; 32]);
    }

    #[test]
    fn test_content_id_changes_with_address() {
        let r1 = make_record_with_addr("node-a", 1000, "tcp://[10.0.0.1]:9443");
        let r2 = make_record_with_addr("node-a", 2000, "tcp://[10.0.0.2]:9443");
        // Different timestamps and addresses → different content_ids
        assert_ne!(r1.content_id, r2.content_id);
    }

    #[test]
    fn test_content_id_deterministic() {
        let r1 = make_record("node-a", 1000);
        let r2 = make_record("node-a", 1000);
        assert_eq!(r1.content_id, r2.content_id);
    }

    #[test]
    fn test_record_roundtrip_bincode() {
        let record = make_record_with_addr("node-a", 5000, "tcp://[200:1234::1]:9443");
        let bytes = bincode::serialize(&record).expect("serialize");
        let decoded: PeerAddrRecord = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.peer_id, record.peer_id);
        assert_eq!(decoded.underlay_uri, record.underlay_uri);
        assert_eq!(decoded.content_id, record.content_id);
    }

    #[test]
    fn test_spore_grows_monotonically() {
        let mut store = PeerAddrStore::new(120_000);
        store.insert(make_record("node-a", 1000));
        let encoding_before = store.spore().encoding_size();

        // Insert a newer record for the same peer (different timestamp → different content_id)
        store.insert(make_record("node-a", 2000));
        // SPORE should have grown (old content_id still tracked + new one adds another range)
        assert!(store.spore().encoding_size() >= encoding_before);
    }
}
