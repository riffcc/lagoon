/// User profile CRDT — bilateral merge with proven convergence.
///
/// Profiles spread organically through the mesh via pull-on-demand:
///   1. User registers on Server A → profile stored locally
///   2. User logs into Server B → B queries mesh → caches profile
///   3. CRDT merge ensures no data loss across nodes
///
/// Passkeys use GSet (grow-only set) semantics — credentials can be added
/// from any node, and merge always produces the union. Metadata uses LWW
/// (last-writer-wins) keyed by modified_at timestamp.
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use citadel_crdt::TotalMerge;
use citadel_spore::{Range256, Spore, U256};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;
use tracing::{info, warn};

/// Convert a 256-bit content ID to a single-point SPORE range `[v, v+1)`.
fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

/// A user profile — the unit of replication across mesh nodes.
///
/// Merge strategy per field:
///   - `username`: stable key (never changes)
///   - `uuid`: stable (set at creation, never overwritten)
///   - `credentials`: GSet — union of all passkey JSON strings
///   - `ed25519_pubkey`: LWW by `modified_at`
///   - `created_at`: min (preserve original registration time)
///   - `modified_at`: max (track latest edit for LWW)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserProfile {
    pub username: String,
    pub uuid: String,
    /// Serialized `webauthn_rs::prelude::Passkey` JSON strings.
    /// BTreeSet gives deterministic ordering + set union for GSet merge.
    pub credentials: BTreeSet<String>,
    pub ed25519_pubkey: Option<String>,
    /// ISO 8601 timestamp of first registration.
    pub created_at: String,
    /// ISO 8601 timestamp of last modification (LWW tiebreaker).
    pub modified_at: String,
}

impl TotalMerge for UserProfile {
    fn merge(&self, other: &Self) -> Self {
        let (newer, _older) = if self.modified_at >= other.modified_at {
            (self, other)
        } else {
            (other, self)
        };
        UserProfile {
            username: self.username.clone(),
            uuid: self.uuid.clone(),
            // GSet: union of all credentials from both nodes.
            credentials: self.credentials.union(&other.credentials).cloned().collect(),
            // LWW: take from whichever was modified more recently.
            ed25519_pubkey: newer.ed25519_pubkey.clone(),
            // min: preserve the earliest creation time.
            created_at: std::cmp::min(&self.created_at, &other.created_at).clone(),
            // max: track the latest modification.
            modified_at: newer.modified_at.clone(),
        }
    }
}

/// Profile store — local cache of user profiles with JSON persistence.
///
/// Follows the same atomic-write pattern as InviteStore and CommunityStore:
/// write to tmp file, then rename for crash safety.
pub struct ProfileStore {
    profiles: HashMap<String, UserProfile>,
    persist_path: Option<PathBuf>,
    /// Pending mesh queries: username → senders waiting for the result.
    pending_queries: HashMap<String, Vec<oneshot::Sender<Option<UserProfile>>>>,
    /// SPORE covering all profile content IDs — for cluster gossip diff.
    spore: Spore,
    /// Current content ID per username (BLAKE3 of bincode-serialized profile).
    content_ids: HashMap<String, [u8; 32]>,
}

impl std::fmt::Debug for ProfileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileStore")
            .field("profiles", &self.profiles.len())
            .field("pending_queries", &self.pending_queries.len())
            .field("content_ids", &self.content_ids.len())
            .finish()
    }
}

impl ProfileStore {
    /// Create a new empty store (no persistence).
    pub fn new() -> Self {
        Self {
            profiles: HashMap::new(),
            persist_path: None,
            pending_queries: HashMap::new(),
            spore: Spore::empty(),
            content_ids: HashMap::new(),
        }
    }

    /// Load from `{data_dir}/profiles.json` or start empty.
    pub fn load_or_create(data_dir: &Path) -> Self {
        let path = data_dir.join("profiles.json");
        let mut store = Self {
            profiles: HashMap::new(),
            persist_path: Some(path.clone()),
            pending_queries: HashMap::new(),
            spore: Spore::empty(),
            content_ids: HashMap::new(),
        };

        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<Vec<UserProfile>>(&json) {
                    Ok(list) => {
                        for p in list {
                            store.profiles.insert(p.username.clone(), p);
                        }
                        info!(count = store.profiles.len(), "loaded user profiles");
                    }
                    Err(e) => warn!("failed to parse profiles.json: {e}"),
                },
                Err(e) => warn!("failed to read profiles.json: {e}"),
            }
        }

        // Rebuild SPORE from loaded profiles.
        store.rebuild_spore();
        store
    }

    /// Look up a profile by username.
    pub fn get(&self, username: &str) -> Option<&UserProfile> {
        self.profiles.get(username)
    }

    /// Insert or merge a profile. Returns true if the profile was new or changed.
    pub fn put(&mut self, profile: UserProfile) -> bool {
        let username = profile.username.clone();
        let changed = if let Some(existing) = self.profiles.get(&username) {
            let merged = existing.merge(&profile);
            if merged != *existing {
                self.profiles.insert(username.clone(), merged);
                true
            } else {
                false
            }
        } else {
            self.profiles.insert(username.clone(), profile);
            true
        };

        if changed {
            // Recompute content ID and update SPORE (monotonic growth).
            if let Some(stored) = self.profiles.get(&username) {
                let content_id = Self::compute_content_id(stored);
                let u = U256::from_be_bytes(&content_id);
                let point = Spore::from_range(point_range(u));
                self.spore = self.spore.union(&point);
                self.content_ids.insert(username, content_id);
            }
            self.persist();
        }
        changed
    }

    /// Register a pending mesh query. Returns a receiver that will fire when
    /// a ProfileResponse arrives (or the query times out on the caller's side).
    pub fn register_query(&mut self, username: &str) -> oneshot::Receiver<Option<UserProfile>> {
        let (tx, rx) = oneshot::channel();
        self.pending_queries
            .entry(username.to_string())
            .or_default()
            .push(tx);
        rx
    }

    /// Resolve all pending queries for a username. Called when a ProfileResponse
    /// arrives from the mesh.
    pub fn resolve_query(&mut self, username: &str, profile: Option<UserProfile>) {
        if let Some(senders) = self.pending_queries.remove(username) {
            for tx in senders {
                let _ = tx.send(profile.clone());
            }
        }
    }

    /// Number of cached profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// SPORE covering all profile content IDs (for cluster gossip).
    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    /// Compute profiles that we have but the peer doesn't (based on SPORE diff).
    pub fn profiles_missing_from(&self, peer_spore: &Spore) -> Vec<&UserProfile> {
        let missing = self.spore.subtract(peer_spore);
        self.profiles
            .iter()
            .filter(|(username, _)| {
                if let Some(cid) = self.content_ids.get(*username) {
                    let u = U256::from_be_bytes(cid);
                    missing.covers(&u)
                } else {
                    false
                }
            })
            .map(|(_, profile)| profile)
            .collect()
    }

    /// Compute BLAKE3 content ID from a profile's bincode serialization.
    fn compute_content_id(profile: &UserProfile) -> [u8; 32] {
        let bytes = bincode::serialize(profile).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Rebuild SPORE and content_ids from all stored profiles.
    fn rebuild_spore(&mut self) {
        self.spore = Spore::empty();
        self.content_ids.clear();
        for (username, profile) in &self.profiles {
            let content_id = Self::compute_content_id(profile);
            let u = U256::from_be_bytes(&content_id);
            let point = Spore::from_range(point_range(u));
            self.spore = self.spore.union(&point);
            self.content_ids.insert(username.clone(), content_id);
        }
    }

    /// Atomic persist to disk (tmp + rename).
    fn persist(&self) {
        let Some(path) = &self.persist_path else {
            return;
        };
        let profiles: Vec<&UserProfile> = self.profiles.values().collect();
        match serde_json::to_string_pretty(&profiles) {
            Ok(json) => {
                let tmp = path.with_extension("json.tmp");
                if let Err(e) = std::fs::write(&tmp, &json) {
                    warn!("failed to write profiles tmp: {e}");
                    return;
                }
                if let Err(e) = std::fs::rename(&tmp, path) {
                    warn!("failed to rename profiles tmp: {e}");
                }
            }
            Err(e) => warn!("failed to serialize profiles: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_profile(username: &str, creds: &[&str], modified: &str) -> UserProfile {
        UserProfile {
            username: username.into(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            credentials: creds.iter().map(|s| (*s).to_string()).collect(),
            ed25519_pubkey: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            modified_at: modified.into(),
        }
    }

    #[test]
    fn gset_union_on_merge() {
        let a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        let b = make_profile("alice", &["cred_b"], "2026-01-01T00:00:00Z");
        let merged = a.merge(&b);
        assert_eq!(merged.credentials.len(), 2);
        assert!(merged.credentials.contains("cred_a"));
        assert!(merged.credentials.contains("cred_b"));
    }

    #[test]
    fn gset_union_with_overlap() {
        let a = make_profile("alice", &["cred_a", "cred_shared"], "2026-01-01T00:00:00Z");
        let b = make_profile("alice", &["cred_b", "cred_shared"], "2026-01-01T00:00:00Z");
        let merged = a.merge(&b);
        assert_eq!(merged.credentials.len(), 3);
    }

    #[test]
    fn lww_takes_newer_metadata() {
        let mut a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        a.ed25519_pubkey = Some("old_key".into());

        let mut b = make_profile("alice", &["cred_b"], "2026-06-15T12:00:00Z");
        b.ed25519_pubkey = Some("new_key".into());

        let merged = a.merge(&b);
        assert_eq!(merged.ed25519_pubkey, Some("new_key".into()));
    }

    #[test]
    fn min_created_at() {
        let mut a = make_profile("alice", &[], "2026-06-01T00:00:00Z");
        a.created_at = "2026-03-01T00:00:00Z".into();

        let mut b = make_profile("alice", &[], "2026-06-01T00:00:00Z");
        b.created_at = "2026-01-15T00:00:00Z".into();

        let merged = a.merge(&b);
        assert_eq!(merged.created_at, "2026-01-15T00:00:00Z");
    }

    #[test]
    fn merge_is_commutative() {
        let a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        let b = make_profile("alice", &["cred_b"], "2026-06-15T12:00:00Z");
        let ab = a.merge(&b);
        let ba = b.merge(&a);
        assert_eq!(ab, ba);
    }

    #[test]
    fn merge_is_idempotent() {
        let a = make_profile("alice", &["cred_a", "cred_b"], "2026-01-01T00:00:00Z");
        let aa = a.merge(&a);
        assert_eq!(a, aa);
    }

    #[test]
    fn merge_is_associative() {
        let a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        let b = make_profile("alice", &["cred_b"], "2026-03-01T00:00:00Z");
        let c = make_profile("alice", &["cred_c"], "2026-06-01T00:00:00Z");
        let ab_c = a.merge(&b).merge(&c);
        let a_bc = a.merge(&b.merge(&c));
        assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn profile_store_put_and_get() {
        let mut store = ProfileStore::new();
        let profile = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        assert!(store.put(profile));
        assert_eq!(store.get("alice").unwrap().credentials.len(), 1);
    }

    #[test]
    fn profile_store_merge_on_put() {
        let mut store = ProfileStore::new();
        let a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        let b = make_profile("alice", &["cred_b"], "2026-06-01T00:00:00Z");
        store.put(a);
        assert!(store.put(b));
        let stored = store.get("alice").unwrap();
        assert_eq!(stored.credentials.len(), 2);
    }

    #[test]
    fn profile_store_no_change_returns_false() {
        let mut store = ProfileStore::new();
        let a = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        store.put(a.clone());
        assert!(!store.put(a));
    }

    #[test]
    fn profile_store_persist_and_load() {
        let dir = std::env::temp_dir().join(format!("lagoon_profile_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        {
            let mut store = ProfileStore::load_or_create(&dir);
            store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
            store.put(make_profile("bob", &["cred_b"], "2026-02-01T00:00:00Z"));
            assert_eq!(store.len(), 2);
        }

        {
            let store = ProfileStore::load_or_create(&dir);
            assert_eq!(store.len(), 2);
            assert!(store.get("alice").is_some());
            assert!(store.get("bob").is_some());
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn pending_query_resolves() {
        let mut store = ProfileStore::new();
        let mut rx = store.register_query("alice");
        let profile = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        store.resolve_query("alice", Some(profile.clone()));
        let result = rx.try_recv().unwrap();
        assert_eq!(result, Some(profile));
    }

    #[test]
    fn pending_query_resolves_none() {
        let mut store = ProfileStore::new();
        let mut rx = store.register_query("ghost");
        store.resolve_query("ghost", None);
        let result = rx.try_recv().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn multiple_pending_queries_all_resolve() {
        let mut store = ProfileStore::new();
        let mut rx1 = store.register_query("alice");
        let mut rx2 = store.register_query("alice");
        let profile = make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z");
        store.resolve_query("alice", Some(profile.clone()));
        assert_eq!(rx1.try_recv().unwrap(), Some(profile.clone()));
        assert_eq!(rx2.try_recv().unwrap(), Some(profile));
    }

    #[test]
    fn spore_tracks_content_ids() {
        let mut store = ProfileStore::new();
        store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
        store.put(make_profile("bob", &["cred_b"], "2026-02-01T00:00:00Z"));
        store.put(make_profile("carol", &["cred_c"], "2026-03-01T00:00:00Z"));

        // All 3 content IDs should be covered by the SPORE.
        assert_eq!(store.content_ids.len(), 3);
        for cid in store.content_ids.values() {
            let u = U256::from_be_bytes(cid);
            assert!(store.spore.covers(&u));
        }
    }

    #[test]
    fn spore_grows_on_merge() {
        let mut store = ProfileStore::new();
        store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
        let cid_v1 = store.content_ids["alice"];

        // Merge with new credential — content_id changes.
        store.put(make_profile("alice", &["cred_b"], "2026-06-01T00:00:00Z"));
        let cid_v2 = store.content_ids["alice"];
        assert_ne!(cid_v1, cid_v2);

        // Both content IDs should be in the SPORE (monotonic growth).
        let u1 = U256::from_be_bytes(&cid_v1);
        let u2 = U256::from_be_bytes(&cid_v2);
        assert!(store.spore.covers(&u1));
        assert!(store.spore.covers(&u2));
    }

    #[test]
    fn profiles_missing_from_diff() {
        let mut store_a = ProfileStore::new();
        store_a.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
        store_a.put(make_profile("bob", &["cred_b"], "2026-02-01T00:00:00Z"));

        let mut store_b = ProfileStore::new();
        store_b.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));

        // A has bob, B doesn't. Diff should return bob.
        let missing = store_a.profiles_missing_from(store_b.spore());
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].username, "bob");
    }

    #[test]
    fn profiles_missing_from_empty_peer() {
        let mut store = ProfileStore::new();
        store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
        store.put(make_profile("bob", &["cred_b"], "2026-02-01T00:00:00Z"));

        let empty = Spore::empty();
        let missing = store.profiles_missing_from(&empty);
        assert_eq!(missing.len(), 2);
    }

    #[test]
    fn profiles_missing_from_identical_spore() {
        let mut store = ProfileStore::new();
        store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));

        // Peer has same SPORE — no diff.
        let missing = store.profiles_missing_from(store.spore());
        assert!(missing.is_empty());
    }

    #[test]
    fn load_recomputes_spore() {
        let dir = std::env::temp_dir().join(format!(
            "lagoon_profile_spore_test_{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let original_cids: HashMap<String, [u8; 32]>;
        {
            let mut store = ProfileStore::load_or_create(&dir);
            store.put(make_profile("alice", &["cred_a"], "2026-01-01T00:00:00Z"));
            store.put(make_profile("bob", &["cred_b"], "2026-02-01T00:00:00Z"));
            original_cids = store.content_ids.clone();
        }

        {
            let store = ProfileStore::load_or_create(&dir);
            // SPORE should be rebuilt from loaded profiles.
            assert_eq!(store.content_ids.len(), 2);
            assert_eq!(store.content_ids["alice"], original_cids["alice"]);
            assert_eq!(store.content_ids["bob"], original_cids["bob"]);
            for cid in store.content_ids.values() {
                let u = U256::from_be_bytes(cid);
                assert!(store.spore.covers(&u));
            }
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
