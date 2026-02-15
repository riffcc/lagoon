//! Bitmap-based liveness tracker with SPORE reconciliation.
//!
//! Each SPIRAL slot index maps to one bit: 1 = alive, 0 = dead/unknown.
//! The alive set IS the SPORE set — slot membership means alive.
//! SPORE XOR gives O(churn) delta reconciliation between peers.
//!
//! **OR-merge with local decay:**
//! - Receiving a `1` from any peer sets our bit to `1`, refreshes local timestamp
//! - Locally, if no fresh attestation within `decay_secs`, flip bit to `0`
//! - Dead node: neighbors stop attesting → `1`s stop propagating → everyone's
//!   bit independently decays to `0`
//!
//! **Event-driven:** every bitmap change triggers immediate SPORE push to all
//! SPIRAL neighbors. Convergence = MIN_LATENCY × HOPS.

use std::collections::{HashMap, HashSet};

use citadel_spore::{Range256, Spore, U256};

/// Create a SPORE point range for a single U256 value: [v, v+1).
fn point_range(v: U256) -> Range256 {
    let next = v.checked_add(&U256::from_u64(1)).unwrap_or(U256::MAX);
    Range256::new(v, next)
}

/// Bitmap-based liveness tracker using SPORE for reconciliation.
///
/// Each alive SPIRAL slot is a member of the SPORE set. Dead slots are absent.
/// SPORE's XOR-based reconciliation identifies exactly which slots two peers
/// disagree on — O(churn), not O(mesh_size).
///
/// Timestamps are LOCAL ONLY — never transmitted. They exist purely for
/// decay timing (flipping stale bits to 0).
#[derive(Debug)]
pub struct LivenessBitmap {
    /// Set of currently-alive SPIRAL slot indices.
    alive: HashSet<u64>,
    /// Local bookkeeping: slot → last time this bit was set/refreshed (epoch secs).
    /// Never transmitted. Used only for local decay timing.
    last_refreshed: HashMap<u64, u64>,
    /// SPORE representation of the alive set.
    /// Incrementally grown via union on set_alive, fully rebuilt on decay.
    spore: Spore,
    /// Decay timeout: bits not refreshed within this many seconds are flipped to 0.
    decay_secs: u64,
}

impl LivenessBitmap {
    /// Create a new empty liveness bitmap.
    pub fn new(decay_secs: u64) -> Self {
        LivenessBitmap {
            alive: HashSet::new(),
            last_refreshed: HashMap::new(),
            spore: Spore::empty(),
            decay_secs,
        }
    }

    /// Deterministic content ID for a SPIRAL slot.
    /// `blake3(slot.to_le_bytes())` → used as SPORE item identifier.
    pub fn content_id_for_slot(slot: u64) -> [u8; 32] {
        *blake3::hash(&slot.to_le_bytes()).as_bytes()
    }

    /// Set a slot as alive. Returns `true` if the bit was newly set (0→1).
    ///
    /// Always refreshes the local timestamp. The SPORE is incrementally
    /// updated (union) only when a new bit is set — no rebuild needed.
    pub fn set_alive(&mut self, slot: u64, now_secs: u64) -> bool {
        self.last_refreshed.insert(slot, now_secs);
        let is_new = self.alive.insert(slot);
        if is_new {
            // Incremental SPORE growth — one union per new slot.
            let cid = Self::content_id_for_slot(slot);
            let u = U256::from_be_bytes(&cid);
            let point = Spore::from_range(point_range(u));
            self.spore = self.spore.union(&point);
        }
        is_new
    }

    /// Decay stale bits: flip any bit not refreshed within `decay_secs` to 0.
    ///
    /// Returns `true` if any bits were flipped (bitmap changed).
    /// Triggers a full SPORE rebuild since SPORE doesn't support removal.
    pub fn decay(&mut self, now_secs: u64) -> bool {
        let before = self.alive.len();
        let decay_secs = self.decay_secs;
        let last_refreshed = &self.last_refreshed;
        self.alive.retain(|slot| {
            last_refreshed
                .get(slot)
                .map(|&ts| now_secs.saturating_sub(ts) <= decay_secs)
                .unwrap_or(false)
        });
        self.last_refreshed
            .retain(|slot, _| self.alive.contains(slot));
        if self.alive.len() != before {
            self.rebuild_spore();
            true
        } else {
            false
        }
    }

    /// Is this slot currently alive?
    pub fn get(&self, slot: u64) -> bool {
        self.alive.contains(&slot)
    }

    /// Number of alive slots.
    pub fn alive_count(&self) -> usize {
        self.alive.len()
    }

    /// Reference to the SPORE representation of the alive set.
    /// Always up-to-date (eagerly maintained on set_alive/decay).
    pub fn spore(&self) -> &Spore {
        &self.spore
    }

    /// Slot data for SPORE delta generation.
    ///
    /// Returns `(serialized_slot, content_id)` pairs for all alive slots.
    /// The gossip coordinator filters these by SPORE diff ranges.
    pub fn slot_data(&self) -> Vec<(Vec<u8>, [u8; 32])> {
        self.alive
            .iter()
            .map(|&slot| {
                let bytes = bincode::serialize(&slot).unwrap_or_default();
                let cid = Self::content_id_for_slot(slot);
                (bytes, cid)
            })
            .collect()
    }

    /// Compute alive slots that a peer is missing, based on their SPORE.
    ///
    /// Returns serialized slot entries for the delta.
    pub fn diff_for_peer(&self, peer_spore: &Spore) -> Vec<Vec<u8>> {
        let missing = self.spore.subtract(peer_spore);
        if missing.is_empty() {
            return Vec::new();
        }
        self.alive
            .iter()
            .filter(|&&slot| {
                let cid = Self::content_id_for_slot(slot);
                let u = U256::from_be_bytes(&cid);
                missing.covers(&u)
            })
            .map(|&slot| bincode::serialize(&slot).unwrap_or_default())
            .collect()
    }

    /// Merge received slot data (from a SPORE delta). OR-merge semantics:
    /// every slot received is set to alive, timestamp refreshed.
    ///
    /// Returns count of newly-set bits (0→1 transitions).
    pub fn merge_slots(&mut self, slot_bytes_list: &[Vec<u8>], now_secs: u64) -> usize {
        let mut new_count = 0;
        for bytes in slot_bytes_list {
            if let Ok(slot) = bincode::deserialize::<u64>(bytes) {
                if self.set_alive(slot, now_secs) {
                    new_count += 1;
                }
            }
        }
        new_count
    }

    /// Rebuild the SPORE from scratch using the current alive set.
    /// Called after decay removes slots (SPORE doesn't support removal).
    fn rebuild_spore(&mut self) {
        let mut spore = Spore::empty();
        for &slot in &self.alive {
            let cid = Self::content_id_for_slot(slot);
            let u = U256::from_be_bytes(&cid);
            let point = Spore::from_range(point_range(u));
            spore = spore.union(&point);
        }
        self.spore = spore;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let bm = LivenessBitmap::new(20);
        assert_eq!(bm.alive_count(), 0);
        assert!(!bm.get(0));
        assert!(!bm.get(42));
    }

    #[test]
    fn test_set_alive_new_bit() {
        let mut bm = LivenessBitmap::new(20);
        assert!(bm.set_alive(5, 100));
        assert!(bm.get(5));
        assert_eq!(bm.alive_count(), 1);
    }

    #[test]
    fn test_set_alive_existing_bit_returns_false() {
        let mut bm = LivenessBitmap::new(20);
        assert!(bm.set_alive(5, 100));
        assert!(!bm.set_alive(5, 105)); // refresh, not new
        assert!(bm.get(5));
        assert_eq!(bm.alive_count(), 1);
    }

    #[test]
    fn test_set_alive_refreshes_timestamp() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(5, 100);
        bm.set_alive(5, 115);
        // Should not decay at t=130 (only 15s since refresh)
        assert!(!bm.decay(130));
        assert!(bm.get(5));
    }

    #[test]
    fn test_decay_removes_stale() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        bm.set_alive(2, 100);
        bm.set_alive(3, 115);

        // At t=125: slot 1 and 2 are 25s old (stale), slot 3 is 10s old (fresh)
        assert!(bm.decay(125));
        assert!(!bm.get(1));
        assert!(!bm.get(2));
        assert!(bm.get(3));
        assert_eq!(bm.alive_count(), 1);
    }

    #[test]
    fn test_decay_no_change_returns_false() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        // At t=110: only 10s old, not stale
        assert!(!bm.decay(110));
        assert!(bm.get(1));
    }

    #[test]
    fn test_decay_at_boundary() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        // At exactly t=120: 20s old = decay_secs, NOT stale (<=)
        assert!(!bm.decay(120));
        assert!(bm.get(1));
        // At t=121: 21s old > decay_secs, stale
        assert!(bm.decay(121));
        assert!(!bm.get(1));
    }

    #[test]
    fn test_spore_reflects_alive_set() {
        let mut bm = LivenessBitmap::new(20);
        // Empty bitmap → empty SPORE
        assert!(bm.spore().subtract(&Spore::empty()).is_empty());

        bm.set_alive(1, 100);
        bm.set_alive(2, 100);
        // SPORE should contain both slots
        let cid1 = LivenessBitmap::content_id_for_slot(1);
        let cid2 = LivenessBitmap::content_id_for_slot(2);
        let u1 = U256::from_be_bytes(&cid1);
        let u2 = U256::from_be_bytes(&cid2);
        // SPORE covers both content IDs
        assert!(!bm.spore().subtract(&Spore::empty()).is_empty());
        // Build a peer SPORE with both slots — diff should be empty
        let peer_spore = bm.spore().clone();
        assert!(bm.spore().subtract(&peer_spore).is_empty());

        // Verify individual coverage via point check
        let full_range = bm.spore().subtract(&Spore::empty());
        assert!(full_range.covers(&u1));
        assert!(full_range.covers(&u2));
    }

    #[test]
    fn test_spore_rebuilt_after_decay() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        bm.set_alive(2, 100);

        // Before decay: SPORE has both
        let cid1 = LivenessBitmap::content_id_for_slot(1);
        let u1 = U256::from_be_bytes(&cid1);
        let cid2 = LivenessBitmap::content_id_for_slot(2);
        let u2 = U256::from_be_bytes(&cid2);

        let full = bm.spore().subtract(&Spore::empty());
        assert!(full.covers(&u1));
        assert!(full.covers(&u2));

        // Refresh only slot 2, then decay
        bm.set_alive(2, 115);
        bm.decay(125);

        // After decay: slot 1 gone, slot 2 stays
        assert!(!bm.get(1));
        assert!(bm.get(2));
        let full = bm.spore().subtract(&Spore::empty());
        assert!(!full.covers(&u1));
        assert!(full.covers(&u2));
    }

    #[test]
    fn test_slot_data_matches_alive_set() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(7, 100);
        bm.set_alive(42, 100);

        let data = bm.slot_data();
        assert_eq!(data.len(), 2);

        // Verify content IDs are correct
        for (bytes, cid) in &data {
            let slot: u64 = bincode::deserialize(bytes).unwrap();
            assert_eq!(*cid, LivenessBitmap::content_id_for_slot(slot));
            assert!(slot == 7 || slot == 42);
        }
    }

    #[test]
    fn test_diff_for_peer_empty_peer() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        bm.set_alive(2, 100);

        let diff = bm.diff_for_peer(&Spore::empty());
        assert_eq!(diff.len(), 2);

        let slots: HashSet<u64> = diff
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();
        assert!(slots.contains(&1));
        assert!(slots.contains(&2));
    }

    #[test]
    fn test_diff_for_peer_synced() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        bm.set_alive(2, 100);

        let peer_spore = bm.spore().clone();
        let diff = bm.diff_for_peer(&peer_spore);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_diff_for_peer_partial() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(1, 100);
        bm.set_alive(2, 100);
        bm.set_alive(3, 100);

        // Peer has slot 1 only
        let mut peer = LivenessBitmap::new(20);
        peer.set_alive(1, 100);
        let peer_spore = peer.spore().clone();

        let diff = bm.diff_for_peer(&peer_spore);
        assert_eq!(diff.len(), 2);
        let slots: HashSet<u64> = diff
            .iter()
            .map(|b| bincode::deserialize(b).unwrap())
            .collect();
        assert!(slots.contains(&2));
        assert!(slots.contains(&3));
        assert!(!slots.contains(&1));
    }

    #[test]
    fn test_merge_slots_new() {
        let mut bm = LivenessBitmap::new(20);
        let slot_bytes: Vec<Vec<u8>> = vec![
            bincode::serialize(&5u64).unwrap(),
            bincode::serialize(&10u64).unwrap(),
        ];
        let new_count = bm.merge_slots(&slot_bytes, 100);
        assert_eq!(new_count, 2);
        assert!(bm.get(5));
        assert!(bm.get(10));
        assert_eq!(bm.alive_count(), 2);
    }

    #[test]
    fn test_merge_slots_existing() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(5, 100);

        let slot_bytes: Vec<Vec<u8>> = vec![
            bincode::serialize(&5u64).unwrap(),
            bincode::serialize(&10u64).unwrap(),
        ];
        let new_count = bm.merge_slots(&slot_bytes, 105);
        assert_eq!(new_count, 1); // only slot 10 is new
        assert!(bm.get(5));
        assert!(bm.get(10));
    }

    #[test]
    fn test_merge_refreshes_timestamp() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(5, 100);

        // Merge at t=115 refreshes slot 5's timestamp
        let slot_bytes: Vec<Vec<u8>> = vec![bincode::serialize(&5u64).unwrap()];
        bm.merge_slots(&slot_bytes, 115);

        // At t=130: 15s since refresh, should NOT decay
        assert!(!bm.decay(130));
        assert!(bm.get(5));
    }

    #[test]
    fn test_content_id_deterministic() {
        let a = LivenessBitmap::content_id_for_slot(42);
        let b = LivenessBitmap::content_id_for_slot(42);
        assert_eq!(a, b);
    }

    #[test]
    fn test_content_id_differs_by_slot() {
        let a = LivenessBitmap::content_id_for_slot(1);
        let b = LivenessBitmap::content_id_for_slot(2);
        assert_ne!(a, b);
    }

    #[test]
    fn test_or_merge_semantics() {
        // OR-merge: 1 always wins over 0.
        // If peer A has {1, 2, 3} and peer B has {2, 4},
        // after A merges B's delta: A has {1, 2, 3, 4}
        let mut a = LivenessBitmap::new(20);
        a.set_alive(1, 100);
        a.set_alive(2, 100);
        a.set_alive(3, 100);

        let mut b = LivenessBitmap::new(20);
        b.set_alive(2, 100);
        b.set_alive(4, 100);

        // B's diff for A (what B has that A doesn't)
        let a_spore = a.spore().clone();
        let delta = b.diff_for_peer(&a_spore);

        // A merges B's delta
        let new_count = a.merge_slots(&delta, 100);
        assert_eq!(new_count, 1); // only slot 4 is new
        assert!(a.get(1));
        assert!(a.get(2));
        assert!(a.get(3));
        assert!(a.get(4));
    }

    #[test]
    fn test_decay_then_reanimate() {
        let mut bm = LivenessBitmap::new(20);
        bm.set_alive(5, 100);
        assert!(bm.get(5));

        // Decay at t=125 (25s > 20s)
        assert!(bm.decay(125));
        assert!(!bm.get(5));
        assert_eq!(bm.alive_count(), 0);

        // Re-animate at t=130
        assert!(bm.set_alive(5, 130));
        assert!(bm.get(5));
        assert_eq!(bm.alive_count(), 1);

        // SPORE should reflect the re-animation
        let cid = LivenessBitmap::content_id_for_slot(5);
        let u = U256::from_be_bytes(&cid);
        let full = bm.spore().subtract(&Spore::empty());
        assert!(full.covers(&u));
    }

    #[test]
    fn test_full_reconciliation_cycle() {
        // Simulate two peers syncing via SPORE:
        // Peer A has {1, 2, 3}, Peer B has {3, 4, 5}
        let mut a = LivenessBitmap::new(20);
        a.set_alive(1, 100);
        a.set_alive(2, 100);
        a.set_alive(3, 100);

        let mut b = LivenessBitmap::new(20);
        b.set_alive(3, 100);
        b.set_alive(4, 100);
        b.set_alive(5, 100);

        // A sends HaveList (SPORE) to B
        let a_spore = a.spore().clone();
        // B computes diff and sends delta to A
        let b_delta_for_a = b.diff_for_peer(&a_spore);
        // A merges B's delta
        let a_new = a.merge_slots(&b_delta_for_a, 100);
        assert_eq!(a_new, 2); // slots 4, 5

        // B sends HaveList (SPORE) to A
        let b_spore = b.spore().clone();
        // A computes diff and sends delta to B
        let a_delta_for_b = a.diff_for_peer(&b_spore);
        // B merges A's delta
        let b_new = b.merge_slots(&a_delta_for_b, 100);
        assert_eq!(b_new, 2); // slots 1, 2

        // Both now have {1, 2, 3, 4, 5}
        for slot in 1..=5 {
            assert!(a.get(slot), "A missing slot {slot}");
            assert!(b.get(slot), "B missing slot {slot}");
        }
        assert_eq!(a.alive_count(), 5);
        assert_eq!(b.alive_count(), 5);

        // SPOREs should now agree
        assert!(a.spore().subtract(b.spore()).is_empty());
        assert!(b.spore().subtract(a.spore()).is_empty());
    }
}
