//! SPIRAL Topology Engine for Lagoon mesh peer selection.
//!
//! Bridges citadel-topology's 3D hexagonal SPIRAL to Lagoon's mesh networking.
//! Each node claims a slot in the SPIRAL, and `compute_all_connections` with
//! gap-and-wrap determines the 20 neighbors it should maintain direct
//! federation connections to.

use std::collections::{HashMap, HashSet};

pub use citadel_topology::Spiral3DIndex;
use citadel_topology::{compute_all_connections, spiral3d_to_coord, HexCoord};

/// Convert hex coordinates to 3D world position for visualization.
///
/// Hex plane on XZ, z-layer maps to Y. Same formula as downward-spiral's
/// `HexCoord3D::to_world()`.
pub fn hex_to_world(coord: HexCoord) -> [f64; 3] {
    let q = coord.q as f64;
    let r = coord.r as f64;
    let x = 3.0_f64.sqrt() * (q + r * 0.5);
    let y = coord.z as f64 * 3.0_f64.sqrt();
    let z = 1.5 * r;
    [x, y, z]
}

/// SPIRAL topology state for this node's mesh.
///
/// All string keys are mesh keys (`"{site_name}/{node_name}"`), the globally
/// unique 2D identity for each node in the mesh.
#[derive(Debug)]
pub struct SpiralTopology {
    /// Our SPIRAL position (None = unclaimed, waiting for network info).
    our_index: Option<Spiral3DIndex>,
    our_coord: Option<HexCoord>,
    our_mesh_key: Option<String>,
    /// All occupied positions: coord → mesh_key.
    occupied: HashMap<HexCoord, String>,
    /// Reverse: mesh_key → (index, coord).
    peer_positions: HashMap<String, (Spiral3DIndex, HexCoord)>,
    /// Current 20-neighbor set (mesh_keys).
    neighbors: HashSet<String>,
}

impl SpiralTopology {
    /// Create a new unclaimed topology.
    pub fn new() -> Self {
        Self {
            our_index: None,
            our_coord: None,
            our_mesh_key: None,
            occupied: HashMap::new(),
            peer_positions: HashMap::new(),
            neighbors: HashSet::new(),
        }
    }

    /// Claim the lowest unclaimed SPIRAL slot. Returns the claimed index.
    ///
    /// Enumerates slots in spiral order from origin, claims the first one
    /// not already occupied. This is SPIRAL self-assembly — first-come,
    /// first-served, sequential from center.
    pub fn claim_position(&mut self, our_mesh_key: &str) -> Spiral3DIndex {
        // Clean up old self entry if re-claiming after a move.
        if let Some(old_coord) = self.our_coord {
            if self.occupied.get(&old_coord).map(|s| s.as_str()) == Some(our_mesh_key) {
                self.occupied.remove(&old_coord);
            }
        }

        // Find first unclaimed slot in spiral order.
        let mut i = 0u64;
        let idx = loop {
            let idx = Spiral3DIndex::new(i);
            let coord = spiral3d_to_coord(idx);
            if !self.occupied.contains_key(&coord) {
                break idx;
            }
            i += 1;
        };

        let coord = spiral3d_to_coord(idx);
        self.our_index = Some(idx);
        self.our_coord = Some(coord);
        self.our_mesh_key = Some(our_mesh_key.to_string());
        self.occupied.insert(coord, our_mesh_key.to_string());
        self.recompute_neighbors();
        idx
    }

    /// Check if we should converge to a better (lower-indexed) slot.
    ///
    /// SPIRAL's iterative convergence protocol: after learning new topology
    /// information (gossip, peer eviction), each node re-evaluates whether
    /// there's an unoccupied slot closer to the origin than its current position.
    /// If yes, the node should vacate and reclaim — filling holes naturally.
    ///
    /// Returns `Some(better_index)` if a lower slot is available, `None` if
    /// we're already at the optimal position for the current topology.
    pub fn evaluate_position(&self) -> Option<Spiral3DIndex> {
        let our_idx = self.our_index?;
        // If we're at slot 0 (origin), can't do better.
        if our_idx.value() == 0 {
            return None;
        }
        // Scan from slot 0 up to (but not including) our current slot.
        for i in 0..our_idx.value() {
            let idx = Spiral3DIndex::new(i);
            let coord = spiral3d_to_coord(idx);
            if !self.occupied.contains_key(&coord) {
                return Some(idx);
            }
        }
        None
    }

    /// Restore a persisted SPIRAL position on restart.
    pub fn set_position(&mut self, our_mesh_key: &str, index: Spiral3DIndex) {
        // Clean up old self entry if changing position.
        if let Some(old_coord) = self.our_coord {
            if self.occupied.get(&old_coord).map(|s| s.as_str()) == Some(our_mesh_key) {
                self.occupied.remove(&old_coord);
            }
        }

        let coord = spiral3d_to_coord(index);
        self.our_index = Some(index);
        self.our_coord = Some(coord);
        self.our_mesh_key = Some(our_mesh_key.to_string());
        self.occupied.insert(coord, our_mesh_key.to_string());
        self.recompute_neighbors();
    }

    /// Force-register a peer at a SPIRAL slot, evicting any existing occupant.
    ///
    /// Used for collision resolution: the winner keeps the slot, the loser
    /// is evicted. Returns the evicted mesh_key (if any).
    pub fn force_add_peer(&mut self, mesh_key: &str, index: Spiral3DIndex) -> Option<String> {
        let coord = spiral3d_to_coord(index);

        // Remove existing occupant at target coord (if different from new claimant).
        let evicted = self.occupied.get(&coord).cloned().filter(|existing| existing != mesh_key);
        if let Some(ref evicted_key) = evicted {
            self.peer_positions.remove(evicted_key);
            // If we evicted ourselves, clear our_* fields.
            if self.our_mesh_key.as_deref() == Some(evicted_key.as_str()) {
                self.our_index = None;
                self.our_coord = None;
                self.our_mesh_key = None;
            }
        }

        // If this peer was already at a DIFFERENT coord, free the old slot.
        if let Some((_, old_coord)) = self.peer_positions.get(mesh_key) {
            if *old_coord != coord {
                // Only remove from occupied if this mesh_key still owns the old slot.
                if self.occupied.get(old_coord).map(|s| s.as_str()) == Some(mesh_key) {
                    self.occupied.remove(old_coord);
                }
            }
        }

        self.occupied.insert(coord, mesh_key.to_string());
        self.peer_positions
            .insert(mesh_key.to_string(), (index, coord));
        self.recompute_neighbors();
        evicted
    }

    /// Register a peer's claimed SPIRAL slot. Returns true if our neighbor
    /// set changed.
    pub fn add_peer(&mut self, mesh_key: &str, index: Spiral3DIndex) -> bool {
        let coord = spiral3d_to_coord(index);

        // Don't overwrite an existing occupant at this coord (first-writer-wins).
        if let Some(existing) = self.occupied.get(&coord) {
            if existing != mesh_key {
                return false;
            }
        }

        // If this peer was already at a DIFFERENT coord, free the old slot.
        // Without this, moving a peer creates a ghost in `occupied` at the
        // old coord — `claim_position()` skips it forever, inflating slot numbers.
        if let Some((_, old_coord)) = self.peer_positions.get(mesh_key) {
            if *old_coord != coord {
                if self.occupied.get(old_coord).map(|s| s.as_str()) == Some(mesh_key) {
                    self.occupied.remove(old_coord);
                }
            }
        }

        self.occupied.insert(coord, mesh_key.to_string());
        self.peer_positions
            .insert(mesh_key.to_string(), (index, coord));

        let old_neighbors = self.neighbors.clone();
        self.recompute_neighbors();
        self.neighbors != old_neighbors
    }

    /// Remove a peer from the topology. Returns true if our neighbor set changed.
    ///
    /// Handles both remote peers (in `peer_positions`) and ourselves (in
    /// `our_*` fields). Calling `remove_peer` with our own key fully un-claims
    /// our position — necessary before `claim_position` during convergence.
    pub fn remove_peer(&mut self, mesh_key: &str) -> bool {
        // Check if this is ourselves.
        if self.our_mesh_key.as_deref() == Some(mesh_key) {
            if let Some(coord) = self.our_coord {
                if self.occupied.get(&coord).map(|s| s.as_str()) == Some(mesh_key) {
                    self.occupied.remove(&coord);
                }
            }
            self.our_index = None;
            self.our_coord = None;
            self.our_mesh_key = None;
            let old_neighbors = self.neighbors.clone();
            self.recompute_neighbors();
            return self.neighbors != old_neighbors;
        }

        if let Some((_, coord)) = self.peer_positions.remove(mesh_key) {
            // Only remove from occupied if this mesh_key still owns the slot.
            if self.occupied.get(&coord).map(|s| s.as_str()) == Some(mesh_key) {
                self.occupied.remove(&coord);
            }

            let old_neighbors = self.neighbors.clone();
            self.recompute_neighbors();
            self.neighbors != old_neighbors
        } else {
            false
        }
    }

    /// Recompute our 20-neighbor set from current occupancy via gap-and-wrap.
    fn recompute_neighbors(&mut self) {
        self.neighbors.clear();

        let Some(our_coord) = self.our_coord else {
            return;
        };

        let occupied_set: HashSet<HexCoord> = self.occupied.keys().copied().collect();
        let connections = compute_all_connections(&occupied_set, our_coord);

        for conn in connections {
            if let Some(mesh_key) = self.occupied.get(&conn.target) {
                // Don't include ourselves as a neighbor.
                if self.our_mesh_key.as_deref() != Some(mesh_key.as_str()) {
                    self.neighbors.insert(mesh_key.clone());
                }
            }
        }
    }

    /// Check if a peer is in our current SPIRAL neighbor set.
    pub fn is_neighbor(&self, mesh_key: &str) -> bool {
        self.neighbors.contains(mesh_key)
    }

    /// Get all current SPIRAL neighbor mesh_keys.
    pub fn neighbors(&self) -> &HashSet<String> {
        &self.neighbors
    }

    /// Our claimed SPIRAL index (None if unclaimed).
    pub fn our_index(&self) -> Option<Spiral3DIndex> {
        self.our_index
    }

    /// Our claimed SPIRAL coordinate (None if unclaimed).
    pub fn our_coord(&self) -> Option<HexCoord> {
        self.our_coord
    }

    /// Get a peer's SPIRAL index.
    pub fn peer_index(&self, mesh_key: &str) -> Option<Spiral3DIndex> {
        self.peer_positions.get(mesh_key).map(|(idx, _)| *idx)
    }

    /// Reverse lookup: get the mesh_key occupying a given SPIRAL index.
    pub fn peer_at_index(&self, index: u64) -> Option<&str> {
        let coord = spiral3d_to_coord(Spiral3DIndex::new(index));
        self.occupied.get(&coord).map(|s| s.as_str())
    }

    /// Number of occupied slots in the topology.
    pub fn occupied_count(&self) -> usize {
        self.occupied.len()
    }

    /// Whether we have claimed a position.
    pub fn is_claimed(&self) -> bool {
        self.our_index.is_some()
    }

    /// Get all unique SPIRAL neighbor mesh_keys as a Vec.
    ///
    /// With fewer than 20 nodes, gap-and-wrap deduplicates to the actual
    /// unique peers — 5 nodes means each node connects to the other 4.
    pub fn all_neighbor_ids(&self) -> Vec<String> {
        self.neighbors.iter().cloned().collect()
    }

    /// Get world coordinates for a peer by mesh_key.
    pub fn peer_world_coord(&self, mesh_key: &str) -> Option<[f64; 3]> {
        self.peer_positions
            .get(mesh_key)
            .map(|(_, coord)| hex_to_world(*coord))
    }

    /// Get our world coordinates (None if unclaimed).
    pub fn our_world_coord(&self) -> Option<[f64; 3]> {
        self.our_coord.map(hex_to_world)
    }

    /// Iterate all occupied slots as (index, mesh_key) pairs, sorted by index.
    /// Remove all peers NOT in the given set (keeps our own position).
    /// Used to evict stale/dead peers before claim_position to prevent slot inflation.
    pub fn retain_peers(&mut self, live_keys: &HashSet<String>) {
        let stale: Vec<String> = self
            .peer_positions
            .keys()
            .filter(|k| {
                // Keep our own key.
                if self.our_mesh_key.as_deref() == Some(k.as_str()) {
                    return false;
                }
                !live_keys.contains(k.as_str())
            })
            .cloned()
            .collect();
        for key in stale {
            self.remove_peer(&key);
        }
    }

    pub fn occupied_slots(&self) -> Vec<(u64, String)> {
        let mut slots: Vec<(u64, String)> = self
            .peer_positions
            .iter()
            .map(|(key, (idx, _))| (idx.value(), key.clone()))
            .collect();
        slots.sort_by_key(|(idx, _)| *idx);
        slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_topology::{coord_to_spiral3d, is_bidirectional, CONNECTIONS_PER_NODE};

    #[test]
    fn claim_first_gets_origin() {
        let mut topo = SpiralTopology::new();
        let idx = topo.claim_position("peer-a");
        assert_eq!(idx, Spiral3DIndex::ORIGIN);
        assert_eq!(topo.our_coord(), Some(HexCoord::ORIGIN));
        assert!(topo.is_claimed());
    }

    #[test]
    fn sequential_claiming() {
        let mut topo = SpiralTopology::new();
        let idx0 = topo.claim_position("peer-a");
        assert_eq!(idx0.value(), 0);

        // Simulate peer-b at index 1 (first shell).
        let mut topo_b = SpiralTopology::new();
        topo_b.add_peer("peer-a", Spiral3DIndex::new(0));
        let idx1 = topo_b.claim_position("peer-b");
        assert_eq!(idx1.value(), 1);

        // Simulate peer-c seeing both a and b.
        let mut topo_c = SpiralTopology::new();
        topo_c.add_peer("peer-a", Spiral3DIndex::new(0));
        topo_c.add_peer("peer-b", Spiral3DIndex::new(1));
        let idx2 = topo_c.claim_position("peer-c");
        assert_eq!(idx2.value(), 2);
    }

    #[test]
    fn two_node_mutual_neighbors() {
        let mut topo_a = SpiralTopology::new();
        topo_a.claim_position("peer-a");
        topo_a.add_peer("peer-b", Spiral3DIndex::new(1));

        let mut topo_b = SpiralTopology::new();
        topo_b.add_peer("peer-a", Spiral3DIndex::new(0));
        topo_b.claim_position("peer-b");

        // With only 2 nodes, they should be each other's neighbors
        // (ghost connections in all 20 directions point at the only other node).
        assert!(topo_a.is_neighbor("peer-b"));
        assert!(topo_b.is_neighbor("peer-a"));
    }

    #[test]
    fn full_shell_1_all_neighbors() {
        // Origin + 20 shell-1 nodes = 21 nodes total.
        // Origin's 20 neighbors should be exactly the 20 shell-1 nodes.
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-0");

        for i in 1..=20u64 {
            let id = format!("peer-{i}");
            topo.add_peer(&id, Spiral3DIndex::new(i));
        }

        assert_eq!(topo.neighbors().len(), CONNECTIONS_PER_NODE);
        for i in 1..=20u64 {
            assert!(
                topo.is_neighbor(&format!("peer-{i}")),
                "peer-{i} should be neighbor of origin"
            );
        }
    }

    #[test]
    fn remove_peer_updates_neighbors() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        topo.add_peer("peer-c", Spiral3DIndex::new(2));

        assert!(topo.is_neighbor("peer-b"));
        assert!(topo.is_neighbor("peer-c"));

        let changed = topo.remove_peer("peer-b");
        assert!(changed);
        assert!(!topo.is_neighbor("peer-b"));
        // peer-c should still be a neighbor.
        assert!(topo.is_neighbor("peer-c"));
    }

    #[test]
    fn set_position_restores_state() {
        let mut topo = SpiralTopology::new();
        topo.set_position("peer-a", Spiral3DIndex::new(5));
        assert_eq!(topo.our_index(), Some(Spiral3DIndex::new(5)));
        assert!(topo.is_claimed());

        // Add a peer and verify neighbor computation works.
        topo.add_peer("peer-b", Spiral3DIndex::new(6));
        assert!(topo.is_neighbor("peer-b"));
    }

    #[test]
    fn single_node_no_neighbors() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");
        assert!(topo.neighbors().is_empty());
    }

    #[test]
    fn ghost_connections_bidirectional() {
        // Verify bidirectionality of connections between two sparse nodes.
        let coord_a = spiral3d_to_coord(Spiral3DIndex::new(0));
        let coord_b = spiral3d_to_coord(Spiral3DIndex::new(5));

        let mut occupied = HashSet::new();
        occupied.insert(coord_a);
        occupied.insert(coord_b);

        let conns_a = compute_all_connections(&occupied, coord_a);
        for conn in &conns_a {
            if conn.target == coord_b {
                assert!(
                    is_bidirectional(&occupied, coord_a, coord_b, conn.direction),
                    "Connection from A to B in {:?} should be bidirectional",
                    conn.direction
                );
            }
        }
    }

    #[test]
    fn first_writer_wins() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");

        // Try to add peer-b at index 0 (already occupied by peer-a).
        let changed = topo.add_peer("peer-b", Spiral3DIndex::new(0));
        assert!(!changed);

        // peer-a should still own slot 0.
        assert_eq!(topo.occupied_count(), 1);
    }

    #[test]
    fn unclaimed_has_no_neighbors() {
        let mut topo = SpiralTopology::new();
        // Add peers but don't claim our position.
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.add_peer("peer-b", Spiral3DIndex::new(1));

        // No neighbors since we haven't claimed.
        assert!(topo.neighbors().is_empty());
        assert!(!topo.is_claimed());
    }

    #[test]
    fn claim_skips_occupied_slots() {
        let mut topo = SpiralTopology::new();
        // Pre-populate slots 0 and 1.
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.add_peer("peer-b", Spiral3DIndex::new(1));

        // Claim should skip to slot 2.
        let idx = topo.claim_position("peer-c");
        assert_eq!(idx.value(), 2);
    }

    #[test]
    fn spiral_index_roundtrip() {
        for i in 0..100u64 {
            let idx = Spiral3DIndex::new(i);
            let coord = spiral3d_to_coord(idx);
            let back = coord_to_spiral3d(coord);
            assert_eq!(back, idx, "Roundtrip failed for index {i}");
        }
    }

    #[test]
    fn hex_to_world_origin() {
        let coord = HexCoord::ORIGIN;
        let [x, y, z] = hex_to_world(coord);
        assert!((x).abs() < f64::EPSILON, "x={x}");
        assert!((y).abs() < f64::EPSILON, "y={y}");
        assert!((z).abs() < f64::EPSILON, "z={z}");
    }

    #[test]
    fn hex_to_world_shell1() {
        // Slot 1 is (q=1, r=0, z=0) on shell 1.
        let coord = spiral3d_to_coord(Spiral3DIndex::new(1));
        let [x, y, z] = hex_to_world(coord);
        // World coords should be non-trivial — at least one axis non-zero.
        assert!(
            x.abs() > f64::EPSILON || y.abs() > f64::EPSILON || z.abs() > f64::EPSILON,
            "Shell 1 node should have non-zero world position: [{x}, {y}, {z}]"
        );
    }

    #[test]
    fn all_neighbor_ids_with_few_nodes() {
        // 3 nodes total: origin + 2 peers. Each should connect to all others.
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        topo.add_peer("peer-c", Spiral3DIndex::new(2));

        let ids = topo.all_neighbor_ids();
        assert_eq!(ids.len(), 2, "3-node mesh: origin should have 2 neighbors");
        assert!(ids.contains(&"peer-b".to_string()));
        assert!(ids.contains(&"peer-c".to_string()));
    }

    #[test]
    fn our_world_coord_matches_peer() {
        // If we claim slot 0 and a peer is at slot 1, the coordinates
        // from our_world_coord / peer_world_coord should match hex_to_world.
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");
        topo.add_peer("peer-b", Spiral3DIndex::new(1));

        let our = topo.our_world_coord().unwrap();
        let expected_our = hex_to_world(spiral3d_to_coord(Spiral3DIndex::new(0)));
        assert_eq!(our, expected_our);

        let peer = topo.peer_world_coord("peer-b").unwrap();
        let expected_peer = hex_to_world(spiral3d_to_coord(Spiral3DIndex::new(1)));
        assert_eq!(peer, expected_peer);

        assert!(topo.peer_world_coord("nonexistent").is_none());
    }

    #[test]
    fn evaluate_position_at_origin() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("peer-a");
        // At slot 0 — no better position exists.
        assert_eq!(topo.evaluate_position(), None);
    }

    #[test]
    fn evaluate_position_with_gap() {
        let mut topo = SpiralTopology::new();
        // Peer at slot 0, we're at slot 5 (slots 1-4 empty).
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.add_peer("peer-b", Spiral3DIndex::new(2));
        // Skip slots 3, 4 — claim at slot 5 by pre-populating 3 and 4.
        topo.add_peer("peer-c", Spiral3DIndex::new(3));
        topo.add_peer("peer-d", Spiral3DIndex::new(4));
        let idx = topo.claim_position("us");
        assert_eq!(idx.value(), 1, "Should claim slot 1 (first hole)");

        // Now remove peer-c from slot 3, creating a gap below us... wait,
        // we're at slot 1, which is lower. Let's test the real scenario.
        // Create a node at a HIGH slot with gaps below.
        let mut topo2 = SpiralTopology::new();
        topo2.add_peer("peer-a", Spiral3DIndex::new(0));
        // Set our position directly at slot 5 (simulating stale data during claim).
        topo2.set_position("us", Spiral3DIndex::new(5));
        // Slots 1-4 are empty — evaluate_position should find slot 1.
        assert_eq!(topo2.evaluate_position(), Some(Spiral3DIndex::new(1)));
    }

    #[test]
    fn evaluate_position_optimal() {
        let mut topo = SpiralTopology::new();
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        topo.set_position("us", Spiral3DIndex::new(2));
        // Slots 0, 1, 2 fully packed — no better position.
        assert_eq!(topo.evaluate_position(), None);
    }

    #[test]
    fn evaluate_position_after_eviction() {
        let mut topo = SpiralTopology::new();
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        topo.add_peer("peer-c", Spiral3DIndex::new(2));
        topo.set_position("us", Spiral3DIndex::new(3));
        // Fully packed — no improvement.
        assert_eq!(topo.evaluate_position(), None);

        // peer-b leaves, freeing slot 1.
        topo.remove_peer("peer-b");
        // Now slot 1 is available — should converge there.
        assert_eq!(topo.evaluate_position(), Some(Spiral3DIndex::new(1)));
    }

    #[test]
    fn add_peer_move_cleans_old_slot() {
        // Regression: moving a peer to a new slot must free the old coord in `occupied`.
        // Without this fix, the old coord becomes a ghost — claim_position skips it,
        // inflating slot numbers in small networks.
        let mut topo = SpiralTopology::new();
        topo.claim_position("us");
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        assert_eq!(topo.occupied_count(), 2);

        // Move peer-b from slot 1 → slot 3.
        topo.add_peer("peer-b", Spiral3DIndex::new(3));
        // occupied should still be 2 (us at 0, peer-b at 3).
        // Slot 1 must be FREE, not a ghost.
        assert_eq!(topo.occupied_count(), 2, "old slot should be freed");
        assert_eq!(topo.peer_at_index(1), None, "slot 1 must not be a ghost");
        assert_eq!(topo.peer_at_index(3), Some("peer-b"), "peer-b should be at slot 3");
    }

    #[test]
    fn force_add_peer_move_cleans_old_slot() {
        // Same ghost-slot regression test but for force_add_peer.
        let mut topo = SpiralTopology::new();
        topo.claim_position("us");
        topo.add_peer("peer-b", Spiral3DIndex::new(1));
        assert_eq!(topo.occupied_count(), 2);

        // Force-move peer-b from slot 1 → slot 3.
        let evicted = topo.force_add_peer("peer-b", Spiral3DIndex::new(3));
        assert_eq!(evicted, None, "no eviction — slot 3 was empty");
        assert_eq!(topo.occupied_count(), 2, "old slot should be freed");
        assert_eq!(topo.peer_at_index(1), None, "slot 1 must not be a ghost");
        assert_eq!(topo.peer_at_index(3), Some("peer-b"), "peer-b should be at slot 3");
    }

    #[test]
    fn ghost_slots_dont_inflate_claim() {
        // The actual production symptom: repeated add_peer moves create ghosts,
        // and claim_position ends up at slot 15 in a 5-node network.
        let mut topo = SpiralTopology::new();
        topo.claim_position("us");
        topo.add_peer("peer-b", Spiral3DIndex::new(5));
        topo.add_peer("peer-b", Spiral3DIndex::new(10));
        topo.add_peer("peer-b", Spiral3DIndex::new(15));
        // peer-b moved 3 times. Only final slot (15) should be occupied.
        assert_eq!(topo.occupied_count(), 2, "us + peer-b only");

        // A new peer claiming should get slot 1, NOT skip over ghosts.
        let mut topo2 = SpiralTopology::new();
        topo2.add_peer("us", Spiral3DIndex::new(0));
        topo2.add_peer("peer-b", Spiral3DIndex::new(15));
        // Simulate the same move history:
        topo2.add_peer("peer-b", Spiral3DIndex::new(5));
        topo2.add_peer("peer-b", Spiral3DIndex::new(10));
        topo2.add_peer("peer-b", Spiral3DIndex::new(15));
        let idx = topo2.claim_position("peer-c");
        assert_eq!(idx.value(), 1, "claim should get slot 1, not skip ghost slots");
    }

    #[test]
    fn converge_fills_hole() {
        // Simulate the full converge cycle: evaluate → remove self → claim.
        let mut topo = SpiralTopology::new();
        topo.add_peer("peer-a", Spiral3DIndex::new(0));
        topo.set_position("us", Spiral3DIndex::new(5));
        assert_eq!(topo.evaluate_position(), Some(Spiral3DIndex::new(1)));

        // Converge: remove ourselves, then re-claim (gets first hole).
        topo.remove_peer("us");
        let new_idx = topo.claim_position("us");
        assert_eq!(new_idx.value(), 1, "Should converge to slot 1");
        assert_eq!(topo.evaluate_position(), None, "Now optimal");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Come-and-Go: Brutal SPIRAL topology stress tests
    // ═══════════════════════════════════════════════════════════════════════
    //
    // These tests simulate real-world mesh scenarios with dozens of nodes
    // joining, leaving, partitioning into independent clumps, and merging.
    // They exercise every code path in SpiralTopology and verify invariants
    // that must hold for SPIRAL to function correctly at scale.

    /// Helper: build a fully-consistent N-node topology where each node has
    /// a complete view. Returns Vec<(mesh_key, SpiralTopology)> in claim order.
    fn build_consistent_mesh(n: usize) -> Vec<(String, SpiralTopology)> {
        // Phase 1: Each node claims sequentially, building global state.
        let mut global_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for i in 0..n {
            let key = format!("node-{i:03}");
            let mut topo = SpiralTopology::new();
            // Register all previously-claimed peers.
            for (pk, pidx) in &global_slots {
                topo.add_peer(pk, *pidx);
            }
            let idx = topo.claim_position(&key);
            global_slots.push((key, idx));
        }

        // Phase 2: Build final topologies with complete mutual knowledge.
        let mut result = Vec::new();
        for i in 0..n {
            let (ref key, _) = global_slots[i];
            let mut topo = SpiralTopology::new();
            // Register all OTHER peers first.
            for (j, (pk, pidx)) in global_slots.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            // Claim our own position.
            topo.set_position(key, global_slots[i].1);
            result.push((key.clone(), topo));
        }
        result
    }

    /// Helper: verify topology is packed — slots [0..n) all occupied, no gaps.
    fn assert_packed(topo: &SpiralTopology, expected_count: usize, context: &str) {
        assert_eq!(
            topo.occupied_count(),
            expected_count,
            "{context}: expected {expected_count} occupied slots, got {}",
            topo.occupied_count()
        );
        for i in 0..expected_count as u64 {
            assert!(
                topo.peer_at_index(i).is_some(),
                "{context}: slot {i} should be occupied in packed topology of {expected_count}"
            );
        }
    }

    /// Helper: verify bidirectional neighbors — if A neighbors B, B neighbors A.
    fn assert_bidirectional(nodes: &[(String, SpiralTopology)], context: &str) {
        for (key_a, topo_a) in nodes {
            for neighbor_key in topo_a.neighbors() {
                let topo_b = nodes
                    .iter()
                    .find(|(k, _)| k == neighbor_key)
                    .unwrap_or_else(|| {
                        panic!(
                            "{context}: {key_a}'s neighbor {neighbor_key} not found in node list"
                        )
                    });
                assert!(
                    topo_b.1.is_neighbor(key_a),
                    "{context}: {key_a} neighbors {neighbor_key} but not vice versa (bidirectional violation)"
                );
            }
        }
    }

    /// Helper: verify no ghost slots — occupied count == peer_positions + self.
    fn assert_no_ghosts(topo: &SpiralTopology, context: &str) {
        let slots = topo.occupied_slots();
        // occupied_slots() iterates peer_positions (excludes self).
        // occupied_count() counts occupied map (includes self).
        let self_offset = if topo.is_claimed() { 1 } else { 0 };
        assert_eq!(
            slots.len() + self_offset,
            topo.occupied_count(),
            "{context}: occupied_slots ({}) + self ({self_offset}) != occupied_count ({}) — ghost slots detected",
            slots.len(), topo.occupied_count()
        );
        // Every slot's occupant must be consistent.
        for (idx, key) in &slots {
            assert_eq!(
                topo.peer_index(key).map(|i| i.value()),
                Some(*idx),
                "{context}: peer_positions disagrees with occupied for {key} at slot {idx}"
            );
        }
    }

    /// Helper: simulate one node's convergence cycle.
    /// Returns the new index if the node moved, None if already optimal.
    fn converge_node(topo: &mut SpiralTopology, mesh_key: &str) -> Option<Spiral3DIndex> {
        if let Some(_better) = topo.evaluate_position() {
            topo.remove_peer(mesh_key);
            let new_idx = topo.claim_position(mesh_key);
            Some(new_idx)
        } else {
            None
        }
    }

    /// Helper: run convergence rounds until stable across all nodes.
    ///
    /// Processes one node per step (highest slot first), propagates the
    /// move to all peers, then re-evaluates. This mirrors real-world
    /// behavior where gossip propagates between individual moves.
    fn converge_all(nodes: &mut [(String, SpiralTopology)], max_steps: usize) {
        for _ in 0..max_steps {
            // Collect candidates: (index, current_slot, target_slot).
            let mut candidates: Vec<(usize, u64)> = Vec::new();
            for (i, (_, topo)) in nodes.iter().enumerate() {
                if topo.evaluate_position().is_some() {
                    let slot = topo.our_index().map(|idx| idx.value()).unwrap_or(0);
                    candidates.push((i, slot));
                }
            }

            if candidates.is_empty() {
                break;
            }

            // Pick the highest-slotted candidate.
            candidates.sort_by(|a, b| b.1.cmp(&a.1));
            let mover_i = candidates[0].0;

            // Move this one node.
            let mover_key = nodes[mover_i].0.clone();
            let new_idx = converge_node(&mut nodes[mover_i].1, &mover_key).unwrap();

            // Propagate to all other nodes.
            for (j, (_, topo)) in nodes.iter_mut().enumerate() {
                if j != mover_i {
                    topo.add_peer(&mover_key, new_idx);
                }
            }
        }
    }

    /// Helper: extract slot map from a clump.
    fn slot_map(nodes: &[(String, SpiralTopology)]) -> Vec<(String, Spiral3DIndex)> {
        nodes
            .iter()
            .map(|(k, t)| (k.clone(), t.our_index().unwrap()))
            .collect()
    }

    /// Helper: atomic clump merge.
    ///
    /// Two independent clumps meet. Compare cluster work (just a number).
    /// Winner keeps all slots. Loser rebuilds from scratch around winner.
    /// Returns unified Vec of (mesh_key, SpiralTopology) with full mutual
    /// knowledge and converged positions.
    fn merge_clumps(
        winner: &[(String, SpiralTopology)],
        loser: &[(String, SpiralTopology)],
    ) -> Vec<(String, SpiralTopology)> {
        let winner_slots = slot_map(winner);
        let loser_keys: Vec<String> = loser.iter().map(|(k, _)| k.clone()).collect();

        // Phase 1: Each loser node builds fresh topology from winner's slots,
        // then claims sequentially. We process losers in order so each one
        // sees the previous loser's claimed position.
        let mut loser_new_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for lkey in &loser_keys {
            let mut topo = SpiralTopology::new();
            // Register all winner slots.
            for (wk, widx) in &winner_slots {
                topo.add_peer(wk, *widx);
            }
            // Register previously-reslotted loser peers.
            for (pk, pidx) in &loser_new_slots {
                topo.add_peer(pk, *pidx);
            }
            let new_idx = topo.claim_position(lkey);
            loser_new_slots.push((lkey.clone(), new_idx));
        }

        // Phase 2: Build unified topology with complete knowledge.
        let all_slots: Vec<(String, Spiral3DIndex)> = winner_slots
            .iter()
            .chain(loser_new_slots.iter())
            .cloned()
            .collect();

        let mut result = Vec::new();
        for (key, idx) in &all_slots {
            let mut topo = SpiralTopology::new();
            for (pk, pidx) in &all_slots {
                if pk != key {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, *idx);
            result.push((key.clone(), topo));
        }

        // Phase 3: Converge (loser nodes may have suboptimal positions).
        converge_all(&mut result, 30);
        result
    }

    // ── Test: Mass sequential join ──────────────────────────────────────

    #[test]
    fn come_and_go_mass_join_30_nodes() {
        let nodes = build_consistent_mesh(30);

        for (key, topo) in &nodes {
            assert_packed(topo, 30, &format!("mass_join: {key}"));
            assert_no_ghosts(topo, &format!("mass_join: {key}"));
        }

        // Sequential claiming: node-000 → slot 0, node-001 → slot 1, etc.
        for (i, (key, topo)) in nodes.iter().enumerate() {
            assert_eq!(
                topo.our_index().unwrap().value(),
                i as u64,
                "{key} should be at slot {i}"
            );
        }

        assert_bidirectional(&nodes, "mass_join_30");

        for (key, topo) in &nodes {
            assert!(
                !topo.neighbors().is_empty(),
                "mass_join_30: {key} has no neighbors"
            );
        }
    }

    // ── Test: Random departures + convergence ───────────────────────────

    #[test]
    fn come_and_go_departures_and_convergence() {
        let mut nodes = build_consistent_mesh(20);

        // Kill nodes at slots 3, 7, 11, 15, 19.
        let dead: Vec<String> = vec![3, 7, 11, 15, 19]
            .into_iter()
            .map(|i| format!("node-{i:03}"))
            .collect();

        nodes.retain(|(k, _)| !dead.contains(k));
        for (_, topo) in &mut nodes {
            for d in &dead {
                topo.remove_peer(d);
            }
        }

        assert_eq!(nodes.len(), 15);

        converge_all(&mut nodes, 30);

        for (key, topo) in &nodes {
            assert_packed(topo, 15, &format!("converged: {key}"));
            assert_no_ghosts(topo, &format!("converged: {key}"));
        }
        assert_bidirectional(&nodes, "converged_after_departures");
    }

    // ── Test: Network partition into two clumps ─────────────────────────

    #[test]
    fn come_and_go_partition_and_independent_evolution() {
        // 20 nodes → partition into two independent clumps → each converges.
        let nodes = build_consistent_mesh(20);

        // Build each clump from scratch with only their members.
        let clump_a = build_consistent_mesh(10); // reuse: 10 nodes = slots 0-9
        // For clump B, take original nodes 10-19 and rebuild as independent clump.
        let b_orig: Vec<(String, Spiral3DIndex)> = (10..20)
            .map(|i| {
                let key = format!("node-{i:03}");
                let idx = nodes
                    .iter()
                    .find(|(k, _)| *k == key)
                    .unwrap()
                    .1
                    .our_index()
                    .unwrap();
                (key, idx)
            })
            .collect();

        // Build B's independent topology from scratch. They only see each other.
        let mut clump_b: Vec<(String, SpiralTopology)> = Vec::new();
        for (i, (key, _)) in b_orig.iter().enumerate() {
            let mut topo = SpiralTopology::new();
            for (j, (pk, _orig_idx)) in b_orig.iter().enumerate() {
                if j != i {
                    // They still have their original slots (10-19) initially.
                    topo.add_peer(pk, b_orig[j].1);
                }
            }
            topo.set_position(key, b_orig[i].1);
            clump_b.push((key.clone(), topo));
        }

        // Converge B into packed [0..10) — they slide down to fill the gap.
        converge_all(&mut clump_b, 30);

        for (key, topo) in &clump_a {
            assert_packed(topo, 10, &format!("clump_a: {key}"));
            assert_no_ghosts(topo, &format!("clump_a: {key}"));
        }
        for (key, topo) in &clump_b {
            assert_packed(topo, 10, &format!("clump_b: {key}"));
            assert_no_ghosts(topo, &format!("clump_b: {key}"));
        }

        assert_bidirectional(&clump_a, "clump_a_independent");
        assert_bidirectional(&clump_b, "clump_b_independent");
    }

    // ── Test: Cluster merge — two clumps meet ───────────────────────────

    #[test]
    fn come_and_go_cluster_merge() {
        // Two independent clumps of 8, both packed [0..8).
        // Atomic merge: compare cluster work → loser rebuilds around winner.
        let clump_a = build_consistent_mesh(8);

        // Build clump B with unique keys.
        let mut clump_b: Vec<(String, SpiralTopology)> = Vec::new();
        let b_count = 8;
        let mut b_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for i in 0..b_count {
            let key = format!("clump-b-{i:03}");
            let mut topo = SpiralTopology::new();
            for (pk, pidx) in &b_slots {
                topo.add_peer(pk, *pidx);
            }
            let idx = topo.claim_position(&key);
            b_slots.push((key.clone(), idx));
        }
        for i in 0..b_count {
            let key = &b_slots[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in b_slots.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, b_slots[i].1);
            clump_b.push((key.clone(), topo));
        }

        // A wins. Atomic merge.
        let merged = merge_clumps(&clump_a, &clump_b);

        assert_eq!(merged.len(), 16);
        for (key, topo) in &merged {
            assert_packed(topo, 16, &format!("merged: {key}"));
            assert_no_ghosts(topo, &format!("merged: {key}"));
        }
        assert_bidirectional(&merged, "cluster_merge_16");

        // Winner privilege: A's nodes keep their original slots.
        for (key, orig_topo) in &clump_a {
            let final_topo = merged.iter().find(|(k, _)| k == key).unwrap();
            assert_eq!(
                final_topo.1.our_index().unwrap(),
                orig_topo.our_index().unwrap(),
                "winner {key} should keep original slot {}",
                orig_topo.our_index().unwrap().value()
            );
        }
    }

    // ── Test: Rapid churn — nodes join and leave randomly ───────────────

    #[test]
    fn come_and_go_rapid_churn() {
        let mut nodes = build_consistent_mesh(10);
        let mut next_id = 10u32;

        // Deterministic LCG.
        let mut rng_state: u64 = 0xDEADBEEF;
        let mut next_rng = || -> u64 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng_state >> 33
        };

        for round in 0..50 {
            let action = next_rng() % 3;

            if action == 0 || nodes.len() < 3 {
                // JOIN.
                let new_key = format!("churn-{next_id:04}");
                next_id += 1;

                let mut new_topo = SpiralTopology::new();
                for (pk, pt) in &nodes {
                    new_topo.add_peer(pk, pt.our_index().unwrap());
                }
                let new_idx = new_topo.claim_position(&new_key);

                for (_, topo) in &mut nodes {
                    topo.add_peer(&new_key, new_idx);
                }
                nodes.push((new_key, new_topo));
            } else {
                // LEAVE.
                let victim_i = (next_rng() as usize) % nodes.len();
                let (victim_key, _) = nodes.remove(victim_i);

                for (_, topo) in &mut nodes {
                    topo.remove_peer(&victim_key);
                }
            }

            // One sequential convergence step per churn event.
            converge_all(&mut nodes, 1);

            for (key, topo) in &nodes {
                assert_no_ghosts(topo, &format!("churn round {round}: {key}"));
            }
        }

        converge_all(&mut nodes, 30);

        let n = nodes.len();
        for (key, topo) in &nodes {
            assert_packed(topo, n, &format!("churn final: {key}"));
            assert_no_ghosts(topo, &format!("churn final: {key}"));
        }
        assert_bidirectional(&nodes, "rapid_churn_final");
    }

    // ── Test: Split and merge — full lifecycle ──────────────────────────

    #[test]
    fn come_and_go_split_merge_full_cycle() {
        // 20 nodes → partition → independent evolution → merge back.

        // Phase 1: Healthy 20-node mesh.
        let nodes = build_consistent_mesh(20);
        for (key, topo) in &nodes {
            assert_packed(topo, 20, &format!("phase1: {key}"));
        }

        // Phase 2: Build two independent clumps as if partitioned.
        // Clump A: nodes 0-9 (already packed at [0..10)).
        // Clump B: nodes 10-19 (rebuild independently, converge to [0..10)).
        let mut clump_a: Vec<(String, SpiralTopology)> = Vec::new();
        let a_slots_orig: Vec<(String, Spiral3DIndex)> = (0..10)
            .map(|i| {
                let key = format!("node-{i:03}");
                (key, Spiral3DIndex::new(i as u64))
            })
            .collect();
        for i in 0..10 {
            let key = &a_slots_orig[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in a_slots_orig.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, a_slots_orig[i].1);
            clump_a.push((key.clone(), topo));
        }

        let b_slots_orig: Vec<(String, Spiral3DIndex)> = (10..20)
            .map(|i| {
                let key = format!("node-{i:03}");
                (key, Spiral3DIndex::new(i as u64))
            })
            .collect();
        let mut clump_b: Vec<(String, SpiralTopology)> = Vec::new();
        for i in 0..10 {
            let key = &b_slots_orig[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in b_slots_orig.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, b_slots_orig[i].1);
            clump_b.push((key.clone(), topo));
        }

        // Phase 3: B converges to [0..10) independently.
        converge_all(&mut clump_b, 30);

        for (key, topo) in &clump_a {
            assert_packed(topo, 10, &format!("split_a: {key}"));
        }
        for (key, topo) in &clump_b {
            assert_packed(topo, 10, &format!("split_b: {key}"));
        }

        // Phase 4: Add 3 new nodes to each clump.
        for (label, clump) in [("a", &mut clump_a), ("b", &mut clump_b)] {
            for extra in 0..3 {
                let new_key = format!("extra-{label}-{extra}");
                let mut new_topo = SpiralTopology::new();
                for (pk, pt) in clump.iter() {
                    new_topo.add_peer(pk, pt.our_index().unwrap());
                }
                let new_idx = new_topo.claim_position(&new_key);
                for (_, topo) in clump.iter_mut() {
                    topo.add_peer(&new_key, new_idx);
                }
                clump.push((new_key, new_topo));
            }
        }

        for (key, topo) in &clump_a {
            assert_packed(topo, 13, &format!("grown_a: {key}"));
        }
        for (key, topo) in &clump_b {
            assert_packed(topo, 13, &format!("grown_b: {key}"));
        }

        // Phase 5: Atomic merge. A wins.
        let merged = merge_clumps(&clump_a, &clump_b);

        assert_eq!(merged.len(), 26);
        for (key, topo) in &merged {
            assert_packed(topo, 26, &format!("final_merge: {key}"));
            assert_no_ghosts(topo, &format!("final_merge: {key}"));
        }
        assert_bidirectional(&merged, "split_merge_full_cycle");
    }

    // ── Test: Scale — 100 nodes, verify gap-and-wrap produces ≤20 ──────

    #[test]
    fn come_and_go_scale_100_neighbors_bounded() {
        let nodes = build_consistent_mesh(100);

        for (key, topo) in &nodes {
            let neighbor_count = topo.neighbors().len();
            assert!(
                neighbor_count <= CONNECTIONS_PER_NODE,
                "scale_100: {key} has {neighbor_count} neighbors > {CONNECTIONS_PER_NODE}"
            );
            assert!(
                neighbor_count >= 1,
                "scale_100: {key} has no neighbors"
            );
            assert_no_ghosts(topo, &format!("scale_100: {key}"));
        }

        assert_bidirectional(&nodes, "scale_100");
    }

    // ── Test: Retain peers — evict stale, keep live ─────────────────────

    #[test]
    fn come_and_go_retain_peers_evicts_stale() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("us");
        for i in 1..10u64 {
            topo.add_peer(&format!("peer-{i}"), Spiral3DIndex::new(i));
        }
        assert_eq!(topo.occupied_count(), 10);

        let live: HashSet<String> = vec!["peer-1", "peer-3", "peer-5", "peer-7"]
            .into_iter()
            .map(String::from)
            .collect();
        topo.retain_peers(&live);

        assert_eq!(topo.occupied_count(), 5);
        assert_eq!(topo.peer_at_index(0), Some("us"));
        assert_eq!(topo.peer_at_index(1), Some("peer-1"));
        assert!(topo.peer_at_index(2).is_none());
        assert_eq!(topo.peer_at_index(3), Some("peer-3"));
        assert!(topo.peer_at_index(4).is_none());
        assert_eq!(topo.peer_at_index(5), Some("peer-5"));
        assert!(topo.peer_at_index(6).is_none());
        assert_eq!(topo.peer_at_index(7), Some("peer-7"));
        assert_no_ghosts(&topo, "retain_peers");
    }

    // ── Test: Force-add collision chain ──────────────────────────────────

    #[test]
    fn come_and_go_force_add_collision_chain() {
        let mut topo = SpiralTopology::new();
        topo.claim_position("alpha");
        assert_eq!(topo.our_index().unwrap().value(), 0);

        let evicted = topo.force_add_peer("beta", Spiral3DIndex::new(0));
        assert_eq!(evicted, Some("alpha".to_string()));
        assert_eq!(topo.peer_at_index(0), Some("beta"));

        let evicted = topo.force_add_peer("gamma", Spiral3DIndex::new(0));
        assert_eq!(evicted, Some("beta".to_string()));
        assert_eq!(topo.peer_at_index(0), Some("gamma"));

        assert_eq!(topo.occupied_count(), 1);
        assert_no_ghosts(&topo, "collision_chain");
    }

    // ── Test: Asymmetric merge — tiny clump meets large ─────────────────

    #[test]
    fn come_and_go_asymmetric_merge() {
        // 3-node clump merges into 30-node clump. Atomic merge.
        let large = build_consistent_mesh(30);

        // Build small clump with unique keys.
        let mut small: Vec<(String, SpiralTopology)> = Vec::new();
        let mut s_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for i in 0..3 {
            let key = format!("tiny-{i}");
            let mut topo = SpiralTopology::new();
            for (pk, pidx) in &s_slots {
                topo.add_peer(pk, *pidx);
            }
            let idx = topo.claim_position(&key);
            s_slots.push((key.clone(), idx));
        }
        for i in 0..3 {
            let key = &s_slots[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in s_slots.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, s_slots[i].1);
            small.push((key.clone(), topo));
        }

        // Large wins. Atomic merge.
        let merged = merge_clumps(&large, &small);

        assert_eq!(merged.len(), 33);
        for (key, topo) in &merged {
            assert_packed(topo, 33, &format!("asymmetric: {key}"));
            assert_no_ghosts(topo, &format!("asymmetric: {key}"));
        }
        assert_bidirectional(&merged, "asymmetric_merge");

        // Large clump keeps original slots.
        for (key, orig_topo) in &large {
            let final_topo = merged.iter().find(|(k, _)| k == key).unwrap();
            assert_eq!(
                final_topo.1.our_index().unwrap(),
                orig_topo.our_index().unwrap(),
                "large winner {key} should keep original slot"
            );
        }
    }

    // ── Test: Double split, double merge ────────────────────────────────

    #[test]
    fn come_and_go_double_split_merge() {
        // 30 nodes → split into 3 clumps → each converges → merge A+B → merge (A+B)+C.

        // Build 3 independent clumps of 10 with unique names per group.
        let ga = build_consistent_mesh(10); // node-000..node-009

        let mut gb: Vec<(String, SpiralTopology)> = Vec::new();
        let mut gb_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for i in 0..10 {
            let key = format!("grp-b-{i:03}");
            let mut topo = SpiralTopology::new();
            for (pk, pidx) in &gb_slots {
                topo.add_peer(pk, *pidx);
            }
            let idx = topo.claim_position(&key);
            gb_slots.push((key.clone(), idx));
        }
        for i in 0..10 {
            let key = &gb_slots[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in gb_slots.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, gb_slots[i].1);
            gb.push((key.clone(), topo));
        }

        let mut gc: Vec<(String, SpiralTopology)> = Vec::new();
        let mut gc_slots: Vec<(String, Spiral3DIndex)> = Vec::new();
        for i in 0..10 {
            let key = format!("grp-c-{i:03}");
            let mut topo = SpiralTopology::new();
            for (pk, pidx) in &gc_slots {
                topo.add_peer(pk, *pidx);
            }
            let idx = topo.claim_position(&key);
            gc_slots.push((key.clone(), idx));
        }
        for i in 0..10 {
            let key = &gc_slots[i].0;
            let mut topo = SpiralTopology::new();
            for (j, (pk, pidx)) in gc_slots.iter().enumerate() {
                if j != i {
                    topo.add_peer(pk, *pidx);
                }
            }
            topo.set_position(key, gc_slots[i].1);
            gc.push((key.clone(), topo));
        }

        // Each group packed [0..10).
        for (label, group) in [("a", &ga), ("b", &gb), ("c", &gc)] {
            for (key, topo) in group.iter() {
                assert_packed(topo, 10, &format!("triple_split_{label}: {key}"));
            }
        }

        // Merge A + B: A wins.
        let ab = merge_clumps(&ga, &gb);
        for (key, topo) in &ab {
            assert_packed(topo, 20, &format!("ab_merged: {key}"));
        }

        // Merge (A+B) + C: A+B wins.
        let final_all = merge_clumps(&ab, &gc);

        assert_eq!(final_all.len(), 30);
        for (key, topo) in &final_all {
            assert_packed(topo, 30, &format!("triple_merge: {key}"));
            assert_no_ghosts(topo, &format!("triple_merge: {key}"));
        }
        assert_bidirectional(&final_all, "double_split_merge");
    }
}
