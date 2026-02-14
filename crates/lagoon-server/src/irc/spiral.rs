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

    /// Restore a persisted SPIRAL position on restart.
    pub fn set_position(&mut self, our_mesh_key: &str, index: Spiral3DIndex) {
        let coord = spiral3d_to_coord(index);
        self.our_index = Some(index);
        self.our_coord = Some(coord);
        self.our_mesh_key = Some(our_mesh_key.to_string());
        self.occupied.insert(coord, our_mesh_key.to_string());
        self.recompute_neighbors();
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

        self.occupied.insert(coord, mesh_key.to_string());
        self.peer_positions
            .insert(mesh_key.to_string(), (index, coord));

        let old_neighbors = self.neighbors.clone();
        self.recompute_neighbors();
        self.neighbors != old_neighbors
    }

    /// Remove a peer from the topology. Returns true if our neighbor set changed.
    pub fn remove_peer(&mut self, mesh_key: &str) -> bool {
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
}
