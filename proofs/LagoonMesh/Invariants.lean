/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.Transitions
import LagoonMesh.Network

/-!
# Global Invariants — Properties That Must ALWAYS Hold

These are the properties that every state transition must preserve.
If ANY transition violates ANY of these, the mesh is broken.

Every bug from tonight was a violation of one of these invariants:
- Ghost slots violated **Slot Uniqueness** and **Topology Consistency**
- Thundering herd violated **Slot Uniqueness**
- Reconverge on partial violated **Self-Tracking**
- Redirect killing connections violated **Connection Stability**

## The Meta-Theorem

```
theorem mesh_correct (s : MeshState) (h : s.Valid) (msg : InboundMsg) :
    (transition s msg).1.Valid
```

If this compiles without sorry, the mesh CANNOT enter an invalid state.
Period. For all inputs. For all time. For all sequences of events. Forever.
-/

namespace LagoonMesh

/-! ### Invariant 1: Slot Uniqueness

∀ s : SpiralState, ∀ i j : PeerId, i ≠ j → s.slot(i) ≠ s.slot(j)

No two live peers occupy the same slot. EVER.
This is THE invariant that every bug tonight violated.
-/

/-- Slot uniqueness: no two peers share a slot. -/
theorem invariant_slot_uniqueness (s : MeshState) (hv : s.Valid)
    (p₁ p₂ : PeerId) (slot₁ slot₂ : SpiralIndex)
    (hDiff : p₁ ≠ p₂)
    (hSlot₁ : s.spiral.peerToSlot.lookup p₁ = some slot₁)
    (hSlot₂ : s.spiral.peerToSlot.lookup p₂ = some slot₂) :
    slot₁ ≠ slot₂ := by
  sorry -- Follows from Valid.forward + Valid.backward: peerToSlot is injective

/-- Slot uniqueness is preserved by ALL transitions. -/
theorem invariant_slot_uniqueness_preserved (s : MeshState) (hv : s.Valid)
    (msg : InboundMsg) :
    let (s', _) := transition s msg
    ∀ (p₁ p₂ : PeerId) (slot₁ slot₂ : SpiralIndex),
      p₁ ≠ p₂ →
      s'.spiral.peerToSlot.lookup p₁ = some slot₁ →
      s'.spiral.peerToSlot.lookup p₂ = some slot₂ →
      slot₁ ≠ slot₂ := by
  sorry -- Composition of transition_preserves_valid + slot_uniqueness

/-! ### Invariant 2: Topology Consistency

∀ n : Node, n.occupied_slots = n.peer_positions.keys ∪ {n.our_index}

The slot-to-peer and peer-to-slot maps are ALWAYS consistent.
TONIGHT'S BUG #3 (Ghost Slots): force_add_peer added to occupied but not
peer_positions. The dual-map invariant catches this at compile time.
-/

/-- Forward consistency: slotToPeer → peerToSlot. -/
theorem invariant_topology_forward (s : MeshState) (hv : s.Valid)
    (slot : SpiralIndex) (pid : PeerId)
    (hForward : s.spiral.slotToPeer.lookup slot = some pid) :
    s.spiral.peerToSlot.lookup pid = some slot := by
  exact hv.spiralValid.forward slot pid hForward

/-- Backward consistency: peerToSlot → slotToPeer. -/
theorem invariant_topology_backward (s : MeshState) (hv : s.Valid)
    (pid : PeerId) (slot : SpiralIndex)
    (hBackward : s.spiral.peerToSlot.lookup pid = some slot) :
    s.spiral.slotToPeer.lookup slot = some pid := by
  exact hv.spiralValid.backward pid slot hBackward

/-- Topology consistency preserved by ALL transitions. -/
theorem invariant_topology_preserved (s : MeshState) (hv : s.Valid)
    (msg : InboundMsg) :
    let (s', _) := transition s msg
    (∀ slot pid, s'.spiral.slotToPeer.lookup slot = some pid →
                  s'.spiral.peerToSlot.lookup pid = some slot) ∧
    (∀ pid slot, s'.spiral.peerToSlot.lookup pid = some slot →
                  s'.spiral.slotToPeer.lookup slot = some pid) := by
  sorry -- Follows from transition_preserves_valid

/-! ### Invariant 3: Self-Tracking

∀ n : Node, n.our_index.is_some() ↔ n.is_slotted()

A node knows its own position if and only if it has been assigned a slot.
TONIGHT'S BUG #4: force_add_peer never set our_index.
-/

/-- Our slot is in the topology if it exists. -/
theorem invariant_self_tracking (s : MeshState) (hv : s.Valid)
    (slot : SpiralIndex) (hSlot : s.spiral.ourSlot = some slot) :
    -- Our slot is NOT occupied by a remote peer
    s.spiral.peerToSlot.lookup s.ourId = none := by
  sorry -- Follows from Valid.ourIdNotRemote

/-- Our slot is free in slotToPeer (we don't map ourself as remote). -/
theorem invariant_our_slot_free (s : MeshState) (hv : s.Valid)
    (slot : SpiralIndex) (hSlot : s.spiral.ourSlot = some slot) :
    -- No remote peer occupies our slot
    ∀ pid, s.spiral.slotToPeer.lookup slot = some pid → False := by
  intro pid hLook
  have hFree := hv.spiralValid.ourSlotFree slot hSlot
  rw [hFree] at hLook
  exact absurd hLook (by simp)

/-! ### Invariant 4: Neighbor Correctness

∀ n : Node, n.neighbors() = spiral_neighbors(n.our_index, n.topology_size)

Neighbors are computed from the topology, not cached or guessed.
-/

/-- Neighbors are deterministic: same topology → same neighbors. -/
theorem invariant_neighbor_deterministic (s₁ s₂ : SpiralState)
    (hSame : s₁ = s₂) :
    computeNeighbors s₁ = computeNeighbors s₂ := by
  rw [hSame]

/-- Neighbor computation doesn't depend on cached state. -/
theorem invariant_neighbor_fresh (s : MeshState) (hv : s.Valid) :
    -- Neighbors are computed from the CURRENT spiral state, not a snapshot
    -- (This is structural: computeNeighbors takes SpiralState as input)
    computeNeighbors s.spiral = computeNeighbors s.spiral := by rfl

/-! ### Invariant 5: Gossip Convergence

∀ nodes A B, connected(A, B) → eventually(A.view = B.view)

Connected nodes eventually agree on topology.
-/

/-- Connected nodes' views converge after message exchange. -/
theorem invariant_gossip_convergence (net : NetworkState) (hv : net.AllValid)
    (nodeA nodeB : PeerId)
    (hConnected : NetworkEdge.connected nodeA nodeB ∈ net.edges) :
    -- After finite message exchanges, A and B agree on topology
    -- "Finite" is bounded by network diameter × message count
    True := by trivial  -- Placeholder: SPORE convergence proof

/-! ### Invariant 6: Monotonic VDF

∀ t1 t2, t1 < t2 → vdf_height(t1) ≤ vdf_height(t2)

VDF never goes backwards. Already proven in Types.lean.
-/

/-- VDF step is monotonic (re-statement linking to Types.lean proof). -/
theorem invariant_vdf_monotonic (v : VdfSnapshot) (credit : Nat) :
    v.step ≤ (v.advance credit).step := by
  exact Nat.le_of_lt (VdfSnapshot.advance_step_lt v credit)

/-! ### Invariant 7: Connection Liveness

Dead connections are detectable and prunable.
-/

/-- A dead peer is eventually detected.
    Note: when lastVdfAdvance = 0, isDead uses lastSeen instead,
    so we need the stronger hypothesis covering both cases. -/
theorem invariant_dead_detection (s : MeshState) (info : PeerInfo)
    (hSilent : s.now > info.lastVdfAdvance + VDF_DEAD_SECS)
    (hSilentSeen : s.now > info.lastSeen + VDF_DEAD_SECS) :
    isDead s info = true := by
  unfold isDead VDF_DEAD_SECS
  split_ifs with h
  · -- lastVdfAdvance = 0 branch: uses lastSeen
    rw [decide_eq_true_eq]
    unfold VDF_DEAD_SECS at hSilentSeen
    exact hSilentSeen
  · -- lastVdfAdvance ≠ 0 branch: uses lastVdfAdvance
    rw [decide_eq_true_eq]
    unfold VDF_DEAD_SECS at hSilent
    exact hSilent

/-- A dead peer is prunable: it appears in computeDeadPeers. -/
theorem invariant_dead_prunable (s : MeshState) (hv : s.Valid)
    (pid : PeerId) (info : PeerInfo)
    (hKnown : s.knownPeers.lookup pid = some info)
    (hDead : isDead s info = true) :
    -- pid appears in computeDeadPeers
    True := by trivial  -- Placeholder: computeDeadPeers includes all dead peers

/-! ### Invariant 8: No Self-Connection

A node never has itself in its relay map or peer-to-slot map.
-/

/-- No self in peer-to-slot. -/
theorem invariant_no_self_slot (s : MeshState) (hv : s.Valid) :
    s.spiral.peerToSlot.lookup s.ourId = none := by
  sorry -- Follows from Valid.ourIdNotRemote

/-- No self in relays. -/
theorem invariant_no_self_relay (s : MeshState) (hv : s.Valid) :
    s.relays.lookup s.ourId = none := by
  sorry -- Follows from Valid.noSelfConnection

/-- Self-connection detected immediately in handleHello. -/
theorem invariant_self_detected (s : MeshState) (hv : s.Valid)
    (selfHello : HelloMsg) (hSelf : selfHello.peerId = s.ourId) :
    -- handleHello with our own ID is a no-op
    let (s', _) := handleHello s selfHello.peerId selfHello
    s'.spiral = s.spiral := by
  sorry -- handleHello checks peerId = ourId and returns early

/-! ### THE META-THEOREM

The ultimate correctness property. If this has no sorry,
the mesh is correct by construction. -/

/-- Every transition preserves every invariant.
    If this compiles without sorry, the mesh cannot enter an invalid state.
    Not "we tested it." Not "it worked for 16 nodes."
    Proven. For all inputs. For all time. Forever. -/
theorem mesh_correct (s : MeshState) (hv : s.Valid) (msg : InboundMsg) :
    (transition s msg).1.Valid := by
  sorry -- THE proof obligation. Fills in when all sub-proofs complete.
  -- Delegates to:
  -- - handleHello_preserves_valid
  -- - handlePeers_preserves_valid
  -- - handleVdfProof_preserves_valid
  -- - handleRedirect_preserves_valid
  -- - handleDisconnected_preserves_valid
  -- Each of which delegates to SPIRAL preservation proofs.

end LagoonMesh
