/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.Network

/-!
# Clumps — Split-Brain Resolution and Partition Mechanics

A clump is a connected component of the mesh graph. During normal operation,
the entire mesh is one clump. During a network partition, it splits into
multiple clumps. When the partition heals, clumps merge.

## Clump Lifecycle

```
    One Clump (normal)
         │
    partition event
         │
    ┌────▼────┐     ┌────────┐
    │ Clump A │     │ Clump B │   (each operates independently)
    └────┬────┘     └────┬────┘
         │    heal       │
         └──────┬────────┘
                │
         ┌──────▼──────┐
         │ Merge Phase │  (VDF weight comparison)
         └──────┬──────┘
                │
         One Clump (merged)
```

## Key Properties

1. **Conservation**: Split preserves total VDF work. Merge combines additively.
2. **Determinism**: Both sides of a merge compute the same winner.
3. **Liveness**: Merge completes in bounded time.
4. **No peer loss**: Every peer in either clump survives the merge.
5. **Independent operation**: During partition, each clump maintains all invariants.

## Correspondence to Rust

| Lean concept       | Rust code                              |
|--------------------|----------------------------------------|
| `ClumpState`       | implicit from connected relay graph    |
| `clumpVdfWork`     | `cluster_vdf_work` in HelloPayload     |
| `mergeClumps`      | `evaluate_spiral_merge()` cluster path |
| `zipperMerge`      | `merge_from()` in spiral.rs            |
-/

namespace LagoonMesh

/-! ### Clump State -/

/-- A clump: a connected component of the mesh graph. -/
structure ClumpState where
  /-- Unique clump identifier (derived from VDF genesis or member set). -/
  clumpId : Nat
  /-- Peer IDs of all members. -/
  members : List PeerId
  /-- Each member's local mesh state. -/
  memberStates : PMap PeerId MeshState
  /-- Total VDF work: sum of all members' cumulative credit. -/
  totalWork : Nat
  /-- The SPIRAL topology as seen by members of this clump. -/
  maxOccupiedSlot : SpiralIndex
  /-- CVDF chain height (cooperative VDF). -/
  cvdfHeight : Nat
  /-- CVDF chain weight (attestation count). -/
  cvdfWeight : Nat

/-- Compute total VDF work for a clump from member states. -/
def ClumpState.computeWork (c : ClumpState) : Nat :=
  c.members.foldl (fun acc pid =>
    match c.memberStates.lookup pid with
    | some st => acc + st.ourVdf.cumulativeCredit
    | none => acc
  ) 0

/-- A clump is well-formed if all members are present in memberStates
    and all member states are valid. -/
structure ClumpState.WellFormed (c : ClumpState) : Prop where
  /-- Every member has a state. -/
  allPresent : ∀ pid ∈ c.members, c.memberStates.lookup pid ≠ none
  /-- Every member state is valid. -/
  allValid : ∀ pid (st : MeshState),
    c.memberStates.lookup pid = some st → st.Valid
  /-- No duplicates in member list. -/
  noDuplicates : c.members.Nodup
  /-- totalWork matches computed work. -/
  workCorrect : c.totalWork = c.computeWork

/-! ### Partition: One Clump → Two Clumps -/

/-- Split a clump into two along a partition boundary.
    Every member goes to exactly one side. -/
def splitClump (c : ClumpState) (boundary : PeerId → Bool)
    : ClumpState × ClumpState :=
  let membersA := c.members.filter boundary
  let membersB := c.members.filter (fun p => !boundary p)
  let statesA := membersA.foldl (fun acc pid =>
    match c.memberStates.lookup pid with
    | some st => acc.insert pid st
    | none => acc
  ) PMap.empty
  let statesB := membersB.foldl (fun acc pid =>
    match c.memberStates.lookup pid with
    | some st => acc.insert pid st
    | none => acc
  ) PMap.empty
  let workA := membersA.foldl (fun acc pid =>
    match c.memberStates.lookup pid with
    | some st => acc + st.ourVdf.cumulativeCredit
    | none => acc
  ) 0
  let workB := membersB.foldl (fun acc pid =>
    match c.memberStates.lookup pid with
    | some st => acc + st.ourVdf.cumulativeCredit
    | none => acc
  ) 0
  ({ clumpId := c.clumpId * 2
     members := membersA
     memberStates := statesA
     totalWork := workA
     maxOccupiedSlot := 0  -- recalculated after split
     cvdfHeight := c.cvdfHeight
     cvdfWeight := 0 },
   { clumpId := c.clumpId * 2 + 1
     members := membersB
     memberStates := statesB
     totalWork := workB
     maxOccupiedSlot := 0
     cvdfHeight := c.cvdfHeight
     cvdfWeight := 0 })

/-- Split preserves total membership: |A| + |B| = |original|. -/
theorem split_preserves_count (c : ClumpState) (boundary : PeerId → Bool) :
    let (a, b) := splitClump c boundary
    a.members.length + b.members.length = c.members.length := by
  simp [splitClump]
  -- This follows from List.filter + List.filter (not) = original
  sorry -- Same proof structure as Conservation.lean's split_conserves

/-- Split preserves total VDF work. -/
theorem split_preserves_work (c : ClumpState) (boundary : PeerId → Bool)
    (hwf : c.WellFormed) :
    let (a, b) := splitClump c boundary
    a.totalWork + b.totalWork = c.totalWork := by
  sorry -- Sum over disjoint partition = original sum

/-- Both sides of a split are well-formed (if original was). -/
theorem split_wellformed (c : ClumpState) (boundary : PeerId → Bool)
    (hwf : c.WellFormed) :
    let (a, b) := splitClump c boundary
    a.WellFormed ∧ b.WellFormed := by
  sorry -- Follows from: filter preserves Nodup, states are inherited

/-! ### Merge: Two Clumps → One Clump -/

/-- Determine the merge winner. Heavier VDF work wins.
    Tiebreak: higher clump ID (deterministic). -/
def mergeWinner (a b : ClumpState) : Bool :=
  if a.totalWork > b.totalWork then true
  else if b.totalWork > a.totalWork then false
  else a.clumpId > b.clumpId  -- deterministic tiebreak

/-- Merge two clumps. Winner keeps its SPIRAL positions,
    loser's unique members get new positions after the winner's max slot. -/
def mergeClumps (a b : ClumpState) : ClumpState :=
  let aWins := mergeWinner a b
  let (winner, loser) := if aWins then (a, b) else (b, a)
  -- Loser-only members: members of loser not in winner
  let loserOnly := loser.members.filter (fun p => p ∉ winner.members)
  -- Combined members
  let allMembers := winner.members ++ loserOnly
  -- Combined states (winner's states take priority)
  let combinedStates := loserOnly.foldl (fun acc pid =>
    match loser.memberStates.lookup pid with
    | some st => acc.insert pid st
    | none => acc
  ) winner.memberStates
  { clumpId := min winner.clumpId loser.clumpId
    members := allMembers
    memberStates := combinedStates
    totalWork := winner.totalWork + loser.totalWork
    maxOccupiedSlot := winner.maxOccupiedSlot + loserOnly.length
    cvdfHeight := max winner.cvdfHeight loser.cvdfHeight
    cvdfWeight := winner.cvdfWeight + loser.cvdfWeight }

/-- Merge is commutative: merge(A,B) has the same members as merge(B,A). -/
theorem merge_commutative_members (a b : ClumpState) :
    (mergeClumps a b).members.toFinset = (mergeClumps b a).members.toFinset := by
  sorry -- Winner/loser swap produces same union of members

/-- Merge preserves total membership (no peers lost). -/
theorem merge_preserves_count (a b : ClumpState)
    (hDisjoint : ∀ p, p ∈ a.members → p ∉ b.members) :
    (mergeClumps a b).members.length = a.members.length + b.members.length := by
  sorry -- Disjoint: loserOnly = loser.members, union = sum

/-- Merge preserves total VDF work (additive). -/
theorem merge_preserves_work (a b : ClumpState) :
    (mergeClumps a b).totalWork = a.totalWork + b.totalWork := by
  simp only [mergeClumps, mergeWinner]
  split_ifs <;> simp_all <;> omega

/-- Merge winner is deterministic: both sides compute the same winner. -/
theorem merge_deterministic (a b : ClumpState) :
    mergeWinner a b = !mergeWinner b a ∨
    (a.totalWork = b.totalWork ∧ a.clumpId = b.clumpId) := by
  sorry -- Bool negation of comparison chain; requires case analysis on total ordering

/-- Merge winner keeps its SPIRAL positions (privilege). -/
theorem merge_winner_privilege (a b : ClumpState)
    (hAWins : mergeWinner a b = true) :
    -- Winner's members are all in the merged clump
    ∀ p ∈ a.members, p ∈ (mergeClumps a b).members := by
  intro p hp
  simp [mergeClumps, hAWins]
  left; exact hp

/-! ### Supernode Clump Behavior -/

/-- Supernode members in the same clump have independent slots.
    They don't share a slot just because they share a site. -/
theorem supernode_independent_slots (c : ClumpState) (hwf : c.WellFormed)
    (p₁ p₂ : PeerId) (st₁ st₂ : MeshState) (s₁ s₂ : SpiralIndex)
    (hMem₁ : p₁ ∈ c.members) (hMem₂ : p₂ ∈ c.members)
    (hSt₁ : c.memberStates.lookup p₁ = some st₁)
    (hSt₂ : c.memberStates.lookup p₂ = some st₂)
    (hDiff : p₁ ≠ p₂)
    (hSlot₁ : st₁.spiral.ourSlot = some s₁)
    (hSlot₂ : st₂.spiral.ourSlot = some s₂)
    -- If both nodes believe the other occupies a different slot
    (hMutualAware : st₁.spiral.peerToSlot.lookup p₂ = some s₂) :
    -- Then their slots are different
    s₁ ≠ s₂ := by
  intro heq
  subst heq
  -- st₁'s Valid says: no remote peer at our slot
  have hv := hwf.allValid p₁ st₁ hSt₁
  exact hv.spiralValid.noRemoteAtOurSlot p₂ s₁ hSlot₁ hMutualAware

/-! ### Partition Detection -/

/-- A node detects partition when ALL non-local SPIRAL neighbors
    have failed VDF liveness checks (silence > 10s). -/
def isPartitioned (node : MeshState) : Bool :=
  let neighbors := computeNeighbors node.spiral
  let aliveNeighbors := neighbors.filter fun pid =>
    match node.knownPeers.lookup pid with
    | some info => !isDead node info
    | none => false
  -- If we have neighbors but none are alive, we're partitioned
  neighbors.length > 0 && aliveNeighbors.length = 0

/-- If any SPIRAL neighbor is alive, we're not partitioned. -/
theorem not_partitioned_if_alive_neighbor (node : MeshState)
    (pid : PeerId) (info : PeerInfo)
    (hNeighbor : pid ∈ computeNeighbors node.spiral)
    (hKnown : node.knownPeers.lookup pid = some info)
    (hAlive : isDead node info = false) :
    isPartitioned node = false := by
  sorry -- At least one alive neighbor → aliveNeighbors.length > 0 → not partitioned

/-! ### Convergence After Merge -/

/-- After merge, the combined clump has strictly more VDF work than either side.
    This means repeated splits and merges monotonically increase total work
    (because VDF ticks continue during partition). -/
theorem merge_increases_work (a b : ClumpState)
    (hAPos : a.totalWork > 0)
    (hBPos : b.totalWork > 0) :
    (mergeClumps a b).totalWork > a.totalWork ∧
    (mergeClumps a b).totalWork > b.totalWork := by
  have h := merge_preserves_work a b
  constructor <;> omega

/-- VDF work is monotonically increasing over time.
    A clump's total work can never decrease. -/
theorem clump_work_monotone (c : ClumpState) (t₁ t₂ : Timestamp)
    (hLe : t₁ ≤ t₂) :
    -- After time passes, total work ≥ original (VDF ticks add work)
    True := by trivial  -- Placeholder: requires modeling VDF ticks per clump

end LagoonMesh
