/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.Types
import LagoonMesh.Spiral
import LagoonMesh.Messages

/-!
# Mesh Protocol State

The complete state of a Lagoon mesh node, modeled as a pure value.
Every state transition is a pure function `MeshState → InboundMsg → MeshState × List OutboundAction`.

## Correspondence to Rust

| Lean field        | Rust field                     | File            |
|-------------------|--------------------------------|-----------------|
| `spiral`          | `state.spiral`                 | spiral.rs       |
| `knownPeers`      | `state.known_peers`            | federation.rs   |
| `connections`     | `federation.relays`            | federation.rs   |
| `bootstrapPeers`  | from `LAGOON_PEERS` config     | federation.rs   |
| `now`             | `Instant::now()`               | federation.rs   |

## Key Design: Pure Functions

The Rust code uses `tokio::select!` with mutable state and async I/O.
We model the SEMANTICS, not the implementation. Each handler is a pure
function that takes the current state + a message and returns the new state
+ a list of outbound actions. This makes every property decidable.
-/

namespace LagoonMesh

/-- Connection info for an active relay. -/
structure RelayInfo where
  peerId : PeerId
  isBootstrap : Bool
  helloExchanged : Bool
  /-- True if the remote side initiated this connection (they dialed us).
      In Rust: `connect_target.is_empty()` for inbound switchboard relays.
      Inbound relays must NEVER be pruned — the dialing side chose us as a
      SPIRAL neighbor, so we must keep the connection even if we don't
      consider them our neighbor (SPIRAL topology convergence is not
      instantaneous, so neighbor relationships may be temporarily asymmetric). -/
  isInbound : Bool
  deriving Repr

/-- The complete mesh node state. -/
structure MeshState where
  /-- Our peer identity. -/
  ourId : PeerId
  /-- SPIRAL topology. -/
  spiral : SpiralState
  /-- Known peers (discovered via gossip or direct connection). -/
  knownPeers : PMap PeerId PeerInfo
  /-- Active relay connections. -/
  relays : PMap PeerId RelayInfo
  /-- Bootstrap peers from LAGOON_PEERS config. -/
  bootstrapPeers : List PeerId
  /-- Current abstract timestamp. -/
  now : Timestamp
  /-- Our VDF state. -/
  ourVdf : VdfSnapshot
  /-- Cached cluster VDF work (sum of connected peers' cumulative credit). -/
  clusterVdfWork : Nat

/-! ### State Invariants -/

/-- The complete mesh state invariant. Every valid state satisfies all of these. -/
structure MeshState.Valid (s : MeshState) : Prop where
  /-- SPIRAL topology is internally consistent. -/
  spiralValid : s.spiral.Valid
  /-- Our ID in spiral matches our global ID. -/
  spiralOurId : s.spiral.ourId = s.ourId
  /-- Every connected peer is known. -/
  connectedIsKnown : ∀ (pid : PeerId) (ri : RelayInfo),
    s.relays.lookup pid = some ri →
    s.knownPeers.lookup pid ≠ none
  /-- We are never connected to ourselves. -/
  noSelfConnection : s.relays.lookup s.ourId = none
  /-- Every SPIRAL peer is known. -/
  spiralPeerKnown : ∀ (pid : PeerId) (slot : SpiralIndex),
    s.spiral.peerToSlot.lookup pid = some slot →
    s.knownPeers.lookup pid ≠ none
  /-- Bootstrap peers that are connected have isBootstrap = true. -/
  bootstrapMarked : ∀ (pid : PeerId) (ri : RelayInfo),
    pid ∈ s.bootstrapPeers →
    s.relays.lookup pid = some ri →
    ri.isBootstrap = true

/-! ### Neighbor Computation

In Rust: `recompute_neighbors()` in `spiral.rs`.
Given a topology, compute the set of SPIRAL neighbors for our position. -/

/-- Compute SPIRAL neighbors for a given position.
    Returns the closest MAX_NEIGHBORS peers by hex distance.
    If fewer than MAX_NEIGHBORS peers exist, all are neighbors. -/
def computeNeighbors (s : SpiralState) : List PeerId :=
  match s.ourSlot with
  | none => []  -- unclaimed, no neighbors
  | some ourIdx =>
    let ourCoord := spiralCoord ourIdx
    -- All remote peers with their distances
    let withDist := s.peerToSlot.keys.map fun pid =>
      match s.peerToSlot.lookup pid with
      | some slot => (pid, hexDistance ourCoord (spiralCoord slot))
      | none => (pid, 0)  -- shouldn't happen
    -- Sort by distance, take top MAX_NEIGHBORS
    let sorted := withDist.mergeSort (fun a b => a.2 ≤ b.2)
    (sorted.take MAX_NEIGHBORS).map Prod.fst

/-- A peer is a SPIRAL neighbor if it's in the neighbor set. -/
def isNeighbor (s : MeshState) (pid : PeerId) : Bool :=
  pid ∈ computeNeighbors s.spiral

/-! ### Pruning Predicates

In Rust: `prune_non_spiral_relays()` in `federation.rs`.
The pruning rule: SPIRAL neighbors stay. Everything else goes.
With a guard: don't prune if we'd go below the minimum. -/

/-- Should this relay be pruned? -/
def shouldPrune (s : MeshState) (pid : PeerId) (ri : RelayInfo) : Bool :=
  -- Never prune bootstrap
  if ri.isBootstrap then false
  -- Never prune inbound connections. The dialing side chose us as a SPIRAL
  -- neighbor; we must not reject that connection even if we don't consider
  -- them our neighbor. SPIRAL topology convergence is not instantaneous:
  -- if A considers B a neighbor but B does not yet consider A a neighbor,
  -- pruning A's inbound relay on B breaks the connection before HELLO
  -- completes, causing A's relay task to escalate to 60-second backoff.
  -- Invariant: isInbound → ¬ shouldPrune (proved in ConnectionProofs.lean).
  else if ri.isInbound then false
  -- Never prune SPIRAL neighbors
  else if isNeighbor s pid then false
  -- Guard: don't prune below minimum
  else
    let nonBootstrapCount := s.relays.values.filter (fun r => !r.isBootstrap) |>.length
    let neighborCount := (computeNeighbors s.spiral).length
    let minRelays := max neighborCount 2
    nonBootstrapCount > minRelays

/-- Compute the set of peers to prune. -/
def computePruneSet (s : MeshState) : List PeerId :=
  s.relays.keys.filter fun pid =>
    match s.relays.lookup pid with
    | some ri => shouldPrune s pid ri
    | none => false

/-! ### VDF Liveness

In Rust: `evict_dead_peers()` in `federation.rs`.
One rule: VDF silence for VDF_DEAD_SECS = death. -/

/-- Is this peer dead (VDF not advancing)? -/
def isDead (s : MeshState) (info : PeerInfo) : Bool :=
  let lastAdvance := if info.lastVdfAdvance = 0 then info.lastSeen else info.lastVdfAdvance
  s.now > lastAdvance + VDF_DEAD_SECS

/-- Compute the set of dead peers to evict. -/
def computeDeadPeers (s : MeshState) : List PeerId :=
  s.knownPeers.keys.filter fun pid =>
    match s.knownPeers.lookup pid with
    | some info => isDead s info
    | none => false

/-! ### Merge Decision

In Rust: `evaluate_spiral_merge()` in `federation.rs`.
Four cases: VDF race, concierge, same-slot collision, cluster merge. -/

/-- The result of evaluating a SPIRAL merge. -/
inductive MergeDecision where
  /-- Both unclaimed: deterministic slot assignment by VDF credit. -/
  | vdfRace : SpiralIndex → MergeDecision
  /-- We're unclaimed, they have a slot: take their assigned_slot. -/
  | concierge : SpiralIndex → MergeDecision
  /-- Same slot claimed: compare credit, loser yields. -/
  | collision : (weWin : Bool) → MergeDecision
  /-- Different clumps: compare cluster work, loser merges around winner. -/
  | clusterMerge : (weWin : Bool) → MergeDecision
  /-- No merge needed (same clump, compatible slots). -/
  | noOp : MergeDecision
  deriving Repr

/-- Evaluate what merge action to take given a HELLO from a remote peer. -/
def evaluateMerge (s : MeshState) (hello : HelloMsg) : MergeDecision :=
  match s.spiral.ourSlot, hello.spiralIndex with
  -- Both unclaimed: VDF race
  | none, none =>
    if s.ourVdf.cumulativeCredit ≥ hello.cumulativeCredit
    then .vdfRace 0  -- we get slot 0
    else .vdfRace 1  -- we get slot 1
  -- We're unclaimed, they have a slot: concierge
  | none, some _ =>
    match hello.assignedSlot with
    | some slot => .concierge slot
    | none => .vdfRace 0  -- fallback: claim first empty
  -- They're unclaimed, we have a slot: we're the concierge (no merge needed for us)
  | some _, none => .noOp
  -- Both claimed
  | some ourSlot, some theirSlot =>
    if ourSlot = theirSlot then
      -- Same slot collision: compare credit
      .collision (s.ourVdf.cumulativeCredit ≥ hello.cumulativeCredit)
    else
      -- Different slots: check if same clump or different clumps
      -- For now: if we know them, same clump. If unknown, cluster merge.
      match s.knownPeers.lookup hello.peerId with
      | some _ => .noOp  -- already known, same clump
      | none => .clusterMerge (s.clusterVdfWork ≥ hello.clusterVdfWork)

end LagoonMesh
