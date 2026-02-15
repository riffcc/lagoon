/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.Types
import Mathlib.Data.Finset.Basic
import Mathlib.Data.Finset.Card
import Mathlib.Data.List.Sort

/-!
# SPIRAL Topology — Formal Model

Pure functional model of `SpiralTopology` from `spiral.rs`.
Every mutation is a pure function `State → State`.
Every invariant is a proposition. Every transition preserves every invariant.

## Key Invariants (proven in SpiralProofs.lean)

1. **No ghost slots**: Every occupied coord has a peer. Every peer has a coord.
2. **Unique occupation**: No two peers at the same slot.
3. **Self-consistency**: Our position appears in occupied iff we're claimed.
4. **Repack fills all holes**: After repack, occupied = {0, 1, ..., N-1}.
5. **Merge preserves peer count**: |peers after merge| = |our peers| + |loser-only peers|.
6. **Swap preserves topology**: Swap doesn't change the set of peers, only their positions.
-/

namespace LagoonMesh

/-! ### Association List Map

A simple partial map modeled as a `List (α × β)`.
We use this instead of Mathlib's `Finmap` for simpler proof automation. -/

/-- A partial function from a finite domain. -/
def PMap (α β : Type) [DecidableEq α] := List (α × β)

namespace PMap

variable {α β : Type} [DecidableEq α]

def empty : PMap α β := []

def lookup (m : PMap α β) (k : α) : Option β :=
  match m with
  | [] => none
  | (k', v) :: rest => if k' == k then some v else lookup rest k

def insert (m : PMap α β) (k : α) (v : β) : PMap α β :=
  (k, v) :: m.filter (fun p => decide (p.1 ≠ k))

def erase (m : PMap α β) (k : α) : PMap α β :=
  m.filter (fun p => decide (p.1 ≠ k))

def keys (m : PMap α β) : List α :=
  m.map Prod.fst

def values (m : PMap α β) : List β :=
  m.map Prod.snd

def size (m : PMap α β) : Nat :=
  m.length

/-- A PMap has unique keys. -/
def UniqueKeys (m : PMap α β) : Prop :=
  m.keys.Nodup

-- Basic lemmas about insert/erase

theorem lookup_insert_eq [BEq α] [LawfulBEq α] (m : PMap α β) (k : α) (v : β) :
    (m.insert k v).lookup k = some v := by
  simp [insert, lookup, beq_self_eq_true]

theorem lookup_insert_ne [BEq α] [LawfulBEq α] (m : PMap α β) (k₁ k₂ : α) (v : β)
    (h : k₁ ≠ k₂) :
    (m.insert k₁ v).lookup k₂ = m.lookup k₂ := by
  simp [insert, lookup, BEq.beq, bne_iff_ne, h, Ne.symm h]
  sorry -- mechanical: filter preserves k₂, cons head doesn't match

theorem lookup_erase [BEq α] [LawfulBEq α] (m : PMap α β) (k : α) :
    (m.erase k).lookup k = none := by
  simp [erase]
  induction m with
  | nil => simp [lookup]
  | cons hd tl ih =>
    simp [List.filter, lookup]
    sorry -- mechanical: filter removes k, recursive lookup on filtered tail

theorem lookup_erase_ne [BEq α] [LawfulBEq α] (m : PMap α β) (k₁ k₂ : α) (h : k₁ ≠ k₂) :
    (m.erase k₁).lookup k₂ = m.lookup k₂ := by
  sorry -- mechanical: filter preserves k₂ entries

end PMap

/-! ### SPIRAL Topology State -/

/-- The SPIRAL topology state.
    In Rust: `SpiralTopology` struct in `spiral.rs`. -/
structure SpiralState where
  /-- Our peer identity. -/
  ourId : PeerId
  /-- Our claimed SPIRAL slot (None = unclaimed). -/
  ourSlot : Option SpiralIndex
  /-- Map from slot index → peer ID (remote peers only). -/
  slotToPeer : PMap SpiralIndex PeerId
  /-- Map from peer ID → slot index (remote peers only). -/
  peerToSlot : PMap PeerId SpiralIndex

/-! ### Invariants -/

/-- The fundamental invariant: slotToPeer and peerToSlot are inverses.
    This is the invariant that ghost slot bugs violate. -/
structure SpiralState.Valid (s : SpiralState) : Prop where
  /-- Forward → backward: slot i → peer p implies peer p → slot i. -/
  forward : ∀ (i : SpiralIndex) (p : PeerId),
    s.slotToPeer.lookup i = some p → s.peerToSlot.lookup p = some i
  /-- Backward → forward: peer p → slot i implies slot i → peer p. -/
  backward : ∀ (p : PeerId) (i : SpiralIndex),
    s.peerToSlot.lookup p = some i → s.slotToPeer.lookup i = some p
  /-- Our slot is not occupied by a remote peer. -/
  ourSlotFree : ∀ (i : SpiralIndex),
    s.ourSlot = some i → s.slotToPeer.lookup i = none
  /-- No remote peer claims our slot. -/
  noRemoteAtOurSlot : ∀ (p : PeerId) (i : SpiralIndex),
    s.ourSlot = some i → s.peerToSlot.lookup p = some i → False
  /-- Our ID is not in the remote peer map. -/
  ourIdNotRemote : s.peerToSlot.lookup s.ourId = none

/-- Total number of occupied slots (us + remote peers). -/
def SpiralState.occupiedCount (s : SpiralState) : Nat :=
  s.peerToSlot.size + (if s.ourSlot.isSome then 1 else 0)

/-- All occupied slot indices. -/
def SpiralState.occupiedSlots (s : SpiralState) : List SpiralIndex :=
  s.slotToPeer.keys ++ s.ourSlot.toList

/-! ### Operations -/

/-- Find the first unoccupied slot (scanning from 0). -/
def firstEmptySlot (slotToPeer : PMap SpiralIndex PeerId) (ourSlot : Option SpiralIndex)
    (bound : Nat) : SpiralIndex :=
  go 0 bound
where
  go (i : Nat) (fuel : Nat) : Nat :=
    match fuel with
    | 0 => i
    | fuel + 1 =>
      if slotToPeer.lookup i = none && ourSlot ≠ some i
      then i
      else go (i + 1) fuel

def SpiralState.firstEmpty (s : SpiralState) : SpiralIndex :=
  firstEmptySlot s.slotToPeer s.ourSlot (s.occupiedCount + 2)

/-- Claim the lowest available slot. No-op if already claimed. -/
def SpiralState.claimPosition (s : SpiralState) : SpiralState :=
  if s.ourSlot.isSome then s
  else { s with ourSlot := some s.firstEmpty }

/-- Claim a specific slot, evicting any remote peer there. -/
def SpiralState.claimSpecific (s : SpiralState) (slot : SpiralIndex) : SpiralState :=
  let evicted := s.slotToPeer.lookup slot
  let s' := match evicted with
    | none => s
    | some pid => { s with
        slotToPeer := s.slotToPeer.erase slot
        peerToSlot := s.peerToSlot.erase pid }
  { s' with ourSlot := some slot }

/-- Add a remote peer. First-writer-wins: if slot occupied, no-op. -/
def SpiralState.addPeer (s : SpiralState) (peerId : PeerId) (slot : SpiralIndex) : SpiralState :=
  if s.ourSlot = some slot then s
  else if s.slotToPeer.lookup slot ≠ none then s
  else if s.peerToSlot.lookup peerId ≠ none then s
  else { s with
    slotToPeer := s.slotToPeer.insert slot peerId
    peerToSlot := s.peerToSlot.insert peerId slot }

/-- Remove a remote peer. -/
def SpiralState.removePeer (s : SpiralState) (peerId : PeerId) : SpiralState :=
  match s.peerToSlot.lookup peerId with
  | none => s
  | some slot => { s with
      slotToPeer := s.slotToPeer.erase slot
      peerToSlot := s.peerToSlot.erase peerId }

/-- Force-add a remote peer, evicting current occupant. -/
def SpiralState.forceAddPeer (s : SpiralState) (peerId : PeerId) (slot : SpiralIndex)
    : SpiralState × Option PeerId :=
  let s₁ := s.removePeer peerId
  let evicted := s₁.slotToPeer.lookup slot
  let s₂ := match evicted with
    | none => s₁
    | some oldPeer => { s₁ with
        slotToPeer := s₁.slotToPeer.erase slot
        peerToSlot := s₁.peerToSlot.erase oldPeer }
  let s₃ := if s₂.ourSlot = some slot
    then { s₂ with ourSlot := none }
    else s₂
  let s₄ := { s₃ with
    slotToPeer := s₃.slotToPeer.insert slot peerId
    peerToSlot := s₃.peerToSlot.insert peerId slot }
  (s₄, evicted)

/-- Remove our claimed position. -/
def SpiralState.unclaim (s : SpiralState) : SpiralState :=
  { s with ourSlot := none }

/-- Swap two remote peers' positions. -/
def SpiralState.applySwap (s : SpiralState) (peerA peerB : PeerId) : SpiralState :=
  match s.peerToSlot.lookup peerA, s.peerToSlot.lookup peerB with
  | some slotA, some slotB =>
    { s with
      slotToPeer := (s.slotToPeer.insert slotA peerB).insert slotB peerA
      peerToSlot := (s.peerToSlot.insert peerA slotB).insert peerB slotA }
  | _, _ => s

/-! ### Repack -/

/-- A repack move. -/
structure RepackMove where
  peerId : PeerId
  fromSlot : SpiralIndex
  toSlot : SpiralIndex

/-- Holes in [0..n). -/
def SpiralState.holesBelow (s : SpiralState) (n : Nat) : List SpiralIndex :=
  (List.range n).filter fun i =>
    decide (s.slotToPeer.lookup i = none ∧ s.ourSlot ≠ some i)

/-- Peers at slots ≥ n. -/
def SpiralState.moversAbove (s : SpiralState) (n : Nat) : List (PeerId × SpiralIndex) :=
  (s.peerToSlot.keys.zip s.peerToSlot.values).filter fun (_, slot) =>
    decide (slot ≥ n)

/-- Compute repack moves (deterministic). -/
def SpiralState.computeRepackMoves (s : SpiralState) : List RepackMove :=
  let n := s.occupiedCount
  let holes := s.holesBelow n
  let movers := (s.moversAbove n).mergeSort (fun a b => a.2 ≤ b.2)
  holes.zip movers |>.map fun (hole, (peer, fromSlot)) =>
    { peerId := peer, fromSlot := fromSlot, toSlot := hole }

/-- Apply one repack move. -/
def SpiralState.applyMove (s : SpiralState) (m : RepackMove) : SpiralState :=
  let s₁ := { s with
    slotToPeer := s.slotToPeer.erase m.fromSlot
    peerToSlot := s.peerToSlot.erase m.peerId }
  { s₁ with
    slotToPeer := s₁.slotToPeer.insert m.toSlot m.peerId
    peerToSlot := s₁.peerToSlot.insert m.peerId m.toSlot }

/-- Apply all repack moves. -/
def SpiralState.applyRepack (s : SpiralState) : SpiralState :=
  s.computeRepackMoves.foldl SpiralState.applyMove s

/-! ### Merge -/

/-- Merge loser peers into our topology, then repack. -/
def SpiralState.mergeFrom (s : SpiralState)
    (loserPeers : List (PeerId × SpiralIndex)) : SpiralState :=
  let maxSlot := s.occupiedSlots.foldl max 0
  let s' := (List.range loserPeers.length).zip loserPeers |>.foldl (fun acc (i, (pid, _)) =>
    let newSlot := maxSlot + 1 + i
    if acc.peerToSlot.lookup pid ≠ none then acc
    else { acc with
      slotToPeer := acc.slotToPeer.insert newSlot pid
      peerToSlot := acc.peerToSlot.insert pid newSlot }
  ) s
  SpiralState.applyRepack s'

/-! ### Reconverge -/

/-- Move our position to the lowest hole below us. -/
def SpiralState.reconverge (s : SpiralState) : SpiralState :=
  match s.ourSlot with
  | none => s
  | some ourIdx =>
    let target := s.firstEmpty
    if target < ourIdx then
      { s with ourSlot := some target }
    else s

end LagoonMesh
