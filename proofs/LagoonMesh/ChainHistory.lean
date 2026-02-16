/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.ClusterChain

/-!
# Cluster Chain History — Blockchain Model with Merge/Split/Prune

Extends ClusterChain with a **full blockchain history** that:

1. **Records every event** — advances, merges, splits, genesis
2. **Supports history playback** — walk backwards through blocks
3. **Tracks merges and splits** — merge events carry both parent chains
4. **Is prunable like Git** — trim old history, snip ranges, keep integrity

## Design

Each block in the chain history records:
- The chain value at that round
- The previous block's hash (blockchain linkage)
- What happened: normal advance, cluster merge, cluster split, or genesis
- Metadata for visualization (participating peer count, cluster size, etc.)

The history is a list of blocks in reverse chronological order (newest first).
Pruning removes blocks from the middle or start while preserving the chain
values at boundaries (like Git shallow clones or history rewriting).

## Pruning Model (Git-Like)

Three operations:
- **Trim**: Remove all blocks before round N. Creates a "shallow" history.
- **Compact**: Remove blocks in a range, keeping boundary blocks.
- Both preserve chain VALUES — only block linkage metadata changes.
-/

namespace LagoonMesh

/-! ### Block Types -/

/-- Events that can occur in the cluster chain history. -/
inductive ChainEvent where
  /-- Normal round advance: chain(n+1) = hash(chain(n), timestamp). -/
  | advance : ChainEvent
  /-- Cluster genesis: a new cluster forms with a seed value. -/
  | genesis : ChainEvent
  /-- Two clusters merge. Carries the loser's chain value at merge time. -/
  | merge (loserChainValue : ChainValue) (loserRound : Round) : ChainEvent
  /-- Cluster splits (network partition detected). -/
  | split : ChainEvent
  deriving DecidableEq, Repr

/-- A single block in the cluster chain history.

    Like a Git commit: has a parent hash, a content hash, and metadata.
    The `chainValue` is the ACTUAL cluster identity at this round.
    The `blockHash` is the HISTORY integrity hash (links blocks together). -/
structure ChainBlock where
  /-- Hash of the previous block (0 for genesis). -/
  prevBlockHash : Nat
  /-- The cluster chain value at this round. -/
  chainValue : ChainValue
  /-- The round number. -/
  round : Round
  /-- The Universal Clock timestamp for this round. -/
  timestamp : RoundedTimestamp
  /-- What happened at this round. -/
  event : ChainEvent
  /-- Number of peers in the cluster at this round (visualization metadata). -/
  clusterSize : Nat
  deriving DecidableEq, Repr

/-- Compute a block's integrity hash from its contents. -/
def computeBlockHash (b : ChainBlock) : Nat :=
  chainHash (chainHash b.prevBlockHash b.chainValue) b.round

/-! ### History Operations

History is `List ChainBlock` in reverse chronological order (newest first). -/

/-- Create a genesis history with a single block. -/
def genesisHistory (seed : ChainValue) (ts : RoundedTimestamp)
    (initialSize : Nat) : List ChainBlock :=
  [{ prevBlockHash := 0
   , chainValue := seed
   , round := 0
   , timestamp := ts
   , event := .genesis
   , clusterSize := initialSize }]

/-- Append an advance block to the history. -/
def advanceHistory (history : List ChainBlock) (ts : RoundedTimestamp)
    (size : Nat) : List ChainBlock :=
  match history with
  | [] => []
  | head :: rest =>
    let newValue := advanceChain head.chainValue ts
    { prevBlockHash := computeBlockHash head
    , chainValue := newValue
    , round := head.round + 1
    , timestamp := ts
    , event := .advance
    , clusterSize := size } :: head :: rest

/-- Append a merge block: two clusters becoming one. -/
def mergeHistory (winnerHistory : List ChainBlock)
    (loserValue : ChainValue) (loserRound : Round)
    (mergedTopoHash : Nat) (ts : RoundedTimestamp)
    (mergedSize : Nat) : List ChainBlock :=
  match winnerHistory with
  | [] => []
  | head :: rest =>
    let mergedSeed := mergeChainSeed head.chainValue loserValue mergedTopoHash
    { prevBlockHash := computeBlockHash head
    , chainValue := mergedSeed
    , round := head.round + 1
    , timestamp := ts
    , event := .merge loserValue loserRound
    , clusterSize := mergedSize } :: head :: rest

/-- Record a split event (partition detected). -/
def splitHistory (history : List ChainBlock)
    (ts : RoundedTimestamp) (remainingSize : Nat) : List ChainBlock :=
  match history with
  | [] => []
  | head :: rest =>
    { prevBlockHash := computeBlockHash head
    , chainValue := advanceChain head.chainValue ts
    , round := head.round + 1
    , timestamp := ts
    , event := .split
    , clusterSize := remainingSize } :: head :: rest

/-! ### History Queries -/

/-- Get the block at a specific round. -/
def blockAtRound (history : List ChainBlock) (r : Round) : Option ChainBlock :=
  history.find? (fun b => b.round == r)

/-- Get all merge events in the history. -/
def mergeBlocks (history : List ChainBlock) : List ChainBlock :=
  history.filter fun b => match b.event with
    | .merge _ _ => true
    | _ => false

/-- Get all split events in the history. -/
def splitBlocks (history : List ChainBlock) : List ChainBlock :=
  history.filter fun b => match b.event with
    | .split => true
    | _ => false

/-! ### Pruning Operations (Git-Like) -/

/-- **Trim**: Remove all blocks before round N.
    Creates a shallow history. Like `git clone --depth N`. -/
def trimHistory (history : List ChainBlock) (keepFromRound : Round)
    : List ChainBlock :=
  history.filter fun b => b.round >= keepFromRound

/-- **Compact**: Remove blocks in range [fromRound, toRound).
    Preserves boundary blocks. Like squashing Git commits. -/
def compactHistory (history : List ChainBlock)
    (fromRound toRound : Round) : List ChainBlock :=
  history.filter fun b => b.round < fromRound || b.round >= toRound

/-- Check if a history has gaps (has been pruned). -/
def historyHasGaps : List ChainBlock → Bool
  | [] => false
  | [_] => false
  | a :: b :: rest =>
    if a.round != b.round + 1 then true
    else historyHasGaps (b :: rest)

/-! ### Hash Chain Integrity -/

/-- A block is validly linked to its predecessor. -/
def validBlockLink (block prev : ChainBlock) : Prop :=
  block.prevBlockHash = computeBlockHash prev

/-- A complete (non-pruned) history has valid hash chain linkage. -/
def validBlockChain : List ChainBlock → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest => validBlockLink a b ∧ validBlockChain (b :: rest)

/-- A history has consistent chain values (each advance follows from previous). -/
def consistentChainValues : List ChainBlock → Prop
  | [] => True
  | [_] => True
  | a :: b :: rest =>
    (match a.event with
     | .advance => a.chainValue = advanceChain b.chainValue a.timestamp
     | .merge loserVal _ => ∃ topoHash, a.chainValue = mergeChainSeed b.chainValue loserVal topoHash
     | .split => a.chainValue = advanceChain b.chainValue a.timestamp
     | .genesis => True) ∧
    consistentChainValues (b :: rest)

-- ═══════════════════════════════════════════════════════════════════════
-- PROOFS
-- ═══════════════════════════════════════════════════════════════════════

/-! ## Genesis Properties -/

/-- Genesis creates a single-block history. -/
theorem genesis_has_one_block (seed : ChainValue) (ts : RoundedTimestamp) (size : Nat) :
    (genesisHistory seed ts size).length = 1 := rfl

/-- Genesis history has valid block chain. -/
theorem genesis_valid_chain (seed : ChainValue) (ts : RoundedTimestamp) (size : Nat) :
    validBlockChain (genesisHistory seed ts size) := trivial

/-- Genesis block has the seed as its chain value. -/
theorem genesis_value (seed : ChainValue) (ts : RoundedTimestamp) (size : Nat) :
    (genesisHistory seed ts size).head?.map ChainBlock.chainValue = some seed := rfl

/-! ## Advance Properties -/

/-- Advancing a non-empty history increases length by 1. -/
theorem advance_increases_length (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    (advanceHistory (head :: rest) ts size).length = (head :: rest).length + 1 := rfl

/-- The new block's chain value matches advanceChain. -/
theorem advance_value (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    (advanceHistory (head :: rest) ts size).head?.map ChainBlock.chainValue =
    some (advanceChain head.chainValue ts) := rfl

/-- Advancing preserves prior blocks (tail is the original history). -/
theorem advance_preserves_tail (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    (advanceHistory (head :: rest) ts size).tail = head :: rest := rfl

/-! ## Merge Properties -/

/-- Merge block uses mergeChainSeed. -/
theorem merge_value (head : ChainBlock) (rest : List ChainBlock)
    (loserVal : ChainValue) (loserRound : Round) (topoHash : Nat)
    (ts : RoundedTimestamp) (size : Nat) :
    (mergeHistory (head :: rest) loserVal loserRound topoHash ts size).head?.map
      ChainBlock.chainValue =
    some (mergeChainSeed head.chainValue loserVal topoHash) := rfl

/-- Merge records the loser's chain value in the event. -/
theorem merge_records_loser (head : ChainBlock) (rest : List ChainBlock)
    (loserVal : ChainValue) (loserRound : Round) (topoHash : Nat)
    (ts : RoundedTimestamp) (size : Nat) :
    let merged := mergeHistory (head :: rest) loserVal loserRound topoHash ts size
    match merged.head?.map ChainBlock.event with
    | some (.merge lv lr) => lv = loserVal ∧ lr = loserRound
    | _ => False := by
  simp [mergeHistory]

/-! ## Hash Chain Integrity -/

/-- Advancing a valid chain produces a valid chain. -/
theorem advance_preserves_chain_validity (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat)
    (hValid : validBlockChain (head :: rest)) :
    validBlockChain (advanceHistory (head :: rest) ts size) := by
  simp only [advanceHistory, validBlockChain]
  exact ⟨rfl, hValid⟩

/-- Merge preserves chain validity. -/
theorem merge_preserves_chain_validity (head : ChainBlock) (rest : List ChainBlock)
    (loserVal : ChainValue) (loserRound : Round) (topoHash : Nat)
    (ts : RoundedTimestamp) (size : Nat)
    (hValid : validBlockChain (head :: rest)) :
    validBlockChain (mergeHistory (head :: rest) loserVal loserRound topoHash ts size) := by
  simp only [mergeHistory, validBlockChain]
  exact ⟨rfl, hValid⟩

/-- Split preserves chain validity. -/
theorem split_preserves_chain_validity (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat)
    (hValid : validBlockChain (head :: rest)) :
    validBlockChain (splitHistory (head :: rest) ts size) := by
  simp only [splitHistory, validBlockChain]
  exact ⟨rfl, hValid⟩

/-! ## Pruning Properties -/

/-- Trimming preserves blocks at or after the trim point. -/
theorem trim_preserves_recent (history : List ChainBlock) (keepFrom : Round)
    (block : ChainBlock) (hMem : block ∈ history) (hRecent : block.round >= keepFrom) :
    block ∈ trimHistory history keepFrom := by
  simp only [trimHistory]
  exact List.mem_filter.mpr ⟨hMem, by simp [decide_eq_true_eq]; exact hRecent⟩

/-- Trimming removes blocks before the trim point. -/
theorem trim_removes_old (history : List ChainBlock) (keepFrom : Round)
    (block : ChainBlock) (hMem : block ∈ trimHistory history keepFrom) :
    block.round >= keepFrom := by
  simp only [trimHistory] at hMem
  have h := (List.mem_filter.mp hMem).2
  simp [decide_eq_true_eq] at h
  exact h

/-- Compact preserves blocks outside the compacted range. -/
theorem compact_preserves_outside (history : List ChainBlock)
    (fromRound toRound : Round)
    (block : ChainBlock) (hMem : block ∈ history)
    (hOutside : block.round < fromRound ∨ block.round >= toRound) :
    block ∈ compactHistory history fromRound toRound := by
  simp only [compactHistory]
  apply List.mem_filter.mpr
  constructor
  · exact hMem
  · simp [decide_eq_true_eq, Bool.or_eq_true]
    exact hOutside

/-! ## Chain Value Preservation Under Pruning -/

/-- Trimming preserves the current (most recent) chain value
    when the head block is kept. -/
theorem trim_preserves_head (head : ChainBlock) (rest : List ChainBlock)
    (keepFrom : Round) (hKeep : head.round >= keepFrom) :
    (trimHistory (head :: rest) keepFrom).head?.map ChainBlock.chainValue =
    some head.chainValue := by
  unfold trimHistory
  rw [List.filter_cons_of_pos]
  · rfl
  · simp [decide_eq_true_eq]; exact hKeep

/-! ## Event Counting -/

/-- Count merges in history. -/
def countMerges : List ChainBlock → Nat
  | [] => 0
  | b :: rest => (match b.event with | .merge _ _ => 1 | _ => 0) + countMerges rest

/-- Count splits in history. -/
def countSplits : List ChainBlock → Nat
  | [] => 0
  | b :: rest => (match b.event with | .split => 1 | _ => 0) + countSplits rest

/-- A merge event increments the merge count. -/
theorem merge_increments_count (head : ChainBlock) (rest : List ChainBlock)
    (loserVal : ChainValue) (loserRound : Round) (topoHash : Nat)
    (ts : RoundedTimestamp) (size : Nat) :
    countMerges (mergeHistory (head :: rest) loserVal loserRound topoHash ts size) =
    countMerges (head :: rest) + 1 := by
  simp [mergeHistory, countMerges]
  omega

/-- A split event increments the split count. -/
theorem split_increments_count (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    countSplits (splitHistory (head :: rest) ts size) =
    countSplits (head :: rest) + 1 := by
  simp [splitHistory, countSplits]
  omega

/-- Advancing doesn't change the merge count. -/
theorem advance_preserves_merge_count (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    countMerges (advanceHistory (head :: rest) ts size) =
    countMerges (head :: rest) := by
  simp [advanceHistory, countMerges]

/-- Advancing doesn't change the split count. -/
theorem advance_preserves_split_count (head : ChainBlock) (rest : List ChainBlock)
    (ts : RoundedTimestamp) (size : Nat) :
    countSplits (advanceHistory (head :: rest) ts size) =
    countSplits (head :: rest) := by
  simp [advanceHistory, countSplits]

/-! ## Helper: Head value through foldl -/

/-- Key invariant: after folding advanceHistory over a non-empty history,
    the head block's chainValue equals computeChain applied to the
    original head's chainValue and the timestamps. -/
theorem foldl_advance_head_value (head : ChainBlock) (rest : List ChainBlock)
    (timestamps : List RoundedTimestamp) (size : Nat) :
    (timestamps.foldl (fun h ts => advanceHistory h ts size) (head :: rest)).head?.map
      ChainBlock.chainValue =
    some (computeChain head.chainValue timestamps) := by
  induction timestamps generalizing head rest with
  | nil => simp [computeChain]
  | cons ts tl ih =>
    simp only [List.foldl_cons, computeChain, advanceHistory]
    exact ih _ _

/-! ## Combined: History Reflects Chain State -/

/-- The history accurately tracks the cluster chain value.
    After N advances from genesis, the head block's chain value
    equals computeChain applied to the seed and timestamps. -/
theorem history_tracks_chain_value (seed : ChainValue) (ts₀ : RoundedTimestamp)
    (timestamps : List RoundedTimestamp) (size : Nat) :
    (timestamps.foldl (fun h ts => advanceHistory h ts size)
      (genesisHistory seed ts₀ size)).head?.map ChainBlock.chainValue =
    some (computeChain seed timestamps) := by
  exact foldl_advance_head_value _ _ timestamps size

/-! ## Pruning Soundness -/

/-- After trimming, every remaining block was in the original history. -/
theorem trim_subset (history : List ChainBlock) (keepFrom : Round)
    (block : ChainBlock) (hMem : block ∈ trimHistory history keepFrom) :
    block ∈ history :=
  (List.mem_filter.mp hMem).1

/-- After compacting, every remaining block was in the original history. -/
theorem compact_subset (history : List ChainBlock) (fromRound toRound : Round)
    (block : ChainBlock) (hMem : block ∈ compactHistory history fromRound toRound) :
    block ∈ history :=
  (List.mem_filter.mp hMem).1

/-- Trimming is monotone: trimming at a later round produces a subset. -/
theorem trim_monotone (history : List ChainBlock) (r₁ r₂ : Round)
    (hLe : r₁ ≤ r₂) (block : ChainBlock)
    (hMem : block ∈ trimHistory history r₂) :
    block ∈ trimHistory history r₁ := by
  have hIn := trim_subset history r₂ block hMem
  have hRound := trim_removes_old history r₂ block hMem
  exact trim_preserves_recent history r₁ block hIn (Nat.le_trans hLe hRound)

end LagoonMesh
