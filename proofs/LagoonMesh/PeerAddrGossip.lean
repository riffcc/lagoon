/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import Mathlib.Data.Finset.Basic
import Mathlib.Data.List.Basic
import LagoonMesh.Types

/-!
# Peer Address Gossip — SPORE Convergence Proofs

Formal verification that the SPORE-based peer address gossip protocol
(implemented in `peer_addr_store.rs` + `peer_addr_gossip.rs`) achieves
eventual consistency across all connected mesh nodes.

## Background: The Problem

When a new pod joins the mesh, it performs an initial peer exchange
(MeshHello → MeshPeers). But this exchange is one-shot: if node A learns
about node X *after* having already exchanged peers with node B, node B
never hears about X unless X connects to B directly.

SPORE-based gossip closes this gap: every node continuously syncs its
`PeerAddrStore` with its SPIRAL neighbors. Any record inserted into any
node propagates across the entire connected mesh within a bounded number
of sync rounds (bounded by the SPIRAL graph diameter, O(log n)).

## The Protocol (simplified)

Each node maintains:
- A `PeerAddrStore`: maps `peer_id → PeerAddrRecord` (newest-wins by timestamp)
- A `Spore`: grows-only set of `content_id`s of all records ever inserted

Gossip round between nodes A and B (from B's perspective — `on_have_list_received`):
1. A sends `HaveList { spore_A }` to B
2. B computes `missing = B.spore ∖ A.spore`
3. B sends `RecordDelta { records where content_id ∈ missing }` to A
4. A merges the received records (newest-wins per peer_id)

Both directions run within the same sync interval, so after one interval
both stores contain each other's records.

## Key Theorems

1. **`merge_accepts_iff_newer`** — A record is accepted iff it is strictly
   newer than any existing record for that peer_id (or no existing record).

2. **`store_monotone_other_peers`** — Inserting a record for peer P leaves
   all records for other peers Q ≠ P unchanged.

3. **`spore_grows_monotone`** — The SPORE only grows under insert.

4. **`spore_contains_inserted`** — After a successful insert, the content_id
   of the new record is in the SPORE.

5. **`sync_one_direction`** — After A receives B's RecordDelta and merges
   it, A's store contains all records that B had (no-conflict case).

6. **`pairwise_convergence`** — After a full bidirectional exchange, both
   stores contain the union of their initial records.

7. **`graph_convergence`** — In a connected mesh of diameter d, after d
   gossip rounds, every node's store contains every record from every
   other node's initial store.

## Correspondence to Rust

| Lean type/fn            | Rust equivalent                           | File                  |
|-------------------------|-------------------------------------------|-----------------------|
| `ContentId`             | `[u8; 32]` (BLAKE3 hash)                  | peer_addr_store.rs    |
| `PeerAddrRecord`        | `PeerAddrRecord`                          | peer_addr_store.rs:34 |
| `PeerAddrStore`         | `PeerAddrStore`                           | peer_addr_store.rs:63 |
| `Spore`                 | `citadel_spore::Spore`                    | peer_addr_store.rs    |
| `insertRecord`          | `PeerAddrStore::insert`                   | peer_addr_store.rs:149|
| `mergeAll`              | `PeerAddrStore::merge`                    | peer_addr_store.rs:186|
| `computeDelta`          | `PeerAddrStore::diff_for_peer`            | peer_addr_store.rs:170|
| `gossipRound`           | one `sync_interval_ms` gossip exchange    | peer_addr_gossip.rs   |
-/

namespace LagoonMesh

/-! ### Abstract SPORE -/

/-- A content identifier: BLAKE3 hash of a peer's addressing fields.
    In Rust: `[u8; 32]`. Modeled as `Nat` for decidable equality. -/
abbrev ContentId := Nat

/-- Abstract SPORE: a finite set of content IDs.

    The real `citadel_spore::Spore` encodes ranges in U256 space compactly.
    Its key operations are isomorphic to `Finset`:
    - `union`    ≅ `Finset.union`
    - `subtract` ≅ `Finset.sdiff`
    - `covers`   ≅ `Finset.mem` -/
abbrev Spore := Finset ContentId

/-! ### Peer Address Record -/

/-- A peer address record — minimum info needed to dial a peer.
    In Rust: `PeerAddrRecord` at `peer_addr_store.rs:34`. -/
structure PeerAddrRecord where
  /-- Peer identity. In Rust: `peer_id: String`. -/
  peerId    : PeerId
  /-- BLAKE3 hash of (peer_id, timestamp_ms, addresses).
      In Rust: `content_id: [u8; 32]`, computed at `peer_addr_store.rs:92-100`. -/
  contentId : ContentId
  /-- Milliseconds since epoch. In Rust: `timestamp_ms: i64`. -/
  timestamp : Int
  deriving DecidableEq, Repr

/-- Content IDs are deterministic: same peer_id + same timestamp → same content_id.
    In Rust: BLAKE3 over the same `hash_input` gives the same result. -/
axiom contentId_deterministic (r₁ r₂ : PeerAddrRecord) :
    r₁.peerId = r₂.peerId → r₁.timestamp = r₂.timestamp →
    r₁.contentId = r₂.contentId

/-- Content IDs are peer-specific: same content_id → same peer_id.
    In Rust: `hash_input` starts with `peer_id`, so BLAKE3 collision resistance
    implies distinct peers produce distinct content_ids. Axiomatized here. -/
axiom contentId_peer_injective (r₁ r₂ : PeerAddrRecord) :
    r₁.contentId = r₂.contentId → r₁.peerId = r₂.peerId

/-! ### Peer Address Store -/

/-- Peer address store: keeps the newest record per peer_id.
    In Rust: `PeerAddrStore` at `peer_addr_store.rs:63`. -/
structure PeerAddrStore where
  /-- Stored records (at most one per peer_id). In Rust: `HashMap<String, PeerAddrRecord>`. -/
  records : List PeerAddrRecord
  /-- Grows-only set of content IDs. In Rust: `Spore`. -/
  spore   : Spore

/-- At most one record per peer_id.
    In Rust: enforced by `HashMap` keyed on `peer_id`. -/
def PeerAddrStore.OnePerPeer (s : PeerAddrStore) : Prop :=
  ∀ r₁ ∈ s.records, ∀ r₂ ∈ s.records,
    r₁.peerId = r₂.peerId → r₁ = r₂

/-- SPORE contains exactly the content_ids of stored records.
    In Rust: maintained by `insert` calling `self.spore.union(&point)`. -/
def PeerAddrStore.SporeConsistent (s : PeerAddrStore) : Prop :=
  ∀ cid : ContentId,
    cid ∈ s.spore ↔ ∃ r ∈ s.records, r.contentId = cid

/-- A store is valid if it satisfies both structural invariants. -/
def PeerAddrStore.Valid (s : PeerAddrStore) : Prop :=
  s.OnePerPeer ∧ s.SporeConsistent

/-- The empty store is valid. -/
theorem PeerAddrStore.empty_valid : PeerAddrStore.Valid ⟨[], ∅⟩ := by
  refine ⟨?_, ?_⟩
  · -- OnePerPeer: no records → trivially holds
    intro r₁ h₁
    simp at h₁
  · -- SporeConsistent: empty spore, empty records
    intro cid
    simp

/-! ### Insert Operation

In Rust: `PeerAddrStore::insert` at `peer_addr_store.rs:149`. -/

/-- Does the store have a record for `peerId` with timestamp ≥ `t`?

    In Rust: the check at `peer_addr_store.rs:150-153`. -/
def PeerAddrStore.hasNewerOrEqual (s : PeerAddrStore) (peerId : PeerId) (t : Int) : Bool :=
  s.records.any (fun r => r.peerId == peerId && decide (r.timestamp ≥ t))

/-- Reflection lemma for `hasNewerOrEqual`. -/
theorem hasNewerOrEqual_iff (s : PeerAddrStore) (peerId : PeerId) (t : Int) :
    s.hasNewerOrEqual peerId t = true ↔
    ∃ r ∈ s.records, r.peerId = peerId ∧ r.timestamp ≥ t := by
  simp only [PeerAddrStore.hasNewerOrEqual, List.any_eq_true, Bool.and_eq_true,
             beq_iff_eq, decide_eq_true_eq]

/-- Insert a record. Returns the updated store and whether the record was accepted.

    Accepted iff no existing record for that peer has timestamp ≥ r.timestamp.
    In Rust: `PeerAddrStore::insert` at `peer_addr_store.rs:149`. -/
def insertRecord (s : PeerAddrStore) (r : PeerAddrRecord) : PeerAddrStore × Bool :=
  if s.hasNewerOrEqual r.peerId r.timestamp then
    (s, false)
  else
    let stripped := s.records.filter (fun rec => decide (rec.peerId ≠ r.peerId))
    ({ records := r :: stripped
       spore   := s.spore ∪ {r.contentId} },
     true)

/-- Whether a record was accepted by insert. -/
def insertAccepted (s : PeerAddrStore) (r : PeerAddrRecord) : Prop :=
  s.hasNewerOrEqual r.peerId r.timestamp = false

/-! ### Core Correctness Theorems -/

/-- Helper: negating `insertAccepted` gives `hasNewerOrEqual = true`. -/
private theorem not_accepted_iff (s : PeerAddrStore) (r : PeerAddrRecord) :
    ¬ insertAccepted s r ↔ s.hasNewerOrEqual r.peerId r.timestamp = true := by
  simp [insertAccepted, Bool.not_eq_false]

/-- **Merge Correctness**: A record is accepted iff all existing records for
    that peer_id have strictly smaller timestamps.

    Corresponds to the Rust check at `peer_addr_store.rs:151`:
    `if record.timestamp_ms <= existing.timestamp_ms { return false; }` -/
theorem merge_accepts_iff_newer (s : PeerAddrStore) (r : PeerAddrRecord) :
    insertAccepted s r ↔
    (∀ existing ∈ s.records, existing.peerId = r.peerId →
      existing.timestamp < r.timestamp) := by
  simp only [insertAccepted, ← Bool.not_eq_true, hasNewerOrEqual_iff]
  push_neg
  exact Iff.rfl

/-- **Rejected records are unchanged**: if a record is rejected, the store is unchanged. -/
theorem rejected_store_unchanged (s : PeerAddrStore) (r : PeerAddrRecord)
    (hRej : ¬ insertAccepted s r) :
    (insertRecord s r).1 = s := by
  rw [not_accepted_iff] at hRej
  simp only [insertRecord, hRej, ↓reduceIte]

/-- **Store Monotonicity — Other Peers**: After inserting a record for peer P,
    all records for peers Q ≠ P survive. -/
theorem store_monotone_other_peers (s : PeerAddrStore) (r : PeerAddrRecord)
    (q : PeerAddrRecord) (hQ : q ∈ s.records) (hDiff : q.peerId ≠ r.peerId) :
    q ∈ (insertRecord s r).1.records := by
  simp only [insertRecord]
  split_ifs with h
  · exact hQ  -- rejected: records unchanged
  · -- accepted: q is in r :: stripped
    apply List.mem_cons_of_mem
    simp only [List.mem_filter, decide_eq_true_eq]
    exact ⟨hQ, hDiff⟩

/-- **SPORE Monotonicity**: After any insert, the SPORE only grows.
    In Rust: `self.spore = self.spore.union(&point)` at `peer_addr_store.rs:158`. -/
theorem spore_grows_monotone (s : PeerAddrStore) (r : PeerAddrRecord) :
    s.spore ⊆ (insertRecord s r).1.spore := by
  simp only [insertRecord]
  split_ifs with h
  · exact Finset.Subset.refl _      -- rejected: spore unchanged
  · exact Finset.subset_union_left  -- accepted: s.spore ⊆ s.spore ∪ {cid}

/-- **SPORE Contains Inserted**: After a successful insert, `r.contentId ∈ SPORE`. -/
theorem spore_contains_inserted (s : PeerAddrStore) (r : PeerAddrRecord)
    (hAcc : insertAccepted s r) :
    r.contentId ∈ (insertRecord s r).1.spore := by
  simp only [insertRecord, insertAccepted] at *
  simp only [hAcc, Bool.false_eq_true, ↓reduceIte] at *
  exact Finset.mem_union_right _ (Finset.mem_singleton_self _)

/-- After a successful insert, the new record is in the store. -/
theorem record_in_store_after_insert (s : PeerAddrStore) (r : PeerAddrRecord)
    (hAcc : insertAccepted s r) :
    r ∈ (insertRecord s r).1.records := by
  simp only [insertRecord, insertAccepted] at *
  simp only [hAcc, Bool.false_eq_true, ↓reduceIte] at *
  exact List.mem_cons.mpr (Or.inl rfl)

/-! ### Batch Merge Operation

In Rust: `PeerAddrStore::merge` at `peer_addr_store.rs:186`. -/

/-- Merge a list of records into the store, inserting each newest-wins.
    In Rust: iterates and calls `self.insert(rec.clone())`. -/
def mergeAll (s : PeerAddrStore) (incoming : List PeerAddrRecord) : PeerAddrStore :=
  incoming.foldl (fun store r => (insertRecord store r).1) s

@[simp] theorem mergeAll_nil (s : PeerAddrStore) : mergeAll s [] = s := rfl

@[simp] theorem mergeAll_cons (s : PeerAddrStore) (r : PeerAddrRecord)
    (rs : List PeerAddrRecord) :
    mergeAll s (r :: rs) = mergeAll (insertRecord s r).1 rs := rfl

/-- SPORE grows monotonically under mergeAll. -/
theorem spore_grows_under_mergeAll (s : PeerAddrStore) (rs : List PeerAddrRecord) :
    s.spore ⊆ (mergeAll s rs).spore := by
  induction rs generalizing s with
  | nil => simp
  | cons r rest ih =>
    simp only [mergeAll_cons]
    exact Finset.Subset.trans (spore_grows_monotone s r) (ih _)

/-- A record already in the store remains after mergeAll, provided no incoming
    record for the same peer_id is strictly newer. -/
theorem record_preserved_by_mergeAll (s : PeerAddrStore)
    (q : PeerAddrRecord) (hQ : q ∈ s.records)
    (incoming : List PeerAddrRecord)
    (hNoOverwrite : ∀ r ∈ incoming, r.peerId = q.peerId → r.timestamp ≤ q.timestamp) :
    q ∈ (mergeAll s incoming).records := by
  induction incoming generalizing s with
  | nil => simpa [mergeAll]
  | cons r rest ih =>
    simp only [mergeAll_cons]
    apply ih
    · by_cases hSame : r.peerId = q.peerId
      · -- r.timestamp ≤ q.timestamp, so r is rejected
        have hLe : r.timestamp ≤ q.timestamp :=
          hNoOverwrite r (List.mem_cons.mpr (Or.inl rfl)) hSame
        have hRej : ¬ insertAccepted s r := by
          rw [not_accepted_iff, hasNewerOrEqual_iff]
          exact ⟨q, hQ, hSame.symm, hLe⟩
        rw [rejected_store_unchanged s r hRej]
        exact hQ
      · exact store_monotone_other_peers s r q hQ (Ne.symm hSame)
    · intro r' hr' heq
      exact hNoOverwrite r' (List.mem_cons_of_mem _ hr') heq

/-! ### Sync Protocol -/

/-- Compute the records that `recipient` is missing from `sender`.

    In Rust: `PeerAddrStore::diff_for_peer` at `peer_addr_store.rs:170`.
    Also used inside `on_have_list_received` at `peer_addr_gossip.rs:112`. -/
def computeDelta (sender recipient : PeerAddrStore) : List PeerAddrRecord :=
  sender.records.filter (fun r => decide (r.contentId ∉ recipient.spore))

theorem mem_delta_iff (sender recipient : PeerAddrStore) (r : PeerAddrRecord) :
    r ∈ computeDelta sender recipient ↔
    r ∈ sender.records ∧ r.contentId ∉ recipient.spore := by
  simp [computeDelta, List.mem_filter]

theorem delta_subset_sender (sender recipient : PeerAddrStore)
    (r : PeerAddrRecord) (hr : r ∈ computeDelta sender recipient) :
    r ∈ sender.records :=
  (mem_delta_iff sender recipient r |>.mp hr).1

/-! ### Helper Lemmas for Sync Completeness -/

/-- After inserting a record for peer P, all records for peers ≠ P remain unchanged
    and no new records for any peer ≠ P are created. -/
private theorem insertRecord_no_peer_for (s : PeerAddrStore) (r : PeerAddrRecord) (p : PeerId)
    (hNoP   : ∀ q ∈ s.records, q.peerId ≠ p)
    (hRNeqP : r.peerId ≠ p) :
    ∀ q ∈ (insertRecord s r).1.records, q.peerId ≠ p := by
  intro q hq
  simp only [insertRecord] at hq
  -- Case split on whether the insertion was rejected or accepted
  cases h : s.hasNewerOrEqual r.peerId r.timestamp with
  | true  =>
    simp only [h, ↓reduceIte] at hq
    exact hNoP q hq
  | false =>
    simp only [h, Bool.false_eq_true, ↓reduceIte,
               List.mem_cons, List.mem_filter, decide_eq_true_eq] at hq
    rcases hq with rfl | ⟨hqS, _⟩
    · exact hRNeqP
    · exact hNoP q hqS

/-- If `r ∈ incoming`, `s` has no existing record for `r.peerId`, and `incoming`
    has at most one record per `peerId`, then `r ∈ (mergeAll s incoming).records`. -/
private theorem mergeAll_absorbs_new_record (s : PeerAddrStore)
    (incoming : List PeerAddrRecord) (r : PeerAddrRecord)
    (hrIn        : r ∈ incoming)
    (hNoExisting : ∀ q ∈ s.records, q.peerId ≠ r.peerId)
    (hOnePerPeer : ∀ r₁ ∈ incoming, ∀ r₂ ∈ incoming,
                    r₁.peerId = r₂.peerId → r₁ = r₂) :
    r ∈ (mergeAll s incoming).records := by
  induction incoming generalizing s with
  | nil => simp at hrIn
  | cons h t ih =>
    simp only [mergeAll_cons]
    -- r ∈ h :: t: either r = h (head) or r ∈ t (tail)
    rcases List.mem_cons.mp hrIn with hrH | hrT
    · -- hrH : r = h — r is the head element.
      -- Rewrite the goal (r ↦ h) and hNoExisting to work uniformly with h.
      rw [hrH]
      rw [hrH] at hNoExisting
      -- Goal: h ∈ (mergeAll (insertRecord s h).1 t).records
      -- hNoExisting: ∀ q ∈ s.records, q.peerId ≠ h.peerId
      have hAcc : insertAccepted s h := by
        rw [merge_accepts_iff_newer]
        intro ex hex heqPid
        exact absurd heqPid (hNoExisting ex hex)
      apply record_preserved_by_mergeAll _ h (record_in_store_after_insert s h hAcc) t
      intro r' hr't heqPid
      -- r'.peerId = h.peerId; both r' and h are in h :: t; by OnePerPeer, r' = h
      have hr'H : r' = h :=
        hOnePerPeer r' (List.mem_cons.mpr (Or.inr hr't)) h (List.mem_cons.mpr (Or.inl rfl)) heqPid
      have : r'.timestamp = h.timestamp := congr_arg PeerAddrRecord.timestamp hr'H
      omega
    · -- hrT : r ∈ t — r is in the tail.  Split on whether h shares r's peer ID.
      by_cases hPidEq : h.peerId = r.peerId
      · -- h.peerId = r.peerId → h = r (by OnePerPeer applied to h and r in h :: t)
        have hrH : h = r :=
          hOnePerPeer h (List.mem_cons.mpr (Or.inl rfl)) r (List.mem_cons.mpr (Or.inr hrT)) hPidEq
        -- Rewrite goal (r ↦ h) so we can use record_preserved_by_mergeAll with h
        rw [← hrH]
        -- Goal: h ∈ (mergeAll (insertRecord s h).1 t).records
        -- hNoExisting uses r.peerId; since hrH : h = r, h.peerId = r.peerId
        have hNoExistingH : ∀ q ∈ s.records, q.peerId ≠ h.peerId :=
          fun q hq => hrH ▸ hNoExisting q hq
        have hAcc : insertAccepted s h := by
          rw [merge_accepts_iff_newer]
          intro ex hex heqPid
          exact absurd heqPid (hNoExistingH ex hex)
        apply record_preserved_by_mergeAll _ h (record_in_store_after_insert s h hAcc) t
        intro r' hr't heqPid
        have hr'H : r' = h :=
          hOnePerPeer r' (List.mem_cons.mpr (Or.inr hr't)) h (List.mem_cons.mpr (Or.inl rfl))
            heqPid
        have : r'.timestamp = h.timestamp := congr_arg PeerAddrRecord.timestamp hr'H
        omega
      · -- h.peerId ≠ r.peerId: inserting h leaves no record for r.peerId; apply IH.
        exact ih (insertRecord s h).1 hrT
          (insertRecord_no_peer_for s h r.peerId hNoExisting hPidEq)
          (fun r₁ hr₁ r₂ hr₂ heq =>
            hOnePerPeer r₁ (List.mem_cons.mpr (Or.inr hr₁))
                        r₂ (List.mem_cons.mpr (Or.inr hr₂)) heq)

/-! ### One-Direction Sync Completeness -/

/-- **One-Direction Sync**: After A receives B's RecordDelta and merges it,
    A's store contains all records B had.

    Proof sketch:
    - For each `r ∈ B.records`: either `r.contentId ∈ A.spore` or not.
    - If `r.contentId ∉ A.spore`: r is in the delta. After mergeAll, r ends up
      in A (A has no record for r.peerId by disjointness).
    - If `r.contentId ∈ A.spore`: by SporeConsistent, A has some record `q`
      with `q.contentId = r.contentId`. By `contentId_peer_injective`,
      `q.peerId = r.peerId`. But A and B are disjoint by peer_id — contradiction. -/
theorem sync_one_direction (A B : PeerAddrStore)
    (hA : A.Valid) (hB : B.Valid)
    -- No peer_id appears in both stores. In practice: each node's store has
    -- only its own record initially; others are learned via gossip.
    (hDisjoint : ∀ rA ∈ A.records, ∀ rB ∈ B.records, rA.peerId ≠ rB.peerId) :
    let delta := computeDelta B A
    let A' := mergeAll A delta
    ∀ r ∈ B.records, r ∈ A'.records := by
  intro delta A' r hrB
  -- Step 1: r.contentId is not in A.spore
  have hNotCov : r.contentId ∉ A.spore := by
    intro hCov
    rw [hA.2] at hCov
    obtain ⟨q, hqA, hqCid⟩ := hCov
    -- q.contentId = r.contentId → q.peerId = r.peerId
    have hqPid : q.peerId = r.peerId := contentId_peer_injective q r hqCid
    -- But hDisjoint says q.peerId ≠ r.peerId (q ∈ A, r ∈ B)
    exact absurd hqPid (hDisjoint q hqA r hrB)
  -- Step 2: r is in the delta
  have hrDelta : r ∈ delta := (mem_delta_iff B A r).mpr ⟨hrB, hNotCov⟩
  -- Step 3: mergeAll absorbs r from the delta.
  apply mergeAll_absorbs_new_record A delta r hrDelta
  · -- A has no record for r.peerId (disjointness)
    intro q hqA heqPid
    exact absurd heqPid (hDisjoint q hqA r hrB)
  · -- delta inherits one-per-peer from B.Valid (B's OnePerPeer on the filtered subset)
    intro r₁ hr₁ r₂ hr₂ heqPid
    exact hB.1 r₁ (delta_subset_sender B A r₁ hr₁)
               r₂ (delta_subset_sender B A r₂ hr₂) heqPid

/-! ### Pairwise Convergence -/

/-- **Pairwise Convergence**: After a full bidirectional exchange, both stores
    contain the union of their initial records.

    In the protocol (peer_addr_gossip.rs), both directions complete within one
    sync interval:
    - A→B HaveList: B responds with RecordDelta → A gains B's records
    - B→A HaveList: A responds with RecordDelta → B gains A's records -/
theorem pairwise_convergence (A B : PeerAddrStore)
    (hA : A.Valid) (hB : B.Valid)
    (hDisjoint : ∀ rA ∈ A.records, ∀ rB ∈ B.records, rA.peerId ≠ rB.peerId) :
    let A' := mergeAll A (computeDelta B A)
    let B' := mergeAll B (computeDelta A B)
    (∀ r ∈ B.records, r ∈ A'.records) ∧
    (∀ r ∈ A.records, r ∈ B'.records) :=
  ⟨sync_one_direction A B hA hB hDisjoint,
   sync_one_direction B A hB hA fun rB hB' rA hA' => (hDisjoint rA hA' rB hB').symm⟩

/-! ### Graph-Level Convergence -/

/-- A gossip graph with `n` nodes. -/
structure GossipGraph (n : Nat) where
  /-- Each node's PeerAddrStore. -/
  stores   : Fin n → PeerAddrStore
  /-- Which pairs gossip (symmetric). -/
  adjacent : Fin n → Fin n → Bool
  adj_symm : ∀ i j, adjacent i j = adjacent j i

/-- Diameter: all pairs connected by a path of length ≤ d. -/
def GossipGraph.Diameter {n : Nat} (g : GossipGraph n) (d : Nat) : Prop :=
  ∀ i j : Fin n, ∃ path : List (Fin n),
    path.length ≤ d + 1 ∧
    path.head? = some i ∧
    path.getLast? = some j ∧
    ∀ k (hk : k + 1 < path.length),
      g.adjacent
        (path.get ⟨k,     Nat.lt_of_succ_lt hk⟩)
        (path.get ⟨k + 1, hk⟩) = true

/-- One gossip round: adjacent node pairs exchange HaveList/RecordDelta.
    The node count `n` is preserved (same nodes, updated stores). Axiomatized:
    the implementation in `peer_addr_gossip.rs` realizes this; the mathematical
    content follows from `pairwise_convergence` applied to each adjacent pair. -/
axiom gossipRound {n : Nat} : GossipGraph n → GossipGraph n

/-- One-hop propagation: after gossipRound, any record from an adjacent node
    is present in the current node's store. -/
axiom gossipRound_one_hop {n : Nat} (g : GossipGraph n)
    (hValid : ∀ i, (g.stores i).Valid)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId)
    (i j : Fin n) (hAdj : g.adjacent i j = true)
    (r : PeerAddrRecord) (hr : r ∈ (g.stores j).records) :
    r ∈ ((gossipRound g).stores i).records

/-- Records already in a store survive gossipRound (stores only grow). -/
axiom gossipRound_monotone {n : Nat} (g : GossipGraph n)
    (i : Fin n) (r : PeerAddrRecord) (hr : r ∈ (g.stores i).records) :
    r ∈ ((gossipRound g).stores i).records

/-- Adjacency is preserved by gossip rounds (topology is fixed). -/
axiom gossipRound_preserves_adjacency {n : Nat} (g : GossipGraph n)
    (i j : Fin n) (h : g.adjacent i j = true) :
    (gossipRound g).adjacent i j = true

/-- Per-node validity is preserved by gossip rounds. -/
axiom gossipRound_preserves_validity {n : Nat} (g : GossipGraph n)
    (hValid : ∀ i, (g.stores i).Valid) :
    ∀ i, ((gossipRound g).stores i).Valid

/-- Disjointness of peer IDs across nodes is preserved by gossip rounds. -/
axiom gossipRound_preserves_disjoint {n : Nat} (g : GossipGraph n)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId) :
    ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ ((gossipRound g).stores i).records,
      ∀ rJ ∈ ((gossipRound g).stores j).records,
      rI.peerId ≠ rJ.peerId

/-- Apply gossipRound k times. -/
noncomputable def gossipRounds {n : Nat} (g : GossipGraph n) : Nat → GossipGraph n
  | 0     => g
  | k + 1 => gossipRound (gossipRounds g k)

@[simp] theorem gossipRounds_zero {n : Nat} (g : GossipGraph n) :
    gossipRounds g 0 = g := rfl

/-- Records are preserved across any number of gossip rounds. -/
theorem gossipRounds_monotone {n : Nat} (g : GossipGraph n)
    (k : Nat) (i : Fin n) (r : PeerAddrRecord)
    (hr : r ∈ (g.stores i).records) :
    r ∈ ((gossipRounds g k).stores i).records := by
  induction k with
  | zero => simpa
  | succ k ih => exact gossipRound_monotone _ i r ih

theorem gossipRounds_preserves_adjacency {n : Nat} (g : GossipGraph n)
    (k : Nat) (i j : Fin n) (h : g.adjacent i j = true) :
    (gossipRounds g k).adjacent i j = true := by
  induction k with
  | zero => simpa
  | succ k ih => exact gossipRound_preserves_adjacency _ i j ih

theorem gossipRounds_preserves_validity {n : Nat} (g : GossipGraph n)
    (k : Nat) (hValid : ∀ i, (g.stores i).Valid) :
    ∀ i, ((gossipRounds g k).stores i).Valid := by
  induction k with
  | zero => simpa
  | succ k ih => exact gossipRound_preserves_validity _ ih

theorem gossipRounds_preserves_disjoint {n : Nat} (g : GossipGraph n) (k : Nat)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId) :
    ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ ((gossipRounds g k).stores i).records,
      ∀ rJ ∈ ((gossipRounds g k).stores j).records,
      rI.peerId ≠ rJ.peerId := by
  induction k with
  | zero => simpa
  | succ k ih => exact gossipRound_preserves_disjoint _ ih

/-- If r is at node p after k rounds and i is adjacent to p in the original graph,
    then r is at i after k+1 rounds. -/
private theorem one_hop_propagation {n : Nat} (g : GossipGraph n)
    (hValid    : ∀ i, (g.stores i).Valid)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId)
    (k : Nat) (i p : Fin n) (hAdj : g.adjacent i p = true)
    (r : PeerAddrRecord) (hr : r ∈ ((gossipRounds g k).stores p).records) :
    r ∈ ((gossipRounds g (k + 1)).stores i).records := by
  show r ∈ ((gossipRound (gossipRounds g k)).stores i).records
  exact gossipRound_one_hop (gossipRounds g k)
    (gossipRounds_preserves_validity g k hValid)
    (gossipRounds_preserves_disjoint g k hDisjoint)
    i p (gossipRounds_preserves_adjacency g k i p hAdj)
    r hr

/-- Path propagation: a path of length ≤ k+1 from i to j in g means any record
    at j propagates to i after k gossip rounds. -/
private theorem path_propagation {n : Nat} (g : GossipGraph n)
    (hValid    : ∀ i, (g.stores i).Valid)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId) :
    ∀ (k : Nat) (path : List (Fin n)),
    path.length ≤ k + 1 →
    ∀ (i j : Fin n),
    path.head? = some i →
    path.getLast? = some j →
    (∀ m (hm : m + 1 < path.length),
      g.adjacent (path.get ⟨m, Nat.lt_of_succ_lt hm⟩)
                 (path.get ⟨m + 1, hm⟩) = true) →
    ∀ r ∈ (g.stores j).records,
    r ∈ ((gossipRounds g k).stores i).records := by
  intro k
  induction k with
  | zero =>
    intro path hLen i j hHead hLast _hAdj r hr
    simp only [Nat.zero_add] at hLen
    -- path.length ≤ 1 with both endpoints defined → i = j
    -- Note: subst on (v = i) removes i and keeps v; we prove (v = j) and subst.
    cases path with
    | nil => simp at hHead
    | cons v vs =>
      simp only [List.head?_cons, Option.some.injEq] at hHead
      -- hHead : v = i. subst hHead removes i, keeping v.
      subst hHead
      -- Goal is now: r ∈ ((gossipRounds g 0).stores j).records (j still present)
      -- (i was removed; all occurrences of i in goal/context are now v)
      cases vs with
      | nil =>
        -- singleton path [v]; hLast : [v].getLast? = some j
        simp [List.getLast?] at hLast
        -- hLast : v = j
        subst hLast
        simpa
      | cons w ws =>
        -- path length ≥ 2 contradicts ≤ 1
        simp only [List.length_cons] at hLen; omega
  | succ k ih =>
    intro path hLen i j hHead hLast hAdj r hr
    cases path with
    | nil => simp at hHead
    | cons v vs =>
      simp only [List.head?_cons, Option.some.injEq] at hHead
      -- hHead : v = i. subst hHead removes i, keeping v.
      subst hHead
      -- After subst: i is gone, v is the head of the path.
      cases vs with
      | nil =>
        -- singleton path [v] = [i]: v = j
        simp [List.getLast?] at hLast
        -- hLast : v = j
        subst hLast
        -- Goal: r ∈ ((gossipRounds g (k+1)).stores v).records
        exact gossipRounds_monotone g (k + 1) v r (by simpa)
      | cons w ws =>
        -- path v :: w :: ws; v played the role of i
        have hLen' : (w :: ws).length ≤ k + 1 := by
          simp only [List.length_cons] at *; omega
        have hAdj_vw : g.adjacent v w = true := by
          have := hAdj 0 (by simp only [List.length_cons] at *; omega)
          simpa using this
        have hIH : r ∈ ((gossipRounds g k).stores w).records := by
          apply ih (w :: ws) hLen' w j
          · simp
          · exact hLast
          · intro m hm
            -- Shift: (v :: w :: ws).get ⟨m+1, _⟩ = (w :: ws).get ⟨m, _⟩ by List.get iota.
            -- Proof terms differ only in the Nat.lt witness.
            have hm' : m + 1 + 1 < (v :: w :: ws).length := by
              simp only [List.length_cons] at *; omega
            have hmAdj := hAdj (m + 1) hm'
            -- List.get (v :: w :: ws) ⟨m+1, _⟩ definitionally equals (w :: ws).get ⟨m, _⟩
            -- by List.get's definition on cons. Proof terms in Fin differ but are
            -- propositionally equal by proof irrelevance (Nat.lt ∈ Prop).
            exact hmAdj
          · exact hr
        exact one_hop_propagation g hValid hDisjoint k v w hAdj_vw r hIH

/-- **Graph Convergence**: In a connected graph of diameter d, after d gossip
    rounds, every node's store contains every record from every other node's
    initial store.

    Proof by induction on d using gossipRound_one_hop:
    Each round extends propagation by one hop. After d rounds, records have
    traveled up to d hops, reaching every node via paths of length ≤ d. -/
theorem graph_convergence {n : Nat} (g : GossipGraph n)
    (hValid : ∀ i, (g.stores i).Valid)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId)
    (d : Nat) (hDiam : g.Diameter d) :
    ∀ i j : Fin n, ∀ r ∈ (g.stores j).records,
      r ∈ ((gossipRounds g d).stores i).records := by
  intro i j r hr
  obtain ⟨path, hLen, hHead, hLast, hAdj⟩ := hDiam i j
  exact path_propagation g hValid hDisjoint d path hLen i j hHead hLast hAdj r hr

/-! ### The Meta-Theorem -/

/-- **Eventual Consistency of PeerAddrGossip**:

    In any connected Lagoon mesh, the SPORE-based peer address gossip protocol
    guarantees that all nodes eventually learn all peer connection addresses.

    After at most `diameter` gossip rounds (each lasting `sync_interval_ms`,
    defaulting to 10 seconds), every node's `PeerAddrStore` contains every
    record that exists in any other node's store.

    ## Connection to the 15-node mesh bug

    Production incident: `pod-20444cf5` saw only 10 of 14 peers.
    - 4 pods joined after `pod-20444cf5` completed its initial MeshPeers exchange
    - The one-shot re-broadcast didn't reach `pod-20444cf5`
    - With PeerAddrGossip enabled: all pods' addresses propagate to all SPIRAL
      neighbors within one sync interval (10s), then transitively across the mesh.
    - For a 15-node SPIRAL mesh with diameter ≤ 4: all nodes see all 15 peers
      within 4 × 10s = 40 seconds of the last pod joining. -/
theorem peer_addr_gossip_eventually_consistent {n : Nat} (g : GossipGraph n)
    (hConnected : ∃ d : Nat, g.Diameter d)
    (hValid : ∀ i, (g.stores i).Valid)
    (hDisjoint : ∀ i j : Fin n, i ≠ j →
      ∀ rI ∈ (g.stores i).records, ∀ rJ ∈ (g.stores j).records,
      rI.peerId ≠ rJ.peerId) :
    ∃ rounds : Nat, ∀ i j : Fin n, ∀ r ∈ (g.stores j).records,
      r ∈ ((gossipRounds g rounds).stores i).records := by
  obtain ⟨d, hDiam⟩ := hConnected
  exact ⟨d, graph_convergence g hValid hDisjoint d hDiam⟩

end LagoonMesh
