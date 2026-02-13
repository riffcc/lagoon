# SUPERSEDED — See FUNGIBLE_VDF_PAPER.md

This implementation reference has been merged into the unified Fungible
VDF paper at `docs/FUNGIBLE_VDF_PAPER.md`. Crate structure, wire
protocol, and deployment details are now in Section 14.

---

# Fungible VDF: Proof of Elapsed Time for Lagoon (ARCHIVED)

This document describes the Verifiable Delay Function (VDF) system that underpins
liveness detection, ghost node pruning, and split-brain resolution in Lagoon's
decentralized mesh. The VDF is the heartbeat of the network -- a cryptographic
pulse that proves a node is alive and computing, without requiring synchronized
clocks, heartbeat protocols, or trusted authorities.

---

## Table of Contents

1. [Core Concept: VDF as Proof of Elapsed Time](#core-concept-vdf-as-proof-of-elapsed-time)
2. [Liveness via ZK Proofs](#liveness-via-zk-proofs)
3. [Ghost Node Pruning](#ghost-node-pruning)
4. [Fungibility and Split-Brain Resolution](#fungibility-and-split-brain-resolution)
5. [Merge Protocol](#merge-protocol)
6. [ZK Proof Structure](#zk-proof-structure)
7. [Lean 4 Proofs](#lean-4-proofs)
8. [Implementation Reference](#implementation-reference)
9. [Current Status](#current-status)

---

## Core Concept: VDF as Proof of Elapsed Time

Each Lagoon node runs an independent Blake3 VDF chain, ticking at 10 Hz (one
hash step every 100ms). The chain is sequential and non-parallelizable: each
step `h_{i+1} = Blake3(h_i)` depends on the output of the previous step.
You cannot skip ahead. You cannot precompute. You can only grind through the
chain one tick at a time.

**Genesis derivation.** The genesis hash of a node's VDF chain is
deterministically derived from its Ed25519 public key using a domain-separated
Blake3 hash:

```
genesis = Blake3("lagoon-vdf-genesis-v1" || public_key)
```

This means anyone who knows a node's public key can independently compute the
expected genesis for that node's chain. There is no secret. There is no seed
ceremony. The chain is deterministic from identity.

**This is NOT proof of work.** A CDN pod saturated with traffic and an idle
standby node both produce the same VDF evidence: "I have been alive and
computing for this long." The VDF does not measure useful work. It measures
elapsed computation time. A high-powered GPU cannot compute it faster than a
Raspberry Pi (Blake3 is sequential -- the bottleneck is latency, not
throughput).

**The work is fungible.** One VDF chain proves liveness regardless of what else
the node is doing. A relay node, a web gateway, a federation bridge, an
embedded server -- they all tick the same chain, and that chain is the only
proof of life the network needs. There is no separate liveness protocol,
no keepalive timer, no "last seen" timestamp.

One chain. One proof. All roles.

---

## Liveness via ZK Proofs

Liveness is not determined by timers. It is determined by cryptographic proof
of recent VDF work.

The mechanism is a zero-knowledge proof system built on Fiat-Shamir challenges
over a Merkle commitment of the VDF chain. When peer A wants to know if peer B
is still alive, it sends a `MESH VDFPROOF_REQ` message. Peer B responds with a
`MESH VDFPROOF` containing a compact ZK proof of its current chain state.

The key invariant: **if a peer can present a valid proof with more steps than
last time, it is alive. If it cannot, it is dead.**

There is no TTL. There is no "last_seen" timestamp that requires synchronized
clocks. There is no heartbeat protocol that a partitioned node might fail to
deliver. The VDF chain is the proof of life, and it is cryptographically
unforgeable. You cannot fake having computed steps you have not computed. The
sequential nature of Blake3 chaining guarantees this.

What this buys us:

- **No clock synchronization.** Nodes do not need to agree on wall-clock time.
  The VDF chain IS the clock.
- **No heartbeat protocol.** No periodic messages that create traffic and fail
  under partition. Proof is on-demand.
- **No TTL timers.** No arbitrary "if we haven't heard from X in 30 seconds,
  assume dead" heuristics.
- **Unforgeable.** A stopped node cannot resume and claim to have been alive.
  The chain gap is cryptographic evidence of downtime.

---

## Ghost Node Pruning

A ghost node is a node that holds a SPIRAL slot but has stopped computing its
VDF. This happens naturally -- pods terminate, servers crash, network links
fail. In a dynamic mesh with ephemeral CDN pods spinning up and down, ghost
nodes are not an edge case. They are the steady state.

The pruning protocol is straightforward:

1. A node is suspected of being a ghost (its reported VDF step has not advanced).
2. A peer challenges it with `MESH VDFPROOF_REQ`.
3. The ghost either:
   - **Cannot respond** (because it is actually dead), or
   - **Presents a stale proof** (same step count as its last known state).
4. In either case, the ghost is pruned: its SPIRAL slot is freed, its peer_id
   is removed, and the topology recomputes.
5. A new node claims the freed slot.

The mesh heals itself. Ephemeral pods spinning up and down are not a problem --
they are the normal operating condition of a healthy dynamic mesh. When a pod
dies, its slot opens. When a new pod arrives, it claims a slot. The VDF chain
is the arbitrator, and it cannot be fooled.

---

## Fungibility and Split-Brain Resolution

This is the property that makes the VDF design genuinely novel.

**VDF work is fungible.** When two groups of nodes that were separated by a
network partition rejoin, their independently accumulated VDF work combines
additively. No work is lost. No work is double-counted.

This has been proven in Lean 4:
- `vdf_merge_fungible` -- merging groups preserves total VDF work
- `vdf_split_fungible` -- splitting groups preserves total VDF work
- `credits_merge_conserves` -- credit totals are conserved across merge
- `credits_split_conserves` -- credit totals are conserved across split

**Split and merge NEVER create or destroy work.** This is not an approximation.
It is a machine-checked mathematical proof.

### How split-brain resolution works

During a network partition, each isolated group ("clump") continues ticking its
own VDF chains independently. Each clump maintains its own SPIRAL topology, its
own slot assignments, its own view of the network. This is correct behavior --
the clumps are genuinely separate networks, and they should operate independently.

On rejoin, the merge proceeds as follows:

1. Both clumps exchange their slot claim histories with VDF timing evidence.
2. The heavier clump (more cumulative VDF work) gets SPIRAL priority -- but
   this is not "winner takes all."
3. A **zipper merge** interleaves positions from both clumps, filling empty
   slots in the winning topology with nodes from the lighter clump.
4. Minimal slot reassignment. The goal is to preserve as much existing topology
   as possible while establishing valid shell geometry.

The result: nodes from both sides of the partition end up in a unified SPIRAL
topology, with their accumulated VDF work correctly attributed. No node loses
credit. No node loses identity. The mesh reconverges.

This achieves what is sometimes called the "holy grail" of P2P networking:
uncensorable, self-coordinating clusters with any point of entry. A node can
join any clump, contribute work, get partitioned, rejoin a different clump, and
its contribution is always conserved.

---

## Merge Protocol

The current design uses an explicit `MESH MERGE` protocol message triggered when
partitions reconnect. This is the pragmatic first step: the two sides exchange
their state, compute the zipper merge, and apply the result.

The longer-term goal is **implicit merge**, where SPIRAL topology structure
itself determines the merge action automatically. When two clumps discover each
other through normal MESH HELLO exchange, the topology difference is the merge
trigger. No explicit protocol message needed -- the structure IS the protocol.

Explicit first (easier to reason about, debug, and prove correct), then
structural/implicit once the merge semantics are battle-tested.

---

## ZK Proof Structure

The zero-knowledge proof that a VDF chain was correctly computed uses three
cryptographic building blocks composed together:

### 1. Blake3 VDF chain

A sequential chain of hashes where each step depends on the previous:

```
h_0 = genesis
h_1 = Blake3(h_0)
h_2 = Blake3(h_1)
...
h_n = Blake3(h_{n-1})
```

### 2. Merkle tree commitment

All chain hashes are committed into a binary Merkle tree (padded to
next power of 2). The Merkle root is a compact commitment to the entire chain.

### 3. Fiat-Shamir non-interactive verification

Challenge indices are derived deterministically from the public parameters:

```
challenge_index = Blake3(merkle_root || genesis || final_hash || steps || k || spiral_slot)
```

Where `k` is the challenge number (0, 1, 2, ...). When `spiral_slot` is
present, the slot index is mixed into the derivation -- this binds the proof to
a specific SPIRAL position. Tampering with the slot invalidates every challenge
index, and therefore the entire proof.

### Verification procedure

For each of the `k` challenges (typically 3-5), the verifier checks:

1. **Challenge index matches.** Re-derive the expected index from public
   parameters. If the prover used a different index, reject.
2. **VDF step is correct.** Verify that `Blake3(h_i) == h_{i+1}` for the
   challenged position.
3. **Merkle membership.** Verify that both `h_i` and `h_{i+1}` have valid
   Merkle proofs against the committed root.

If all challenges pass, the verifier has high-probability confidence that the
entire chain was correctly computed, having checked only a handful of positions.
With 5 challenges, the probability of a forged chain passing is negligible.

The proofs are compact. A proof of a chain with millions of steps is the same
size as a proof of a chain with hundreds: a Merkle root, a genesis hash, a
final hash, a step count, and 3-5 challenge responses with their Merkle paths.

---

## Lean 4 Proofs

The mathematical properties of the Fungible VDF system are machine-checked in
Lean 4, in the `downward-spiral` project. These are not informal arguments or
"we believe this is correct" hand-waves. They are proofs that have been verified
by a proof assistant.

### VDF properties

| Theorem | Statement |
|---|---|
| `vdf_monotone` | More ticks produce more or equal credits (VDF never decreases) |
| `vdf_strictMono` | With at least one active node, credits strictly increase |
| `vdf_additive` | Time segments compose correctly (computing A ticks then B ticks equals computing A+B ticks) |

### Fungibility properties

| Theorem | Statement |
|---|---|
| `vdf_split_fungible` | Splitting a group into partitions preserves total VDF work |
| `vdf_merge_fungible` | Merging partitions back together preserves total VDF work |

### Conservation properties

| Theorem | Statement |
|---|---|
| `split_conserves` | Splitting does not create or destroy nodes |
| `merge_conserves` | Merging does not create or destroy nodes |
| `credits_split_conserves` | Total credits are conserved across a split |
| `credits_merge_conserves` | Total credits are conserved across a merge |

### Merkle properties

| Theorem | Statement |
|---|---|
| `merkle_completeness` | Round-trip prove/verify always succeeds for valid trees |

### SPIRAL shell geometry

| Formula | Domain |
|---|---|
| `3n^2 + 3n + 1` | 2D shell capacity at ring n |
| `6n^3 + 9n^2 + 5n + 1` | 3D shell capacity at ring n |

These proofs mean that the core invariants of the system -- work conservation
across splits and merges, monotonic VDF progress, correct Merkle verification --
are guaranteed to hold. Not "tested with 10,000 random inputs." Proven for all
possible inputs.

---

## Implementation Reference

### Crate: `lagoon-vdf`

**Path:** `crates/lagoon-vdf/`

The standalone VDF library, extracted from the `downward-spiral` prototype for
use in production Lagoon. Contains:

- **`VdfChain`** -- The sequential Blake3 hash chain. Supports `compute(genesis, steps)`
  for batch computation and `tick()` for incremental extension.
- **`MerkleTree`** -- Binary Merkle tree over 32-byte leaves, with `prove(index)`
  and `verify_proof(root, leaf, index, proof)`.
- **`VdfProof`** -- Non-interactive ZK proof via Fiat-Shamir transform. Supports
  `generate(chain, num_challenges)` and `generate_with_slot(chain, num_challenges, slot)`
  for SPIRAL-bound proofs. Verification via `verify()`.
- **`ChallengeResponse`** -- A single Fiat-Shamir challenge: chain index, both
  hashes, and both Merkle proofs.

Dependencies: `blake3`, `serde`, `serde_json`. No async runtime required.

### VDF engine: `lagoon-server`

**Path:** `crates/lagoon-server/src/irc/vdf.rs`

The async VDF engine that runs as a tokio task inside each Lagoon server:

- Ticks at a configurable rate (default 10 Hz, override via `LAGOON_VDF_RATE` env var).
- Genesis derived from the node's Ed25519 public key via `derive_genesis()`.
- State broadcast via `tokio::sync::watch` channel (`VdfState` snapshots).
- VDF chain shared via `Arc<RwLock<VdfChain>>` for on-demand ZK proof generation.
- Tracks both session steps (since boot) and total steps (including restored
  state from `lens_identity.json`).
- Shuts down cleanly via broadcast shutdown signal.

### Wire protocol

VDF state is exchanged over IRC MESH protocol messages:

| Message | Direction | Purpose |
|---|---|---|
| `MESH HELLO` | Bidirectional | Includes `vdf_genesis`, `vdf_hash`, `vdf_step` fields |
| `MESH PEERS` | Bidirectional | Propagates VDF state for known peers |
| `MESH VDFPROOF_REQ` | Request | "Prove you are alive" |
| `MESH VDFPROOF` | Response | JSON-serialized `VdfProof` |

VDF genesis is hex-encoded, derived from the node's Ed25519 public key. The
step count is cumulative across restarts (persisted in `lens_identity.json`).

### Prototype: `downward-spiral`

**Path:** `/mnt/castle/garage/downward-spiral/`

The original 3D SPIRAL simulation with cooperative VDF, wgpu visualization,
and the Lean 4 proof suite. This is where the mathematical foundations were
developed and verified before extraction into `lagoon-vdf`.

---

## Current Status

### Implemented (LAGOON-101 through LAGOON-107)

- `lagoon-vdf` crate with `VdfChain`, `MerkleTree`, `VdfProof`, Fiat-Shamir
  challenge derivation, and SPIRAL slot binding.
- Async VDF engine at 10 Hz with watch-channel state broadcast.
- VDF fields in `MESH HELLO` and `MESH PEERS` protocol messages
  (`vdf_genesis`, `vdf_hash`, `vdf_step`).
- `MESH VDFPROOF` / `MESH VDFPROOF_REQ` for ZK proof exchange between peers.
- VDF persistence across restarts via `lens_identity.json`.
- VDF state exposed in mesh snapshots and the debug HTTP endpoint.

### Not yet implemented

- **Proof-based liveness checks.** The current eviction logic uses a broken
  ratio-based comparison against total VDF work. This needs to be replaced with
  proper proof-challenge-response liveness: request a proof, compare step count
  to last known, prune if stale.
- **`MESH MERGE` protocol.** The split-brain resolution protocol is designed but
  not yet wired into the federation layer.
- **Cooperative VDF within SPIRAL clumps.** Currently each node runs its own
  independent chain. The design calls for nodes within a SPIRAL clump to
  contribute to a shared cooperative chain, but this is future work.
- **Zipper merge for slot claim histories.** The merge algorithm is proven in
  Lean 4 but not yet implemented in Rust.
- **Automatic/implicit merge.** Currently planned as explicit `MESH MERGE`
  first, then evolving toward structural merge triggered by SPIRAL topology
  discovery.

---

*This document describes the Fungible VDF system as designed and partially
implemented in Lagoon. The mathematical foundations are proven. The core VDF
engine and ZK proof system are deployed. The liveness and merge protocols
are the next frontier.*
