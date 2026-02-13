# Fungible VDF: Self-Coordinating Distributed Systems via Proof of Time

**Authors:** Wings (Riff Labs)
**Date:** February 2026
**Reference Implementation:** Lagoon (https://github.com/riffcc/lagoon)
**Simulation:** Downward Spiral (3D SPIRAL mesh with cooperative VDF)
**Formal Proofs:** Lean 4 with Mathlib

---

## Abstract

We present Fungible VDF, a mechanism for building self-coordinating
distributed systems without consensus protocols, synchronized clocks,
or distinguished infrastructure nodes.

A Fungible VDF chain is a sequential Blake3 hash chain that constitutes
a cryptographically unforgeable proof of elapsed computation time. The
defining property is *fungibility*: when network partitions heal,
independently accumulated VDF work combines additively. No work is
lost. No side of a partition is "wrong." The total weight of a swarm
is the sum of all elapsed time across every participating node.

Sybil resistance is *constitutional*: because VDF chains are
sequential and non-parallelizable, an attacker cannot accelerate
identity creation. Every node — honest or adversarial — proves elapsed
time at the same rate. You cannot fake time, stockpile it, or
parallelize it. Existence is the credential.

We define the *difficulty ceiling*, an adaptive cap on per-node
computation that inverts the economics of every previous consensus
mechanism. Where a difficulty target creates an arms race (more
hardware = more blocks), a difficulty ceiling creates a Nash
equilibrium at minimum energy expenditure. The rational strategy and
the efficient strategy are identical: do the minimum.

We formally define *Any Point Of Entry* (APE), a property where any
participating node is a valid entry point for new members, with no
bootstrap servers, directory authorities, or DNS chokepoints. We show
that Fungible VDF, combined with deterministic topology assignment
(SPIRAL), achieves APE.

All core invariants — VDF monotonicity, additivity, fungibility,
node conservation, credit conservation, and Merkle verification
completeness — are machine-checked in Lean 4. The split/merge
dynamics are demonstrated in a 3D simulation with ZK proof generation
at every state transition.

---

## 1. Introduction

Every distributed system faces the same fundamental questions: How do
you know who is alive? How do you agree on membership? How do you
recover from partitions? How do you resist Sybil attacks?

Traditional answers all involve some form of authority or waste:

- **Consensus protocols** (Raft, Paxos, PBFT) require quorums, leader
  election, and fixed membership views. A minority partition halts.
- **Nakamoto consensus** (Bitcoin) uses proof of work: energy
  expenditure as authority. Parallelizable. Concentrates power in
  mining hardware. Wastes energy by design.
- **Proof of Space** (Chia) wastes hardware. More storage = more plot
  wins. SSDs burn out. The insight was "waste storage instead of
  electricity." Still wasteful.
- **Proof of Stake** wastes capital. More tokens locked = more
  validation power. Creates plutocracy.
- **Infrastructure-dependent P2P** (Tor, BitTorrent, Matrix) relies on
  directory authorities, tracker servers, or homeservers that become
  seizure targets.

All of these systems have chokepoints: nodes that, if removed, degrade
or destroy the network. They all incentivize acquiring *more* of
something — more hashrate, more storage, more tokens, faster CPUs.
Network security comes from waste. The cost of attack is the cost of
out-wasting the honest participants.

Fungible VDF asks: what if the scarce resource is not anything you
provide, but the one thing you cannot fake? **Elapsed time.**

Time passes at the same rate for everyone. A Raspberry Pi and a data
center experience the same 10 seconds. Sequential computation proceeds.
The chain advances. This cannot be stopped, forged, or centralized.

The key insight is that VDF work is fungible: it combines additively
across partition merges and is conserved across splits. This transforms
network partitions from crises into normal operation. Both sides of a
partition are valid, productive swarms that merge seamlessly when
connectivity returns. The total weight of the merged swarm is the sum
of all elapsed time across every node in every partition.

---

## 2. Construction

### 2.1 The Blake3 VDF Chain

Given a genesis hash `g`, the VDF chain is a sequential hash chain:

```
h_0 = g
h_1 = Blake3(h_0)
h_2 = Blake3(h_1)
...
h_n = Blake3(h_{n-1})
```

Each step depends on the output of the previous step. The chain is
inherently sequential: there is no way to compute `h_n` without
computing all intermediate values `h_1, ..., h_{n-1}`. More hardware
does not help. More cores do not help. The bottleneck is latency, not
throughput.

### 2.2 Genesis Derivation

The genesis hash of a node's VDF chain is deterministically derived
from its Ed25519 public key using a domain-separated Blake3 hash:

```
genesis = Blake3("lagoon-vdf-genesis-v1" || public_key)
```

Anyone who knows a node's public key can independently compute the
expected genesis for that node's chain. There is no secret. There is
no seed ceremony. The chain is deterministic from identity.

This has a critical consequence for Sybil resistance: a new identity
starts at step 0. There is no way to create an Ed25519 keypair whose
derived genesis is "further along" a VDF chain. Every identity begins
with zero proven elapsed time. Authority accrues only through real
computation over real time.

### 2.3 Proof of Elapsed Time

A completed chain of `n` steps proves that at least `n * t_step`
wall-clock time has elapsed, where `t_step` is the minimum time to
compute one Blake3 hash on the fastest available hardware.

This is categorically different from proof of work:

| | Proof of Work | Proof of Elapsed Time |
|---|---|---|
| **Measures** | Energy expenditure | Duration |
| **Parallelizable** | Yes (mining pools) | No (sequential by construction) |
| **Hardware advantage** | GPU farm >> laptop | None (latency-bound) |
| **What scales** | Power with hardware | Nothing — time is constant |

A CDN edge pod saturated with traffic and an idle standby server
produce the same VDF evidence: "I have been alive and computing for
this long." The work is fungible across all roles and workloads.

---

## 3. Fungibility

This is the central property.

### 3.1 Definition

Let a **swarm** be a connected subset of nodes in the network, each
running an independent VDF chain. Let `W(S)` denote the total VDF work
of swarm `S`, defined as the sum of all chain lengths:

```
W(S) = sum_{i in S} steps(chain_i)
```

Let `credits(S)` denote the credit allocation within `S`, tracking how
much each node has contributed.

**Definition (VDF Fungibility).** A VDF system is *fungible* if for any
swarm `S` and any partition of `S` into `S_1` and `S_2`:

```
W(S) = W(S_1) + W(S_2)                         (work conservation)
credits(S) = credits(S_1) + credits(S_2)        (credit conservation)
```

and conversely, for any merge of swarms `S_1` and `S_2` into `S`:

```
W(S) = W(S_1) + W(S_2)                         (merge preserves work)
credits(S) = credits(S_1) + credits(S_2)        (merge preserves credits)
```

### 3.2 Swarm Weight

The **weight** of a swarm is its total VDF work: the sum of all
elapsed time across every participating node. This is the measure of
a swarm's computational history — not how much energy it burned, but
how much real time its members collectively experienced.

When two swarms merge, the merged weight equals the sum of the
individual weights. No work is lost. No work is double-counted. When
a swarm splits, both sub-swarms inherit their respective portions.
The total is always conserved.

This weight determines authority in the merged topology. The heavier
swarm (more cumulative elapsed time) receives priority in SPIRAL slot
assignment. This is not "winner takes all" — it is a weighted merge
where longer-running nodes earn inner topology positions and newer
nodes fill outer shells.

### 3.3 Machine-Checked Proofs

These properties are proven in Lean 4, not merely tested:

| Theorem | Statement |
|---|---|
| `vdf_split_fungible` | Splitting preserves total VDF work |
| `vdf_merge_fungible` | Merging preserves total VDF work |
| `credits_split_conserves` | Credit totals conserved across split |
| `credits_merge_conserves` | Credit totals conserved across merge |
| `split_conserves` | Node count conserved across split |
| `merge_conserves` | Node count conserved across merge |
| `vdf_monotone` | More ticks produce more or equal credits |
| `vdf_strictMono` | With active nodes, credits strictly increase |
| `vdf_additive` | Time segments compose correctly |

The proofs use Lean 4 with Mathlib and have been verified by the Lean
type checker. They are available in the `downward-spiral` repository.

### 3.4 Why Fungibility Matters

In every existing distributed system, network partitions create
conflict. Raft halts the minority partition. Bitcoin forks and discards
the shorter chain. PBFT requires `2f + 1` nodes to make progress.

With Fungible VDF, **both sides of a partition are valid.** London
cannot reach Tokyo. Both swarms keep ticking their VDF chains. Both
maintain their topology. Both serve their users. Neither is wrong.

When connectivity returns, the chains merge. Total work = London's work
+ Tokyo's work. No chain is discarded. No work is lost. The partition
was simply the mesh temporarily existing as two swarms instead of one.

This is a fundamentally different model of distributed computation.
Partitions are not failures to be recovered from. They are the normal
operation of a dynamic mesh that continuously self-assembles around
connectivity.

### 3.5 Simulation Evidence

The `downward-spiral` simulation demonstrates fungibility across
complex operation sequences:

1. **VDF Fungibility Proof scenario.** 10 nodes tick 50 VDF steps.
   Split into 2 swarms. Both tick 30 more steps independently. Merge.
   Total VDF work = 110, exactly conserved.

2. **Big Bang / Big Crunch scenario.** 25 nodes shattered into ~25
   single-node swarms (split-all), tick independently, then merge back
   into one. All VDF work preserved.

3. **Gauntlet stress test.** 100 random operations (splits, merges,
   node additions, node removals) with conservation invariant checked
   after every operation.

These scenarios produce JSON output with ZK proofs at every state
transition, enabling independent verification of every claim.

---

## 4. Constitutional VDF: Sybil Resistance

### 4.1 The Problem

Sybil attacks — creating many fake identities to gain disproportionate
influence — are the fundamental threat to permissionless systems.
Bitcoin resists Sybils through energy cost (each mining identity
requires hardware investment). Proof of Stake resists through capital
lockup. Both create barriers to entry that also exclude honest
participants.

### 4.2 Time as the Constitutional Limit

Fungible VDF provides Sybil resistance through a mechanism we call
*Constitutional VDF*: the VDF chain itself is the constitutional limit
on how many slots an entity can meaningfully hold.

The argument:

1. **Every identity starts at zero.** Genesis is derived from the
   Ed25519 public key. A new keypair produces a new chain starting at
   step 0. There is no way to create an identity with pre-existing VDF
   weight.

2. **VDF chains are sequential.** An attacker running 1000 Sybil nodes
   needs 1000 independent sequential chains. Each chain advances at
   wall-clock speed. The attacker cannot parallelize a single chain
   across multiple cores.

3. **Swarm weight reflects real elapsed time.** The attacker's 1000
   nodes contribute 1000 chains to the swarm weight, but each chain
   only represents the time since that node started. Existing nodes
   that have been running longer have more individual VDF weight.

4. **SPIRAL topology is VDF-weighted.** On merge, the heavier swarm
   gets inner (higher-priority) SPIRAL slots. An attacker's fresh
   Sybil nodes are placed in outer shells by construction — they
   haven't earned inner positions because they haven't existed long
   enough.

5. **Dead nodes are pruned.** Sybil nodes that stop computing are
   detected (VDF chain stops advancing) and pruned. Their SPIRAL
   slots are freed and reclaimed by active nodes. The attacker must
   keep all Sybil nodes running continuously to maintain their slots.

6. **The cost is real time.** The cost of holding N SPIRAL slots for
   T seconds is exactly: running N nodes for T seconds. There is no
   shortcut. No hardware advantage. No parallelization trick. The
   attacker pays the same cost as N honest participants.

### 4.3 Why This Works

The essential insight is that VDF chains are *non-fungible across
identities* while being *fungible across partitions*. You cannot
transfer VDF weight from one identity to another. You cannot
pre-compute weight for a future identity. You cannot batch-create
weighted identities. Each identity earns its weight independently,
sequentially, at the pace of real time.

This means the barrier to a Sybil attack is not hardware (as in PoW)
or capital (as in PoS) but *time*. An attacker who wants to dominate
the topology must run many nodes for a long time. There is no way to
shortcut this. And while the attacker is running those nodes, they are
indistinguishable from honest participants — they are contributing
real VDF work to the swarm.

The cost of attack converges to the cost of honest participation. The
VDF is the constitution: it sets an equal speed limit for all
participants, and that speed limit cannot be exceeded.

---

## 5. Split-Brain Resolution

### 5.1 Partition Behavior

When a network partition occurs, the mesh splits into swarms. Each
swarm:

- Continues advancing its VDF chains independently.
- Maintains its own SPIRAL topology.
- Serves its users normally.
- Is a complete, functional system on its own.

Neither side halts. Neither side is "wrong." Both sides accumulate
genuine VDF evidence of elapsed time.

### 5.2 Merge Protocol

When connectivity returns, the merge proceeds:

1. Both swarms exchange VDF chain states and slot claim histories with
   timing evidence (VDF step counts at the time of each claim).

2. The **heavier swarm** (more total VDF work) has SPIRAL priority.
   "Heavier" is computed as: `W(S) = sum of all VDF steps across all
   nodes in S`.

3. Swarms are sorted by VDF weight, heaviest first. Their node
   orderings are concatenated into a single SPIRAL sequence. Nodes
   from the heavier swarm occupy inner shells; nodes from lighter
   swarms fill outer shells.

4. VDF work combines additively:
   `W(merged) = W(S_1) + W(S_2)`.

5. Per-node credits are preserved. No node loses attribution for its
   contributed VDF work.

6. The merged VDF hash is derived from the constituent hashes:
   `merged_hash = Blake3(hash_1 || hash_2 || ...)`.

### 5.3 Topology Recomputation

After merge, the entire SPIRAL topology is recomputed from the merged
node ordering. Each node is assigned a position in the 3D hexagonal-z
lattice based on its index in the ordering. The position determines
the neighbor set (Section 11). This is a deterministic, one-shot
computation — no iterative convergence, no negotiation protocol.

The simulation demonstrates this in the **Big Bang / Big Crunch**
scenario: 25 nodes are shattered into individual single-node swarms,
tick independently, and then merge back into a single swarm with
complete topology recomputation. All VDF work is preserved. All
SPIRAL positions are valid.

### 5.4 Properties of Merge

The following properties are machine-checked (Lean 4):

- **Work conservation.** `W(merged) = W(S_1) + W(S_2)`. No VDF work
  is created or destroyed.
- **Credit conservation.** `credits(merged) = credits(S_1) + credits(S_2)`.
  No node's credit is lost.
- **Node conservation.** `|merged| = |S_1| + |S_2|`. No nodes are
  created or destroyed (for disjoint swarms).

These properties hold regardless of:
- The size difference between swarms.
- The duration of the partition.
- The number of nodes in each swarm.
- How many times the network has previously split and merged.

---

## 6. Zero-Knowledge Verification

A node claiming `n` VDF steps must be able to prove it without
transmitting the entire chain. We achieve this through a three-layer
cryptographic construction.

### 6.1 Merkle Commitment

All chain hashes `h_0, ..., h_n` are committed into a binary Merkle
tree, padded to the next power of 2. The Merkle root is a constant-size
commitment to the entire chain.

**Theorem (Merkle Completeness).** For any valid Merkle tree, any leaf
index `i`, and the proof generated by `genProof(i)`:

```
recompute(leaf_i, i, genProof(i)) = root
```

This is machine-checked in Lean 4 (`merkle_completeness`).

### 6.2 Fiat-Shamir Challenges

Verification uses a non-interactive challenge-response protocol derived
from the Fiat-Shamir heuristic. Challenge indices are computed
deterministically from public parameters:

```
challenge_k = Blake3(merkle_root || genesis || final_hash
                     || steps || k || spiral_slot) mod steps
```

Where `k` ranges from `0` to `num_challenges - 1`, and `spiral_slot`
is the prover's claimed SPIRAL topology position (binding the proof to
a specific slot — tampering with the slot invalidates all challenges).

### 6.3 Verification Procedure

For each challenge `k`:

1. Derive the expected challenge index from public parameters.
2. Verify the VDF step: `Blake3(h_{challenge_k}) == h_{challenge_k + 1}`.
3. Verify Merkle membership of both `h_{challenge_k}` and
   `h_{challenge_k + 1}` against the committed root.

If all challenges pass, the verifier has high-probability confidence
that the chain was correctly computed.

### 6.4 Proof Compactness

A proof consists of:
- Merkle root (32 bytes)
- Genesis hash (32 bytes)
- Final hash (32 bytes)
- Step count (8 bytes)
- Per challenge: index (8 bytes), two hashes (64 bytes), two Merkle
  paths (each `ceil(log_2(n + 1))` hashes of 32 bytes)

For `k` challenges over a chain of `n` steps, the proof size grows
as `O(k * log(n))`. For 5 challenges over a chain of `2^20` steps
(~1M), the Merkle depth is 21 (since the tree contains `2^20 + 1`
leaves including genesis, padded to `2^21`). The per-challenge payload
is `8 + 64 + 2 * 21 * 32 = 1,416` bytes, giving a total proof size
of approximately `104 + 5 * 1,416 = 7,184` bytes. This is constant
relative to the chain length, growing only logarithmically.

### 6.5 Security Analysis

The security of the ZK proof relies on the Fiat-Shamir heuristic:
the prover must commit to a Merkle root *before* knowing the
challenge indices. If the committed chain has any incorrect VDF steps,
challenges landing on those positions will detect the error.

For a Blake3 VDF chain, corruption is sequential: if the adversary
stops computing correctly at step `j` and fills the rest with
arbitrary values, all positions from `j` onward are incorrect. The
probability that all `k` challenges fall within the correct prefix
is:

```
P(undetected by one verifier) = (j / n)^k
```

where `j` is the number of correctly computed steps and `n` is the
total claimed steps.

For a single verifier with `k = 5` challenges, this is weak against
adversaries who skip small fractions: skipping 1% gives a 95.1%
chance of evading detection. But a single verifier is not the security
model.

### 6.6 Topology-Amplified Verification

SPIRAL assigns exactly 20 neighbors to every node: 6 planar
(hexagonal grid), 2 vertical (z-axis), and 12 extended diagonal
(all combinations of planar and vertical offsets). This is a
compile-time invariant of the Citadel topology — not "approximately
20" but exactly 20, with a static assertion in the implementation.

Each neighbor independently verifies a node's VDF chain by issuing
a `VDFPROOF_REQ` with its own identity mixed into the Fiat-Shamir
challenge derivation:

```
challenge_k = Blake3(merkle_root || genesis || final_hash
                     || steps || k || prover_slot
                     || verifier_pubkey) mod steps
```

Each neighbor derives a *completely different* set of challenge
indices. The adversary must fool *all 20* to avoid detection.

With `k` challenges per neighbor and 20 independent verifiers:

```
P(undetected by ALL neighbors) = ((j / n)^k)^20
                                = (j / n)^(20k)
```

For k = 5, the effective challenge count is **100**:

| Fraction skipped | k=5, 1 verifier | k=5, 20 neighbors |
|---|---|---|
| 1% | 0.951 | 0.366 |
| 5% | 0.774 | 0.006 |
| 10% | 0.590 | ~0 |
| 50% | 0.031 | ~0 |

**The topology is the security mechanism.** You do not need more
challenges per proof — you need more verifiers per node. SPIRAL
provides 20 for free. Each neighbor only receives a compact 5-
challenge proof, but the aggregate security is equivalent to 100
independent challenges.

### 6.7 Two-Hop Verification: The Honeycomb Property

SPIRAL's gap-and-wrap indexing and toroidal structure create an
extraordinary geometric property: **all neighbors are neighbors of
neighbors.** The 20 canonical direction offsets are translation-
invariant — every node in the lattice has the same 20 relative
neighbor directions. If A is your neighbor via direction D, then
A's neighbors include many of your other neighbors (the offsets
overlap). The clustering coefficient is approximately 0.87: 87% of
any two adjacent nodes' neighbor sets are shared.

Going one more hop — each node also verifies its neighbors'
neighbors — exploits this structure. Because the overlap is so
dense, 2-hop barely grows the unique verifier set. Most of the
"new" nodes at 2-hop are already existing neighbors. The additional
network cost is approximately 2x, not 20x.

But the security improvement is devastating, because 2-hop
verification creates a **cross-validated verification mesh.** Your
20 neighbors don't just independently verify you — they also verify
*each other.* Every edge in the local subgraph is checked from both
ends. An adversary who presents different chain states to different
neighbors is immediately caught when those neighbors cross-check.
The neighborhood is a near-clique — there is nowhere to hide an
inconsistency.

In concrete terms, the ~2x network cost yields:

| Fraction skipped | 1-hop (k_eff=100) | 2-hop (k_eff=200) |
|---|---|---|
| 1% | 0.366 | 0.134 |
| 2% | 0.133 | 0.018 |
| 5% | 0.006 | 0.00004 |
| 10% | ~0 | ~0 |

At 2-hop, skipping 2% of the chain has a 1.8% chance of success.
Skipping 5% is four-in-a-hundred-thousand.

This works because SPIRAL is a self-similar honeycomb, not a random
graph. In a random graph, 2-hop would explode to hundreds of unique
nodes and be prohibitively expensive. In SPIRAL, the toroidal
structure and gap-and-wrap indexing ensure that the 2-hop
neighborhood is dense, overlapping, and cross-connected — delivering
multiplicative security amplification for additive network cost.
The geometry enforces the verification.

---

## 7. Any Point Of Entry

### 7.1 Definition

**Definition (Any Point Of Entry).** A distributed system satisfies
*Any Point Of Entry* (APE) if and only if:

1. **Entry equivalence.** For any node `n` currently participating in
   the system, a new node `m` connecting to `n` can:
   (a) verify the system's state (membership, topology, liveness), and
   (b) begin full participation (claim a position, contribute work,
   send and receive messages),
   using only information obtained from `n` and its neighbors, with no
   out-of-band communication required.

2. **No distinguished infrastructure.** There exists no node, server,
   or service whose unavailability prevents new nodes from joining.
   Specifically: no bootstrap server, no directory authority, no DNS
   name, no tracker, no homeserver whose removal would make the system
   unjoinable.

3. **Partition resilience.** If the system is partitioned into swarms
   `S_1, ..., S_k`, APE holds independently within each swarm. A new
   node connecting to any node in any swarm can join that swarm without
   requiring connectivity to any other swarm.

### 7.2 How Fungible VDF Achieves APE

A new node `m` connects to any existing node `n`:

1. **Receives VDF chain state.** The current chain tip hash, step
   count, and genesis. This is cryptographic proof that the swarm has
   existed for real time — it cannot be fabricated.

2. **Verifies the chain.** Requests a ZK proof from `n`. Checks the
   Fiat-Shamir challenges against the Merkle commitment. If valid, the
   chain represents genuine elapsed time.

3. **Receives SPIRAL topology.** The set of known peers, their VDF
   states, their claimed SPIRAL positions. `m` can verify each peer's
   VDF proof independently.

4. **Claims a SPIRAL slot.** Self-assembly: `m` starts its own VDF
   chain, claims an available slot in the SPIRAL topology, and begins
   contributing. No permission needed. No authority to approve.

5. **Is fully participating.** `m` is now a member of the mesh. It can
   be an entry point for the next node that joins.

No step requires contacting a distinguished server. No step requires
DNS resolution. No step requires a specific node to be available.

### 7.3 Censorship Resistance

To prevent a new node from joining a system that satisfies APE, an
adversary must prevent it from reaching *every single existing node*.
Blocking any subset less than the entire membership is insufficient —
a single reachable node is a valid entry point.

Combined with an overlay network (such as Yggdrasil) that provides
cryptographic addressing and NAT traversal, the reachability
requirement reduces to: the new node must know the overlay address of
any one existing node. Since overlay addresses are derived from public
keys and are globally routable, this is equivalent to knowing any one
node's public key.

### 7.4 Comparison

| System | APE? | Chokepoint |
|---|---|---|
| Bitcoin | No | DNS seeds, well-known bootstrap nodes |
| Tor | No | Directory authorities (10 hardcoded) |
| BitTorrent | No | Trackers, DHT bootstrap nodes |
| Matrix | No | Homeservers (account bound to one server) |
| IPFS | No | DHT bootstrap nodes |
| Raft/Paxos | No | Configuration server, leader |
| **Fungible VDF** | **Yes** | **None** |

---

## 8. Liveness and Ghost Pruning

### 8.1 VDF as Liveness Signal

Liveness is determined by VDF chain advancement, not by timers or
heartbeats.

A node is alive if and only if its VDF chain is advancing. Specifically:
if the step count reported by a node has not increased between
successive observations, the node is considered dead. The VDF chain IS
the heartbeat.

This eliminates:

- **Clock synchronization.** No NTP. No wall-clock agreement.
- **Heartbeat protocols.** No periodic messages that fail under
  partition and create false positives.
- **TTL timers.** No arbitrary thresholds that are too aggressive
  (false evictions under load) or too lenient (ghosts persist).

### 8.2 On-Demand Proof Challenge

For stronger liveness guarantees, a peer can challenge another to
produce a *fresh* ZK proof:

1. Challenger sends `VDFPROOF_REQ` to the suspect node.
2. Suspect responds with a `VDFPROOF` proving its current chain state.
3. Challenger verifies the proof and checks that the step count
   exceeds the last known value.

If the suspect cannot respond, or responds with a stale proof (same
step count as previously known), it is pruned. Its SPIRAL slot is
freed, and the topology recomputes.

### 8.3 Attestation-Based Liveness (Target Architecture)

In the cooperative VDF model, ghost node pruning becomes trivial
through checkpoint attestations:

```
Checkpoint N:   attestations from {A, B, C, D, E}
Checkpoint N+1: attestations from {A, B, C, E}
Checkpoint N+2: attestations from {A, B, C, E}
```

Node D did not attest at checkpoints N+1 or N+2. D is dead. Prune.
SPIRAL slot freed. Topology recomputes.

No TTL timer. No "last seen" timestamp. No heartbeat protocol. No
synchronized clocks. Just: did you sign the checkpoint? No? You're
gone.

### 8.4 Self-Healing Topology

Ghost node pruning is automatic:

1. Node dies (pod terminates, server crashes, link fails).
2. Its VDF chain stops advancing.
3. Neighbors observe the stale step count.
4. The ghost is pruned.
5. Its SPIRAL slot is freed.
6. A new node claims the slot.
7. The mesh continues with no manual intervention.

In a CDN deployment with ephemeral pods, this is not an edge case.
It is the steady state. Pods spin up, claim slots, contribute VDF
work, get terminated, are pruned, and their slots are reclaimed by
new pods. The mesh breathes.

---

## 9. The Difficulty Ceiling

### 9.1 Floors vs Ceilings

Every blockchain has a **difficulty floor** — a target that miners
must reach. You must do *at least this much work* to produce a valid
block. Nodes compete to exceed the floor. The floor rises. Energy
consumption spirals. It is an arms race by construction.

Fungible VDF uses a **difficulty ceiling** — an adaptive cap on how
much work any node may contribute per checkpoint. Any computation
exceeding the cap is discarded. Not invalid — just ignored.

```
ceiling = total_work_needed / known_network_size
```

Adaptive. As nodes join, the ceiling drops. Each node does less. As
nodes leave, the ceiling rises. Remaining nodes do more. The total
work stays constant. The checkpoint cadence stays constant.

### 9.2 The Solid Wall

A difficulty target is a hole you have to dig. Deeper hole = more
valid. Everyone digs as fast as they can. The hole serves no purpose.
It is just proof you dug.

A difficulty ceiling is a wall. You push against it. It doesn't move.
Push harder — still doesn't move. Bring a thousand friends to push —
it still doesn't move. So you stop pushing. You lean against it. You
put exactly enough weight on it to prove you're standing there. That's
the minimum. That's the optimum. They're the same thing.

**The wall is time.** It doesn't care how strong you are.

### 9.3 Nash Equilibrium: Minimum Energy

A difficulty target says "prove you burned this much energy." The
rational response is to burn as much energy as possible.

A difficulty ceiling says "stop burning energy, we have enough." The
rational response is to burn as little as possible.

**The economically rational behavior and the ecologically optimal
behavior are identical.** You cannot gain advantage by doing more work.
You can only waste your own electricity. The Nash equilibrium of a
Fungible VDF network is minimum energy expenditure — not because
participants are altruistic, but because the wall doesn't move.

### 9.4 The Ohm's Law Analogy

```
Voltage (V) = Current (I) x Resistance (R)
Time    (T) = Compute (C) x Difficulty (D)
```

In a resistor, more current does not increase voltage — it increases
heat dissipation. The voltage drop is constant.

In Fungible VDF, more compute does not decrease checkpoint time — it
hits the difficulty ceiling. The interval is constant.

| Electrical | Fungible VDF |
|---|---|
| Voltage (constant) | Checkpoint interval (constant) |
| Current (variable) | Compute power thrown at the network |
| Resistance (adapts) | Difficulty ceiling (adapts to network size) |
| Heat (dissipated) | Wasted computation (discarded above ceiling) |

Push harder, and the wall pushes back.

### 9.5 Energy Budget

For a network of N nodes:

| Component | Cost | Scales with |
|---|---|---|
| VDF computation | 1 sequential hash chain | Nothing (constant) |
| Attestations | N Ed25519 signatures | O(N), each is microseconds |
| **Total** | **One VDF + N signatures** | **O(N) trivial operations** |

Compare to Bitcoin (N nodes): O(N) parallel hash computations at
maximum hardware throughput, continuously, with difficulty scaled to
ensure only one block per 10 minutes. The energy ratio between Fungible
VDF and PoW is not a percentage improvement. It is an inversion.

### 9.6 The Resonance Curve

The difficulty ceiling is the simple mechanism: a flat cap on per-node
work. Sufficient for embedded systems and resource-constrained nodes.
But there is a more powerful construction.

Instead of a flat ceiling, use a **resonance curve** — a bell curve
where maximum credit is awarded at exactly the target tick rate, with
progressive penalties in both directions:

```
Credit
  |
  |         .---.
  |        /     \
  |       /       \
  |      /         \
  |     /           \
  |    /             \
  |   /               \
  |--/                 \--
  +------------------------
  slow    target    fast
```

Too slow: not enough ticks. Progressive penalty — the node is
underproviding proof of elapsed time. Too fast: too many ticks.
Quadratic anti-returns — the node is overexerting, wasting energy
for diminishing credit. The peak is exactly the target rate. Not
approximately. Not "within tolerance." The maximum credit is a single
point on the curve.

The credit function for a node ticking at rate `r` against target
rate `r_0`:

```
credit(r) = exp(-((r - r_0) / sigma)^2)
```

Where `sigma` controls the sharpness of the peak. A tighter `sigma`
demands more precise timekeeping. The function is:
- 1.0 at exactly `r = r_0` (full credit)
- Continuously decreasing as `r` deviates in either direction
- Approaching 0 for significantly off-rate nodes

This creates **natural selection for clock precision.** A node with
a precise crystal oscillator hits the peak every epoch. Full credit.
A node with a cheap clock wobbles — sometimes 9.97s, sometimes
10.04s. Each wobble costs credit. Not catastrophically, because the
curve is progressive. But consistently. Over thousands of epochs,
the precise node earns measurably more than the wobbly one.

The mesh does not enforce clock precision. It rewards it. Nodes are
not required to have good clocks. They are incentivized to. The
ones that do, thrive. The ones that don't, survive but earn less.
The ones that are wildly off, starve.

### 9.7 Dual Population

The ceiling and the resonance curve serve different worlds:

**Embedded (ceiling).** Raspberry Pi, IoT, sensors. Limited hardware.
"Don't exceed your slot. Here's your cap. Stay under it." Simple.
Fair. Works on a $5 chip.

**Full nodes (resonance).** Servers, infrastructure, dedicated
hardware. "Hit the target exactly. The closer you get to true 10
seconds, the more you earn. Your precision is your competitive
advantage."

The dual population creates a natural clock hierarchy. Full nodes
with precise oscillators define the reference rate — they earn
maximum credit by hitting the peak consistently. Embedded nodes
with cheap clocks earn less per epoch but still participate. The
incentive gradient points every node toward the peak.

### 9.8 The Wobble Is Data

A node's tick pattern is a signal:

- Consistently 9.98s: **systematic drift** — the oscillator runs
  slightly fast. Correctable.
- Alternating 9.95s and 10.05s: **jitter** — noisy clock source.
  Hardware quality visible in the credit curve.
- Perfect for hours, then a sudden jump: **thermal event** — the
  crystal changed temperature. Environmental conditions are encoded
  in the timing data.
- Gradual drift over weeks: **oscillator aging** — the crystal is
  physically changing. Predictable. Compensatable.

The mesh is an observatory for clock behavior across every node on
every continent. You can watch crystal oscillators age in real time
by tracking credit curves.

---

## 10. The Ensemble Clock

The resonance curve has a consequence that transcends timekeeping
as a mechanism. It creates a clock.

### 10.1 Independent Errors

Every individual crystal oscillator drifts. Temperature, voltage,
aging, vibration — each one is imprecise in its own way. Each one is
wrong. But they are all wrong *differently*. The errors are
independent. Random. Uncorrelated.

When you average uncorrelated random errors across `N` samples, the
noise drops as `1 / sqrt(N)`:

| Nodes | Precision improvement |
|---|---|
| 10 | 3.2x |
| 1,000 | 31.6x |
| 100,000 | 316x |
| 10,000,000 | 3,162x |

This is ensemble averaging — the same principle behind atomic time
standards. NIST does not use one cesium atom. They use millions. A
single atom has quantum uncertainty. The average converges on true
time because the errors cancel.

Fungible VDF does the same thing with commodity hardware. Every $2
crystal oscillator is wrong. But they are all wrong independently.
The resonance curve weights precise nodes higher (they earn more
credit, they contribute more to the swarm's timing). The wobbly
ones contribute less but still contribute. The ensemble converges.

### 10.2 Precision Scales with Participation

The more nodes join the mesh, the more precise the clock becomes.
Not by adding better hardware. By adding *more* hardware — including
bad hardware. Every cheap oscillator on every Raspberry Pi on every
continent is another sample that cancels another fraction of the
noise.

This is the inverse of every other scaling property in distributed
systems. Usually, adding nodes makes coordination harder. Here,
adding nodes makes the clock better.

### 10.3 The Resonance Curve Is NTP

Nodes do not synchronize by asking "what time is it." They
synchronize by observing which tick rate earns maximum credit and
adjusting toward it.

The peak of the resonance curve IS the correct time. The credit
gradient points toward it. Every node in the mesh is continuously
hill-climbing toward true time. The nodes at the summit — the ones
with precise oscillators hitting the peak consistently — are the
reference clocks. Not because anyone designated them. Because the
economics did.

You do not need NTP because the resonance curve is NTP. The
incentive IS the synchronization protocol. Physics, economics, and
timekeeping — one curve.

### 10.4 A Planetary Timepiece

This is not a network of clocks that synchronize to a reference. It
is a single clock made of every node on earth.

Each oscillator is an atom in the crystal. Each tick is a measurement.
The ensemble averages them. The resonance curve weights them. The
swarm converges on true time with precision that improves as
participation grows.

A node joins in São Paulo with a $2 crystal. Its clock is wrong by
200 parts per million. It contributes a measurement. A server in
Frankfurt with a temperature-compensated oscillator is wrong by 0.5
ppm. It contributes a more heavily weighted measurement. A rack in
Tokyo with a GPS-disciplined clock is wrong by 0.01 ppm. It earns
maximum credit and anchors the ensemble.

All three are atoms in the same crystal. The planetary timepiece gets
more precise with every node that joins, every tick that fires, every
measurement that averages into the ensemble. The clock cannot be
stopped because it is everywhere. It cannot be wrong because it is
everyone.

---

## 11. SPIRAL Topology

Fungible VDF provides the temporal foundation (proof of life, swarm
weight, split-brain resolution). SPIRAL provides the spatial foundation
(who connects to whom).

SPIRAL is a deterministic topology based on 3D hexagonal-z lattice
geometry. Each node claims a slot in the lattice, and the geometry
determines the neighbor set.

### 10.1 Shell Geometry

Each shell `n` (the `n`-th ring from the origin) has a deterministic
capacity:

| Dimension | Shell `n` size (n > 0) | Shell 0 | Cumulative through shell `n` |
|---|---|---|---|
| 2D hex | `6n` | 1 | `3n^2 + 3n + 1` |
| 3D hex-z | `18n^2 + 2` | 1 | `6n^3 + 9n^2 + 5n + 1` |

Both the shell size formulas and cumulative formulas are
machine-checked in Lean 4. The cumulative formulas equal the sum of
shell sizes from 0 through `n`, verified by the proof assistant for
all `n`.

The 3D lattice extends the 2D hexagonal grid with a vertical (z) axis.
Each 3D position `(q, r, z)` has a shell radius defined as
`max(hex_chebyshev(q, r), |z|)`. Nodes at the same shell radius are
equidistant from the origin in this metric.

### 10.2 Deterministic Neighbors

Each node has exactly 20 neighbors: 6 planar (hexagonal grid in the
same z-layer), 2 vertical (directly above and below on the z-axis),
and 12 extended diagonal (all 6 planar directions combined with both
vertical directions). This is `6 + 2 + 12 = 20`, enforced by a
compile-time assertion in the Citadel topology implementation.

The neighbor offsets are **translation-invariant**: every node in the
lattice has the same 20 canonical direction vectors. This creates a
self-similar honeycomb structure with clustering coefficient ~0.87 —
meaning 87% of any two adjacent nodes' neighborhoods overlap.

**Gap-and-wrap indexing** makes the topology toroidal. In a sparse
mesh where the theoretical neighbor in a given direction is
unoccupied, the connection wraps to the next occupied node in that
direction. This ensures every node always has exactly 20 live
neighbors regardless of mesh density, with bidirectionality proven
in Lean 4.

The neighbor set is determined entirely by a node's SPIRAL index.
If you know the index assignments, you know the entire topology. No
routing table exchange. No neighbor discovery protocol. The geometry
IS the routing table.

### 10.3 Slot Claiming

A new node joining the mesh:

1. Examines the current SPIRAL topology (received from its entry point).
2. Identifies unclaimed slots.
3. Claims an available slot and announces it.
4. Its neighbor set is now deterministic from its slot index.

No authority assigns slots. No consensus protocol agrees on assignment.
The topology self-assembles.

---

## 12. Formal Properties

### 11.1 Acceleration Resistance

**Definition (Acceleration Resistance).** A distributed timing
primitive is acceleration-resistant if for any number of participants
`N` and any amount of computational power `P` available to those
participants, the time between successive outputs is bounded below by
a constant `T` that depends on neither `N` nor `P`.

Fungible VDF satisfies this. The VDF step takes a fixed interval. One
node or ten thousand. One CPU or ten thousand GPUs. The "resistance"
increases proportionally to the "current."

### 11.2 Checkpoint Validity

A checkpoint `C_n` is valid if and only if:

1. `C_n.vdf_step = VDF(C_{n-1}.vdf_step)` — sequential dependency
2. For each attestation `sig_i` in `C_n.attestations`:
   `verify(pubkey_i, sig_i, hash(C_n.vdf_step || n))` — valid signature
3. `n = C_{n-1}.n + 1` — monotonic sequence

### 11.3 Difficulty Ceiling Validity

An individual node's contribution `w_i` to checkpoint `C_n` is valid
if and only if:

```
w_i <= total_work_required / |known_peers_at_C_{n-1}|
```

Contributions exceeding the ceiling are discarded by verifying peers.

---

## 13. Comparison

### 12.1 Comprehensive Comparison

| Property | Nakamoto (PoW) | BFT/Raft/Paxos | Chia (PoSpace) | Fungible VDF |
|---|---|---|---|---|
| **Scarce resource** | Electricity | N/A | Storage | Time |
| **Can be stockpiled?** | Yes (hashrate) | N/A | Yes (plots) | No |
| **Can be accelerated?** | Yes (faster ASICs) | N/A | Yes (faster I/O) | No |
| **Can be parallelized?** | Yes (mining pools) | N/A | Yes (plot farms) | No |
| **Difficulty mechanism** | Floor (target) | N/A | Floor (target) | Ceiling (cap) |
| **Nash equilibrium** | Max energy | N/A | Max storage | Min energy |
| **Energy at scale** | Grows with network | Low | Grows with network | Constant |
| **Per-node cost** | Max hashrate | Low | Max storage | One signature |
| **Partition tolerance** | Fork, discard shorter | Minority halts | Fork, discard shorter | Both valid, merge |
| **Work conservation** | No (shorter chain lost) | N/A | No (shorter chain lost) | Yes (proven) |
| **Clock requirement** | No | Timeouts | No | No |
| **Bootstrap dependency** | DNS seeds | Config file | DNS seeds | None (APE) |
| **Membership** | Peer gossip | Explicit reconfig | Peer gossip | Self-assembly (SPIRAL) |
| **Liveness signal** | Block production | Heartbeat/timeout | Block production | VDF advancement |
| **Any Point Of Entry** | No | No | No | **Yes** |
| **Split-brain resolution** | Longest chain wins | Quorum required | Longest chain wins | VDF-weighted merge |
| **Sybil resistance** | Energy cost | Permissioned | Storage cost | Constitutional VDF |
| **Waste** | By design | Low | By design | None |

### 12.2 What Each Primitive Proves

- **PoW:** "I burned this much electricity."
- **PoSpace:** "I dedicated this much storage."
- **PoStake:** "I locked this much capital."
- **Fungible VDF:** "I existed for this much time."

You cannot burn more time. You cannot dedicate more time. You cannot
lock more time. Time passes at the same rate for everyone. The only
thing you can do is prove you were there for it.

---

## 14. Machine-Checked Proofs

The mathematical properties of Fungible VDF are not informal arguments
or "we believe this is correct" hand-waves. They are machine-checked
by the Lean 4 theorem prover.

### 13.1 VDF Properties

| Theorem | Statement |
|---|---|
| `vdf_monotone` | More ticks produce more or equal credits |
| `vdf_strictMono` | With at least one active node, credits strictly increase |
| `vdf_additive` | Time segments compose correctly |

### 13.2 Fungibility Properties

| Theorem | Statement |
|---|---|
| `vdf_split_fungible` | Splitting preserves total VDF work |
| `vdf_merge_fungible` | Merging preserves total VDF work |

### 13.3 Conservation Properties

| Theorem | Statement |
|---|---|
| `split_conserves` | Node count conserved across split |
| `merge_conserves` | Node count conserved across merge |
| `credits_split_conserves` | Credit totals conserved across split |
| `credits_merge_conserves` | Credit totals conserved across merge |

### 13.4 Merkle Properties

| Theorem | Statement |
|---|---|
| `merkle_completeness` | Round-trip prove/verify always succeeds |

### 13.5 SPIRAL Shell Geometry

| Formula | Domain | Proven |
|---|---|---|
| `3n^2 + 3n + 1` | 2D cumulative shell capacity | Yes |
| `6n^3 + 9n^2 + 5n + 1` | 3D cumulative shell capacity | Yes |

The shell geometry includes a complete geometric decomposition proof
for the 3D formula in the Lean codebase (`Shell3D.lean`).

---

## 15. Implementation

### 14.1 Crate Structure

- **`lagoon-vdf`** — Standalone VDF library: `VdfChain` (Blake3
  sequential chain), `MerkleTree`, `VdfProof` (Fiat-Shamir ZK),
  `ChallengeResponse`. No async runtime dependency.
- **`lagoon-server`** — IRC mesh server with embedded VDF engine
  ticking at 10 Hz, MESH protocol for peer state exchange, and
  SPIRAL topology.

### 14.2 Wire Protocol

VDF state is exchanged over an IRC-based mesh protocol:

| Message | Purpose |
|---|---|
| `MESH HELLO` | Peer announcement with VDF state (genesis, hash, step count) |
| `MESH PEERS` | Gossip propagation of known peers and their VDF states |
| `MESH VDFPROOF_REQ` | Liveness challenge: "prove you are alive" |
| `MESH VDFPROOF` | ZK proof response |

### 14.3 Simulation

The `downward-spiral` project is a 3D simulation of cooperative VDF
on a hex-z SPIRAL lattice, with wgpu visualization, gamepad support,
and a scenario animator that produces machine-verifiable JSON output
with ZK proofs at every state transition.

The simulation implements:
- Independent VDF chains per swarm (Blake3, tick at configurable rate)
- Round-robin credit distribution within swarms
- Split by random 3D plane (both sub-swarms get fresh SPIRAL ordering)
- VDF-weighted merge (heavier swarm gets inner SPIRAL slots)
- Topology recomputation on every split and merge
- ZK proof generation and verification at every state transition
- Stress tests verifying conservation invariants under random operations

Five built-in scenarios demonstrate: genesis and first split, split
cascades, complete fragmentation and recovery (Big Bang / Big Crunch),
VDF fungibility proof, and dynamic growth with node addition and
removal.

### 14.4 Deployment

Lagoon is deployed as an anycast mesh with nodes across multiple
regions. Each node runs an embedded Yggdrasil overlay for NAT-free
global reachability. The VDF engine, ZK proof system, and MESH
protocol are operational in production. The cooperative VDF model and
difficulty ceiling are the target architecture.

### 14.5 Python Verification

A comprehensive Python verification script (`docs/verify_claims.py`)
independently validates every mathematical claim in this paper:
Blake3 chain construction, genesis determinism, Merkle tree
round-trips, Fiat-Shamir challenge derivation, ZK proof verification,
SPIRAL shell geometry formulas, and fungibility conservation. All
claims pass verification.

---

## 16. Evolution Path

The transition from current implementation to full Fungible VDF is
incremental:

1. **Current (deployed).** Independent VDF chains per node. ZK proof
   liveness challenges. VDF state gossip via MESH protocol.

2. **Cooperative VDF.** Nodes within a SPIRAL swarm contribute to a
   shared chain (round-robin credit assignment, simulated in
   `downward-spiral`). One chain per swarm instead of one per node.

3. **Full Fungible VDF.** Cooperative chains + attestation-based
   liveness + difficulty ceiling. One VDF computation per checkpoint +
   N signatures. Energy cost approaches the thermodynamic minimum.

Each step removes waste while preserving the core properties:
fungibility across partitions, Any Point Of Entry, Constitutional VDF
for Sybil resistance, and acceleration resistance.

---

## 17. Conclusion

Fungible VDF replaces authority with physics. Time passes. Sequential
computation proceeds. The chain advances. This cannot be stopped,
forged, or centralized.

The key insight is fungibility: VDF work combines additively across
merges and is conserved across splits. The total weight of a swarm is
the sum of all elapsed time across its members. Partitions are not
crises — they are the mesh temporarily existing as multiple swarms
that merge seamlessly when connectivity returns. No work is lost. No
side is wrong.

Sybil resistance is constitutional. The VDF chain is sequential and
non-parallelizable. Every identity starts at zero. Every identity
advances at the same rate. There is no shortcut, no hardware
advantage, no way to pre-compute weight. The cost of a Sybil attack
is exactly the cost of honest participation for the same duration.

The difficulty ceiling inverts the economics of consensus. Where every
previous system incentivizes maximizing resource expenditure, Fungible
VDF's Nash equilibrium is minimum energy. The rational strategy and
the efficient strategy are the same: lean against the wall with
minimum force.

Combined with deterministic topology (SPIRAL) and zero-knowledge
verification, Fungible VDF achieves Any Point Of Entry: any node is a
valid entry point for new members, with no bootstrap servers, directory
authorities, or DNS chokepoints. To censor the network, an adversary
must block every single node. Missing one is enough.

Bitcoin is proof of computation over time. Chia is proof of space over
time. Fungible VDF is proof of time over computation. Time is the one
resource you cannot fake, stockpile, accelerate, or centralize.
Existence is the credential.

The mathematical foundations are machine-checked in Lean 4. The
dynamics are simulated with ZK proofs at every state transition. The
VDF engine and ZK proof system are deployed in production.

Self-coordinating distributed systems that require no consensus, no
leaders, no quorum, and no distinguished infrastructure are possible.
Fungible VDF provides the mechanism.

---

## References

1. Boneh, D., Bonneau, J., Bunz, B., and Fisch, B. "Verifiable Delay
   Functions." CRYPTO 2018.
2. Wesolowski, B. "Efficient Verifiable Delay Functions." EUROCRYPT
   2019.
3. Pietrzak, K. "Simple Verifiable Delay Functions." ITCS 2019.
4. Rivest, R., Shamir, A., and Wagner, D. "Time-lock Puzzles and
   Timed-release Crypto." 1996.
5. Mahmoody, M., Moran, T., and Vadhan, S. "Publicly Verifiable Proofs
   of Sequential Work." ITCS 2013.
6. Cohen, B. and Pietrzak, K. "Simple Proofs of Sequential Work."
   EUROCRYPT 2018.
7. Lamport, L. "The Part-Time Parliament." ACM TOCS, 1998.
8. Ongaro, D. and Ousterhout, J. "In Search of an Understandable
   Consensus Algorithm." USENIX ATC, 2014.
9. Castro, M. and Liskov, B. "Practical Byzantine Fault Tolerance."
   OSDI, 1999.
10. Nakamoto, S. "Bitcoin: A Peer-to-Peer Electronic Cash System."
    2008.
11. de Moura, L. and Ullrich, S. "The Lean 4 Theorem Prover and
    Programming Language." CADE, 2021.
12. Cohen, B. "Chia Network: A Blockchain Based on Proofs of Space and
    Time." 2017.
