# SUPERSEDED — See FUNGIBLE_VDF_PAPER.md

This document has been merged into the unified Fungible VDF paper at
`docs/FUNGIBLE_VDF_PAPER.md`. All concepts (difficulty ceiling, Ohm's
Law analogy, Nash equilibrium, attestation-based liveness) are now
sections of the unified paper under the "Fungible VDF" name.

---

# Verifiable Inverse Delay Function: Proof of Time (ARCHIVED)

**Authors:** Wings (Riff Labs)
**Date:** February 2026
**Reference Implementation:** Lagoon (https://github.com/riffcc/lagoon)

---

## Abstract

We introduce the Verifiable Inverse Delay Function (VIDF), a
cryptographic primitive that inverts the relationship between
computation and time in distributed consensus. Where proof of work
treats time as the output of computation (more compute = more blocks),
VIDF treats time as the constant and computation as what you minimize.
One sequential VDF computation per checkpoint. One Ed25519 signature
per node per checkpoint. Nothing else. The energy budget of the entire
network approaches the thermodynamic minimum: the cost of proving time
passed plus the cost of proving you exist.

The key mechanism is a **difficulty ceiling** — the inverse of every
blockchain's difficulty target. Where a difficulty target sets a floor
("you must do at least this much work"), a difficulty ceiling sets a
cap ("you may do at most this much work"). Excess computation is not
rewarded. It is ignored. The Nash equilibrium of a VIDF network is
minimum energy expenditure.

Bitcoin is proof of computation over time. Chia is proof of space over
time. VIDF is proof of time over computation. Time is the one resource
you cannot fake, stockpile, accelerate, or centralize. Existence is the
credential.

---

## 1. The Problem with Existing Primitives

Every consensus mechanism wastes something:

**Proof of Work** (Bitcoin): Wastes energy. More computation = more
blocks. Miners race to burn electricity. The difficulty adjusts to
ensure a constant block time, but the energy cost scales with network
hashrate. A faster GPU finds blocks faster. The scarce resource is
electricity.

**Proof of Space** (Chia): Wastes hardware. More storage = more plot
wins. Farmers race to fill disks. SSDs burn out. The scarce resource
is disk space. Chia's insight was "what if we waste storage instead of
electricity." Still wasteful — people bought petabytes of SSDs and
destroyed them.

**Proof of Stake**: Wastes capital. More tokens locked = more
validation power. Creates plutocracy. The scarce resource is money.

**VDFs** (Boneh et al., 2018): Resist parallelism but not faster
sequential hardware. A faster CPU computes the chain faster. The
computation is minimal but not minimized.

All of these share a flaw: **they incentivize acquiring more of
something** — more hashrate, more storage, more tokens, faster CPUs.
The network's security comes from waste. The cost of attack is the cost
of out-wasting the honest participants.

VIDF asks: what if the scarce resource isn't anything you provide, but
the one thing you can't fake? **Elapsed time.**

---

## 2. The Primitive

### 2.1 VDF vs VIDF

A Verifiable Delay Function proves "this took at least T time."
Difficulty is fixed. More compute doesn't help. The delay is the point.

A Verifiable **Inverse** Delay Function proves "this took exactly T
time and it cost us almost nothing." Difficulty is inverse to
participation. More nodes means less work per node. The minimum delay
is the point — and the function actively seeks it.

```
VDF:   cost_per_node = constant
       cost_total    = O(N) or O(1) depending on construction
       time          = fixed

VIDF:  cost_per_node = O(1/N)
       cost_total    = O(1)
       time          = fixed
```

Total cost of the network is constant regardless of size. Ten nodes or
ten million. The function consumes the same total energy. It divides it
among more participants as the network grows.

### 2.2 Core Construction

A VIDF checkpoint consists of two components:

```
checkpoint[n] = (
    vdf_step:    VDF(checkpoint[n-1].vdf_step),
    attestations: [sig_1, sig_2, ..., sig_k]
)
```

**Component 1: The VDF step.** A single sequential hash computation.
`h_{n} = Blake3(h_{n-1})`. Cannot be parallelized. Cannot be
accelerated by adding hardware. Calibrated to take 10 seconds on the
fastest available sequential hardware. This is the proof that time
passed. One computation. One node produces it.

**Component 2: The attestations.** Each node in the network signs the
checkpoint: "I observed checkpoint N. I am alive." Ed25519 signature.
Microseconds to produce. Negligible energy. This is the proof that
nodes are present.

That's it. One VDF computation plus N signatures. Everything else is
waste.

### 2.3 VDF Producer Selection

The VDF producer role is not assigned by leader election (requires
consensus), random selection (requires agreed randomness), or fixed
rotation (requires coordination).

Nodes volunteer to produce the VDF step. The network naturally converges
on whoever can produce it fastest with least marginal cost — a node
that is already running, already online, already idle between real
tasks. The VDF step costs it nearly nothing. It was going to burn those
CPU cycles anyway.

Once a valid step is published, all other nodes can verify it instantly
(the VDF is efficiently verifiable) and begin attesting. No wasted
duplicate computation, because the VDF is sequential — once step N is
published, computing it again is pointless.

If the current producer goes offline mid-step, other nodes that are
also computing the step complete it. There is no single point of
failure. First valid step wins.

### 2.4 Energy Budget

For a network of N nodes:

| Component | Cost | Scales with |
|---|---|---|
| VDF computation | 1 sequential hash chain (10s) | Nothing (constant) |
| Attestations | N Ed25519 signatures | O(N), but each is microseconds |
| **Total** | **One VDF + N signatures** | **O(N) trivial operations** |

Compare to Bitcoin (N nodes): O(N) parallel hash computations at
maximum hardware throughput, continuously, with difficulty scaled to
ensure only one block per 10 minutes. The energy ratio between VIDF and
PoW is not a percentage improvement. It is an inversion.

---

## 3. The Difficulty Ceiling

This is the mechanism that makes VIDF fundamentally different from every
blockchain ever built.

### 3.1 Floors vs Ceilings

Every blockchain has a **difficulty floor** — a target that miners must
reach. You must do *at least this much work* to produce a valid block.
Nodes compete to exceed the floor. The floor rises. Energy consumption
spirals. It is an arms race by construction.

VIDF uses a **difficulty ceiling** — an adaptive cap on how much work
any node may contribute per checkpoint. Any computation exceeding the
cap is discarded. Not invalid — just ignored. You computed more than
you needed to. The network doesn't reward it.

```
ceiling = total_work_needed / known_network_size
```

Adaptive. As nodes join, the ceiling drops. Each node does less. As
nodes leave, the ceiling rises. Remaining nodes do more. The total work
stays constant. The checkpoint cadence stays constant.

### 3.2 Enforcement

In a P2P network, the ceiling is enforceable because peers can observe
each other. SPIRAL neighbors see your attestations. If you submit work
above the ceiling, they reject it. Not because a central authority says
so — because the ceiling is computable from the network state that
every node already has.

### 3.3 The Solid Wall

A difficulty target is a hole you have to dig. Deeper hole = more
valid. Everyone digs as fast as they can. The hole serves no purpose.
It is just proof you dug.

A difficulty ceiling is a wall. You push against it. It doesn't move.
Push harder — still doesn't move. Bring a thousand friends to push —
it still doesn't move. So you stop pushing. You lean against it. You
put exactly enough weight on it to prove you're standing there. That's
the minimum. That's the optimum. They're the same thing.

**The wall is time.** Ten seconds. It doesn't care how strong you are.

### 3.4 Nash Equilibrium

A difficulty target says "prove you burned this much energy." The
rational response is to burn as much energy as possible.

A difficulty ceiling says "stop burning energy, we have enough." The
rational response is to burn as little as possible.

**The economically rational behavior and the ecologically optimal
behavior are identical.** You cannot gain advantage by doing more work.
You can only waste your own electricity. The Nash equilibrium of a VIDF
network is minimum energy expenditure — not because participants are
altruistic, but because the wall doesn't move.

---

## 4. Properties

### 4.1 Proof of Time

The VDF checkpoint proves that 10 seconds of wall-clock time have
elapsed since the previous checkpoint. This proof is:

- **Unforgeable.** Sequential hashing cannot be accelerated. You cannot
  produce checkpoint N+1 without first completing checkpoint N.
- **Hardware-resistant.** A GPU farm computes one Blake3 step in the
  same wall time as a single core. Parallelism does not help.
- **Unincentivizable.** There is nothing to gain from faster hardware.
  The step takes 10 seconds. Always. A Raspberry Pi and a data center
  produce the same evidence.

### 4.2 Proof of Presence

The attestation set proves which nodes were alive at checkpoint N. This
is not proof of work. Not proof of stake. Not proof of storage. Just
proof of presence. "I was here. I saw the checkpoint. Here is my
signature."

The per-node cost of proving presence: one Ed25519 signature per
checkpoint. Constant. Does not increase with network size. Does not
increase with checkpoint frequency. Does not increase with anything.

### 4.3 Inverse Difficulty

In Bitcoin, difficulty increases as the network grows:

```
more miners → more hashrate → higher difficulty → same block time
                                                  → more energy wasted
```

In VIDF, per-node cost *decreases* as the network grows:

```
more nodes → lower ceiling per node → same checkpoint time
           → less work per participant → same total energy
```

The VDF cost is O(1). The attestation cost is one signature per node.
The total network energy cost is essentially constant — it does not
scale with participation. Adding 10,000 nodes to the network costs
10,000 additional Ed25519 signatures per checkpoint. That's it.

### 4.4 Acceleration Resistance

**Definition (Acceleration Resistance).** A distributed timing primitive
is acceleration-resistant if for any number of participants `N` and any
amount of computational power `P` available to those participants, the
time between successive outputs is bounded below by a constant `T` that
depends on neither `N` nor `P`.

VIDF satisfies this. The VDF step takes 10 seconds. One node or ten
thousand. One CPU or ten thousand GPUs. 10 seconds. The "resistance"
increases proportionally to the "current" — Ohm's Law for computation.

---

## 5. Liveness and Ghost Pruning

### 5.1 Attestation-Based Liveness

Ghost node pruning becomes trivial:

```
Checkpoint N:   attestations from {A, B, C, D, E}
Checkpoint N+1: attestations from {A, B, C, E}
Checkpoint N+2: attestations from {A, B, C, E}
```

Node D did not attest at checkpoints N+1 or N+2. D is dead. Prune.
SPIRAL slot freed. Topology recomputes.

No TTL timer. No "last seen" timestamp. No heartbeat protocol. No
synchronized clocks. No proof-challenge-response. Just: did you sign
the checkpoint? No? You're gone.

### 5.2 Grace Period

A configurable number of missed checkpoints (e.g., 3) before pruning.
This handles transient network delays without false evictions. The grace
period is measured in checkpoints, not seconds — the VDF provides the
clock.

### 5.3 Partition Behavior

Network splits. London can't reach Tokyo.

- London clump (900 nodes): produces checkpoints every 10s. 900
  attestations per checkpoint. VDF cost: one computation. Difficulty
  ceiling per node: low.
- Tokyo clump (3 nodes): produces checkpoints every 10s. 3 attestations
  per checkpoint. VDF cost: one computation. Difficulty ceiling per
  node: higher (fewer nodes to share the minimum work).

Both clumps produce checkpoints at the same rate. Both are valid. The
per-node cost in the Tokyo clump is higher — with fewer nodes, the
ceiling per node rises. But the VDF cost is still just one computation.
The economic incentive is to be in the larger clump. Rejoin as fast as
you can.

On rejoin: both chains are the same length (same cadence). The
attestation history shows which nodes were in which clump. Merge the
topologies. All attestations from both sides are valid. No conflict.
No rollback.

---

## 6. The Ohm's Law Analogy

The electrical metaphor is exact:

```
Voltage (V) = Current (I) × Resistance (R)
Time    (T) = Compute (C) × Difficulty (D)
```

In a resistor, more current does not increase voltage — it increases
heat dissipation. The voltage drop is constant.

In VIDF, more compute does not decrease checkpoint time — it hits the
difficulty ceiling. The 10-second interval is constant.

| Electrical | VIDF |
|---|---|
| Voltage (constant) | Checkpoint interval (10s, constant) |
| Current (variable) | Compute power thrown at the network |
| Resistance (adapts) | Difficulty ceiling (adapts to network size) |
| Heat (dissipated) | Wasted computation (discarded above ceiling) |

You can push as much current as you want through the network. The
resistance increases proportionally. The voltage — the elapsed time —
does not change. Push harder, and the wall pushes back.

---

## 7. Comparison

| | Bitcoin (PoW) | Chia (PoSpace) | VIDF (PoTime) |
|---|---|---|---|
| **Scarce resource** | Electricity | Storage | Time |
| **Can be stockpiled?** | Yes (hashrate) | Yes (plots) | No |
| **Can be accelerated?** | Yes (faster ASICs) | Yes (faster I/O) | No |
| **Can be parallelized?** | Yes (mining pools) | Yes (plot farms) | No |
| **Incentivizes hoarding?** | Yes (hardware) | Yes (disks) | No |
| **Difficulty mechanism** | Floor (target) | Floor (target) | Ceiling (cap) |
| **Nash equilibrium** | Max energy | Max storage | Min energy |
| **Energy at scale** | Grows with network | Grows with network | Constant |
| **Per-node cost** | Maximum hashrate | Maximum storage | One signature |
| **Waste** | By design | By design | None |
| **Partition behavior** | Fork, discard shorter | Fork, discard shorter | Both valid, merge |

### 7.1 What Each Primitive Proves

- **PoW:** "I burned this much electricity."
- **PoSpace:** "I dedicated this much storage."
- **PoStake:** "I locked this much capital."
- **VIDF:** "I existed for this much time."

You cannot burn more time. You cannot dedicate more time. You cannot
lock more time. Time passes at the same rate for everyone. The only
thing you can do is prove you were there for it.

---

## 8. Formal Properties

### 8.1 Checkpoint Validity

A checkpoint `C_n` is valid if and only if:

1. `C_n.vdf_step = VDF(C_{n-1}.vdf_step)` — sequential dependency
2. For each attestation `sig_i` in `C_n.attestations`:
   `verify(pubkey_i, sig_i, hash(C_n.vdf_step || n))` — valid signature
3. `n = C_{n-1}.n + 1` — monotonic sequence

### 8.2 Difficulty Ceiling Validity

An individual node's contribution `w_i` to checkpoint `C_n` is valid
if and only if:

```
w_i <= total_work_required / |known_peers_at_C_{n-1}|
```

Contributions exceeding the ceiling are discarded by verifying peers.

### 8.3 Fungibility

VIDF checkpoints are fungible:

- **Split conservation:** If a clump splits into two, both sub-clumps
  produce valid checkpoint chains independently.
- **Merge conservation:** When clumps rejoin, both checkpoint histories
  are valid. Attestations from both sides are preserved.
- **No work lost:** Every VDF computation and every attestation from
  every partition is retained in the merged history.

### 8.4 Any Point Of Entry

VIDF satisfies APE (Any Point Of Entry): any node with a valid
checkpoint chain is a complete entry point. A new node connects,
receives the chain, verifies the VDF steps, checks the attestation
signatures, and begins participating. No bootstrap server. No directory
authority. No permission required.

---

## 9. From VDF to VIDF: The Evolution

The path from existing primitives to VIDF:

1. **VDF** (Boneh et al.): Sequential computation proves delay. But
   only one node computes. No participation proof for the rest.

2. **Fungible VDF** (this project): Independent VDF chains per node.
   Work merges additively across partitions. But each node runs its own
   chain — redundant computation.

3. **Resistive Hash** (intermediate idea): VDF-gated checkpoints with
   parallel proof-of-work for credit distribution. Difficulty scales
   inversely with network size. But the PoW component is still waste.

4. **VIDF**: The minimal construction. One VDF. N signatures. A
   difficulty ceiling instead of a floor. The PoW is gone. The per-node
   computation is one signature. The total energy approaches the
   theoretical minimum for proving time and presence.

Each step removes waste. VIDF sits on the thermodynamic floor: you
cannot prove time passed with less than one sequential computation, and
you cannot prove a node is alive with less than one signature. That is
the lower bound, and VIDF achieves it.

---

## 10. Implementation Considerations

### 10.1 VDF Calibration

The VDF step time (10 seconds) should be calibrated to the fastest
known sequential hardware. If the fastest available CPU can compute one
Blake3 step in 10 nanoseconds, then `10s / 10ns = 10^9` iterations per
step. The calibration is a network parameter, adjustable if hardware
capabilities change dramatically.

### 10.2 Attestation Propagation

Attestations must reach the next VDF producer before the step completes.
With a 10-second window and modern network latencies (sub-second for
global propagation), this is comfortable. Attestations can be gossiped
through the mesh and aggregated.

### 10.3 Attestation Aggregation

For large networks, individual attestations can be aggregated using
BLS signature aggregation or similar schemes, reducing the per-
checkpoint attestation size from O(N) signatures to O(1) aggregate
signature. The liveness guarantee is preserved — each node's
contribution to the aggregate is verifiable.

### 10.4 Ceiling Adaptation

The difficulty ceiling adapts to the known network size at the previous
checkpoint. This is stable because:

- Network size changes slowly relative to the checkpoint cadence.
- The ceiling is computed from attestation counts, which are
  self-reported and verifiable.
- Sybil attacks (creating fake nodes to lower the ceiling) don't help
  because the ceiling is per-node — adding fake nodes just means more
  nodes share the same fixed total work. The attacker gains nothing.

---

## 11. Relationship to Lagoon

VIDF is the target consensus primitive for Lagoon's mesh. The current
implementation uses independent VDF chains per node (Fungible VDF).
The evolution path:

1. **Current:** Independent VDF chains + ZK proof liveness (deployed)
2. **Next:** Cooperative VDF within SPIRAL clumps (Fungible VDF merge)
3. **Target:** VIDF — one VDF per clump checkpoint + attestations +
   difficulty ceiling

The transition is incremental. Each step removes waste while preserving
the core properties: fungibility across partitions, Any Point Of Entry,
and acceleration resistance.

---

## 12. Conclusion

Proof of Work proved that decentralized consensus is possible. Proof of
Space proved that the scarce resource doesn't have to be electricity.
Proof of Time proves that the scarce resource doesn't have to be
anything you can buy.

Time passes at the same rate for everyone. A Raspberry Pi and a data
center experience the same 10 seconds. You cannot stockpile time. You
cannot accelerate it. You cannot buy more of it. The only thing you can
do is prove you were there while it happened.

The difficulty ceiling is what makes it real. Every previous system uses
a difficulty floor — push harder to prove more. VIDF uses a ceiling —
the network tells you to stop. The rational choice and the efficient
choice are the same choice: do the minimum. Lean against the wall.

VIDF is proof of existence. One sequential computation proves time
passed. One signature proves you were there. The energy cost of
securing the network approaches zero. The cost of attacking it
approaches infinity — you would need to control time itself.

Every previous consensus mechanism answers the question "who did the
most work?" VIDF asks a different question: "who was here?"

That is enough.

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
