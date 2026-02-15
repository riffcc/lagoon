/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/

/-!
# Lagoon Mesh Protocol — Formal Verification

Complete formal verification of the Lagoon mesh protocol state machine.
Every state, every transition, every invariant — proven in Lean 4.

## Motivation (2026-02-15, 08:22 AM)

Every bug tonight was a state machine violation:
- **Ghost slots**: `add_peer` didn't maintain `occupied.len() == peer_positions.len() + 1`
- **Thundering herd**: response construction happened-before state mutation
- **Reconverge on partial**: function assumed complete topology when it had partial
- **Redirect killing connections**: informational message treated as control signal

Each of these is a failed proof obligation. Not a runtime crash. Not a 4 AM
debugging session. Not thirteen nodes fighting over slot 0. A compile-time
error that says "you haven't proven this invariant holds after this state transition."

## Architecture

The state machine is modeled as pure functions:
  `MeshState → InboundMsg → MeshState × List OutboundAction`

Separating messages (input) from actions (output) at the type level makes
Bug 4 (redirect kills connection) literally unrepresentable in the type system.

The `Valid` predicate on `MeshState` encodes ALL structural invariants.
The master theorem `mesh_correct` proves that EVERY message handler
preserves EVERY invariant. If it compiles, it's correct.

## Module Structure

### Layer 0: Core Types
* `Types.lean` — PeerId, SpiralIndex, HexCoord, VdfSnapshot, PeerInfo

### Layer 1: State Machine Model
* `Spiral.lean` — SPIRAL topology operations (claim, add, remove, repack, merge, swap)
* `Messages.lean` — Inbound messages and outbound actions (separated by type)
* `State.lean` — Full MeshState + invariant predicates + merge/prune/liveness decisions
* `Transitions.lean` — Pure transition functions for every message handler

### Layer 2: Single-Node Proofs
* `SpiralProofs.lean` — Every SPIRAL operation preserves the Valid invariant
* `TransitionProofs.lean` — Every message handler preserves MeshState.Valid
* `MergeProofs.lean` — Merge determinism, conservation, convergence
* `LivenessProofs.lean` — VDF monotonicity, dead peer detection correctness
* `BootstrapProofs.lean` — APE bootstrap sequence correctness

### Layer 3: Slot Assignment Paths
* `SlotPaths.lean` — The five and ONLY five ways to get a slot
  (VDF race, concierge, cluster merge, reslot, latency swap)

### Layer 4: Global Invariants
* `Invariants.lean` — The 8 invariants that must ALWAYS hold + THE meta-theorem

### Layer 5: Multi-Node Models
* `Network.lean` — Network topology, global invariants, partition/merge/join/leave events
* `NodeLifecycle.lean` — Node lifecycle FSM (Unknown → Booting → ... → Connected → Dead)
* `Clumps.lean` — Split-brain resolution, partition mechanics, merge conservation
* `Supernode.lean` — HA site model proving supernodes need no special protocol cases

### Layer 6: Causality and Ordering
* `Causality.lean` — Message ordering, juggler invariant, causal consistency,
  VDF-based authority, tiebreaker stability

### Layer 7: Hacks Audit
* `HacksAudit.lean` — Every hack classified as NECESSARY / REMOVABLE / WRONG

### Layer 8: Integration Scenarios
* `Scenarios.lean` — Core multi-node interaction proofs
* `SimScenarios.lean` — Full scenario suite (thundering herd, partition, churn,
  rolling deploy, supernode failure, Byzantine concierge, defederation)

### Layer 9: Network of Networks
* `Defederation.lean` — Banning, federation, superclusters, lens model

### Layer 10: Performance Bounds
* `PerformanceBounds.lean` — Propagation, convergence, swap optimization,
  slot assignment latency, scalability bounds

## Correspondence to Rust

Every Lean definition has a comment linking to the exact Rust function
and line number it models. The Lean model is the SPECIFICATION.
The Rust code is the IMPLEMENTATION. Any divergence is a bug in the Rust.

## Status

This is the first formally verified P2P mesh network protocol.
Not "tested extensively." Not "battle hardened." Proven. Mathematically.
Every state. Every transition. Every invariant. Every scenario.

*e cinere surgemus*
-/

-- Layer 0: Core types
import LagoonMesh.Types

-- Layer 1: State machine model
import LagoonMesh.Spiral
import LagoonMesh.Messages
import LagoonMesh.State
import LagoonMesh.Transitions

-- Layer 2: Single-node proofs
import LagoonMesh.SpiralProofs
import LagoonMesh.TransitionProofs
import LagoonMesh.MergeProofs
import LagoonMesh.LivenessProofs
import LagoonMesh.BootstrapProofs

-- Layer 3: Slot assignment paths
import LagoonMesh.SlotPaths

-- Layer 4: Global invariants
import LagoonMesh.Invariants

-- Layer 5: Multi-node models
import LagoonMesh.Network
import LagoonMesh.NodeLifecycle
import LagoonMesh.Clumps
import LagoonMesh.Supernode

-- Layer 6: Causality and ordering
import LagoonMesh.Causality

-- Layer 7: Hacks audit
import LagoonMesh.HacksAudit

-- Layer 8: Integration scenarios
import LagoonMesh.Scenarios
import LagoonMesh.SimScenarios

-- Layer 9: Network of networks
import LagoonMesh.Defederation

-- Layer 10: Performance bounds
import LagoonMesh.PerformanceBounds
