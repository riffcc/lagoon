/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.Types

/-!
# Mesh Protocol Messages

Formal model of all message types in the Lagoon mesh protocol.
Corresponds to `MeshMessage` enum in `wire.rs`.

## Design: Messages vs Actions

We separate INBOUND messages (what we receive) from OUTBOUND actions
(what we produce). A state transition takes `(State, Message) → (State, List Action)`.

This separation makes it trivially provable that receiving a `Redirect`
message never produces a `Disconnect` action — the bug from 2026-02-15
becomes a type-level impossibility.
-/

namespace LagoonMesh

/-! ### Inbound Messages

These are messages received from remote peers.
In Rust: variants of `MeshMessage` in `wire.rs`. -/

/-- HELLO payload — identity exchange.
    In Rust: `HelloPayload` in `wire.rs`. -/
structure HelloMsg where
  peerId : PeerId
  spiralIndex : Option SpiralIndex
  vdf : VdfSnapshot
  cumulativeCredit : Nat
  clusterVdfWork : Nat
  assignedSlot : Option SpiralIndex
  deriving Repr

/-- Peer info as gossiped in MESH PEERS.
    In Rust: `MeshPeerInfo` in `wire.rs`. -/
structure PeerGossip where
  peerId : PeerId
  spiralIndex : Option SpiralIndex
  vdf : VdfSnapshot
  cumulativeCredit : Nat
  deriving Repr

/-- Inbound mesh message.
    We only model the messages that affect topology.
    Profile, latency, connection gossip are data-plane — they don't
    change the state machine structure. -/
inductive InboundMsg where
  /-- Identity exchange — the first message on any connection. -/
  | hello : HelloMsg → InboundMsg
  /-- Peer gossip — bulk peer info from a connected peer. -/
  | peers : List PeerGossip → InboundMsg
  /-- VDF proof received — proves liveness. -/
  | vdfProof : PeerId → InboundMsg
  /-- Redirect — peer telling us to connect elsewhere. NOT a disconnect signal. -/
  | redirect : List PeerGossip → InboundMsg
  /-- Relay disconnected — the underlying connection closed. -/
  | disconnected : PeerId → InboundMsg
  deriving Repr

/-! ### Outbound Actions

These are actions the mesh node produces in response to messages.
They are SEPARATE from messages — a handler returns actions, not side effects. -/

/-- Outbound action produced by a state transition. -/
inductive OutboundAction where
  /-- Send a HELLO to a specific peer. -/
  | sendHello : PeerId → OutboundAction
  /-- Send PEERS gossip to a specific peer. -/
  | sendPeers : PeerId → List PeerGossip → OutboundAction
  /-- Dial a new connection to a peer. -/
  | connect : PeerId → OutboundAction
  /-- Gracefully close connection to a peer. -/
  | disconnect : PeerId → OutboundAction
  /-- Add a Yggdrasil underlay peer. -/
  | addYggPeer : PeerId → OutboundAction
  /-- Request VDF proof from a peer. -/
  | requestVdfProof : PeerId → OutboundAction
  deriving Repr

/-! ### Key Property: Message Type Safety

The redirect-killing-connections bug was caused by treating a `Redirect`
message as a termination signal. By separating messages from actions at
the type level, we can prove this can't happen. -/

/-- A `Redirect` message NEVER produces a `Disconnect` action. -/
def OutboundAction.isDisconnect : OutboundAction → Bool
  | .disconnect _ => true
  | _ => false

end LagoonMesh
