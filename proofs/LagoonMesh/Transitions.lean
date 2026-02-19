/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import LagoonMesh.State

/-!
# Mesh Protocol State Transitions

Every state transition modeled as a pure function:
  `MeshState → InboundMsg → MeshState × List OutboundAction`

This is the semantic model of the `tokio::select!` event loop in
`spawn_event_processor()` in `federation.rs`.

## Design: Sequential Message Processing

The Rust code processes messages sequentially within the event loop
(one `RelayEvent` at a time, no concurrent mutation). We model this
directly: each transition reads the CURRENT state and produces the NEXT state.
No interleaving. No races. This is what the code actually does.

## The Four Bug Classes (2026-02-15)

Each transition function is designed to make the corresponding bug class
impossible:

1. **Ghost slots**: `handleHello` calls `addPeer` which maintains the
   SPIRAL invariant. Proven in `SpiralProofs.lean`.

2. **Thundering herd**: `handleHello` writes the concierge slot BEFORE
   returning actions. The next HELLO sees the updated state.

3. **Reconverge on partial**: `handleDisconnected` calls `reconverge`
   only if `ourSlot.isSome`. Encoded as a field of `Valid`.

4. **Redirect kills connection**: `handleRedirect` returns `connect`
   actions, NEVER `disconnect`. Proven in `TransitionProofs.lean`.
-/

namespace LagoonMesh

/-! ### HELLO Handler

In Rust: `RelayEvent::MeshHello` handler in `federation.rs:1111-1640`.

The most complex transition. Handles:
- Self-connection detection
- SPIRAL merge evaluation
- Concierge slot assignment
- APE Yggdrasil peering
- Reciprocal connection
- Dead peer eviction
-/

/-- Handle a HELLO message from a remote peer. -/
def handleHello (s : MeshState) (from_ : PeerId) (hello : HelloMsg)
    : MeshState × List OutboundAction :=
  -- Step 1: Self-connection detection
  if hello.peerId = s.ourId then
    (s, [.disconnect from_])
  else
  -- Step 2: Update known peers
  let peerInfo : PeerInfo := {
    peerId := hello.peerId
    spiralIndex := hello.spiralIndex
    vdf := hello.vdf
    lastVdfAdvance := s.now
    lastSeen := s.now
    isBootstrap := from_ ∈ s.bootstrapPeers
  }
  let s₁ := { s with knownPeers := s.knownPeers.insert hello.peerId peerInfo }
  -- Step 3: Mark as connected
  let relayInfo : RelayInfo := {
    peerId := hello.peerId
    isBootstrap := from_ ∈ s.bootstrapPeers
    helloExchanged := true
  }
  let s₂ := { s₁ with relays := s₁.relays.insert hello.peerId relayInfo }
  -- Step 4: SPIRAL merge evaluation
  let decision := evaluateMerge s₂ hello
  let s₃ := match decision with
    | .vdfRace slot => { s₂ with spiral := s₂.spiral.claimSpecific slot }
    | .concierge slot => { s₂ with spiral := s₂.spiral.claimSpecific slot }
    | .collision weWin =>
      if weWin then s₂  -- we keep our slot
      else
        -- We lose: reslot around winner
        let s' := { s₂ with spiral := s₂.spiral.unclaim }
        match hello.spiralIndex with
        | some theirSlot =>
          let (spiral', _) := s'.spiral.forceAddPeer hello.peerId theirSlot
          { s' with spiral := spiral'.claimPosition }
        | none => { s' with spiral := s'.spiral.claimPosition }
    | .clusterMerge weWin =>
      if weWin then
        -- They merge around us: add them
        match hello.spiralIndex with
        | some slot => { s₂ with spiral := s₂.spiral.addPeer hello.peerId slot }
        | none => s₂
      else
        -- We merge around them: reslot
        let s' := { s₂ with spiral := s₂.spiral.unclaim }
        match hello.spiralIndex with
        | some theirSlot =>
          let (spiral', _) := s'.spiral.forceAddPeer hello.peerId theirSlot
          { s' with spiral := spiral'.claimPosition }
        | none => { s' with spiral := s'.spiral.claimPosition }
    | .noOp =>
      -- Still add the peer's SPIRAL position if known
      match hello.spiralIndex with
      | some slot => { s₂ with spiral := s₂.spiral.addPeer hello.peerId slot }
      | none => s₂
  -- Step 5: Produce actions
  let actions : List OutboundAction := [
    .sendHello hello.peerId,
    .addYggPeer hello.peerId,
    .requestVdfProof hello.peerId
  ]
  -- Step 6: Dial missing SPIRAL neighbors
  let neighborActions := (computeNeighbors s₃.spiral).filterMap fun pid =>
    if s₃.relays.lookup pid = none then some (.connect pid) else none
  -- Step 7: Prune non-SPIRAL relays
  let pruneActions := (computePruneSet s₃).map .disconnect
  (s₃, actions ++ neighborActions ++ pruneActions)

/-! ### PEERS Handler

In Rust: `RelayEvent::MeshPeers` handler in `federation.rs:1642-2058`.
Batch merge of incoming SPIRAL positions. -/

/-- Handle a PEERS gossip message. -/
def handlePeers (s : MeshState) (peers : List PeerGossip)
    : MeshState × List OutboundAction :=
  -- Process each peer
  let s' := peers.foldl (fun acc pg =>
    -- Skip self
    if pg.peerId = acc.ourId then acc
    -- Skip if defederated (modeled as: always accept for now)
    else
    -- Update known peers
    let info : PeerInfo := {
      peerId := pg.peerId
      spiralIndex := pg.spiralIndex
      vdf := pg.vdf
      lastVdfAdvance := 0  -- unknown until VDF proof received
      lastSeen := acc.now
      isBootstrap := false
    }
    let acc₁ := { acc with knownPeers := acc.knownPeers.insert pg.peerId info }
    -- SPIRAL merge: add their slot if known and free
    match pg.spiralIndex with
    | none => acc₁
    | some slot =>
      -- Check for collision
      match acc₁.spiral.slotToPeer.lookup slot with
      | none =>
        -- Slot free: add peer
        if acc₁.spiral.ourSlot = some slot then acc₁  -- our slot, skip
        else { acc₁ with spiral := acc₁.spiral.addPeer pg.peerId slot }
      | some existingPeer =>
        -- Slot occupied: compare credit, higher wins
        if pg.cumulativeCredit > (match acc₁.knownPeers.lookup existingPeer with
          | some ei => ei.vdf.cumulativeCredit
          | none => 0)
        then
          let (spiral', _) := acc₁.spiral.forceAddPeer pg.peerId slot
          { acc₁ with spiral := spiral' }
        else acc₁  -- existing peer wins
  ) s
  -- Dial missing SPIRAL neighbors
  let neighborActions := (computeNeighbors s'.spiral).filterMap fun pid =>
    if s'.relays.lookup pid = none then some (.connect pid) else none
  (s', neighborActions)

/-! ### VDF Proof Handler

In Rust: `RelayEvent::MeshVdfProof` handler in `federation.rs:2095-2140`.
Updates the liveness timestamp. -/

/-- Handle a VDF proof from a peer. -/
def handleVdfProof (s : MeshState) (from_ : PeerId)
    : MeshState × List OutboundAction :=
  -- Update last_vdf_advance timestamp
  match s.knownPeers.lookup from_ with
  | none => (s, [])  -- unknown peer, ignore
  | some info =>
    let info' := { info with lastVdfAdvance := s.now }
    ({ s with knownPeers := s.knownPeers.insert from_ info' }, [])

/-! ### Redirect Handler

In Rust: `MeshMessage::Redirect` handler.

CRITICAL: This handler NEVER produces a Disconnect action.
A redirect is informational — "here are more peers you might want to connect to."
It does NOT mean "disconnect from me." -/

/-- Handle a Redirect message. Returns ONLY connect actions. -/
def handleRedirect (s : MeshState) (peers : List PeerGossip)
    : MeshState × List OutboundAction :=
  -- Update known peers with the redirect info
  let s' := peers.foldl (fun acc pg =>
    if pg.peerId = acc.ourId then acc
    else
      let info : PeerInfo := {
        peerId := pg.peerId
        spiralIndex := pg.spiralIndex
        vdf := pg.vdf
        lastVdfAdvance := 0
        lastSeen := acc.now
        isBootstrap := false
      }
      { acc with knownPeers := acc.knownPeers.insert pg.peerId info }
  ) s
  -- Connect to redirected peers (never disconnect!)
  let connectActions := peers.filterMap fun pg =>
    if pg.peerId = s'.ourId then none
    else if s'.relays.lookup pg.peerId ≠ none then none  -- already connected
    else some (.connect pg.peerId)
  (s', connectActions)

/-! ### Disconnected Handler

In Rust: `RelayEvent::Disconnected` handler in `federation.rs`.
Remove relay, remove SPIRAL peer, reconverge. -/

/-- Handle a relay disconnection. -/
def handleDisconnected (s : MeshState) (peerId : PeerId)
    : MeshState × List OutboundAction :=
  -- Remove relay
  let s₁ := { s with relays := s.relays.erase peerId }
  -- Remove from SPIRAL topology
  let s₂ := { s₁ with spiral := s₁.spiral.removePeer peerId }
  -- Reconverge (only if we have a position)
  let s₃ := { s₂ with spiral := s₂.spiral.reconverge }
  -- Dial missing SPIRAL neighbors
  let neighborActions := (computeNeighbors s₃.spiral).filterMap fun pid =>
    if s₃.relays.lookup pid = none then some (.connect pid) else none
  (s₃, neighborActions)

/-! ### Tick Handler

In Rust: the periodic VDF challenge interval (5s) and dead peer eviction.

BUG FIX APPLIED: This handler now emits `cancelConnect` for every peer it evicts.
Previously the Rust code had no mechanism to cancel connection tasks when their
target peer was evicted. That produced the connection storm observed in production
(attempt=925350 against a dead peer). -/

/-- Handle a periodic tick (advance time, evict dead peers, cancel stale connects). -/
def handleTick (s : MeshState) (newTime : Timestamp)
    : MeshState × List OutboundAction :=
  let s₁ := { s with now := newTime }
  -- Evict dead peers, collecting cancelConnect actions for each one.
  -- A peer is dead if VDF silent for VDF_DEAD_SECS (or lastSeen stale if never seen VDF).
  let deadPeers := computeDeadPeers s₁
  let (s₂, cancelActions) := deadPeers.foldl (fun acc pid =>
    let (accS, accActs) := acc
    let accS₁ := { accS with knownPeers := accS.knownPeers.erase pid }
    let accS₂ := { accS₁ with relays := accS₁.relays.erase pid }
    let accS₃ := { accS₂ with spiral := accS₂.spiral.removePeer pid }
    -- Cancel any pending connection task for this peer.
    -- Without this, the Rust retry loop runs forever after eviction.
    (accS₃, accActs ++ [.cancelConnect pid])
  ) (s₁, [])
  -- Reconverge after evictions
  let s₃ := { s₂ with spiral := s₂.spiral.reconverge }
  -- VDF proof requests to all SPIRAL neighbors
  let proofReqs := (computeNeighbors s₃.spiral).map .requestVdfProof
  -- Dial missing neighbors
  let dialActions := (computeNeighbors s₃.spiral).filterMap fun pid =>
    if s₃.relays.lookup pid = none then some (.connect pid) else none
  (s₃, cancelActions ++ proofReqs ++ dialActions)

/-! ### Connection Failed Handler

In Rust: currently MISSING — connection tasks retry forever with no backoff (BUG).

This models the retry feedback loop so the FSM can bound connection attempts.
The design is a DECAY rather than hard eviction:
- Attempts < MAX_CONNECT_RETRIES: schedule retry with exponential backoff (1s, 2s, 4s…)
- Attempts ≥ MAX_CONNECT_RETRIES: demote the peer from SPIRAL topology but keep in
  knownPeers with refreshed lastSeen, giving it VDF_DEAD_SECS to prove itself alive.
  If it doesn't show up, handleTick will evict it naturally.
- Peer not in knownPeers (already evicted): cancel the retry task immediately. -/

/-- Handle a failed connection attempt to a peer. -/
def handleConnectionFailed (s : MeshState) (target : PeerId) (attempts : Nat)
    : MeshState × List OutboundAction :=
  match s.knownPeers.lookup target with
  | none =>
    -- Peer was already evicted (by tick or disconnect). The connection task is stale.
    -- Just cancel it — nothing else to do.
    (s, [.cancelConnect target])
  | some _ =>
    if attempts < MAX_CONNECT_RETRIES then
      -- Still within retry budget. Back off exponentially and try again.
      -- backoff: 1s, 2s, 4s, 8s, 16s (then demote)
      (s, [.scheduleRetry target (CONNECT_BACKOFF_BASE_MS * 2 ^ attempts)])
    else
      -- Retry budget exhausted. Demote: remove from SPIRAL topology so we stop
      -- treating this peer as a required neighbor, but refresh lastSeen so the
      -- VDF clock is reset. handleTick will complete the eviction if VDF stays silent.
      let s₁ := { s with spiral := s.spiral.removePeer target }
      let s₂ := { s₁ with spiral := s₁.spiral.reconverge }
      -- Refresh lastSeen to give the peer VDF_DEAD_SECS to show itself alive.
      -- Update the existing PeerInfo rather than removing it.
      let s₃ := match s₂.knownPeers.lookup target with
        | none => s₂
        | some info =>
          let info' := { info with lastSeen := s₂.now, lastVdfAdvance := 0 }
          { s₂ with knownPeers := s₂.knownPeers.insert target info' }
      -- Redial any SPIRAL neighbors that are now missing after reconverge
      let dialActions := (computeNeighbors s₃.spiral).filterMap fun pid =>
        if s₃.relays.lookup pid = none then some (.connect pid) else none
      -- Cancel the current retry task — peer is demoted, not a neighbor target
      (s₃, [.cancelConnect target] ++ dialActions)

/-! ### Master Transition Function

The single entry point for all state transitions.
In Rust: the `tokio::select!` match in `spawn_event_processor()`.

BUG FIX APPLIED: `.tick` is now wired in. Previously handleTick was unreachable
from transition, meaning dead peer eviction NEVER fired. -/

/-- Process any inbound message or event. -/
def transition (s : MeshState) (msg : InboundMsg)
    : MeshState × List OutboundAction :=
  match msg with
  | .hello h => handleHello s h.peerId h
  | .peers ps => handlePeers s ps
  | .vdfProof pid => handleVdfProof s pid
  | .redirect ps => handleRedirect s ps
  | .disconnected pid => handleDisconnected s pid
  | .tick t => handleTick s t
  | .connectionFailed target attempts => handleConnectionFailed s target attempts

end LagoonMesh
