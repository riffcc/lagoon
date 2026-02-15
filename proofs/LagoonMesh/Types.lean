/-
Copyright (c) 2026 Lagun Project. All rights reserved.
Released under AGPL-3.0-or-later license.
-/
import Mathlib.Data.Finset.Basic
import Mathlib.Data.Finset.Card
import Mathlib.Order.Defs.PartialOrder

/-!
# Lagoon Mesh Protocol — Core Types

Lean4 formalization of the Lagoon mesh protocol state machine.
Every type here corresponds to a Rust struct in the lagoon-server crate.

## Correspondence to Rust

| Lean type         | Rust type                       | File                  |
|-------------------|---------------------------------|-----------------------|
| `PeerId`          | `String` (peer_id field)        | wire.rs               |
| `SpiralIndex`     | `Spiral3DIndex` (u64 newtype)   | spiral.rs             |
| `HexCoord`        | `HexCoord` struct               | citadel-topology      |
| `VdfSnapshot`     | VDF fields in `HelloPayload`    | wire.rs               |
| `PeerInfo`        | `MeshPeerInfo`                  | wire.rs               |
| `ConnectionState` | `MeshConnectionState`           | federation.rs         |
| `RelayInfo`       | `RelayHandle`                   | federation.rs         |

## Design Decisions

We model the protocol using natural numbers and rationals (not floats) so that
all comparisons are decidable and all proofs are constructive. The Rust code
uses f64 for VDF credits; we use `ℚ` (rationals) which are order-isomorphic
for our purposes (all credits are rational multiples of tick counts).
-/

namespace LagoonMesh

/-! ### Peer Identity -/

/-- Opaque peer identity. In Rust: `b3b3/{hex(BLAKE3(BLAKE3(pubkey)))}`.
    We model it as a natural number for decidable equality. -/
abbrev PeerId := Nat

/-- Distinguished "no peer" value. -/
def PeerId.none : PeerId := 0

instance : DecidableEq PeerId := inferInstance
instance : Repr PeerId := inferInstance

/-! ### SPIRAL Slot Index -/

/-- SPIRAL slot index. Slot 0 is the origin.
    In Rust: `Spiral3DIndex` (newtype over u64). -/
abbrev SpiralIndex := Nat

/-! ### 3D Hex Coordinate -/

/-- 3D hexagonal coordinate (axial q,r + vertical z).
    In Rust: `HexCoord { q: i32, r: i32, z: i32 }` from citadel-topology. -/
structure HexCoord where
  q : Int
  r : Int
  z : Int
  deriving DecidableEq, Repr

instance : BEq HexCoord where
  beq a b := a.q == b.q && a.r == b.r && a.z == b.z

instance : Hashable HexCoord where
  hash c := mixHash (hash c.q) (mixHash (hash c.r) (hash c.z))

/-- The origin coordinate. -/
def HexCoord.origin : HexCoord := ⟨0, 0, 0⟩

/-! ### SPIRAL Enumeration

The SPIRAL enumeration maps each `SpiralIndex` to a unique `HexCoord`.
We axiomatize it as a bijection — the closed-form formula is proven
in `downward-spiral/lean/DownwardSpiral/Shell3D.lean`. -/

instance : Inhabited HexCoord := ⟨HexCoord.origin⟩
instance : Nonempty HexCoord := ⟨HexCoord.origin⟩

/-- The SPIRAL enumeration function: index → coordinate.
    Axiomatized as injective (each index maps to a unique coordinate). -/
opaque spiralCoord : SpiralIndex → HexCoord

/-- SPIRAL enumeration is injective: distinct indices → distinct coordinates. -/
axiom spiralCoord_injective : Function.Injective spiralCoord

/-- SPIRAL slot 0 is the origin. -/
axiom spiralCoord_zero : spiralCoord 0 = HexCoord.origin

/-! ### Hex Distance

The hex distance determines SPIRAL neighbor relationships.
In Rust: `citadel_topology::hex_distance`. -/

/-- Distance between two hex coordinates.
    Axiomatized — the formula is:
    `max(|Δq|, |Δr|, |Δq+Δr|) + |Δz|` (axial hex + Manhattan z). -/
opaque hexDistance : HexCoord → HexCoord → Nat

/-- Distance is a metric: d(a,a) = 0 -/
axiom hexDistance_self (c : HexCoord) : hexDistance c c = 0

/-- Distance is symmetric: d(a,b) = d(b,a) -/
axiom hexDistance_symm (a b : HexCoord) : hexDistance a b = hexDistance b a

/-- Triangle inequality -/
axiom hexDistance_triangle (a b c : HexCoord) :
    hexDistance a c ≤ hexDistance a b + hexDistance b c

/-! ### VDF State -/

/-- VDF state snapshot for a peer.
    In Rust: VDF fields in `HelloPayload` / `MeshPeerInfo`.
    We use `Nat` for step counts and `ℚ` for credits (rational, not float). -/
structure VdfSnapshot where
  /-- VDF chain step count (monotonically increasing). -/
  step : Nat
  /-- Cumulative precision-weighted credit (sum of per-tick resonance scores). -/
  cumulativeCredit : Nat  -- scaled integer, not float
  deriving DecidableEq, Repr

instance : LE VdfSnapshot where
  le a b := a.step ≤ b.step

instance : LT VdfSnapshot where
  lt a b := a.step < b.step

/-- Initial VDF state (genesis). -/
def VdfSnapshot.genesis : VdfSnapshot := ⟨0, 0⟩

/-- VDF monotonicity: advancing a step increases the step count. -/
def VdfSnapshot.advance (s : VdfSnapshot) (credit : Nat) : VdfSnapshot :=
  ⟨s.step + 1, s.cumulativeCredit + credit⟩

theorem VdfSnapshot.advance_step_lt (s : VdfSnapshot) (c : Nat) :
    s.step < (s.advance c).step := by
  simp [advance]

theorem VdfSnapshot.advance_credit_le (s : VdfSnapshot) (c : Nat) :
    s.cumulativeCredit ≤ (s.advance c).cumulativeCredit := by
  simp [advance]

/-! ### Connection State -/

/-- Per-peer connection state. In Rust: implicit in `federation.relays` membership. -/
inductive ConnectionState where
  /-- Peer discovered via gossip but not directly connected. -/
  | known : ConnectionState
  /-- Active relay connection exists. -/
  | connected : ConnectionState
  deriving DecidableEq, Repr

/-! ### Peer Info -/

/-- Per-peer metadata. In Rust: `MeshPeerInfo` (wire.rs). -/
structure PeerInfo where
  /-- Cryptographic identity. -/
  peerId : PeerId
  /-- Claimed SPIRAL slot (None = unclaimed/joining). -/
  spiralIndex : Option SpiralIndex
  /-- VDF state snapshot. -/
  vdf : VdfSnapshot
  /-- Last time VDF was observed advancing (abstract timestamp). -/
  lastVdfAdvance : Nat
  /-- Last time peer was seen at all. -/
  lastSeen : Nat
  /-- Whether this peer came from LAGOON_PEERS config. -/
  isBootstrap : Bool
  deriving Repr

/-! ### Timestamp -/

/-- Abstract monotonic timestamp. -/
abbrev Timestamp := Nat

/-- VDF dead threshold: 10 seconds (in abstract time units). -/
def VDF_DEAD_SECS : Nat := 10

/-- Maximum SPIRAL neighbors per node. -/
def MAX_NEIGHBORS : Nat := 20

end LagoonMesh
