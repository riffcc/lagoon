# Lagoon — CLAUDE.md

## The Golden Rule: Rooms Are Per-Server

**Every server has its OWN rooms.** `#lagoon` on lagoon.lagun.co is lagoon's room. `#lagoon` on per.lagun.co is per's room. They are SEPARATE. They have their own users, their own LagoonBot, their own state. They are NOT the same room.

**Federation is opt-in via `#room:server`.** If you're on lagoon.lagun.co and you want to visit per's `#lagoon`, you join `#lagoon:per.lagun.co`. That's a portal into their room. You see their users. You talk in their room. Like cross-server battlegrounds in WoW — you're visiting their instance, not merging your server into theirs.

**LAGOON_PEERS means servers CAN communicate.** It does NOT mean rooms are automatically shared. It means the infrastructure exists for cross-server visits. The relay connections are available. Users choose when and where to visit.

### What this means in code:

- `#lagoon` JOIN = local room, local users, local LagoonBot. Zero federation. Zero remote users in NAMES.
- `#lagoon:per.lagun.co` JOIN = explicit visit to per's room. Relay connects to per, joins their `#lagoon`, shows you their users.
- NEVER merge remote users into local channel NAMES.
- NEVER auto-create relays when a user joins a local channel.
- NEVER pump remote server state into local rooms.
- LagoonBot is per-server infrastructure. Each server's LagoonBot lives in that server's rooms. It does not cross federation boundaries.

### When you're about to write federation code, ask yourself:

1. Am I putting remote data into a local room? **Stop. That's wrong.**
2. Am I making something automatic that should be the user's choice? **Stop. Federation is opt-in.**
3. Am I filtering out garbage that shouldn't be there? **Stop. Fix the boundary so the garbage never enters.**

## APE (Anycast Peer Entry) — How Bootstrap Works

**One address is all you need.** Set `LAGOON_PEERS=lagun.co:443` and the node joins the mesh.

**A brand new node joining the mesh. Knows ONE address:**

```
Config:
  LAGOON_PEERS=lagun.co:443    # the only config needed
  LAGOON_YGG=1                 # start Ygg with empty peers

1. Node starts
   - Creates Ygg node (no peers yet, but has 200: address)
   - Has peer_id (generated from keypair)
   - If FIRST node: nobody replies. Listen and wait.

2. Mesh connector dials lagun.co:443 via WebSocket
   - Anycast routes to the NEAREST LIVE node (not random)
   - This is a bootstrap connection — a concierge, not a database

3. MESH HELLO exchange (over the WebSocket)
   → Sends: our peer_id, our ygg_addr, our ygg_peer_uri
   ← Receives: their peer_id, their ygg_addr, their ygg_peer_uri
   - First node has longer VDF chain (more elapsed time) → takes slot 0

4. Bootstrap node tells joiner its SPIRAL neighbors
   - NOT a full peer table dump. NOT "MESH PEERS with all known nodes."
   - Just the joiner's SPIRAL neighbors and their Ygg addresses.
   - A handful of addresses, not O(N) data.
   - NEVER send the full peer table. At 10M nodes that's insane.

5. Ygg bootstrap
   - Calls ygg_node.add_peer(their_ygg_peer_uri)
   - Now on the Ygg overlay with global reachability

6. SPIRAL self-assembly
   - Claims lowest unclaimed SPIRAL slot
   - Computes ≤20 neighbors from topology

7. Dial SPIRAL neighbors directly via Ygg
   - For each neighbor: spawn relay using their Ygg address
   - Direct connections, NOT through the anycast entry point
   - The anycast address was BOOTSTRAP ONLY

8. Incremental sync via SPORE
   - Mesh state syncs through Citadel gossip protocol
   - Your neighbors tell you what you need to know
   - Your view builds over time through your neighborhood
   - You NEVER need the full picture. You need YOUR picture.

9. Drop the bootstrap relay
   - prune_non_spiral_relays() drops the entry point
   - (unless it happens to be a SPIRAL neighbor)

Result: fully meshed, entry point released.
```

### CRITICAL: No Full Peer Table Dumps

**NEVER send the entire peer table to a joining node.** At 10M nodes that's
a multi-gigabyte packet. The bootstrap node is a concierge — it tells you
who your neighbors are. Your neighbors tell you what you need to know.
Everything else syncs incrementally via SPORE.

**Only nodes with the power to act on the information need the information.**
A new node needs to know its SPIRAL neighbors. It does NOT need to know about
a node on the other side of the planet that it will never interact with.

## VDF Proofs — Direct Neighbor Handshake, NOT Gossip

**VDF proof is a handshake with your direct SPIRAL neighbors. Period.**

- Send your proof to your ≤20 direct SPIRAL neighbors
- They receive it, verify it, done
- Proofs are NOT forwarded. NOT gossiped. NOT propagated.
- A node three hops away can't disconnect you, so your proof is noise to them
- They have their OWN neighbors to worry about

**This is NOT gossip. It's a handshake.** "Hey neighbor, I'm alive." "Cool, me too." Done.

**Scoping:** VDF proofs are neighbor-local, not clump-local, not network-wide.
Only your direct SPIRAL neighbors can disconnect you, so only they need your proof.

**Cost:** O(1) per node (≤20 neighbors). NOT O(N) flooding the network.
N nodes, each sending to ≤20 neighbors = O(N) total across the whole mesh.

**CVDF chain** is the aggregated cooperative weight — used when clumps merge.
Individual VDF proofs are internal bookkeeping. The chain is the summary.

### Rules

- **NEVER flood VDF proofs to all connected relays.** SPIRAL neighbors only.
- **NEVER re-gossip received VDF proofs.** They stop at the recipient.
- **NEVER build a gossip protocol for VDF proofs.** It's a handshake, not gossip.
- **NEVER send proofs to nodes that aren't your direct SPIRAL neighbors.**

### Ygg Integration

- Ygg starts with EMPTY peer list (`LAGOON_YGG=1`)
- First Ygg peer comes from MESH HELLO (ygg_peer_uri field)
- ygg_peer_uri = `tcp://[{ygg_addr}]:9443` (overlay IS routable)
- `ygg_node.add_peer(uri)` — FFI exists, already exposed in Rust API
- After first peer: overlay connectivity to all nodes
- SPIRAL neighbors connected by Ygg address, not hostnames
- NEVER derive Ygg bootstrap peers from DNS — use MESH HELLO's ygg_peer_uri
- NEVER use shared DNS (e.g. `anycast-mesh.internal:9443`) as `YGG_PEERS`

### MESH HELLO Addition

One new field in the existing HELLO payload:

```
ygg_peer_uri: "tcp://[200:xxxx::]:9443"
```

The underlay peer URI derived from the overlay address. Everything else in HELLO stays the same.

## The Anycast Switchboard Protocol (ASP) — NO PROVIDER-SPECIFIC HACKS

### ABSOLUTE RULE: NO PROVIDER-SPECIFIC HACKS

This protocol is PROVIDER-AGNOSTIC. It works identically on:
- Fly.io anycast
- Bunny.net CDN edge
- BGP anycast on bare metal (Gigahost, own prefix)
- Floating VIP behind keepalived
- DNS round-robin
- A single box in someone's basement

If a proposed fix references Fly DNS, `.internal` domains, `FLY_PRIVATE_IP`,
Bunny-specific headers, or ANY provider-specific mechanism: **STOP. You are
solving the wrong problem. The fix goes in the PROTOCOL, not the deployment.**

### Core Principle: Every Node Is A Switchboard

**The anycast address is a socket factory. Every node is a switchboard. Every dial is a routed request.**

When a client dials the anycast address, the node that answers is a **router**,
not a destination. It may or may not be the node the client needs. It doesn't
matter. The answering node's job is to connect the client to the RIGHT node.

Self-connection (dialing anycast and reaching yourself) is **not a failure
mode**. It is the **optimal case** — zero network hops to the router. You tell
yourself who you need, you hand the socket to them.

### The Half-Dial

Normal connection: dial → full handshake → discover identity → "oh it's me" → disconnect → waste.
Half-dial: dial → responder identifies itself FIRST → client decides → complete or redirect.

**Protocol (3 phases):**

**Phase 1: TCP SYN** (standard)
```
Client → anycast_ip:9443 (normal TCP connection)
```

**Phase 2: PEER_REQUEST**
```
Client → Responder: {
  type: "peer_request",
  want: "spiral_slot:7"      // or "specific_peer:<peer_id>" or "any"
  my_peer_id: "<client_id>"
}
```

**Phase 3: PEER_HANDOFF (if needed)**

Case A — Responder IS the requested peer:
```
Responder → Client: { type: "peer_ready", peer_id: "<responder_id>" }
// Handshake completes normally. Done.
```

Case B — Responder is NOT the requested peer (including self-connection):
```
Responder → Client: { type: "peer_redirect", target_peer_id: "<actual_target_id>" }
// Responder TCP_REPAIR freezes the socket (~40 bytes of state)
// Responder sends socket state to target via Ygg overlay
// Target reconstructs socket, completes handshake
// Client never knows the handoff happened
```

**Result: Every dial succeeds. Every single one.**

No retries. No aborts. No wasted connections. No self-connection detection
loops. The answering node is a switchboard. It routes you to whoever you need.

### The Socket Factory

The anycast address is not a load balancer. Not a discovery service. It's a
**socket factory**.

Each dial to the anycast address produces:
- A fresh TCP socket
- A valid NAT mapping (client's firewall opened it)
- A connection to a switchboard node

The switchboard routes each socket to its destination via TCP_REPAIR. The
client dials ONE address. Gets connections to MANY nodes. The NAT mapping
is always valid because the 4-tuple always shows the anycast IP.

```
Dial #1 → switchboard routes to Node A (SPIRAL neighbor 1)
Dial #2 → switchboard routes to Node B (SPIRAL neighbor 2)
Dial #3 → switchboard routes to Node C (SPIRAL neighbor 3)
...all to the same anycast address, all different destinations
```

### TCP_REPAIR Socket Migration

The mechanism that makes the switchboard work across machines.

```
1. Responder puts socket into TCP_REPAIR mode (CAP_NET_ADMIN required)
2. Reads state: (local_addr, remote_addr, send_seq, recv_seq, window) ~40 bytes
3. Sends state to target node via Ygg overlay (internal, encrypted)
4. Target reconstructs socket with identical 4-tuple
5. Target takes over the connection seamlessly
```

Works because: all anycast nodes share the same IP. The TCP 4-tuple
`(client_ip, client_port, anycast_ip, port)` is valid on every machine.

**Requires:** CAP_NET_ADMIN (available on Fly.io microVMs, bare metal,
any environment where you have root).

**Fallback if unavailable:** Application-layer proxy. Accepting node
forwards bytes to target node over Ygg. More overhead, functionally
identical. TCP_REPAIR is optimization, not requirement.

### Sovereign Connectivity

One outbound TCP connection to any reachable node = full bidirectional access
to every node in the mesh.

- Works through any NAT (client made an outbound connection)
- Works through any firewall (port 443, looks like HTTPS)
- Works through corporate proxies (valid TLS)
- Works through symmetric NAT (no hole-punching needed)
- Works through state-level censorship (one HTTPS connection)

The mesh-side migration (TCP_REPAIR handoff) is invisible to every layer
below the application. The client's firewall, NAT, proxy — none of them
see anything but a single HTTPS connection to one IP address.

This is not hole-punching. This is not NAT traversal. This is:
**one connection, any network, full mesh access**.

### What This Eliminates

- STUN servers (don't need to discover public IP)
- TURN relays (don't need to relay around NAT)
- ICE negotiation (don't need to try five methods)
- WebRTC's hole-punching complexity
- Signaling servers
- Bootstrap server persistence
- Self-connection detection/retry loops
- Provider-specific DNS hacks
- The entire "unreachable node" problem

### Node Identity

- **peer_id** (public key, `b3b3/{hex}`) = THE identity. HashMap key. SPIRAL
  key. Unique by construction. Ephemeral nodes generate fresh keys. That's a
  feature, not a bug.
- **site_name** = metadata. "What domain does this node serve?" Display/routing.
  NOT used for keying.
- **node_name** = human-friendly label. Logging. Nothing structural.

Ghost nodes are detected by VDF non-participation, NOT by identity tracking.
No VDF attestation = dead = prune.

### Rules

- **NEVER write provider-specific workarounds.** No Fly DNS hacks. No AWS tricks. No special-cased cloud logic. The protocol works on ANY anycast: BGP anycast, Fly global anycast, keepalived floating VIPs, DNS round-robin. The protocol doesn't care how the routing works.
- **NEVER treat self-connections as errors to detect and discard.** They are routable inventory.
- **NEVER retry/poll on self-connection.** Route through it.
- **NEVER "fix" self-connections with DNS tricks, multi-address resolution, or shuffling.** The protocol USES self-connections. They are productive.
- **The half-dial requires modifying yggdrasil-go's handshake.** Peer ID exchange before full handshake. PEER_REQUEST/PEER_HANDOFF messages. TCP_REPAIR socket migration. This is a yggdrasil-go change, not an application-layer workaround.

## Critical: Regions Are NOT Nodes

**A region is a geographic location. A node is a process. They are DIFFERENT things.**

- Multiple nodes can exist in the same region. This is normal. This is expected.
- NEVER treat region == node. NEVER filter/deduplicate by region.
- NEVER assume one node per region. 5 nodes in lhr is a valid deployment.
- Node identity comes from `LAGOON_NODE_NAME` / lens_id, NOT from `FLY_REGION`.
- Self-identification uses the node's own identity (node_name, Ygg keypair, etc.), NEVER the region name.
