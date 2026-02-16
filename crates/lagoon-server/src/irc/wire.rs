//! Native mesh wire protocol — JSON over WebSocket.
//!
//! Replaces the IRC-framed `MESH {subcommand} {json}` protocol with a proper
//! tagged JSON envelope. Each WebSocket text frame is one `MeshMessage`.
//! No IRC. No chunking. No NICK/USER registration.

use serde::{Deserialize, Serialize};

use super::profile::UserProfile;
use super::server::MeshPeerInfo;

/// JSON payload for the Hello message — identity exchange.
///
/// First message on every mesh connection. Replaces the IRC registration
/// handshake (NICK/USER/001) + `MESH HELLO {json}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    pub peer_id: String,
    pub server_name: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub spiral_index: Option<u64>,
    #[serde(default)]
    pub vdf_genesis: Option<String>,
    #[serde(default)]
    pub vdf_hash: Option<String>,
    #[serde(default)]
    pub vdf_step: Option<u64>,
    #[serde(default)]
    pub yggdrasil_addr: Option<String>,
    #[serde(default)]
    pub site_name: String,
    #[serde(default)]
    pub node_name: String,
    #[serde(default)]
    pub vdf_resonance_credit: Option<f64>,
    #[serde(default)]
    pub vdf_actual_rate_hz: Option<f64>,
    /// Cumulative resonance credit — total precision-weighted VDF work over time.
    /// Used for SPIRAL slot collision resolution (higher credit wins).
    #[serde(default)]
    pub vdf_cumulative_credit: Option<f64>,
    #[serde(default)]
    pub ygg_peer_uri: Option<String>,
    /// CVDF cooperative chain height (round number).
    #[serde(default)]
    pub cvdf_height: Option<u64>,
    /// CVDF cooperative chain weight (attestation-weighted sum).
    #[serde(default)]
    pub cvdf_weight: Option<u64>,
    /// CVDF chain tip hash (hex-encoded).
    #[serde(default)]
    pub cvdf_tip_hex: Option<String>,
    /// CVDF genesis seed (hex-encoded) — chains with different genesis are incompatible.
    #[serde(default)]
    pub cvdf_genesis_hex: Option<String>,
    /// Total VDF work of this node's entire connected graph.
    /// Sum of cumulative_credit across all known peers + self.
    /// Used for SPIRAL merge negotiation — cluster with more work wins.
    #[serde(default)]
    pub cluster_vdf_work: Option<f64>,
    /// Concierge slot assignment — the first empty slot in the sender's
    /// SPIRAL topology. Included when the sender is an established node
    /// (has a claimed SPIRAL slot). The joiner takes this slot immediately.
    /// One integer. O(1). Scales to millions of nodes.
    #[serde(default)]
    pub assigned_slot: Option<u64>,
    /// Cluster identity chain value (hex-encoded blake3 hash, current tip).
    #[serde(default)]
    pub cluster_chain_value: Option<String>,
    /// Cluster epoch origin (hex-encoded blake3 hash).
    /// Stable across advances — only changes on merge/adopt.
    #[serde(default)]
    pub cluster_chain_epoch_origin: Option<String>,
    /// Cluster identity chain round number.
    #[serde(default)]
    pub cluster_chain_round: Option<u64>,
    /// Cluster chain cumulative work — total advance steps across all epochs.
    /// Used in DifferentCluster comparison: higher work wins (adoption),
    /// equal work triggers symmetric merge (blake3(sort), epoch reset).
    #[serde(default)]
    pub cluster_chain_work: Option<u64>,
    /// Cluster round seed (hex-encoded [u8; 32]) — the VDF quantum hash used
    /// as the advance seed for the cluster chain. Propagated from the cluster's
    /// clock source (highest VDF work). Losers don't generate — they receive.
    #[serde(default)]
    pub cluster_round_seed: Option<String>,
}

/// Native mesh protocol message — the sole on-the-wire type.
///
/// Sent as JSON text frames over WebSocket. Binary payloads (SPORE,
/// bincode) use base64 encoding within the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MeshMessage {
    /// Identity exchange — first message on any connection.
    #[serde(rename = "hello")]
    Hello(HelloPayload),

    /// Known peer list (gossip propagation). No chunking needed.
    #[serde(rename = "peers")]
    Peers { peers: Vec<MeshPeerInfo> },

    /// Request VDF proof from peer.
    #[serde(rename = "vdf_proof_req")]
    VdfProofReq,

    /// VDF proof response.
    #[serde(rename = "vdf_proof")]
    VdfProof { proof: serde_json::Value },

    /// Request full peer table sync.
    #[serde(rename = "sync")]
    Sync,

    /// Single gossip message (IRC event replication).
    #[serde(rename = "gossip")]
    Gossip { message: serde_json::Value },

    /// SPORE HaveList for gossip dedup (base64-bincode).
    #[serde(rename = "gossip_spore")]
    GossipSpore { data: String },

    /// Gossip diff batch (base64-bincode).
    #[serde(rename = "gossip_diff")]
    GossipDiff { data: String },

    /// Latency proof SPORE HaveList (base64-bincode).
    #[serde(rename = "latency_have")]
    LatencyHave { data: String },

    /// Latency proof delta entries (base64-bincode).
    #[serde(rename = "latency_delta")]
    LatencyDelta { data: String },

    /// Query: "do you have this user's profile?"
    #[serde(rename = "profile_query")]
    ProfileQuery { username: String },

    /// Response: profile data (or null if not found).
    #[serde(rename = "profile_response")]
    ProfileResponse {
        username: String,
        profile: Option<UserProfile>,
    },

    /// Profile SPORE HaveList for intra-cluster sync (base64-bincode).
    #[serde(rename = "profile_have")]
    ProfileHave { data: String },

    /// Profile delta — missing profiles for intra-cluster sync (base64-bincode).
    #[serde(rename = "profile_delta")]
    ProfileDelta { data: String },

    /// Connection snapshot SPORE HaveList (base64-bincode).
    #[serde(rename = "connection_have")]
    ConnectionHave { data: String },

    /// Connection snapshot delta entries (base64-bincode).
    #[serde(rename = "connection_delta")]
    ConnectionDelta { data: String },

    /// Liveness attestation SPORE HaveList (base64-bincode).
    #[serde(rename = "liveness_have")]
    LivenessHave { data: String },

    /// Liveness attestation delta entries (base64-bincode).
    #[serde(rename = "liveness_delta")]
    LivenessDelta { data: String },


    /// Socket migration — TCP_REPAIR state delivered via existing mesh relay.
    /// The target node calls `anymesh::restore()` to reconstruct the socket.
    #[serde(rename = "socket_migrate")]
    SocketMigrate {
        /// Base64-encoded bincode `SocketMigration` from anymesh.
        migration: String,
        /// The peer_id of the original client (so target knows who to expect).
        client_peer_id: String,
    },

    /// Cluster chain update — broadcast after merge so cluster-mates adopt
    /// the new value without re-merging (prevents double-counting).
    ///
    /// Propagated via SPORE-style push to all connected peers. Receivers
    /// compare `cumulative_work`: if higher, adopt value + work + round.
    /// This is the intra-cluster cascade path — DifferentCluster HELLO is
    /// only for genuine cross-cluster contact.
    #[serde(rename = "chain_update")]
    ChainUpdate {
        /// New chain value (hex-encoded 32 bytes).
        value: String,
        /// Cumulative work across all epochs.
        cumulative_work: u64,
        /// Current round number.
        round: u64,
        /// Base64-bincode-encoded `ClusterChainProof`. Receivers MUST verify
        /// this proof before adopting. Without a valid proof, the cumulative_work
        /// claim is just a number someone made up.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof: Option<String>,
        /// Work contributions ledger: genesis_hash(hex) → advance_steps.
        /// Enables idempotent merge (union, not addition). If absent (old nodes),
        /// receivers synthesize a single-entry map from cumulative_work.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        work_contributions: Option<std::collections::HashMap<String, u64>>,
        /// Epoch origin (hex-encoded 32 bytes). Stable across advances — only
        /// changes on merge/adopt. Used by receivers to set their epoch_origin
        /// correctly when adopting via SPORE cascade.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        epoch_origin: Option<String>,
    },

    /// CVDF cooperative VDF message — attestations, rounds, sync.
    /// Payload is base64-encoded bincode (same pattern as SPORE payloads).
    #[serde(rename = "cvdf")]
    Cvdf { data: String },

    /// Redirect: hub already connected to this peer. Carries known peers
    /// (especially SPIRAL neighbors) so the connecting node can dial them.
    /// Sent before closing a duplicate connection. Recipient should process
    /// the peers and NOT reconnect to this hub.
    #[serde(rename = "redirect")]
    Redirect { peers: Vec<MeshPeerInfo> },

    /// PoL challenge — initiates latency measurement to a neighbor.
    /// The receiver must immediately respond with PolResponse carrying the same nonce.
    /// RTT is measured between sending this and receiving the response.
    /// The resulting proof is Ed25519-signed and VDF-anchored (Citadel PoLP).
    #[serde(rename = "pol_challenge")]
    PolChallenge { nonce: u64 },

    /// PoL response — echoes the nonce from a PolChallenge.
    /// Must be sent as fast as possible (no routing through event loop).
    #[serde(rename = "pol_response")]
    PolResponse { nonce: u64 },

    /// VDF window proof — push-based proof of sequential computation.
    /// Replaces the old VdfProofReq/VdfProof challenge-response.
    /// Sent every 3 seconds to SPIRAL neighbors (base64-bincode encoded).
    #[serde(rename = "vdf_window")]
    VdfWindow { data: String },
}

impl MeshMessage {
    /// Serialize to JSON string for WebSocket text frame.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string (WebSocket text frame).
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed framing for raw TCP mesh sessions
// ---------------------------------------------------------------------------
//
// After the switchboard handshake (which uses newline-delimited JSON),
// the TCP stream switches to length-prefixed framing:
//   [4-byte big-endian u32 length][JSON bytes]
//
// This eliminates the newline-delimiter bug where large messages (200KB+
// CVDF proofs) were being split across read_line() boundaries.
// A zero-length frame is a keepalive.

/// Maximum mesh message size (4 MiB). Reject anything larger to prevent OOM.
const MAX_MESH_FRAME: u32 = 4 * 1024 * 1024;

/// Write a length-prefixed mesh message to a raw TCP stream.
pub async fn write_mesh_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let len = data.len() as u32;
    // Combine length header + payload into a single buffer to avoid
    // Nagle-induced splits between the header and payload.
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    writer.write_all(&buf).await
}

/// Write a keepalive (zero-length frame).
pub async fn write_mesh_keepalive(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    writer.write_all(&0u32.to_be_bytes()).await
}

/// Read a length-prefixed mesh message from a raw TCP stream.
///
/// Returns `Ok(None)` for keepalive frames (length = 0).
/// Returns `Ok(Some(String))` for message frames.
/// Returns `Err` on I/O error or protocol violation.
pub async fn read_mesh_frame(
    reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> std::io::Result<Option<String>> {
    use tokio::io::AsyncReadExt;
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Ok(None); // keepalive
    }
    if len > MAX_MESH_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("mesh frame too large: {len} bytes (max {MAX_MESH_FRAME})"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }).map(Some)
}

// ---------------------------------------------------------------------------
// Switchboard protocol — pre-WebSocket half-dial on raw TCP
// ---------------------------------------------------------------------------

/// Anycast Switchboard Protocol messages — JSON + newline on raw TCP.
///
/// These are exchanged BEFORE the WebSocket upgrade. The responder identifies
/// itself immediately, the client requests a specific target, and the
/// switchboard either confirms readiness or redirects the connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SwitchboardMessage {
    /// Responder announces identity immediately on accept.
    #[serde(rename = "switchboard_hello")]
    SwitchboardHello {
        peer_id: String,
        spiral_slot: Option<u64>,
    },

    /// Client requests connection to a specific target.
    ///
    /// `want` is a plain string:
    /// - `"any"` — connect me to anyone (bootstrap)
    /// - `"spiral_slot:N"` — connect me to whoever occupies SPIRAL slot N
    /// - `"peer:ID"` — connect me to specific peer_id
    #[serde(rename = "peer_request")]
    PeerRequest {
        my_peer_id: String,
        want: String,
    },

    /// Responder IS the requested target — proceed with raw TCP mesh session.
    #[serde(rename = "peer_ready")]
    PeerReady { peer_id: String },

    /// Responder is NOT the target — initiating redirect.
    ///
    /// `method`:
    /// - `"direct"` — target's Ygg address included, client dials them directly
    /// - `"splice"` — switchboard proxies bytes to target (bootstrap, no Ygg yet)
    /// - `"repair"` — TCP_REPAIR socket migration (bare-metal BGP anycast)
    #[serde(rename = "peer_redirect")]
    PeerRedirect {
        target_peer_id: String,
        method: String,
        /// Target's Ygg overlay address (for `"direct"` method).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ygg_addr: Option<String>,
    },
}

impl SwitchboardMessage {
    /// Serialize to a JSON line (JSON + `\n`) for raw TCP.
    pub fn to_line(&self) -> Result<String, serde_json::Error> {
        let mut json = serde_json::to_string(self)?;
        json.push('\n');
        Ok(json)
    }

    /// Deserialize from a JSON line (strips trailing newline/whitespace).
    pub fn from_line(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_round_trip() {
        let msg = MeshMessage::Hello(HelloPayload {
            peer_id: "b3b3/deadbeef".into(),
            server_name: "lon.lagun.co".into(),
            public_key_hex: "aabbccdd".into(),
            spiral_index: Some(7),
            vdf_genesis: Some("0011".into()),
            vdf_hash: Some("ffee".into()),
            vdf_step: Some(12345),
            yggdrasil_addr: Some("200:1234::1".into()),
            site_name: "lagun.co".into(),
            node_name: "lon".into(),
            vdf_resonance_credit: Some(0.999),
            vdf_actual_rate_hz: Some(10.0),
            vdf_cumulative_credit: Some(42.5),
            ygg_peer_uri: Some("tcp://[200:1234::1]:9443".into()),
            cvdf_height: Some(42),
            cvdf_weight: Some(100),
            cvdf_tip_hex: Some("aabbccdd".into()),
            cvdf_genesis_hex: Some("11223344".into()),
            cluster_vdf_work: Some(1000.5),
            assigned_slot: Some(3),
            cluster_chain_value: Some("deadbeefcafe".into()),
            cluster_chain_epoch_origin: Some("cafebabe1234".into()),
            cluster_chain_round: Some(99),
            cluster_chain_work: Some(42),
            cluster_round_seed: Some("abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234".into()),
        });

        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"hello""#));
        assert!(json.contains(r#""peer_id":"b3b3/deadbeef""#));

        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Hello(h) => {
                assert_eq!(h.peer_id, "b3b3/deadbeef");
                assert_eq!(h.server_name, "lon.lagun.co");
                assert_eq!(h.spiral_index, Some(7));
                assert_eq!(h.vdf_step, Some(12345));
                assert_eq!(h.node_name, "lon");
                assert_eq!(h.cvdf_height, Some(42));
                assert_eq!(h.cvdf_weight, Some(100));
                assert_eq!(h.cvdf_tip_hex.as_deref(), Some("aabbccdd"));
                assert_eq!(h.cvdf_genesis_hex.as_deref(), Some("11223344"));
                assert_eq!(h.cluster_vdf_work, Some(1000.5));
                assert_eq!(h.assigned_slot, Some(3));
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn hello_minimal_fields() {
        // Only required fields — all optional fields default to None/empty.
        let json = r#"{"type":"hello","peer_id":"b3b3/aa","server_name":"x.co","public_key_hex":"bb"}"#;
        let msg = MeshMessage::from_json(json).unwrap();
        match msg {
            MeshMessage::Hello(h) => {
                assert_eq!(h.peer_id, "b3b3/aa");
                assert_eq!(h.spiral_index, None);
                assert_eq!(h.site_name, "");
                assert_eq!(h.node_name, "");
                assert_eq!(h.cluster_vdf_work, None);
                assert_eq!(h.assigned_slot, None);
            }
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    #[test]
    fn peers_round_trip() {
        let peer = MeshPeerInfo {
            peer_id: "b3b3/cafe".into(),
            server_name: "per.lagun.co".into(),
            public_key_hex: "1234".into(),
            site_name: "lagun.co".into(),
            node_name: "per".into(),
            ..Default::default()
        };
        let msg = MeshMessage::Peers { peers: vec![peer] };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"peers""#));

        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Peers { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].peer_id, "b3b3/cafe");
            }
            other => panic!("expected Peers, got {other:?}"),
        }
    }

    #[test]
    fn peers_empty_list() {
        let msg = MeshMessage::Peers { peers: vec![] };
        let json = msg.to_json().unwrap();
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Peers { peers } => assert!(peers.is_empty()),
            other => panic!("expected Peers, got {other:?}"),
        }
    }

    #[test]
    fn peers_large_list_no_chunking() {
        // WebSocket has no size limit — verify large peer lists work.
        let peers: Vec<MeshPeerInfo> = (0..100)
            .map(|i| MeshPeerInfo {
                peer_id: format!("b3b3/{i:064x}"),
                server_name: format!("node-{i}.lagun.co"),
                public_key_hex: format!("{i:064x}"),
                site_name: "lagun.co".into(),
                node_name: format!("node-{i}"),
                ..Default::default()
            })
            .collect();
        let msg = MeshMessage::Peers { peers };
        let json = msg.to_json().unwrap();
        assert!(json.len() > 8191, "must exceed old IRC line limit");
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Peers { peers } => assert_eq!(peers.len(), 100),
            other => panic!("expected Peers, got {other:?}"),
        }
    }

    #[test]
    fn vdf_proof_req_round_trip() {
        let msg = MeshMessage::VdfProofReq;
        let json = msg.to_json().unwrap();
        assert_eq!(json, r#"{"type":"vdf_proof_req"}"#);
        let decoded = MeshMessage::from_json(&json).unwrap();
        assert!(matches!(decoded, MeshMessage::VdfProofReq));
    }

    #[test]
    fn vdf_proof_round_trip() {
        let proof = serde_json::json!({"steps": 1000, "genesis": "aabb", "hash": "ccdd"});
        let msg = MeshMessage::VdfProof { proof: proof.clone() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"vdf_proof""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::VdfProof { proof: p } => assert_eq!(p, proof),
            other => panic!("expected VdfProof, got {other:?}"),
        }
    }

    #[test]
    fn sync_round_trip() {
        let msg = MeshMessage::Sync;
        let json = msg.to_json().unwrap();
        assert_eq!(json, r#"{"type":"sync"}"#);
        let decoded = MeshMessage::from_json(&json).unwrap();
        assert!(matches!(decoded, MeshMessage::Sync));
    }

    #[test]
    fn gossip_round_trip() {
        let event = serde_json::json!({"nick": "alice", "channel": "#lagoon", "text": "hi"});
        let msg = MeshMessage::Gossip { message: event.clone() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"gossip""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Gossip { message } => assert_eq!(message, event),
            other => panic!("expected Gossip, got {other:?}"),
        }
    }

    #[test]
    fn gossip_spore_round_trip() {
        let msg = MeshMessage::GossipSpore { data: "YmFzZTY0ZGF0YQ==".into() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"gossip_spore""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::GossipSpore { data } => assert_eq!(data, "YmFzZTY0ZGF0YQ=="),
            other => panic!("expected GossipSpore, got {other:?}"),
        }
    }

    #[test]
    fn gossip_diff_round_trip() {
        let msg = MeshMessage::GossipDiff { data: "c29tZWRhdGE=".into() };
        let json = msg.to_json().unwrap();
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::GossipDiff { data } => assert_eq!(data, "c29tZWRhdGE="),
            other => panic!("expected GossipDiff, got {other:?}"),
        }
    }

    #[test]
    fn latency_have_round_trip() {
        let msg = MeshMessage::LatencyHave { data: "bGF0ZW5jeQ==".into() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"latency_have""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::LatencyHave { data } => assert_eq!(data, "bGF0ZW5jeQ=="),
            other => panic!("expected LatencyHave, got {other:?}"),
        }
    }

    #[test]
    fn latency_delta_round_trip() {
        let msg = MeshMessage::LatencyDelta { data: "ZGVsdGE=".into() };
        let json = msg.to_json().unwrap();
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::LatencyDelta { data } => assert_eq!(data, "ZGVsdGE="),
            other => panic!("expected LatencyDelta, got {other:?}"),
        }
    }

    #[test]
    fn profile_query_round_trip() {
        let msg = MeshMessage::ProfileQuery { username: "wings".into() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"profile_query""#));
        assert!(json.contains(r#""username":"wings""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ProfileQuery { username } => assert_eq!(username, "wings"),
            other => panic!("expected ProfileQuery, got {other:?}"),
        }
    }

    #[test]
    fn profile_response_with_profile_round_trip() {
        use std::collections::BTreeSet;

        let profile = UserProfile {
            username: "wings".into(),
            uuid: "550e8400-e29b-41d4-a716-446655440000".into(),
            credentials: BTreeSet::from(["cred_json_1".into(), "cred_json_2".into()]),
            ed25519_pubkey: Some("aabbccdd".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
            modified_at: "2026-02-13T18:00:00Z".into(),
        };
        let msg = MeshMessage::ProfileResponse {
            username: "wings".into(),
            profile: Some(profile),
        };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"profile_response""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ProfileResponse { username, profile } => {
                assert_eq!(username, "wings");
                let p = profile.unwrap();
                assert_eq!(p.credentials.len(), 2);
            }
            other => panic!("expected ProfileResponse, got {other:?}"),
        }
    }

    #[test]
    fn profile_response_not_found_round_trip() {
        let msg = MeshMessage::ProfileResponse {
            username: "ghost".into(),
            profile: None,
        };
        let json = msg.to_json().unwrap();
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ProfileResponse { username, profile } => {
                assert_eq!(username, "ghost");
                assert!(profile.is_none());
            }
            other => panic!("expected ProfileResponse, got {other:?}"),
        }
    }

    #[test]
    fn unknown_type_fails() {
        let json = r#"{"type":"bogus","data":"hello"}"#;
        assert!(MeshMessage::from_json(json).is_err());
    }

    #[test]
    fn missing_type_fails() {
        let json = r#"{"peer_id":"b3b3/aa"}"#;
        assert!(MeshMessage::from_json(json).is_err());
    }

    #[test]
    fn type_tag_is_first_field() {
        // Ensure "type" appears early for efficient prefix matching if needed.
        let msg = MeshMessage::Sync;
        let json = msg.to_json().unwrap();
        assert!(json.starts_with(r#"{"type":"#));
    }

    #[test]
    fn profile_have_round_trip() {
        let msg = MeshMessage::ProfileHave { data: "cHJvZmlsZV9zcG9yZQ==".into() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"profile_have""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ProfileHave { data } => assert_eq!(data, "cHJvZmlsZV9zcG9yZQ=="),
            other => panic!("expected ProfileHave, got {other:?}"),
        }
    }

    #[test]
    fn profile_delta_round_trip() {
        let msg = MeshMessage::ProfileDelta { data: "ZGVsdGFfcHJvZmlsZXM=".into() };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"profile_delta""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ProfileDelta { data } => assert_eq!(data, "ZGVsdGFfcHJvZmlsZXM="),
            other => panic!("expected ProfileDelta, got {other:?}"),
        }
    }

    #[test]
    fn socket_migrate_round_trip() {
        let msg = MeshMessage::SocketMigrate {
            migration: "bWlncmF0aW9uX2RhdGE=".into(),
            client_peer_id: "b3b3/abc123".into(),
        };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"socket_migrate""#));
        assert!(json.contains(r#""client_peer_id":"b3b3/abc123""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::SocketMigrate { migration, client_peer_id } => {
                assert_eq!(migration, "bWlncmF0aW9uX2RhdGE=");
                assert_eq!(client_peer_id, "b3b3/abc123");
            }
            other => panic!("expected SocketMigrate, got {other:?}"),
        }
    }

    #[test]
    fn chain_update_round_trip() {
        let mut contribs = std::collections::HashMap::new();
        contribs.insert("aa".repeat(32), 3000u64);
        contribs.insert("bb".repeat(32), 2300u64);
        let msg = MeshMessage::ChainUpdate {
            value: "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".into(),
            cumulative_work: 5300,
            round: 42,
            proof: Some("c29tZXByb29m".into()),
            work_contributions: Some(contribs),
            epoch_origin: Some("dd".repeat(32)),
        };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"chain_update""#));
        assert!(json.contains(r#""cumulative_work":5300"#));
        assert!(json.contains(r#""proof":"c29tZXByb29m""#));
        assert!(json.contains(r#""work_contributions""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ChainUpdate { value, cumulative_work, round, proof, work_contributions, epoch_origin } => {
                assert_eq!(value, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233");
                assert_eq!(cumulative_work, 5300);
                assert_eq!(round, 42);
                assert_eq!(proof.as_deref(), Some("c29tZXByb29m"));
                let wc = work_contributions.unwrap();
                assert_eq!(wc.get(&"aa".repeat(32)), Some(&3000));
                assert_eq!(wc.get(&"bb".repeat(32)), Some(&2300));
                assert_eq!(epoch_origin.as_deref(), Some(&*"dd".repeat(32)));
            }
            other => panic!("expected ChainUpdate, got {other:?}"),
        }
    }

    #[test]
    fn chain_update_without_proof_round_trip() {
        let msg = MeshMessage::ChainUpdate {
            value: "ff".repeat(32),
            cumulative_work: 0,
            round: 0,
            proof: None,
            work_contributions: None,
            epoch_origin: None,
        };
        let json = msg.to_json().unwrap();
        assert!(!json.contains("proof")); // skip_serializing_if = None
        assert!(!json.contains("work_contributions"));
        assert!(!json.contains("epoch_origin"));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::ChainUpdate { proof, .. } => {
                assert!(proof.is_none());
            }
            other => panic!("expected ChainUpdate, got {other:?}"),
        }
    }

    // --- Switchboard protocol tests ---

    #[test]
    fn switchboard_hello_round_trip() {
        let msg = SwitchboardMessage::SwitchboardHello {
            peer_id: "b3b3/deadbeef".into(),
            spiral_slot: Some(7),
        };
        let line = msg.to_line().unwrap();
        assert!(line.ends_with('\n'));
        assert!(line.contains(r#""type":"switchboard_hello""#));
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::SwitchboardHello { peer_id, spiral_slot } => {
                assert_eq!(peer_id, "b3b3/deadbeef");
                assert_eq!(spiral_slot, Some(7));
            }
            other => panic!("expected SwitchboardHello, got {other:?}"),
        }
    }

    #[test]
    fn peer_request_any() {
        let msg = SwitchboardMessage::PeerRequest {
            my_peer_id: "b3b3/aaa".into(),
            want: "any".into(),
        };
        let line = msg.to_line().unwrap();
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRequest { my_peer_id, want } => {
                assert_eq!(my_peer_id, "b3b3/aaa");
                assert_eq!(want, "any");
            }
            other => panic!("expected PeerRequest, got {other:?}"),
        }
    }

    #[test]
    fn peer_request_spiral_slot() {
        let msg = SwitchboardMessage::PeerRequest {
            my_peer_id: "b3b3/bbb".into(),
            want: "spiral_slot:42".into(),
        };
        let line = msg.to_line().unwrap();
        assert!(line.contains(r#""want":"spiral_slot:42""#));
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRequest { want, .. } => assert_eq!(want, "spiral_slot:42"),
            other => panic!("expected PeerRequest, got {other:?}"),
        }
    }

    #[test]
    fn peer_request_specific_peer() {
        let msg = SwitchboardMessage::PeerRequest {
            my_peer_id: "b3b3/ccc".into(),
            want: "peer:b3b3/deadbeef".into(),
        };
        let line = msg.to_line().unwrap();
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRequest { want, .. } => {
                assert_eq!(want, "peer:b3b3/deadbeef");
            }
            other => panic!("expected PeerRequest, got {other:?}"),
        }
    }

    #[test]
    fn peer_ready_round_trip() {
        let msg = SwitchboardMessage::PeerReady { peer_id: "b3b3/fff".into() };
        let line = msg.to_line().unwrap();
        assert!(line.contains(r#""type":"peer_ready""#));
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerReady { peer_id } => assert_eq!(peer_id, "b3b3/fff"),
            other => panic!("expected PeerReady, got {other:?}"),
        }
    }

    #[test]
    fn peer_redirect_splice() {
        let msg = SwitchboardMessage::PeerRedirect {
            target_peer_id: "b3b3/target".into(),
            method: "splice".into(),
            ygg_addr: None,
        };
        let line = msg.to_line().unwrap();
        assert!(line.contains(r#""type":"peer_redirect""#));
        assert!(line.contains(r#""method":"splice""#));
        // ygg_addr omitted when None
        assert!(!line.contains("ygg_addr"));
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRedirect { target_peer_id, method, ygg_addr } => {
                assert_eq!(target_peer_id, "b3b3/target");
                assert_eq!(method, "splice");
                assert!(ygg_addr.is_none());
            }
            other => panic!("expected PeerRedirect, got {other:?}"),
        }
    }

    #[test]
    fn peer_redirect_direct_with_ygg() {
        let msg = SwitchboardMessage::PeerRedirect {
            target_peer_id: "b3b3/target".into(),
            method: "direct".into(),
            ygg_addr: Some("200:abcd::1".into()),
        };
        let line = msg.to_line().unwrap();
        assert!(line.contains(r#""method":"direct""#));
        assert!(line.contains(r#""ygg_addr":"200:abcd::1""#));
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRedirect { target_peer_id, method, ygg_addr } => {
                assert_eq!(target_peer_id, "b3b3/target");
                assert_eq!(method, "direct");
                assert_eq!(ygg_addr.as_deref(), Some("200:abcd::1"));
            }
            other => panic!("expected PeerRedirect, got {other:?}"),
        }
    }

    #[test]
    fn peer_redirect_repair() {
        let msg = SwitchboardMessage::PeerRedirect {
            target_peer_id: "b3b3/target".into(),
            method: "repair".into(),
            ygg_addr: None,
        };
        let line = msg.to_line().unwrap();
        let decoded = SwitchboardMessage::from_line(&line).unwrap();
        match decoded {
            SwitchboardMessage::PeerRedirect { method, .. } => assert_eq!(method, "repair"),
            other => panic!("expected PeerRedirect, got {other:?}"),
        }
    }

    #[test]
    fn redirect_round_trip() {
        let peer = MeshPeerInfo {
            peer_id: "b3b3/redirect".into(),
            server_name: "node-b.lagun.co".into(),
            public_key_hex: "abcd".into(),
            site_name: "lagun.co".into(),
            node_name: "node-b".into(),
            yggdrasil_addr: Some("200:b::1".into()),
            ..Default::default()
        };
        let msg = MeshMessage::Redirect { peers: vec![peer] };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"redirect""#));

        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Redirect { peers } => {
                assert_eq!(peers.len(), 1);
                assert_eq!(peers[0].peer_id, "b3b3/redirect");
                assert_eq!(peers[0].yggdrasil_addr.as_deref(), Some("200:b::1"));
            }
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn redirect_empty_peers() {
        let msg = MeshMessage::Redirect { peers: vec![] };
        let json = msg.to_json().unwrap();
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Redirect { peers } => assert!(peers.is_empty()),
            other => panic!("expected Redirect, got {other:?}"),
        }
    }

    #[test]
    fn cvdf_round_trip() {
        use base64::Engine as _;
        use citadel_lens::service::CvdfServiceMessage;

        // Encode: bincode → base64
        let cvdf_msg = CvdfServiceMessage::SyncReq { from_height: 42 };
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(bincode::serialize(&cvdf_msg).unwrap());

        let msg = MeshMessage::Cvdf { data: encoded };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"cvdf""#));

        // Decode: JSON → base64 → bincode
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::Cvdf { data } => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&data).unwrap();
                let payload: CvdfServiceMessage = bincode::deserialize(&bytes).unwrap();
                match payload {
                    CvdfServiceMessage::SyncReq { from_height } => assert_eq!(from_height, 42),
                    other => panic!("expected SyncReq, got {other:?}"),
                }
            }
            other => panic!("expected Cvdf, got {other:?}"),
        }
    }

    #[test]
    fn pol_challenge_round_trip() {
        let msg = MeshMessage::PolChallenge { nonce: 0xDEADBEEF_CAFEBABE };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"pol_challenge""#));
        assert!(json.contains(r#""nonce""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::PolChallenge { nonce } => {
                assert_eq!(nonce, 0xDEADBEEF_CAFEBABE);
            }
            other => panic!("expected PolChallenge, got {other:?}"),
        }
    }

    #[test]
    fn pol_response_round_trip() {
        let msg = MeshMessage::PolResponse { nonce: 42 };
        let json = msg.to_json().unwrap();
        assert!(json.contains(r#""type":"pol_response""#));
        let decoded = MeshMessage::from_json(&json).unwrap();
        match decoded {
            MeshMessage::PolResponse { nonce } => assert_eq!(nonce, 42),
            other => panic!("expected PolResponse, got {other:?}"),
        }
    }

    #[test]
    fn pol_challenge_response_nonce_matches() {
        let nonce = 123456789;
        let challenge = MeshMessage::PolChallenge { nonce };
        let response = MeshMessage::PolResponse { nonce };
        let cj = challenge.to_json().unwrap();
        let rj = response.to_json().unwrap();
        match (MeshMessage::from_json(&cj).unwrap(), MeshMessage::from_json(&rj).unwrap()) {
            (MeshMessage::PolChallenge { nonce: cn }, MeshMessage::PolResponse { nonce: rn }) => {
                assert_eq!(cn, rn);
            }
            _ => panic!("unexpected types"),
        }
    }

    #[test]
    fn switchboard_unknown_type_fails() {
        let json = r#"{"type":"bogus_switchboard","data":"x"}"#;
        assert!(SwitchboardMessage::from_line(json).is_err());
    }
}
