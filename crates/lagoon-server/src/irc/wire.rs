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
    #[serde(default)]
    pub ygg_peer_uri: Option<String>,
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
            ygg_peer_uri: Some("tcp://[200:1234::1]:9443".into()),
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
}
