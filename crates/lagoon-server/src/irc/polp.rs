//! Proof-of-Latency Protocol (PoLP) — cryptographic challenge-response RTT measurement.
//!
//! Implements Citadel Paper 12's core primitive: challenge-response latency
//! measurement with bilateral Ed25519 signatures. Each proof attests that two
//! peers measured a specific RTT at a specific time.
//!
//! ## Protocol Flow
//!
//! 1. **Challenger** generates a random 32-byte nonce → `LatencyChallenge`
//! 2. **Responder** signs the nonce with their Ed25519 key → `ChallengeResponse`
//! 3. **Challenger** measures RTT from send→receive, verifies signature
//! 4. **Both** sign the `(edge, rtt_ms, timestamp)` tuple → `LatencyProof`
//!
//! The bilateral signature prevents either party from forging a proof alone.
//! The BLAKE3 proof hash serves as a unique content ID for SPORE set-tracking.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Domain separator for challenge-response signatures.
const CHALLENGE_DOMAIN: &[u8] = b"lagoon-polp-challenge-v1";

/// Domain separator for proof signing (bilateral attestation).
const PROOF_DOMAIN: &[u8] = b"lagoon-polp-proof-v1";

/// A latency measurement challenge: random nonce + metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyChallenge {
    /// Random 32-byte nonce.
    pub nonce: [u8; 32],
    /// Peer ID of the challenger (the node that initiated the challenge).
    pub challenger_peer_id: String,
    /// Timestamp when the challenge was created (ms since epoch).
    pub created_ms: i64,
}

/// Response to a latency challenge: Ed25519 signature of the domain-separated nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The nonce being responded to (must match the challenge).
    pub nonce: [u8; 32],
    /// Ed25519 signature of `BLAKE3(CHALLENGE_DOMAIN || nonce)`.
    pub signature: Vec<u8>,
    /// Responder's peer ID.
    pub responder_peer_id: String,
    /// Responder's Ed25519 public key (32 bytes).
    pub responder_pubkey: [u8; 32],
}

/// A bilateral latency proof: both peers attest to the measured RTT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyProof {
    /// Sorted edge (peer_a < peer_b lexicographically).
    pub edge: (String, String),
    /// Measured round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// Timestamp of the measurement (ms since epoch).
    pub timestamp_ms: i64,
    /// The challenge nonce used for this measurement.
    pub nonce: [u8; 32],
    /// Challenger's Ed25519 signature of the proof hash.
    pub challenger_sig: Vec<u8>,
    /// Challenger's public key.
    pub challenger_pubkey: [u8; 32],
    /// Responder's Ed25519 signature of the proof hash.
    pub responder_sig: Vec<u8>,
    /// Responder's public key.
    pub responder_pubkey: [u8; 32],
    /// BLAKE3 proof hash — used as SPORE content ID.
    pub proof_hash: [u8; 32],
}

/// Create a new latency challenge with a random nonce.
pub fn create_challenge(challenger_peer_id: &str, now_ms: i64) -> LatencyChallenge {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill(&mut nonce);
    LatencyChallenge {
        nonce,
        challenger_peer_id: challenger_peer_id.to_owned(),
        created_ms: now_ms,
    }
}

/// Compute the challenge signing payload: `BLAKE3(CHALLENGE_DOMAIN || nonce)`.
fn challenge_signing_payload(nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// Sign a challenge response (called by the responder).
///
/// Returns a `ChallengeResponse` containing the Ed25519 signature over the
/// domain-separated nonce.
pub fn sign_challenge_response(
    challenge: &LatencyChallenge,
    signing_key: &SigningKey,
    responder_peer_id: &str,
) -> ChallengeResponse {
    let payload = challenge_signing_payload(&challenge.nonce);
    let signature = signing_key.sign(&payload);
    ChallengeResponse {
        nonce: challenge.nonce,
        signature: signature.to_bytes().to_vec(),
        responder_peer_id: responder_peer_id.to_owned(),
        responder_pubkey: signing_key.verifying_key().to_bytes(),
    }
}

/// Verify a challenge response signature.
///
/// Returns `true` if the responder's signature over the nonce is valid.
pub fn verify_challenge_response(
    response: &ChallengeResponse,
    expected_nonce: &[u8; 32],
) -> bool {
    if response.nonce != *expected_nonce {
        return false;
    }

    let sig_bytes: [u8; 64] = match response.signature.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_bytes);

    let verifying_key = match VerifyingKey::from_bytes(&response.responder_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };

    let payload = challenge_signing_payload(expected_nonce);
    verifying_key.verify(&payload, &signature).is_ok()
}

/// Compute the proof signing hash: `BLAKE3(PROOF_DOMAIN || edge.0 || edge.1 || rtt_ms_bytes || timestamp_bytes || nonce)`.
///
/// This is what both parties sign to create the bilateral proof.
pub fn proof_signing_hash(
    edge: &(String, String),
    rtt_ms: f64,
    timestamp_ms: i64,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROOF_DOMAIN);
    hasher.update(edge.0.as_bytes());
    hasher.update(edge.1.as_bytes());
    hasher.update(&rtt_ms.to_le_bytes());
    hasher.update(&timestamp_ms.to_le_bytes());
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

/// Sign a proof hash with an Ed25519 key.
pub fn sign_proof_hash(signing_key: &SigningKey, proof_hash: &[u8; 32]) -> Vec<u8> {
    signing_key.sign(proof_hash).to_bytes().to_vec()
}

/// Build a complete bilateral `LatencyProof`.
///
/// Called by the challenger after verifying the response and measuring RTT.
/// Both the challenger's and responder's signatures attest to the measurement.
pub fn build_proof(
    challenger_peer_id: &str,
    responder_peer_id: &str,
    rtt_ms: f64,
    timestamp_ms: i64,
    nonce: &[u8; 32],
    challenger_key: &SigningKey,
    responder_sig: &[u8],
    responder_pubkey: &[u8; 32],
) -> LatencyProof {
    let edge = canonical_edge(challenger_peer_id, responder_peer_id);
    let proof_hash = proof_signing_hash(&edge, rtt_ms, timestamp_ms, nonce);
    let challenger_sig = sign_proof_hash(challenger_key, &proof_hash);

    LatencyProof {
        edge,
        rtt_ms,
        timestamp_ms,
        nonce: *nonce,
        challenger_sig,
        challenger_pubkey: challenger_key.verifying_key().to_bytes(),
        responder_sig: responder_sig.to_vec(),
        responder_pubkey: *responder_pubkey,
        proof_hash,
    }
}

/// Verify a bilateral latency proof.
///
/// Checks:
/// 1. Proof hash matches the declared edge/rtt/timestamp/nonce
/// 2. Challenger's signature over the proof hash is valid
/// 3. Responder's signature over the proof hash is valid
pub fn verify_proof(proof: &LatencyProof) -> bool {
    // Recompute the proof hash.
    let expected_hash = proof_signing_hash(
        &proof.edge,
        proof.rtt_ms,
        proof.timestamp_ms,
        &proof.nonce,
    );
    if expected_hash != proof.proof_hash {
        return false;
    }

    // Verify challenger signature.
    if !verify_signature(
        &proof.challenger_pubkey,
        &proof.challenger_sig,
        &proof.proof_hash,
    ) {
        return false;
    }

    // Verify responder signature.
    verify_signature(
        &proof.responder_pubkey,
        &proof.responder_sig,
        &proof.proof_hash,
    )
}

/// Verify a single Ed25519 signature over a message.
fn verify_signature(pubkey_bytes: &[u8; 32], sig_bytes: &[u8], message: &[u8]) -> bool {
    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_array);

    let verifying_key = match VerifyingKey::from_bytes(pubkey_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };

    verifying_key.verify(message, &signature).is_ok()
}

/// Produce a canonical sorted edge (alphabetically by peer ID).
pub fn canonical_edge(peer_a: &str, peer_b: &str) -> (String, String) {
    if peer_a <= peer_b {
        (peer_a.to_owned(), peer_b.to_owned())
    } else {
        (peer_b.to_owned(), peer_a.to_owned())
    }
}

/// Check whether a proof is fresh relative to a TTL.
pub fn is_proof_fresh(proof: &LatencyProof, now_ms: i64, ttl_ms: i64) -> bool {
    now_ms - proof.timestamp_ms <= ttl_ms
}

/// Serialize a proof for wire transport / storage.
pub fn serialize_proof(proof: &LatencyProof) -> Vec<u8> {
    bincode::serialize(proof).expect("LatencyProof serialization cannot fail")
}

/// Deserialize a proof from wire bytes.
pub fn deserialize_proof(bytes: &[u8]) -> Option<LatencyProof> {
    bincode::deserialize(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> SigningKey {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    fn deterministic_keypair(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    #[test]
    fn test_create_challenge_has_random_nonce() {
        let c1 = create_challenge("b3b3/alice", 1000);
        let c2 = create_challenge("b3b3/alice", 1000);
        assert_ne!(c1.nonce, c2.nonce);
        assert_eq!(c1.challenger_peer_id, "b3b3/alice");
        assert_eq!(c1.created_ms, 1000);
    }

    #[test]
    fn test_challenge_response_signs_correctly() {
        let key = test_keypair();
        let challenge = create_challenge("b3b3/alice", 1000);
        let response = sign_challenge_response(&challenge, &key, "b3b3/bob");

        assert_eq!(response.nonce, challenge.nonce);
        assert_eq!(response.responder_peer_id, "b3b3/bob");
        assert_eq!(response.signature.len(), 64);
    }

    #[test]
    fn test_verify_challenge_response_valid() {
        let key = test_keypair();
        let challenge = create_challenge("b3b3/alice", 1000);
        let response = sign_challenge_response(&challenge, &key, "b3b3/bob");

        assert!(verify_challenge_response(&response, &challenge.nonce));
    }

    #[test]
    fn test_verify_challenge_response_wrong_nonce() {
        let key = test_keypair();
        let challenge = create_challenge("b3b3/alice", 1000);
        let response = sign_challenge_response(&challenge, &key, "b3b3/bob");

        let wrong_nonce = [0xFFu8; 32];
        assert!(!verify_challenge_response(&response, &wrong_nonce));
    }

    #[test]
    fn test_verify_challenge_response_tampered_sig() {
        let key = test_keypair();
        let challenge = create_challenge("b3b3/alice", 1000);
        let mut response = sign_challenge_response(&challenge, &key, "b3b3/bob");

        // Tamper with the signature.
        response.signature[0] ^= 0xFF;
        assert!(!verify_challenge_response(&response, &challenge.nonce));
    }

    #[test]
    fn test_verify_challenge_response_wrong_key() {
        let key1 = test_keypair();
        let key2 = test_keypair();
        let challenge = create_challenge("b3b3/alice", 1000);
        let mut response = sign_challenge_response(&challenge, &key1, "b3b3/bob");

        // Replace pubkey with a different key's.
        response.responder_pubkey = key2.verifying_key().to_bytes();
        assert!(!verify_challenge_response(&response, &challenge.nonce));
    }

    #[test]
    fn test_proof_signing_hash_deterministic() {
        let edge = ("b3b3/alice".to_owned(), "b3b3/bob".to_owned());
        let nonce = [42u8; 32];
        let h1 = proof_signing_hash(&edge, 15.0, 1000, &nonce);
        let h2 = proof_signing_hash(&edge, 15.0, 1000, &nonce);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_proof_signing_hash_varies_with_rtt() {
        let edge = ("b3b3/alice".to_owned(), "b3b3/bob".to_owned());
        let nonce = [42u8; 32];
        let h1 = proof_signing_hash(&edge, 15.0, 1000, &nonce);
        let h2 = proof_signing_hash(&edge, 16.0, 1000, &nonce);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_proof_signing_hash_varies_with_timestamp() {
        let edge = ("b3b3/alice".to_owned(), "b3b3/bob".to_owned());
        let nonce = [42u8; 32];
        let h1 = proof_signing_hash(&edge, 15.0, 1000, &nonce);
        let h2 = proof_signing_hash(&edge, 15.0, 2000, &nonce);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_build_and_verify_proof() {
        let challenger_key = deterministic_keypair(1);
        let responder_key = deterministic_keypair(2);

        let challenge = create_challenge("b3b3/alice", 1000);
        let response = sign_challenge_response(&challenge, &responder_key, "b3b3/bob");
        assert!(verify_challenge_response(&response, &challenge.nonce));

        // Build the proof hash (responder signs it too).
        let edge = canonical_edge("b3b3/alice", "b3b3/bob");
        let proof_hash = proof_signing_hash(&edge, 15.0, 1000, &challenge.nonce);
        let responder_proof_sig = sign_proof_hash(&responder_key, &proof_hash);

        let proof = build_proof(
            "b3b3/alice",
            "b3b3/bob",
            15.0,
            1000,
            &challenge.nonce,
            &challenger_key,
            &responder_proof_sig,
            &responder_key.verifying_key().to_bytes(),
        );

        assert!(verify_proof(&proof));
        assert_eq!(proof.edge, ("b3b3/alice".to_owned(), "b3b3/bob".to_owned()));
        assert_eq!(proof.rtt_ms, 15.0);
        assert_eq!(proof.timestamp_ms, 1000);
    }

    #[test]
    fn test_verify_proof_tampered_rtt() {
        let challenger_key = deterministic_keypair(1);
        let responder_key = deterministic_keypair(2);

        let challenge = create_challenge("b3b3/alice", 1000);
        let edge = canonical_edge("b3b3/alice", "b3b3/bob");
        let proof_hash = proof_signing_hash(&edge, 15.0, 1000, &challenge.nonce);
        let responder_proof_sig = sign_proof_hash(&responder_key, &proof_hash);

        let mut proof = build_proof(
            "b3b3/alice",
            "b3b3/bob",
            15.0,
            1000,
            &challenge.nonce,
            &challenger_key,
            &responder_proof_sig,
            &responder_key.verifying_key().to_bytes(),
        );

        // Tamper: change the RTT after signing.
        proof.rtt_ms = 1.0;
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn test_verify_proof_tampered_challenger_sig() {
        let challenger_key = deterministic_keypair(1);
        let responder_key = deterministic_keypair(2);

        let challenge = create_challenge("b3b3/alice", 1000);
        let edge = canonical_edge("b3b3/alice", "b3b3/bob");
        let proof_hash = proof_signing_hash(&edge, 15.0, 1000, &challenge.nonce);
        let responder_proof_sig = sign_proof_hash(&responder_key, &proof_hash);

        let mut proof = build_proof(
            "b3b3/alice",
            "b3b3/bob",
            15.0,
            1000,
            &challenge.nonce,
            &challenger_key,
            &responder_proof_sig,
            &responder_key.verifying_key().to_bytes(),
        );

        proof.challenger_sig[0] ^= 0xFF;
        assert!(!verify_proof(&proof));
    }

    #[test]
    fn test_canonical_edge_sorts() {
        let edge = canonical_edge("b3b3/bob", "b3b3/alice");
        assert_eq!(edge.0, "b3b3/alice");
        assert_eq!(edge.1, "b3b3/bob");

        let edge2 = canonical_edge("b3b3/alice", "b3b3/bob");
        assert_eq!(edge, edge2);
    }

    #[test]
    fn test_is_proof_fresh() {
        let challenger_key = deterministic_keypair(1);
        let responder_key = deterministic_keypair(2);

        let challenge = create_challenge("b3b3/alice", 5000);
        let edge = canonical_edge("b3b3/alice", "b3b3/bob");
        let proof_hash = proof_signing_hash(&edge, 10.0, 5000, &challenge.nonce);
        let resp_sig = sign_proof_hash(&responder_key, &proof_hash);

        let proof = build_proof(
            "b3b3/alice",
            "b3b3/bob",
            10.0,
            5000,
            &challenge.nonce,
            &challenger_key,
            &resp_sig,
            &responder_key.verifying_key().to_bytes(),
        );

        // Within 60s TTL.
        assert!(is_proof_fresh(&proof, 50_000, 60_000));
        // Outside TTL.
        assert!(!is_proof_fresh(&proof, 100_000, 60_000));
    }

    #[test]
    fn test_serialize_deserialize_proof() {
        let challenger_key = deterministic_keypair(1);
        let responder_key = deterministic_keypair(2);

        let challenge = create_challenge("b3b3/alice", 1000);
        let edge = canonical_edge("b3b3/alice", "b3b3/bob");
        let proof_hash = proof_signing_hash(&edge, 15.0, 1000, &challenge.nonce);
        let resp_sig = sign_proof_hash(&responder_key, &proof_hash);

        let proof = build_proof(
            "b3b3/alice",
            "b3b3/bob",
            15.0,
            1000,
            &challenge.nonce,
            &challenger_key,
            &resp_sig,
            &responder_key.verifying_key().to_bytes(),
        );

        let bytes = serialize_proof(&proof);
        let decoded = deserialize_proof(&bytes).expect("deserialization should succeed");
        assert_eq!(decoded.edge, proof.edge);
        assert_eq!(decoded.rtt_ms, proof.rtt_ms);
        assert_eq!(decoded.proof_hash, proof.proof_hash);
        assert!(verify_proof(&decoded));
    }

    #[test]
    fn test_deserialize_invalid_bytes() {
        let result = deserialize_proof(b"not a valid proof");
        assert!(result.is_none());
    }
}
