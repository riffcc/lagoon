/// Lens identity — cryptographic identity for mesh networking.
///
/// Each Lagoon server gets a persistent ed25519 keypair and a PeerID derived
/// via double-BLAKE3 hashing of the public key. This is interoperable with
/// Citadel's `compute_peer_id` from `citadel-lens/src/mesh/peer.rs`.
use std::path::Path;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Persistent cryptographic identity for a Lagoon server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensIdentity {
    /// Secret seed — the ed25519 private key material (32 bytes, hex-encoded in JSON).
    pub secret_seed: [u8; 32],
    /// Hex-encoded ed25519 public key.
    pub public_key_hex: String,
    /// PeerID: `"b3b3/{hex(BLAKE3(BLAKE3(pubkey)))}"`.
    pub peer_id: String,
    /// The server name this identity was generated for.
    pub server_name: String,
    /// Site identity for supernode clustering (derived from server_name).
    #[serde(default)]
    pub site_name: String,
    /// Node identity within site (derived from server_name).
    #[serde(default)]
    pub node_name: String,
    /// Claimed SPIRAL slot index (None = unclaimed fresh node).
    #[serde(default)]
    pub spiral_index: Option<u64>,
    /// Cumulative VDF steps persisted across restarts.
    #[serde(default)]
    pub vdf_total_steps: u64,
}

/// Compute a PeerID from an ed25519 public key.
///
/// Uses double-BLAKE3 hashing to derive a stable identifier:
/// `"b3b3/{hex(BLAKE3(BLAKE3(pubkey)))}"`.
///
/// This matches Citadel's `compute_peer_id` algorithm.
pub fn compute_peer_id(pubkey_bytes: &[u8; 32]) -> String {
    let first = blake3::hash(pubkey_bytes);
    let second = blake3::hash(first.as_bytes());
    format!("b3b3/{}", hex::encode(second.as_bytes()))
}

/// Verify that a claimed PeerID matches the given public key.
pub fn verify_peer_id(claimed: &str, pubkey_bytes: &[u8; 32]) -> bool {
    compute_peer_id(pubkey_bytes) == claimed
}

/// Generate a new Lens identity for the given server name.
pub fn generate_identity(server_name: &str) -> LensIdentity {
    let mut csprng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes = verifying_key.to_bytes();
    let public_key_hex = hex::encode(pubkey_bytes);
    let peer_id = compute_peer_id(&pubkey_bytes);

    LensIdentity {
        secret_seed: signing_key.to_bytes(),
        public_key_hex,
        peer_id,
        server_name: server_name.to_owned(),
        site_name: super::server::SITE_NAME.clone(),
        node_name: super::server::NODE_NAME.clone(),
        spiral_index: None,
        vdf_total_steps: 0,
    }
}

/// Load an existing identity from disk, or generate and persist a new one.
///
/// Identity is stored as `{data_dir}/lens_identity.json`.
pub fn load_or_create(data_dir: &Path, server_name: &str) -> LensIdentity {
    let identity_path = data_dir.join("lens_identity.json");

    if identity_path.exists() {
        match std::fs::read_to_string(&identity_path) {
            Ok(json) => match serde_json::from_str::<LensIdentity>(&json) {
                Ok(identity) => {
                    // Verify the identity is internally consistent.
                    let signing_key = SigningKey::from_bytes(&identity.secret_seed);
                    let pubkey_bytes = signing_key.verifying_key().to_bytes();
                    let expected_hex = hex::encode(pubkey_bytes);
                    let expected_peer_id = compute_peer_id(&pubkey_bytes);

                    if identity.public_key_hex != expected_hex
                        || identity.peer_id != expected_peer_id
                    {
                        warn!("lens identity file is inconsistent, regenerating");
                    } else {
                        // Always sync node_name/site_name from runtime statics
                        // (env vars or hostname may differ from what was persisted).
                        let mut identity = identity;
                        identity.site_name = super::server::SITE_NAME.clone();
                        identity.node_name = super::server::NODE_NAME.clone();
                        info!(
                            peer_id = %identity.peer_id,
                            "loaded lens identity from {}",
                            identity_path.display()
                        );
                        return identity;
                    }
                }
                Err(e) => {
                    warn!("failed to parse lens identity: {e}, regenerating");
                }
            },
            Err(e) => {
                warn!("failed to read lens identity: {e}, regenerating");
            }
        }
    }

    // Generate new identity.
    let identity = generate_identity(server_name);

    // Ensure data directory exists.
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        warn!("failed to create data dir {}: {e}", data_dir.display());
        return identity;
    }

    // Atomic write: write to tmp, rename into place.
    let tmp_path = data_dir.join("lens_identity.json.tmp");
    match serde_json::to_string_pretty(&identity) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&tmp_path, &json) {
                warn!("failed to write lens identity tmp file: {e}");
            } else if let Err(e) = std::fs::rename(&tmp_path, &identity_path) {
                warn!("failed to rename lens identity file: {e}");
            } else {
                info!(
                    peer_id = %identity.peer_id,
                    "generated new lens identity at {}",
                    identity_path.display()
                );
            }
        }
        Err(e) => {
            warn!("failed to serialize lens identity: {e}");
        }
    }

    identity
}

/// Persist an updated LensIdentity to disk (e.g. after claiming a SPIRAL slot).
///
/// Uses atomic write (tmp + rename) to avoid corruption.
pub fn persist_identity(data_dir: &Path, identity: &LensIdentity) {
    let identity_path = data_dir.join("lens_identity.json");
    let tmp_path = data_dir.join("lens_identity.json.tmp");
    match serde_json::to_string_pretty(identity) {
        Ok(json) => {
            if let Err(e) = std::fs::write(&tmp_path, &json) {
                warn!("failed to write lens identity tmp file: {e}");
            } else if let Err(e) = std::fs::rename(&tmp_path, &identity_path) {
                warn!("failed to rename lens identity file: {e}");
            } else {
                info!(
                    peer_id = %identity.peer_id,
                    spiral_index = ?identity.spiral_index,
                    vdf_total_steps = identity.vdf_total_steps,
                    "persisted lens identity to {}",
                    identity_path.display()
                );
            }
        }
        Err(e) => {
            warn!("failed to serialize lens identity: {e}");
        }
    }
}

/// Extract the public key bytes from a LensIdentity.
pub fn pubkey_bytes(identity: &LensIdentity) -> Option<[u8; 32]> {
    let signing_key = SigningKey::from_bytes(&identity.secret_seed);
    Some(signing_key.verifying_key().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_peer_id_deterministic() {
        let key = [42u8; 32];
        let id1 = compute_peer_id(&key);
        let id2 = compute_peer_id(&key);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("b3b3/"));
    }

    #[test]
    fn compute_peer_id_different_keys() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        assert_ne!(compute_peer_id(&key1), compute_peer_id(&key2));
    }

    #[test]
    fn verify_peer_id_valid() {
        let key = [99u8; 32];
        let peer_id = compute_peer_id(&key);
        assert!(verify_peer_id(&peer_id, &key));
    }

    #[test]
    fn verify_peer_id_invalid() {
        let key = [99u8; 32];
        assert!(!verify_peer_id("b3b3/0000", &key));
    }

    #[test]
    fn generate_identity_has_valid_peer_id() {
        let identity = generate_identity("test.lagun.co");
        let signing_key = SigningKey::from_bytes(&identity.secret_seed);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();
        assert!(verify_peer_id(&identity.peer_id, &pubkey_bytes));
        assert_eq!(identity.server_name, "test.lagun.co");
        assert_eq!(identity.public_key_hex, hex::encode(pubkey_bytes));
    }

    #[test]
    fn generate_identity_unique_each_time() {
        let id1 = generate_identity("a.lagun.co");
        let id2 = generate_identity("b.lagun.co");
        assert_ne!(id1.peer_id, id2.peer_id);
        assert_ne!(id1.secret_seed, id2.secret_seed);
    }

    #[test]
    fn load_or_create_generates_new() {
        let tmp = std::env::temp_dir().join(format!("lagoon-test-lens-{}", rand::random::<u64>()));
        let identity = load_or_create(&tmp, "test.lagun.co");
        assert!(identity.peer_id.starts_with("b3b3/"));
        // Check file was written.
        assert!(tmp.join("lens_identity.json").exists());
        // Clean up.
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn load_or_create_loads_existing() {
        let tmp = std::env::temp_dir().join(format!("lagoon-test-lens-{}", rand::random::<u64>()));
        let id1 = load_or_create(&tmp, "test.lagun.co");
        let id2 = load_or_create(&tmp, "test.lagun.co");
        assert_eq!(id1.peer_id, id2.peer_id);
        assert_eq!(id1.secret_seed, id2.secret_seed);
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn peer_id_format() {
        let key = [0u8; 32];
        let peer_id = compute_peer_id(&key);
        assert!(peer_id.starts_with("b3b3/"));
        // BLAKE3 output is 32 bytes = 64 hex chars.
        let hex_part = &peer_id[5..];
        assert_eq!(hex_part.len(), 64);
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pubkey_bytes_roundtrip() {
        let identity = generate_identity("test.lagun.co");
        let bytes = pubkey_bytes(&identity).unwrap();
        assert_eq!(hex::encode(bytes), identity.public_key_hex);
    }
}
