//! VDF engine — runs a continuous Blake3 hash chain as a tokio task.
//!
//! Each Lagoon node runs its own VDF chain, ticking at a configurable rate.
//! The chain provides proof-of-elapsed-time that peers can verify via ZK proofs.
//!
//! Genesis is deterministically derived from the node's ed25519 public key,
//! so anyone can verify the expected genesis for a given identity.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch, RwLock};
use tracing::info;

/// Snapshot of the VDF engine's current state, broadcast via watch channel.
#[derive(Debug, Clone)]
pub struct VdfState {
    /// Genesis hash (derived from public key).
    pub genesis: [u8; 32],
    /// Current chain tip hash.
    pub current_hash: [u8; 32],
    /// Steps computed in this session (provable via ZK).
    pub session_steps: u64,
    /// Cumulative steps across all sessions (session + restored).
    pub total_steps: u64,
}

/// Derive a VDF genesis hash from an ed25519 public key.
///
/// Deterministic: given a public key, anyone can compute the expected genesis.
/// Uses a domain separator to prevent collisions with other Blake3 usages.
pub fn derive_genesis(public_key: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"lagoon-vdf-genesis-v1");
    h.update(public_key);
    *h.finalize().as_bytes()
}

/// Run the VDF engine as an async task.
///
/// Ticks a VDF chain at a configurable rate (default 10 Hz, set via LAGOON_VDF_RATE).
/// Broadcasts state updates via the watch channel. Stops on shutdown signal.
///
/// The `chain` is shared via `Arc<RwLock<>>` so ZK proofs can be generated on demand.
pub async fn run_vdf_engine(
    genesis: [u8; 32],
    restored_total: u64,
    chain: Arc<RwLock<lagoon_vdf::VdfChain>>,
    state_tx: watch::Sender<VdfState>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let tick_rate: u64 = std::env::var("LAGOON_VDF_RATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let tick_duration = Duration::from_millis(1000 / tick_rate.max(1));
    let mut interval = tokio::time::interval(tick_duration);
    // Don't try to catch up if we fall behind — just skip missed ticks.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!(
        tick_rate_hz = tick_rate,
        genesis = lagoon_vdf::to_hex_short(&genesis, 8),
        restored_total,
        "VDF engine started"
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let mut c = chain.write().await;
                c.tick();
                let session_steps = c.steps();
                let current_hash = c.final_hash();
                drop(c);

                let _ = state_tx.send(VdfState {
                    genesis,
                    current_hash,
                    session_steps,
                    total_steps: restored_total + session_steps,
                });
            }
            _ = shutdown.recv() => {
                info!("VDF engine shutting down");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_genesis_deterministic() {
        let key = [42u8; 32];
        let g1 = derive_genesis(&key);
        let g2 = derive_genesis(&key);
        assert_eq!(g1, g2);
    }

    #[test]
    fn derive_genesis_different_keys() {
        let g1 = derive_genesis(&[1u8; 32]);
        let g2 = derive_genesis(&[2u8; 32]);
        assert_ne!(g1, g2);
    }

    #[test]
    fn derive_genesis_domain_separated() {
        // Raw blake3 of the key should differ from our domain-separated genesis.
        let key = [42u8; 32];
        let raw = *blake3::hash(&key).as_bytes();
        let genesis = derive_genesis(&key);
        assert_ne!(raw, genesis);
    }

    #[tokio::test]
    async fn vdf_engine_ticks() {
        let genesis = derive_genesis(&[99u8; 32]);
        let chain = Arc::new(RwLock::new(lagoon_vdf::VdfChain::new(genesis)));
        let (state_tx, mut state_rx) = watch::channel(VdfState {
            genesis,
            current_hash: genesis,
            session_steps: 0,
            total_steps: 0,
        });
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let chain_clone = Arc::clone(&chain);
        let handle = tokio::spawn(async move {
            // Override tick rate to very fast for test (env var won't be set,
            // so we use default 10Hz which ticks every 100ms).
            run_vdf_engine(genesis, 0, chain_clone, state_tx, shutdown_rx).await;
        });

        // Wait for at least one tick.
        tokio::time::timeout(Duration::from_secs(2), state_rx.changed())
            .await
            .expect("timed out waiting for VDF tick")
            .expect("watch channel closed");

        let state = state_rx.borrow().clone();
        assert!(state.session_steps > 0);
        assert!(state.total_steps > 0);
        assert_ne!(state.current_hash, genesis);

        let _ = shutdown_tx.send(());
        let _ = handle.await;
    }

    #[tokio::test]
    async fn vdf_engine_restored_total() {
        let genesis = derive_genesis(&[50u8; 32]);
        let chain = Arc::new(RwLock::new(lagoon_vdf::VdfChain::new(genesis)));
        let restored = 1000;
        let (state_tx, mut state_rx) = watch::channel(VdfState {
            genesis,
            current_hash: genesis,
            session_steps: 0,
            total_steps: restored,
        });
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let chain_clone = Arc::clone(&chain);
        let handle = tokio::spawn(async move {
            run_vdf_engine(genesis, restored, chain_clone, state_tx, shutdown_rx).await;
        });

        tokio::time::timeout(Duration::from_secs(2), state_rx.changed())
            .await
            .expect("timed out")
            .expect("closed");

        let state = state_rx.borrow().clone();
        assert!(state.total_steps > restored);
        assert_eq!(state.total_steps, restored + state.session_steps);

        let _ = shutdown_tx.send(());
        let _ = handle.await;
    }
}
