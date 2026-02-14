//! VDF engine — runs a continuous Blake3 hash chain as a tokio task.
//!
//! Each Lagoon node runs its own VDF chain, ticking at a configurable rate.
//! The chain provides proof-of-elapsed-time that peers can verify via ZK proofs.
//!
//! Genesis is deterministically derived from the node's ed25519 public key,
//! so anyone can verify the expected genesis for a given identity.
//!
//! ## Resonance curve
//!
//! The engine measures actual tick timing and scores each tick against a
//! Gaussian "resonance curve" centered on the target rate.  Nodes that tick
//! closer to the target earn higher credit; nodes that drift are penalized
//! symmetrically in both directions.  Over many nodes the independent timing
//! errors average out, giving ensemble-clock precision that scales as 1/√N.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Resonance curve metrics (None until first tick interval is measured).
    pub resonance: Option<ResonanceMetrics>,
}

/// Resonance curve metrics for this node's VDF precision.
#[derive(Debug, Clone)]
pub struct ResonanceMetrics {
    /// Target tick rate in Hz.
    pub target_rate_hz: f64,
    /// Actual measured tick rate (exponential moving average, Hz).
    pub actual_rate_hz: f64,
    /// Resonance credit: exp(-((actual - target) / sigma)^2), range [0, 1].
    pub credit: f64,
    /// Sigma parameter of the resonance Gaussian (Hz).
    pub sigma: f64,
    /// Instantaneous tick interval (last tick, seconds).
    pub last_interval_secs: f64,
    /// Deviation from target (actual_rate - target_rate, Hz). Positive = fast.
    pub deviation_hz: f64,
    /// Cumulative resonance credit (sum of per-tick credits).
    pub cumulative_credit: f64,
    /// Rolling credit over last 3 cycles (30s at 10Hz). Used for SPIRAL
    /// slot collision resolution — measures *current* precision, not lifetime.
    pub rolling_credit_3c: f64,
    /// Number of ticks measured (excludes first tick which has no interval).
    pub measured_ticks: u64,
}

/// Compute resonance credit: Gaussian bell curve centered on target rate.
///
/// `credit(r) = exp(-((r - r0) / sigma)^2)`
///
/// - r: actual tick rate (Hz)
/// - r0: target tick rate (Hz)
/// - sigma: width parameter (Hz) — how forgiving the curve is
///
/// Returns a value in [0, 1] where 1.0 = perfect precision.
pub fn resonance_credit(actual_rate: f64, target_rate: f64, sigma: f64) -> f64 {
    let deviation = actual_rate - target_rate;
    (-((deviation / sigma).powi(2))).exp()
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
///
/// Each tick is instrumented with high-resolution timing.  The actual tick rate
/// is computed as an exponential moving average and scored against a Gaussian
/// resonance curve.  Metrics are published in every `VdfState` snapshot.
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

    // Resonance sigma: how forgiving the bell curve is (Hz).
    // Default: 10% of target rate.  LAGOON_VDF_SIGMA overrides.
    let sigma: f64 = std::env::var("LAGOON_VDF_SIGMA")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(tick_rate as f64 * 0.1);

    let target_rate = tick_rate as f64;
    let tick_duration = Duration::from_millis(1000 / tick_rate.max(1));
    let mut interval = tokio::time::interval(tick_duration);
    // Don't try to catch up if we fall behind — just skip missed ticks.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // EMA smoothing factor.  α = 0.05 → ~20-tick window.
    const EMA_ALPHA: f64 = 0.05;

    // Rolling window: 3 cycles × 10 seconds × tick_rate ticks per second.
    let cycle_secs: u64 = 10;
    let window_ticks = (3 * cycle_secs * tick_rate) as usize;

    let mut last_tick: Option<Instant> = None;
    let mut ema_rate: f64 = target_rate; // start at target (no bias)
    let mut cumulative_credit: f64 = 0.0;
    let mut rolling_window: VecDeque<f64> = VecDeque::with_capacity(window_ticks);
    let mut rolling_sum: f64 = 0.0;
    let mut measured_ticks: u64 = 0;

    info!(
        tick_rate_hz = tick_rate,
        sigma,
        genesis = lagoon_vdf::to_hex_short(&genesis, 8),
        restored_total,
        "VDF engine started (resonance instrumented)"
    );

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = Instant::now();

                let mut c = chain.write().await;
                c.tick();
                let session_steps = c.steps();
                let current_hash = c.final_hash();
                drop(c);

                // Compute resonance metrics from tick timing.
                let resonance = if let Some(prev) = last_tick {
                    let elapsed = now.duration_since(prev);
                    let interval_secs = elapsed.as_secs_f64();
                    let instant_rate = if interval_secs > 0.0 {
                        1.0 / interval_secs
                    } else {
                        target_rate
                    };

                    // Exponential moving average of tick rate.
                    ema_rate = EMA_ALPHA * instant_rate + (1.0 - EMA_ALPHA) * ema_rate;

                    let credit = resonance_credit(ema_rate, target_rate, sigma);
                    cumulative_credit += credit;
                    measured_ticks += 1;

                    // Maintain rolling window of last 3 cycles.
                    rolling_sum += credit;
                    rolling_window.push_back(credit);
                    if rolling_window.len() > window_ticks {
                        rolling_sum -= rolling_window.pop_front().unwrap_or(0.0);
                    }

                    Some(ResonanceMetrics {
                        target_rate_hz: target_rate,
                        actual_rate_hz: ema_rate,
                        credit,
                        sigma,
                        last_interval_secs: interval_secs,
                        deviation_hz: ema_rate - target_rate,
                        cumulative_credit,
                        rolling_credit_3c: rolling_sum,
                        measured_ticks,
                    })
                } else {
                    None
                };
                last_tick = Some(now);

                let _ = state_tx.send(VdfState {
                    genesis,
                    current_hash,
                    session_steps,
                    total_steps: restored_total + session_steps,
                    resonance,
                });
            }
            _ = shutdown.recv() => {
                info!(
                    measured_ticks,
                    cumulative_credit,
                    avg_credit = if measured_ticks > 0 { cumulative_credit / measured_ticks as f64 } else { 0.0 },
                    "VDF engine shutting down"
                );
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

    #[test]
    fn resonance_credit_peak() {
        let c = resonance_credit(10.0, 10.0, 1.0);
        assert!((c - 1.0).abs() < 1e-10, "peak credit should be 1.0");
    }

    #[test]
    fn resonance_credit_symmetric() {
        let fast = resonance_credit(11.0, 10.0, 1.0);
        let slow = resonance_credit(9.0, 10.0, 1.0);
        assert!((fast - slow).abs() < 1e-10, "symmetric around target");
    }

    #[test]
    fn resonance_credit_progressive_penalty() {
        let c1 = resonance_credit(10.1, 10.0, 1.0);
        let c5 = resonance_credit(10.5, 10.0, 1.0);
        let c10 = resonance_credit(11.0, 10.0, 1.0);
        assert!(c1 > c5, "+0.1 Hz better than +0.5 Hz");
        assert!(c5 > c10, "+0.5 Hz better than +1.0 Hz");
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
            resonance: None,
        });
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let chain_clone = Arc::clone(&chain);
        let handle = tokio::spawn(async move {
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
            resonance: None,
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

    #[tokio::test]
    async fn vdf_engine_produces_resonance_metrics() {
        let genesis = derive_genesis(&[77u8; 32]);
        let chain = Arc::new(RwLock::new(lagoon_vdf::VdfChain::new(genesis)));
        let (state_tx, mut state_rx) = watch::channel(VdfState {
            genesis,
            current_hash: genesis,
            session_steps: 0,
            total_steps: 0,
            resonance: None,
        });
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let chain_clone = Arc::clone(&chain);
        let handle = tokio::spawn(async move {
            run_vdf_engine(genesis, 0, chain_clone, state_tx, shutdown_rx).await;
        });

        // Wait for enough ticks that resonance metrics appear (need 2+ ticks).
        for _ in 0..5 {
            let _ = tokio::time::timeout(Duration::from_secs(2), state_rx.changed()).await;
        }

        let state = state_rx.borrow().clone();
        if state.session_steps >= 2 {
            let r = state.resonance.expect("resonance should be Some after 2+ ticks");
            assert!(r.measured_ticks > 0);
            assert!(r.credit > 0.0 && r.credit <= 1.0);
            assert!(r.actual_rate_hz > 0.0);
            assert!(r.cumulative_credit > 0.0);
        }

        let _ = shutdown_tx.send(());
        let _ = handle.await;
    }
}
