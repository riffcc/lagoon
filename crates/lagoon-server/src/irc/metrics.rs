// Copyright (c) 2026 Lagun Project. All rights reserved.
// Released under AGPL-3.0-or-later license.

//! Prometheus metrics for Lagoon.
//!
//! All metric name constants live here. Call sites use these constants rather
//! than raw strings to prevent typos and keep renaming centralized.
//!
//! Three background collectors are spawned at server startup:
//! - `spawn_system_collector`  — CPU/RAM via sysinfo (5s interval, unavoidable)
//! - `spawn_vdf_metrics_collector` — VDF resonance via watch channel (event-driven)
//! - `spawn_mesh_metrics_collector` — topology gauges via watch channel (event-driven)

use metrics::{counter, gauge, histogram};
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};
use tokio::sync::watch;
use tracing::warn;

use crate::irc::server::{MeshSnapshot, SharedState};
use crate::irc::vdf::VdfState;

// ---------------------------------------------------------------------------
// Relay / federation metrics
// ---------------------------------------------------------------------------

/// Total bytes sent to remote relay peers.
pub const RELAY_BYTES_SENT: &str = "lagoon_relay_bytes_sent_total";
/// Total bytes received from remote relay peers.
pub const RELAY_BYTES_RECV: &str = "lagoon_relay_bytes_received_total";
/// Total mesh wire messages sent.
pub const RELAY_MSGS_SENT: &str = "lagoon_relay_messages_sent_total";
/// Total mesh wire messages received.
pub const RELAY_MSGS_RECV: &str = "lagoon_relay_messages_received_total";
/// Total outbound connection attempts.
pub const RELAY_CONNECT_ATTEMPT: &str = "lagoon_relay_connect_attempts_total";
/// Total successful connections (MeshHello exchanged).
pub const RELAY_CONNECT_SUCCESS: &str = "lagoon_relay_connect_successes_total";
/// Total failed connections (any error before MeshHello).
pub const RELAY_CONNECT_FAILURE: &str = "lagoon_relay_connect_failures_total";
/// Current number of active relay connections (gauge).
pub const RELAY_ACTIVE: &str = "lagoon_relay_connections_active";
/// Relay round-trip latency in milliseconds (histogram).
pub const RELAY_RTT_MS: &str = "lagoon_relay_rtt_milliseconds";

// ---------------------------------------------------------------------------
// Mesh topology metrics
// ---------------------------------------------------------------------------

/// Current number of known peers in the mesh (gauge).
pub const MESH_KNOWN_PEERS: &str = "lagoon_mesh_known_peers_total";
/// Current number of SPIRAL topology neighbors (gauge).
pub const MESH_SPIRAL_NEIGHBORS: &str = "lagoon_mesh_spiral_neighbors_total";
/// Current number of peered Yggdrasil nodes (gauge).
pub const MESH_YGG_PEERS: &str = "lagoon_mesh_yggdrasil_peers_total";

// ---------------------------------------------------------------------------
// VDF engine metrics
// ---------------------------------------------------------------------------

/// Total VDF steps computed across all sessions (gauge).
pub const VDF_STEPS: &str = "lagoon_vdf_steps_total";
/// VDF steps computed in the current session (gauge).
pub const VDF_SESSION_STEPS: &str = "lagoon_vdf_session_steps_total";
/// Actual measured VDF tick rate in Hz (gauge).
pub const VDF_ACTUAL_RATE_HZ: &str = "lagoon_vdf_actual_rate_hz";
/// VDF resonance credit [0, 1] — 1.0 = perfect precision (gauge).
pub const VDF_RESONANCE_CREDIT: &str = "lagoon_vdf_resonance_credit";
/// Cumulative VDF resonance credit across all ticks (gauge).
pub const VDF_CUMULATIVE_CREDIT: &str = "lagoon_vdf_cumulative_credit";
/// Rolling VDF credit over last 3 cycles — used for SPIRAL collision resolution (gauge).
pub const VDF_ROLLING_CREDIT_3C: &str = "lagoon_vdf_rolling_credit_3c";

// ---------------------------------------------------------------------------
// Gossip metrics
// ---------------------------------------------------------------------------

/// Total gossip messages dispatched to peers (counter).
pub const GOSSIP_SENT: &str = "lagoon_gossip_messages_sent_total";
/// Total gossip messages received from peers (counter).
pub const GOSSIP_RECV: &str = "lagoon_gossip_messages_received_total";
/// Gossip message payload size in bytes (histogram).
pub const GOSSIP_DELTA_BYTES: &str = "lagoon_gossip_delta_bytes";

// ---------------------------------------------------------------------------
// IRC server metrics
// ---------------------------------------------------------------------------

/// Current number of connected IRC clients (gauge).
pub const IRC_CLIENTS: &str = "lagoon_irc_clients_connected";
/// Current number of active IRC channels (gauge).
pub const IRC_CHANNELS: &str = "lagoon_irc_channels_active";
/// Total IRC messages processed by command (counter).
pub const IRC_MESSAGES: &str = "lagoon_irc_messages_total";

// ---------------------------------------------------------------------------
// Process / system metrics
// ---------------------------------------------------------------------------

/// Process CPU usage percentage (gauge, 0-100).
pub const PROC_CPU_PCT: &str = "lagoon_process_cpu_usage_percent";
/// Process resident set size in bytes (gauge).
pub const PROC_MEM_BYTES: &str = "lagoon_process_memory_bytes";
/// Process virtual memory size in bytes (gauge).
pub const PROC_VMEM_BYTES: &str = "lagoon_process_virtual_memory_bytes";

// ---------------------------------------------------------------------------
// Background collectors
// ---------------------------------------------------------------------------

/// Collect CPU and RAM metrics via sysinfo, every 5 seconds.
///
/// This is the only place in the metrics system that uses a timer — CPU and
/// RSS cannot be measured any other way. All other collectors are event-driven
/// (watch channel changed() loops).
pub async fn spawn_system_collector() {
    let pid = Pid::from(std::process::id() as usize);
    let refresh_kind = RefreshKind::nothing()
        .with_processes(ProcessRefreshKind::nothing().with_cpu().with_memory());

    let mut sys = System::new_with_specifics(refresh_kind);
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        sys.refresh_specifics(refresh_kind);

        if let Some(proc) = sys.process(pid) {
            gauge!(PROC_CPU_PCT).set(proc.cpu_usage() as f64);
            gauge!(PROC_MEM_BYTES).set(proc.memory() as f64);
            gauge!(PROC_VMEM_BYTES).set(proc.virtual_memory() as f64);
        }
    }
}

/// Update VDF metrics from the watch channel whenever the state changes.
///
/// Driven entirely by `rx.changed()` — fires at the VDF tick rate (default 10 Hz).
pub async fn spawn_vdf_metrics_collector(mut rx: watch::Receiver<VdfState>) {
    loop {
        if rx.changed().await.is_err() {
            // Sender dropped — VDF engine shut down.
            break;
        }
        let state = rx.borrow_and_update().clone();

        gauge!(VDF_STEPS).set(state.total_steps as f64);
        gauge!(VDF_SESSION_STEPS).set(state.session_steps as f64);

        if let Some(r) = &state.resonance {
            gauge!(VDF_ACTUAL_RATE_HZ).set(r.actual_rate_hz);
            gauge!(VDF_RESONANCE_CREDIT).set(r.credit);
            gauge!(VDF_CUMULATIVE_CREDIT).set(r.cumulative_credit);
            gauge!(VDF_ROLLING_CREDIT_3C).set(r.rolling_credit_3c);
        }
    }
}

/// Update mesh topology gauges whenever the topology snapshot changes.
///
/// Driven by the topology watch channel — fires on every mesh state change.
/// Reads the full ServerState briefly to capture known_peers and SPIRAL counts.
pub async fn spawn_mesh_metrics_collector(
    mut topology_rx: watch::Receiver<MeshSnapshot>,
    state: SharedState,
) {
    loop {
        if topology_rx.changed().await.is_err() {
            break;
        }

        // Brief read of the shared state — just counting collection lengths.
        let st = match state.try_read() {
            Ok(s) => s,
            Err(_) => {
                // State is write-locked (topology update in progress). Skip this
                // snapshot — the next changed() will fire shortly.
                warn!("mesh metrics: state locked, skipping snapshot");
                continue;
            }
        };

        gauge!(MESH_KNOWN_PEERS).set(st.mesh.known_peers.len() as f64);
        gauge!(MESH_SPIRAL_NEIGHBORS).set(st.mesh.spiral.neighbors().len() as f64);
        gauge!(MESH_YGG_PEERS).set(st.mesh.ygg_peer_count as f64);
        gauge!(RELAY_ACTIVE).set(st.federation.relays.len() as f64);
        gauge!(IRC_CLIENTS).set(st.clients.len() as f64);
        gauge!(IRC_CHANNELS).set(st.channels.len() as f64);
    }
}

// ---------------------------------------------------------------------------
// Inline helpers used at call sites
// ---------------------------------------------------------------------------

/// Record bytes sent on a relay connection.
#[inline]
pub fn relay_bytes_sent(peer_label: &str, n: usize) {
    let labels = [("peer", peer_label.to_owned())];
    counter!(RELAY_BYTES_SENT, &labels).increment(n as u64);
    counter!(RELAY_MSGS_SENT, &labels).increment(1);
}

/// Record bytes received on a relay connection.
#[inline]
pub fn relay_bytes_recv(peer_label: &str, n: usize) {
    let labels = [("peer", peer_label.to_owned())];
    counter!(RELAY_BYTES_RECV, &labels).increment(n as u64);
    counter!(RELAY_MSGS_RECV, &labels).increment(1);
}

/// Record a round-trip latency measurement for a relay peer.
#[inline]
pub fn relay_rtt(peer_label: &str, rtt_ms: f64) {
    let labels = [("peer", peer_label.to_owned())];
    histogram!(RELAY_RTT_MS, &labels).record(rtt_ms);
}
