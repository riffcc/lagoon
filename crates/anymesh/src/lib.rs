//! Anymesh — TCP socket migration and anycast mesh coordination.
//!
//! Provides three capabilities:
//!
//! 1. **TCP_REPAIR socket migration** — Freeze a live TCP connection, serialize
//!    its state, and restore it on another process or machine. The client sees
//!    zero disruption: same 4-tuple, same sequence numbers, no RST/FIN.
//!
//! 2. **SO_REUSEPORT handoff** — Multiple nodes bind the same IP:port. The kernel
//!    distributes connections; nodes coordinate ownership and hand off connections
//!    to the correct owner.
//!
//! 3. **Distributed mesh** — Nodes peer via HELLO/PING/PONG, measure RTT, and
//!    coordinate socket migrations across the mesh.
//!
//! # Capabilities
//!
//! TCP_REPAIR requires `CAP_NET_ADMIN` (typically root). Use [`Capabilities::detect`]
//! to check at runtime:
//!
//! ```no_run
//! let caps = anymesh::Capabilities::detect();
//! if caps.tcp_repair {
//!     // Full socket migration available
//! } else {
//!     // Graceful degradation: same-machine handoff only
//! }
//! ```

pub mod error;
pub mod repair;
pub mod sockaddr;
pub mod handoff;
pub mod mesh;
pub mod transport;

pub use error::Error;
pub use repair::{SocketMigration, TcpRepairWindow, freeze, restore, check_tcp_repair};
pub use transport::AnymeshStream;

/// Runtime capability detection.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub tcp_repair: bool,
}

impl Capabilities {
    /// Probe the kernel for available capabilities.
    pub fn detect() -> Self {
        Self {
            tcp_repair: check_tcp_repair(),
        }
    }
}
