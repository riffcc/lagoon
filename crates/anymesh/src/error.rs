use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TCP_REPAIR not available (need CAP_NET_ADMIN)")]
    CapabilityUnavailable,

    #[error("freeze failed: {0}")]
    Freeze(#[source] io::Error),

    #[error("restore failed: {0}")]
    Restore(#[source] io::Error),

    #[error("handoff full: all node slots occupied")]
    HandoffFull,

    #[error("mesh protocol error: {0}")]
    Protocol(String),

    #[error("invalid address family: expected {expected}, got {got}")]
    AddressFamily { expected: &'static str, got: &'static str },

    #[error(transparent)]
    Io(#[from] io::Error),
}
