//! Lagoon's implementation of Citadel's CvdfTransport trait.
//!
//! Routes CVDF messages through the mesh relay system as base64-encoded
//! bincode within `MeshMessage::Cvdf { data }`. Same pattern as SPORE,
//! latency proofs, and gossip diffs — compact binary, text-safe transport.
//!
//! The transport uses an internal channel — the federation event loop
//! drains queued messages and dispatches them to the appropriate relays.

use citadel_lens::service::{CvdfServiceMessage, CvdfTransport};
use tokio::sync::mpsc;

/// Queued CVDF message: target peer (None = broadcast) + message.
pub type CvdfOutbound = (Option<[u8; 32]>, CvdfServiceMessage);

/// Lagoon's CvdfTransport — buffers messages for the federation event loop.
pub struct LagoonCvdfTransport {
    /// Outbound message queue. The federation loop drains this.
    tx: mpsc::UnboundedSender<CvdfOutbound>,
}

impl LagoonCvdfTransport {
    /// Create a new transport and its receiver.
    ///
    /// The caller (federation event loop) holds the receiver and dispatches
    /// queued messages to the appropriate mesh relays.
    pub fn new() -> (Self, mpsc::UnboundedReceiver<CvdfOutbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl CvdfTransport for LagoonCvdfTransport {
    fn send_to(&self, peer: &[u8; 32], msg: CvdfServiceMessage) {
        let _ = self.tx.send((Some(*peer), msg));
    }

    fn broadcast(&self, msg: CvdfServiceMessage) {
        let _ = self.tx.send((None, msg));
    }
}

/// Encode a `CvdfServiceMessage` to wire format: bincode → base64.
pub fn encode_cvdf_message(msg: &CvdfServiceMessage) -> String {
    use base64::Engine as _;
    let bytes = bincode::serialize(msg).expect("CvdfServiceMessage serializable");
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
