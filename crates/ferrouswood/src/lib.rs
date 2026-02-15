//! ferrouswood — SPIRAL-based mesh routing.
//!
//! Replaces ironwood's spanning tree with SPIRAL topology routing.
//! Uses yggdrasil-rs for authenticated peer connections.
//!
//! # What ferrouswood does
//!
//! - Takes peer connections from yggdrasil-rs (authenticated, Ed25519-verified)
//! - Routes packets using SPIRAL neighbor topology (NOT spanning tree)
//! - Handles ironwood wire protocol gracefully for stock Ygg peer compatibility
//! - Manages encrypted sessions (NaCl box) for end-to-end application traffic
//!
//! # What SPIRAL replaces
//!
//! | ironwood mechanism | ferrouswood replacement |
//! |---|---|
//! | Spanning tree (SigReq/SigRes/Announce) | SPIRAL neighbor graph |
//! | Bloom filter path discovery | Direct SPIRAL neighbor knowledge |
//! | Greedy tree forwarding | SPIRAL-aware forwarding |
//! | Source-routed paths | Peer-id addressed routing |

pub mod router;

pub use router::Router;
