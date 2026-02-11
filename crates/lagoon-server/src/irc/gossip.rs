//! SPORE Gossip: Mesh-wide message replication for Lagoon.
//!
//! Uses citadel-gossip's SPORE-backed GossipStore for deduplication and
//! epidemic broadcast of IRC events across the mesh. Nodes sharing the same
//! SERVER_NAME form a **supernode** — they replicate ALL channel events and
//! act as one logical server. Inter-supernode replication is topic-based
//! (only subscribed channels).
//!
//! ## Topic Naming
//!
//! - `cluster:{channel}` — intra-supernode (same SERVER_NAME), full replication
//! - `fed:{channel}:{server}` — inter-supernode, subscription-based
//!
//! ## Delivery Rules
//!
//! - Same SERVER_NAME origin → bare nick (transparent, users can't tell which
//!   physical instance originated the message)
//! - Different SERVER_NAME → `nick@origin` display format

use std::collections::HashMap;

use citadel_gossip::{GossipMessage, GossipStore};
use citadel_spore::{Spore, U256};
use serde::{Deserialize, Serialize};
use tracing::{debug, trace, warn};

/// Serializable IRC event for gossip replication.
///
/// These are the events that travel across the mesh. Each variant captures
/// enough context to reconstruct the IRC message at the receiving end.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GossipIrcEvent {
    /// A channel message (PRIVMSG or NOTICE).
    Message {
        nick: String,
        /// SERVER_NAME of the originating node (derive SITE_NAME for cluster checks).
        origin: String,
        channel: String,
        text: String,
        /// "PRIVMSG" or "NOTICE".
        command: String,
    },
    /// A user joined a channel.
    Join {
        nick: String,
        origin: String,
        channel: String,
    },
    /// A user left a channel.
    Part {
        nick: String,
        origin: String,
        channel: String,
        reason: String,
    },
    /// A channel topic was changed.
    Topic {
        nick: String,
        origin: String,
        channel: String,
        text: String,
    },
}

impl GossipIrcEvent {
    /// The channel this event pertains to.
    pub fn channel(&self) -> &str {
        match self {
            Self::Message { channel, .. }
            | Self::Join { channel, .. }
            | Self::Part { channel, .. }
            | Self::Topic { channel, .. } => channel,
        }
    }

    /// The origin server name.
    pub fn origin(&self) -> &str {
        match self {
            Self::Message { origin, .. }
            | Self::Join { origin, .. }
            | Self::Part { origin, .. }
            | Self::Topic { origin, .. } => origin,
        }
    }

    /// The nick of the user who triggered the event.
    pub fn nick(&self) -> &str {
        match self {
            Self::Message { nick, .. }
            | Self::Join { nick, .. }
            | Self::Part { nick, .. }
            | Self::Topic { nick, .. } => nick,
        }
    }
}

// ── Topic naming ──────────────────────────────────────────────────────

/// Build a cluster topic name for intra-supernode replication.
///
/// All nodes sharing the same SERVER_NAME subscribe to these topics
/// automatically when users join channels.
pub fn cluster_topic(channel: &str) -> String {
    format!("cluster:{channel}")
}

/// Build a federation topic name for inter-supernode replication.
///
/// Subscribed when a local user joins `#channel:server` — that specific
/// channel's events from that specific remote server flow back to us.
pub fn federation_topic(channel: &str, server: &str) -> String {
    format!("fed:{channel}:{server}")
}

/// Parsed topic components.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedTopic {
    /// Intra-supernode cluster topic.
    Cluster { channel: String },
    /// Inter-supernode federation topic.
    Federation { channel: String, server: String },
}

/// Parse a gossip topic string back into its components.
pub fn parse_topic(topic: &str) -> Option<ParsedTopic> {
    if let Some(channel) = topic.strip_prefix("cluster:") {
        Some(ParsedTopic::Cluster {
            channel: channel.to_string(),
        })
    } else if let Some(rest) = topic.strip_prefix("fed:") {
        // Split on the LAST colon — channel names can contain colons
        // in federation syntax (#channel:server), but the server name
        // is always the last segment.
        let colon_pos = rest.rfind(':')?;
        let channel = &rest[..colon_pos];
        let server = &rest[colon_pos + 1..];
        if channel.is_empty() || server.is_empty() {
            return None;
        }
        Some(ParsedTopic::Federation {
            channel: channel.to_string(),
            server: server.to_string(),
        })
    } else {
        None
    }
}

/// Check if a peer is in the same supernode (same SITE_NAME).
///
/// Supernodes are clusters of nodes sharing the same site identity.
/// Parameters are site names (e.g. "lagun.co"), not server names.
pub fn is_cluster_peer(our_site_name: &str, their_site_name: &str) -> bool {
    our_site_name == their_site_name
}

// ── GossipRouter ──────────────────────────────────────────────────────

/// Message TTL for intra-supernode gossip (5 minutes).
pub const CLUSTER_TTL: u64 = 300;

/// Message TTL for inter-supernode gossip (10 minutes — longer propagation path).
pub const FEDERATION_TTL: u64 = 600;

/// SPORE-backed gossip router for Lagoon mesh.
///
/// Wraps `citadel_gossip::GossipStore` with:
/// - A message cache for SPORE diff catch-up on reconnection
/// - Topic-aware broadcast with automatic topic derivation
/// - IRC event serialization via bincode
pub struct GossipRouter {
    /// The underlying SPORE-deduplicating gossip store.
    pub store: GossipStore,
    /// Our 256-bit sender identity (derived from ed25519 public key).
    pub sender_id: U256,
    /// Message cache: content_id bytes → (GossipMessage, GossipIrcEvent).
    /// Kept for SPORE diff catch-up — peers that reconnect can request
    /// messages they missed by comparing SPORE HaveLists.
    message_cache: HashMap<[u8; 32], (GossipMessage, GossipIrcEvent)>,
}

impl std::fmt::Debug for GossipRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GossipRouter")
            .field("sender_id", &self.sender_id)
            .field("cache_len", &self.message_cache.len())
            .finish_non_exhaustive()
    }
}

impl GossipRouter {
    /// Create a new gossip router.
    ///
    /// `public_key_bytes` is the 32-byte ed25519 public key, used to derive
    /// the U256 sender identity for SPORE dedup.
    pub fn new(public_key_bytes: &[u8; 32]) -> Self {
        let sender_id = U256::from_be_bytes(public_key_bytes);
        debug!(sender = %hex::encode(sender_id.to_be_bytes()), "Gossip router initialized");
        Self {
            store: GossipStore::new(),
            sender_id,
            message_cache: HashMap::new(),
        }
    }

    /// Subscribe to a cluster channel (intra-supernode).
    pub fn subscribe_cluster_channel(&mut self, channel: &str) {
        let topic = cluster_topic(channel);
        self.store.subscribe(&topic);
        trace!(topic = %topic, "Subscribed to cluster channel");
    }

    /// Unsubscribe from a cluster channel.
    pub fn unsubscribe_cluster_channel(&mut self, channel: &str) {
        let topic = cluster_topic(channel);
        self.store.unsubscribe(&topic);
        trace!(topic = %topic, "Unsubscribed from cluster channel");
    }

    /// Subscribe to a federation channel (inter-supernode).
    pub fn subscribe_federation_channel(&mut self, channel: &str, server: &str) {
        let topic = federation_topic(channel, server);
        self.store.subscribe(&topic);
        trace!(topic = %topic, "Subscribed to federation channel");
    }

    /// Unsubscribe from a federation channel.
    pub fn unsubscribe_federation_channel(&mut self, channel: &str, server: &str) {
        let topic = federation_topic(channel, server);
        self.store.unsubscribe(&topic);
        trace!(topic = %topic, "Unsubscribed from federation channel");
    }

    /// Broadcast an IRC event into the gossip mesh.
    ///
    /// Determines the topic from the event's channel and origin, serializes
    /// via bincode, and queues for outbound delivery. Returns the content ID
    /// bytes for cache tracking.
    pub fn broadcast_event(
        &mut self,
        event: &GossipIrcEvent,
        our_site_name: &str,
    ) -> [u8; 32] {
        let topic = cluster_topic(event.channel());
        let their_site = super::server::derive_site_name(event.origin());
        let ttl = if is_cluster_peer(our_site_name, &their_site) {
            CLUSTER_TTL
        } else {
            FEDERATION_TTL
        };

        let payload = bincode::serialize(event).expect("GossipIrcEvent serialization cannot fail");
        let msg = GossipMessage::new(topic, payload, ttl, self.sender_id);
        let content_id = msg.content_id();
        let id_bytes = *content_id.as_bytes();

        self.store.broadcast(msg.clone());
        self.message_cache.insert(id_bytes, (msg, event.clone()));

        trace!(
            channel = %event.channel(),
            nick = %event.nick(),
            "Broadcast gossip event"
        );

        id_bytes
    }

    /// Receive a gossip message from a remote peer.
    ///
    /// SPORE dedup ensures each message is accepted at most once.
    /// Returns `Some(event)` if accepted and on a subscribed topic,
    /// `None` if filtered (unsubscribed topic, duplicate, or expired).
    pub fn receive_message(&mut self, msg: GossipMessage) -> Option<GossipIrcEvent> {
        let content_id = msg.content_id();
        let id_bytes = *content_id.as_bytes();

        match self.store.receive(msg.clone()) {
            Ok(true) => {
                // Accepted — deserialize the IRC event.
                match bincode::deserialize::<GossipIrcEvent>(&msg.payload) {
                    Ok(event) => {
                        self.message_cache.insert(id_bytes, (msg, event.clone()));
                        trace!(
                            channel = %event.channel(),
                            nick = %event.nick(),
                            "Accepted gossip event"
                        );
                        Some(event)
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to deserialize gossip payload");
                        None
                    }
                }
            }
            Ok(false) => {
                // Filtered (unsubscribed topic) — still mark as seen for dedup.
                trace!("Gossip message filtered (unsubscribed topic)");
                None
            }
            Err(e) => {
                // Duplicate or expired.
                trace!(error = %e, "Gossip message rejected");
                None
            }
        }
    }

    /// Drain outbox — returns all queued messages for sending to connected peers.
    pub fn drain_outbox(&mut self) -> Vec<GossipMessage> {
        self.store.drain_outbox()
    }

    /// Our SPORE HaveList (seen message IDs) — for diff exchange with peers.
    pub fn seen_messages(&self) -> &Spore {
        self.store.seen_messages()
    }

    /// Find cached messages that a peer is missing, given their SPORE HaveList.
    ///
    /// Computes `our_seen \ their_seen` via SPORE diff, then walks our cache
    /// to find messages whose content IDs fall in those ranges.
    pub fn diff_messages(&self, peer_seen: &Spore) -> Vec<GossipMessage> {
        let diff = self.store.diff(peer_seen);
        if diff.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();
        for (id_bytes, (msg, _event)) in &self.message_cache {
            let u256 = U256::from_be_bytes(id_bytes);
            if diff.covers(&u256) && !msg.is_expired() {
                result.push(msg.clone());
            }
        }
        result
    }

    /// Prune expired messages from the cache.
    pub fn prune_cache(&mut self) {
        let before = self.message_cache.len();
        self.message_cache
            .retain(|_, (msg, _)| !msg.is_expired());
        let pruned = before - self.message_cache.len();
        if pruned > 0 {
            debug!(pruned, remaining = self.message_cache.len(), "Pruned gossip cache");
        }
        self.store.gc();
    }

    /// Number of cached messages.
    pub fn cache_len(&self) -> usize {
        self.message_cache.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0xAA;
        key[31] = 0xBB;
        key
    }

    fn other_pubkey() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = 0xCC;
        key[31] = 0xDD;
        key
    }

    #[test]
    fn cluster_topic_format() {
        assert_eq!(cluster_topic("#lagoon"), "cluster:#lagoon");
        assert_eq!(cluster_topic("#general"), "cluster:#general");
    }

    #[test]
    fn federation_topic_format() {
        assert_eq!(
            federation_topic("#lagoon", "lon.lagun.co"),
            "fed:#lagoon:lon.lagun.co"
        );
    }

    #[test]
    fn parse_topic_cluster() {
        let parsed = parse_topic("cluster:#lagoon").unwrap();
        assert_eq!(
            parsed,
            ParsedTopic::Cluster {
                channel: "#lagoon".to_string()
            }
        );
    }

    #[test]
    fn parse_topic_federation() {
        let parsed = parse_topic("fed:#lagoon:lon.lagun.co").unwrap();
        assert_eq!(
            parsed,
            ParsedTopic::Federation {
                channel: "#lagoon".to_string(),
                server: "lon.lagun.co".to_string(),
            }
        );
    }

    #[test]
    fn parse_topic_roundtrip() {
        let channel = "#test-room";
        let server = "per.lagun.co";

        let ct = cluster_topic(channel);
        let ft = federation_topic(channel, server);

        assert_eq!(
            parse_topic(&ct),
            Some(ParsedTopic::Cluster {
                channel: channel.to_string()
            })
        );
        assert_eq!(
            parse_topic(&ft),
            Some(ParsedTopic::Federation {
                channel: channel.to_string(),
                server: server.to_string(),
            })
        );
    }

    #[test]
    fn parse_topic_invalid() {
        assert!(parse_topic("garbage").is_none());
        assert!(parse_topic("").is_none());
        assert!(parse_topic("fed:").is_none());
        assert!(parse_topic("fed:#chan:").is_none());
        // Note: "cluster:" with empty channel parses as Cluster { channel: "" }
        // — see parse_topic_cluster_empty_channel_is_some test.
    }

    #[test]
    fn parse_topic_cluster_empty_channel_is_some() {
        // "cluster:" with empty channel — technically has a channel of ""
        // which is a valid (if weird) parse. The strip_prefix returns "".
        // We allow this — the IRC layer validates channel names.
        let result = parse_topic("cluster:");
        assert_eq!(
            result,
            Some(ParsedTopic::Cluster {
                channel: String::new()
            })
        );
    }

    #[test]
    fn is_cluster_peer_same() {
        assert!(is_cluster_peer("lagun.co", "lagun.co"));
    }

    #[test]
    fn is_cluster_peer_different() {
        assert!(!is_cluster_peer("lagun.co", "lon.lagun.co"));
    }

    #[test]
    fn gossip_router_broadcast() {
        let mut router = GossipRouter::new(&test_pubkey());
        router.subscribe_cluster_channel("#lagoon");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "hello mesh!".into(),
            command: "PRIVMSG".into(),
        };

        let id = router.broadcast_event(&event, "lagun.co");
        assert_ne!(id, [0u8; 32]);

        // Should be in outbox.
        let outbox = router.drain_outbox();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].topic, "cluster:#lagoon");

        // Should be cached.
        assert_eq!(router.cache_len(), 1);
    }

    #[test]
    fn gossip_router_dedup() {
        let mut router_a = GossipRouter::new(&test_pubkey());
        let mut router_b = GossipRouter::new(&other_pubkey());
        router_b.subscribe_cluster_channel("#lagoon");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "dedup test".into(),
            command: "PRIVMSG".into(),
        };

        router_a.broadcast_event(&event, "lagun.co");
        let outbox = router_a.drain_outbox();
        assert_eq!(outbox.len(), 1);

        // First receive → accepted.
        let first = router_b.receive_message(outbox[0].clone());
        assert!(first.is_some());
        assert_eq!(first.unwrap(), event);

        // Second receive of same message → rejected (duplicate).
        let second = router_b.receive_message(outbox[0].clone());
        assert!(second.is_none());
    }

    #[test]
    fn gossip_router_unsubscribed_filtered() {
        let mut router_a = GossipRouter::new(&test_pubkey());
        let mut router_b = GossipRouter::new(&other_pubkey());
        // router_b does NOT subscribe to #lagoon.

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "filtered".into(),
            command: "PRIVMSG".into(),
        };

        router_a.broadcast_event(&event, "lagun.co");
        let outbox = router_a.drain_outbox();

        // Receive → filtered (not subscribed).
        let result = router_b.receive_message(outbox[0].clone());
        assert!(result.is_none());
    }

    #[test]
    fn gossip_event_bincode_roundtrip() {
        let events = vec![
            GossipIrcEvent::Message {
                nick: "wings".into(),
                origin: "lagun.co".into(),
                channel: "#lagoon".into(),
                text: "hello!".into(),
                command: "PRIVMSG".into(),
            },
            GossipIrcEvent::Join {
                nick: "ada".into(),
                origin: "lon.lagun.co".into(),
                channel: "#general".into(),
            },
            GossipIrcEvent::Part {
                nick: "bob".into(),
                origin: "lagun.co".into(),
                channel: "#test".into(),
                reason: "later".into(),
            },
            GossipIrcEvent::Topic {
                nick: "charlie".into(),
                origin: "per.lagun.co".into(),
                channel: "#news".into(),
                text: "Breaking: SPORE works!".into(),
            },
        ];

        for event in events {
            let bytes = bincode::serialize(&event).unwrap();
            let decoded: GossipIrcEvent = bincode::deserialize(&bytes).unwrap();
            assert_eq!(decoded, event);
        }
    }

    #[test]
    fn gossip_event_accessors() {
        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "test".into(),
            command: "PRIVMSG".into(),
        };

        assert_eq!(event.channel(), "#lagoon");
        assert_eq!(event.origin(), "lagun.co");
        assert_eq!(event.nick(), "wings");
    }

    #[test]
    fn diff_messages_catches_missing() {
        let mut router_a = GossipRouter::new(&test_pubkey());
        router_a.subscribe_cluster_channel("#lagoon");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "catchup test".into(),
            command: "PRIVMSG".into(),
        };

        router_a.broadcast_event(&event, "lagun.co");

        // A peer with an empty SPORE should get our message in the diff.
        let empty_spore = Spore::empty();
        let diff = router_a.diff_messages(&empty_spore);
        assert_eq!(diff.len(), 1);

        // A peer with our exact seen set should get nothing.
        let our_seen = router_a.seen_messages().clone();
        let diff2 = router_a.diff_messages(&our_seen);
        assert_eq!(diff2.len(), 0);
    }

    #[test]
    fn prune_cache_removes_expired() {
        let mut router = GossipRouter::new(&test_pubkey());
        router.subscribe_cluster_channel("#lagoon");

        // Create a message with created_at in the past and TTL=1, so it's expired.
        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#lagoon".into(),
            text: "ephemeral".into(),
            command: "PRIVMSG".into(),
        };

        let payload =
            bincode::serialize(&event).expect("GossipIrcEvent serialization cannot fail");
        let mut msg = GossipMessage::new("cluster:#lagoon", payload, 1, router.sender_id);
        // Force created_at to the past so is_expired() returns true.
        msg.created_at = 1000;
        let content_id = msg.content_id();
        let id_bytes = *content_id.as_bytes();

        router.store.broadcast(msg.clone());
        router.message_cache.insert(id_bytes, (msg, event));
        assert_eq!(router.cache_len(), 1);

        // Prune should remove expired.
        router.prune_cache();
        assert_eq!(router.cache_len(), 0);
    }

    #[test]
    fn cluster_ttl_for_same_origin() {
        let mut router = GossipRouter::new(&test_pubkey());
        router.subscribe_cluster_channel("#test");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lagun.co".into(),
            channel: "#test".into(),
            text: "hi".into(),
            command: "PRIVMSG".into(),
        };

        router.broadcast_event(&event, "lagun.co");
        let outbox = router.drain_outbox();
        assert_eq!(outbox[0].ttl, CLUSTER_TTL);
    }

    #[test]
    fn cluster_ttl_for_subdomain_origin() {
        let mut router = GossipRouter::new(&test_pubkey());
        router.subscribe_cluster_channel("#test");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "lon.lagun.co".into(),
            channel: "#test".into(),
            text: "hi from lon".into(),
            command: "PRIVMSG".into(),
        };

        // lon.lagun.co derives to site lagun.co → same site → cluster TTL.
        router.broadcast_event(&event, "lagun.co");
        let outbox = router.drain_outbox();
        assert_eq!(outbox[0].ttl, CLUSTER_TTL);
    }

    #[test]
    fn federation_ttl_for_different_origin() {
        let mut router = GossipRouter::new(&test_pubkey());
        router.subscribe_cluster_channel("#test");

        let event = GossipIrcEvent::Message {
            nick: "wings".into(),
            origin: "node1.riff.cc".into(),
            channel: "#test".into(),
            text: "hi from riff".into(),
            command: "PRIVMSG".into(),
        };

        // Our site is lagun.co, event is from riff.cc → federation TTL.
        router.broadcast_event(&event, "lagun.co");
        let outbox = router.drain_outbox();
        assert_eq!(outbox[0].ttl, FEDERATION_TTL);
    }
}
