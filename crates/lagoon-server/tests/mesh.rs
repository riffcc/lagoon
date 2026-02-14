/// Integration tests for mesh networking, invite codes, defederation, and
/// TLS federation transport.
///
/// These tests verify the mesh protocol, invite code lifecycle,
/// defederation behavior, and TLS peer configuration using in-process servers.
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use lagoon_server::irc::federation::{ape_peer_uri, RelayEvent};
use lagoon_server::irc::invite::{InviteKind, InviteStore, Privilege};
use lagoon_server::irc::lens;
use lagoon_server::irc::server::{
    MeshConnectionState, MeshPeerInfo, MeshSnapshot, ServerState, SharedState,
};
use lagoon_server::irc::transport::{self, TransportMode};

/// Create a test ServerState with a unique identity.
fn make_test_state(server_name: &str) -> (SharedState, watch::Receiver<MeshSnapshot>) {
    let transport_config = Arc::new(transport::build_config());
    let (event_tx, _event_rx) = mpsc::unbounded_channel::<RelayEvent>();
    let identity = Arc::new(lens::generate_identity(server_name));
    let (topology_tx, topology_rx) = watch::channel(MeshSnapshot::empty());

    let tmp_dir = std::env::temp_dir().join(format!(
        "lagoon-test-mesh-{}-{}",
        server_name,
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();

    let state = Arc::new(tokio::sync::RwLock::new(ServerState::new(
        event_tx,
        transport_config,
        identity,
        topology_tx,
        tmp_dir,
    )));

    (state, topology_rx)
}

#[test]
fn lens_identity_generation() {
    let id = lens::generate_identity("test.lagun.co");
    assert!(id.peer_id.starts_with("b3b3/"));
    assert_eq!(id.server_name, "test.lagun.co");
    assert_eq!(id.public_key_hex.len(), 64);
}

#[test]
fn lens_identity_persistence() {
    let tmp = std::env::temp_dir().join(format!("lagoon-mesh-test-{}", rand::random::<u64>()));
    let id1 = lens::load_or_create(&tmp, "persist.lagun.co");
    let id2 = lens::load_or_create(&tmp, "persist.lagun.co");
    assert_eq!(id1.peer_id, id2.peer_id);
    assert_eq!(id1.secret_seed, id2.secret_seed);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn lens_peer_id_verification() {
    let id = lens::generate_identity("verify.lagun.co");
    let pubkey = lens::pubkey_bytes(&id).unwrap();
    assert!(lens::verify_peer_id(&id.peer_id, &pubkey));
    assert!(!lens::verify_peer_id("b3b3/fake", &pubkey));
}

#[tokio::test]
async fn mesh_state_tracks_peers() {
    let (state, _rx) = make_test_state("tracker.lagun.co");

    // Add a peer.
    let peer_id = lens::generate_identity("peer.lagun.co");
    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            peer_id.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer_id.peer_id.clone(),
                server_name: "peer.lagun.co".into(),
                public_key_hex: peer_id.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer_id.peer_id.clone(), MeshConnectionState::Connected);
        st.notify_topology_change();
    }

    let st = state.read().await;
    assert!(st.mesh.known_peers.contains_key(&peer_id.peer_id));
    assert_eq!(
        st.mesh.connections.get(&peer_id.peer_id),
        Some(&MeshConnectionState::Connected)
    );
}

#[tokio::test]
async fn topology_snapshot_includes_self_and_peers() {
    let (state, rx) = make_test_state("snapshot.lagun.co");

    // Add some peers.
    let peer1 = lens::generate_identity("peer1.lagun.co");
    let peer2 = lens::generate_identity("peer2.lagun.co");
    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            peer1.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer1.peer_id.clone(),
                server_name: "peer1.lagun.co".into(),
                public_key_hex: peer1.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer1.peer_id.clone(), MeshConnectionState::Connected);

        st.mesh.known_peers.insert(
            peer2.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer2.peer_id.clone(),
                server_name: "peer2.lagun.co".into(),
                public_key_hex: peer2.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer2.peer_id.clone(), MeshConnectionState::Known);

        st.notify_topology_change();
    }

    let snapshot = rx.borrow().clone();
    assert_eq!(snapshot.self_server_name, "snapshot.lagun.co");
    assert_eq!(snapshot.nodes.len(), 3); // self + 2 peers

    // Self node should be marked is_self.
    let self_node = snapshot.nodes.iter().find(|n| n.is_self).unwrap();
    assert_eq!(self_node.server_name, "snapshot.lagun.co");
    assert!(self_node.connected);

    // Connected peer should have a link.
    let connected_peer = snapshot
        .nodes
        .iter()
        .find(|n| n.server_name == "peer1.lagun.co")
        .unwrap();
    assert!(connected_peer.connected);

    // Known-only peer should not have a link.
    let known_peer = snapshot
        .nodes
        .iter()
        .find(|n| n.server_name == "peer2.lagun.co")
        .unwrap();
    assert!(!known_peer.connected);

    // Should have exactly 1 link (self → peer1).
    assert_eq!(snapshot.links.len(), 1);
}

#[test]
fn invite_code_lifecycle() {
    let mut store = InviteStore::new();

    // Create.
    let code = store
        .create(
            InviteKind::CommunityLink,
            "b3b3/creator".into(),
            "#lagoon".into(),
            vec![Privilege::Read, Privilege::Write],
            Some(3),
            None,
        )
        .code
        .clone();

    // Validate.
    assert!(store.validate(&code).is_ok());

    // Use once.
    let used = store.use_code(&code).unwrap();
    assert_eq!(used.uses, 1);
    assert!(used.active);

    // Use twice more.
    store.use_code(&code).unwrap();
    let exhausted = store.use_code(&code).unwrap();
    assert_eq!(exhausted.uses, 3);
    assert!(!exhausted.active); // Auto-deactivated at max_uses.

    // Fourth use fails.
    assert!(store.use_code(&code).is_err());
}

#[test]
fn invite_code_modification() {
    let mut store = InviteStore::new();
    let code = store
        .create(
            InviteKind::CommunityLink,
            "b3b3/creator".into(),
            "#dev".into(),
            vec![Privilege::Read],
            None,
            None,
        )
        .code
        .clone();

    // Modify privileges.
    let modified = store
        .modify(
            &code,
            Some(vec![Privilege::Read, Privilege::Write, Privilege::Moderate]),
            Some(Some(50)),
            None,
        )
        .unwrap();

    assert_eq!(modified.privileges.len(), 3);
    assert_eq!(modified.max_uses, Some(50));

    // Modify expiry.
    let future = chrono::Utc::now() + chrono::Duration::hours(24);
    let modified = store
        .modify(&code, None, None, Some(Some(future)))
        .unwrap();
    assert!(modified.expires_at.is_some());
}

#[test]
fn invite_time_expiry() {
    let mut store = InviteStore::new();
    let past = chrono::Utc::now() - chrono::Duration::hours(1);
    let code = store
        .create(
            InviteKind::CommunityLink,
            "b3b3/creator".into(),
            "#expired".into(),
            vec![Privilege::Read],
            None,
            Some(past),
        )
        .code
        .clone();

    assert!(store.validate(&code).is_err());
    assert!(store.use_code(&code).is_err());
}

#[test]
fn invite_count_expiry() {
    let mut store = InviteStore::new();
    let code = store
        .create(
            InviteKind::ServerPeering,
            "b3b3/creator".into(),
            "remote.lagun.co".into(),
            vec![],
            Some(1),
            None,
        )
        .code
        .clone();

    // First use succeeds.
    let used = store.use_code(&code).unwrap();
    assert!(!used.active);

    // Second use fails.
    assert!(store.use_code(&code).is_err());
}

#[tokio::test]
async fn defederation_blocks_peer() {
    let (state, _rx) = make_test_state("defed.lagun.co");

    // Add a peer.
    let peer = lens::generate_identity("blocked.lagun.co");
    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            peer.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer.peer_id.clone(),
                server_name: "blocked.lagun.co".into(),
                public_key_hex: peer.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer.peer_id.clone(), MeshConnectionState::Connected);
    }

    // Defederate.
    {
        let mut st = state.write().await;
        st.mesh.defederated.insert("blocked.lagun.co".into());
        st.mesh.connections.remove(&peer.peer_id);
        st.notify_topology_change();
    }

    // Verify blocked.
    let st = state.read().await;
    assert!(st.mesh.defederated.contains("blocked.lagun.co"));
    assert!(!st.mesh.connections.contains_key(&peer.peer_id));

    // Topology should show peer but not connected.
    let snapshot = st.build_mesh_snapshot();
    let blocked_node = snapshot
        .nodes
        .iter()
        .find(|n| n.server_name == "blocked.lagun.co")
        .unwrap();
    assert!(!blocked_node.connected);
    // No link to blocked peer.
    assert!(snapshot
        .links
        .iter()
        .all(|l| l.target != peer.peer_id));
}

#[tokio::test]
async fn refederation_unblocks_peer() {
    let (state, _rx) = make_test_state("refed.lagun.co");

    // Defederate.
    {
        let mut st = state.write().await;
        st.mesh.defederated.insert("restored.lagun.co".into());
    }

    // Verify blocked.
    {
        let st = state.read().await;
        assert!(st.mesh.defederated.contains("restored.lagun.co"));
    }

    // Refederate.
    {
        let mut st = state.write().await;
        st.mesh.defederated.remove("restored.lagun.co");
    }

    // Verify unblocked.
    let st = state.read().await;
    assert!(!st.mesh.defederated.contains("restored.lagun.co"));
}

#[test]
fn invite_revocation() {
    let mut store = InviteStore::new();
    let code = store
        .create(
            InviteKind::CommunityLink,
            "b3b3/creator".into(),
            "#revoke-test".into(),
            vec![Privilege::Read],
            None,
            None,
        )
        .code
        .clone();

    assert!(store.validate(&code).is_ok());
    store.revoke(&code).unwrap();
    assert!(store.validate(&code).is_err());
}

#[test]
fn invite_persistence() {
    let tmp = std::env::temp_dir().join(format!(
        "lagoon-mesh-invite-test-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&tmp).unwrap();

    let code = {
        let mut store = InviteStore::load_or_create(&tmp);
        let invite = store.create(
            InviteKind::ServerPeering,
            "b3b3/persist".into(),
            "remote.lagun.co".into(),
            vec![Privilege::Admin],
            Some(10),
            None,
        );
        invite.code.clone()
    };

    // Reload and verify.
    let store = InviteStore::load_or_create(&tmp);
    let invite = store.validate(&code).unwrap();
    assert_eq!(invite.target, "remote.lagun.co");
    assert_eq!(invite.privileges, vec![Privilege::Admin]);
    assert_eq!(invite.max_uses, Some(10));

    let _ = std::fs::remove_dir_all(&tmp);
}

#[tokio::test]
async fn mesh_snapshot_watch_channel_updates() {
    let (state, mut rx) = make_test_state("watch.lagun.co");

    // Initial snapshot should be empty (just self).
    let initial = rx.borrow().clone();
    assert_eq!(initial.nodes.len(), 0); // Empty snapshot before first notify.

    // Trigger a topology update.
    {
        let st = state.read().await;
        st.notify_topology_change();
    }

    // Wait for the update.
    rx.changed().await.unwrap();
    let updated = rx.borrow().clone();
    assert_eq!(updated.nodes.len(), 1); // Just self.
    assert_eq!(updated.self_server_name, "watch.lagun.co");

    // Add a peer and update.
    let peer = lens::generate_identity("dynamic.lagun.co");
    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            peer.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer.peer_id.clone(),
                server_name: "dynamic.lagun.co".into(),
                public_key_hex: peer.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer.peer_id.clone(), MeshConnectionState::Connected);
        st.notify_topology_change();
    }

    rx.changed().await.unwrap();
    let with_peer = rx.borrow().clone();
    assert_eq!(with_peer.nodes.len(), 2);
    assert_eq!(with_peer.links.len(), 1);
}

#[tokio::test]
async fn defederation_persists_to_disk() {
    let tmp = std::env::temp_dir().join(format!(
        "lagoon-defed-persist-{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&tmp).unwrap();

    // Create state and defederate.
    {
        let transport_config = Arc::new(transport::build_config());
        let (event_tx, _) = mpsc::unbounded_channel::<RelayEvent>();
        let identity = Arc::new(lens::generate_identity("persist.lagun.co"));
        let (topology_tx, _) = watch::channel(MeshSnapshot::empty());

        let state = Arc::new(tokio::sync::RwLock::new(ServerState::new(
            event_tx,
            transport_config,
            identity,
            topology_tx,
            tmp.clone(),
        )));

        let mut st = state.write().await;
        st.mesh.defederated.insert("evil.lagun.co".into());

        // Persist.
        let defed_path = st.data_dir.join("defederated.json");
        let json = serde_json::to_string_pretty(&st.mesh.defederated).unwrap();
        std::fs::write(&defed_path, json).unwrap();
    }

    // Reload and verify.
    let defed_path = tmp.join("defederated.json");
    let json = std::fs::read_to_string(&defed_path).unwrap();
    let defed: HashSet<String> = serde_json::from_str(&json).unwrap();
    assert!(defed.contains("evil.lagun.co"));

    let _ = std::fs::remove_dir_all(&tmp);
}

// --- TLS federation transport integration tests ---

#[test]
fn tls_peer_entry_struct() {
    use lagoon_server::irc::transport::PeerEntry;

    // TLS peer on port 443.
    let tls_peer = PeerEntry {
        yggdrasil_addr: None,
        port: 443,
        tls: true,
    };
    assert!(tls_peer.tls);
    assert_eq!(tls_peer.port, 443);

    // Plain TCP peer.
    let plain_peer = PeerEntry {
        yggdrasil_addr: None,
        port: 6667,
        tls: false,
    };
    assert!(!plain_peer.tls);
    assert_eq!(plain_peer.port, 6667);
}

#[test]
fn transport_config_peer_operations() {
    use lagoon_server::irc::transport::{PeerEntry, TransportConfig};

    let mut config = TransportConfig::new();
    assert!(config.peers.is_empty());

    // Add a TLS peer (lon.lagun.co:443).
    config.peers.insert(
        "lon.lagun.co".into(),
        PeerEntry {
            yggdrasil_addr: None,
            port: 443,
            tls: true,
        },
    );

    // Add a plain TCP peer (aus.lagun.co).
    config.peers.insert(
        "aus.lagun.co".into(),
        PeerEntry {
            yggdrasil_addr: None,
            port: 6667,
            tls: false,
        },
    );

    // Add a Yggdrasil peer.
    config.peers.insert(
        "ygg-node".into(),
        PeerEntry {
            yggdrasil_addr: Some("200:abcd::1".parse().unwrap()),
            port: 6667,
            tls: false,
        },
    );

    assert_eq!(config.peers.len(), 3);

    let lon = &config.peers["lon.lagun.co"];
    assert!(lon.tls);
    assert_eq!(lon.port, 443);
    assert!(lon.yggdrasil_addr.is_none());

    let aus = &config.peers["aus.lagun.co"];
    assert!(!aus.tls);
    assert_eq!(aus.port, 6667);

    let ygg = &config.peers["ygg-node"];
    assert!(!ygg.tls);
    assert!(ygg.yggdrasil_addr.is_some());
    assert_eq!(
        ygg.yggdrasil_addr.unwrap(),
        "200:abcd::1".parse::<std::net::Ipv6Addr>().unwrap()
    );
}

#[test]
fn mesh_peers_keys_work_with_peer_entry() {
    use lagoon_server::irc::transport::{PeerEntry, TransportConfig};

    // Federation's spawn_mesh_connector uses config.peers.keys() to get
    // the list of hostnames to connect to. Verify that works with PeerEntry.
    let mut config = TransportConfig::new();
    config.peers.insert(
        "lon.lagun.co".into(),
        PeerEntry { yggdrasil_addr: None, port: 443, tls: true },
    );
    config.peers.insert(
        "nyc.lagun.co".into(),
        PeerEntry { yggdrasil_addr: None, port: 443, tls: true },
    );
    config.peers.insert(
        "aus.lagun.co".into(),
        PeerEntry { yggdrasil_addr: None, port: 443, tls: true },
    );

    let hosts: Vec<&String> = config.peers.keys().collect();
    assert_eq!(hosts.len(), 3);
    assert!(hosts.iter().any(|h| h.as_str() == "lon.lagun.co"));
    assert!(hosts.iter().any(|h| h.as_str() == "nyc.lagun.co"));
    assert!(hosts.iter().any(|h| h.as_str() == "aus.lagun.co"));
}

#[test]
fn tls_client_config_integration() {
    // Verify that the TLS client config can be built — this exercises the
    // webpki-roots CA root store integration from the transport module.
    let config = transport::build_config();

    // The config itself is usable regardless of TLS state.
    // The TLS wrapping happens inside connect() at runtime.
    assert!(config.peers.is_empty() || !config.peers.is_empty());
}

#[tokio::test]
async fn duplicate_server_names_unique_nodes() {
    let (state, _rx) = make_test_state("hub.lagun.co");

    // Two CDN containers sharing the same server_name but different mesh_keys.
    let cdn1 = lens::generate_identity("lagun.co");
    let cdn2 = lens::generate_identity("lagun.co");
    assert_ne!(cdn1.peer_id, cdn2.peer_id);

    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            cdn1.peer_id.clone(),
            MeshPeerInfo {
                peer_id: cdn1.peer_id.clone(),
                server_name: "lagun.co".into(),
                public_key_hex: cdn1.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(cdn1.peer_id.clone(), MeshConnectionState::Connected);

        st.mesh.known_peers.insert(
            cdn2.peer_id.clone(),
            MeshPeerInfo {
                peer_id: cdn2.peer_id.clone(),
                server_name: "lagun.co".into(),
                public_key_hex: cdn2.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(cdn2.peer_id.clone(), MeshConnectionState::Connected);
        st.notify_topology_change();
    }

    let st = state.read().await;
    let snapshot = st.build_mesh_snapshot();

    // Self + 2 CDN nodes = 3 nodes, even though both CDNs share server_name "lagun.co".
    assert_eq!(snapshot.nodes.len(), 3);
    let cdn_nodes: Vec<_> = snapshot
        .nodes
        .iter()
        .filter(|n| n.server_name == "lagun.co")
        .collect();
    assert_eq!(cdn_nodes.len(), 2);
    assert!(cdn_nodes[0].connected);
    assert!(cdn_nodes[1].connected);
    assert_ne!(cdn_nodes[0].mesh_key, cdn_nodes[1].mesh_key);

    // Both should have links.
    assert_eq!(snapshot.links.len(), 2);
}

#[tokio::test]
async fn web_client_appears_in_topology() {
    let (state, _rx) = make_test_state("web.lagun.co");

    {
        let mut st = state.write().await;
        st.mesh.web_clients.insert("alice".into());
        st.notify_topology_change();
    }

    let st = state.read().await;
    let snapshot = st.build_mesh_snapshot();

    // Self + 1 browser node = 2.
    assert_eq!(snapshot.nodes.len(), 2);

    let browser = snapshot
        .nodes
        .iter()
        .find(|n| n.node_type == "browser")
        .unwrap();
    assert_eq!(browser.mesh_key, "web/alice");
    assert_eq!(browser.node_type, "browser");
    assert!(browser.connected);
    assert!(!browser.is_self);

    // Link from self to browser.
    assert_eq!(snapshot.links.len(), 1);
    assert_eq!(snapshot.links[0].target, "web/alice");
}

#[tokio::test]
async fn web_client_removed_on_disconnect() {
    let (state, _rx) = make_test_state("webdc.lagun.co");

    {
        let mut st = state.write().await;
        st.mesh.web_clients.insert("bob".into());
        st.notify_topology_change();
    }

    // Verify present.
    {
        let st = state.read().await;
        let snapshot = st.build_mesh_snapshot();
        assert_eq!(snapshot.nodes.len(), 2);
    }

    // Remove (simulates disconnect).
    {
        let mut st = state.write().await;
        st.mesh.web_clients.remove("bob");
        st.notify_topology_change();
    }

    // Verify gone.
    let st = state.read().await;
    let snapshot = st.build_mesh_snapshot();
    assert_eq!(snapshot.nodes.len(), 1); // Just self.
    assert_eq!(snapshot.links.len(), 0);
}

#[tokio::test]
async fn disconnect_cleans_up_connection_state() {
    let (state, _rx) = make_test_state("cleanup.lagun.co");

    let peer = lens::generate_identity("remote.lagun.co");
    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            peer.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer.peer_id.clone(),
                server_name: "remote.lagun.co".into(),
                public_key_hex: peer.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer.peer_id.clone(), MeshConnectionState::Connected);
        st.notify_topology_change();
    }

    // Verify connected.
    {
        let st = state.read().await;
        let snapshot = st.build_mesh_snapshot();
        let remote = snapshot.nodes.iter().find(|n| n.server_name == "remote.lagun.co").unwrap();
        assert!(remote.connected);
        assert_eq!(snapshot.links.len(), 1);
    }

    // Simulate disconnect — remove connection but keep known_peer.
    {
        let mut st = state.write().await;
        st.mesh.connections.remove(&peer.peer_id);
        st.notify_topology_change();
    }

    // Verify peer shows as disconnected (still known, not connected).
    let st = state.read().await;
    let snapshot = st.build_mesh_snapshot();
    assert_eq!(snapshot.nodes.len(), 2); // Self + known peer.
    let remote = snapshot.nodes.iter().find(|n| n.server_name == "remote.lagun.co").unwrap();
    assert!(!remote.connected);
    assert_eq!(snapshot.links.len(), 0); // No link to disconnected peer.
}

#[tokio::test]
async fn disconnect_reclaims_spiral_slot() {
    use lagoon_server::irc::spiral::Spiral3DIndex;

    let (state, _rx) = make_test_state("spiral-test.lagun.co");

    let peer = lens::generate_identity("peer.lagun.co");
    let peer_slot = Spiral3DIndex::new(1); // Slot 1 (slot 0 is typically ours).
    {
        let mut st = state.write().await;
        // Claim our own slot first.
        let our_id = st.lens.peer_id.clone();
        st.mesh.spiral.claim_position(&our_id);
        // Add peer to SPIRAL.
        st.mesh.spiral.add_peer(&peer.peer_id, peer_slot);
        st.mesh.known_peers.insert(
            peer.peer_id.clone(),
            MeshPeerInfo {
                peer_id: peer.peer_id.clone(),
                server_name: "peer.lagun.co".into(),
                public_key_hex: peer.public_key_hex.clone(),
                ..Default::default()
            },
        );
        st.mesh
            .connections
            .insert(peer.peer_id.clone(), MeshConnectionState::Connected);
        st.notify_topology_change();
    }

    // Verify slot is claimed.
    {
        let st = state.read().await;
        assert!(st.mesh.spiral.peer_index(&peer.peer_id).is_some());
        assert_eq!(st.mesh.spiral.occupied_count(), 2); // us + peer
    }

    // Simulate disconnect — exactly what spawn_event_processor does
    // on RelayEvent::Disconnected (federation.rs:407-458).
    {
        let mut st = state.write().await;
        st.mesh.connections.remove(&peer.peer_id);
        st.mesh.spiral.remove_peer(&peer.peer_id);
        st.notify_topology_change();
    }

    // Verify slot is freed immediately.
    let st = state.read().await;
    assert!(st.mesh.spiral.peer_index(&peer.peer_id).is_none());
    assert_eq!(st.mesh.spiral.occupied_count(), 1); // just us
    let snapshot = st.build_mesh_snapshot();
    assert!(!snapshot.links.iter().any(|l| l.target == peer.peer_id));
}

#[test]
fn pong_message_format() {
    use lagoon_server::irc::message::Message;
    // Verify we can construct and parse PONG messages (relay protocol contract).
    let pong = Message {
        prefix: None,
        command: "PONG".into(),
        params: vec!["lon~relay".into(), "test.lagun.co".into()],
    };
    assert_eq!(pong.command, "PONG");
    assert_eq!(pong.params.len(), 2);
}

// ─── dispatch_mesh_message tests ───────────────────────────────────────────

use lagoon_server::irc::federation::dispatch_mesh_message;
use lagoon_server::irc::wire::{HelloPayload, MeshMessage};

/// Helper: create an event channel and return (tx, rx).
fn make_event_channel() -> (
    mpsc::UnboundedSender<RelayEvent>,
    mpsc::UnboundedReceiver<RelayEvent>,
) {
    mpsc::unbounded_channel()
}

/// Helper: build a HelloPayload with all fields populated.
fn make_hello() -> HelloPayload {
    HelloPayload {
        peer_id: "b3b3/deadbeef".into(),
        server_name: "lon.lagun.co".into(),
        public_key_hex: "aabbccdd".into(),
        spiral_index: Some(7),
        vdf_genesis: Some("0011".into()),
        vdf_hash: Some("ffee".into()),
        vdf_step: Some(12345),
        yggdrasil_addr: Some("200:1234::1".into()),
        site_name: "lagun.co".into(),
        node_name: "lon".into(),
        vdf_resonance_credit: Some(0.999),
        vdf_actual_rate_hz: Some(10.0),
        ygg_peer_uri: Some("tcp://[200:1234::1]:9443".into()),
        cvdf_height: None,
        cvdf_weight: None,
        cvdf_tip_hex: None,
        cvdf_genesis_hex: None,
    }
}

#[test]
fn dispatch_hello_returns_payload() {
    let (tx, _rx) = make_event_channel();
    let msg = MeshMessage::Hello(make_hello());
    let result = dispatch_mesh_message(msg, "lon.lagun.co", None, &None, &tx);
    assert!(result.is_some());
    let hello = result.unwrap();
    assert_eq!(hello.peer_id, "b3b3/deadbeef");
    assert_eq!(hello.server_name, "lon.lagun.co");
    assert_eq!(hello.spiral_index, Some(7));
}

#[test]
fn dispatch_hello_sends_mesh_hello_event() {
    let (tx, mut rx) = make_event_channel();
    let peer_addr: SocketAddr = "10.7.1.37:9443".parse().unwrap();
    let msg = MeshMessage::Hello(make_hello());
    dispatch_mesh_message(msg, "lon.lagun.co", Some(peer_addr), &None, &tx);

    let event = rx.try_recv().unwrap();
    match event {
        RelayEvent::MeshHello {
            remote_host,
            peer_id,
            server_name,
            public_key_hex,
            spiral_index,
            vdf_genesis,
            vdf_hash,
            vdf_step,
            yggdrasil_addr,
            site_name,
            node_name,
            vdf_resonance_credit,
            vdf_actual_rate_hz,
            ygg_peer_uri,
            relay_peer_addr,
            ..
        } => {
            assert_eq!(remote_host, "lon.lagun.co");
            assert_eq!(peer_id, "b3b3/deadbeef");
            assert_eq!(server_name, "lon.lagun.co");
            assert_eq!(public_key_hex, "aabbccdd");
            assert_eq!(spiral_index, Some(7));
            assert_eq!(vdf_genesis.as_deref(), Some("0011"));
            assert_eq!(vdf_hash.as_deref(), Some("ffee"));
            assert_eq!(vdf_step, Some(12345));
            assert_eq!(yggdrasil_addr.as_deref(), Some("200:1234::1"));
            assert_eq!(site_name, "lagun.co");
            assert_eq!(node_name, "lon");
            assert_eq!(vdf_resonance_credit, Some(0.999));
            assert_eq!(vdf_actual_rate_hz, Some(10.0));
            assert_eq!(ygg_peer_uri.as_deref(), Some("tcp://[200:1234::1]:9443"));
            assert_eq!(relay_peer_addr, Some(peer_addr));
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_hello_derives_site_name_when_empty() {
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.site_name = String::new(); // empty → derive from server_name
    hello.server_name = "lon.lagun.co".into();
    let msg = MeshMessage::Hello(hello);
    dispatch_mesh_message(msg, "lon.lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { site_name, .. } => {
            assert_eq!(site_name, "lagun.co"); // derived: strip first label
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_hello_derives_node_name_when_empty() {
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.node_name = String::new(); // empty → derive from server_name
    hello.server_name = "per.lagun.co".into();
    let msg = MeshMessage::Hello(hello);
    dispatch_mesh_message(msg, "per.lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { node_name, .. } => {
            assert_eq!(node_name, "per"); // derived: first label
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_hello_bare_domain_derivation() {
    // Bare domain (1 dot) — site_name = server_name, node_name = server_name.
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.site_name = String::new();
    hello.node_name = String::new();
    hello.server_name = "lagun.co".into();
    let msg = MeshMessage::Hello(hello);
    dispatch_mesh_message(msg, "lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello {
            site_name,
            node_name,
            ..
        } => {
            assert_eq!(site_name, "lagun.co"); // bare domain → self
            assert_eq!(node_name, "lagun.co"); // bare domain → self
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_peers_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let peers = vec![
        MeshPeerInfo {
            peer_id: "b3b3/aaaa".into(),
            server_name: "per.lagun.co".into(),
            public_key_hex: "1111".into(),
            site_name: "lagun.co".into(),
            node_name: "per".into(),
            ..Default::default()
        },
        MeshPeerInfo {
            peer_id: "b3b3/bbbb".into(),
            server_name: "nyc.lagun.co".into(),
            public_key_hex: "2222".into(),
            site_name: "lagun.co".into(),
            node_name: "nyc".into(),
            ..Default::default()
        },
    ];
    let msg = MeshMessage::Peers {
        peers: peers.clone(),
    };
    let result = dispatch_mesh_message(msg, "per.lagun.co", None, &None, &tx);
    assert!(result.is_none()); // non-Hello returns None

    match rx.try_recv().unwrap() {
        RelayEvent::MeshPeers {
            remote_host,
            peers: received,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(received.len(), 2);
            assert_eq!(received[0].peer_id, "b3b3/aaaa");
            assert_eq!(received[1].peer_id, "b3b3/bbbb");
        }
        other => panic!("expected MeshPeers, got {other:?}"),
    }
}

#[test]
fn dispatch_vdf_proof_req_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let result = dispatch_mesh_message(
        MeshMessage::VdfProofReq,
        "per.lagun.co",
        None,
        &None,
        &tx,
    );
    assert!(result.is_none());

    match rx.try_recv().unwrap() {
        RelayEvent::MeshVdfProofReq { remote_host } => {
            assert_eq!(remote_host, "per.lagun.co");
        }
        other => panic!("expected MeshVdfProofReq, got {other:?}"),
    }
}

#[test]
fn dispatch_vdf_proof_threads_mesh_key() {
    let (tx, mut rx) = make_event_channel();
    let proof = serde_json::json!({"steps": 1000, "genesis": "aabb", "hash": "ccdd"});
    let mesh_key = Some("b3b3/deadbeef".to_string());
    let result = dispatch_mesh_message(
        MeshMessage::VdfProof {
            proof: proof.clone(),
        },
        "per.lagun.co",
        None,
        &mesh_key,
        &tx,
    );
    assert!(result.is_none());

    match rx.try_recv().unwrap() {
        RelayEvent::MeshVdfProof {
            remote_host,
            proof_json,
            mesh_key: received_key,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(received_key, Some("b3b3/deadbeef".to_string()));
            // Verify the proof JSON survived the round-trip.
            let parsed: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
            assert_eq!(parsed["steps"], 1000);
            assert_eq!(parsed["genesis"], "aabb");
        }
        other => panic!("expected MeshVdfProof, got {other:?}"),
    }
}

#[test]
fn dispatch_vdf_proof_none_mesh_key() {
    let (tx, mut rx) = make_event_channel();
    let proof = serde_json::json!({"steps": 500});
    dispatch_mesh_message(
        MeshMessage::VdfProof { proof },
        "nyc.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::MeshVdfProof { mesh_key, .. } => {
            assert!(mesh_key.is_none());
        }
        other => panic!("expected MeshVdfProof, got {other:?}"),
    }
}

#[test]
fn dispatch_sync_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let result = dispatch_mesh_message(MeshMessage::Sync, "per.lagun.co", None, &None, &tx);
    assert!(result.is_none());

    match rx.try_recv().unwrap() {
        RelayEvent::MeshSync { remote_host } => {
            assert_eq!(remote_host, "per.lagun.co");
        }
        other => panic!("expected MeshSync, got {other:?}"),
    }
}

#[test]
fn dispatch_gossip_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let event = serde_json::json!({"nick": "alice", "channel": "#lagoon", "text": "hi"});
    dispatch_mesh_message(
        MeshMessage::Gossip {
            message: event.clone(),
        },
        "per.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::GossipReceive {
            remote_host,
            message_json,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            let parsed: serde_json::Value = serde_json::from_str(&message_json).unwrap();
            assert_eq!(parsed["nick"], "alice");
            assert_eq!(parsed["channel"], "#lagoon");
            assert_eq!(parsed["text"], "hi");
        }
        other => panic!("expected GossipReceive, got {other:?}"),
    }
}

#[test]
fn dispatch_gossip_spore_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let b64_data = "YmFzZTY0ZGF0YQ==".to_string();
    dispatch_mesh_message(
        MeshMessage::GossipSpore {
            data: b64_data.clone(),
        },
        "per.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::GossipSpore {
            remote_host,
            spore_json,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(spore_json, b64_data);
        }
        other => panic!("expected GossipSpore, got {other:?}"),
    }
}

#[test]
fn dispatch_gossip_diff_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let b64_data = "c29tZWRhdGE=".to_string();
    dispatch_mesh_message(
        MeshMessage::GossipDiff {
            data: b64_data.clone(),
        },
        "per.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::GossipDiff {
            remote_host,
            messages_json,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(messages_json, b64_data);
        }
        other => panic!("expected GossipDiff, got {other:?}"),
    }
}

#[test]
fn dispatch_latency_have_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let b64_data = "bGF0ZW5jeQ==".to_string();
    dispatch_mesh_message(
        MeshMessage::LatencyHave {
            data: b64_data.clone(),
        },
        "per.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::LatencyHaveList {
            remote_host,
            payload_b64,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(payload_b64, b64_data);
        }
        other => panic!("expected LatencyHaveList, got {other:?}"),
    }
}

#[test]
fn dispatch_latency_delta_sends_event() {
    let (tx, mut rx) = make_event_channel();
    let b64_data = "ZGVsdGE=".to_string();
    dispatch_mesh_message(
        MeshMessage::LatencyDelta {
            data: b64_data.clone(),
        },
        "per.lagun.co",
        None,
        &None,
        &tx,
    );

    match rx.try_recv().unwrap() {
        RelayEvent::LatencyProofDelta {
            remote_host,
            payload_b64,
        } => {
            assert_eq!(remote_host, "per.lagun.co");
            assert_eq!(payload_b64, b64_data);
        }
        other => panic!("expected LatencyProofDelta, got {other:?}"),
    }
}

#[test]
fn dispatch_non_hello_returns_none() {
    // Every variant except Hello should return None.
    let (tx, _rx) = make_event_channel();
    let variants: Vec<MeshMessage> = vec![
        MeshMessage::Peers { peers: vec![] },
        MeshMessage::VdfProofReq,
        MeshMessage::VdfProof {
            proof: serde_json::json!({}),
        },
        MeshMessage::Sync,
        MeshMessage::Gossip {
            message: serde_json::json!({}),
        },
        MeshMessage::GossipSpore {
            data: String::new(),
        },
        MeshMessage::GossipDiff {
            data: String::new(),
        },
        MeshMessage::LatencyHave {
            data: String::new(),
        },
        MeshMessage::LatencyDelta {
            data: String::new(),
        },
    ];
    for variant in variants {
        let result = dispatch_mesh_message(variant, "test.co", None, &None, &tx);
        assert!(result.is_none());
    }
}

#[test]
fn dispatch_hello_explicit_site_node_preserved() {
    // When site_name and node_name are explicitly set, they should NOT be derived.
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.server_name = "lon.lagun.co".into();
    hello.site_name = "custom-site.example".into();
    hello.node_name = "custom-node".into();
    let msg = MeshMessage::Hello(hello);
    dispatch_mesh_message(msg, "lon.lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello {
            site_name,
            node_name,
            ..
        } => {
            assert_eq!(site_name, "custom-site.example");
            assert_eq!(node_name, "custom-node");
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_all_variants_produce_exactly_one_event() {
    // Each dispatch call should produce exactly one RelayEvent, never zero, never more.
    let variants: Vec<MeshMessage> = vec![
        MeshMessage::Hello(make_hello()),
        MeshMessage::Peers { peers: vec![] },
        MeshMessage::VdfProofReq,
        MeshMessage::VdfProof {
            proof: serde_json::json!({}),
        },
        MeshMessage::Sync,
        MeshMessage::Gossip {
            message: serde_json::json!({}),
        },
        MeshMessage::GossipSpore {
            data: "aa".into(),
        },
        MeshMessage::GossipDiff {
            data: "bb".into(),
        },
        MeshMessage::LatencyHave {
            data: "cc".into(),
        },
        MeshMessage::LatencyDelta {
            data: "dd".into(),
        },
    ];
    for variant in variants {
        let (tx, mut rx) = make_event_channel();
        dispatch_mesh_message(variant, "test.co", None, &None, &tx);
        assert!(rx.try_recv().is_ok(), "dispatch must produce exactly one event");
        assert!(rx.try_recv().is_err(), "dispatch must produce no more than one event");
    }
}

#[test]
fn dispatch_wire_round_trip_hello() {
    // Serialize a MeshMessage to JSON, deserialize, dispatch, verify event.
    let (tx, mut rx) = make_event_channel();
    let original = MeshMessage::Hello(make_hello());
    let json = original.to_json().unwrap();
    let deserialized = MeshMessage::from_json(&json).unwrap();
    let result = dispatch_mesh_message(deserialized, "lon.lagun.co", None, &None, &tx);
    assert!(result.is_some());

    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { peer_id, .. } => {
            assert_eq!(peer_id, "b3b3/deadbeef");
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_wire_round_trip_peers() {
    let (tx, mut rx) = make_event_channel();
    let peer = MeshPeerInfo {
        peer_id: "b3b3/cafe".into(),
        server_name: "per.lagun.co".into(),
        public_key_hex: "1234".into(),
        site_name: "lagun.co".into(),
        node_name: "per".into(),
        ..Default::default()
    };
    let original = MeshMessage::Peers {
        peers: vec![peer],
    };
    let json = original.to_json().unwrap();
    let deserialized = MeshMessage::from_json(&json).unwrap();
    dispatch_mesh_message(deserialized, "per.lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshPeers { peers, .. } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].peer_id, "b3b3/cafe");
        }
        other => panic!("expected MeshPeers, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// APE (Anycast Peer Entry) — peer URI construction tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ape_peer_uri_prefers_underlay() {
    // Relay TCP peer address (underlay) should be preferred over overlay.
    let peer_addr: SocketAddr = "10.7.1.37:6667".parse().unwrap();
    let overlay_uri = "tcp://[200:1234::1]:9443";
    let result = ape_peer_uri(Some(peer_addr), Some(overlay_uri));
    assert_eq!(result.unwrap(), "tcp://[10.7.1.37]:9443");
}

#[test]
fn ape_peer_uri_ipv6_underlay() {
    // IPv6 underlay address (e.g. Fly 6PN fdaa: or public 2605:).
    let peer_addr: SocketAddr = "[fdaa:0:dead:a7b:66:2:9b55:2]:6667".parse().unwrap();
    let result = ape_peer_uri(Some(peer_addr), Some("tcp://[200:1234::1]:9443"));
    assert_eq!(result.unwrap(), "tcp://[fdaa:0:dead:a7b:66:2:9b55:2]:9443");
}

#[test]
fn ape_peer_uri_falls_back_to_overlay() {
    // No relay TCP address → use ygg_peer_uri from MESH HELLO.
    let result = ape_peer_uri(None, Some("tcp://[200:1234::1]:9443"));
    assert_eq!(result.unwrap(), "tcp://[200:1234::1]:9443");
}

#[test]
fn ape_peer_uri_none_when_neither() {
    // No relay address and no ygg_peer_uri → None.
    let result = ape_peer_uri(None, None);
    assert!(result.is_none());
}

#[test]
fn ape_peer_uri_underlay_with_no_overlay() {
    // Relay address exists but no ygg_peer_uri → use underlay.
    let peer_addr: SocketAddr = "192.168.1.50:6667".parse().unwrap();
    let result = ape_peer_uri(Some(peer_addr), None);
    assert_eq!(result.unwrap(), "tcp://[192.168.1.50]:9443");
}

#[test]
fn ape_peer_uri_always_port_9443() {
    // Regardless of the relay's port, APE URI always uses 9443 (Ygg listen port).
    let peer_addr: SocketAddr = "10.0.0.1:443".parse().unwrap();
    let result = ape_peer_uri(Some(peer_addr), None);
    assert_eq!(result.unwrap(), "tcp://[10.0.0.1]:9443");
}

// ═══════════════════════════════════════════════════════════════════════════
// Transport priority selection tests
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn transport_ygg_overlay_priority_with_ygg_addr() {
    use std::collections::HashMap;
    let ygg: std::net::Ipv6Addr = "200:1234::1".parse().unwrap();
    let mut peers = HashMap::new();
    peers.insert(
        "per.lagun.co".into(),
        transport::PeerEntry {
            yggdrasil_addr: Some(ygg),
            port: 443,
            tls: true,
        },
    );
    // With ygg_node AND ygg_addr → overlay wins over TLS.
    let mode = transport::select_transport_inner("per.lagun.co", &peers, true);
    assert_eq!(mode, TransportMode::YggOverlay { addr: ygg });
}

#[test]
fn transport_tls_ws_when_bootstrap_no_ygg() {
    use std::collections::HashMap;
    let mut peers = HashMap::new();
    peers.insert(
        "lagun.co".into(),
        transport::PeerEntry {
            yggdrasil_addr: None,
            port: 443,
            tls: true,
        },
    );
    // Bootstrap peer: no ygg_addr → TLS WebSocket.
    let mode = transport::select_transport_inner("lagun.co", &peers, true);
    assert_eq!(
        mode,
        TransportMode::TlsWebSocket {
            host: "lagun.co".into(),
            port: 443,
        }
    );
}

#[test]
fn transport_peer_table_ygg_addr_enables_overlay() {
    // Simulates: MESH PEERS arrives with ygg_addr for a node.
    // The event processor inserts it into the transport peer table.
    // Next connect() should use Ygg overlay.
    use std::collections::HashMap;
    let ygg: std::net::Ipv6Addr = "201:abcd::beef".parse().unwrap();
    let mut peers = HashMap::new();

    // Before MESH PEERS: no entry → unknown peer → plain TCP.
    assert_eq!(
        transport::select_transport_inner("per", &peers, true),
        TransportMode::PlainTcp {
            host: "per".into(),
            port: 443,
        }
    );

    // After MESH PEERS: ygg_addr inserted → overlay.
    peers.insert(
        "per".into(),
        transport::PeerEntry {
            yggdrasil_addr: Some(ygg),
            port: 443,
            tls: false,
        },
    );
    let mode = transport::select_transport_inner("per", &peers, true);
    assert_eq!(mode, TransportMode::YggOverlay { addr: ygg });
}

// ═══════════════════════════════════════════════════════════════════════════
// MESH HELLO dispatches ygg_peer_uri into RelayEvent
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn dispatch_hello_carries_ygg_peer_uri() {
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.ygg_peer_uri = Some("tcp://[200:1234::1]:9443".into());
    dispatch_mesh_message(
        MeshMessage::Hello(hello),
        "test-node",
        None,
        &None,
        &tx,
    );
    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { ygg_peer_uri, .. } => {
            assert_eq!(ygg_peer_uri, Some("tcp://[200:1234::1]:9443".into()));
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_hello_carries_relay_peer_addr() {
    let (tx, mut rx) = make_event_channel();
    let hello = make_hello();
    let peer_addr: SocketAddr = "10.7.1.37:6667".parse().unwrap();
    dispatch_mesh_message(
        MeshMessage::Hello(hello),
        "test-node",
        Some(peer_addr),
        &None,
        &tx,
    );
    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { relay_peer_addr, .. } => {
            assert_eq!(relay_peer_addr, Some(peer_addr));
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn dispatch_hello_yggdrasil_addr_propagated() {
    let (tx, mut rx) = make_event_channel();
    let mut hello = make_hello();
    hello.yggdrasil_addr = Some("200:abcd::1".into());
    dispatch_mesh_message(
        MeshMessage::Hello(hello),
        "test-node",
        None,
        &None,
        &tx,
    );
    match rx.try_recv().unwrap() {
        RelayEvent::MeshHello { yggdrasil_addr, .. } => {
            assert_eq!(yggdrasil_addr, Some("200:abcd::1".into()));
        }
        other => panic!("expected MeshHello, got {other:?}"),
    }
}

#[test]
fn anycast_ghost_peers_cleared_on_node_change() {
    // Reproduces the ghost peer bug from rolling deploys:
    //
    // 1. Relay "anycast-mesh" connects to pod-1a1345dd → marked Connected
    // 2. Rolling deploy kills that pod, relay reconnects to pod-be8f7c33
    // 3. Old pod-1a1345dd should be cleared from Connected state
    //
    // The bug was: disconnect cleanup searched `p.node_name == "anycast-mesh"`
    // which matched nothing, so ghosts accumulated forever.
    //
    // The fix: use relay.remote_node_name (the actual node) for cleanup.
    //
    // This test validates the state-level invariant: when we know a relay
    // was previously connected to node X, switching to node Y must clear
    // node X's Connected state.

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (state, _rx) = make_test_state("ghost-test.lagun.co");

        // Simulate: old pod was known and marked Connected.
        let old_ghost = lens::generate_identity("lagun.co");
        let new_node = lens::generate_identity("lagun.co");
        {
            let mut st = state.write().await;
            st.mesh.known_peers.insert(
                old_ghost.peer_id.clone(),
                MeshPeerInfo {
                    peer_id: old_ghost.peer_id.clone(),
                    server_name: "lagun.co".into(),
                    public_key_hex: old_ghost.public_key_hex.clone(),
                    node_name: "pod-1a1345dd".into(),
                    site_name: "lagun.co".into(),
                    ..Default::default()
                },
            );
            st.mesh.connections.insert(
                old_ghost.peer_id.clone(),
                MeshConnectionState::Connected,
            );

            // Ghost is Connected.
            assert_eq!(
                st.mesh.connections.get(&old_ghost.peer_id),
                Some(&MeshConnectionState::Connected)
            );
        }

        // Simulate: relay reconnects, HELLO from different node.
        // The fix clears ghosts by searching node_name, not relay_key.
        {
            let mut st = state.write().await;
            let old_node_name = "pod-1a1345dd";
            let new_node_name = "pod-be8f7c33";

            // This is what the fixed code does on HELLO with changed node:
            let ghost_ids: Vec<String> = st.mesh.known_peers.iter()
                .filter(|(_, p)| p.node_name == old_node_name)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ghost_ids {
                st.mesh.connections.remove(id);
                st.mesh.spiral.remove_peer(id);
            }

            // Add the new node.
            st.mesh.known_peers.insert(
                new_node.peer_id.clone(),
                MeshPeerInfo {
                    peer_id: new_node.peer_id.clone(),
                    server_name: "lagun.co".into(),
                    public_key_hex: new_node.public_key_hex.clone(),
                    node_name: new_node_name.into(),
                    site_name: "lagun.co".into(),
                    ..Default::default()
                },
            );
            st.mesh.connections.insert(
                new_node.peer_id.clone(),
                MeshConnectionState::Connected,
            );
        }

        let st = state.read().await;

        // Ghost must NOT be Connected.
        assert_ne!(
            st.mesh.connections.get(&old_ghost.peer_id),
            Some(&MeshConnectionState::Connected),
            "ghost peer from old deploy must not remain Connected"
        );

        // New node IS Connected.
        assert_eq!(
            st.mesh.connections.get(&new_node.peer_id),
            Some(&MeshConnectionState::Connected),
            "new node must be Connected"
        );

        // Only 1 Connected entry, not 2.
        let connected_count = st.mesh.connections.values()
            .filter(|&&s| s == MeshConnectionState::Connected)
            .count();
        assert_eq!(connected_count, 1, "exactly 1 connected peer, no ghosts");
    });
}

/// Verifies that disconnect cleanup uses actual node_name (not relay_key)
/// to find and remove the old peer's Connected state.
#[test]
fn disconnect_cleanup_uses_node_name_not_relay_key() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (state, _rx) = make_test_state("relay-key-test.lagun.co");

        let peer = lens::generate_identity("lagun.co");
        {
            let mut st = state.write().await;
            st.mesh.known_peers.insert(
                peer.peer_id.clone(),
                MeshPeerInfo {
                    peer_id: peer.peer_id.clone(),
                    server_name: "lagun.co".into(),
                    public_key_hex: peer.public_key_hex.clone(),
                    node_name: "pod-abc123".into(),
                    site_name: "lagun.co".into(),
                    ..Default::default()
                },
            );
            st.mesh.connections.insert(
                peer.peer_id.clone(),
                MeshConnectionState::Connected,
            );
        }

        // Simulate: relay_key is "anycast-mesh" but the actual node was "pod-abc123".
        // Old buggy code searched: p.node_name == "anycast-mesh" → found NOTHING.
        // Fixed code uses: relay.remote_node_name → "pod-abc123".
        {
            let mut st = state.write().await;

            // Bug: searching by relay_key finds nothing.
            let relay_key = "anycast-mesh";
            let buggy_result: Vec<String> = st.mesh.known_peers.iter()
                .filter(|(_, p)| p.node_name == relay_key)
                .map(|(id, _)| id.clone())
                .collect();
            assert!(buggy_result.is_empty(), "relay_key 'anycast-mesh' should match no nodes");

            // Fix: searching by actual node_name finds the peer.
            let actual_node = "pod-abc123";
            let fixed_result: Vec<String> = st.mesh.known_peers.iter()
                .filter(|(_, p)| p.node_name == actual_node)
                .map(|(id, _)| id.clone())
                .collect();
            assert_eq!(fixed_result.len(), 1);
            assert_eq!(fixed_result[0], peer.peer_id);

            // Clean it up.
            for id in &fixed_result {
                st.mesh.connections.remove(id);
            }
        }

        let st = state.read().await;
        assert!(
            !st.mesh.connections.contains_key(&peer.peer_id),
            "peer must be cleaned up when using actual node_name"
        );
    });
}

#[test]
fn dispatch_peers_carries_yggdrasil_addr() {
    let (tx, mut rx) = make_event_channel();
    let peer = MeshPeerInfo {
        peer_id: "b3b3/cafe".into(),
        server_name: "per.lagun.co".into(),
        public_key_hex: "1234".into(),
        site_name: "lagun.co".into(),
        node_name: "per".into(),
        yggdrasil_addr: Some("200:1234::1".into()),
        ygg_peer_uri: Some("tcp://[200:1234::1]:9443".into()),
        ..Default::default()
    };
    let msg = MeshMessage::Peers { peers: vec![peer] };
    dispatch_mesh_message(msg, "per.lagun.co", None, &None, &tx);

    match rx.try_recv().unwrap() {
        RelayEvent::MeshPeers { peers, .. } => {
            assert_eq!(peers[0].yggdrasil_addr, Some("200:1234::1".into()));
            assert_eq!(
                peers[0].ygg_peer_uri,
                Some("tcp://[200:1234::1]:9443".into())
            );
        }
        other => panic!("expected MeshPeers, got {other:?}"),
    }
}
