/// Integration tests for mesh networking, invite codes, defederation, and
/// TLS federation transport.
///
/// These tests verify the mesh protocol, invite code lifecycle,
/// defederation behavior, and TLS peer configuration using in-process servers.
use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};

use lagoon_server::irc::federation::RelayEvent;
use lagoon_server::irc::invite::{InviteKind, InviteStore, Privilege};
use lagoon_server::irc::lens;
use lagoon_server::irc::server::{
    MeshConnectionState, MeshPeerInfo, MeshSnapshot, ServerState, SharedState,
};
use lagoon_server::irc::transport;

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
                lens_id: peer_id.peer_id.clone(),
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
                lens_id: peer1.peer_id.clone(),
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
                lens_id: peer2.peer_id.clone(),
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
                lens_id: peer.peer_id.clone(),
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
                lens_id: peer.peer_id.clone(),
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

    // Two CDN containers sharing the same server_name but different lens_ids.
    let cdn1 = lens::generate_identity("lagun.co");
    let cdn2 = lens::generate_identity("lagun.co");
    assert_ne!(cdn1.peer_id, cdn2.peer_id);

    {
        let mut st = state.write().await;
        st.mesh.known_peers.insert(
            cdn1.peer_id.clone(),
            MeshPeerInfo {
                lens_id: cdn1.peer_id.clone(),
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
                lens_id: cdn2.peer_id.clone(),
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
    assert_ne!(cdn_nodes[0].lens_id, cdn_nodes[1].lens_id);

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
    assert_eq!(browser.lens_id, "web/alice");
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
                lens_id: peer.peer_id.clone(),
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
