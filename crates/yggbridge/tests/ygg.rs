/// Yggdrasil overlay networking tests — real CGO, real Go runtime, real peering.
///
/// These tests create actual embedded Yggdrasil nodes with gVisor TCP/IP stacks,
/// peer them via localhost TCP (underlay), and verify overlay connectivity.
///
/// `dial()` IS the proof that peering works — if the overlay TCP connection
/// succeeds, the underlay peering was established.  No polling.
use std::net::Ipv6Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yggbridge::{YggNode, YggPeerInfo};

/// Generate a 64-byte Ed25519 private key from a random 32-byte seed.
fn make_ygg_key() -> [u8; 64] {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&seed);
    key[32..].copy_from_slice(signing_key.verifying_key().as_bytes());
    key
}

/// Find a free TCP port by binding to port 0 and reading the assigned port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Check if an address is in the Yggdrasil 0200::/7 range.
fn is_ygg_addr(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] & 0xfe == 0x02
}

// ═══════════════════════════════════════════════════════════════════════════
// Node lifecycle
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn node_starts_with_empty_peers() {
    let key = make_ygg_key();
    let port = free_port();
    let listen = vec![format!("tcp://127.0.0.1:{port}")];
    let node = YggNode::new(&key, &[], &listen).unwrap();

    let addr = node.address();
    assert!(is_ygg_addr(addr), "expected 200::/7 address, got {addr}");
    assert_ne!(addr, Ipv6Addr::UNSPECIFIED);

    let peers = node.peers();
    assert!(peers.is_empty(), "expected no peers, got {peers:?}");
}

#[test]
fn node_has_public_key() {
    let key = make_ygg_key();
    let port = free_port();
    let listen = vec![format!("tcp://127.0.0.1:{port}")];
    let node = YggNode::new(&key, &[], &listen).unwrap();

    let pubkey = node.public_key_hex();
    assert_eq!(pubkey.len(), 64, "expected 32-byte hex pubkey");
    assert!(
        pubkey.chars().all(|c| c.is_ascii_hexdigit()),
        "pubkey should be hex: {pubkey}"
    );
}

#[test]
fn two_nodes_have_different_addresses() {
    let port_a = free_port();
    let port_b = free_port();
    let node_a = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_a}")],
    )
    .unwrap();
    let node_b = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_b}")],
    )
    .unwrap();

    assert_ne!(
        node_a.address(),
        node_b.address(),
        "two nodes with different keys must have different addresses"
    );
}

#[test]
fn deterministic_address_from_key() {
    let key = make_ygg_key();
    let port_a = free_port();
    let port_b = free_port();
    let node_a = YggNode::new(&key, &[], &[format!("tcp://127.0.0.1:{port_a}")]).unwrap();
    let addr_a = node_a.address();
    drop(node_a);

    let node_b = YggNode::new(&key, &[], &[format!("tcp://127.0.0.1:{port_b}")]).unwrap();
    let addr_b = node_b.address();

    assert_eq!(addr_a, addr_b, "same key must produce same address");
}

// ═══════════════════════════════════════════════════════════════════════════
// Peering — add_peer establishes underlay connection
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn add_peer_connects_nodes() {
    let port_a = free_port();
    let port_b = free_port();
    let node_a = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_a}")],
    )
    .unwrap();
    let node_b = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_b}")],
    )
    .unwrap();

    // B peers with A.
    node_b
        .add_peer(&format!("tcp://127.0.0.1:{port_a}"))
        .unwrap();

    // Give Ygg a moment to establish the underlay TCP + key exchange.
    // We verify by checking peers() — at least one peer should appear.
    // The peer may not be `up` instantly, but the add_peer call itself
    // should succeed without error.
    let peers_b = node_b.peers();
    // add_peer registers the peer — it should show in the list even if
    // the connection is still being established.
    assert!(
        !peers_b.is_empty(),
        "after add_peer, node B should have at least one peer entry"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Overlay connectivity — dial/listen proves the mesh works
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn overlay_dial_and_listen() {
    let port_a = free_port();
    let port_b = free_port();
    let node_a = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_a}")],
    )
    .unwrap();
    let node_b = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_b}")],
    )
    .unwrap();

    let addr_a = node_a.address();
    let addr_b = node_b.address();

    // Peer in both directions for fast establishment.
    node_a
        .add_peer(&format!("tcp://127.0.0.1:{port_b}"))
        .unwrap();
    node_b
        .add_peer(&format!("tcp://127.0.0.1:{port_a}"))
        .unwrap();

    // Node A listens on overlay port 7777.
    let listener = node_a.listen(7777).unwrap();

    // Spawn acceptor.
    let accept_handle = tokio::spawn(async move {
        let (mut stream, remote_addr) = listener.accept().await.unwrap();
        assert_eq!(remote_addr, addr_b, "remote addr should be node B's overlay addr");

        // Read what B sends.
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello from B");

        // Send response.
        stream.write_all(b"hello from A").await.unwrap();
    });

    // Node B dials Node A's overlay address on port 7777.
    // This IS the proof: if dial succeeds, peering works.
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        node_b.dial(addr_a, 7777),
    )
    .await
    .expect("dial timed out — peering may not have established")
    .expect("dial failed");

    stream.write_all(b"hello from B").await.unwrap();

    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello from A");

    accept_handle.await.unwrap();
}

#[tokio::test]
async fn ape_flow_empty_start_then_add_peer_then_dial() {
    // Simulates the full APE bootstrap flow:
    //
    // 1. Node A starts with EMPTY peers (LAGOON_YGG=1, no LAGOON_PEERS)
    // 2. Node B starts with EMPTY peers
    // 3. They discover each other via MESH HELLO (simulated by add_peer)
    // 4. Overlay connectivity is proven by dial/listen
    //
    // This is exactly what happens in production:
    //   - Node starts with empty Ygg peer list
    //   - WebSocket bootstrap → MESH HELLO → ygg_peer_uri
    //   - add_peer(ygg_peer_uri) → underlay TCP peering established
    //   - Overlay dial works → federation can flow over Ygg

    let port_a = free_port();
    let port_b = free_port();

    // Both nodes start with NO peers — pure APE.
    let node_a = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_a}")],
    )
    .unwrap();
    let node_b = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_b}")],
    )
    .unwrap();

    // Verify both start isolated.
    assert!(node_a.peers().is_empty());
    assert!(node_b.peers().is_empty());

    let addr_a = node_a.address();

    // Simulate APE: Node B learns Node A's underlay address from MESH HELLO.
    // In production this is: ape_peer_uri(relay_addr, ygg_peer_uri)
    let ape_uri = format!("tcp://127.0.0.1:{port_a}");
    node_b.add_peer(&ape_uri).unwrap();

    // Node A also peers back (middle-out: both sides try).
    node_a
        .add_peer(&format!("tcp://127.0.0.1:{port_b}"))
        .unwrap();

    // Prove overlay works: A listens, B dials.
    let listener = node_a.listen(8080).unwrap();

    let accept_handle = tokio::spawn(async move {
        let (mut stream, _remote) = listener.accept().await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    });

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        node_b.dial(addr_a, 8080),
    )
    .await
    .expect("APE dial timed out — add_peer didn't establish overlay")
    .expect("APE dial failed");

    stream.write_all(b"mesh:hello").await.unwrap();
    stream.shutdown().await.unwrap();

    let received = tokio::time::timeout(std::time::Duration::from_secs(5), accept_handle)
        .await
        .expect("accept timed out")
        .unwrap();
    assert_eq!(received, "mesh:hello");
}

#[test]
fn remove_peer_succeeds() {
    let port_a = free_port();
    let port_b = free_port();
    let node_a = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_a}")],
    )
    .unwrap();
    let _node_b = YggNode::new(
        &make_ygg_key(),
        &[],
        &[format!("tcp://127.0.0.1:{port_b}")],
    )
    .unwrap();

    let uri = format!("tcp://127.0.0.1:{port_b}");
    node_a.add_peer(&uri).unwrap();
    assert!(!node_a.peers().is_empty());

    // remove_peer removes the peer from Ygg's configuration.
    // The underlying TCP connection may not close instantly, but
    // the peer won't be re-established after removal.
    node_a.remove_peer(&uri).unwrap();
}
