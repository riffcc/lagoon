//! Wire compatibility tests: yggdrasil-rs (Rust) ↔ yggdrasil-go (via yggbridge FFI).
//!
//! These tests prove our pure Rust implementation can peer with stock Yggdrasil.
//! If the meta handshake succeeds and ironwood frames flow, we're wire-compatible.

use std::time::Duration;

use tokio::io::BufReader;
use tokio::net::TcpStream;

use yggdrasil_rs::crypto::Identity;
use yggdrasil_rs::{meta, wire};

/// Generate a 64-byte Ed25519 private key (Go format: seed:32 + pubkey:32).
fn make_key() -> [u8; 64] {
    let id = Identity::generate();
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&id.signing_key.to_bytes());
    key[32..].copy_from_slice(&id.public_key_bytes);
    key
}

/// Find a free TCP port.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ═══════════════════════════════════════════════════════════════════════════
// Address derivation compatibility
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn address_matches_go_derivation() {
    // Same key → both implementations must produce the same Ygg overlay address.
    let key = make_key();
    let go_node = yggbridge::YggNode::new(&key, &[], &[]).unwrap();
    let rust_id = Identity::from_privkey_bytes(&key);

    assert_eq!(
        rust_id.address,
        go_node.address(),
        "Rust and Go must derive identical addresses from the same key.\n\
         Rust: {}\n\
         Go:   {}",
        rust_id.address,
        go_node.address(),
    );
}

#[test]
fn public_key_matches_go() {
    let key = make_key();
    let go_node = yggbridge::YggNode::new(&key, &[], &[]).unwrap();
    let rust_id = Identity::from_privkey_bytes(&key);

    assert_eq!(
        rust_id.public_key_hex(),
        go_node.public_key_hex(),
        "Rust and Go must produce identical public key hex"
    );
}

#[test]
fn many_keys_all_match() {
    // Stress test: 100 random keys, all must produce matching addresses.
    for _ in 0..100 {
        let key = make_key();
        let go_node = yggbridge::YggNode::new(&key, &[], &[]).unwrap();
        let rust_id = Identity::from_privkey_bytes(&key);
        assert_eq!(
            rust_id.address,
            go_node.address(),
            "address mismatch for key {}",
            rust_id.public_key_hex()
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Meta handshake: Rust → Go
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn rust_meta_handshake_with_go_node() {
    // The real proof: our Rust meta handshake is accepted by stock Go Yggdrasil.
    //
    // Flow:
    //   1. Go node listens on TCP port (via yggbridge)
    //   2. Rust connects raw TCP
    //   3. Both sides exchange "meta" messages simultaneously
    //   4. If Go accepts our meta → we're wire-compatible

    let go_key = make_key();
    let go_port = free_port();
    let go_node = yggbridge::YggNode::new(
        &go_key,
        &[],
        &[format!("tcp://127.0.0.1:{go_port}")],
    )
    .unwrap();

    let go_pubkey_hex = go_node.public_key_hex();

    // Connect raw TCP to Go's listen port
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{go_port}")),
    )
    .await
    .expect("TCP connect timed out")
    .expect("TCP connect failed");

    // Perform our Rust meta handshake against the Go node
    let rust_id = Identity::generate();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        meta::handshake(&mut stream, &rust_id, 0, None),
    )
    .await
    .expect("meta handshake timed out");

    let remote = result.expect("meta handshake failed — Go rejected our Rust meta message!");

    // Verify we got Go's actual public key back
    assert_eq!(
        hex::encode(remote.public_key),
        go_pubkey_hex,
        "meta handshake returned wrong public key"
    );

    // The handshake succeeded. We are wire-compatible with stock Yggdrasil.
    //
    // After meta, ironwood takes over on the Go side. It will send tree protocol
    // messages (SigReq, Announce, etc.). Let's verify we can read them.

    let mut reader = BufReader::new(&mut stream);

    // Read the first ironwood frame from Go.
    // Stock Ygg typically sends wireProtoSigReq or wireKeepAlive first.
    let first_frame = tokio::time::timeout(
        Duration::from_secs(5),
        wire::read_frame(&mut reader),
    )
    .await
    .expect("reading first ironwood frame timed out");

    let (ptype, payload) = first_frame.expect("failed to read ironwood frame from Go");
    eprintln!(
        "Got ironwood frame from Go: type={:?}, payload_len={}",
        ptype,
        payload.len()
    );

    // We accept any valid packet type — the point is that framing works.
    assert!(
        matches!(
            ptype,
            wire::PacketType::KeepAlive
                | wire::PacketType::ProtoSigReq
                | wire::PacketType::ProtoSigRes
                | wire::PacketType::ProtoAnnounce
                | wire::PacketType::ProtoBloomFilter
                | wire::PacketType::Traffic
        ),
        "unexpected packet type from Go: {ptype:?}"
    );

    // Keep Go node alive until test completes
    drop(go_node);
}

#[tokio::test]
async fn rust_reads_multiple_go_frames() {
    // Read several frames to verify sustained ironwood framing compatibility.

    let go_key = make_key();
    let go_port = free_port();
    let go_node = yggbridge::YggNode::new(
        &go_key,
        &[],
        &[format!("tcp://127.0.0.1:{go_port}")],
    )
    .unwrap();

    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{go_port}")),
    )
    .await
    .expect("connect timed out")
    .expect("connect failed");

    let rust_id = Identity::generate();
    let _remote = tokio::time::timeout(
        Duration::from_secs(5),
        meta::handshake(&mut stream, &rust_id, 0, None),
    )
    .await
    .expect("handshake timed out")
    .expect("handshake failed");

    let mut reader = BufReader::new(&mut stream);
    let mut frame_count = 0;

    // Read up to 5 frames (or timeout after 10s total).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while frame_count < 5 {
        match tokio::time::timeout_at(deadline, wire::read_frame(&mut reader)).await {
            Ok(Ok((ptype, payload))) => {
                eprintln!("frame {}: type={:?}, len={}", frame_count, ptype, payload.len());
                frame_count += 1;
            }
            Ok(Err(e)) => {
                eprintln!("frame read error after {frame_count} frames: {e}");
                break;
            }
            Err(_) => {
                eprintln!("timeout after {frame_count} frames");
                break;
            }
        }
    }

    // We should get at least 1 frame (keepalive or tree protocol).
    assert!(
        frame_count >= 1,
        "expected at least 1 ironwood frame from Go, got {frame_count}"
    );

    drop(go_node);
}

// ═══════════════════════════════════════════════════════════════════════════
// Bidirectional: Go dials Rust
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn go_node_peers_with_rust_listener() {
    // Prove it works in both directions: Rust listens, Go dials.
    //
    // This is the "stock Ygg node peers with us" scenario.

    let rust_id = Identity::generate();
    let rust_port = free_port();

    // Rust listener
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{rust_port}"))
        .await
        .unwrap();

    let rust_id_clone = rust_id.clone();
    let accept_handle = tokio::spawn(async move {
        let (mut stream, _addr) = tokio::time::timeout(
            Duration::from_secs(10),
            listener.accept(),
        )
        .await
        .expect("accept timed out")
        .expect("accept failed");

        // Perform meta handshake from Rust side
        let remote = tokio::time::timeout(
            Duration::from_secs(5),
            meta::handshake(&mut stream, &rust_id_clone, 0, None),
        )
        .await
        .expect("handshake timed out")
        .expect("Go's meta handshake was rejected by our Rust verifier!");

        remote.public_key
    });

    // Go node dials our Rust listener
    let go_key = make_key();
    let go_node = yggbridge::YggNode::new(
        &go_key,
        &[format!("tcp://127.0.0.1:{rust_port}")],
        &[],
    )
    .unwrap();

    let remote_key = tokio::time::timeout(Duration::from_secs(10), accept_handle)
        .await
        .expect("accept task timed out")
        .expect("accept task panicked");

    // Verify we got Go's key
    assert_eq!(
        hex::encode(remote_key),
        go_node.public_key_hex(),
        "Rust accepted Go's meta, but public key doesn't match"
    );

    drop(go_node);
}
