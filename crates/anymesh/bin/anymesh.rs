//! Anymesh CLI — standalone mesh node for testing and deployment.
//!
//! Modes:
//!   node                         — env-var-driven container mode (default)
//!   repair                       — TCP_REPAIR socket migration demo (needs root)

use std::net::SocketAddr;

use anymesh::mesh::{self, MeshConfig};
use anymesh::Capabilities;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::mpsc;

const MESH_PORT: u16 = 42105;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("");

    match mode {
        "repair" => repair_demo().await,
        "node" | "" => node_mode().await,
        _ => {
            eprintln!("usage: anymesh <node|repair>");
            eprintln!("  node     — env-var-driven container mode (default)");
            eprintln!("  repair   — TCP_REPAIR socket migration demo (needs root)");
            eprintln!();
            eprintln!("env vars (node mode):");
            eprintln!("  ANYCAST_IP    — bind address (default: 0.0.0.0)");
            eprintln!("  NODE_NAME     — this node's name (default: hostname)");
            eprintln!("  PEERS         — comma-separated peer addresses");
            eprintln!("  PORT          — listen/dial port (default: 42105)");
            std::process::exit(1);
        }
    }
}

async fn node_mode() -> Result<(), Box<dyn std::error::Error>> {
    let config = MeshConfig::from_env();
    let caps = Capabilities::detect();

    eprintln!("=== anymesh node ===");
    eprintln!("  node_name:  {}", config.node_name);
    eprintln!(
        "  anycast_ip: {}",
        config.bind_ip.as_deref().unwrap_or("0.0.0.0 (default)")
    );
    eprintln!("  port:       {}", config.port);
    eprintln!(
        "  peers:      {}",
        if config.peers.is_empty() {
            "(none)".into()
        } else {
            config.peers.join(", ")
        }
    );
    if caps.tcp_repair {
        eprintln!("  tcp_repair: YES — socket migration available!");
    } else {
        eprintln!("  tcp_repair: no (EPERM — need CAP_NET_ADMIN)");
    }
    eprintln!("=========================");

    let mut event_rx = mesh::run_mesh(config).await?;

    // Process mesh events.
    while let Some(event) = event_rx.recv().await {
        match event {
            mesh::MeshEvent::PeerConnected { name, addr } => {
                tracing::info!(peer = %name, addr = %addr, "peer connected");
            }
            mesh::MeshEvent::PeerDisconnected { name } => {
                tracing::info!(peer = %name, "peer disconnected");
            }
            mesh::MeshEvent::RttMeasured {
                peer,
                min_us,
                avg_us,
                max_us,
                samples,
            } => {
                println!(
                    "{peer}: min={min_us:.0}µs avg={avg_us:.0}µs max={max_us:.0}µs ({samples} samples)"
                );
            }
            mesh::MeshEvent::MigrationReceived { from_peer, state } => {
                tracing::info!(
                    from = %from_peer,
                    local = %state.local_addr,
                    remote = %state.remote_addr,
                    "migration received"
                );
            }
        }
    }

    Ok(())
}

async fn repair_demo() -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr: SocketAddr = format!("127.0.0.1:{MESH_PORT}").parse()?;
    let (migrate_tx, mut migrate_rx) = mpsc::channel::<anymesh::SocketMigration>(1);

    // Node-1: waits for a migrated socket, then takes over.
    let node1 = tokio::spawn(async move {
        eprintln!("[node-1] waiting for socket migration...");
        let state = migrate_rx.recv().await.expect("migration channel closed");
        eprintln!(
            "[node-1] received migration state: {:?} → {:?}, send_seq={}, recv_seq={}",
            state.local_addr, state.remote_addr, state.send_seq, state.recv_seq
        );

        let stream =
            anymesh::AnymeshStream::restore(&state).expect("restore failed");
        let (reader, mut writer) = stream.into_inner().into_split();

        writer
            .write_all(b"MIGRATED to node-1\n")
            .await
            .expect("write failed");
        eprintln!("[node-1] took over connection, sent MIGRATED");

        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let echo = format!("[node-1] {line}\n");
            if writer.write_all(echo.as_bytes()).await.is_err() {
                break;
            }
        }
        eprintln!("[node-1] connection closed");
    });

    // Node-0: accepts the connection, chats, then migrates to node-1.
    let node0 = tokio::spawn(async move {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseport(true).unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(bind_addr).unwrap();
        let listener = socket.listen(1).unwrap();
        eprintln!("[node-0] listening on {bind_addr}");

        let (stream, addr) = listener.accept().await.unwrap();
        eprintln!("[node-0] accepted connection from {addr}");

        let am_stream = anymesh::AnymeshStream::from_stream(stream);
        let (reader, mut writer) = am_stream.into_inner().into_split();
        writer.write_all(b"HELLO from node-0\n").await.unwrap();

        let mut lines = BufReader::new(reader).lines();
        let mut count = 0;

        loop {
            match lines.next_line().await {
                Ok(Some(line)) if line == "MIGRATE" => {
                    eprintln!("[node-0] received MIGRATE command, freezing socket...");
                    let reader = lines.into_inner().into_inner();
                    let tcp_stream = reader.reunite(writer).unwrap();
                    let am_stream = anymesh::AnymeshStream::from_stream(tcp_stream);
                    let state = am_stream.freeze().expect("freeze failed");
                    eprintln!(
                        "[node-0] frozen: send_seq={}, recv_seq={}",
                        state.send_seq, state.recv_seq
                    );
                    migrate_tx.send(state).await.expect("send failed");
                    eprintln!("[node-0] migration state sent to node-1");
                    return;
                }
                Ok(Some(line)) => {
                    count += 1;
                    let echo = format!("[node-0] {line}\n");
                    writer.write_all(echo.as_bytes()).await.unwrap();
                    eprintln!("[node-0] echoed message {count}: {line}");
                }
                _ => {
                    eprintln!("[node-0] connection closed unexpectedly");
                    return;
                }
            }
        }
    });

    // Client: connects, chats with node-0, triggers migration, then chats with node-1.
    let client = tokio::spawn(async move {
        tokio::task::yield_now().await;

        let stream = TcpStream::connect(bind_addr)
            .await
            .expect("connect failed");
        let local = stream.local_addr().unwrap();
        let remote = stream.peer_addr().unwrap();
        println!("client: connected {local} → {remote}");

        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();

        let hello = lines.next_line().await.unwrap().unwrap();
        println!("client: received «{hello}»");

        for i in 1..=3 {
            let msg = format!("message {i}\n");
            writer.write_all(msg.as_bytes()).await.unwrap();
            let echo = lines.next_line().await.unwrap().unwrap();
            println!("client: sent «message {i}» → got «{echo}»");
        }

        println!();
        println!("client: triggering MIGRATE...");
        writer.write_all(b"MIGRATE\n").await.unwrap();

        let migrated = lines.next_line().await.unwrap().unwrap();
        println!("client: received «{migrated}»");
        println!();

        for i in 4..=6 {
            let msg = format!("message {i}\n");
            writer.write_all(msg.as_bytes()).await.unwrap();
            let echo = lines.next_line().await.unwrap().unwrap();
            println!("client: sent «message {i}» → got «{echo}»");
        }

        println!();
        println!("client: same connection, same ports ({local} → {remote})");
        println!("client: messages 1-3 handled by node-0");
        println!("client: messages 4-6 handled by node-1");
        println!("client: TCP_REPAIR socket migration — the connection moved.");
    });

    client.await?;
    tokio::select! {
        _ = node0 => {}
        _ = node1 => {}
    }

    Ok(())
}
