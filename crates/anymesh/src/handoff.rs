//! SO_REUSEPORT shared-listener coordination.
//!
//! Multiple nodes bind the same `IP:port` with `SO_REUSEPORT`. The kernel
//! distributes incoming connections across listeners. This module coordinates
//! which node owns each connection, handing off misrouted connections via
//! channels.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::{mpsc, Mutex};

use crate::Error;

/// Policy for assigning connections to nodes.
pub trait OwnershipPolicy: Send + Sync + 'static {
    /// Given a client IP and the set of node IDs that already own connections
    /// from this IP, return the node that should own the next connection.
    /// Returns `None` if all slots are full.
    fn assign(
        &self,
        client_ip: IpAddr,
        occupied: &HashSet<usize>,
        node_count: usize,
    ) -> Option<usize>;
}

/// Default policy: first unoccupied node slot for each client IP.
#[derive(Debug, Clone)]
pub struct RoundRobinPolicy;

impl OwnershipPolicy for RoundRobinPolicy {
    fn assign(
        &self,
        _client_ip: IpAddr,
        occupied: &HashSet<usize>,
        node_count: usize,
    ) -> Option<usize> {
        (0..node_count).find(|id| !occupied.contains(id))
    }
}

/// Tracks per-IP connection ownership across nodes.
pub struct HandoffMesh<P: OwnershipPolicy = RoundRobinPolicy> {
    policy: P,
    node_count: usize,
    peered: HashMap<IpAddr, HashSet<usize>>,
    handoff_tx: Vec<mpsc::Sender<(TcpStream, SocketAddr)>>,
}

impl<P: OwnershipPolicy> HandoffMesh<P> {
    /// Create a new mesh with the given node count and ownership policy.
    /// Returns the mesh (wrapped in `Arc<Mutex>`) and a vec of handoff receivers.
    pub fn new(
        node_count: usize,
        policy: P,
    ) -> (
        Arc<Mutex<Self>>,
        Vec<mpsc::Receiver<(TcpStream, SocketAddr)>>,
    ) {
        let mut txs = Vec::with_capacity(node_count);
        let mut rxs = Vec::with_capacity(node_count);
        for _ in 0..node_count {
            let (tx, rx) = mpsc::channel(16);
            txs.push(tx);
            rxs.push(rx);
        }
        let mesh = Arc::new(Mutex::new(Self {
            policy,
            node_count,
            peered: HashMap::new(),
            handoff_tx: txs,
        }));
        (mesh, rxs)
    }

    /// Determine which node should own the next connection from this IP.
    pub fn assign(&self, client_ip: IpAddr) -> Option<usize> {
        let occupied = self.peered.get(&client_ip).cloned().unwrap_or_default();
        self.policy.assign(client_ip, &occupied, self.node_count)
    }

    /// Register that a node owns a connection from this IP.
    pub fn register(&mut self, client_ip: IpAddr, node_id: usize) {
        self.peered.entry(client_ip).or_default().insert(node_id);
    }
}

/// Bind a `SO_REUSEPORT` + `SO_REUSEADDR` shared listener.
pub fn bind_shared(addr: SocketAddr) -> Result<TcpListener, Error> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    Ok(socket.listen(128)?)
}

/// Run a handoff node's accept loop.
///
/// Accepts connections, consults the mesh for ownership, and either handles
/// locally or forwards to the correct node.
pub async fn run_handoff_node<P, F, Fut>(
    id: usize,
    listener: TcpListener,
    mesh: Arc<Mutex<HandoffMesh<P>>>,
    mut handoff_rx: mpsc::Receiver<(TcpStream, SocketAddr)>,
    handler: F,
) where
    P: OwnershipPolicy,
    F: Fn(usize, TcpStream, SocketAddr) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = ()> + Send,
{
    loop {
        tokio::select! {
            result = listener.accept() => {
                if let Ok((stream, addr)) = result {
                    let mesh = mesh.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let mut m = mesh.lock().await;
                        let owner = m.assign(addr.ip());
                        match owner {
                            Some(oid) if oid == id => {
                                m.register(addr.ip(), id);
                                drop(m);
                                tracing::debug!(node = id, addr = %addr, "accepted — keeping");
                                handler(id, stream, addr).await;
                            }
                            Some(oid) => {
                                tracing::debug!(node = id, target = oid, addr = %addr, "accepted — handing off");
                                let tx = m.handoff_tx[oid].clone();
                                m.register(addr.ip(), oid);
                                drop(m);
                                let _ = tx.send((stream, addr)).await;
                            }
                            None => {
                                drop(m);
                                tracing::debug!(node = id, addr = %addr, "rejected — full");
                                let mut s = stream;
                                let _ = s.write_all(b"FULL\n").await;
                            }
                        }
                    });
                }
            }
            Some((stream, addr)) = handoff_rx.recv() => {
                tracing::debug!(node = id, addr = %addr, "received handoff");
                let handler = handler.clone();
                tokio::spawn(async move { handler(id, stream, addr).await });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn round_robin_assigns_sequentially() {
        let policy = RoundRobinPolicy;
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut occupied = HashSet::new();

        assert_eq!(policy.assign(ip, &occupied, 3), Some(0));
        occupied.insert(0);
        assert_eq!(policy.assign(ip, &occupied, 3), Some(1));
        occupied.insert(1);
        assert_eq!(policy.assign(ip, &occupied, 3), Some(2));
        occupied.insert(2);
        assert_eq!(policy.assign(ip, &occupied, 3), None);
    }

    #[test]
    fn handoff_mesh_tracks_ownership() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mesh, _rxs) = HandoffMesh::new(3, RoundRobinPolicy);
            let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

            let mut m = mesh.lock().await;
            assert_eq!(m.assign(ip), Some(0));
            m.register(ip, 0);
            assert_eq!(m.assign(ip), Some(1));
            m.register(ip, 1);
            assert_eq!(m.assign(ip), Some(2));
            m.register(ip, 2);
            assert_eq!(m.assign(ip), None);
        });
    }
}
