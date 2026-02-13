mod ffi;

use std::ffi::{CStr, CString};
use std::io;
use std::net::Ipv6Addr;
use std::os::fd::FromRawFd;
use std::pin::Pin;
use std::task::{Context, Poll};

use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;

#[derive(Debug, thiserror::Error)]
pub enum YggError {
    #[error("yggdrasil init failed")]
    InitFailed,
    #[error("dial failed: {0}")]
    DialFailed(String),
    #[error("listen failed")]
    ListenFailed,
    #[error("accept failed")]
    AcceptFailed,
    #[error("peer operation failed")]
    PeerFailed,
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

/// An embedded Yggdrasil node with a gVisor TCP/IP stack.
pub struct YggNode {
    handle: usize,
}

/// A listener accepting TCP connections over the Yggdrasil overlay.
pub struct YggListener {
    handle: usize,
}

/// A TCP stream over the Yggdrasil overlay, backed by a Unix socketpair.
pub struct YggStream {
    inner: UnixStream,
}

#[derive(Debug, Clone, Deserialize)]
pub struct YggPeerInfo {
    pub uri: String,
    pub key: String,
    pub up: bool,
    pub inbound: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub latency_ms: f64,
    pub uptime: f64,
    pub priority: u8,
}

// ── Helper: read a C string from Go, free it ────────────────────────

unsafe fn go_string(ptr: *mut std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned();
    unsafe { ffi::ygg_free(ptr) };
    Some(s)
}

// ── YggNode ─────────────────────────────────────────────────────────

impl YggNode {
    /// Start a new embedded Yggdrasil node.
    ///
    /// - `private_key`: 64-byte Ed25519 private key
    /// - `peers`: peer URIs like `["tcp://host:9443"]`
    /// - `listen_addrs`: listen URIs like `["tcp://[::]:9443"]`
    pub fn new(
        private_key: &[u8; 64],
        peers: &[String],
        listen_addrs: &[String],
    ) -> Result<Self, YggError> {
        let key_hex = hex::encode(private_key);
        let key_c = CString::new(key_hex).unwrap();
        let peers_json = serde_json::to_string(peers).unwrap();
        let peers_c = CString::new(peers_json).unwrap();
        let listen_json = serde_json::to_string(listen_addrs).unwrap();
        let listen_c = CString::new(listen_json).unwrap();

        let handle =
            unsafe { ffi::ygg_init(key_c.as_ptr(), peers_c.as_ptr(), listen_c.as_ptr()) };

        if handle == 0 {
            return Err(YggError::InitFailed);
        }

        Ok(Self { handle })
    }

    /// The node's Yggdrasil IPv6 address.
    pub fn address(&self) -> Ipv6Addr {
        let s = unsafe { go_string(ffi::ygg_address(self.handle)) };
        s.and_then(|s| s.parse().ok())
            .unwrap_or(Ipv6Addr::UNSPECIFIED)
    }

    /// The node's Ed25519 public key as hex.
    pub fn public_key_hex(&self) -> String {
        unsafe { go_string(ffi::ygg_public_key(self.handle)) }.unwrap_or_default()
    }

    /// Connected Yggdrasil peers.
    pub fn peers(&self) -> Vec<YggPeerInfo> {
        let json = unsafe { go_string(ffi::ygg_peers_json(self.handle)) };
        json.and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Add a persistent peer.
    pub fn add_peer(&self, uri: &str) -> Result<(), YggError> {
        let uri_c = CString::new(uri).unwrap();
        let rc = unsafe { ffi::ygg_add_peer(self.handle, uri_c.as_ptr()) };
        if rc < 0 {
            Err(YggError::PeerFailed)
        } else {
            Ok(())
        }
    }

    /// Remove a peer.
    pub fn remove_peer(&self, uri: &str) -> Result<(), YggError> {
        let uri_c = CString::new(uri).unwrap();
        let rc = unsafe { ffi::ygg_remove_peer(self.handle, uri_c.as_ptr()) };
        if rc < 0 {
            Err(YggError::PeerFailed)
        } else {
            Ok(())
        }
    }

    /// Listen for inbound TCP connections on the given Ygg overlay port.
    pub fn listen(&self, port: u16) -> Result<YggListener, YggError> {
        let handle = unsafe { ffi::ygg_listen(self.handle, port as i32) };
        if handle == 0 {
            return Err(YggError::ListenFailed);
        }
        Ok(YggListener { handle })
    }

    /// Dial a remote Yggdrasil address over TCP.
    pub async fn dial(&self, addr: Ipv6Addr, port: u16) -> Result<YggStream, YggError> {
        let handle = self.handle;
        let addr_str = addr.to_string();

        let (fd, err_msg) = tokio::task::spawn_blocking(move || {
            let addr_c = CString::new(addr_str).unwrap();
            let mut err_buf = [0u8; 512];
            let fd = unsafe {
                ffi::ygg_dial(
                    handle,
                    addr_c.as_ptr(),
                    port as i32,
                    err_buf.as_mut_ptr() as *mut std::os::raw::c_char,
                    err_buf.len() as i32,
                )
            };

            let err_msg = if fd < 0 {
                let end = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
                Some(String::from_utf8_lossy(&err_buf[..end]).into_owned())
            } else {
                None
            };

            (fd, err_msg)
        })
        .await
        .map_err(|e| YggError::Io(io::Error::other(e)))?;

        if let Some(msg) = err_msg {
            return Err(YggError::DialFailed(msg));
        }

        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let inner = UnixStream::from_std(std_stream)?;

        Ok(YggStream { inner })
    }
}

impl Drop for YggNode {
    fn drop(&mut self) {
        unsafe { ffi::ygg_shutdown(self.handle) };
    }
}

// ── YggListener ─────────────────────────────────────────────────────

impl YggListener {
    /// Accept a connection. Blocks on a tokio blocking thread.
    pub async fn accept(&self) -> Result<(YggStream, Ipv6Addr), YggError> {
        let handle = self.handle;

        let (fd, remote) = tokio::task::spawn_blocking(move || {
            let mut remote_buf = [0u8; 128];
            let fd = unsafe {
                ffi::ygg_accept(
                    handle,
                    remote_buf.as_mut_ptr() as *mut std::os::raw::c_char,
                    remote_buf.len() as i32,
                )
            };

            if fd < 0 {
                return Err(YggError::AcceptFailed);
            }

            let end = remote_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(remote_buf.len());
            let remote_str = String::from_utf8_lossy(&remote_buf[..end]).into_owned();
            let remote_addr = remote_str.parse().unwrap_or(Ipv6Addr::UNSPECIFIED);

            Ok((fd, remote_addr))
        })
        .await
        .map_err(|e| YggError::Io(io::Error::other(e)))??;

        let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
        std_stream.set_nonblocking(true)?;
        let inner = UnixStream::from_std(std_stream)?;

        Ok((YggStream { inner }, remote))
    }
}

// ── YggStream: AsyncRead + AsyncWrite ───────────────────────────────

impl AsyncRead for YggStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for YggStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// Send + Sync are safe because YggStream is just a UnixStream wrapper.
unsafe impl Send for YggStream {}
unsafe impl Sync for YggStream {}
