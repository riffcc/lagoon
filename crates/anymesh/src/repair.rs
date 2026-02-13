//! TCP_REPAIR socket migration engine.
//!
//! Freeze a live TCP connection, extract its complete state (sequence numbers,
//! window parameters), and restore it on another process or machine. The client
//! sees zero disruption: same 4-tuple, same sequence numbers, no RST/FIN.
//!
//! Requires `CAP_NET_ADMIN` (typically root). Use [`check_tcp_repair`] to probe
//! at runtime.

use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

use serde::{Deserialize, Serialize};

use crate::sockaddr;
use crate::Error;

// TCP_REPAIR constants (from linux/tcp.h).
const SOL_TCP: libc::c_int = 6;
const TCP_REPAIR: libc::c_int = 19;
const TCP_REPAIR_QUEUE: libc::c_int = 20;
const TCP_QUEUE_SEQ: libc::c_int = 21;
const TCP_REPAIR_WINDOW: libc::c_int = 29;

const TCP_NO_QUEUE: libc::c_int = 0;
const TCP_RECV_QUEUE: libc::c_int = 1;
const TCP_SEND_QUEUE: libc::c_int = 2;

/// TCP window parameters extracted from a frozen socket.
///
/// `#[repr(C)]` for direct kernel interface via `setsockopt`/`getsockopt`.
/// Serde serialization is field-by-field (endian-safe across architectures).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(C)]
pub struct TcpRepairWindow {
    pub snd_wl1: u32,
    pub snd_wnd: u32,
    pub max_window: u32,
    pub rcv_wnd: u32,
    pub rcv_wup: u32,
}

impl Default for TcpRepairWindow {
    fn default() -> Self {
        Self {
            snd_wl1: 0,
            snd_wnd: 0,
            max_window: 0,
            rcv_wnd: 0,
            rcv_wup: 0,
        }
    }
}

/// Complete TCP socket state for cross-machine migration.
///
/// Serialize with bincode for wire transport (~40 bytes, compact binary),
/// or serde_json for debugging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SocketMigration {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub send_seq: u32,
    pub recv_seq: u32,
    pub window: TcpRepairWindow,
}

// ---------------------------------------------------------------------------
// Low-level sockopt helpers
// ---------------------------------------------------------------------------

fn tcp_setsockopt<T>(fd: RawFd, opt: libc::c_int, val: &T) -> std::io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_TCP,
            opt,
            val as *const T as *const libc::c_void,
            mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn tcp_getsockopt<T: Default>(fd: RawFd, opt: libc::c_int) -> std::io::Result<T> {
    let mut val = T::default();
    let mut len = mem::size_of::<T>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_TCP,
            opt,
            &mut val as *mut T as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(val)
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Probe whether TCP_REPAIR is available on this system.
///
/// Creates a test socket and attempts to enter repair mode. Returns `true`
/// if the kernel supports it and we have `CAP_NET_ADMIN`.
pub fn check_tcp_repair() -> bool {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return false;
    }
    let one: libc::c_int = 1;
    let ok = tcp_setsockopt(fd, TCP_REPAIR, &one).is_ok();
    if ok {
        let zero: libc::c_int = 0;
        let _ = tcp_setsockopt(fd, TCP_REPAIR, &zero);
    }
    unsafe { libc::close(fd) };
    ok
}

/// Freeze a live TCP connection and extract its state.
///
/// After freeze(), the socket is in repair mode. The caller should either:
/// - Call `restore()` to recreate the connection elsewhere, OR
/// - Close the fd (in repair mode, close sends no RST/FIN)
///
/// # Errors
///
/// Returns [`Error::CapabilityUnavailable`] if TCP_REPAIR is not available.
/// Returns [`Error::Freeze`] if any sockopt operation fails.
pub fn freeze(stream: &std::net::TcpStream) -> Result<SocketMigration, Error> {
    let fd = stream.as_raw_fd();
    let local_addr = stream.local_addr().map_err(Error::Freeze)?;
    let remote_addr = stream.peer_addr().map_err(Error::Freeze)?;

    // Enter repair mode — freezes TCP state machine.
    let one: libc::c_int = 1;
    tcp_setsockopt(fd, TCP_REPAIR, &one).map_err(|e| {
        if e.raw_os_error() == Some(libc::EPERM) {
            Error::CapabilityUnavailable
        } else {
            Error::Freeze(e)
        }
    })?;

    // Read send sequence number.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_SEND_QUEUE).map_err(Error::Freeze)?;
    let send_seq: u32 = tcp_getsockopt(fd, TCP_QUEUE_SEQ).map_err(Error::Freeze)?;

    // Read recv sequence number.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_RECV_QUEUE).map_err(Error::Freeze)?;
    let recv_seq: u32 = tcp_getsockopt(fd, TCP_QUEUE_SEQ).map_err(Error::Freeze)?;

    // Read window parameters.
    let window: TcpRepairWindow = tcp_getsockopt(fd, TCP_REPAIR_WINDOW).map_err(Error::Freeze)?;

    // Reset to no queue.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_NO_QUEUE).map_err(Error::Freeze)?;

    Ok(SocketMigration {
        local_addr,
        remote_addr,
        send_seq,
        recv_seq,
        window,
    })
}

/// Recreate a TCP connection from frozen state.
///
/// Returns a live `std::net::TcpStream` connected to the original remote,
/// with the original 4-tuple intact. The caller should:
/// 1. Call `set_nonblocking(true)` if needed
/// 2. Convert to `tokio::net::TcpStream::from_std()` for async usage
///
/// # Errors
///
/// Returns [`Error::CapabilityUnavailable`] if TCP_REPAIR is not available.
/// Returns [`Error::Restore`] if any operation fails.
pub fn restore(state: &SocketMigration) -> Result<std::net::TcpStream, Error> {
    let af = match state.local_addr {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };

    let fd = unsafe { libc::socket(af, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(Error::Restore(std::io::Error::last_os_error()));
    }

    // SO_REUSEADDR + SO_REUSEPORT so we can bind to the same port.
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Enter repair mode BEFORE bind/connect.
    tcp_setsockopt(fd, TCP_REPAIR, &one).map_err(|e| {
        unsafe { libc::close(fd) };
        if e.raw_os_error() == Some(libc::EPERM) {
            Error::CapabilityUnavailable
        } else {
            Error::Restore(e)
        }
    })?;

    // Helper: clean up fd on error after entering repair mode.
    let cleanup = |e: std::io::Error| -> Error {
        let zero: libc::c_int = 0;
        let _ = tcp_setsockopt(fd, TCP_REPAIR, &zero);
        unsafe { libc::close(fd) };
        Error::Restore(e)
    };

    // Set send sequence.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_SEND_QUEUE).map_err(|e| cleanup(e))?;
    tcp_setsockopt(fd, TCP_QUEUE_SEQ, &state.send_seq).map_err(|e| cleanup(e))?;

    // Set recv sequence.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_RECV_QUEUE).map_err(|e| cleanup(e))?;
    tcp_setsockopt(fd, TCP_QUEUE_SEQ, &state.recv_seq).map_err(|e| cleanup(e))?;

    // Set window.
    tcp_setsockopt(fd, TCP_REPAIR_WINDOW, &state.window).map_err(|e| cleanup(e))?;

    // Reset to no queue.
    tcp_setsockopt(fd, TCP_REPAIR_QUEUE, &TCP_NO_QUEUE).map_err(|e| cleanup(e))?;

    // Bind to the original local address.
    sockaddr::bind_raw(fd, &state.local_addr).map_err(|_| {
        let zero: libc::c_int = 0;
        let _ = tcp_setsockopt(fd, TCP_REPAIR, &zero);
        unsafe { libc::close(fd) };
        Error::Restore(std::io::Error::last_os_error())
    })?;

    // Connect to the original remote address.
    // In repair mode, connect() sets the 4-tuple without sending SYN.
    sockaddr::connect_raw(fd, &state.remote_addr).map_err(|_| {
        let zero: libc::c_int = 0;
        let _ = tcp_setsockopt(fd, TCP_REPAIR, &zero);
        unsafe { libc::close(fd) };
        Error::Restore(std::io::Error::last_os_error())
    })?;

    // Exit repair mode — connection is now live.
    let zero: libc::c_int = 0;
    tcp_setsockopt(fd, TCP_REPAIR, &zero).map_err(|e| {
        unsafe { libc::close(fd) };
        Error::Restore(e)
    })?;

    let stream = unsafe { std::net::TcpStream::from_raw_fd(fd) };
    Ok(stream)
}

/// Close a socket while in TCP_REPAIR mode (no RST/FIN sent).
///
/// This consumes the stream. The fd is closed silently — the remote side
/// will not be notified of the disconnection.
pub fn close_silent(stream: std::net::TcpStream) {
    let fd = stream.into_raw_fd();
    unsafe { libc::close(fd) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn socket_migration_bincode_roundtrip() {
        let state = SocketMigration {
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 42105)),
            remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 7, 1, 37), 60000)),
            send_seq: 1776391221,
            recv_seq: 3081153519,
            window: TcpRepairWindow {
                snd_wl1: 100,
                snd_wnd: 65536,
                max_window: 65536,
                rcv_wnd: 65536,
                rcv_wup: 200,
            },
        };

        let bytes = bincode::serialize(&state).unwrap();
        let restored: SocketMigration = bincode::deserialize(&bytes).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn socket_migration_ipv6_bincode_roundtrip() {
        let state = SocketMigration {
            local_addr: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1),
                42105,
                0,
                0,
            )),
            remote_addr: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x0200, 0, 0, 0, 0xabcd, 0, 0, 2),
                6667,
                0,
                0,
            )),
            send_seq: 42,
            recv_seq: 99,
            window: TcpRepairWindow::default(),
        };

        let bytes = bincode::serialize(&state).unwrap();
        let restored: SocketMigration = bincode::deserialize(&bytes).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn socket_migration_json_roundtrip() {
        let state = SocketMigration {
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080)),
            remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 443)),
            send_seq: 0,
            recv_seq: 0,
            window: TcpRepairWindow::default(),
        };

        let json = serde_json::to_string(&state).unwrap();
        let restored: SocketMigration = serde_json::from_str(&json).unwrap();
        assert_eq!(state, restored);
    }

    #[test]
    fn bincode_size_is_compact() {
        let state = SocketMigration {
            local_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42105)),
            remote_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 60000)),
            send_seq: u32::MAX,
            recv_seq: u32::MAX,
            window: TcpRepairWindow {
                snd_wl1: u32::MAX,
                snd_wnd: u32::MAX,
                max_window: u32::MAX,
                rcv_wnd: u32::MAX,
                rcv_wup: u32::MAX,
            },
        };

        let bytes = bincode::serialize(&state).unwrap();
        // SocketAddr encoding: 4 (enum tag) + 4 (ip) + 2 (port) = ~10 per addr
        // Two addrs + 2 u32s + 5 u32s = ~48-60 bytes (bincode adds enum tags)
        assert!(bytes.len() < 100, "bincode too large: {} bytes", bytes.len());
    }

    #[test]
    fn check_tcp_repair_returns_bool() {
        // Just verify it doesn't panic. Result depends on capabilities.
        let _result = check_tcp_repair();
    }

    #[test]
    fn tcp_repair_window_default_is_zeroed() {
        let w = TcpRepairWindow::default();
        assert_eq!(w.snd_wl1, 0);
        assert_eq!(w.snd_wnd, 0);
        assert_eq!(w.max_window, 0);
        assert_eq!(w.rcv_wnd, 0);
        assert_eq!(w.rcv_wup, 0);
    }
}
