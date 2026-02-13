//! Safe conversion between Rust `SocketAddr` and libc sockaddr types.
//!
//! Handles both IPv4 (`sockaddr_in`) and IPv6 (`sockaddr_in6`), which is
//! required for Yggdrasil overlay addresses (`200::/7`).

use std::mem;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;

use crate::Error;

/// Convert a Rust `SocketAddr::V4` to a C `sockaddr_in`.
pub fn to_sockaddr_in(addr: &SocketAddr) -> Result<libc::sockaddr_in, Error> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            Ok(sa)
        }
        SocketAddr::V6(_) => Err(Error::AddressFamily {
            expected: "IPv4",
            got: "IPv6",
        }),
    }
}

/// Convert a Rust `SocketAddr::V6` to a C `sockaddr_in6`.
pub fn to_sockaddr_in6(addr: &SocketAddr) -> Result<libc::sockaddr_in6, Error> {
    match addr {
        SocketAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            sa.sin6_scope_id = v6.scope_id();
            Ok(sa)
        }
        SocketAddr::V4(_) => Err(Error::AddressFamily {
            expected: "IPv6",
            got: "IPv4",
        }),
    }
}

/// Bind a raw fd to a `SocketAddr`, dispatching to v4 or v6.
pub fn bind_raw(fd: RawFd, addr: &SocketAddr) -> Result<(), Error> {
    let ret = match addr {
        SocketAddr::V4(_) => {
            let sa = to_sockaddr_in(addr)?;
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(_) => {
            let sa = to_sockaddr_in6(addr)?;
            unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret < 0 {
        Err(Error::Io(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Connect a raw fd to a `SocketAddr`, dispatching to v4 or v6.
/// In TCP_REPAIR mode, connect() sets the 4-tuple without sending SYN.
pub fn connect_raw(fd: RawFd, addr: &SocketAddr) -> Result<(), Error> {
    let ret = match addr {
        SocketAddr::V4(_) => {
            let sa = to_sockaddr_in(addr)?;
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(_) => {
            let sa = to_sockaddr_in6(addr)?;
            unsafe {
                libc::connect(
                    fd,
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };
    if ret < 0 {
        Err(Error::Io(std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn ipv4_roundtrip() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 42105));
        let sa = to_sockaddr_in(&addr).unwrap();
        assert_eq!(sa.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(u16::from_be(sa.sin_port), 42105);
        let ip_bytes = sa.sin_addr.s_addr.to_ne_bytes();
        assert_eq!(ip_bytes, [127, 0, 0, 1]);
    }

    #[test]
    fn ipv6_roundtrip() {
        // Yggdrasil-style address
        let ip = Ipv6Addr::new(0x0200, 0, 0, 0, 0, 0, 0, 1);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 6667, 0, 0));
        let sa = to_sockaddr_in6(&addr).unwrap();
        assert_eq!(sa.sin6_family, libc::AF_INET6 as libc::sa_family_t);
        assert_eq!(u16::from_be(sa.sin6_port), 6667);
        assert_eq!(sa.sin6_addr.s6_addr, ip.octets());
    }

    #[test]
    fn wrong_family_v4_to_v6() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80));
        assert!(to_sockaddr_in6(&addr).is_err());
    }

    #[test]
    fn wrong_family_v6_to_v4() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0));
        assert!(to_sockaddr_in(&addr).is_err());
    }
}
