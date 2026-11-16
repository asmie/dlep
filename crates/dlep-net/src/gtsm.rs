//! Generalized TTL Security Mechanism (RFC 5082) helpers for DLEP.
//!
//! DLEP requires outbound discovery packets to have TTL=255 and inbound
//! packets with a lower TTL to be dropped. This module hosts the
//! setsockopt wiring (IP_TTL / IP_MULTICAST_TTL / IPV6_UNICAST_HOPS /
//! IPV6_MULTICAST_HOPS) used at socket creation time, and a one-line
//! TTL validator used by the recvmsg path.

use std::io;
use std::os::fd::AsFd;

use socket2::Socket;

/// Threshold TTL/HopLimit: packets with a lower value must be dropped.
pub const REQUIRED_TTL: u8 = 255;

/// Check platform support without opening sockets or checking privileges.
/// Opting out only disables TCP receive enforcement; discovery stays strict.
pub fn validate_tcp_enforcement(enforce: bool) -> io::Result<()> {
    if enforce && !cfg!(target_os = "linux") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "strict TCP GTSM requires Linux; set network.gtsm_enforce = false to opt out explicitly",
        ));
    }
    Ok(())
}

/// Configure TCP before connect/listen, including the SYN/SYN-ACK. Linux
/// rejects segments below the minimum in the kernel, before delivery to TCP.
/// The transport's privileged packet monitor resets established connections
/// on rejected segments, because the TCP stream API does not report them.
pub fn configure_tcp<F: std::os::fd::AsFd>(sock: &F, is_v6: bool, enforce: bool) -> io::Result<()> {
    validate_tcp_enforcement(enforce)?;
    let socket = socket2::SockRef::from(sock);
    if is_v6 {
        socket.set_unicast_hops_v6(REQUIRED_TTL.into())?;
        // A dual-stack listener also sends IPv4 SYN-ACKs. Darwin copies the
        // IPv6 hop option into the mapped IPv4 TTL; setting IP_TTL on an IPv6
        // socket there fails with EINVAL. Linux needs both options.
        #[cfg(not(target_os = "macos"))]
        socket.set_ttl(REQUIRED_TTL.into())?;
    } else {
        socket.set_ttl(REQUIRED_TTL.into())?;
    }
    if enforce {
        set_minimum_ttl(sock, is_v6)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_minimum_ttl<F: std::os::fd::AsFd>(sock: &F, is_v6: bool) -> io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    let value = libc::c_int::from(REQUIRED_TTL);
    let (level, option) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_MINHOPCOUNT)
    } else {
        (libc::IPPROTO_IP, libc::IP_MINTTL)
    };
    // SAFETY: the borrowed fd remains live, and the option takes a pointer
    // to a c_int of the supplied size. setsockopt does not retain it.
    let result = unsafe {
        libc::setsockopt(
            sock.as_fd().as_raw_fd(),
            level,
            option,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // IPv4-mapped connections accepted by a dual-stack listener use IP_MINTTL.
    if is_v6 {
        set_minimum_ttl(sock, false)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_minimum_ttl<F: std::os::fd::AsFd>(_sock: &F, _is_v6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP minimum TTL enforcement requires Linux",
    ))
}

/// Set TTL/HopLimit = 255 on a freshly built `socket2::Socket`. Covers
/// unicast and multicast TTLs for both v4 and v6 sockets; the caller
/// passes whichever family the socket was created with.
pub fn set_send_ttl(sock: &Socket, is_v6: bool) -> io::Result<()> {
    if is_v6 {
        sock.set_unicast_hops_v6(u32::from(REQUIRED_TTL))?;
        sock.set_multicast_hops_v6(u32::from(REQUIRED_TTL))?;
    } else {
        sock.set_ttl(u32::from(REQUIRED_TTL))?;
        sock.set_multicast_ttl_v4(u32::from(REQUIRED_TTL))?;
    }
    Ok(())
}

/// Enable cmsg-based TTL reporting on receive. The recvmsg path can then
/// extract IP_TTL (v4) or IPV6_HOPLIMIT (v6) from ancillary data and
/// enforce `is_gtsm_valid`.
pub fn enable_recv_ttl<F: AsFd>(sock: &F, is_v6: bool) -> io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    let (level, option) = if is_v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVHOPLIMIT)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVTTL)
    };
    let enabled: libc::c_int = 1;
    // SAFETY: the borrowed descriptor stays live, and these options read a
    // c_int of the supplied size without retaining the pointer. nix does not
    // expose the receive-TTL options on macOS.
    let result = unsafe {
        libc::setsockopt(
            sock.as_fd().as_raw_fd(),
            level,
            option,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Verify an inbound TTL value meets the GTSM requirement.
pub const fn is_gtsm_valid(ttl: u8) -> bool {
    ttl == REQUIRED_TTL
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;

    #[test]
    fn set_send_ttl_v4_round_trips() {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        set_send_ttl(&sock, false).unwrap();
        sock.bind(&std::net::SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
            .unwrap();
    }

    #[test]
    fn set_send_ttl_v6_round_trips() {
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        set_send_ttl(&sock, true).unwrap();
        sock.bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 0)).into())
            .unwrap();
    }

    #[test]
    fn enable_recv_ttl_v4() {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        enable_recv_ttl(&sock, false).unwrap();
    }

    #[test]
    fn is_gtsm_valid_only_at_255() {
        assert!(is_gtsm_valid(255));
        assert!(!is_gtsm_valid(254));
        assert!(!is_gtsm_valid(0));
    }
}
