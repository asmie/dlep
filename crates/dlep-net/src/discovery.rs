//! UDP multicast discovery socket.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use dlep_core::Signal;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;

use crate::framed::SignalCodec;
use crate::gtsm;

/// Parameters needed to bring up the discovery socket. Lives here (rather
/// than reaching into `dlep-daemon::NetworkConfig`) to keep `dlep-net`
/// config-free.
#[derive(Clone, Debug)]
pub struct DiscoveryParams {
    /// Multicast group to join.
    pub group_v4: Ipv4Addr,
    /// Local IPv4 address of the interface on which to join. Use
    /// `127.0.0.1` for loopback tests; `0.0.0.0` lets the kernel pick the
    /// default route.
    pub interface_v4: Ipv4Addr,
    /// UDP port to bind for both send and receive.
    pub port: u16,
    /// Whether the sender's own packets should loop back to its receive
    /// queue. Required for the loopback integration test where one host
    /// runs both router and modem; ignored in normal multi-host deployments.
    pub multicast_loop: bool,
}

#[derive(Debug)]
pub struct DiscoverySocket {
    fd: AsyncFd<OwnedFd>,
    group_v4: Ipv4Addr,
    port: u16,
    codec: SignalCodec,
}

impl DiscoverySocket {
    /// Bind and join the IPv4 multicast group described by `params`.
    pub fn bind(params: &DiscoveryParams) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        // SO_REUSEPORT is needed on some Linux distros to let two sockets
        // share the same (addr, port) for multicast group membership in
        // the same process (the loopback test pattern). Cheap to set
        // unconditionally; on platforms where it's not supported,
        // `socket2` returns an error which we propagate so the test
        // surfaces the limitation cleanly.
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        gtsm::set_send_ttl(&sock, false)?;
        gtsm::enable_recv_ttl(&sock, false)?;
        sock.set_multicast_loop_v4(params.multicast_loop)?;
        let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, params.port).into();
        sock.bind(&bind_addr.into())?;
        sock.join_multicast_v4(&params.group_v4, &params.interface_v4)?;
        let raw = sock.into_raw_fd();
        // Safety: `raw` came from `socket2::Socket` which uniquely owned the
        // descriptor; `into_raw_fd` consumed the Socket, so `OwnedFd::from_raw_fd`
        // takes ownership cleanly.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd: AsyncFd::new(owned)?,
            group_v4: params.group_v4,
            port: params.port,
            codec: SignalCodec,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    pub fn raw_fd(&self) -> i32 {
        self.fd.get_ref().as_raw_fd()
    }

    pub(crate) fn fd(&self) -> &AsyncFd<OwnedFd> {
        &self.fd
    }

    pub(crate) fn codec(&self) -> &SignalCodec {
        &self.codec
    }

    pub(crate) fn group_v4(&self) -> Ipv4Addr {
        self.group_v4
    }

    /// Send a signal to the configured multicast group. **Stub** —
    /// real implementation lands in Task 6.
    pub async fn send_to_group(&self, _signal: &Signal) -> io::Result<()> {
        Err(io::Error::other(
            "DiscoverySocket::send_to_group not yet implemented (Task 6)",
        ))
    }

    /// Receive a single signal with its source address and TTL. **Stub** —
    /// real implementation lands in Task 6.
    pub async fn recv(&self) -> io::Result<(Signal, SocketAddr, u8)> {
        Err(io::Error::other(
            "DiscoverySocket::recv not yet implemented (Task 6)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_params(port: u16) -> DiscoveryParams {
        DiscoveryParams {
            group_v4: Ipv4Addr::new(224, 0, 0, 117),
            interface_v4: Ipv4Addr::LOCALHOST,
            port,
            multicast_loop: true,
        }
    }

    #[tokio::test]
    async fn bind_succeeds_on_loopback() {
        let _sock =
            DiscoverySocket::bind(&loopback_params(0)).expect("bind should succeed on loopback");
    }

    #[tokio::test]
    async fn two_sockets_can_share_group() {
        // SO_REUSEADDR + SO_REUSEPORT + same multicast group → both join.
        // This is the configuration used by the loopback integration test
        // (router and modem both bind the group).
        let params = loopback_params(0);
        let a = DiscoverySocket::bind(&params).unwrap();
        let b = DiscoverySocket::bind(&params).unwrap();
        assert_eq!(a.local_port(), 0);
        assert_eq!(b.local_port(), 0);
    }
}
