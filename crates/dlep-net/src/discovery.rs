//! UDP multicast discovery socket.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
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
    /// Preferred local IPv4 address for membership and sending. Use
    /// `127.0.0.1` for loopback tests; `0.0.0.0` selects an address on the
    /// named interface, or lets the kernel pick when no interface is named.
    pub interface_v4: Ipv4Addr,
    /// UDP port to bind. `0` lets the kernel pick an ephemeral source port,
    /// useful for router-side sockets that only send multicast and receive
    /// unicast Peer_Offer replies — picking ephemeral avoids colliding with
    /// the modem's well-known port in same-host loopback tests (where
    /// SO_REUSEPORT would otherwise hash unicast replies to the wrong
    /// socket).
    pub port: u16,
    /// Destination port used by `send_to_group`. Defaults to `port` for
    /// historical callers; an explicit value lets ephemeral-bound sockets
    /// still send to the canonical multicast port. `None` means "use
    /// `port`".
    pub group_port: Option<u16>,
    /// Whether the sender's own packets should loop back to its receive
    /// queue. Required for the loopback integration test where one host
    /// runs both router and modem; ignored in normal multi-host deployments.
    pub multicast_loop: bool,
    /// When `false`, skip `join_multicast_v4`. Router-side sockets that
    /// only need to send multicast (not receive it) can opt out, which
    /// keeps them out of the modem's SO_REUSEPORT group on the same host.
    pub join_group: bool,
}

/// IPv6 discovery parameters. Interface scope is resolved from the supplied
/// interface or concrete local address; a wildcard needs an explicit interface.
#[derive(Clone, Debug)]
pub struct DiscoveryParamsV6 {
    pub group: Ipv6Addr,
    pub local_address: Ipv6Addr,
    pub port: u16,
    pub group_port: Option<u16>,
    pub multicast_loop: bool,
    pub join_group: bool,
}

/// A decoded signal and the kernel metadata for this individual datagram.
/// The ingress interface is independent of the sender's address family:
/// IPv4 offers can advertise IPv6 link-local TCP endpoints.
#[derive(Debug)]
pub struct ReceivedSignal {
    pub signal: Signal,
    pub from: SocketAddr,
    pub ttl: u8,
    pub local_addr: IpAddr,
    pub interface_index: u32,
}

#[derive(Debug)]
pub struct DiscoverySocket {
    fd: AsyncFd<OwnedFd>,
    group: SocketAddr,
    /// The actual local bind port resolved at bind time (kernel-picked when
    /// `params.port == 0`).
    port: u16,
    codec: SignalCodec,
    interface: Option<crate::addr::Ipv4Interface>,
    interface_v6: Option<crate::addr::Ipv6Interface>,
}

impl DiscoverySocket {
    /// Bind and (optionally) join the IPv4 multicast group described by
    /// `params`.
    pub fn bind(params: &DiscoveryParams) -> io::Result<Self> {
        Self::bind_on_interface(params, &crate::addr::InterfaceSpec::Any)
    }

    /// Select multicast membership, egress, unicast reply source, and ingress
    /// by interface. No SO_BINDTODEVICE privilege is needed. A nonzero
    /// `interface_v4` must be assigned to that interface.
    pub fn bind_on_interface(
        params: &DiscoveryParams,
        spec: &crate::addr::InterfaceSpec,
    ) -> io::Result<Self> {
        let interface = spec.resolve_v4(params.interface_v4)?;
        let address = interface.map_or(params.interface_v4, |i| i.address);
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
        nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::Ipv4PacketInfo, &true)?;
        sock.set_multicast_loop_v4(params.multicast_loop)?;
        sock.set_multicast_if_v4(&address)?;
        // Linux otherwise also delivers multicast joined by other sockets.
        #[cfg(target_os = "linux")]
        sock.set_multicast_all_v4(false)?;
        let bind_addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, params.port).into();
        sock.bind(&bind_addr.into())?;
        if params.join_group {
            if let Some(interface) = interface {
                sock.join_multicast_v4_n(
                    &params.group_v4,
                    &socket2::InterfaceIndexOrAddress::Index(interface.index),
                )?;
            } else {
                sock.join_multicast_v4(&params.group_v4, &address)?;
            }
        }
        // If the caller asked for ephemeral (`port = 0`), resolve the
        // actual port the kernel assigned so subsequent unicast replies
        // can land on this socket.
        let resolved_port = match sock.local_addr()?.as_socket() {
            Some(SocketAddr::V4(v4)) => v4.port(),
            _ => params.port,
        };
        let raw = sock.into_raw_fd();
        // Safety: `raw` came from `socket2::Socket` which uniquely owned the
        // descriptor; `into_raw_fd` consumed the Socket, so `OwnedFd::from_raw_fd`
        // takes ownership cleanly.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd: AsyncFd::new(owned)?,
            group: (params.group_v4, params.group_port.unwrap_or(resolved_port)).into(),
            port: resolved_port,
            codec: SignalCodec,
            interface,
            interface_v6: None,
        })
    }

    /// Bind an IPv6-only discovery socket with explicit multicast scope.
    pub fn bind_v6(
        params: &DiscoveryParamsV6,
        spec: &crate::addr::InterfaceSpec,
    ) -> io::Result<Self> {
        let interface = spec.resolve_v6(params.local_address)?;
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_only_v6(true)?;
        sock.set_reuse_address(true)?;
        sock.set_reuse_port(true)?;
        sock.set_nonblocking(true)?;
        gtsm::set_send_ttl(&sock, true)?;
        gtsm::enable_recv_ttl(&sock, true)?;
        nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::Ipv6RecvPacketInfo, &true)?;
        sock.set_multicast_loop_v6(params.multicast_loop)?;
        sock.set_multicast_if_v6(interface.index)?;
        #[cfg(target_os = "linux")]
        sock.set_multicast_all_v6(false)?;
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, params.port)).into())?;
        if params.join_group {
            sock.join_multicast_v6(&params.group, interface.index)?;
        }
        let port = sock
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("missing IPv6 local address"))?
            .port();
        let owned: OwnedFd = sock.into();
        Ok(Self {
            fd: AsyncFd::new(owned)?,
            group: SocketAddrV6::new(
                params.group,
                params.group_port.unwrap_or(port),
                0,
                interface.index,
            )
            .into(),
            port,
            codec: SignalCodec,
            interface: None,
            interface_v6: Some(interface),
        })
    }

    /// Configured interface, if any. For the actual ingress interface of a
    /// datagram (including with no selected IPv4 interface), use `recv_with_metadata`.
    pub fn interface_index(&self) -> Option<u32> {
        self.interface
            .map(|i| i.index)
            .or_else(|| self.interface_v6.map(|i| i.index))
    }

    pub fn local_port(&self) -> u16 {
        self.port
    }

    /// Send a signal to the configured multicast group. Loops until the
    /// kernel accepts the datagram (handling `EAGAIN` via tokio's
    /// `AsyncFd::writable`). Errors propagate as `io::Error`; a short
    /// `sendto` (which UDP doesn't normally produce) is reported rather
    /// than silently truncated.
    pub async fn send_to_group(&self, signal: &Signal) -> io::Result<()> {
        self.send_unicast(signal, self.group).await
    }

    /// Send a signal to a specific unicast destination (used for modem
    /// Peer_Offer replies). Like `send_to_group`, but the destination
    /// address comes from the caller (typically the source address of an
    /// inbound Peer_Discovery).
    pub async fn send_unicast(&self, signal: &Signal, dest: SocketAddr) -> io::Result<()> {
        if dest.is_ipv6() != self.interface_v6.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "discovery destination address family mismatch",
            ));
        }
        let bytes = signal
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        send_datagram(&self.fd, &bytes, |fd, bytes| {
            use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
            let nix_addr = SockaddrStorage::from(dest);
            let info = self.interface.map(|i| nix::libc::in_pktinfo {
                ipi_ifindex: i.index as _,
                ipi_spec_dst: nix::libc::in_addr {
                    s_addr: u32::from_ne_bytes(i.address.octets()),
                },
                ipi_addr: nix::libc::in_addr { s_addr: 0 },
            });
            let info_v6 = self.interface_v6.map(|i| nix::libc::in6_pktinfo {
                ipi6_ifindex: i.index,
                ipi6_addr: nix::libc::in6_addr {
                    s6_addr: i.address.octets(),
                },
            });
            let controls: Vec<_> = info
                .as_ref()
                .map(ControlMessage::Ipv4PacketInfo)
                .into_iter()
                .chain(info_v6.as_ref().map(ControlMessage::Ipv6PacketInfo))
                .collect();
            sendmsg(
                fd.as_raw_fd(),
                &[std::io::IoSlice::new(bytes)],
                &controls,
                MsgFlags::empty(),
                Some(&nix_addr),
            )
            .map_err(io::Error::from)
        })
        .await
    }

    /// Receive a single signal with its source address and the
    /// kernel-reported IPv4 TTL or IPv6 hop limit. Packets with a value other
    /// than 255 are discarded before decoding. Missing ancillary data is an
    /// error; a missing TTL is never assumed valid.
    pub async fn recv(&self) -> io::Result<(Signal, SocketAddr, u8)> {
        let (signal, from, ttl, _) = self.recv_with_local().await?;
        Ok((signal, from, ttl))
    }

    /// Receive with a usable local unicast address for wildcard Peer Offers.
    /// IPv6 senders retain their link-local interface scope. Invalid TTL/hop
    /// limits are filtered before decoding. Malformed or truncated packets
    /// return `InvalidData`; callers may immediately receive the next packet.
    pub async fn recv_with_local(&self) -> io::Result<(Signal, SocketAddr, u8, IpAddr)> {
        let received = self.recv_with_metadata().await?;
        Ok((
            received.signal,
            received.from,
            received.ttl,
            received.local_addr,
        ))
    }

    /// Receive a signal with its usable local address and ingress interface.
    /// Interface filtering and TTL/hop-limit validation run before decoding.
    /// Missing packet metadata is an error, never an unspecified scope.
    pub async fn recv_with_metadata(&self) -> io::Result<ReceivedSignal> {
        use bytes::BytesMut;
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};

        // Bound discovery packet storage to one standard Ethernet MTU.
        // Reject MSG_TRUNC rather than decoding an incomplete datagram.
        // Hoisted above the retry loop so an EAGAIN spin doesn't re-allocate.
        // IP_TTL cmsg payload is `int` on Linux (`ControlMessageOwned::Ipv4Ttl(i32)`);
        // `i32` matches `libc::c_int` on every supported target, keeping
        // `dlep-net` free of an explicit `libc` dep.
        let mut payload = [0u8; 1500];
        let mut cmsg_space = nix::cmsg_space!(i32, nix::libc::in_pktinfo, nix::libc::in6_pktinfo);

        loop {
            let mut guard = self.fd.readable().await?;
            let outcome = guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let mut iov = [std::io::IoSliceMut::new(&mut payload)];
                let res = recvmsg::<SockaddrStorage>(
                    fd,
                    &mut iov,
                    Some(&mut cmsg_space),
                    MsgFlags::empty(),
                )
                .map_err(io::Error::from)?;
                if res
                    .flags
                    .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "truncated discovery datagram or ancillary data",
                    ));
                }
                let bytes_read = res.bytes;
                let mut from: SocketAddr = res
                    .address
                    .and_then(|a| {
                        a.as_sockaddr_in()
                            .map(|s| -> SocketAddr {
                                std::net::SocketAddrV4::new(s.ip(), s.port()).into()
                            })
                            .or_else(|| {
                                a.as_sockaddr_in6().map(|s| {
                                    SocketAddrV6::new(s.ip(), s.port(), s.flowinfo(), s.scope_id())
                                        .into()
                                })
                            })
                    })
                    .ok_or_else(|| io::Error::other("recvmsg without IP sender"))?;
                let mut ttl: Option<u8> = None;
                let mut local = None;
                let mut interface_index = None;
                for cmsg in res.cmsgs().map_err(io::Error::from)? {
                    if let ControlMessageOwned::Ipv4PacketInfo(info) = cmsg {
                        local = Some(IpAddr::V4(Ipv4Addr::from(
                            info.ipi_spec_dst.s_addr.to_ne_bytes(),
                        )));
                        interface_index = Some(info.ipi_ifindex as u32);
                    }
                    if let ControlMessageOwned::Ipv6PacketInfo(info) = cmsg {
                        interface_index = Some(info.ipi6_ifindex);
                        // IPv6 pktinfo reports the destination (often multicast),
                        // not a unicast local address as IPv4's ipi_spec_dst does.
                        local = self.interface_v6.map(|i| IpAddr::V6(i.address));
                        if let SocketAddr::V6(addr) = &mut from {
                            if addr.ip().is_unicast_link_local() {
                                addr.set_scope_id(info.ipi6_ifindex);
                            }
                        }
                    }
                    if let ControlMessageOwned::Ipv4Ttl(t) | ControlMessageOwned::Ipv6HopLimit(t) =
                        cmsg
                    {
                        // TTL is a single byte in the IP header; the kernel
                        // hands it back as `int` (0..=255), so the cast is
                        // lossless.
                        ttl = Some(t as u8);
                    }
                }
                Ok::<_, io::Error>((bytes_read, from, ttl, local, interface_index))
            });
            match outcome {
                Ok(Ok((bytes_read, from, ttl_opt, local, interface_index))) => {
                    // Missing metadata is a receive error, not evidence that
                    // this packet arrived on a different interface. Report it
                    // so the caller can apply its I/O error/backoff policy.
                    let interface_index =
                        interface_index.filter(|index| *index != 0).ok_or_else(|| {
                            io::Error::other("missing packet ingress interface index")
                        })?;
                    if self
                        .interface
                        .map(|i| i.index)
                        .or_else(|| self.interface_v6.map(|i| i.index))
                        .is_some_and(|index| index != interface_index)
                    {
                        // Filter before decode; unrelated interface traffic must
                        // not reach the discovery FSM, even when malformed.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    let ttl = ttl_opt.ok_or_else(|| {
                        io::Error::other("recvmsg returned no TTL/hop-limit control message")
                    })?;
                    if !gtsm::is_gtsm_valid(ttl) {
                        // Do not decode off-link traffic or let a perpetually
                        // readable socket monopolize the discovery task.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    let buf = BytesMut::from(&payload[..bytes_read]);
                    let signal = self
                        .codec
                        .decode_datagram(buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok(ReceivedSignal {
                        signal,
                        from,
                        ttl,
                        local_addr: local.ok_or_else(|| {
                            io::Error::other("missing packet interface information")
                        })?,
                        interface_index,
                    });
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

// Keep the readiness/retry policy separate from sendmsg so tests can exercise
// real backpressure and inject the short-write/error results UDP rarely emits.
async fn send_datagram(
    fd: &AsyncFd<OwnedFd>,
    bytes: &[u8],
    mut send: impl FnMut(&OwnedFd, &[u8]) -> io::Result<usize>,
) -> io::Result<()> {
    loop {
        let mut guard = fd.writable().await?;
        match guard.try_io(|inner| send(inner.get_ref(), bytes)) {
            Ok(Ok(n)) if n == bytes.len() => return Ok(()),
            Ok(Ok(n)) => {
                return Err(io::Error::other(format!(
                    "short sendto: {n}/{}",
                    bytes.len()
                )));
            }
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn datagram_pair() -> (AsyncFd<OwnedFd>, std::os::unix::net::UnixDatagram) {
        // Unix datagrams provide deterministic kernel backpressure on loopback;
        // UDP may drop packets instead of filling the sender's queue.
        let (sender, receiver) = std::os::unix::net::UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        socket2::SockRef::from(&sender)
            .set_send_buffer_size(4096)
            .unwrap();
        (AsyncFd::new(sender.into()).unwrap(), receiver)
    }

    async fn fill_datagram_queue(fd: &AsyncFd<OwnedFd>) -> usize {
        // Prime cached readiness, then fill the kernel queue without clearing
        // it. The next real send must hit EAGAIN inside AsyncFd::try_io.
        drop(
            tokio::time::timeout(std::time::Duration::from_secs(2), fd.writable())
                .await
                .unwrap()
                .unwrap(),
        );
        for queued in 0..1024 {
            match socket2::SockRef::from(fd.get_ref()).send(b"queued") {
                Ok(n) => assert_eq!(n, 6),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    assert!(queued > 0);
                    return queued;
                }
                Err(e) => panic!("filling datagram queue: {e}"),
            }
        }
        panic!("datagram queue did not fill within the test bound");
    }

    fn drain_datagram_queue(receiver: &std::os::unix::net::UnixDatagram, queued: usize) {
        let mut buf = [0; 128];
        for _ in 0..queued {
            let n = receiver.recv(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"queued");
        }
        assert_eq!(
            receiver.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }

    async fn blocked_datagram_send(cancel: bool) {
        use std::cell::Cell;
        use std::future::{Future, poll_fn};
        use std::task::Poll;
        use std::time::Duration;

        let (fd, receiver) = datagram_pair();
        let queued = fill_datagram_queue(&fd).await;
        let bytes = Signal::new(dlep_core::SignalType::PEER_DISCOVERY)
            .encode()
            .unwrap();
        let attempts = Cell::new(0);
        let mut send = Box::pin(send_datagram(&fd, &bytes, |fd, bytes| {
            attempts.set(attempts.get() + 1);
            socket2::SockRef::from(fd).send(bytes)
        }));
        // A full queue must suspend the future, not spin or report success.
        poll_fn(|cx| {
            assert!(send.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(attempts.get(), 1, "expected one failed kernel send");
        if cancel {
            drop(send);
            drain_datagram_queue(&receiver, queued);
            // Deliver readiness after cancellation; there is no detached retry.
            tokio::task::yield_now().await;
            assert_eq!(attempts.get(), 1);
            let mut buf = [0; 128];
            assert_eq!(
                receiver.recv(&mut buf).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            tokio::time::timeout(
                Duration::from_secs(2),
                send_datagram(&fd, &bytes, |fd, bytes| {
                    socket2::SockRef::from(fd).send(bytes)
                }),
            )
            .await
            .unwrap()
            .unwrap();
        } else {
            drain_datagram_queue(&receiver, queued);
            tokio::time::timeout(Duration::from_secs(2), send)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(attempts.get(), 2, "retry only after the queue is drained");
        }
        let mut buf = [0; 128];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &bytes[..], "one complete datagram");
        assert_eq!(
            receiver.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "must not send duplicates"
        );
    }

    #[tokio::test]
    async fn datagram_send_waits_for_writable_after_would_block() {
        blocked_datagram_send(false).await;
    }

    #[tokio::test]
    async fn cancelling_blocked_datagram_send_does_not_transmit() {
        blocked_datagram_send(true).await;
    }

    async fn rejected_datagram_send_recovers(result: io::Result<usize>) -> io::Error {
        use std::time::Duration;
        let (fd, receiver) = datagram_pair();
        let bytes = Signal::new(dlep_core::SignalType::PEER_DISCOVERY)
            .encode()
            .unwrap();
        let mut result = Some(result);
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            send_datagram(&fd, &bytes, |_, _| {
                result
                    .take()
                    .expect("must not retry short sends or I/O errors")
            }),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(result.is_none(), "must attempt the send");
        tokio::time::timeout(
            Duration::from_secs(2),
            send_datagram(&fd, &bytes, |fd, bytes| {
                socket2::SockRef::from(fd).send(bytes)
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let mut buf = [0; 128];
        let n = receiver.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &bytes[..]);
        assert_eq!(
            receiver.recv(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        error
    }

    #[tokio::test]
    async fn datagram_short_send_errors_do_not_retry() {
        let len = Signal::new(dlep_core::SignalType::PEER_DISCOVERY)
            .encode()
            .unwrap()
            .len();
        for sent in [0, len - 1] {
            let error = rejected_datagram_send_recovers(Ok(sent)).await;
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert!(error.to_string().contains("short sendto"));
        }
    }

    #[tokio::test]
    async fn datagram_send_syscall_errors_propagate_without_retry() {
        for errno in [nix::libc::EACCES, nix::libc::ENETUNREACH, nix::libc::EINTR] {
            let error =
                rejected_datagram_send_recovers(Err(io::Error::from_raw_os_error(errno))).await;
            assert_eq!(error.raw_os_error(), Some(errno));
        }
    }

    fn loopback_params(port: u16) -> DiscoveryParams {
        DiscoveryParams {
            group_v4: Ipv4Addr::new(224, 0, 0, 117),
            interface_v4: Ipv4Addr::LOCALHOST,
            port,
            group_port: None,
            multicast_loop: true,
            join_group: true,
        }
    }

    async fn udp_send_error_preserves_socket(ip: IpAddr) {
        use crate::addr::InterfaceSpec;
        use dlep_core::SignalType;
        use std::time::Duration;

        let socket = match ip {
            IpAddr::V4(_) => DiscoverySocket::bind(&loopback_params(0)).unwrap(),
            IpAddr::V6(local_address) => DiscoverySocket::bind_v6(
                &DiscoveryParamsV6 {
                    group: "ff02::1:7".parse().unwrap(),
                    local_address,
                    port: 0,
                    group_port: None,
                    multicast_loop: true,
                    join_group: false,
                },
                &InterfaceSpec::Any,
            )
            .unwrap(),
        };
        let signal = Signal::new(SignalType::PEER_DISCOVERY);
        // Linux rejects destination port zero in the real sendmsg syscall.
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            socket.send_unicast(&signal, SocketAddr::new(ip, 0)),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(nix::libc::EINVAL));
        let dest = SocketAddr::new(ip, socket.local_port());
        tokio::time::timeout(Duration::from_secs(2), socket.send_unicast(&signal, dest))
            .await
            .unwrap()
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), socket.recv_with_metadata())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.signal.signal_type, signal.signal_type);
        assert!(received.signal.data_items.is_empty());
        assert_eq!(received.from, dest);
        assert_eq!(received.local_addr, ip);
        assert_eq!(received.ttl, 255);
        assert_eq!(Some(received.interface_index), socket.interface_index());
    }

    #[tokio::test]
    async fn ipv4_send_error_preserves_socket_for_next_datagram() {
        udp_send_error_preserves_socket(Ipv4Addr::LOCALHOST.into()).await;
    }

    #[tokio::test]
    async fn ipv6_send_error_preserves_socket_for_next_datagram() {
        udp_send_error_preserves_socket(Ipv6Addr::LOCALHOST.into()).await;
    }

    #[derive(Clone, Copy)]
    enum MissingMetadata {
        Ttl,
        PacketInfo,
    }

    async fn missing_metadata_returns_error_and_receive_recovers(
        ip: IpAddr,
        selected_interface: bool,
        missing: MissingMetadata,
    ) {
        use crate::addr::InterfaceSpec;
        use dlep_core::SignalType;
        use nix::sys::socket::{setsockopt, sockopt};
        use std::time::Duration;

        let receiver = match ip {
            IpAddr::V4(_) => {
                let mut params = loopback_params(0);
                params.join_group = false;
                if !selected_interface {
                    params.interface_v4 = Ipv4Addr::UNSPECIFIED;
                }
                DiscoverySocket::bind(&params).unwrap()
            }
            IpAddr::V6(local_address) => DiscoverySocket::bind_v6(
                &DiscoveryParamsV6 {
                    group: "ff02::1:7".parse().unwrap(),
                    local_address,
                    port: 0,
                    group_port: None,
                    multicast_loop: true,
                    join_group: false,
                },
                &InterfaceSpec::Any,
            )
            .unwrap(),
        };
        let set_metadata = |enabled| {
            let fd = receiver.fd.get_ref();
            match (ip, missing) {
                (IpAddr::V4(_), MissingMetadata::Ttl) => {
                    setsockopt(fd, sockopt::Ipv4RecvTtl, &enabled)
                }
                (IpAddr::V6(_), MissingMetadata::Ttl) => {
                    setsockopt(fd, sockopt::Ipv6RecvHopLimit, &enabled)
                }
                (IpAddr::V4(_), MissingMetadata::PacketInfo) => {
                    setsockopt(fd, sockopt::Ipv4PacketInfo, &enabled)
                }
                (IpAddr::V6(_), MissingMetadata::PacketInfo) => {
                    setsockopt(fd, sockopt::Ipv6RecvPacketInfo, &enabled)
                }
            }
            .unwrap();
        };
        let sender = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let socket = socket2::SockRef::from(&sender);
        if ip.is_ipv6() {
            socket.set_unicast_hops_v6(255).unwrap();
        } else {
            socket.set_ttl(255).unwrap();
        }
        let dest = SocketAddr::new(ip, receiver.local_port());
        let valid = Signal::new(SignalType::PEER_DISCOVERY).encode().unwrap();

        set_metadata(false);
        sender.send_to(&valid, dest).unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), receiver.recv_with_metadata())
            .await
            .expect("missing metadata must return an error, not silently wait for another packet")
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        let expected = match missing {
            MissingMetadata::Ttl => "TTL/hop-limit",
            MissingMetadata::PacketInfo => "interface",
        };
        assert!(error.to_string().contains(expected), "{error}");

        // Restore the socket option, not the socket itself: an errored receive
        // must consume that datagram and leave subsequent packets usable.
        set_metadata(true);
        sender.send_to(&valid, dest).unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), receiver.recv_with_metadata())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.signal.signal_type, SignalType::PEER_DISCOVERY);
        assert_eq!(received.from, sender.local_addr().unwrap());
        assert_eq!(received.ttl, 255);
        assert_eq!(received.local_addr, ip);
        let loopback = InterfaceSpec::Any
            .resolve_v4(Ipv4Addr::LOCALHOST)
            .unwrap()
            .unwrap();
        assert_eq!(received.interface_index, loopback.index);
    }

    #[tokio::test]
    async fn ipv4_missing_ttl_returns_error_and_receive_recovers() {
        missing_metadata_returns_error_and_receive_recovers(
            Ipv4Addr::LOCALHOST.into(),
            true,
            MissingMetadata::Ttl,
        )
        .await;
    }

    #[tokio::test]
    async fn ipv6_missing_hop_limit_returns_error_and_receive_recovers() {
        missing_metadata_returns_error_and_receive_recovers(
            Ipv6Addr::LOCALHOST.into(),
            true,
            MissingMetadata::Ttl,
        )
        .await;
    }

    #[tokio::test]
    async fn ipv4_selected_interface_missing_packet_info_returns_error_and_receive_recovers() {
        missing_metadata_returns_error_and_receive_recovers(
            Ipv4Addr::LOCALHOST.into(),
            true,
            MissingMetadata::PacketInfo,
        )
        .await;
    }

    #[tokio::test]
    async fn ipv4_any_interface_missing_packet_info_returns_error_and_receive_recovers() {
        missing_metadata_returns_error_and_receive_recovers(
            Ipv4Addr::LOCALHOST.into(),
            false,
            MissingMetadata::PacketInfo,
        )
        .await;
    }

    #[tokio::test]
    async fn ipv6_missing_packet_info_returns_error_and_receive_recovers() {
        missing_metadata_returns_error_and_receive_recovers(
            Ipv6Addr::LOCALHOST.into(),
            true,
            MissingMetadata::PacketInfo,
        )
        .await;
    }

    async fn rejects_bad_packets_before_accepting_valid_signal(ip: IpAddr) {
        use crate::addr::InterfaceSpec;
        use dlep_core::{DataItem, SignalType};
        use std::time::Duration;
        let receiver = match ip {
            IpAddr::V4(_) => DiscoverySocket::bind(&loopback_params(0)).unwrap(),
            IpAddr::V6(local_address) => DiscoverySocket::bind_v6(
                &DiscoveryParamsV6 {
                    group: "ff02::1:7".parse().unwrap(),
                    local_address,
                    port: 0,
                    group_port: None,
                    multicast_loop: true,
                    join_group: false,
                },
                &InterfaceSpec::Any,
            )
            .unwrap(),
        };
        let sender = std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).unwrap();
        let dest = SocketAddr::new(ip, receiver.local_port());
        let set_hops = |hops| {
            let socket = socket2::SockRef::from(&sender);
            if ip.is_ipv6() {
                socket.set_unicast_hops_v6(hops).unwrap();
            } else {
                socket.set_ttl(hops).unwrap();
            }
        };
        let valid = Signal::new(SignalType::PEER_DISCOVERY).encode().unwrap();
        set_hops(254);
        // If decoding happens before GTSM, the first packet returns an error.
        sender.send_to(b"invalid signal", dest).unwrap();
        sender
            .send_to(&Signal::new(SignalType::PEER_OFFER).encode().unwrap(), dest)
            .unwrap();
        set_hops(255);
        sender.send_to(&valid, dest).unwrap();
        let (signal, _, hops) = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(signal.signal_type, SignalType::PEER_DISCOVERY);
        assert_eq!(hops, 255);

        // On-link malformed packets remain distinguishable from socket errors.
        sender.send_to(b"invalid signal", dest).unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A complete-looking prefix must not hide bytes truncated by recvmsg.
        let mut truncated = Signal::new(SignalType::PEER_DISCOVERY)
            .with_item(DataItem::PeerType {
                flags: Default::default(),
                description: "x".repeat(1487),
            })
            .encode()
            .unwrap()
            .to_vec();
        assert_eq!(truncated.len(), 1500);
        truncated.push(0);
        sender.send_to(&truncated, dest).unwrap();
        let err = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("truncated"));
        sender.send_to(&valid, dest).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap()
                .unwrap()
                .0
                .signal_type,
            SignalType::PEER_DISCOVERY
        );
    }

    #[tokio::test]
    async fn ipv4_filters_ttl_before_decode_and_rejects_truncation() {
        rejects_bad_packets_before_accepting_valid_signal(Ipv4Addr::LOCALHOST.into()).await;
    }

    #[tokio::test]
    async fn ipv6_filters_hop_limit_before_decode_and_rejects_truncation() {
        rejects_bad_packets_before_accepting_valid_signal(Ipv6Addr::LOCALHOST.into()).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn ipv6_multicast_and_unicast_keep_scope_source_and_hop_limit() {
        use crate::addr::InterfaceSpec;
        use dlep_core::SignalType;
        use std::time::Duration;
        let spec = InterfaceSpec::ByName("dlep-test".into());
        let iface = spec
            .resolve_v6(Ipv6Addr::UNSPECIFIED)
            .expect("test harness needs IPv6 on dlep-test");
        assert!(iface.address.is_unicast_link_local());
        let mut params = DiscoveryParamsV6 {
            group: "ff02::1:7".parse().unwrap(),
            local_address: Ipv6Addr::UNSPECIFIED,
            port: 0,
            group_port: None,
            multicast_loop: true,
            join_group: true,
        };
        let modem = DiscoverySocket::bind_v6(&params, &spec).unwrap();
        params.join_group = false;
        params.group_port = Some(modem.local_port());
        let router = DiscoverySocket::bind_v6(&params, &spec).unwrap();
        // IPv6 pktinfo must reject loopback ingress before decoding, even
        // though the wildcard UDP socket also receives that traffic.
        let unrelated = std::net::UdpSocket::bind("[::1]:0").unwrap();
        unrelated
            .send_to(b"malformed", (Ipv6Addr::LOCALHOST, modem.local_port()))
            .unwrap();
        let discovery = Signal::new(SignalType::PEER_DISCOVERY);
        router.send_to_group(&discovery).await.unwrap();
        let (sig, from, hops, local) =
            tokio::time::timeout(Duration::from_secs(2), modem.recv_with_local())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(sig.signal_type, discovery.signal_type);
        assert_eq!(hops, 255);
        assert_eq!(local, iface.address);
        assert_eq!(
            from,
            SocketAddrV6::new(iface.address, router.local_port(), 0, iface.index).into()
        );
        let offer = Signal::new(SignalType::PEER_OFFER);
        modem.send_unicast(&offer, from).await.unwrap();
        let (sig, from, hops, local) =
            tokio::time::timeout(Duration::from_secs(2), router.recv_with_local())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(sig.signal_type, offer.signal_type);
        assert_eq!(hops, 255);
        assert_eq!(local, iface.address);
        assert_eq!(
            from,
            SocketAddrV6::new(iface.address, modem.local_port(), 0, iface.index).into()
        );
        // A low-hop-limit signal is discarded before the valid one behind it.
        socket2::SockRef::from(router.fd.get_ref())
            .set_multicast_hops_v6(254)
            .unwrap();
        router.send_to_group(&offer).await.unwrap();
        socket2::SockRef::from(router.fd.get_ref())
            .set_multicast_hops_v6(255)
            .unwrap();
        router.send_to_group(&discovery).await.unwrap();
        let (signal, _, hops) = tokio::time::timeout(Duration::from_secs(2), modem.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(signal.signal_type, discovery.signal_type);
        assert_eq!(hops, 255);
        assert!(
            router
                .send_unicast(&discovery, "127.0.0.1:854".parse().unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn bind_succeeds_on_loopback() {
        let _sock =
            DiscoverySocket::bind(&loopback_params(0)).expect("bind should succeed on loopback");
    }

    #[tokio::test]
    async fn two_sockets_can_share_group() {
        // SO_REUSEADDR + SO_REUSEPORT + same multicast group → both join.
        // This is the legacy configuration used before M6's discovery
        // integration test split router (ephemeral, no group join) from
        // modem (well-known port, group join). Both binds succeed; the
        // resolved local ports come from the kernel-assigned ephemeral
        // pool when `port = 0`.
        let params = loopback_params(0);
        let a = DiscoverySocket::bind(&params).unwrap();
        let b = DiscoverySocket::bind(&params).unwrap();
        assert_ne!(a.local_port(), 0, "kernel must resolve ephemeral port");
        assert_ne!(b.local_port(), 0, "kernel must resolve ephemeral port");
    }

    #[tokio::test]
    async fn loopback_send_recv_with_ttl_255() {
        use std::time::Duration;

        use dlep_core::SignalType;

        // High port to minimise collisions.
        let port = 49_854_u16;
        // Exercise default-route selection; the explicit-interface tests below
        // cover loopback independently of the system's default multicast route.
        let params = DiscoveryParams {
            group_v4: Ipv4Addr::new(224, 0, 0, 117),
            interface_v4: Ipv4Addr::UNSPECIFIED,
            port,
            group_port: None,
            multicast_loop: true,
            join_group: true,
        };
        let sender = DiscoverySocket::bind(&params).unwrap();
        let receiver = DiscoverySocket::bind(&params).unwrap();

        let sig = Signal::new(SignalType::PEER_DISCOVERY);
        sender.send_to_group(&sig).await.unwrap();
        let (received, _from, ttl) = tokio::time::timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("recv timed out")
            .expect("recv failed");
        assert_eq!(received.signal_type, SignalType::PEER_DISCOVERY);
        assert_eq!(ttl, 255, "GTSM requires outbound TTL=255");
    }
    #[tokio::test]
    async fn selected_interface_controls_multicast_and_unicast_source() {
        use crate::addr::InterfaceSpec;
        use dlep_core::SignalType;
        let loopback = InterfaceSpec::Any
            .resolve_v4(Ipv4Addr::LOCALHOST)
            .unwrap()
            .unwrap();
        let name = nix::net::if_::if_indextoname(loopback.index).unwrap();
        let spec = InterfaceSpec::ByName(name.to_string_lossy().into_owned());
        let mut params = loopback_params(0);
        // The name alone must work with the default wildcard address.
        params.interface_v4 = Ipv4Addr::UNSPECIFIED;
        let modem = DiscoverySocket::bind_on_interface(&params, &spec).unwrap();
        params.join_group = false;
        params.group_port = Some(modem.local_port());
        let router = DiscoverySocket::bind_on_interface(&params, &spec).unwrap();
        router
            .send_to_group(&Signal::new(SignalType::PEER_DISCOVERY))
            .await
            .unwrap();
        let (_, from, ttl, local) =
            tokio::time::timeout(std::time::Duration::from_secs(2), modem.recv_with_local())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(local, Ipv4Addr::LOCALHOST);
        assert_eq!(ttl, 255);
        modem
            .send_unicast(&Signal::new(SignalType::PEER_OFFER), from)
            .await
            .unwrap();
        let (offer, from, ttl) =
            tokio::time::timeout(std::time::Duration::from_secs(2), router.recv())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(offer.signal_type, SignalType::PEER_OFFER);
        assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
        assert_eq!(ttl, 255);
    }

    #[tokio::test]
    async fn multicast_membership_is_isolated_between_interfaces() {
        use crate::addr::InterfaceSpec;
        use dlep_core::SignalType;
        use nix::net::if_::InterfaceFlags;
        use std::time::Duration;
        // The workspace network harness supplies a multicast-capable default
        // interface as well as loopback (also needed by the default-route test).
        let foreign = nix::ifaddrs::getifaddrs()
            .unwrap()
            .find(|i| {
                i.flags
                    .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_MULTICAST)
                    && !i.flags.contains(InterfaceFlags::IFF_LOOPBACK)
                    && i.address.is_some_and(|a| a.as_sockaddr_in().is_some())
            })
            .expect("network test harness needs a non-loopback IPv4 multicast interface");
        let foreign_spec = InterfaceSpec::ByName(foreign.interface_name);
        let mut params = loopback_params(0);
        let selected = DiscoverySocket::bind(&params).unwrap();
        params.port = selected.local_port();
        params.interface_v4 = Ipv4Addr::UNSPECIFIED;
        let other = DiscoverySocket::bind_on_interface(&params, &foreign_spec).unwrap();
        params.port = 0;
        params.group_port = Some(selected.local_port());
        params.join_group = false;
        let other_sender = DiscoverySocket::bind_on_interface(&params, &foreign_spec).unwrap();
        // Use a unique port so reuse-port hashing cannot deliver this unicast
        // to the other socket instead of exercising the packet-info filter.
        let filter_params = DiscoveryParams {
            port: 0,
            join_group: true,
            group_port: None,
            ..params.clone()
        };
        let filtered = DiscoverySocket::bind_on_interface(&filter_params, &foreign_spec).unwrap();
        let filter_sender = DiscoverySocket::bind_on_interface(
            &DiscoveryParams {
                group_port: Some(filtered.local_port()),
                join_group: false,
                ..filter_params
            },
            &foreign_spec,
        )
        .unwrap();
        let stray = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        stray.set_ttl(255).unwrap();
        let destination = (Ipv4Addr::LOCALHOST, filtered.local_port());
        stray
            .send_to(b"not a DLEP signal", destination)
            .await
            .unwrap();
        stray
            .send_to(
                &Signal::new(SignalType::PEER_OFFER).encode().unwrap(),
                destination,
            )
            .await
            .unwrap();
        filter_sender
            .send_to_group(&Signal::new(SignalType::PEER_DISCOVERY))
            .await
            .unwrap();
        let (received, from, _) = tokio::time::timeout(Duration::from_secs(2), filtered.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.signal_type, SignalType::PEER_DISCOVERY);
        assert!(!from.ip().is_loopback());
        other_sender
            .send_to_group(&Signal::new(SignalType::PEER_DISCOVERY))
            .await
            .unwrap();
        let (received, from, _) = tokio::time::timeout(Duration::from_secs(2), other.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.signal_type, SignalType::PEER_DISCOVERY);
        assert!(!from.ip().is_loopback());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), selected.recv())
                .await
                .is_err()
        );
        params.interface_v4 = Ipv4Addr::LOCALHOST;
        let sender = DiscoverySocket::bind(&params).unwrap();
        sender
            .send_to_group(&Signal::new(SignalType::PEER_DISCOVERY))
            .await
            .unwrap();
        let (_, from, _, _) =
            tokio::time::timeout(Duration::from_secs(2), selected.recv_with_local())
                .await
                .unwrap()
                .unwrap();
        assert_eq!(from.ip(), Ipv4Addr::LOCALHOST);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), other.recv())
                .await
                .is_err()
        );
    }
}
