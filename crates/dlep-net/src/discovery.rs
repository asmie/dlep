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

    /// Interface scope used by connection points advertised over this socket.
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
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
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
                    inner.get_ref().as_raw_fd(),
                    &[std::io::IoSlice::new(&bytes)],
                    &controls,
                    MsgFlags::empty(),
                    Some(&nix_addr),
                )
                .map_err(io::Error::from)
            }) {
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

    /// Receive a single signal with its source address and the
    /// kernel-reported IPv4 TTL or IPv6 hop limit. Missing ancillary data
    /// is an error; callers must validate the value before processing it.
    pub async fn recv(&self) -> io::Result<(Signal, SocketAddr, u8)> {
        let (signal, from, ttl, _) = self.recv_with_local().await?;
        Ok((signal, from, ttl))
    }

    /// Receive with a usable local unicast address for wildcard Peer Offers.
    /// IPv6 senders retain their link-local interface scope.
    pub async fn recv_with_local(&self) -> io::Result<(Signal, SocketAddr, u8, IpAddr)> {
        use bytes::BytesMut;
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};

        // 1500 ≈ standard Ethernet MTU; DLEP signals fit easily. The
        // datagram boundary is authoritative, so a fixed buffer is fine.
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
                    if self
                        .interface
                        .map(|i| i.index)
                        .or_else(|| self.interface_v6.map(|i| i.index))
                        .is_some_and(|index| Some(index) != interface_index)
                    {
                        // Filter before decode; unrelated interface traffic must
                        // not reach the discovery FSM, even when malformed.
                        tokio::task::yield_now().await;
                        continue;
                    }
                    let ttl = ttl_opt.ok_or_else(|| {
                        io::Error::other("recvmsg returned no TTL/hop-limit control message")
                    })?;
                    let buf = BytesMut::from(&payload[..bytes_read]);
                    let signal = self
                        .codec
                        .decode_datagram(buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok((
                        signal,
                        from,
                        ttl,
                        local.ok_or_else(|| {
                            io::Error::other("missing packet interface information")
                        })?,
                    ));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
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
            group_port: None,
            multicast_loop: true,
            join_group: true,
        }
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
        // Receive the actual hop limit, including invalid GTSM values; the
        // daemon uses this metadata to discard non-255 discovery signals.
        socket2::SockRef::from(router.fd.get_ref())
            .set_multicast_hops_v6(254)
            .unwrap();
        router.send_to_group(&discovery).await.unwrap();
        let (_, _, hops) = tokio::time::timeout(Duration::from_secs(2), modem.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(hops, 254);
        assert!(!gtsm::is_gtsm_valid(hops));
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
