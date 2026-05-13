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

#[derive(Debug)]
pub struct DiscoverySocket {
    fd: AsyncFd<OwnedFd>,
    group_v4: Ipv4Addr,
    /// The actual local bind port resolved at bind time (kernel-picked when
    /// `params.port == 0`).
    port: u16,
    /// Destination port for multicast group sends (`params.group_port`
    /// falling back to `params.port`).
    group_port: u16,
    codec: SignalCodec,
}

impl DiscoverySocket {
    /// Bind and (optionally) join the IPv4 multicast group described by
    /// `params`.
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
        if params.join_group {
            sock.join_multicast_v4(&params.group_v4, &params.interface_v4)?;
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
            group_v4: params.group_v4,
            port: resolved_port,
            group_port: params.group_port.unwrap_or(resolved_port),
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

    /// Send a signal to the configured multicast group. Loops until the
    /// kernel accepts the datagram (handling `EAGAIN` via tokio's
    /// `AsyncFd::writable`). Errors propagate as `io::Error`; a short
    /// `sendto` (which UDP doesn't normally produce) is reported rather
    /// than silently truncated.
    pub async fn send_to_group(&self, signal: &Signal) -> io::Result<()> {
        let bytes = signal
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let dest = std::net::SocketAddrV4::new(self.group_v4, self.group_port);
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                use nix::sys::socket::{MsgFlags, SockaddrIn, sendto};
                let nix_addr = SockaddrIn::from(dest);
                sendto(
                    inner.get_ref().as_raw_fd(),
                    &bytes,
                    &nix_addr,
                    MsgFlags::empty(),
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

    /// Send a signal to a specific unicast destination (used for modem
    /// Peer_Offer replies). Like `send_to_group`, but the destination
    /// address comes from the caller (typically the source address of an
    /// inbound Peer_Discovery).
    pub async fn send_unicast(&self, signal: &Signal, dest: SocketAddr) -> io::Result<()> {
        let bytes = signal
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let SocketAddr::V4(dest_v4) = dest else {
            return Err(io::Error::other("only v4 unicast is supported in M6"));
        };
        loop {
            let mut guard = self.fd.writable().await?;
            match guard.try_io(|inner| {
                use nix::sys::socket::{MsgFlags, SockaddrIn, sendto};
                let nix_addr = SockaddrIn::from(dest_v4);
                sendto(
                    inner.get_ref().as_raw_fd(),
                    &bytes,
                    &nix_addr,
                    MsgFlags::empty(),
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
    /// kernel-reported TTL. The TTL comes from an `IP_TTL` cmsg attached
    /// by the kernel because Task 1 enabled `IP_RECVTTL` on the socket;
    /// if the cmsg is missing the function returns an error rather than
    /// guessing (silent guess would defeat GTSM).
    pub async fn recv(&self) -> io::Result<(Signal, SocketAddr, u8)> {
        use bytes::BytesMut;
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg};

        // 1500 ≈ standard Ethernet MTU; DLEP signals fit easily. The
        // datagram boundary is authoritative, so a fixed buffer is fine.
        let mut payload = vec![0u8; 1500];
        // IP_TTL cmsg payload is `int` on Linux (`ControlMessageOwned::Ipv4Ttl(i32)`).
        // `i32` matches `libc::c_int` on every supported target — using it
        // here keeps `dlep-net` free of an explicit `libc` dep.
        let mut cmsg_space = nix::cmsg_space!(i32);

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
                let from: SocketAddr = res
                    .address
                    .and_then(|a| {
                        a.as_sockaddr_in().map(|s| -> SocketAddr {
                            std::net::SocketAddrV4::new(s.ip(), s.port()).into()
                        })
                    })
                    .ok_or_else(|| io::Error::other("recvmsg without v4 sender"))?;
                let mut ttl: Option<u8> = None;
                for cmsg in res.cmsgs().map_err(io::Error::from)? {
                    if let ControlMessageOwned::Ipv4Ttl(t) = cmsg {
                        // TTL is a single byte in the IP header; the kernel
                        // hands it back as `int` (0..=255), so the cast is
                        // lossless.
                        ttl = Some(t as u8);
                    }
                }
                Ok::<_, io::Error>((bytes_read, from, ttl))
            });
            match outcome {
                Ok(Ok((bytes_read, from, ttl_opt))) => {
                    let ttl = ttl_opt.ok_or_else(|| {
                        io::Error::other(
                            "recvmsg returned no IP_TTL cmsg — IP_RECVTTL not enabled?",
                        )
                    })?;
                    let buf = BytesMut::from(&payload[..bytes_read]);
                    let signal = self
                        .codec
                        .decode_datagram(buf)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    return Ok((signal, from, ttl));
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
        // INADDR_ANY (`0.0.0.0`) for the join lets the kernel pick the
        // default multicast egress interface. On hosts where the loopback
        // interface lacks the `MULTICAST` link flag (e.g. WSL2 — see
        // `ip link show lo`), binding the join to `127.0.0.1` would
        // silently succeed but never deliver datagrams, because the
        // kernel routes `224.0.0.117` via the default route (typically
        // `eth0`). Using `UNSPECIFIED` matches the receive interface to
        // wherever IP_MULTICAST_IF (defaulted by the kernel) sends from,
        // so the round-trip closes regardless of which interface carries
        // the traffic. The TTL assertion remains the load-bearing check:
        // it confirms `set_send_ttl` and `IP_RECVTTL`/cmsg extraction are
        // wired correctly.
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
}
