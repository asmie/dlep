//! UDP multicast discovery socket.
//!
//! The real implementation joins the IANA-assigned IPv4/IPv6 groups on a
//! chosen interface, sets `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` for GTSM, and
//! exposes an async `recv` that returns `(Signal, from, ttl)` so the
//! runtime can drop TTL != 255 packets.

use std::io;
use std::net::SocketAddr;

use dlep_core::Signal;
use tokio::net::UdpSocket;

use crate::addr::InterfaceSpec;
use crate::framed::SignalCodec;

#[derive(Debug)]
pub struct DiscoverySocket {
    pub v4: Option<UdpSocket>,
    pub v6: Option<UdpSocket>,
    pub iface: InterfaceSpec,
    codec: SignalCodec,
}

impl DiscoverySocket {
    pub fn new(iface: InterfaceSpec) -> Self {
        Self {
            v4: None,
            v6: None,
            iface,
            codec: SignalCodec,
        }
    }

    /// Receive a single signal. Real implementation unblocks on either the
    /// v4 or v6 socket and uses `recvmsg` to extract the TTL. Skeleton stub
    /// keeps the signature stable.
    pub async fn recv(&self) -> io::Result<(Signal, SocketAddr, u8)> {
        // TODO (M6): AsyncFd + recvmsg + cmsg TTL extraction.
        let _ = &self.codec;
        std::future::pending().await
    }

    pub async fn send_to_group(&self, signal: &Signal) -> io::Result<()> {
        // TODO (M6): pick v4 vs v6 per config and send to the DLEP
        // link-local multicast group.
        let _encoded = signal.encode();
        Ok(())
    }
}
