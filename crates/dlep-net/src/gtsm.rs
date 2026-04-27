//! Generalized TTL Security Mechanism (RFC 5082) helpers for DLEP.
//!
//! DLEP requires outbound packets to have TTL=255 and inbound packets with a
//! lower TTL to be dropped. This module will host the `setsockopt` wiring
//! (IP_TTL / IPV6_UNICAST_HOPS / IP_MULTICAST_TTL) and cmsg-based inbound
//! checks via `recvmsg`.

use std::io;

use tokio::net::UdpSocket;

/// Threshold TTL/HopLimit: packets with a lower value must be dropped.
pub const REQUIRED_TTL: u8 = 255;

/// Set TTL/HopLimit = 255 on an already-bound tokio UDP socket.
pub fn set_send_ttl(_sock: &UdpSocket) -> io::Result<()> {
    // TODO: socket2::Socket::from reuse — pending M6.
    Ok(())
}

/// Verify an inbound TTL value meets the GTSM requirement.
pub fn is_gtsm_valid(ttl: u8) -> bool {
    ttl == REQUIRED_TTL
}
