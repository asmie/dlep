//! Builders and extractors shared by both discovery FSMs (router + modem).
//!
//! Peer_Discovery (RFC 8175 §12.3): signal sent by routers searching for
//! a modem. Payload is the router's Peer Type and (optionally) Extensions
//! Supported.
//!
//! Peer_Offer (RFC 8175 §12.4): signal sent by a modem in response to a
//! Peer_Discovery. Carries Peer Type + at least one Connection Point
//! identifying the TCP endpoint the router should dial.

use std::net::{IpAddr, SocketAddr};

use dlep_core::data_item::{ConnectionPointFlags, DataItem, PeerFlags};
use dlep_core::{Signal, SignalType};

/// Build a `Peer_Discovery` signal.
pub fn build_peer_discovery(peer_description: &str) -> Signal {
    Signal::new(SignalType::PEER_DISCOVERY).with_item(DataItem::PeerType {
        flags: PeerFlags::default(),
        description: peer_description.to_string(),
    })
}

/// Build a `Peer_Offer` signal carrying the modem's TCP endpoint and
/// description. The endpoint is encoded as the matching v4 or v6
/// Connection Point.
pub fn build_peer_offer(peer_description: &str, tcp_endpoint: SocketAddr, use_tls: bool) -> Signal {
    let flags = ConnectionPointFlags { use_tls };
    let mut sig = Signal::new(SignalType::PEER_OFFER).with_item(DataItem::PeerType {
        flags: PeerFlags::default(),
        description: peer_description.to_string(),
    });
    sig = match tcp_endpoint.ip() {
        IpAddr::V4(addr) => sig.with_item(DataItem::Ipv4ConnectionPoint {
            flags,
            addr,
            port: Some(tcp_endpoint.port()),
        }),
        IpAddr::V6(addr) => sig.with_item(DataItem::Ipv6ConnectionPoint {
            flags,
            addr,
            port: Some(tcp_endpoint.port()),
        }),
    };
    sig
}

/// Extract the peer description from any Peer_Discovery / Peer_Offer
/// signal. Returns `None` if no Peer Type item is present.
pub fn extract_peer_description(sig: &Signal) -> Option<String> {
    sig.data_items.iter().find_map(|item| match item {
        DataItem::PeerType { description, .. } => Some(description.clone()),
        _ => None,
    })
}

/// Decoded Connection Point from a Peer_Offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfferEndpoint {
    pub addr: SocketAddr,
    pub use_tls: bool,
}

/// Validate discovery grammar and collect endpoints in preference order.
/// A missing Connection Point means the offer's source address at port 854.
pub fn offer_endpoints(sig: &Signal, from: SocketAddr) -> Vec<OfferEndpoint> {
    let mut endpoints: Vec<_> = sig
        .data_items
        .iter()
        .filter_map(|item| match item {
            DataItem::Ipv4ConnectionPoint { flags, addr, port } => Some(OfferEndpoint {
                addr: SocketAddr::new((*addr).into(), port.unwrap_or(dlep_core::DEFAULT_PORT)),
                use_tls: flags.use_tls,
            }),
            DataItem::Ipv6ConnectionPoint { flags, addr, port } => {
                let mut endpoint =
                    SocketAddr::new((*addr).into(), port.unwrap_or(dlep_core::DEFAULT_PORT));
                if let (SocketAddr::V6(source), SocketAddr::V6(target)) = (from, &mut endpoint) {
                    if addr.is_unicast_link_local() {
                        target.set_scope_id(source.scope_id());
                    }
                }
                Some(OfferEndpoint {
                    addr: endpoint,
                    use_tls: flags.use_tls,
                })
            }
            _ => None,
        })
        .collect();
    if endpoints.is_empty() {
        let mut addr = from;
        addr.set_port(dlep_core::DEFAULT_PORT);
        endpoints.push(OfferEndpoint {
            addr,
            use_tls: false,
        });
    }
    endpoints.retain(|e| {
        !e.addr.ip().is_unspecified() && !e.addr.ip().is_multicast() && e.addr.port() != 0
    });
    endpoints.sort_by_key(|e| (!e.use_tls, !e.addr.is_ipv6()));
    endpoints.dedup();
    endpoints
}

pub fn valid_signal(signal: &Signal) -> bool {
    let mut peer_type = false;
    let mut seen = std::collections::HashSet::new();
    for item in &signal.data_items {
        match item {
            DataItem::PeerType { .. } if !peer_type => peer_type = true,
            DataItem::Ipv4ConnectionPoint { .. } | DataItem::Ipv6ConnectionPoint { .. }
                if signal.signal_type == SignalType::PEER_OFFER => {}
            _ => return false,
        }
        let mut bytes = bytes::BytesMut::new();
        if item.encode(&mut bytes).is_err() || !seen.insert(bytes.to_vec()) {
            return false;
        }
    }
    true
}

/// Extract the *first* connection point from a `Peer_Offer`. If port is
/// absent the RFC's default DLEP port (854) is filled in. Returns `None`
/// when no v4 or v6 connection point is present.
pub fn extract_offer_endpoint(sig: &Signal) -> Option<OfferEndpoint> {
    sig.data_items.iter().find_map(|item| match item {
        DataItem::Ipv4ConnectionPoint { flags, addr, port } => Some(OfferEndpoint {
            addr: SocketAddr::new(IpAddr::V4(*addr), port.unwrap_or(dlep_core::DEFAULT_PORT)),
            use_tls: flags.use_tls,
        }),
        DataItem::Ipv6ConnectionPoint { flags, addr, port } => Some(OfferEndpoint {
            addr: SocketAddr::new(IpAddr::V6(*addr), port.unwrap_or(dlep_core::DEFAULT_PORT)),
            use_tls: flags.use_tls,
        }),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn peer_discovery_carries_description() {
        let sig = build_peer_discovery("dlep-router");
        assert_eq!(sig.signal_type, SignalType::PEER_DISCOVERY);
        assert_eq!(
            extract_peer_description(&sig).as_deref(),
            Some("dlep-router")
        );
    }

    #[test]
    fn peer_offer_v4_round_trip() {
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 854);
        let sig = build_peer_offer("dlep-modem", endpoint, false);
        assert_eq!(sig.signal_type, SignalType::PEER_OFFER);
        let parsed = extract_offer_endpoint(&sig).expect("endpoint present");
        assert_eq!(parsed.addr, endpoint);
        assert!(!parsed.use_tls);
        assert_eq!(
            extract_peer_description(&sig).as_deref(),
            Some("dlep-modem")
        );
    }

    #[test]
    fn peer_offer_v6_round_trip() {
        let endpoint = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9999);
        let sig = build_peer_offer("dlep-modem", endpoint, true);
        let parsed = extract_offer_endpoint(&sig).expect("endpoint present");
        assert_eq!(parsed.addr, endpoint);
        assert!(parsed.use_tls);
    }

    #[test]
    fn extract_offer_endpoint_defaults_port_when_absent() {
        let sig = Signal::new(SignalType::PEER_OFFER).with_item(DataItem::Ipv4ConnectionPoint {
            flags: ConnectionPointFlags::default(),
            addr: Ipv4Addr::new(10, 0, 0, 1),
            port: None,
        });
        let parsed = extract_offer_endpoint(&sig).unwrap();
        assert_eq!(parsed.addr.port(), dlep_core::DEFAULT_PORT);
    }
}
