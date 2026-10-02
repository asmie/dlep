use std::any::Any;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::{ExtensionId, MacAddress, StatusCode};
use ipnet::{Ipv4Net, Ipv6Net};

pub use dlep_fsm::{AddressChanges, DestinationAddrs, LinkCharacteristics, LinkMetrics};

/// Opaque destination identifier. Today it is a MAC address; this wrapper
/// lets the API evolve (e.g. for logical-destination extensions).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DestinationId(pub MacAddress);

impl From<MacAddress> for DestinationId {
    fn from(m: MacAddress) -> Self {
        Self(m)
    }
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub is_tls: bool,
    pub peer_description: Option<String>,
}

/// Candidate endpoints from one modem offer, ordered TLS first, then IPv6.
#[derive(Clone, Debug)]
pub struct PeerOffer {
    pub endpoints: Vec<dlep_fsm::discovery_common::OfferEndpoint>,
    pub peer_description: Option<String>,
}

#[derive(Clone, Debug)]
pub enum DestinationEvent {
    Up {
        id: DestinationId,
        metrics: LinkMetrics,
        v4_addrs: Vec<std::net::Ipv4Addr>,
        v6_addrs: Vec<std::net::Ipv6Addr>,
        v4_subnets: Vec<Ipv4Net>,
        v6_subnets: Vec<Ipv6Net>,
    },
    Update {
        id: DestinationId,
        metrics: LinkMetrics,
    },
    /// Outcome of a Link Characteristics Request. Metrics describe the link
    /// after processing, including when the requested change was denied.
    LinkCharacteristicsResponse {
        id: DestinationId,
        status: StatusCode,
        text: String,
        metrics: LinkMetrics,
    },
    AddressesChanged {
        id: DestinationId,
        changes: AddressChanges,
        addresses: DestinationAddrs,
    },
    Announced {
        id: DestinationId,
        requested_addresses: AddressChanges,
    },
    Down {
        id: DestinationId,
        reason: StatusCode,
    },
}

#[derive(Clone, Debug)]
pub struct MetricsEvent {
    pub session_wide: LinkMetrics,
}

/// Broadcastable public event. Uses `Arc<dyn Any + Send + Sync>` for
/// extension-emitted payloads so the event itself stays `Clone`, which the
/// broadcast channel needs to fan out to multiple subscribers.
#[derive(Clone)]
pub enum DaemonEvent {
    CommandRejected {
        session_id: dlep_ext::SessionId,
        peer: PeerInfo,
        rejection: dlep_fsm::CommandRejection,
    },
    PeerDiscovered(PeerOffer),
    SessionUp {
        session_id: dlep_ext::SessionId,
        peer: PeerInfo,
        negotiated_extensions: Vec<ExtensionId>,
    },
    SessionDown {
        session_id: dlep_ext::SessionId,
        /// Which peer's session ended. Required so a multi-session embedder
        /// (one router, several modems) can attribute the drop — and so a
        /// run loop can evict the dead peer and reconnect.
        peer: PeerInfo,
        reason: StatusCode,
    },
    Destination {
        session_id: dlep_ext::SessionId,
        peer: PeerInfo,
        event: DestinationEvent,
    },
    Metrics {
        session_id: dlep_ext::SessionId,
        peer: PeerInfo,
        event: MetricsEvent,
    },
    SessionAddresses {
        session_id: dlep_ext::SessionId,
        peer: PeerInfo,
        changes: AddressChanges,
        addresses: DestinationAddrs,
    },
    Extension(Arc<dyn Any + Send + Sync>),
}

impl fmt::Debug for DaemonEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerDiscovered(p) => f.debug_tuple("PeerDiscovered").field(p).finish(),
            Self::SessionUp {
                peer,
                negotiated_extensions,
                ..
            } => f
                .debug_struct("SessionUp")
                .field("peer", peer)
                .field("negotiated_extensions", negotiated_extensions)
                .finish(),
            Self::SessionDown { peer, reason, .. } => f
                .debug_struct("SessionDown")
                .field("peer", peer)
                .field("reason", reason)
                .finish(),
            Self::Destination {
                peer,
                session_id,
                event,
            } => f
                .debug_struct("Destination")
                .field("session_id", session_id)
                .field("peer", peer)
                .field("event", event)
                .finish(),
            Self::Metrics {
                peer,
                session_id,
                event,
            } => f
                .debug_struct("Metrics")
                .field("session_id", session_id)
                .field("peer", peer)
                .field("event", event)
                .finish(),
            Self::SessionAddresses {
                session_id,
                peer,
                changes,
                addresses,
            } => f
                .debug_struct("SessionAddresses")
                .field("session_id", session_id)
                .field("peer", peer)
                .field("changes", changes)
                .field("addresses", addresses)
                .finish(),
            Self::CommandRejected {
                session_id,
                peer,
                rejection,
            } => f
                .debug_struct("CommandRejected")
                .field("session_id", session_id)
                .field("peer", peer)
                .field("rejection", rejection)
                .finish(),
            Self::Extension(_) => f.debug_tuple("Extension").field(&"<opaque>").finish(),
        }
    }
}
