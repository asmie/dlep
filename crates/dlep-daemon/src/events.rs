use std::any::Any;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::{ExtensionId, MacAddress, StatusCode};
use ipnet::{Ipv4Net, Ipv6Net};

pub use dlep_fsm::LinkMetrics;

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
    Announced {
        id: DestinationId,
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
    PeerDiscovered(PeerInfo),
    SessionUp {
        peer: PeerInfo,
        negotiated_extensions: Vec<ExtensionId>,
    },
    SessionDown {
        reason: StatusCode,
    },
    Destination(DestinationEvent),
    Metrics(MetricsEvent),
    Extension(Arc<dyn Any + Send + Sync>),
}

impl fmt::Debug for DaemonEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerDiscovered(p) => f.debug_tuple("PeerDiscovered").field(p).finish(),
            Self::SessionUp {
                peer,
                negotiated_extensions,
            } => f
                .debug_struct("SessionUp")
                .field("peer", peer)
                .field("negotiated_extensions", negotiated_extensions)
                .finish(),
            Self::SessionDown { reason } => f
                .debug_struct("SessionDown")
                .field("reason", reason)
                .finish(),
            Self::Destination(e) => f.debug_tuple("Destination").field(e).finish(),
            Self::Metrics(e) => f.debug_tuple("Metrics").field(e).finish(),
            Self::Extension(_) => f.debug_tuple("Extension").field(&"<opaque>").finish(),
        }
    }
}
