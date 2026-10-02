use std::time::Duration;

pub use dlep_core::{LinkCharacteristics, LinkMetrics};
use dlep_core::{MacAddress, Message, Signal, StatusCode};

use crate::timers::{TimerId, TimerKind};

/// Peer address hints produced by extensions or app calls.
pub type PeerHint = std::net::SocketAddr;

#[derive(Debug)]
pub enum SendTarget {
    /// Multicast discovery.
    DiscoveryGroup,
    /// Unicast reply to a discovered peer.
    Unicast(std::net::SocketAddr),
}

pub use crate::addresses::{AddressChanges, DestinationAddrs};

/// Inbound events consumed by any FSM.
#[derive(Debug)]
pub enum FsmEvent {
    // Wire
    RecvMessage(Message),
    /// A negotiated extension consumed a valid message.
    RecvExtensionMessage,
    /// Malformed input detected by the transport codec.
    ProtocolError(StatusCode),
    RecvSignal {
        signal: Signal,
        from: std::net::SocketAddr,
    },

    // Transport lifecycle
    TcpConnected,
    TcpAccepted,
    TcpClosed,

    // Timers
    TimerExpired(TimerId, TimerKind),

    // Application-level commands (modem side dominates)
    AppAddDestination {
        mac: MacAddress,
        metrics: LinkMetrics,
        addrs: DestinationAddrs,
    },
    AppDropDestination {
        mac: MacAddress,
        reason: StatusCode,
    },
    AppUpdateMetrics {
        mac: MacAddress,
        metrics: LinkMetrics,
    },
    AppUpdateAddresses {
        mac: MacAddress,
        changes: AddressChanges,
    },
    AppSessionAddresses {
        changes: AddressChanges,
    },
    AppAnnounceDestination {
        mac: MacAddress,
    },
    /// Push session-wide metric changes to the peer via a Session Update
    /// Message (RFC 8175 §12.7). Metrics may only originate at the modem.
    AppSessionUpdate {
        metrics: LinkMetrics,
    },
    AppRequestLinkCharacteristics {
        mac: MacAddress,
        requested: LinkCharacteristics,
    },
    AppStartDiscovery,
    AppShutdown {
        reason: StatusCode,
    },
}

/// Actions the FSM asks the runtime to perform. Returned as a `Vec` so each
/// `step` call produces an ordered batch the runtime can drain.
#[derive(Debug)]
pub enum FsmAction {
    SendMessage(Message),
    SendSignal {
        signal: Signal,
        target: SendTarget,
    },
    StartTimer {
        id: TimerId,
        kind: TimerKind,
        duration: Duration,
        periodic: bool,
    },
    CancelTimer(TimerId),
    /// Re-arm the missed-heartbeat deadline timer. The runtime cancels the
    /// timer at `timer_id` (if armed) and starts a fresh single-shot timer
    /// at `missed_deadline`. The FSM owns the timer-id choice so the runtime
    /// stays decoupled from FSM-internal timer naming. The send-side
    /// periodic heartbeat timer is independent (started once at `InSession`
    /// entry) and is *not* affected.
    ResetHeartbeat {
        timer_id: TimerId,
        missed_deadline: Duration,
    },
    CloseTcp,
    /// Hand an event to the public API (e.g. `DestinationEvent::Up`).
    Emit(EmittedEvent),
}

/// Minimal public-API-side events the FSM can surface. The daemon translates
/// these into the richer `DaemonEvent` type with full metric payloads.
#[derive(Debug)]
pub enum EmittedEvent {
    SessionUp {
        /// Extension IDs the peer advertised in `ExtensionsSupported`.
        /// The daemon intersects with its own advertised set to compute
        /// `DaemonEvent::SessionUp.negotiated_extensions`.
        peer_extensions: Vec<dlep_core::ExtensionId>,
    },
    SessionDown(StatusCode),
    PeerDiscovered {
        endpoints: Vec<crate::discovery_common::OfferEndpoint>,
        peer_description: Option<String>,
    },
    DestinationUp {
        mac: MacAddress,
        metrics: LinkMetrics,
        addrs: DestinationAddrs,
    },
    DestinationDown {
        mac: MacAddress,
        reason: StatusCode,
    },
    DestinationUpdate {
        mac: MacAddress,
        metrics: LinkMetrics,
    },
    DestinationAddressesUpdate {
        mac: MacAddress,
        changes: Box<AddressChanges>,
        addresses: DestinationAddrs,
    },
    SessionAddressesUpdate {
        changes: Box<AddressChanges>,
        addresses: DestinationAddrs,
    },
    /// Reply to the router's Link Characteristics Request, including the
    /// current metrics even when the requested change was denied.
    LinkCharacteristicsResponse {
        mac: MacAddress,
        status: StatusCode,
        text: String,
        metrics: LinkMetrics,
    },
    /// Session-wide metric change the peer reported in a Session Update
    /// Message (RFC 8175 §12.7). Distinct from `DestinationUpdate`, which
    /// is scoped to one destination MAC.
    SessionMetricsUpdate {
        metrics: LinkMetrics,
    },
    /// The router asked us (the modem) to report on a destination it is
    /// interested in — inbound Destination Announce (RFC 8175 §12.13).
    DestinationAnnounced {
        mac: MacAddress,
        requested_addresses: AddressChanges,
    },
}
