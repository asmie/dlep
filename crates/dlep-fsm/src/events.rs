use std::time::Duration;

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

/// Inbound events consumed by any FSM.
#[derive(Debug)]
pub enum FsmEvent {
    // Wire
    RecvMessage(Message),
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
    },
    AppDropDestination {
        mac: MacAddress,
        reason: StatusCode,
    },
    AppUpdateMetrics {
        mac: MacAddress,
    },
    AppAnnounceDestination {
        mac: MacAddress,
    },
    AppRequestLinkCharacteristics {
        mac: MacAddress,
    },
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
    ResetHeartbeat,
    CloseTcp,
    /// Hand an event to the public API (e.g. `DestinationEvent::Up`).
    Emit(EmittedEvent),
}

/// Minimal public-API-side events the FSM can surface. The daemon translates
/// these into the richer `DaemonEvent` type with full metric payloads.
#[derive(Debug)]
pub enum EmittedEvent {
    SessionUp,
    SessionDown(StatusCode),
    DestinationUp(MacAddress),
    DestinationDown(MacAddress, StatusCode),
    DestinationUpdate(MacAddress),
}
