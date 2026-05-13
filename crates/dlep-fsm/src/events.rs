use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use dlep_core::{MacAddress, Message, Signal, StatusCode};
use ipnet::{Ipv4Net, Ipv6Net};

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

/// Metric values reported per destination. Mirrors the RFC 8175 §11.3
/// metric Data Items (data rates, latency, RLQ, resources, MTU). Lives in
/// `dlep-fsm` so both the FSM-internal events and the daemon's public API
/// share one type — `dlep_daemon::LinkMetrics` re-exports this.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkMetrics {
    pub max_data_rate_rx_bps: u64,
    pub max_data_rate_tx_bps: u64,
    pub current_data_rate_rx_bps: u64,
    pub current_data_rate_tx_bps: u64,
    pub latency: Duration,
    pub resources: u8,
    pub rlq_rx: u8,
    pub rlq_tx: u8,
    pub mtu: u16,
}

/// Address / subnet payload accompanying a destination. All four vectors
/// may be empty — the modem reports only what it knows. The `add` flag is
/// implicit (true for the Up / Update direction); the FSM never emits
/// remove-style entries until a follow-up plan adds the `Address Remove`
/// path.
#[derive(Clone, Debug, Default)]
pub struct DestinationAddrs {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub v4_subnets: Vec<Ipv4Net>,
    pub v6_subnets: Vec<Ipv6Net>,
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
    AppAnnounceDestination {
        mac: MacAddress,
    },
    AppRequestLinkCharacteristics {
        mac: MacAddress,
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
    SessionUp,
    SessionDown(StatusCode),
    PeerDiscovered {
        addr: std::net::SocketAddr,
        peer_description: Option<String>,
        use_tls: bool,
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
}
