use dlep_core::MacAddress;

/// Opaque, FSM-assigned timer handle. The runtime uses it to match expiry
/// deliveries back to the FSM that scheduled them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct TimerId(pub u32);

impl TimerId {
    pub const fn new(v: u32) -> Self {
        Self(v)
    }
}

/// What the timer represents. Carried alongside `TimerId` for cheap
/// dispatching without a side-table lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TimerKind {
    /// Periodic heartbeat send timer.
    Heartbeat,
    /// "No message received for 2× heartbeat" deadline.
    HeartbeatMissed,
    /// Waiting for Session Initialization Response.
    SessionInit,
    /// Waiting for Session Termination Response.
    Termination,
    /// Per-destination in-flight request deadline.
    Transaction(MacAddress),
    /// Periodic discovery Peer Discovery send.
    Discovery,
}
