//! Session and destination link metrics — RFC 8175 §13.12–13.20, reduced to a
//! single plain-old-data struct.
//!
//! Lives in `dlep-core` (alongside the wire data items) so the FSM, the
//! daemon runtime, and the extension plug-in API can all share one type
//! without dragging in larger crates as a dependency.

use std::time::Duration;

/// The five mandatory metrics are always supplied. Optional `None` values mean
/// unsupported at initialization, or omitted (unchanged/inherited) in updates.
/// `Some(0)` is a reported zero, not an absent value. Optional metric support
/// cannot change during a session.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkMetrics {
    pub max_data_rate_rx_bps: u64,
    pub max_data_rate_tx_bps: u64,
    pub current_data_rate_rx_bps: u64,
    pub current_data_rate_tx_bps: u64,
    pub latency: Duration,
    pub resources: Option<u8>,
    pub rlq_rx: Option<u8>,
    pub rlq_tx: Option<u8>,
    pub mtu: Option<u16>,
}

impl LinkMetrics {
    /// Whether every supplied optional field was declared at initialization.
    pub fn supported_by(&self, initial: &Self) -> bool {
        (self.resources.is_none() || initial.resources.is_some())
            && (self.rlq_rx.is_none() || initial.rlq_rx.is_some())
            && (self.rlq_tx.is_none() || initial.rlq_tx.is_some())
            && (self.mtu.is_none() || initial.mtu.is_some())
    }
}

/// Requested changes in RFC 8175 §12.18. At least one field must be present;
/// omitted fields are not requests to change that characteristic.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkCharacteristics {
    pub current_data_rate_rx_bps: Option<u64>,
    pub current_data_rate_tx_bps: Option<u64>,
    pub latency: Option<Duration>,
}

impl LinkCharacteristics {
    pub fn is_empty(&self) -> bool {
        self.current_data_rate_rx_bps.is_none()
            && self.current_data_rate_tx_bps.is_none()
            && self.latency.is_none()
    }
}
