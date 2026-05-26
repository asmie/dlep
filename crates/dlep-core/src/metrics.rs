//! Per-destination link metrics — RFC 8175 §11.3 Data Items, reduced to a
//! single plain-old-data struct.
//!
//! Lives in `dlep-core` (alongside the wire data items) so the FSM, the
//! daemon runtime, and the extension plug-in API can all share one type
//! without dragging in larger crates as a dependency.

use std::time::Duration;

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
