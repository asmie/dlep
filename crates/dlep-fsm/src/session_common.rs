//! Types and message builders shared by both session FSMs (router and modem).
//!
//! Lives in its own module so neither side reaches across to the other for
//! shared structures, and so M4+ message builders (heartbeat, etc.) have a
//! natural home alongside the existing termination builders.

use std::time::Duration;

use dlep_core::{
    DataItem, MIN_HEARTBEAT_INTERVAL_MS, MacAddress, Message, MessageType, StatusCode,
};

use crate::events::{DestinationAddrs, FsmAction, LinkMetrics};
use crate::timers::TimerId;

/// FSM-side configuration. The runtime hydrates this from `TimersConfig` and
/// the per-role config (router or modem) before constructing the FSM, so the
/// state handlers themselves never reach into config files or environment.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub peer_description: String,
    pub heartbeat_interval_ms: u32,
    pub session_init_timeout: Duration,
    pub termination_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            peer_description: "dlep-router".into(),
            heartbeat_interval_ms: 60_000,
            session_init_timeout: Duration::from_millis(5_000),
            termination_timeout: Duration::from_millis(1_000),
        }
    }
}

/// Return the RFC-conformant local heartbeat interval to advertise and use
/// for the send-side timer. RFC 8175 §7.3.1 requires a minimum of one second,
/// and §13.5 says the Heartbeat Interval value MUST NOT be zero.
pub fn local_heartbeat_interval(config: &SessionConfig) -> Duration {
    Duration::from_millis(
        config
            .heartbeat_interval_ms
            .max(MIN_HEARTBEAT_INTERVAL_MS)
            .into(),
    )
}

pub fn build_session_termination(reason: StatusCode) -> Message {
    Message::new(MessageType::SESSION_TERMINATION).with_item(DataItem::Status {
        code: reason,
        text: String::new(),
    })
}

/// RFC 8175 §12.10 specifies no Data Items for the Session Termination
/// Response Message — emit it bare.
pub fn build_session_termination_response() -> Message {
    Message::new(MessageType::SESSION_TERMINATION_RESPONSE)
}

pub fn extract_status(msg: &Message) -> Option<StatusCode> {
    msg.data_items.iter().find_map(|item| match item {
        DataItem::Status { code, .. } => Some(*code),
        _ => None,
    })
}

/// `Message::new(MessageType::HEARTBEAT)` with no Data Items. RFC 8175
/// §11.2 allows the Heartbeat Message to carry no fields.
pub fn build_heartbeat() -> Message {
    Message::new(MessageType::HEARTBEAT)
}

/// Pull the peer's `HeartbeatInterval` Data Item out of a Session
/// Initialization or Session Initialization Response message. Decoded
/// messages should already satisfy RFC 8175 §13.5 (`MUST NOT be 0`) via the
/// codec; this helper returns `None` only when the field is absent.
pub fn extract_heartbeat_interval(msg: &Message) -> Option<Duration> {
    msg.data_items.iter().find_map(|item| match item {
        DataItem::HeartbeatInterval(d) => Some(*d),
        _ => None,
    })
}

/// Build a `ResetHeartbeat` action carrying `2 × peer_interval` if the peer
/// announced a valid heartbeat interval. Returns `None` when
/// `peer_interval` is `None` (the field was missing) or when the doubling
/// would overflow `Duration` (defensive — u32-ms
/// values from RFC-conformant peers fit in u64 with decades of headroom,
/// but the check costs nothing). Callers `push`, `insert`, or
/// `into_iter().collect()` based on context.
///
/// The FSM passes its own `timer_id` so the runtime needn't know which
/// timer ID this FSM uses for its missed-deadline.
pub fn heartbeat_reset_action(
    timer_id: TimerId,
    peer_interval: Option<Duration>,
) -> Option<FsmAction> {
    let d = peer_interval?;
    if d < Duration::from_millis(MIN_HEARTBEAT_INTERVAL_MS.into()) {
        return None;
    }
    let missed_deadline = d.checked_mul(2)?;
    Some(FsmAction::ResetHeartbeat {
        timer_id,
        missed_deadline,
    })
}

/// Build a `Destination_Up` message (RFC 8175 §11.3). The MAC must be the
/// first Data Item — the RFC does not strictly require ordering, but every
/// real-world peer (LL-DLEP, vendor X) puts MAC first and reads no further
/// to identify the destination.
pub fn build_destination_up(
    mac: MacAddress,
    metrics: &LinkMetrics,
    addrs: &DestinationAddrs,
) -> Message {
    let mut msg = Message::new(MessageType::DESTINATION_UP).with_item(DataItem::MacAddress(mac));
    for a in &addrs.v4 {
        msg = msg.with_item(DataItem::Ipv4Address {
            add: true,
            addr: *a,
        });
    }
    for a in &addrs.v6 {
        msg = msg.with_item(DataItem::Ipv6Address {
            add: true,
            addr: *a,
        });
    }
    for s in &addrs.v4_subnets {
        msg = msg.with_item(DataItem::Ipv4AttachedSubnet {
            add: true,
            subnet: *s,
        });
    }
    for s in &addrs.v6_subnets {
        msg = msg.with_item(DataItem::Ipv6AttachedSubnet {
            add: true,
            subnet: *s,
        });
    }
    push_metric_items(msg, metrics)
}

/// Build a `Destination_Up_Response` (RFC 8175 §11.4). Carries the same
/// MAC the request used plus a Status.
pub fn build_destination_up_response(mac: MacAddress, status: StatusCode) -> Message {
    Message::new(MessageType::DESTINATION_UP_RESPONSE)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: status,
            text: String::new(),
        })
}

/// Build a `Destination_Update` message (RFC 8175 §11.7). Modem → router,
/// no response expected.
pub fn build_destination_update(mac: MacAddress, metrics: &LinkMetrics) -> Message {
    let msg = Message::new(MessageType::DESTINATION_UPDATE).with_item(DataItem::MacAddress(mac));
    push_metric_items(msg, metrics)
}

/// Build a `Destination_Down` message (RFC 8175 §11.5).
pub fn build_destination_down(mac: MacAddress, reason: StatusCode) -> Message {
    Message::new(MessageType::DESTINATION_DOWN)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: reason,
            text: String::new(),
        })
}

/// Build a `Destination_Down_Response` (RFC 8175 §11.6).
pub fn build_destination_down_response(mac: MacAddress, status: StatusCode) -> Message {
    Message::new(MessageType::DESTINATION_DOWN_RESPONSE)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: status,
            text: String::new(),
        })
}

/// First `DataItem::MacAddress` in the message, if any.
pub fn extract_destination_mac(msg: &Message) -> Option<MacAddress> {
    msg.data_items.iter().find_map(|item| match item {
        DataItem::MacAddress(m) => Some(*m),
        _ => None,
    })
}

/// Pull the nine metric Data Items into a `LinkMetrics`. Missing fields
/// stay at their `Default` value; the RFC requires all of them in
/// `Destination_Up`, but we are lenient on receive (out-of-spec peers
/// shouldn't crash a router). Returns `None` only when no metric Data Item
/// is present at all.
pub fn extract_link_metrics(msg: &Message) -> Option<LinkMetrics> {
    let mut found = false;
    let mut m = LinkMetrics::default();
    for item in &msg.data_items {
        match item {
            DataItem::MaxDataRateReceive(v) => {
                m.max_data_rate_rx_bps = *v;
                found = true;
            }
            DataItem::MaxDataRateTransmit(v) => {
                m.max_data_rate_tx_bps = *v;
                found = true;
            }
            DataItem::CurrentDataRateReceive(v) => {
                m.current_data_rate_rx_bps = *v;
                found = true;
            }
            DataItem::CurrentDataRateTransmit(v) => {
                m.current_data_rate_tx_bps = *v;
                found = true;
            }
            DataItem::Latency(v) => {
                m.latency = *v;
                found = true;
            }
            DataItem::Resources(v) => {
                m.resources = *v;
                found = true;
            }
            DataItem::RelativeLinkQualityReceive(v) => {
                m.rlq_rx = *v;
                found = true;
            }
            DataItem::RelativeLinkQualityTransmit(v) => {
                m.rlq_tx = *v;
                found = true;
            }
            DataItem::Mtu(v) => {
                m.mtu = *v;
                found = true;
            }
            _ => {}
        }
    }
    found.then_some(m)
}

/// Collect every `Ipv4Address` / `Ipv6Address` / `Ipv4AttachedSubnet` /
/// `Ipv6AttachedSubnet` Data Item with `add == true`. Remove-style entries
/// (`add == false`) are ignored for M5.
pub fn extract_destination_addrs(msg: &Message) -> DestinationAddrs {
    let mut out = DestinationAddrs::default();
    for item in &msg.data_items {
        match item {
            DataItem::Ipv4Address { add: true, addr } => out.v4.push(*addr),
            DataItem::Ipv6Address { add: true, addr } => out.v6.push(*addr),
            DataItem::Ipv4AttachedSubnet { add: true, subnet } => out.v4_subnets.push(*subnet),
            DataItem::Ipv6AttachedSubnet { add: true, subnet } => out.v6_subnets.push(*subnet),
            _ => {}
        }
    }
    out
}

fn push_metric_items(mut msg: Message, m: &LinkMetrics) -> Message {
    msg = msg.with_item(DataItem::MaxDataRateReceive(m.max_data_rate_rx_bps));
    msg = msg.with_item(DataItem::MaxDataRateTransmit(m.max_data_rate_tx_bps));
    msg = msg.with_item(DataItem::CurrentDataRateReceive(m.current_data_rate_rx_bps));
    msg = msg.with_item(DataItem::CurrentDataRateTransmit(
        m.current_data_rate_tx_bps,
    ));
    msg = msg.with_item(DataItem::Latency(m.latency));
    msg = msg.with_item(DataItem::Resources(m.resources));
    msg = msg.with_item(DataItem::RelativeLinkQualityReceive(m.rlq_rx));
    msg = msg.with_item(DataItem::RelativeLinkQualityTransmit(m.rlq_tx));
    msg = msg.with_item(DataItem::Mtu(m.mtu));
    msg
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use dlep_core::data_item::DataItem;
    use dlep_core::{MacAddress, MessageType, StatusCode};
    use ipnet::Ipv4Net;

    use super::*;
    use crate::events::{DestinationAddrs, LinkMetrics};

    fn sample_metrics() -> LinkMetrics {
        LinkMetrics {
            max_data_rate_rx_bps: 100_000_000,
            max_data_rate_tx_bps: 100_000_000,
            current_data_rate_rx_bps: 50_000_000,
            current_data_rate_tx_bps: 50_000_000,
            latency: Duration::from_micros(2_500),
            resources: 80,
            rlq_rx: 95,
            rlq_tx: 95,
            mtu: 1500,
        }
    }

    fn mac() -> MacAddress {
        MacAddress::new_eui48([1, 2, 3, 4, 5, 6])
    }

    #[test]
    fn destination_up_carries_mac_and_metrics() {
        let metrics = sample_metrics();
        let msg = build_destination_up(mac(), &metrics, &DestinationAddrs::default());
        assert_eq!(msg.message_type, MessageType::DESTINATION_UP);
        assert!(matches!(
            msg.data_items.first(),
            Some(DataItem::MacAddress(_))
        ));
        let extracted = extract_link_metrics(&msg).expect("metrics present");
        assert_eq!(extracted.current_data_rate_rx_bps, 50_000_000);
        assert_eq!(extracted.latency, Duration::from_micros(2_500));
        assert_eq!(extracted.mtu, 1500);
    }

    #[test]
    fn destination_up_response_round_trip() {
        let msg = build_destination_up_response(mac(), StatusCode::SUCCESS);
        assert_eq!(msg.message_type, MessageType::DESTINATION_UP_RESPONSE);
        assert_eq!(extract_destination_mac(&msg), Some(mac()));
        assert_eq!(extract_status(&msg), Some(StatusCode::SUCCESS));
    }

    #[test]
    fn destination_down_round_trip() {
        let msg = build_destination_down(mac(), StatusCode::SHUTTING_DOWN);
        assert_eq!(msg.message_type, MessageType::DESTINATION_DOWN);
        assert_eq!(extract_destination_mac(&msg), Some(mac()));
        assert_eq!(extract_status(&msg), Some(StatusCode::SHUTTING_DOWN));

        let resp = build_destination_down_response(mac(), StatusCode::SUCCESS);
        assert_eq!(resp.message_type, MessageType::DESTINATION_DOWN_RESPONSE);
        assert_eq!(extract_destination_mac(&resp), Some(mac()));
        assert_eq!(extract_status(&resp), Some(StatusCode::SUCCESS));
    }

    #[test]
    fn destination_update_carries_metrics_only() {
        let metrics = sample_metrics();
        let msg = build_destination_update(mac(), &metrics);
        assert_eq!(msg.message_type, MessageType::DESTINATION_UPDATE);
        assert_eq!(extract_destination_mac(&msg), Some(mac()));
        let extracted = extract_link_metrics(&msg).expect("metrics present");
        assert_eq!(extracted.current_data_rate_tx_bps, 50_000_000);
    }

    #[test]
    fn extract_addrs_collects_v4_v6_and_subnets() {
        let addrs = DestinationAddrs {
            v4: vec![Ipv4Addr::new(10, 0, 0, 1)],
            v6: vec![Ipv6Addr::LOCALHOST],
            v4_subnets: vec!["10.0.0.0/24".parse::<Ipv4Net>().unwrap()],
            v6_subnets: vec![],
        };
        let msg = build_destination_up(mac(), &sample_metrics(), &addrs);
        let parsed = extract_destination_addrs(&msg);
        assert_eq!(parsed.v4, vec![Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(parsed.v6, vec![Ipv6Addr::LOCALHOST]);
        assert_eq!(parsed.v4_subnets.len(), 1);
        assert!(parsed.v6_subnets.is_empty());
    }
}
