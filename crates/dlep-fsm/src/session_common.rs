//! Types and message builders shared by both session FSMs (router and modem).
//!
//! Lives in its own module so neither side reaches across to the other for
//! shared structures, and so M4+ message builders (heartbeat, etc.) have a
//! natural home alongside the existing termination builders.

use std::time::Duration;

use dlep_core::{DataItem, MIN_HEARTBEAT_INTERVAL_MS, Message, MessageType, StatusCode};

use crate::events::FsmAction;
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
