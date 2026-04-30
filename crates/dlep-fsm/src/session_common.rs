//! Types and message builders shared by both session FSMs (router and modem).
//!
//! Lives in its own module so neither side reaches across to the other for
//! shared structures, and so M4+ message builders (heartbeat, etc.) have a
//! natural home alongside the existing termination builders.

use std::time::Duration;

use dlep_core::{DataItem, Message, MessageType, StatusCode};

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

pub fn build_session_termination(reason: StatusCode) -> Message {
    Message::new(MessageType::SESSION_TERMINATION).with_item(DataItem::Status {
        code: reason,
        text: String::new(),
    })
}

pub fn build_session_termination_response() -> Message {
    Message::new(MessageType::SESSION_TERMINATION_RESPONSE).with_item(DataItem::Status {
        code: StatusCode::SUCCESS,
        text: String::new(),
    })
}

pub fn extract_status(msg: &Message) -> Option<StatusCode> {
    msg.data_items.iter().find_map(|item| match item {
        DataItem::Status { code, .. } => Some(*code),
        _ => None,
    })
}
