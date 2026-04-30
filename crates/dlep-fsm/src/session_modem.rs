use std::collections::HashMap;
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::{
    SessionConfig, build_session_termination, build_session_termination_response, extract_status,
};
use crate::session_router::{TIMER_SESSION_INIT, TIMER_TERMINATION};
use crate::timers::TimerKind;
use crate::transaction::TransactionTracker;

/// Placeholder link metrics advertised in Session Initialization Response.
/// M5 wires `ModemDaemon::add_destination` to surface real values; M3 just
/// needs the session to come up. RFC 8175 §11.2 mandates all of these in
/// the Response, so we cannot omit them.
const PLACEHOLDER_DATA_RATE_BPS: u64 = 1_000_000_000;
const PLACEHOLDER_RESOURCES: u8 = 100;
const PLACEHOLDER_RLQ: u8 = 100;
const PLACEHOLDER_MTU: u16 = 1500;

/// Modem-side session states (RFC 8175 §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemSessionState {
    Listening,
    AwaitingSessionInit,
    InSession,
    Terminating,
    Terminated,
}

#[derive(Debug)]
pub struct ModemSessionFsm {
    pub state: ModemSessionState,
    pub tx: TransactionTracker,
    pub destinations: HashMap<MacAddress, DestinationState>,
    config: SessionConfig,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationState {
    pub announced: bool,
}

impl Default for ModemSessionFsm {
    fn default() -> Self {
        Self::with_config(SessionConfig {
            peer_description: "dlep-modem".into(),
            ..SessionConfig::default()
        })
    }
}

impl ModemSessionFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            state: ModemSessionState::Listening,
            tx: TransactionTracker::default(),
            destinations: HashMap::new(),
            config,
        }
    }

    pub fn state(&self) -> ModemSessionState {
        self.state
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match (self.state, event) {
            // Listening: a TCP connection arrived. Arm the Session Init deadline.
            (ModemSessionState::Listening, FsmEvent::TcpAccepted) => {
                self.state = ModemSessionState::AwaitingSessionInit;
                vec![FsmAction::StartTimer {
                    id: TIMER_SESSION_INIT,
                    kind: TimerKind::SessionInit,
                    duration: self.config.session_init_timeout,
                    periodic: false,
                }]
            }
            (ModemSessionState::Listening, FsmEvent::AppShutdown { .. }) => {
                self.state = ModemSessionState::Terminated;
                Vec::new()
            }
            (ModemSessionState::Listening, FsmEvent::TcpClosed) => {
                self.state = ModemSessionState::Terminated;
                Vec::new()
            }

            // AwaitingSessionInit: receive Session Initialization, reply with Response.
            (ModemSessionState::AwaitingSessionInit, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_INITIALIZATION =>
            {
                self.state = ModemSessionState::InSession;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::SendMessage(build_session_initialization_response(&self.config)),
                    FsmAction::ResetHeartbeat,
                    FsmAction::Emit(EmittedEvent::SessionUp),
                ]
            }
            (
                ModemSessionState::AwaitingSessionInit,
                FsmEvent::TimerExpired(_, TimerKind::SessionInit),
            ) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
            }
            (ModemSessionState::AwaitingSessionInit, FsmEvent::TcpClosed) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
            }
            (ModemSessionState::AwaitingSessionInit, FsmEvent::AppShutdown { reason }) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(reason)),
                ]
            }

            // InSession: same shape as router; only Session Initialization is asymmetric.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::HEARTBEAT =>
            {
                vec![FsmAction::ResetHeartbeat]
            }
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION =>
            {
                let status = extract_status(&msg).unwrap_or(StatusCode::SHUTTING_DOWN);
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::SendMessage(build_session_termination_response()),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(status)),
                ]
            }
            (ModemSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.state = ModemSessionState::Terminating;
                vec![
                    FsmAction::SendMessage(build_session_termination(reason)),
                    FsmAction::StartTimer {
                        id: TIMER_TERMINATION,
                        kind: TimerKind::Termination,
                        duration: self.config.termination_timeout,
                        periodic: false,
                    },
                ]
            }
            (ModemSessionState::InSession, FsmEvent::TcpClosed) => {
                self.state = ModemSessionState::Terminated;
                vec![FsmAction::Emit(EmittedEvent::SessionDown(
                    StatusCode::TIMED_OUT,
                ))]
            }

            // Terminating: same as router.
            (ModemSessionState::Terminating, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION_RESPONSE =>
            {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_TERMINATION),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::SUCCESS)),
                ]
            }
            (ModemSessionState::Terminating, FsmEvent::TimerExpired(_, TimerKind::Termination)) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
            }
            (ModemSessionState::Terminating, FsmEvent::TcpClosed) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_TERMINATION),
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::SUCCESS)),
                ]
            }

            _ => Vec::new(),
        }
    }
}

fn build_session_initialization_response(config: &SessionConfig) -> Message {
    Message::new(MessageType::SESSION_INITIALIZATION_RESPONSE)
        .with_item(DataItem::Status {
            code: StatusCode::SUCCESS,
            text: String::new(),
        })
        .with_item(DataItem::HeartbeatInterval(Duration::from_millis(
            config.heartbeat_interval_ms.into(),
        )))
        .with_item(DataItem::PeerType {
            flags: PeerFlags::default(),
            description: config.peer_description.clone(),
        })
        .with_item(DataItem::ExtensionsSupported(Vec::new()))
        .with_item(DataItem::Mtu(PLACEHOLDER_MTU))
        .with_item(DataItem::MaxDataRateReceive(PLACEHOLDER_DATA_RATE_BPS))
        .with_item(DataItem::MaxDataRateTransmit(PLACEHOLDER_DATA_RATE_BPS))
        .with_item(DataItem::CurrentDataRateReceive(PLACEHOLDER_DATA_RATE_BPS))
        .with_item(DataItem::CurrentDataRateTransmit(PLACEHOLDER_DATA_RATE_BPS))
        .with_item(DataItem::Latency(Duration::from_micros(0)))
        .with_item(DataItem::Resources(PLACEHOLDER_RESOURCES))
        .with_item(DataItem::RelativeLinkQualityReceive(PLACEHOLDER_RLQ))
        .with_item(DataItem::RelativeLinkQualityTransmit(PLACEHOLDER_RLQ))
}
