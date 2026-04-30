use std::collections::HashMap;
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::{
    SessionConfig, build_session_termination, build_session_termination_response, extract_status,
};
use crate::timers::{TimerId, TimerKind};
use crate::transaction::TransactionTracker;

/// Stable timer IDs. M3 only ever has at most one of each kind in flight, so
/// fixed IDs are sufficient; M4+ may need an allocator if heartbeat timers
/// stack on top.
pub const TIMER_SESSION_INIT: TimerId = TimerId::new(1);
pub const TIMER_TERMINATION: TimerId = TimerId::new(2);

/// Router-side session states (RFC 8175 §7.1). The current runtime calls
/// `Connector::connect` synchronously and feeds `TcpConnected` once that
/// future resolves, so the FSM never sits in an explicit "connecting" state
/// — `Closed` transitions straight to `SessionInitPending`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterSessionState {
    Closed,
    SessionInitPending,
    InSession,
    Terminating,
    Terminated,
}

#[derive(Debug)]
pub struct RouterSessionFsm {
    pub state: RouterSessionState,
    pub tx: TransactionTracker,
    pub destinations: HashMap<MacAddress, DestinationState>,
    config: SessionConfig,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationState {
    pub up: bool,
}

impl Default for RouterSessionFsm {
    fn default() -> Self {
        Self::with_config(SessionConfig::default())
    }
}

impl RouterSessionFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            state: RouterSessionState::Closed,
            tx: TransactionTracker::default(),
            destinations: HashMap::new(),
            config,
        }
    }

    pub fn state(&self) -> RouterSessionState {
        self.state
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match (self.state, event) {
            // Closed: TcpConnected fires once the runtime's connect future resolved.
            (RouterSessionState::Closed, FsmEvent::TcpConnected) => {
                self.state = RouterSessionState::SessionInitPending;
                vec![
                    FsmAction::SendMessage(build_session_initialization(&self.config)),
                    FsmAction::StartTimer {
                        id: TIMER_SESSION_INIT,
                        kind: TimerKind::SessionInit,
                        duration: self.config.session_init_timeout,
                        periodic: false,
                    },
                ]
            }
            (RouterSessionState::Closed, FsmEvent::AppShutdown { .. }) => {
                self.state = RouterSessionState::Terminated;
                Vec::new()
            }
            (RouterSessionState::Closed, FsmEvent::TcpClosed) => {
                self.state = RouterSessionState::Terminated;
                Vec::new()
            }

            // SessionInitPending: receive Session Initialization Response.
            (RouterSessionState::SessionInitPending, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_INITIALIZATION_RESPONSE =>
            {
                let status = extract_status(&msg).unwrap_or(StatusCode::SUCCESS);
                if status.terminates_session() {
                    self.state = RouterSessionState::Terminated;
                    vec![
                        FsmAction::CancelTimer(TIMER_SESSION_INIT),
                        FsmAction::CloseTcp,
                        FsmAction::Emit(EmittedEvent::SessionDown(status)),
                    ]
                } else {
                    self.state = RouterSessionState::InSession;
                    vec![
                        FsmAction::CancelTimer(TIMER_SESSION_INIT),
                        FsmAction::ResetHeartbeat,
                        FsmAction::Emit(EmittedEvent::SessionUp),
                    ]
                }
            }
            (
                RouterSessionState::SessionInitPending,
                FsmEvent::TimerExpired(_, TimerKind::SessionInit),
            ) => {
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
            }
            (RouterSessionState::SessionInitPending, FsmEvent::TcpClosed) => {
                self.state = RouterSessionState::Terminated;
                vec![FsmAction::Emit(EmittedEvent::SessionDown(
                    StatusCode::TIMED_OUT,
                ))]
            }
            (RouterSessionState::SessionInitPending, FsmEvent::AppShutdown { reason }) => {
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(reason)),
                ]
            }

            // InSession: heartbeats, peer-initiated termination, app shutdown.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::HEARTBEAT =>
            {
                vec![FsmAction::ResetHeartbeat]
            }
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION =>
            {
                let status = extract_status(&msg).unwrap_or(StatusCode::SHUTTING_DOWN);
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::SendMessage(build_session_termination_response()),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(status)),
                ]
            }
            (RouterSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.state = RouterSessionState::Terminating;
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
            (RouterSessionState::InSession, FsmEvent::TcpClosed) => {
                self.state = RouterSessionState::Terminated;
                vec![FsmAction::Emit(EmittedEvent::SessionDown(
                    StatusCode::TIMED_OUT,
                ))]
            }

            // Terminating: await Session Termination Response or timer.
            (RouterSessionState::Terminating, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION_RESPONSE =>
            {
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_TERMINATION),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::SUCCESS)),
                ]
            }
            (
                RouterSessionState::Terminating,
                FsmEvent::TimerExpired(_, TimerKind::Termination),
            ) => {
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
            }
            (RouterSessionState::Terminating, FsmEvent::TcpClosed) => {
                // Plan §"Risks": treat transport drop during Terminating as
                // success. Avoids a spurious timeout on simultaneous shutdown.
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_TERMINATION),
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::SUCCESS)),
                ]
            }

            // Anything else (destination messages in InSession, stray events
            // in Terminated, unknown message types) — ignore for M3. M5 will
            // reject Destination_* in pre-InSession states with
            // UNEXPECTED_MESSAGE.
            _ => Vec::new(),
        }
    }
}

fn build_session_initialization(config: &SessionConfig) -> Message {
    Message::new(MessageType::SESSION_INITIALIZATION)
        .with_item(DataItem::HeartbeatInterval(Duration::from_millis(
            config.heartbeat_interval_ms.into(),
        )))
        .with_item(DataItem::PeerType {
            flags: PeerFlags::default(),
            description: config.peer_description.clone(),
        })
        .with_item(DataItem::ExtensionsSupported(Vec::new()))
}
