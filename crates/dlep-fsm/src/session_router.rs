use std::collections::HashMap;
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::{
    SessionConfig, build_destination_up_response, build_heartbeat, build_session_termination,
    build_session_termination_response, extract_destination_addrs, extract_destination_mac,
    extract_heartbeat_interval, extract_link_metrics, extract_status, heartbeat_reset_action,
    local_heartbeat_interval,
};
use crate::timers::{TimerId, TimerKind};
use crate::transaction::TransactionTracker;

/// Stable timer IDs. Each session has at most one of each kind in flight,
/// so fixed IDs are sufficient.
pub const TIMER_SESSION_INIT: TimerId = TimerId::new(1);
pub const TIMER_TERMINATION: TimerId = TimerId::new(2);
/// Periodic timer that drives outbound `Heartbeat` sends at the local
/// announced interval (RFC 8175 §9, §11.2).
pub const TIMER_HEARTBEAT: TimerId = TimerId::new(3);
/// Single-shot deadline armed at `2 × peer_interval`. One fire ⇒ "two
/// consecutive missed heartbeats" ⇒ Terminate with `TIMED_OUT` (RFC 8175
/// §11.2).
pub const TIMER_HEARTBEAT_MISSED: TimerId = TimerId::new(4);

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
    /// Peer's announced heartbeat interval, captured from the Heartbeat
    /// Interval Data Item in `Session Initialization Response`. `None` means
    /// the field was absent (RFC-non-conformant peer; we are lenient at the
    /// FSM layer). The codec rejects zero and sub-1s intervals before they
    /// reach this state.
    pub peer_heartbeat_interval: Option<Duration>,
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
            peer_heartbeat_interval: None,
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
                    self.peer_heartbeat_interval = extract_heartbeat_interval(&msg);
                    self.state = RouterSessionState::InSession;
                    let mut actions = vec![FsmAction::CancelTimer(TIMER_SESSION_INIT)];
                    actions.push(FsmAction::StartTimer {
                        id: TIMER_HEARTBEAT,
                        kind: TimerKind::Heartbeat,
                        duration: local_heartbeat_interval(&self.config),
                        periodic: true,
                    });
                    if let Some(action) =
                        heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    {
                        actions.push(action);
                    }
                    actions.push(FsmAction::Emit(EmittedEvent::SessionUp));
                    actions
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
            // RFC 8175 §7.2 mandates strict rejection only on the modem
            // side. Router-side defensive symmetry: any message that isn't
            // a Session Initialization Response is by definition out of
            // sequence here, so drop the connection now rather than wait
            // for the SessionInit timer.
            (RouterSessionState::SessionInitPending, FsmEvent::RecvMessage(_)) => {
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA)),
                ]
            }

            // InSession: peer-initiated termination is special (teardown).
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION =>
            {
                let status = extract_status(&msg).unwrap_or(StatusCode::SHUTTING_DOWN);
                self.state = RouterSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                    FsmAction::SendMessage(build_session_termination_response()),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(status)),
                ]
            }
            // Destination_Up: insert into the map, ACK with
            // Destination_Up_Response { SUCCESS }, emit DestinationUp, and
            // reset the missed-heartbeat deadline (RFC §11.2). Malformed
            // inbound — no MAC — is symmetric to the SessionInitPending
            // defensive arm: drop the connection rather than emit a partial
            // event.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_UP =>
            {
                let Some(mac) = extract_destination_mac(&msg) else {
                    self.state = RouterSessionState::Terminated;
                    return vec![
                        FsmAction::CancelTimer(TIMER_HEARTBEAT),
                        FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                        FsmAction::CloseTcp,
                        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA)),
                    ];
                };
                let metrics = extract_link_metrics(&msg).unwrap_or_default();
                let addrs = extract_destination_addrs(&msg);
                self.destinations.insert(mac, DestinationState { up: true });
                let mut actions = vec![
                    FsmAction::SendMessage(build_destination_up_response(mac, StatusCode::SUCCESS)),
                    FsmAction::Emit(EmittedEvent::DestinationUp {
                        mac,
                        metrics,
                        addrs,
                    }),
                ];
                if let Some(reset) =
                    heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                {
                    actions.push(reset);
                }
                actions
            }
            // Catch-all for any other successfully decoded message in
            // InSession (Heartbeat, future Destination_*, etc.) — RFC 8175
            // §11.2 says any received message resets the missed-heartbeat
            // deadline. Stay in InSession.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(_)) => {
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // New: periodic heartbeat-send timer fires.
            (RouterSessionState::InSession, FsmEvent::TimerExpired(_, TimerKind::Heartbeat)) => {
                vec![FsmAction::SendMessage(build_heartbeat())]
            }
            // New: missed-deadline fires ⇒ "two consecutive missed
            // heartbeats" per RFC §11.2 ⇒ Terminate with TIMED_OUT (132).
            // Mirror the InSession+AppShutdown shape: cancel the periodic
            // send timer, send Termination, arm the Termination response
            // deadline, transition to Terminating.
            (
                RouterSessionState::InSession,
                FsmEvent::TimerExpired(_, TimerKind::HeartbeatMissed),
            ) => {
                self.state = RouterSessionState::Terminating;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::SendMessage(build_session_termination(StatusCode::TIMED_OUT)),
                    FsmAction::StartTimer {
                        id: TIMER_TERMINATION,
                        kind: TimerKind::Termination,
                        duration: self.config.termination_timeout,
                        periodic: false,
                    },
                ]
            }
            (RouterSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.state = RouterSessionState::Terminating;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
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
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
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
        .with_item(DataItem::HeartbeatInterval(local_heartbeat_interval(
            config,
        )))
        .with_item(DataItem::PeerType {
            flags: PeerFlags::default(),
            description: config.peer_description.clone(),
        })
        .with_item(DataItem::ExtensionsSupported(Vec::new()))
}
