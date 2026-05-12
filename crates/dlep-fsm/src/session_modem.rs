use std::collections::HashMap;
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::{
    SessionConfig, build_destination_up, build_heartbeat, build_session_termination,
    build_session_termination_response, extract_destination_mac, extract_heartbeat_interval,
    extract_status, heartbeat_reset_action, local_heartbeat_interval,
};
use crate::session_router::{
    TIMER_HEARTBEAT, TIMER_HEARTBEAT_MISSED, TIMER_SESSION_INIT, TIMER_TERMINATION,
};
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
    /// Peer's announced heartbeat interval, captured from the Heartbeat
    /// Interval Data Item in `Session Initialization`. See
    /// [`super::session_router::RouterSessionFsm::peer_heartbeat_interval`]
    /// for the `None`-case semantics.
    pub peer_heartbeat_interval: Option<Duration>,
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
            peer_heartbeat_interval: None,
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
                self.peer_heartbeat_interval = extract_heartbeat_interval(&msg);
                self.state = ModemSessionState::InSession;
                let mut actions = vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::SendMessage(build_session_initialization_response(&self.config)),
                ];
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
            // RFC 8175 §7.2: "If the modem receives any Message other than
            // Session Initialization or it fails to parse the received
            // Message, it MUST NOT send any Message, and it MUST terminate
            // the TCP connection and transition to the Session Reset state."
            // The Session Initialization arm above wins for the typed match;
            // any other message type lands here.
            (ModemSessionState::AwaitingSessionInit, FsmEvent::RecvMessage(_)) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA)),
                ]
            }

            // InSession: peer-initiated termination is special (teardown).
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_TERMINATION =>
            {
                let status = extract_status(&msg).unwrap_or(StatusCode::SHUTTING_DOWN);
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                    FsmAction::SendMessage(build_session_termination_response()),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(status)),
                ]
            }
            // InSession: app asks us to advertise a new destination.
            (
                ModemSessionState::InSession,
                FsmEvent::AppAddDestination {
                    mac,
                    metrics,
                    addrs,
                },
            ) => {
                use crate::transaction::RequestKind;
                if self
                    .tx
                    .open_destination(mac, RequestKind::DestinationUp)
                    .is_err()
                {
                    tracing::debug!(?mac, "duplicate add_destination while Up pending");
                    return Vec::new();
                }
                self.destinations
                    .entry(mac)
                    .or_insert(DestinationState { announced: false });
                vec![FsmAction::SendMessage(build_destination_up(
                    mac, &metrics, &addrs,
                ))]
            }
            // InSession: router replied to our Destination_Up. Close the
            // per-destination transaction. On Success flip `announced`; on
            // any non-Success status drop the local entry so a future
            // add_destination(mac) is a clean retry. RFC 8175 §11.2: every
            // received message resets the missed-heartbeat deadline.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_UP_RESPONSE =>
            {
                let mac = extract_destination_mac(&msg);
                let status = extract_status(&msg).unwrap_or(StatusCode::SUCCESS);
                if let Some(mac) = mac {
                    self.tx.close_destination(&mac);
                    if status == StatusCode::SUCCESS {
                        if let Some(d) = self.destinations.get_mut(&mac) {
                            d.announced = true;
                        }
                    } else {
                        // Router rejected. Drop locally so a later
                        // add_destination for the same MAC is a clean retry.
                        self.destinations.remove(&mac);
                    }
                }
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // Catch-all for any other successfully decoded message —
            // RFC 8175 §11.2 says any received message resets the
            // missed-heartbeat deadline.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(_)) => {
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            (ModemSessionState::InSession, FsmEvent::TimerExpired(_, TimerKind::Heartbeat)) => {
                vec![FsmAction::SendMessage(build_heartbeat())]
            }
            (
                ModemSessionState::InSession,
                FsmEvent::TimerExpired(_, TimerKind::HeartbeatMissed),
            ) => {
                self.state = ModemSessionState::Terminating;
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
            (ModemSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.state = ModemSessionState::Terminating;
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
            (ModemSessionState::InSession, FsmEvent::TcpClosed) => {
                self.state = ModemSessionState::Terminated;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT)),
                ]
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
        .with_item(DataItem::HeartbeatInterval(local_heartbeat_interval(
            config,
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
