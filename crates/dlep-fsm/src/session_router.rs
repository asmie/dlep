use crate::{AddressChanges, DestinationAddrs};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::merge_link_metrics;
use crate::session_common::{
    SessionConfig, build_destination_announce, build_destination_down_response,
    build_destination_up_response, build_heartbeat, build_session_termination,
    build_session_termination_response, build_session_update_response, extract_destination_mac,
    extract_extensions_supported, extract_heartbeat_interval, extract_status,
    heartbeat_reset_action, local_heartbeat_interval,
};
use crate::timers::{TimerId, TimerKind};
use crate::transaction::TransactionTracker;
use crate::validation::{validate_message, validate_transaction};
use dlep_core::LinkMetrics;

/// Stable timer IDs. Each session has at most one of each kind in flight,
/// so fixed IDs are sufficient.
pub const TIMER_SESSION_INIT: TimerId = TimerId::new(1);
pub const TIMER_TERMINATION: TimerId = TimerId::new(2);
/// Periodic timer that drives outbound `Heartbeat` sends at the local
/// announced interval (RFC 8175 §7.3.1).
pub const TIMER_HEARTBEAT: TimerId = TimerId::new(3);
/// Single-shot deadline armed at `2 × peer_interval`. One fire ⇒ "two
/// consecutive missed heartbeats" ⇒ Terminate with `TIMED_OUT` (RFC 8175
/// §7.3.1).
pub const TIMER_HEARTBEAT_MISSED: TimerId = TimerId::new(4);

/// Router-side session states (RFC 8175 §7.2–§7.5). The runtime awaits
/// `Connector::connect` outside the FSM and feeds `TcpConnected` once that
/// future resolves, so the FSM has no explicit "connecting" state
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
    pub session_metrics: LinkMetrics,
    session_metric_types: HashSet<dlep_core::DataItemType>,
    pub peer_addresses: DestinationAddrs,
    local_addresses: DestinationAddrs,
    config: SessionConfig,
    termination_reason: StatusCode,
    /// Peer's interval, populated by a validated initialization response.
    /// It is absent only before the handshake.
    pub peer_heartbeat_interval: Option<Duration>,
    /// Captured from the peer's `Session Initialization Response`
    /// `ExtensionsSupported` data item at the moment we transition to
    /// `InSession`. Empty if the peer advertised none. Surfaced via
    /// `EmittedEvent::SessionUp { peer_extensions }` so the runtime can
    /// negotiate registered extensions.
    pub peer_extensions: Vec<dlep_core::ExtensionId>,
}

#[derive(Clone, Debug)]
pub struct DestinationState {
    pub up: bool,
    pub metrics: LinkMetrics,
    pub addrs: DestinationAddrs,
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
            session_metrics: LinkMetrics::default(),
            session_metric_types: HashSet::new(),
            peer_addresses: DestinationAddrs::default(),
            local_addresses: DestinationAddrs::default(),
            config,
            termination_reason: StatusCode::SUCCESS,
            peer_heartbeat_interval: None,
            peer_extensions: Vec::new(),
        }
    }

    pub fn state(&self) -> RouterSessionState {
        self.state
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        if let Some(command) = event.command() {
            if let Err(reason) = self.check_command(&event) {
                return vec![FsmAction::Emit(EmittedEvent::CommandRejected(
                    crate::CommandRejection { command, reason },
                ))];
            }
        }
        if let FsmEvent::RecvMessage(msg) = &event {
            if matches!(
                self.state,
                RouterSessionState::SessionInitPending | RouterSessionState::InSession
            ) {
                // A fatal status is echoed verbatim, including its explanation.
                if msg.message_type != MessageType::SESSION_TERMINATION {
                    if let Some(item) = msg.data_items.iter().find(
                        |i| matches!(i, DataItem::Status { code, .. } if code.terminates_session()),
                    ) {
                        return self.protocol_error(item.clone());
                    }
                }
                let initializing = self.state == RouterSessionState::SessionInitPending;
                let checked =
                    validate_message(msg, true, initializing, &self.config.advertised_extensions)
                        .and_then(|()| {
                            if initializing || msg.message_type == MessageType::SESSION_UPDATE {
                                let mut addresses = self.peer_addresses.clone();
                                AddressChanges::from_message(msg).apply_strict(&mut addresses)?;
                            }
                            if initializing {
                                return Ok(());
                            }
                            if msg.data_items.iter().map(DataItem::type_id).any(|t| {
                                (12..=20).contains(&t.0) && !self.session_metric_types.contains(&t)
                            }) {
                                return Err(StatusCode::INVALID_DATA);
                            }
                            if msg.message_type == MessageType::LINK_CHARACTERISTICS_RESPONSE {
                                let received: HashSet<_> = msg
                                    .data_items
                                    .iter()
                                    .map(DataItem::type_id)
                                    .filter(|t| (12..=20).contains(&t.0))
                                    .collect();
                                if received != self.session_metric_types {
                                    return Err(StatusCode::INVALID_DATA);
                                }
                            }
                            let known = extract_destination_mac(msg)
                                .and_then(|mac| self.destinations.get(&mac))
                                .is_some_and(|d| d.up);
                            validate_transaction(msg, &self.tx, known)
                        });
                if let Err(code) = checked {
                    return self.protocol_error(DataItem::Status {
                        code,
                        text: String::new(),
                    });
                }
            }
        }
        if let FsmEvent::ProtocolError(code) = event {
            return self.protocol_error(DataItem::Status {
                code,
                text: String::new(),
            });
        }
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
                if status != StatusCode::SUCCESS {
                    self.protocol_error(DataItem::Status {
                        code: StatusCode::UNEXPECTED_MESSAGE,
                        text: "initialization did not succeed".into(),
                    })
                } else {
                    self.peer_addresses = AddressChanges::from_message(&msg).added;
                    merge_link_metrics(&msg, &mut self.session_metrics);
                    self.session_metric_types = msg
                        .data_items
                        .iter()
                        .map(DataItem::type_id)
                        .filter(|t| (12..=20).contains(&t.0))
                        .collect();
                    self.peer_heartbeat_interval = extract_heartbeat_interval(&msg);
                    self.peer_extensions = match extract_extensions_supported(&msg) {
                        Some(ids) => ids,
                        None => {
                            tracing::debug!(
                                "peer's Session_Initialization_Response omitted ExtensionsSupported \
                                 (RFC 8175 §13.6 optional); treating as no extensions advertised"
                            );
                            Vec::new()
                        }
                    };
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
                    actions.push(FsmAction::Emit(EmittedEvent::SessionUp {
                        peer_extensions: self.peer_extensions.clone(),
                    }));
                    actions.push(FsmAction::Emit(EmittedEvent::SessionMetricsUpdate {
                        metrics: self.session_metrics,
                    }));
                    if !self.peer_addresses.is_empty() {
                        actions.push(FsmAction::Emit(EmittedEvent::SessionAddressesUpdate {
                            changes: Box::new(AddressChanges {
                                added: self.peer_addresses.clone(),
                                removed: DestinationAddrs::default(),
                            }),
                            addresses: self.peer_addresses.clone(),
                        }));
                    }
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
            // Announce a validated destination and apply session defaults.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_UP =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let mut metrics = self.session_metrics;
                merge_link_metrics(&msg, &mut metrics);
                let mut addrs = DestinationAddrs::default();
                self.destination_address_changes(mac, &msg)
                    .apply_lenient(&mut addrs);
                self.destinations.insert(
                    mac,
                    DestinationState {
                        up: true,
                        metrics,
                        addrs: addrs.clone(),
                    },
                );
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
            // Apply metric and address deltas independently; omissions retain
            // previous values. Destination inconsistencies are nonfatal (§13).
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_UPDATE =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let changes = self.destination_address_changes(mac, &msg);
                let destination = self
                    .destinations
                    .get_mut(&mac)
                    .expect("validated destination");
                let old = destination.addrs.clone();
                changes.apply_lenient(&mut destination.addrs);
                let changes = AddressChanges::between(&old, &destination.addrs);
                let mut actions = Vec::new();
                if merge_link_metrics(&msg, &mut destination.metrics) {
                    actions.push(FsmAction::Emit(EmittedEvent::DestinationUpdate {
                        mac,
                        metrics: destination.metrics,
                    }));
                }
                if !changes.is_empty() {
                    actions.push(FsmAction::Emit(EmittedEvent::DestinationAddressesUpdate {
                        mac,
                        changes: Box::new(changes),
                        addresses: destination.addrs.clone(),
                    }));
                }
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            // Remove the validated destination and acknowledge the peer.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_DOWN =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let reason = extract_status(&msg).unwrap_or(StatusCode::SUCCESS);
                self.destinations.remove(&mac);
                let mut actions = vec![
                    FsmAction::SendMessage(build_destination_down_response(
                        mac,
                        StatusCode::SUCCESS,
                    )),
                    FsmAction::Emit(EmittedEvent::DestinationDown { mac, reason }),
                ];
                if let Some(reset) =
                    heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                {
                    actions.push(reset);
                }
                actions
            }
            // Router-originated Down withdraws interest on this session.
            // Keep the entry until the response so updates already in transit
            // can still be processed. Section 8 permits no transaction timeout.
            (RouterSessionState::InSession, FsmEvent::AppDropDestination { mac, .. }) => {
                self.tx
                    .open_destination(mac, crate::transaction::RequestKind::DestinationDown)
                    .expect("checked idle destination");
                vec![FsmAction::SendMessage(
                    crate::session_common::build_destination_down(mac, StatusCode::SUCCESS),
                )]
            }
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_DOWN_RESPONSE =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let reason = extract_status(&msg).expect("validated status");
                self.tx.close_destination(&mac);
                self.destinations.remove(&mac);
                let mut actions = vec![FsmAction::Emit(EmittedEvent::DestinationDown {
                    mac,
                    reason,
                })];
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            // Session_Update: RFC 8175 §12.7 — session-wide metric / L3
            // address change from the peer. §12.8 makes the response
            // MANDATORY ("MUST be sent ... when a Session Update Message is
            // received"), so we always answer, even when the message carried
            // no metrics we could parse. Emit the session-wide metrics only
            // when present.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_UPDATE =>
            {
                let mut actions = vec![FsmAction::SendMessage(build_session_update_response(
                    StatusCode::SUCCESS,
                ))];
                let changes = AddressChanges::from_message(&msg);
                changes
                    .apply_strict(&mut self.peer_addresses)
                    .expect("validated peer addresses");
                if !changes.is_empty() {
                    actions.push(FsmAction::Emit(EmittedEvent::SessionAddressesUpdate {
                        changes: Box::new(changes),
                        addresses: self.peer_addresses.clone(),
                    }));
                }
                if merge_link_metrics(&msg, &mut self.session_metrics) {
                    for destination in self.destinations.values_mut() {
                        merge_link_metrics(&msg, &mut destination.metrics);
                    }
                    let metrics = self.session_metrics;
                    actions.push(FsmAction::Emit(EmittedEvent::SessionMetricsUpdate {
                        metrics,
                    }));
                }
                if let Some(reset) =
                    heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                {
                    actions.push(reset);
                }
                actions
            }
            // Peer answered our Session_Update — free the session-level
            // transaction slot (RFC 8175 §12.8).
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_UPDATE_RESPONSE =>
            {
                self.tx.close_session();
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // Modem answered our Destination_Announce (RFC 8175 §12.14) —
            // free the per-destination transaction slot.
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_ANNOUNCE_RESPONSE =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                self.tx.close_destination(&mac);
                let mut actions = Vec::new();
                if extract_status(&msg) == Some(StatusCode::SUCCESS) {
                    let mut metrics = self.session_metrics;
                    merge_link_metrics(&msg, &mut metrics);
                    let mut addrs = DestinationAddrs::default();
                    self.destination_address_changes(mac, &msg)
                        .apply_lenient(&mut addrs);
                    self.destinations.insert(
                        mac,
                        DestinationState {
                            up: true,
                            metrics,
                            addrs: addrs.clone(),
                        },
                    );
                    actions.push(FsmAction::Emit(EmittedEvent::DestinationUp {
                        mac,
                        metrics,
                        addrs,
                    }));
                }
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            (
                RouterSessionState::InSession,
                FsmEvent::AppRequestLinkCharacteristics { mac, requested },
            ) => {
                let message =
                    crate::session_common::build_link_characteristics_request(mac, &requested);
                self.tx
                    .open_destination(mac, crate::transaction::RequestKind::LinkCharacteristics)
                    .expect("checked idle transaction");
                // RFC 8175 §8: transactions remain pending until a matching
                // response or session reset; heartbeats detect peer failure.
                vec![FsmAction::SendMessage(message)]
            }
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::LINK_CHARACTERISTICS_RESPONSE =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let destination = self
                    .destinations
                    .get_mut(&mac)
                    .expect("pending destination");
                merge_link_metrics(&msg, &mut destination.metrics);
                let metrics = destination.metrics;
                let (status, text) = msg
                    .data_items
                    .iter()
                    .find_map(|item| match item {
                        DataItem::Status { code, text } => Some((*code, text.clone())),
                        _ => None,
                    })
                    .expect("validated status");
                self.tx.close_destination(&mac);
                let mut actions =
                    vec![FsmAction::Emit(EmittedEvent::LinkCharacteristicsResponse {
                        mac,
                        status,
                        text,
                        metrics,
                    })];
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            (RouterSessionState::InSession, FsmEvent::AppSessionAddresses { changes }) => {
                crate::session_common::apply_local_address_update(
                    &mut self.tx,
                    &mut self.local_addresses,
                    changes,
                )
            }
            // Negotiated extension traffic also keeps the session alive.
            (RouterSessionState::InSession, FsmEvent::RecvExtensionMessage) => {
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // New: periodic heartbeat-send timer fires.
            (RouterSessionState::InSession, FsmEvent::TimerExpired(_, TimerKind::Heartbeat)) => {
                vec![FsmAction::SendMessage(build_heartbeat())]
            }
            // New: missed-deadline fires ⇒ "two consecutive missed
            // heartbeats" per RFC §7.3.1 ⇒ Terminate with TIMED_OUT (132).
            // Mirror the InSession+AppShutdown shape: cancel the periodic
            // send timer, send Termination, arm the Termination response
            // deadline, transition to Terminating.
            (
                RouterSessionState::InSession,
                FsmEvent::TimerExpired(_, TimerKind::HeartbeatMissed),
            ) => {
                self.termination_reason = StatusCode::TIMED_OUT;
                self.state = RouterSessionState::Terminating;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::SendMessage(build_session_termination(StatusCode::TIMED_OUT)),
                    FsmAction::StartTimer {
                        id: TIMER_TERMINATION,
                        kind: TimerKind::Termination,
                        duration: self.config.termination_timeout(),
                        periodic: false,
                    },
                ]
            }
            // Router Session Updates may carry addresses, never metrics.
            (RouterSessionState::InSession, FsmEvent::AppSessionUpdate { .. }) => Vec::new(),
            // InSession: app declares interest in a destination the modem
            // has not reported (RFC 8175 §12.13). Router-originated only.
            (RouterSessionState::InSession, FsmEvent::AppAnnounceDestination { mac }) => {
                use crate::transaction::RequestKind;
                self.tx
                    .open_destination(mac, RequestKind::DestinationAnnounce)
                    .expect("checked idle destination");
                vec![FsmAction::SendMessage(build_destination_announce(mac))]
            }
            (RouterSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.termination_reason = reason;
                self.state = RouterSessionState::Terminating;
                vec![
                    FsmAction::CancelTimer(TIMER_HEARTBEAT),
                    FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
                    FsmAction::SendMessage(build_session_termination(reason)),
                    FsmAction::StartTimer {
                        id: TIMER_TERMINATION,
                        kind: TimerKind::Termination,
                        duration: self.config.termination_timeout(),
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
                    FsmAction::Emit(EmittedEvent::SessionDown(self.termination_reason)),
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
                    FsmAction::Emit(EmittedEvent::SessionDown(self.termination_reason)),
                ]
            }

            // Valid heartbeats refresh peer liveness. Unknown/unexpected input
            // is rejected by the validation at the start of step().
            (RouterSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::HEARTBEAT =>
            {
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            (RouterSessionState::InSession, FsmEvent::RecvMessage(_)) => {
                self.protocol_error(DataItem::Status {
                    code: StatusCode::UNEXPECTED_MESSAGE,
                    text: String::new(),
                })
            }
            _ => Vec::new(),
        }
    }

    /// Do not steal an address already associated with another destination or
    /// the peer in this session. Such destination inconsistencies are ignored,
    /// while valid changes and unrelated metrics continue to be processed.
    fn destination_address_changes(&self, mac: MacAddress, msg: &Message) -> AddressChanges {
        let mut changes = AddressChanges::from_message(msg);
        changes.added.v4.retain(|a| {
            changes.removed.v4.contains(a)
                || (!self.peer_addresses.v4.contains(a)
                    && !self
                        .destinations
                        .iter()
                        .any(|(m, d)| *m != mac && d.addrs.v4.contains(a)))
        });
        changes.added.v6.retain(|a| {
            changes.removed.v6.contains(a)
                || (!self.peer_addresses.v6.contains(a)
                    && !self
                        .destinations
                        .iter()
                        .any(|(m, d)| *m != mac && d.addrs.v6.contains(a)))
        });
        changes.added.v4_subnets.retain(|a| {
            changes.removed.v4_subnets.contains(a)
                || (!self.peer_addresses.v4_subnets.contains(a)
                    && !self
                        .destinations
                        .iter()
                        .any(|(m, d)| *m != mac && d.addrs.v4_subnets.contains(a)))
        });
        changes.added.v6_subnets.retain(|a| {
            changes.removed.v6_subnets.contains(a)
                || (!self.peer_addresses.v6_subnets.contains(a)
                    && !self
                        .destinations
                        .iter()
                        .any(|(m, d)| *m != mac && d.addrs.v6_subnets.contains(a)))
        });
        changes
    }

    fn check_command(&self, event: &FsmEvent) -> Result<(), crate::CommandError> {
        use crate::CommandError as E;
        if self.state != RouterSessionState::InSession {
            return Err(E::NotReady);
        }
        if !matches!(
            event,
            FsmEvent::AppDropDestination { .. }
                | FsmEvent::AppAnnounceDestination { .. }
                | FsmEvent::AppRequestLinkCharacteristics { .. }
                | FsmEvent::AppSessionAddresses { .. }
        ) {
            return Err(E::Unsupported);
        }
        let info = event.command().expect("application command");
        if let Some(mac) = info.destination {
            if self.tx.destination_busy(&mac) {
                return Err(E::Busy);
            }
        } else if self.tx.session_busy() {
            return Err(E::Busy);
        }
        match event {
            FsmEvent::AppDropDestination { mac, .. }
            | FsmEvent::AppRequestLinkCharacteristics { mac, .. } => {
                if !self.destinations.get(mac).is_some_and(|d| d.up) {
                    return Err(E::UnknownDestination);
                }
                if let FsmEvent::AppRequestLinkCharacteristics { requested, .. } = event {
                    if requested.is_empty() {
                        return Err(E::InvalidInput);
                    }
                    crate::session_common::build_link_characteristics_request(*mac, requested)
                        .encode()
                        .map_err(|_| E::InvalidInput)?;
                }
            }
            FsmEvent::AppAnnounceDestination { mac } => {
                if self.destinations.get(mac).is_some_and(|d| d.up) {
                    return Err(E::AlreadyExists);
                }
            }
            FsmEvent::AppSessionAddresses { changes } => {
                crate::session_common::validate_local_address_update(
                    &self.local_addresses,
                    changes,
                )?;
            }
            _ => return Err(E::Unsupported),
        }
        Ok(())
    }

    fn protocol_error(&mut self, status: DataItem) -> Vec<FsmAction> {
        let DataItem::Status { code, .. } = &status else {
            unreachable!()
        };
        let code = *code;
        if matches!(
            self.state,
            RouterSessionState::Terminating | RouterSessionState::Terminated
        ) {
            return Vec::new();
        }

        self.state = RouterSessionState::Terminating;
        self.termination_reason = code;
        vec![
            FsmAction::CancelTimer(TIMER_SESSION_INIT),
            FsmAction::CancelTimer(TIMER_HEARTBEAT),
            FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED),
            FsmAction::SendMessage(
                Message::new(MessageType::SESSION_TERMINATION).with_item(status),
            ),
            FsmAction::StartTimer {
                id: TIMER_TERMINATION,
                kind: TimerKind::Termination,
                duration: self.config.termination_timeout(),
                periodic: false,
            },
        ]
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
        .with_item(DataItem::ExtensionsSupported(
            config.advertised_extensions.clone(),
        ))
}
