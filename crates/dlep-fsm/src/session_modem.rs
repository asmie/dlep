use crate::{AddressChanges, DestinationAddrs};
use std::collections::HashMap;
use std::time::Duration;

use dlep_core::data_item::PeerFlags;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};

use crate::events::{EmittedEvent, FsmAction, FsmEvent};
use crate::session_common::{
    SessionConfig, build_destination_announce_response, build_destination_down,
    build_destination_up, build_destination_update, build_heartbeat, build_session_termination,
    build_session_termination_response, build_session_update, build_session_update_response,
    extract_destination_mac, extract_extensions_supported, extract_heartbeat_interval,
    extract_status, heartbeat_reset_action, local_heartbeat_interval,
};
use crate::session_router::{
    TIMER_HEARTBEAT, TIMER_HEARTBEAT_MISSED, TIMER_SESSION_INIT, TIMER_TERMINATION,
};
use crate::timers::TimerKind;
use crate::transaction::TransactionTracker;
use crate::validation::{validate_message, validate_transaction};
use dlep_core::LinkMetrics;

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
    pub peer_addresses: DestinationAddrs,
    local_addresses: DestinationAddrs,
    session_metrics: LinkMetrics,
    config: SessionConfig,
    termination_reason: StatusCode,
    /// Peer's announced heartbeat interval, captured from the Heartbeat
    /// Interval Data Item in `Session Initialization`. See
    /// [`super::session_router::RouterSessionFsm::peer_heartbeat_interval`]
    /// for the `None`-case semantics.
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
    pub announced: bool,
    pub pending_metrics: bool,
    pub metrics: LinkMetrics,
    pub addrs: crate::events::DestinationAddrs,
    pub advertised_addrs: DestinationAddrs,
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
            peer_addresses: DestinationAddrs::default(),
            local_addresses: DestinationAddrs::default(),
            session_metrics: config.initial_metrics,
            config,
            termination_reason: StatusCode::SUCCESS,
            peer_heartbeat_interval: None,
            peer_extensions: Vec::new(),
        }
    }

    pub fn state(&self) -> ModemSessionState {
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
                ModemSessionState::AwaitingSessionInit | ModemSessionState::InSession
            ) {
                // A fatal status is echoed verbatim, including its explanation.
                if msg.message_type != MessageType::SESSION_TERMINATION {
                    if let Some(item) = msg.data_items.iter().find(
                        |i| matches!(i, DataItem::Status { code, .. } if code.terminates_session()),
                    ) {
                        return self.protocol_error(item.clone());
                    }
                }
                let initializing = self.state == ModemSessionState::AwaitingSessionInit;
                let checked =
                    validate_message(msg, false, initializing, &self.config.advertised_extensions)
                        .and_then(|()| {
                            if initializing || msg.message_type == MessageType::SESSION_UPDATE {
                                let mut addresses = self.peer_addresses.clone();
                                AddressChanges::from_message(msg).apply_strict(&mut addresses)?;
                            }
                            if initializing {
                                return Ok(());
                            }
                            let known = extract_destination_mac(msg)
                                .and_then(|mac| self.destinations.get(&mac))
                                .is_some_and(|d| d.announced);
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
                self.peer_addresses = AddressChanges::from_message(&msg).added;
                self.peer_heartbeat_interval = extract_heartbeat_interval(&msg);
                self.peer_extensions = match extract_extensions_supported(&msg) {
                    Some(ids) => ids,
                    None => {
                        tracing::debug!(
                            "peer's Session_Initialization omitted ExtensionsSupported \
                             (RFC 8175 §13.6 optional); treating as no extensions advertised"
                        );
                        Vec::new()
                    }
                };
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
                actions.push(FsmAction::Emit(EmittedEvent::SessionUp {
                    peer_extensions: self.peer_extensions.clone(),
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
                let mut effective = self.session_metrics;
                crate::session_common::merge_link_metrics(
                    &build_session_update(&metrics),
                    &mut effective,
                );
                let metrics = effective;
                let addrs = addrs.canonical();
                self.tx
                    .open_destination(mac, RequestKind::DestinationUp)
                    .expect("checked idle destination");
                self.destinations.insert(
                    mac,
                    DestinationState {
                        announced: false,
                        pending_metrics: false,
                        metrics,
                        addrs: addrs.canonical(),
                        advertised_addrs: addrs.canonical(),
                    },
                );
                vec![FsmAction::SendMessage(build_destination_up(
                    mac, &metrics, &addrs,
                ))]
            }
            // InSession: router replied to our Destination_Up. Close the
            // per-destination transaction. On Success flip `announced`; on
            // any non-Success status stop updates, retaining modem knowledge
            // so the router may subsequently request Destination Announce.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_UP_RESPONSE =>
            {
                let mut actions = Vec::new();
                let mac = extract_destination_mac(&msg);
                let status = extract_status(&msg).unwrap_or(StatusCode::SUCCESS);
                if let Some(mac) = mac {
                    self.tx.close_destination(&mac);
                    if status == StatusCode::SUCCESS {
                        if let Some(d) = self.destinations.get_mut(&mac) {
                            d.announced = true;
                            let changes = AddressChanges::between(&d.advertised_addrs, &d.addrs);
                            if d.pending_metrics || !changes.is_empty() {
                                let message = if d.pending_metrics {
                                    build_destination_update(mac, &d.metrics)
                                } else {
                                    Message::new(MessageType::DESTINATION_UPDATE)
                                        .with_item(DataItem::MacAddress(mac))
                                };
                                actions.push(FsmAction::SendMessage(changes.append_to(message)));
                                d.pending_metrics = false;
                                d.advertised_addrs = d.addrs.clone();
                            }
                        }
                    } else {
                        // Retain knowledge, but respect the router's refusal.
                        if let Some(d) = self.destinations.get_mut(&mac) {
                            d.announced = false;
                        }
                    }
                }
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            // InSession: app asks us to advertise an updated metric set for
            // an existing destination. RFC 8175 §11.7 — Destination_Update is
            // one-way; there is no Response. Preflight rejects unknown MACs.
            (ModemSessionState::InSession, FsmEvent::AppUpdateMetrics { mac, metrics }) => {
                let destination = self
                    .destinations
                    .get_mut(&mac)
                    .expect("checked destination");
                crate::session_common::merge_link_metrics(
                    &build_session_update(&metrics),
                    &mut destination.metrics,
                );
                if !destination.announced || self.tx.destination_busy(&mac) {
                    destination.pending_metrics = true;
                    return Vec::new();
                }
                vec![FsmAction::SendMessage(build_destination_update(
                    mac, &metrics,
                ))]
            }
            (ModemSessionState::InSession, FsmEvent::AppUpdateAddresses { mac, changes }) => {
                let destination = self
                    .destinations
                    .get_mut(&mac)
                    .expect("checked destination");
                let mut desired = destination.addrs.clone();
                changes.apply_lenient(&mut desired);
                destination.addrs = desired;
                if !destination.announced || self.tx.destination_busy(&mac) {
                    return Vec::new();
                }
                let effective =
                    AddressChanges::between(&destination.advertised_addrs, &destination.addrs);
                if effective.is_empty() {
                    return Vec::new();
                }
                destination.advertised_addrs = destination.addrs.clone();
                vec![FsmAction::SendMessage(
                    effective.append_to(
                        Message::new(MessageType::DESTINATION_UPDATE)
                            .with_item(DataItem::MacAddress(mac)),
                    ),
                )]
            }
            // InSession: app asks us to tear down a previously announced
            // destination. RFC 8175 §11.5 — open a per-destination transaction
            // and send `Destination_Down(mac, reason)`. The local entry stays
            // until the response arrives (symmetric to the Up flow where
            // `announced` flips only on response).
            (ModemSessionState::InSession, FsmEvent::AppDropDestination { mac, reason }) => {
                use crate::transaction::RequestKind;
                if !self.destinations[&mac].announced && !self.tx.destination_busy(&mac) {
                    self.destinations.remove(&mac);
                    return Vec::new();
                }
                self.tx
                    .open_destination(mac, RequestKind::DestinationDown)
                    .expect("checked idle destination");
                vec![FsmAction::SendMessage(build_destination_down(mac, reason))]
            }
            // A router withdraws interest, not physical reachability. Keep
            // local knowledge for a later Announce, but stop reporting this
            // destination on this session (§12.13, §12.15–12.16).
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_DOWN =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let destination = self
                    .destinations
                    .get_mut(&mac)
                    .expect("validated destination");
                destination.announced = false;
                destination.pending_metrics = false;
                let mut actions = vec![
                    FsmAction::SendMessage(crate::session_common::build_destination_down_response(
                        mac,
                        StatusCode::SUCCESS,
                    )),
                    FsmAction::Emit(EmittedEvent::DestinationDown {
                        mac,
                        reason: StatusCode::SUCCESS,
                    }),
                ];
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            // InSession: router replied to our Destination_Down. Close the
            // per-destination transaction, remove the local entry, and reset
            // the missed-heartbeat deadline (RFC §11.2).
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_DOWN_RESPONSE =>
            {
                if let Some(mac) = extract_destination_mac(&msg) {
                    self.tx.close_destination(&mac);
                    self.destinations.remove(&mac);
                }
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // Session_Update: RFC 8175 §12.7 / §12.8 — the response is
            // MANDATORY, so answer unconditionally. See the router-side twin
            // for the reasoning; §12.7 scopes Session Update to "a DLEP
            // participant", so both roles must implement both directions.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
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
                if let Some(reset) =
                    heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                {
                    actions.push(reset);
                }
                actions
            }
            // Peer answered our Session_Update — free the session-level slot.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::SESSION_UPDATE_RESPONSE =>
            {
                self.tx.close_session();
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            // Announce succeeds only when the modem has destination data.
            // Retained destinations declined earlier by this router can be
            // reactivated, with their latest metrics and addresses.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::DESTINATION_ANNOUNCE =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let mut response =
                    build_destination_announce_response(mac, StatusCode::REQUEST_DENIED);
                if let Some(destination) = self.destinations.get_mut(&mac) {
                    response = build_destination_up(mac, &destination.metrics, &destination.addrs);
                    response.message_type = MessageType::DESTINATION_ANNOUNCE_RESPONSE;
                    response.data_items.push(DataItem::Status {
                        code: StatusCode::SUCCESS,
                        text: String::new(),
                    });
                    destination.announced = true;
                    destination.pending_metrics = false;
                    destination.advertised_addrs = destination.addrs.clone();
                }
                let mut actions = vec![
                    FsmAction::SendMessage(response),
                    FsmAction::Emit(EmittedEvent::DestinationAnnounced {
                        mac,
                        requested_addresses: AddressChanges::from_message(&msg),
                    }),
                ];
                if let Some(reset) =
                    heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                {
                    actions.push(reset);
                }
                actions
            }
            // This modem has no backend capable of changing radio parameters.
            // The mandatory response reports actual stored metrics and denies
            // the requested alteration, rather than claiming it was applied.
            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::LINK_CHARACTERISTICS_REQUEST =>
            {
                let mac = extract_destination_mac(&msg).expect("validated MAC");
                let metrics = self.destinations[&mac].metrics;
                let mut actions = vec![FsmAction::SendMessage(
                    crate::session_common::build_link_characteristics_response(
                        mac,
                        StatusCode::REQUEST_DENIED,
                        &metrics,
                    ),
                )];
                actions.extend(heartbeat_reset_action(
                    TIMER_HEARTBEAT_MISSED,
                    self.peer_heartbeat_interval,
                ));
                actions
            }
            (ModemSessionState::InSession, FsmEvent::AppSessionAddresses { changes }) => {
                crate::session_common::apply_local_address_update(
                    &mut self.tx,
                    &mut self.local_addresses,
                    changes,
                )
            }
            // Negotiated extension traffic also keeps the session alive.
            (ModemSessionState::InSession, FsmEvent::RecvExtensionMessage) => {
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
                self.termination_reason = StatusCode::TIMED_OUT;
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
            // InSession: app pushes session-wide metric changes to the router
            // (RFC 8175 §12.7). Occupies the single session-level
            // transaction slot until the Response arrives.
            (ModemSessionState::InSession, FsmEvent::AppSessionUpdate { metrics }) => {
                use crate::transaction::RequestKind;
                self.tx
                    .open_session(RequestKind::SessionUpdate)
                    .expect("checked idle session");
                // Subsequent Link Characteristics Responses must report the
                // same effective metrics we just advertised for every link.
                let message = build_session_update(&metrics);
                crate::session_common::merge_link_metrics(&message, &mut self.session_metrics);
                for destination in self.destinations.values_mut() {
                    crate::session_common::merge_link_metrics(&message, &mut destination.metrics);
                }
                vec![FsmAction::SendMessage(message)]
            }
            (ModemSessionState::InSession, FsmEvent::AppShutdown { reason }) => {
                self.termination_reason = reason;
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
                    FsmAction::Emit(EmittedEvent::SessionDown(self.termination_reason)),
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
                    FsmAction::Emit(EmittedEvent::SessionDown(self.termination_reason)),
                ]
            }

            (ModemSessionState::InSession, FsmEvent::RecvMessage(msg))
                if msg.message_type == MessageType::HEARTBEAT =>
            {
                heartbeat_reset_action(TIMER_HEARTBEAT_MISSED, self.peer_heartbeat_interval)
                    .into_iter()
                    .collect()
            }
            (ModemSessionState::InSession, FsmEvent::RecvMessage(_)) => {
                self.protocol_error(DataItem::Status {
                    code: StatusCode::UNEXPECTED_MESSAGE,
                    text: String::new(),
                })
            }
            _ => Vec::new(),
        }
    }

    fn valid_metrics(&self, metrics: &LinkMetrics) -> bool {
        metrics.supported_by(&self.config.initial_metrics)
            && build_session_update(metrics).encode().is_ok()
    }

    fn check_command(&self, event: &FsmEvent) -> Result<(), crate::CommandError> {
        use crate::CommandError as E;
        use crate::transaction::RequestKind;
        if self.state != ModemSessionState::InSession {
            return Err(E::NotReady);
        }
        let info = event.command().expect("application command");
        match event {
            FsmEvent::AppAnnounceDestination { .. }
            | FsmEvent::AppRequestLinkCharacteristics { .. } => return Err(E::Unsupported),
            _ => {}
        }
        if let Some(mac) = info.destination {
            if let Some(pending) = self.tx.per_destination.get(&mac) {
                // Updates during Up are retained/coalesced. During Down, the
                // destination will be removed, so accepting updates loses them.
                let retained = matches!(
                    event,
                    FsmEvent::AppUpdateMetrics { .. } | FsmEvent::AppUpdateAddresses { .. }
                ) && pending.kind == RequestKind::DestinationUp;
                if !retained {
                    return Err(E::Busy);
                }
            }
        } else if self.tx.session_busy() {
            return Err(E::Busy);
        }
        match event {
            FsmEvent::AppAddDestination {
                mac,
                metrics,
                addrs,
            } => {
                if self.destinations.contains_key(mac) {
                    return Err(E::AlreadyExists);
                }
                if !self.valid_metrics(metrics) {
                    return Err(E::InvalidInput);
                }
                AddressChanges {
                    added: addrs.clone(),
                    removed: Default::default(),
                }
                .validate()
                .map_err(|_| E::InvalidInput)?;
                let mut effective = self.session_metrics;
                crate::session_common::merge_link_metrics(
                    &build_session_update(metrics),
                    &mut effective,
                );
                build_destination_up(*mac, &effective, addrs)
                    .encode()
                    .map_err(|_| E::InvalidInput)?;
            }
            FsmEvent::AppDropDestination { mac, .. } => {
                if !self.destinations.contains_key(mac) {
                    return Err(E::UnknownDestination);
                }
            }
            FsmEvent::AppUpdateMetrics { mac, metrics } => {
                if !self.destinations.contains_key(mac) {
                    return Err(E::UnknownDestination);
                }
                if !self.valid_metrics(metrics) {
                    return Err(E::InvalidInput);
                }
            }
            FsmEvent::AppUpdateAddresses { mac, changes } => {
                let destination = self.destinations.get(mac).ok_or(E::UnknownDestination)?;
                changes.validate().map_err(|_| E::InvalidInput)?;
                let mut desired = destination.addrs.clone();
                changes.apply_lenient(&mut desired);
                build_destination_up(*mac, &destination.metrics, &desired)
                    .encode()
                    .map_err(|_| E::InvalidInput)?;
            }
            FsmEvent::AppSessionUpdate { metrics } => {
                if !self.valid_metrics(metrics) {
                    return Err(E::InvalidInput);
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
            ModemSessionState::Terminating | ModemSessionState::Terminated
        ) {
            return Vec::new();
        }
        if self.state == ModemSessionState::AwaitingSessionInit {
            self.state = ModemSessionState::Terminated;
            return vec![
                FsmAction::CancelTimer(TIMER_SESSION_INIT),
                FsmAction::CloseTcp,
                FsmAction::Emit(EmittedEvent::SessionDown(code)),
            ];
        }
        self.state = ModemSessionState::Terminating;
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
                duration: self.config.termination_timeout,
                periodic: false,
            },
        ]
    }
}

fn build_session_initialization_response(config: &SessionConfig) -> Message {
    crate::session_common::push_metric_items(
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
            .with_item(DataItem::ExtensionsSupported(
                config.advertised_extensions.clone(),
            )),
        &config.initial_metrics,
    )
}
