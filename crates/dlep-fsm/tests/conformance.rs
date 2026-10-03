//! Regression cases from the RFC 8175 audit. Each session performs the real
//! initialization exchange rather than bypassing setup by assigning a state.
use dlep_core::{
    DataItem, DataItemType, MacAddress, Message, MessageType, Signal, SignalType, StatusCode,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{
    DestinationAddrs, FsmAction, FsmEvent, LinkMetrics, SessionConfig, TIMER_HEARTBEAT,
    TIMER_HEARTBEAT_MISSED, TIMER_SESSION_INIT, TIMER_TERMINATION, TimerKind,
};
use std::time::Duration;

fn mac() -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
}
fn sessions() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::with_config(dlep_fsm::SessionConfig {
        initial_metrics: LinkMetrics {
            mtu: Some(1500),
            ..Default::default()
        },
        ..Default::default()
    });
    m.step(FsmEvent::TcpAccepted);
    let init = sent(
        r.step(FsmEvent::TcpConnected),
        MessageType::SESSION_INITIALIZATION,
    );
    let response = sent(
        m.step(FsmEvent::RecvMessage(init)),
        MessageType::SESSION_INITIALIZATION_RESPONSE,
    );
    r.step(FsmEvent::RecvMessage(response));
    (r, m)
}
fn sent(actions: Vec<FsmAction>, ty: MessageType) -> Message {
    actions
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) if m.message_type == ty => Some(m),
            _ => None,
        })
        .expect("expected outbound message")
}
fn terminates(actions: &[FsmAction]) -> bool {
    actions.iter().any(|a| matches!(a, FsmAction::SendMessage(m) if m.message_type == MessageType::SESSION_TERMINATION))
}
fn status(code: StatusCode) -> DataItem {
    DataItem::Status {
        code,
        text: "reason".into(),
    }
}

#[test]
fn empty_initialization_must_not_establish_session() {
    let mut m = ModemSessionFsm::new();
    m.step(FsmEvent::TcpAccepted);
    m.step(FsmEvent::RecvMessage(Message::new(
        MessageType::SESSION_INITIALIZATION,
    )));
    assert_ne!(m.state(), ModemSessionState::InSession);
}
#[test]
fn unknown_message_must_terminate() {
    let (mut r, _) = sessions();
    assert!(terminates(
        &r.step(FsmEvent::RecvMessage(Message::new(MessageType(65000))))
    ));
}
#[test]
fn duplicate_metric_must_terminate() {
    let (mut r, _) = sessions();
    let msg = Message::new(MessageType::SESSION_UPDATE)
        .with_item(DataItem::Latency(Duration::from_micros(1)))
        .with_item(DataItem::Latency(Duration::from_micros(2)));
    assert!(terminates(&r.step(FsmEvent::RecvMessage(msg))));
}
#[test]
fn fatal_response_status_must_terminate() {
    let (mut r, _) = sessions();
    r.step(FsmEvent::AppSessionUpdate {
        metrics: LinkMetrics::default(),
    });
    let msg = Message::new(MessageType::SESSION_UPDATE_RESPONSE)
        .with_item(status(StatusCode::INVALID_DATA));
    assert!(terminates(&r.step(FsmEvent::RecvMessage(msg))));
}
#[test]
fn update_for_unannounced_destination_must_terminate() {
    let (mut r, _) = sessions();
    let msg = Message::new(MessageType::DESTINATION_UPDATE).with_item(DataItem::MacAddress(mac()));
    assert!(terminates(&r.step(FsmEvent::RecvMessage(msg))));
}
#[test]
fn update_must_wait_for_destination_up_response() {
    let (_, mut m) = sessions();
    m.step(FsmEvent::AppAddDestination {
        mac: mac(),
        metrics: LinkMetrics::default(),
        addrs: DestinationAddrs::default(),
    });
    let changed = LinkMetrics {
        latency: Duration::from_millis(123),
        ..LinkMetrics::default()
    };
    let actions = m.step(FsmEvent::AppUpdateMetrics {
        mac: mac(),
        metrics: changed,
    });
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_)))
    );
    let response = Message::new(MessageType::DESTINATION_UP_RESPONSE)
        .with_item(DataItem::MacAddress(mac()))
        .with_item(status(StatusCode::SUCCESS));
    let update = sent(
        m.step(FsmEvent::RecvMessage(response)),
        MessageType::DESTINATION_UPDATE,
    );
    assert!(
        update
            .data_items
            .iter()
            .any(|item| matches!(item, DataItem::Latency(value) if *value == changed.latency))
    );
}
#[test]
fn conflicting_inbound_transaction_must_terminate() {
    let (_, mut m) = sessions();
    m.step(FsmEvent::AppSessionUpdate {
        metrics: LinkMetrics::default(),
    });
    assert!(terminates(&m.step(FsmEvent::RecvMessage(Message::new(
        MessageType::SESSION_UPDATE
    )))));
}
#[test]
fn mismatched_response_must_not_close_destination_up_transaction() {
    let (_, mut m) = sessions();
    m.step(FsmEvent::AppAddDestination {
        mac: mac(),
        metrics: LinkMetrics::default(),
        addrs: DestinationAddrs::default(),
    });
    m.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_DOWN_RESPONSE)
            .with_item(DataItem::MacAddress(mac()))
            .with_item(status(StatusCode::SUCCESS)),
    ));
    assert!(m.tx.destination_busy(&mac()));
}
#[test]
fn router_must_not_send_metric_items_in_session_update() {
    let (mut r, _) = sessions();
    let actions = r.step(FsmEvent::AppSessionUpdate {
        metrics: LinkMetrics::default(),
    });
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(m) if !m.data_items.is_empty()))
    );
}
#[test]
fn successful_announce_response_must_surface_destination() {
    let (mut r, _) = sessions();
    r.step(FsmEvent::AppAnnounceDestination { mac: mac() });
    let actions = r.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_ANNOUNCE_RESPONSE)
            .with_item(DataItem::MacAddress(mac()))
            .with_item(status(StatusCode::SUCCESS)),
    ));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::DestinationUp { .. })))
    );
}
#[test]
fn offer_without_connection_point_must_use_source() {
    let mut r = dlep_fsm::discovery_router::RouterDiscoveryFsm::new();
    r.step(FsmEvent::AppStartDiscovery);
    let actions = r.step(FsmEvent::RecvSignal {
        signal: Signal::new(SignalType::PEER_OFFER),
        from: "192.0.2.1:854".parse().unwrap(),
    });
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::PeerDiscovered { .. })))
    );
}
#[test]
fn partial_metric_update_must_preserve_previous_rate() {
    let (mut r, mut m) = sessions();
    let metrics = LinkMetrics {
        current_data_rate_tx_bps: 12345,
        ..LinkMetrics::default()
    };
    let up = sent(
        m.step(FsmEvent::AppAddDestination {
            mac: mac(),
            metrics,
            addrs: DestinationAddrs::default(),
        }),
        MessageType::DESTINATION_UP,
    );
    r.step(FsmEvent::RecvMessage(up));
    let actions = r.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_UPDATE)
            .with_item(DataItem::MacAddress(mac()))
            .with_item(DataItem::Latency(Duration::from_micros(12))),
    ));
    let metrics = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::Emit(EmittedEvent::DestinationUpdate { metrics, .. }) => Some(metrics),
            _ => None,
        })
        .unwrap();
    // The public event has no presence mask; it must provide merged values
    // (or the API must be changed to express a delta).
    assert_eq!(metrics.current_data_rate_tx_bps, 12345);
}

#[test]
fn fatal_status_is_echoed_including_text() {
    let (mut r, _) = sessions();
    let msg = Message::new(MessageType::SESSION_UPDATE_RESPONSE).with_item(DataItem::Status {
        code: StatusCode::INVALID_DATA,
        text: "peer explanation".into(),
    });
    let termination = sent(
        r.step(FsmEvent::RecvMessage(msg)),
        MessageType::SESSION_TERMINATION,
    );
    assert!(
        matches!(&termination.data_items[0], DataItem::Status { code: StatusCode::INVALID_DATA, text } if text == "peer explanation")
    );
}

#[test]
fn unknown_items_and_wrong_direction_are_rejected() {
    let (mut r, mut m) = sessions();
    let msg = Message::new(MessageType::SESSION_UPDATE).with_item(DataItem::Unknown(
        dlep_core::RawDataItem {
            type_id: dlep_core::DataItemType(65000),
            value: vec![1].into(),
        },
    ));
    assert!(terminates(&r.step(FsmEvent::RecvMessage(msg))));
    assert!(terminates(&m.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_UP).with_item(DataItem::MacAddress(mac()))
    ))));
}

#[test]
fn defaults_and_session_deltas_apply_to_existing_and_new_destinations() {
    let (mut r, _) = sessions();
    let rate = r.session_metrics.current_data_rate_tx_bps;
    let actions = r.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_UP).with_item(DataItem::MacAddress(mac())),
    ));
    assert!(actions.iter().any(|a| matches!(a, FsmAction::Emit(EmittedEvent::DestinationUp { metrics, .. }) if metrics.current_data_rate_tx_bps == rate)));
    r.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_UPDATE)
            .with_item(DataItem::MacAddress(mac()))
            .with_item(DataItem::CurrentDataRateTransmit(12)),
    ));
    r.step(FsmEvent::RecvMessage(
        Message::new(MessageType::SESSION_UPDATE).with_item(DataItem::CurrentDataRateTransmit(34)),
    ));
    assert_eq!(r.destinations[&mac()].metrics.current_data_rate_tx_bps, 34);
    assert_eq!(r.session_metrics.current_data_rate_tx_bps, 34);
    assert_eq!(
        r.destinations[&mac()].metrics.max_data_rate_tx_bps,
        r.session_metrics.max_data_rate_tx_bps
    );
}

#[test]
fn declined_destination_can_be_announced_then_updated() {
    let (mut r, mut m) = sessions();
    let _up = m.step(FsmEvent::AppAddDestination {
        mac: mac(),
        metrics: LinkMetrics {
            mtu: Some(1400),
            ..LinkMetrics::default()
        },
        addrs: DestinationAddrs::default(),
    });
    m.step(FsmEvent::RecvMessage(
        Message::new(MessageType::DESTINATION_UP_RESPONSE)
            .with_item(DataItem::MacAddress(mac()))
            .with_item(status(StatusCode::NOT_INTERESTED)),
    ));
    let announce = sent(
        r.step(FsmEvent::AppAnnounceDestination { mac: mac() }),
        MessageType::DESTINATION_ANNOUNCE,
    );
    let response = sent(
        m.step(FsmEvent::RecvMessage(announce)),
        MessageType::DESTINATION_ANNOUNCE_RESPONSE,
    );
    r.step(FsmEvent::RecvMessage(response));
    assert!(m.destinations[&mac()].announced);
    assert_eq!(r.destinations[&mac()].metrics.mtu, Some(1400));
    let update = sent(
        m.step(FsmEvent::AppUpdateMetrics {
            mac: mac(),
            metrics: LinkMetrics {
                mtu: Some(1300),
                ..LinkMetrics::default()
            },
        }),
        MessageType::DESTINATION_UPDATE,
    );
    r.step(FsmEvent::RecvMessage(update));
    assert_eq!(r.destinations[&mac()].metrics.mtu, Some(1300));
}

#[test]
fn destination_up_without_mac_terminates_with_invalid_data() {
    let (mut r, _) = sessions();
    let actions = r.step(FsmEvent::RecvMessage(Message::new(
        MessageType::DESTINATION_UP,
    )));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::DestinationUp { .. })))
    );
    let termination = sent(actions, MessageType::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|item| matches!(
        item,
        DataItem::Status {
            code: StatusCode::INVALID_DATA,
            ..
        }
    )));
    assert_eq!(
        r.state(),
        dlep_fsm::session_router::RouterSessionState::Terminating
    );
}

#[test]
fn terminating_sessions_ignore_messages_without_restarting_the_deadline() {
    let (mut r, mut m) = sessions();
    r.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    m.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    // Includes malformed typed content, a fatal response, and simultaneous
    // termination: section 7.4 only permits the expected response here.
    let messages = [
        Message::new(MessageType::HEARTBEAT),
        Message::new(MessageType(65000)),
        Message::new(MessageType::DESTINATION_UP),
        Message::new(MessageType::SESSION_UPDATE_RESPONSE)
            .with_item(status(StatusCode::INVALID_DATA)),
        Message::new(MessageType::SESSION_TERMINATION).with_item(status(StatusCode::SHUTTING_DOWN)),
    ];
    for msg in messages {
        assert!(r.step(FsmEvent::RecvMessage(msg.clone())).is_empty());
        assert!(m.step(FsmEvent::RecvMessage(msg)).is_empty());
    }
    for actions in [
        r.step(FsmEvent::RecvMessage(Message::new(
            MessageType::SESSION_TERMINATION_RESPONSE,
        ))),
        m.step(FsmEvent::RecvMessage(Message::new(
            MessageType::SESSION_TERMINATION_RESPONSE,
        ))),
    ] {
        assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(
                    a,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::SHUTTING_DOWN))
                ))
                .count(),
            1
        );
    }
    assert!(r.step(FsmEvent::TcpClosed).is_empty());
    assert!(m.step(FsmEvent::TcpClosed).is_empty());
}

#[test]
fn modem_termination_timeout_closes_once_and_reports_timeout() {
    let (_, mut m) = sessions();
    let actions = m.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    let id = actions
        .iter()
        .find_map(|action| match action {
            FsmAction::StartTimer {
                id,
                kind: dlep_fsm::TimerKind::Termination,
                ..
            } => Some(*id),
            _ => None,
        })
        .unwrap();
    let actions = m.step(FsmEvent::TimerExpired(id, dlep_fsm::TimerKind::Termination));
    assert!(matches!(
        actions.as_slice(),
        [
            FsmAction::CloseTcp,
            FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::TIMED_OUT))
        ]
    ));
    assert_eq!(m.state(), ModemSessionState::Terminated);
    assert!(
        m.step(FsmEvent::TimerExpired(id, dlep_fsm::TimerKind::Termination))
            .is_empty()
    );
    assert!(
        m.step(FsmEvent::RecvMessage(Message::new(
            MessageType::SESSION_TERMINATION_RESPONSE
        )))
        .is_empty()
    );
}

#[test]
fn initialization_without_optional_extensions_preserves_heartbeat_negotiation() {
    let mut r = RouterSessionFsm::with_config(SessionConfig {
        heartbeat_interval_ms: 2_000,
        ..Default::default()
    });
    let mut m = ModemSessionFsm::with_config(SessionConfig {
        heartbeat_interval_ms: 3_000,
        ..Default::default()
    });
    m.step(FsmEvent::TcpAccepted);
    let mut init = sent(
        r.step(FsmEvent::TcpConnected),
        MessageType::SESSION_INITIALIZATION,
    );
    init.data_items
        .retain(|i| i.type_id() != DataItemType::EXTENSIONS_SUPPORTED);
    let modem_actions = m.step(FsmEvent::RecvMessage(init));
    let mut response = modem_actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(msg)
                if msg.message_type == MessageType::SESSION_INITIALIZATION_RESPONSE =>
            {
                Some(msg.clone())
            }
            _ => None,
        })
        .expect("initialization response");
    response
        .data_items
        .retain(|i| i.type_id() != DataItemType::EXTENSIONS_SUPPORTED);
    let router_actions = r.step(FsmEvent::RecvMessage(response));
    assert_eq!(r.state(), RouterSessionState::InSession);
    assert_eq!(m.state(), ModemSessionState::InSession);
    assert!(r.peer_extensions.is_empty() && m.peer_extensions.is_empty());
    assert_eq!(r.peer_heartbeat_interval, Some(Duration::from_secs(3)));
    assert_eq!(m.peer_heartbeat_interval, Some(Duration::from_secs(2)));
    for (actions, local, peer) in [(router_actions, 2, 3), (modem_actions, 3, 2)] {
        assert!(actions.iter().any(|a| matches!(a,
            FsmAction::CancelTimer(id) if *id == TIMER_SESSION_INIT)));
        assert_eq!(actions.iter().filter(|a| matches!(a,
            FsmAction::Emit(EmittedEvent::SessionUp { peer_extensions }) if peer_extensions.is_empty())).count(), 1);
        assert!(actions.iter().any(|a| matches!(a,
            FsmAction::StartTimer { id: TIMER_HEARTBEAT, kind: TimerKind::Heartbeat, duration, periodic: true }
                if *duration == Duration::from_secs(local))));
        assert!(actions.iter().any(|a| matches!(a,
            FsmAction::ResetHeartbeat { timer_id: TIMER_HEARTBEAT_MISSED, missed_deadline }
                if *missed_deadline == Duration::from_secs(peer * 2))));
    }
}

#[test]
fn each_required_initialization_item_is_checked_before_session_up() {
    for missing in [DataItemType::PEER_TYPE, DataItemType::HEARTBEAT_INTERVAL] {
        let mut r = RouterSessionFsm::new();
        let mut m = ModemSessionFsm::new();
        m.step(FsmEvent::TcpAccepted);
        let mut init = sent(
            r.step(FsmEvent::TcpConnected),
            MessageType::SESSION_INITIALIZATION,
        );
        init.data_items.retain(|i| i.type_id() != missing);
        let actions = m.step(FsmEvent::RecvMessage(init));
        assert_eq!(m.state(), ModemSessionState::Terminated, "{missing:?}");
        assert!(
            matches!(
                actions.as_slice(),
                [
                    FsmAction::CancelTimer(TIMER_SESSION_INIT),
                    FsmAction::CloseTcp,
                    FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
                ]
            ),
            "{missing:?}: {actions:?}"
        );
    }
    for missing in [
        DataItemType::STATUS,
        DataItemType::PEER_TYPE,
        DataItemType::HEARTBEAT_INTERVAL,
        DataItemType::MAXIMUM_DATA_RATE_RECEIVE,
        DataItemType::MAXIMUM_DATA_RATE_TRANSMIT,
        DataItemType::CURRENT_DATA_RATE_RECEIVE,
        DataItemType::CURRENT_DATA_RATE_TRANSMIT,
        DataItemType::LATENCY,
    ] {
        let mut r = RouterSessionFsm::new();
        let mut m = ModemSessionFsm::new();
        m.step(FsmEvent::TcpAccepted);
        let init = sent(
            r.step(FsmEvent::TcpConnected),
            MessageType::SESSION_INITIALIZATION,
        );
        let mut response = sent(
            m.step(FsmEvent::RecvMessage(init)),
            MessageType::SESSION_INITIALIZATION_RESPONSE,
        );
        response.data_items.retain(|i| i.type_id() != missing);
        let actions = r.step(FsmEvent::RecvMessage(response));
        assert_eq!(r.state(), RouterSessionState::Terminating, "{missing:?}");
        assert!(
            !actions.iter().any(|a| matches!(a, FsmAction::Emit(_))),
            "{missing:?}"
        );
        let termination = sent(actions, MessageType::SESSION_TERMINATION);
        assert!(
            matches!(
                termination.data_items.as_slice(),
                [DataItem::Status {
                    code: StatusCode::INVALID_DATA,
                    ..
                }]
            ),
            "{missing:?}"
        );
        assert_eq!(r.peer_heartbeat_interval, None);
        assert!(r.peer_extensions.is_empty());
    }
}

#[test]
fn modem_stopped_before_tcp_accept_emits_no_session_lifecycle_events() {
    for event in [
        FsmEvent::TcpClosed,
        FsmEvent::AppShutdown {
            reason: StatusCode::SHUTTING_DOWN,
        },
    ] {
        let mut m = ModemSessionFsm::new();
        assert!(m.step(event).is_empty());
        assert_eq!(m.state(), ModemSessionState::Terminated);
        assert!(m.step(FsmEvent::TcpAccepted).is_empty());
        assert!(m.step(FsmEvent::TcpClosed).is_empty());
        assert_eq!(m.state(), ModemSessionState::Terminated);
    }
}

#[test]
fn initialization_decode_error_closes_modem_without_sending_a_message() {
    let mut m = ModemSessionFsm::new();
    m.step(FsmEvent::TcpAccepted);
    let actions = m.step(FsmEvent::ProtocolError(StatusCode::INVALID_DATA));
    assert!(matches!(
        actions.as_slice(),
        [
            FsmAction::CancelTimer(TIMER_SESSION_INIT),
            FsmAction::CloseTcp,
            FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
        ]
    ));
    assert_eq!(m.state(), ModemSessionState::Terminated);
    assert!(
        m.step(FsmEvent::ProtocolError(StatusCode::UNKNOWN_MESSAGE))
            .is_empty()
    );
    assert!(m.step(FsmEvent::TcpClosed).is_empty());
    assert!(
        m.step(FsmEvent::TimerExpired(
            TIMER_SESSION_INIT,
            TimerKind::SessionInit
        ))
        .is_empty()
    );
}

#[test]
fn modem_echoes_fatal_response_status_and_reports_it_after_acknowledgement() {
    let (_, mut m) = sessions();
    sent(
        m.step(FsmEvent::AppSessionUpdate {
            metrics: LinkMetrics::default(),
        }),
        MessageType::SESSION_UPDATE,
    );
    let fatal = DataItem::Status {
        code: StatusCode::INVALID_DATA,
        text: "peer rejected update: café".into(),
    };
    let actions = m.step(FsmEvent::RecvMessage(
        Message::new(MessageType::SESSION_UPDATE_RESPONSE).with_item(fatal),
    ));
    assert_eq!(m.state(), ModemSessionState::Terminating);
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::CloseTcp | FsmAction::Emit(_)))
    );
    let termination = sent(actions, MessageType::SESSION_TERMINATION);
    assert!(matches!(termination.data_items.as_slice(),
        [DataItem::Status { code: StatusCode::INVALID_DATA, text }]
            if text == "peer rejected update: café"));
    let actions = m.step(FsmEvent::RecvMessage(Message::new(
        MessageType::SESSION_TERMINATION_RESPONSE,
    )));
    assert!(matches!(
        actions.as_slice(),
        [
            FsmAction::CancelTimer(TIMER_TERMINATION),
            FsmAction::CloseTcp,
            FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
        ]
    ));
    assert_eq!(m.state(), ModemSessionState::Terminated);
    assert!(m.step(FsmEvent::TcpClosed).is_empty());
}

#[test]
fn repeated_decode_errors_do_not_restart_teardown_or_replace_its_reason() {
    for tcp_closed in [false, true] {
        let (mut r, mut m) = sessions();
        let steps: [&mut dyn FnMut(FsmEvent) -> Vec<FsmAction>; 2] =
            [&mut |event| r.step(event), &mut |event| m.step(event)];
        for step in steps {
            let actions = step(FsmEvent::ProtocolError(StatusCode::INVALID_DATA));
            assert!(terminates(&actions));
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(
                        a,
                        FsmAction::StartTimer {
                            id: TIMER_TERMINATION,
                            kind: TimerKind::Termination,
                            periodic: false,
                            ..
                        }
                    ))
                    .count(),
                1
            );
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, FsmAction::CloseTcp | FsmAction::Emit(_)))
            );
            assert!(step(FsmEvent::ProtocolError(StatusCode::UNKNOWN_MESSAGE)).is_empty());
            let actions = step(if tcp_closed {
                FsmEvent::TcpClosed
            } else {
                FsmEvent::RecvMessage(Message::new(MessageType::SESSION_TERMINATION_RESPONSE))
            });
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(
                        a,
                        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
                    ))
                    .count(),
                1
            );
            assert_eq!(
                actions
                    .iter()
                    .filter(|a| matches!(a, FsmAction::CloseTcp))
                    .count(),
                usize::from(!tcp_closed)
            );
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_TERMINATION)))
            );
            assert!(step(FsmEvent::ProtocolError(StatusCode::TIMED_OUT)).is_empty());
            assert!(step(FsmEvent::TcpClosed).is_empty());
            assert!(
                step(FsmEvent::TimerExpired(
                    TIMER_TERMINATION,
                    TimerKind::Termination
                ))
                .is_empty()
            );
        }
        assert_eq!(r.state(), RouterSessionState::Terminated);
        assert_eq!(m.state(), ModemSessionState::Terminated);
    }
}
