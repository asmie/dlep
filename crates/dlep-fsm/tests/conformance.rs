//! Regression cases from the RFC 8175 audit. Each session performs the real
//! initialization exchange rather than bypassing setup by assigning a state.
use dlep_core::{DataItem, MacAddress, Message, MessageType, Signal, SignalType, StatusCode};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{DestinationAddrs, FsmAction, FsmEvent, LinkMetrics};
use std::time::Duration;

fn mac() -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
}
fn sessions() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::new();
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
            mtu: 1400,
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
    assert_eq!(r.destinations[&mac()].metrics.mtu, 1400);
    let update = sent(
        m.step(FsmEvent::AppUpdateMetrics {
            mac: mac(),
            metrics: LinkMetrics {
                mtu: 1300,
                ..LinkMetrics::default()
            },
        }),
        MessageType::DESTINATION_UPDATE,
    );
    r.step(FsmEvent::RecvMessage(update));
    assert_eq!(r.destinations[&mac()].metrics.mtu, 1300);
}
