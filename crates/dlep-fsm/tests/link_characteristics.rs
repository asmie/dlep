use std::time::Duration;

use dlep_core::{
    DataItem, LinkCharacteristics, LinkMetrics, MacAddress, Message, MessageType as M,
    StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::{
    build_link_characteristics_request, build_link_characteristics_response,
};
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{DestinationAddrs, FsmAction as A, FsmEvent as E, TimerId, TimerKind};

fn mac(n: u8) -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, n])
}
fn metrics() -> LinkMetrics {
    LinkMetrics {
        max_data_rate_rx_bps: 20_000,
        max_data_rate_tx_bps: 10_000,
        current_data_rate_rx_bps: 5_000,
        current_data_rate_tx_bps: 3_000,
        latency: Duration::from_micros(800),
        resources: 70,
        rlq_rx: 80,
        rlq_tx: 90,
        mtu: 1400,
    }
}
fn requested() -> LinkCharacteristics {
    LinkCharacteristics {
        latency: Some(Duration::from_micros(200)),
        ..Default::default()
    }
}
fn sent(actions: &[A], kind: M) -> Message {
    actions
        .iter()
        .find_map(|a| match a {
            A::SendMessage(m) if m.message_type == kind => Some(m.clone()),
            _ => None,
        })
        .expect("expected wire message")
}
fn status(m: &Message) -> S {
    m.data_items
        .iter()
        .find_map(|i| match i {
            DataItem::Status { code, .. } => Some(*code),
            _ => None,
        })
        .unwrap()
}
fn sessions() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::new();
    m.step(E::TcpAccepted);
    let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let reply = sent(
        &m.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    r.step(E::RecvMessage(reply));
    add(&mut r, &mut m, mac(1));
    (r, m)
}
fn add(r: &mut RouterSessionFsm, m: &mut ModemSessionFsm, mac: MacAddress) {
    let up = sent(
        &m.step(E::AppAddDestination {
            mac,
            metrics: metrics(),
            addrs: DestinationAddrs::default(),
        }),
        M::DESTINATION_UP,
    );
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
}
fn request(r: &mut RouterSessionFsm, mac: MacAddress) -> (Message, TimerId) {
    let actions = r.step(E::AppRequestLinkCharacteristics {
        mac,
        requested: requested(),
    });
    let id = actions
        .iter()
        .find_map(|a| match a {
            A::StartTimer {
                id,
                kind: TimerKind::Transaction(m),
                duration,
                periodic,
            } if *m == mac => {
                assert_eq!(*duration, Duration::from_secs(60));
                assert!(!periodic);
                Some(*id)
            }
            _ => None,
        })
        .unwrap();
    (sent(&actions, M::LINK_CHARACTERISTICS_REQUEST), id)
}

#[test]
fn request_encodes_only_selected_characteristics_including_zero() {
    for requested in [
        LinkCharacteristics {
            current_data_rate_rx_bps: Some(0),
            ..Default::default()
        },
        LinkCharacteristics {
            current_data_rate_tx_bps: Some(100),
            ..Default::default()
        },
        requested(),
    ] {
        let message = build_link_characteristics_request(mac(1), &requested);
        let decoded = Message::decode(message.encode().unwrap().freeze()).unwrap();
        assert_eq!(decoded.data_items.len(), 2);
        dlep_fsm::validation::validate_message(&decoded, false, false, &[]).unwrap();
    }
}

#[test]
fn modem_denies_change_with_all_current_metrics_and_router_completes_transaction() {
    let (mut r, mut m) = sessions();
    let (message, timer) = request(&mut r, mac(1));
    let response = sent(
        &m.step(E::RecvMessage(message)),
        M::LINK_CHARACTERISTICS_RESPONSE,
    );
    assert_eq!(status(&response), S::REQUEST_DENIED);
    assert_eq!(response.data_items.len(), 11); // MAC + Status + nine declared metrics
    assert_eq!(m.destinations[&mac(1)].metrics.latency, metrics().latency);
    let actions = r.step(E::RecvMessage(response));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, A::CancelTimer(id) if *id == timer))
    );
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::LinkCharacteristicsResponse { status: S::REQUEST_DENIED, metrics: got, .. }) if got.latency == metrics().latency)));
    assert!(!r.tx.destination_busy(&mac(1)));
    assert_eq!(r.state(), RouterSessionState::InSession);
    assert_eq!(m.state(), ModemSessionState::InSession);
    // Completion permits a later request; a stale timeout cannot kill it.
    request(&mut r, mac(1));
    assert!(
        r.step(E::TimerExpired(timer, TimerKind::Transaction(mac(1))))
            .is_empty()
    );
}

#[test]
fn successful_response_updates_metrics_and_preserves_status_text() {
    let (mut r, _) = sessions();
    request(&mut r, mac(1));
    let changed = LinkMetrics {
        latency: Duration::from_micros(200),
        ..metrics()
    };
    let mut response = build_link_characteristics_response(mac(1), S::SUCCESS, &changed);
    for item in &mut response.data_items {
        if let DataItem::Status { text, .. } = item {
            *text = "applied".into();
        }
    }
    let actions = r.step(E::RecvMessage(response));
    assert_eq!(r.destinations[&mac(1)].metrics.latency, changed.latency);
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::LinkCharacteristicsResponse { status: S::SUCCESS, text, .. }) if text == "applied")));
}

#[test]
fn response_reports_session_updates_as_current_metrics() {
    let (mut r, mut m) = sessions();
    let changed = LinkMetrics {
        latency: Duration::from_millis(3),
        ..metrics()
    };
    let update = sent(
        &m.step(E::AppSessionUpdate { metrics: changed }),
        M::SESSION_UPDATE,
    );
    let ack = sent(&r.step(E::RecvMessage(update)), M::SESSION_UPDATE_RESPONSE);
    m.step(E::RecvMessage(ack));
    let (message, _) = request(&mut r, mac(1));
    let response = sent(
        &m.step(E::RecvMessage(message)),
        M::LINK_CHARACTERISTICS_RESPONSE,
    );
    r.step(E::RecvMessage(response));
    assert_eq!(r.destinations[&mac(1)].metrics.latency, changed.latency);
}

#[test]
fn missing_declared_metric_is_invalid_even_on_denial() {
    let (mut r, _) = sessions();
    request(&mut r, mac(1));
    let mut response = build_link_characteristics_response(mac(1), S::REQUEST_DENIED, &metrics());
    response
        .data_items
        .retain(|item| !matches!(item, DataItem::Mtu(_)));
    assert_eq!(
        status(&sent(
            &r.step(E::RecvMessage(response)),
            M::SESSION_TERMINATION
        )),
        S::INVALID_DATA
    );
}

#[test]
fn malformed_or_unknown_destination_request_terminates_modem() {
    for (request, expected) in [
        (
            Message::new(M::LINK_CHARACTERISTICS_REQUEST).with_item(DataItem::MacAddress(mac(1))),
            S::INVALID_DATA,
        ),
        (
            build_link_characteristics_request(mac(2), &requested()),
            S::INVALID_DESTINATION,
        ),
        (
            build_link_characteristics_request(mac(1), &requested()).with_item(DataItem::Mtu(1500)),
            S::INVALID_DATA,
        ),
    ] {
        let (_, mut m) = sessions();
        assert_eq!(
            status(&sent(
                &m.step(E::RecvMessage(request)),
                M::SESSION_TERMINATION
            )),
            expected
        );
    }
}

#[test]
fn unsolicited_response_and_conflicting_request_are_rejected() {
    let (mut r, mut m) = sessions();
    let response = build_link_characteristics_response(mac(1), S::SUCCESS, &metrics());
    assert_eq!(
        status(&sent(
            &r.step(E::RecvMessage(response)),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
    m.step(E::AppDropDestination {
        mac: mac(1),
        reason: S::SUCCESS,
    });
    assert_eq!(
        status(&sent(
            &m.step(E::RecvMessage(build_link_characteristics_request(
                mac(1),
                &requested()
            ))),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
}

#[test]
fn concurrent_destinations_have_independent_timers_and_heartbeat_does_not_extend_request() {
    let (mut r, mut m) = sessions();
    add(&mut r, &mut m, mac(2));
    let (_, first) = request(&mut r, mac(1));
    let (_, second) = request(&mut r, mac(2));
    assert_ne!(first, second);
    assert!(
        r.step(E::AppRequestLinkCharacteristics {
            mac: mac(1),
            requested: requested()
        })
        .is_empty()
    );
    r.step(E::RecvMessage(Message::new(M::HEARTBEAT)));
    let actions = r.step(E::TimerExpired(first, TimerKind::Transaction(mac(1))));
    assert_eq!(
        status(&sent(&actions, M::SESSION_TERMINATION)),
        S::TIMED_OUT
    );
    assert_eq!(r.state(), RouterSessionState::Terminating);
}

#[test]
fn response_metric_set_matches_what_this_peer_declared() {
    for extra_optional in [false, true] {
        let mut r = RouterSessionFsm::new();
        let mut m = ModemSessionFsm::new();
        m.step(E::TcpAccepted);
        let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
        let mut reply = sent(
            &m.step(E::RecvMessage(init)),
            M::SESSION_INITIALIZATION_RESPONSE,
        );
        // An independent modem can omit optional metrics during initialization.
        reply
            .data_items
            .retain(|i| !(17..=20).contains(&i.type_id().0));
        r.step(E::RecvMessage(reply));
        r.step(E::RecvMessage(
            Message::new(M::DESTINATION_UP).with_item(DataItem::MacAddress(mac(1))),
        ));
        request(&mut r, mac(1));
        let mut response = build_link_characteristics_response(mac(1), S::SUCCESS, &metrics());
        response
            .data_items
            .retain(|i| !(17..=20).contains(&i.type_id().0));
        if extra_optional {
            response.data_items.push(DataItem::Mtu(1400));
        }
        let actions = r.step(E::RecvMessage(response));
        if extra_optional {
            assert_eq!(
                status(&sent(&actions, M::SESSION_TERMINATION)),
                S::INVALID_DATA
            );
        } else {
            assert!(actions.iter().any(|a| matches!(
                a,
                A::Emit(EmittedEvent::LinkCharacteristicsResponse {
                    status: S::SUCCESS,
                    ..
                })
            )));
            assert_eq!(r.state(), RouterSessionState::InSession);
        }
    }
}
