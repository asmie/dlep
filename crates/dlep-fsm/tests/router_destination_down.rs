use std::time::Duration;

use dlep_core::{
    DataItem, LinkCharacteristics, LinkMetrics, MacAddress, Message, MessageType as M,
    StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::{
    build_destination_down, build_destination_down_response, build_destination_update,
};
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{DestinationAddrs, FsmAction as A, FsmEvent as E, TimerKind};

fn mac() -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
}
fn metrics() -> LinkMetrics {
    LinkMetrics {
        latency: Duration::from_micros(500),
        current_data_rate_rx_bps: 1000,
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
fn status(message: &Message) -> S {
    message
        .data_items
        .iter()
        .find_map(|i| match i {
            DataItem::Status { code, .. } => Some(*code),
            _ => None,
        })
        .unwrap()
}
fn sessions() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut router = RouterSessionFsm::new();
    let mut modem = ModemSessionFsm::new();
    modem.step(E::TcpAccepted);
    let init = sent(&router.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let ack = sent(
        &modem.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    router.step(E::RecvMessage(ack));
    let up = sent(
        &modem.step(E::AppAddDestination {
            mac: mac(),
            metrics: metrics(),
            addrs: DestinationAddrs {
                v4: vec!["192.0.2.1".parse().unwrap()],
                ..Default::default()
            },
        }),
        M::DESTINATION_UP,
    );
    let ack = sent(&router.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    modem.step(E::RecvMessage(ack));
    (router, modem)
}
fn down(router: &mut RouterSessionFsm) -> Message {
    let actions = router.step(E::AppDropDestination {
        mac: mac(),
        reason: S::SHUTTING_DOWN,
    });
    // A reason from a caller must never become a forbidden Status TLV.
    let message = sent(&actions, M::DESTINATION_DOWN);
    assert_eq!(message.data_items.len(), 1);
    assert!(matches!(message.data_items[0], DataItem::MacAddress(_)));
    assert!(!actions.iter().any(|a| matches!(
        a,
        A::StartTimer {
            kind: TimerKind::Transaction(_),
            ..
        } | A::Emit(EmittedEvent::DestinationDown { .. })
    )));
    assert!(router.destinations.contains_key(&mac()));
    message
}
fn assert_down_event(actions: &[A]) {
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::DestinationDown { mac: m, reason: S::SUCCESS }) if *m == mac())));
}

#[test]
fn withdraw_stop_updates_and_reannounce_for_both_original_up_and_announce() {
    let (mut router, mut modem) = sessions();
    // The second round starts from Announce rather than Up.
    for n in 1..=2 {
        let message = down(&mut router);
        let actions = modem.step(E::RecvMessage(message));
        assert_down_event(&actions);
        let response = sent(&actions, M::DESTINATION_DOWN_RESPONSE);
        assert_eq!(status(&response), S::SUCCESS);
        assert!(!modem.destinations[&mac()].announced);
        let actions = router.step(E::RecvMessage(response));
        assert_down_event(&actions);
        assert!(!router.destinations.contains_key(&mac()));
        assert!(!router.tx.destination_busy(&mac()));
        assert_eq!(router.state(), RouterSessionState::InSession);
        assert_eq!(modem.state(), ModemSessionState::InSession);

        let changed = LinkMetrics {
            latency: Duration::from_millis(n),
            ..metrics()
        };
        assert!(
            modem
                .step(E::AppUpdateMetrics {
                    mac: mac(),
                    metrics: changed
                })
                .is_empty()
        );
        assert!(
            modem
                .step(E::AppAddDestination {
                    mac: mac(),
                    metrics: changed,
                    addrs: Default::default()
                })
                .is_empty()
        );
        let announce = sent(
            &router.step(E::AppAnnounceDestination { mac: mac() }),
            M::DESTINATION_ANNOUNCE,
        );
        let response = sent(
            &modem.step(E::RecvMessage(announce)),
            M::DESTINATION_ANNOUNCE_RESPONSE,
        );
        assert_eq!(status(&response), S::SUCCESS);
        let actions = router.step(E::RecvMessage(response));
        assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::DestinationUp { addrs, metrics, .. }) if addrs.v4.len() == 1 && metrics.latency == changed.latency)));
        assert!(modem.destinations[&mac()].announced);
        assert!(!modem.destinations[&mac()].pending_metrics);
    }
}

#[test]
fn updates_in_transit_are_accepted_until_response_but_rejected_afterwards() {
    let (mut router, mut modem) = sessions();
    let request = down(&mut router);
    let update = build_destination_update(mac(), &metrics());
    let actions = router.step(E::RecvMessage(update.clone()));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, A::Emit(EmittedEvent::DestinationUpdate { .. })))
    );
    let response = sent(
        &modem.step(E::RecvMessage(request)),
        M::DESTINATION_DOWN_RESPONSE,
    );
    router.step(E::RecvMessage(response));
    let termination = sent(&router.step(E::RecvMessage(update)), M::SESSION_TERMINATION);
    assert_eq!(status(&termination), S::INVALID_DESTINATION);
}

#[test]
fn modem_can_forget_a_withdrawn_destination_without_sending_another_down() {
    let (mut router, mut modem) = sessions();
    let response = sent(
        &modem.step(E::RecvMessage(down(&mut router))),
        M::DESTINATION_DOWN_RESPONSE,
    );
    router.step(E::RecvMessage(response));
    assert!(
        modem
            .step(E::AppDropDestination {
                mac: mac(),
                reason: S::SUCCESS
            })
            .is_empty()
    );
    assert!(!modem.destinations.contains_key(&mac()));
    let announce = sent(
        &router.step(E::AppAnnounceDestination { mac: mac() }),
        M::DESTINATION_ANNOUNCE,
    );
    let response = sent(
        &modem.step(E::RecvMessage(announce)),
        M::DESTINATION_ANNOUNCE_RESPONSE,
    );
    assert_eq!(status(&response), S::REQUEST_DENIED);
}

#[test]
fn local_unknown_or_busy_destination_does_not_send_down() {
    let (mut router, _) = sessions();
    let other = MacAddress::new_eui48([2, 0, 0, 0, 0, 2]);
    assert!(
        router
            .step(E::AppDropDestination {
                mac: other,
                reason: S::SUCCESS
            })
            .is_empty()
    );
    router.step(E::AppRequestLinkCharacteristics {
        mac: mac(),
        requested: LinkCharacteristics {
            latency: Some(Duration::ZERO),
            ..Default::default()
        },
    });
    assert!(
        router
            .step(E::AppDropDestination {
                mac: mac(),
                reason: S::SUCCESS
            })
            .is_empty()
    );
}

#[test]
fn crossed_down_requests_terminate_both_sessions() {
    let (mut router, mut modem) = sessions();
    let router_down = down(&mut router);
    let modem_down = sent(
        &modem.step(E::AppDropDestination {
            mac: mac(),
            reason: S::SUCCESS,
        }),
        M::DESTINATION_DOWN,
    );
    assert_eq!(
        status(&sent(
            &router.step(E::RecvMessage(modem_down)),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
    assert_eq!(
        status(&sent(
            &modem.step(E::RecvMessage(router_down)),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
}

#[test]
fn modem_rejects_unknown_duplicate_and_malformed_down() {
    for case in 0..3 {
        let (mut router, mut modem) = sessions();
        let request = match case {
            0 => build_destination_down(MacAddress::new_eui48([2, 0, 0, 0, 0, 2]), S::SUCCESS),
            1 => {
                let request = down(&mut router);
                modem.step(E::RecvMessage(request.clone()));
                request
            }
            _ => build_destination_down(mac(), S::SUCCESS).with_item(DataItem::Status {
                code: S::SUCCESS,
                text: String::new(),
            }),
        };
        let expected = if case == 2 {
            S::INVALID_DATA
        } else {
            S::INVALID_DESTINATION
        };
        assert_eq!(
            status(&sent(
                &modem.step(E::RecvMessage(request)),
                M::SESSION_TERMINATION
            )),
            expected
        );
    }
}

#[test]
fn router_requires_matching_response_and_echoes_fatal_status() {
    let (mut router, _) = sessions();
    assert_eq!(
        status(&sent(
            &router.step(E::RecvMessage(build_destination_down_response(
                mac(),
                S::SUCCESS
            ))),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
    let (mut router, _) = sessions();
    down(&mut router);
    let other = MacAddress::new_eui48([2, 0, 0, 0, 0, 2]);
    assert_eq!(
        status(&sent(
            &router.step(E::RecvMessage(build_destination_down_response(
                other,
                S::SUCCESS
            ))),
            M::SESSION_TERMINATION
        )),
        S::UNEXPECTED_MESSAGE
    );
    let (mut router, _) = sessions();
    down(&mut router);
    let reply = Message::new(M::DESTINATION_DOWN_RESPONSE)
        .with_item(DataItem::MacAddress(mac()))
        .with_item(DataItem::Status {
            code: S::INVALID_DESTINATION,
            text: "unknown MAC".into(),
        });
    let termination = sent(&router.step(E::RecvMessage(reply)), M::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|i| matches!(i, DataItem::Status { code: S::INVALID_DESTINATION, text } if text == "unknown MAC")));
}
