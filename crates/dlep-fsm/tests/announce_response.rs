use std::time::Duration;

use dlep_core::{
    DataItem, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{FsmAction as A, FsmEvent as E, LinkMetrics, SessionConfig};

fn cases() -> [(MacAddressFormat, MacAddress); 2] {
    [
        (
            MacAddressFormat::Eui48,
            MacAddress::new_eui48([2, 0, 0, 0, 0, 1]),
        ),
        (
            MacAddressFormat::Eui64,
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        ),
    ]
}

fn sent(actions: Vec<A>) -> Message {
    actions
        .into_iter()
        .find_map(|action| match action {
            A::SendMessage(message) => Some(message),
            _ => None,
        })
        .expect("expected message")
}

fn router(format: MacAddressFormat) -> RouterSessionFsm {
    let config = SessionConfig {
        mac_address_format: format,
        initial_metrics: LinkMetrics {
            current_data_rate_tx_bps: 321,
            mtu: Some(1500),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut router = RouterSessionFsm::with_config(config.clone());
    let mut modem = ModemSessionFsm::with_config(config);
    modem.step(E::TcpAccepted);
    let init = sent(router.step(E::TcpConnected));
    let response = sent(modem.step(E::RecvMessage(init)));
    router.step(E::RecvMessage(response));
    assert_eq!(router.state(), RouterSessionState::InSession);
    router
}

fn response(mac: MacAddress, status: S) -> Message {
    Message::new(M::DESTINATION_ANNOUNCE_RESPONSE)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: status,
            text: "peer says: dostęp ✓".into(),
        })
}

#[test]
fn announce_replies_emit_status_text_and_release_the_transaction() {
    for (format, mac) in cases() {
        let mut router = router(format);
        for status in [S::REQUEST_DENIED, S::NOT_INTERESTED, S(42), S::SUCCESS] {
            assert_eq!(
                sent(router.step(E::AppAnnounceDestination { mac })).message_type,
                M::DESTINATION_ANNOUNCE
            );
            assert!(router.tx.destination_busy(&mac));
            let reply = response(mac, status)
                .with_item(DataItem::Latency(Duration::from_micros(444)))
                .with_item(DataItem::Ipv4Address {
                    add: true,
                    addr: "192.0.2.1".parse().unwrap(),
                });
            let reply = Message::decode(reply.encode().unwrap().into()).unwrap();
            let actions = router.step(E::RecvMessage(reply.clone()));
            assert_eq!(router.state(), RouterSessionState::InSession);
            assert!(!router.tx.destination_busy(&mac));
            let events: Vec<_> = actions
                .iter()
                .filter_map(|a| match a {
                    A::Emit(event) => Some(event),
                    _ => None,
                })
                .collect();
            assert!(
                matches!(events.last(), Some(EmittedEvent::DestinationAnnounceResponse {
                mac: got, status: code, text,
            }) if *got == mac && *code == status && text == "peer says: dostęp ✓")
            );
            if status == S::SUCCESS {
                assert_eq!(events.len(), 2);
                assert!(
                    matches!(events[0], EmittedEvent::DestinationUp { mac: got, .. } if *got == mac)
                );
                let destination = &router.destinations[&mac];
                assert_eq!(destination.metrics.latency, Duration::from_micros(444));
                assert_eq!(destination.metrics.current_data_rate_tx_bps, 321);
                assert_eq!(destination.metrics.mtu, Some(1500));
                assert_eq!(
                    destination.addrs.v4,
                    vec!["192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap()]
                );
                // A duplicate reply must not manufacture a second completion.
                let duplicate = router.step(E::RecvMessage(reply));
                assert!(!duplicate.iter().any(|a| matches!(
                    a,
                    A::Emit(EmittedEvent::DestinationAnnounceResponse { .. })
                )));
                assert_eq!(router.state(), RouterSessionState::Terminating);
            } else {
                assert_eq!(events.len(), 1);
                assert!(router.destinations.is_empty());
            }
        }
    }
}

#[test]
fn invalid_unsolicited_and_fatal_announces_do_not_emit_completion() {
    for (format, mac) in cases() {
        let wrong = match format {
            MacAddressFormat::Eui48 => MacAddress::new_eui48([2, 0, 0, 0, 0, 2]),
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 2]),
        };
        for (pending, reply) in [
            (false, response(mac, S::REQUEST_DENIED)),
            (true, response(wrong, S::REQUEST_DENIED)),
            (
                true,
                Message::new(M::DESTINATION_ANNOUNCE_RESPONSE).with_item(DataItem::MacAddress(mac)),
            ),
            (true, response(mac, S::INVALID_DATA)),
        ] {
            let mut router = router(format);
            if pending {
                router.step(E::AppAnnounceDestination { mac });
            }
            let actions = router.step(E::RecvMessage(reply));
            assert_eq!(router.state(), RouterSessionState::Terminating);
            assert!(
                !actions.iter().any(|a| matches!(
                    a,
                    A::Emit(EmittedEvent::DestinationAnnounceResponse { .. })
                ))
            );
            assert!(router.destinations.is_empty());
        }
    }
}
