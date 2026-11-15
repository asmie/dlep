use std::time::Duration;

use dlep_core::{
    DataItem, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::{build_destination_announce, extract_link_metrics};
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{
    AddressChanges, DestinationAddrs, FsmAction as A, FsmEvent as E, LinkMetrics, SessionConfig,
};

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
        .find_map(|a| match a {
            A::SendMessage(message) => Some(message),
            _ => None,
        })
        .expect("expected message")
}

fn modem(format: MacAddressFormat) -> ModemSessionFsm {
    let config = SessionConfig {
        mac_address_format: format,
        ..Default::default()
    };
    let mut router = RouterSessionFsm::with_config(config.clone());
    let mut modem = ModemSessionFsm::with_config(config);
    modem.step(E::TcpAccepted);
    let init = sent(router.step(E::TcpConnected));
    router.step(E::RecvMessage(sent(modem.step(E::RecvMessage(init)))));
    assert_eq!(modem.state(), ModemSessionState::InSession);
    modem
}

fn add(modem: &mut ModemSessionFsm, mac: MacAddress) {
    assert_eq!(
        sent(modem.step(E::AppAddDestination {
            mac,
            metrics: LinkMetrics::default(),
            addrs: DestinationAddrs::default(),
        }))
        .message_type,
        M::DESTINATION_UP
    );
}

fn response(mac: MacAddress, status: S) -> Message {
    Message::new(M::DESTINATION_UP_RESPONSE)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: status,
            text: "router says: dostęp ✓".into(),
        })
}

#[test]
fn up_outcomes_preserve_queued_changes_and_report_status_after_corrections() {
    for (format, mac) in cases() {
        for status in [S::SUCCESS, S::NOT_INTERESTED, S::REQUEST_DENIED, S(42)] {
            let mut modem = modem(format);
            add(&mut modem, mac);
            let metrics = LinkMetrics {
                latency: Duration::from_micros(321),
                ..Default::default()
            };
            let addrs = DestinationAddrs {
                v4: vec!["192.0.2.1".parse().unwrap()],
                ..Default::default()
            };
            assert!(modem.step(E::AppUpdateMetrics { mac, metrics }).is_empty());
            assert!(
                modem
                    .step(E::AppUpdateAddresses {
                        mac,
                        changes: AddressChanges {
                            added: addrs.clone(),
                            removed: Default::default()
                        },
                    })
                    .is_empty()
            );
            let reply = response(mac, status);
            let actions = modem.step(E::RecvMessage(
                Message::decode(reply.encode().unwrap().into()).unwrap(),
            ));
            assert_eq!(modem.state(), ModemSessionState::InSession);
            assert!(!modem.tx.destination_busy(&mac));
            let destination = &modem.destinations[&mac];
            assert_eq!(destination.announced, status == S::SUCCESS);
            assert_eq!(destination.metrics, metrics);
            assert_eq!(destination.addrs, addrs);
            let mut completed = false;
            let mut updates = Vec::new();
            for action in actions {
                match action {
                    A::SendMessage(message) => {
                        assert!(!completed, "queued changes precede the completion event");
                        assert_eq!(message.message_type, M::DESTINATION_UPDATE);
                        updates.push(message);
                    }
                    A::Emit(EmittedEvent::DestinationUpResponse {
                        mac: got,
                        status: code,
                        text,
                    }) => {
                        assert!(!completed, "one event per reply");
                        completed = true;
                        assert_eq!(
                            (got, code, text.as_str()),
                            (mac, status, "router says: dostęp ✓")
                        );
                    }
                    _ => {}
                }
            }
            assert!(completed);
            if status == S::SUCCESS {
                assert_eq!(updates.len(), 1);
                assert_eq!(extract_link_metrics(&updates[0]), Some(metrics));
                let duplicate = modem.step(E::RecvMessage(reply));
                assert_eq!(modem.state(), ModemSessionState::Terminating);
                assert!(
                    !duplicate
                        .iter()
                        .any(|a| matches!(a, A::Emit(EmittedEvent::DestinationUpResponse { .. })))
                );
            } else {
                assert!(updates.is_empty());
                let newer = LinkMetrics {
                    latency: Duration::from_micros(654),
                    ..metrics
                };
                assert!(
                    modem
                        .step(E::AppUpdateMetrics {
                            mac,
                            metrics: newer
                        })
                        .is_empty()
                );
                // Declined destinations stay available for a later Announce.
                let restored = sent(modem.step(E::RecvMessage(build_destination_announce(mac))));
                assert_eq!(restored.message_type, M::DESTINATION_ANNOUNCE_RESPONSE);
                assert_eq!(extract_link_metrics(&restored), Some(newer));
                assert_eq!(AddressChanges::from_message(&restored).added, addrs);
            }
        }
    }
}

#[test]
fn invalid_unsolicited_and_fatal_up_replies_do_not_emit_completion() {
    for (format, mac) in cases() {
        let wrong = match format {
            MacAddressFormat::Eui48 => MacAddress::new_eui48([2, 0, 0, 0, 0, 2]),
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 2]),
        };
        for (pending, reply) in [
            (false, response(mac, S::SUCCESS)),
            (true, response(wrong, S::SUCCESS)),
            (
                true,
                Message::new(M::DESTINATION_UP_RESPONSE).with_item(DataItem::MacAddress(mac)),
            ),
            (true, response(mac, S::INVALID_DATA)),
        ] {
            let mut modem = modem(format);
            if pending {
                add(&mut modem, mac);
            }
            let actions = modem.step(E::RecvMessage(reply));
            assert_eq!(modem.state(), ModemSessionState::Terminating);
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, A::Emit(EmittedEvent::DestinationUpResponse { .. })))
            );
        }
    }
}
