use dlep_core::{
    DataItem, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{FsmAction as A, FsmEvent as E, SessionConfig};

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

fn pair(format: MacAddressFormat, mac: MacAddress) -> (RouterSessionFsm, ModemSessionFsm) {
    let config = SessionConfig {
        mac_address_format: format,
        ..Default::default()
    };
    let mut router = RouterSessionFsm::with_config(config.clone());
    let mut modem = ModemSessionFsm::with_config(config);
    modem.step(E::TcpAccepted);
    let init = sent(router.step(E::TcpConnected));
    router.step(E::RecvMessage(sent(modem.step(E::RecvMessage(init)))));
    let up = sent(modem.step(E::AppAddDestination {
        mac,
        metrics: Default::default(),
        addrs: Default::default(),
    }));
    modem.step(E::RecvMessage(sent(router.step(E::RecvMessage(up)))));
    (router, modem)
}

fn response(mac: MacAddress, status: S) -> Message {
    Message::new(M::DESTINATION_DOWN_RESPONSE)
        .with_item(DataItem::MacAddress(mac))
        .with_item(DataItem::Status {
            code: status,
            text: "peer: dostęp ✓\n\"withdrawal\"".into(),
        })
}

#[test]
fn down_replies_remove_state_then_emit_status_and_text_on_both_roles() {
    for (format, mac) in cases() {
        for status in [S::SUCCESS, S::NOT_INTERESTED, S::REQUEST_DENIED, S(42)] {
            let (mut router, mut modem) = pair(format, mac);
            for actions in [
                router.step(E::AppDropDestination {
                    mac,
                    reason: S::SUCCESS,
                }),
                modem.step(E::AppDropDestination {
                    mac,
                    reason: S::SUCCESS,
                }),
            ] {
                assert!(!actions.iter().any(|a| matches!(a, A::Emit(_))));
                assert_eq!(sent(actions).message_type, M::DESTINATION_DOWN);
            }
            let reply = Message::decode(response(mac, status).encode().unwrap().into()).unwrap();
            for (is_router, actions) in [
                (true, router.step(E::RecvMessage(reply.clone()))),
                (false, modem.step(E::RecvMessage(reply.clone()))),
            ] {
                let events: Vec<_> = actions
                    .iter()
                    .filter_map(|a| match a {
                        A::Emit(event) => Some(event),
                        _ => None,
                    })
                    .collect();
                assert_eq!(events.len(), if is_router { 2 } else { 1 });
                if is_router {
                    assert!(
                        matches!(events[0], EmittedEvent::DestinationDown { mac: got, reason } if *got == mac && *reason == status)
                    );
                }
                assert!(
                    matches!(events.last(), Some(EmittedEvent::DestinationDownResponse { mac: got, status: code, text })
                    if *got == mac && *code == status && text == "peer: dostęp ✓\n\"withdrawal\"")
                );
            }
            assert_eq!(router.state(), RouterSessionState::InSession);
            assert_eq!(modem.state(), ModemSessionState::InSession);
            assert!(!router.tx.destination_busy(&mac));
            assert!(!modem.tx.destination_busy(&mac));
            assert!(!router.destinations.contains_key(&mac));
            assert!(!modem.destinations.contains_key(&mac));
            // A duplicate cannot produce another completion.
            for actions in [
                router.step(E::RecvMessage(reply.clone())),
                modem.step(E::RecvMessage(reply)),
            ] {
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        A::Emit(EmittedEvent::DestinationDownResponse { .. })
                    ))
                );
            }
            assert_eq!(router.state(), RouterSessionState::Terminating);
            assert_eq!(modem.state(), ModemSessionState::Terminating);
        }
    }
}

#[test]
fn invalid_unsolicited_and_fatal_down_replies_do_not_emit_completion() {
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
                Message::new(M::DESTINATION_DOWN_RESPONSE).with_item(DataItem::MacAddress(mac)),
            ),
            (
                true,
                Message::new(M::DESTINATION_DOWN_RESPONSE).with_item(DataItem::Status {
                    code: S::SUCCESS,
                    text: String::new(),
                }),
            ),
            (true, response(mac, S::INVALID_DATA)),
        ] {
            let (mut router, mut modem) = pair(format, mac);
            if pending {
                router.step(E::AppDropDestination {
                    mac,
                    reason: S::SUCCESS,
                });
                modem.step(E::AppDropDestination {
                    mac,
                    reason: S::SUCCESS,
                });
            }
            for actions in [
                router.step(E::RecvMessage(reply.clone())),
                modem.step(E::RecvMessage(reply)),
            ] {
                assert!(
                    !actions.iter().any(|a| matches!(
                        a,
                        A::Emit(EmittedEvent::DestinationDownResponse { .. })
                    ))
                );
            }
            assert_eq!(router.state(), RouterSessionState::Terminating);
            assert_eq!(modem.state(), ModemSessionState::Terminating);
        }
    }
}
