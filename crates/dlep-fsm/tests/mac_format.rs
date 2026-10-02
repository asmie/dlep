use dlep_core::{
    DataItem, MacAddress, MacAddressFormat as F, Message, MessageType as M, StatusCode as S,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{CommandError, FsmAction as A, FsmEvent as E, SessionConfig};

fn mac(format: F) -> MacAddress {
    match format {
        F::Eui48 => MacAddress::new_eui48([2, 0, 0, 0, 0, 1]),
        F::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
    }
}
fn other(format: F) -> F {
    match format {
        F::Eui48 => F::Eui64,
        F::Eui64 => F::Eui48,
    }
}
fn sent(actions: Vec<A>, kind: M) -> Message {
    actions
        .into_iter()
        .find_map(|a| match a {
            A::SendMessage(m) if m.message_type == kind => Some(m),
            _ => None,
        })
        .expect("expected message")
}
fn sessions(format: F) -> (RouterSessionFsm, ModemSessionFsm) {
    let config = SessionConfig {
        mac_address_format: format,
        ..Default::default()
    };
    let mut r = RouterSessionFsm::with_config(config.clone());
    let mut m = ModemSessionFsm::with_config(config);
    m.step(E::TcpAccepted);
    let init = sent(r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let reply = sent(
        m.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    r.step(E::RecvMessage(reply));
    (r, m)
}
fn add(r: &mut RouterSessionFsm, m: &mut ModemSessionFsm, mac: MacAddress) {
    let up = sent(
        m.step(E::AppAddDestination {
            mac,
            metrics: Default::default(),
            addrs: Default::default(),
        }),
        M::DESTINATION_UP,
    );
    let ack = sent(r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
    assert!(r.destinations[&mac].up);
    assert!(m.destinations[&mac].announced);
}
fn rejected(actions: Vec<A>) {
    assert!(
        matches!(actions.as_slice(), [A::Emit(EmittedEvent::CommandRejected(rejection))]
        if rejection.reason == CommandError::MacAddressFormatMismatch)
    );
}
fn invalid(actions: Vec<A>) {
    let termination = sent(actions, M::SESSION_TERMINATION);
    assert!(
        termination
            .data_items
            .iter()
            .any(|item| matches!(item, DataItem::Status { code, .. } if *code == S::INVALID_DATA))
    );
}

#[test]
fn matching_formats_work_and_local_mismatches_never_reach_wire() {
    for format in [F::Eui48, F::Eui64] {
        let (mut r, mut m) = sessions(format);
        let wrong = mac(other(format));
        // Policy applies before the first destination, not only after learning one.
        rejected(r.step(E::AppAnnounceDestination { mac: wrong }));
        rejected(m.step(E::AppAddDestination {
            mac: wrong,
            metrics: Default::default(),
            addrs: Default::default(),
        }));
        assert!(r.tx.per_destination.is_empty() && m.tx.per_destination.is_empty());
        add(&mut r, &mut m, mac(format));
        for event in [
            E::AppDropDestination {
                mac: wrong,
                reason: S::SUCCESS,
            },
            E::AppRequestLinkCharacteristics {
                mac: wrong,
                requested: dlep_core::LinkCharacteristics {
                    latency: Some(Default::default()),
                    ..Default::default()
                },
            },
        ] {
            rejected(r.step(event));
        }
        for event in [
            E::AppDropDestination {
                mac: wrong,
                reason: S::SUCCESS,
            },
            E::AppUpdateMetrics {
                mac: wrong,
                metrics: Default::default(),
            },
            E::AppUpdateAddresses {
                mac: wrong,
                changes: Default::default(),
            },
        ] {
            rejected(m.step(event));
        }
        assert_eq!(r.state(), RouterSessionState::InSession);
        assert_eq!(m.state(), ModemSessionState::InSession);
        assert_eq!(r.destinations.len(), 1);
        assert_eq!(m.destinations.len(), 1);
    }
}

#[test]
fn every_incoming_destination_message_checks_format_before_transaction_lookup() {
    for format in [F::Eui48, F::Eui64] {
        for router in [false, true] {
            let kinds: &[M] = if router {
                &[
                    M::DESTINATION_UP,
                    M::DESTINATION_UPDATE,
                    M::DESTINATION_DOWN,
                    M::DESTINATION_ANNOUNCE_RESPONSE,
                    M::DESTINATION_DOWN_RESPONSE,
                    M::LINK_CHARACTERISTICS_RESPONSE,
                ]
            } else {
                &[
                    M::DESTINATION_ANNOUNCE,
                    M::DESTINATION_DOWN,
                    M::DESTINATION_UP_RESPONSE,
                    M::DESTINATION_DOWN_RESPONSE,
                    M::LINK_CHARACTERISTICS_REQUEST,
                ]
            };
            for &kind in kinds {
                let (mut r, mut m) = sessions(format);
                add(&mut r, &mut m, mac(format));
                let mut message =
                    Message::new(kind).with_item(DataItem::MacAddress(mac(other(format))));
                if matches!(
                    kind,
                    M::DESTINATION_UP_RESPONSE
                        | M::DESTINATION_DOWN_RESPONSE
                        | M::DESTINATION_ANNOUNCE_RESPONSE
                        | M::LINK_CHARACTERISTICS_RESPONSE
                ) {
                    message = message.with_item(DataItem::Status {
                        code: S::SUCCESS,
                        text: String::new(),
                    });
                }
                if kind == M::LINK_CHARACTERISTICS_REQUEST {
                    message = message.with_item(DataItem::Latency(Default::default()));
                }
                if kind == M::LINK_CHARACTERISTICS_RESPONSE {
                    message.data_items.extend(
                        dlep_fsm::session_common::build_session_update(&Default::default())
                            .data_items,
                    );
                }
                if router {
                    invalid(r.step(E::RecvMessage(message)));
                    assert_eq!(r.state(), RouterSessionState::Terminating);
                } else {
                    invalid(m.step(E::RecvMessage(message)));
                    assert_eq!(m.state(), ModemSessionState::Terminating);
                }
            }
        }
    }
}

#[test]
fn format_remains_fixed_after_last_destination_is_removed() {
    for format in [F::Eui48, F::Eui64] {
        let (mut r, mut m) = sessions(format);
        add(&mut r, &mut m, mac(format));
        let down = sent(
            m.step(E::AppDropDestination {
                mac: mac(format),
                reason: S::SUCCESS,
            }),
            M::DESTINATION_DOWN,
        );
        let ack = sent(r.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
        m.step(E::RecvMessage(ack));
        assert!(r.destinations.is_empty() && m.destinations.is_empty());
        rejected(m.step(E::AppAddDestination {
            mac: mac(other(format)),
            metrics: Default::default(),
            addrs: Default::default(),
        }));
        rejected(r.step(E::AppAnnounceDestination {
            mac: mac(other(format)),
        }));
        add(&mut r, &mut m, mac(format));
        // Reconnected/new sessions may explicitly choose a different link format.
        let (mut fresh_r, mut fresh_m) = sessions(other(format));
        add(&mut fresh_r, &mut fresh_m, mac(other(format)));
    }
}

#[test]
fn first_incoming_mac_must_match_configured_link_format() {
    for format in [F::Eui48, F::Eui64] {
        let (mut r, mut m) = sessions(format);
        invalid(r.step(E::RecvMessage(
            Message::new(M::DESTINATION_UP).with_item(DataItem::MacAddress(mac(other(format)))),
        )));
        invalid(
            m.step(E::RecvMessage(
                Message::new(M::DESTINATION_ANNOUNCE)
                    .with_item(DataItem::MacAddress(mac(other(format)))),
            )),
        );
    }
}
