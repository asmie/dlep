use std::time::Duration;

use dlep_core::{DataItem, Message, MessageType as M, StatusCode as S};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::extract_link_metrics;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{AddressChanges, DestinationAddrs, FsmAction as A, FsmEvent as E, LinkMetrics};

fn sent(actions: Vec<A>) -> Message {
    actions
        .into_iter()
        .find_map(|a| match a {
            A::SendMessage(message) => Some(message),
            _ => None,
        })
        .expect("expected message")
}

fn pair() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut router = RouterSessionFsm::new();
    let mut modem = ModemSessionFsm::new();
    modem.step(E::TcpAccepted);
    let init = sent(router.step(E::TcpConnected));
    router.step(E::RecvMessage(sent(modem.step(E::RecvMessage(init)))));
    (router, modem)
}

fn addresses(n: u8) -> AddressChanges {
    AddressChanges {
        added: DestinationAddrs {
            v4: vec![format!("192.0.2.{n}").parse().unwrap()],
            ..Default::default()
        },
        removed: Default::default(),
    }
}

fn response(status: S) -> Message {
    Message::new(M::SESSION_UPDATE_RESPONSE).with_item(DataItem::Status {
        code: status,
        text: "peer says: dostęp ✓\n\"status\"".into(),
    })
}

fn completion(actions: &[A], expected: S) {
    let events: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            A::Emit(event) => Some(event),
            _ => None,
        })
        .collect();
    assert!(
        matches!(events.as_slice(), [EmittedEvent::SessionUpdateResponse { status, text }]
        if *status == expected && text == "peer says: dostęp ✓\n\"status\""),
        "{events:?}"
    );
}

#[test]
fn both_roles_expose_status_and_text_without_rolling_back_local_addresses() {
    let (mut router, mut modem) = pair();
    for (n, status) in [S::SUCCESS, S::NOT_INTERESTED, S::REQUEST_DENIED, S(42)]
        .into_iter()
        .enumerate()
    {
        let changes = addresses(n as u8 + 1);
        for actions in [
            router.step(E::AppSessionAddresses {
                changes: changes.clone(),
            }),
            modem.step(E::AppSessionAddresses {
                changes: changes.clone(),
            }),
        ] {
            assert_eq!(sent(actions).message_type, M::SESSION_UPDATE);
        }
        let reply = Message::decode(response(status).encode().unwrap().into()).unwrap();
        for actions in [
            router.step(E::RecvMessage(reply.clone())),
            modem.step(E::RecvMessage(reply)),
        ] {
            completion(&actions, status);
            assert!(!actions.iter().any(|a| matches!(a, A::SendMessage(_))));
        }
        assert_eq!(router.state(), RouterSessionState::InSession);
        assert_eq!(modem.state(), ModemSessionState::InSession);
        assert!(!router.tx.session_busy());
        assert!(!modem.tx.session_busy());
        // Repeating desired addresses sends no update and cannot emit completion.
        assert!(
            router
                .step(E::AppSessionAddresses {
                    changes: changes.clone()
                })
                .is_empty()
        );
        assert!(modem.step(E::AppSessionAddresses { changes }).is_empty());
    }
}

#[test]
fn completion_precedes_coalesced_next_update_and_does_not_signal_idle() {
    let (_, mut modem) = pair();
    sent(modem.step(E::AppSessionAddresses {
        changes: addresses(1),
    }));
    for latency in [100, 200, 300] {
        assert!(
            modem
                .step(E::AppQueueSessionUpdate {
                    metrics: LinkMetrics {
                        latency: Duration::from_micros(latency),
                        ..Default::default()
                    }
                })
                .is_empty()
        );
    }
    let actions = modem.step(E::RecvMessage(response(S::REQUEST_DENIED)));
    completion(&actions, S::REQUEST_DENIED);
    assert!(matches!(
        actions.first(),
        Some(A::Emit(EmittedEvent::SessionUpdateResponse { .. }))
    ));
    assert_eq!(
        extract_link_metrics(&sent(actions)).unwrap().latency,
        Duration::from_micros(300)
    );
    assert!(
        modem.tx.session_busy(),
        "the coalesced update is now pending"
    );
    completion(
        &modem.step(E::RecvMessage(response(S::SUCCESS))),
        S::SUCCESS,
    );
    assert!(!modem.tx.session_busy());
    assert!(
        modem
            .step(E::AppSessionAddresses {
                changes: addresses(1)
            })
            .is_empty()
    );
}

#[test]
fn malformed_unsolicited_duplicate_and_fatal_replies_never_emit_completion() {
    for (pending, reply) in [
        (false, response(S::SUCCESS)),
        (true, Message::new(M::SESSION_UPDATE_RESPONSE)),
        (
            true,
            response(S::SUCCESS).with_item(DataItem::Status {
                code: S::SUCCESS,
                text: String::new(),
            }),
        ),
        (true, response(S::INVALID_DATA)),
    ] {
        let (mut router, mut modem) = pair();
        if pending {
            router.step(E::AppSessionAddresses {
                changes: addresses(1),
            });
            modem.step(E::AppSessionAddresses {
                changes: addresses(1),
            });
        }
        for actions in [
            router.step(E::RecvMessage(reply.clone())),
            modem.step(E::RecvMessage(reply)),
        ] {
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, A::Emit(EmittedEvent::SessionUpdateResponse { .. })))
            );
        }
        assert_eq!(router.state(), RouterSessionState::Terminating);
        assert_eq!(modem.state(), ModemSessionState::Terminating);
    }
    let (mut router, mut modem) = pair();
    router.step(E::AppSessionAddresses {
        changes: addresses(1),
    });
    modem.step(E::AppSessionAddresses {
        changes: addresses(1),
    });
    router.step(E::RecvMessage(response(S::SUCCESS)));
    modem.step(E::RecvMessage(response(S::SUCCESS)));
    for actions in [
        router.step(E::RecvMessage(response(S::SUCCESS))),
        modem.step(E::RecvMessage(response(S::SUCCESS))),
    ] {
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, A::Emit(EmittedEvent::SessionUpdateResponse { .. })))
        );
    }
    assert_eq!(router.state(), RouterSessionState::Terminating);
    assert_eq!(modem.state(), ModemSessionState::Terminating);
}
