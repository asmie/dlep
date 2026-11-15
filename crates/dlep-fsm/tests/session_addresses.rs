mod common;

use std::time::Duration;

use dlep_core::{DataItem, MacAddress, Message, MessageType as M, StatusCode as S};
use dlep_fsm::{
    AddressChanges, CommandError, DestinationAddrs, FsmAction as A, FsmEvent as E, LinkMetrics,
    events::EmittedEvent, session_common::extract_link_metrics, session_modem::ModemSessionFsm,
    session_router::RouterSessionFsm,
};

fn messages(actions: &[A]) -> Vec<Message> {
    actions
        .iter()
        .filter_map(|a| match a {
            A::SendMessage(message) => Some(message.clone()),
            _ => None,
        })
        .collect()
}

fn pair() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut router = RouterSessionFsm::new();
    let mut modem = ModemSessionFsm::new();
    modem.step(E::TcpAccepted);
    let init = messages(&router.step(E::TcpConnected)).remove(0);
    let response = messages(&modem.step(E::RecvMessage(init))).remove(0);
    router.step(E::RecvMessage(response));
    (router, modem)
}

fn addresses(n: u8) -> DestinationAddrs {
    DestinationAddrs {
        v4: vec![format!("192.0.2.{n}").parse().unwrap()],
        v6: vec![format!("2001:db8::{n}").parse().unwrap()],
        v4_subnets: vec![format!("198.51.{n}.7/24").parse().unwrap()],
        v6_subnets: vec![format!("2001:db8:{n}::7/64").parse().unwrap()],
    }
}

fn set(addresses: DestinationAddrs) -> E {
    E::AppSetSessionAddresses { addresses }
}

fn response(status: S) -> E {
    E::RecvMessage(
        Message::new(M::SESSION_UPDATE_RESPONSE).with_item(DataItem::Status {
            code: status,
            text: "peer reply".into(),
        }),
    )
}

fn completion(actions: &[A], status: S) {
    assert!(
        matches!(actions.first(), Some(A::Emit(EmittedEvent::SessionUpdateResponse { status: got, text }))
        if *got == status && text == "peer reply")
    );
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, A::Emit(EmittedEvent::SessionUpdateResponse { .. })))
            .count(),
        1
    );
}

fn deliver(router: &mut RouterSessionFsm, actions: &[A]) -> Vec<Message> {
    let sent = messages(actions);
    for message in &sent {
        let bytes = message.encode().expect("every queued message must fit");
        let decoded = Message::decode(bytes.freeze()).unwrap();
        let replies = messages(&router.step(E::RecvMessage(decoded)));
        if message.message_type == M::SESSION_UPDATE {
            assert_eq!(replies.len(), 1);
            assert_eq!(replies[0].message_type, M::SESSION_UPDATE_RESPONSE);
            assert!(
                replies[0].data_items.iter().any(
                    |item| matches!(item, DataItem::Status { code, .. } if *code == S::SUCCESS)
                )
            );
        } else {
            assert_eq!(message.message_type, M::DESTINATION_UPDATE);
            assert!(replies.is_empty());
        }
    }
    sent
}

#[test]
fn replacements_coalesce_with_metrics_and_preserve_later_destination_changes() {
    let (mut router, mut modem) = pair();
    let mac = MacAddress::new_eui48([2, 0, 0, 0, 0, 1]);
    let up = messages(&modem.step(E::AppAddDestination {
        mac,
        metrics: LinkMetrics::default(),
        addrs: Default::default(),
    }))
    .remove(0);
    let ack = messages(&router.step(E::RecvMessage(up))).remove(0);
    modem.step(E::RecvMessage(ack));
    let first = modem.step(set(addresses(1)));
    assert_eq!(deliver(&mut router, &first).len(), 1);
    for n in 2..=100 {
        assert!(modem.step(set(addresses(n))).is_empty());
        assert_eq!(modem.local_addresses(), &addresses(n).canonical());
    }
    common::assert_rejected(
        modem.step(E::AppSessionAddresses {
            changes: AddressChanges::default(),
        }),
        CommandError::Busy,
    );
    let defaults = LinkMetrics {
        latency: Duration::from_micros(200),
        ..Default::default()
    };
    assert!(
        modem
            .step(E::AppQueueSessionUpdate { metrics: defaults })
            .is_empty()
    );
    let later = LinkMetrics {
        latency: Duration::from_micros(999),
        ..defaults
    };
    deliver(
        &mut router,
        &modem.step(E::AppUpdateMetrics {
            mac,
            metrics: later,
        }),
    );

    let actions = modem.step(response(S::REQUEST_DENIED));
    completion(&actions, S::REQUEST_DENIED);
    let sent = deliver(&mut router, &actions);
    assert_eq!(
        sent.len(),
        2,
        "one combined update, then the destination correction"
    );
    assert_eq!(extract_link_metrics(&sent[0]), Some(defaults));
    assert_eq!(
        AddressChanges::from_message(&sent[0]),
        AddressChanges {
            added: addresses(100).canonical(),
            removed: addresses(1).canonical(),
        }
    );
    assert_eq!(router.peer_addresses, addresses(100).canonical());
    assert_eq!(router.destinations[&mac].metrics, later);
    assert_eq!(modem.destinations[&mac].metrics, later);
    let actions = modem.step(response(S(42)));
    completion(&actions, S(42));
    assert!(messages(&actions).is_empty());
    assert!(
        modem.step(set(addresses(100))).is_empty(),
        "refusals do not roll back local state"
    );
    assert_eq!(modem.local_addresses(), &addresses(100).canonical());
    deliver(&mut router, &modem.step(set(DestinationAddrs::default())));
    assert!(router.peer_addresses.is_empty());
    assert_eq!(router.destinations[&mac].metrics, later);
}

#[test]
fn unchanged_or_reverted_desired_sets_cancel_unsent_work() {
    let (mut router, mut modem) = pair();
    assert!(modem.step(set(DestinationAddrs::default())).is_empty());
    deliver(&mut router, &modem.step(set(addresses(1))));
    assert!(modem.step(set(addresses(2))).is_empty());
    assert!(modem.step(set(addresses(1))).is_empty());
    let actions = modem.step(response(S::SUCCESS));
    completion(&actions, S::SUCCESS);
    assert!(messages(&actions).is_empty());
    assert!(!modem.tx.session_busy());
    // Existing delta commands still work once the transaction is released.
    deliver(
        &mut router,
        &modem.step(E::AppSessionAddresses {
            changes: AddressChanges {
                removed: addresses(1),
                added: addresses(3),
            },
        }),
    );
    assert_eq!(modem.local_addresses(), &addresses(3).canonical());
    assert_eq!(router.peer_addresses, addresses(3).canonical());
}

fn large(prefix: u16, count: u16) -> DestinationAddrs {
    DestinationAddrs {
        v6: (1..=count)
            .map(|n| format!("2001:db8:{prefix:x}::{n:x}").parse().unwrap())
            .collect(),
        ..Default::default()
    }
}

#[test]
fn invalid_replacements_preserve_previously_accepted_desired_state() {
    let (_, mut modem) = pair();
    modem.step(set(addresses(1)));
    modem.step(set(addresses(2)));
    let invalid = DestinationAddrs {
        v4_subnets: vec![
            "192.0.2.1/24".parse().unwrap(),
            "192.0.2.2/24".parse().unwrap(),
        ],
        ..Default::default()
    };
    for invalid in [invalid, large(1, 3121)] {
        common::assert_rejected(modem.step(set(invalid)), CommandError::InvalidInput);
        assert_eq!(modem.local_addresses(), &addresses(2).canonical());
    }
    let next = messages(&modem.step(response(S::SUCCESS))).remove(0);
    assert_eq!(
        AddressChanges::from_message(&next).added,
        addresses(2).canonical()
    );
}

#[test]
fn near_limit_sets_share_metric_updates_and_split_large_replacements() {
    let (mut router, mut modem) = pair();
    let initial = large(1, 3120);
    assert_eq!(
        AddressChanges {
            added: initial.clone(),
            removed: Default::default()
        }
        .append_to(Message::new(M::SESSION_UPDATE))
        .encode()
        .unwrap()
        .len(),
        65524
    );
    deliver(
        &mut router,
        &modem.step(E::AppQueueSessionUpdate {
            metrics: LinkMetrics::default(),
        }),
    );
    assert!(modem.step(set(initial.clone())).is_empty());
    let metrics = LinkMetrics {
        latency: Duration::from_micros(333),
        ..Default::default()
    };
    assert!(modem.step(E::AppQueueSessionUpdate { metrics }).is_empty());
    let first = modem.step(response(S::SUCCESS));
    completion(&first, S::SUCCESS);
    let sent = deliver(&mut router, &first);
    assert_eq!(sent.len(), 1);
    assert_eq!(extract_link_metrics(&sent[0]), Some(metrics));
    assert!(router.peer_addresses.v6.len() < initial.v6.len());
    assert_eq!(modem.local_addresses(), &initial);
    let second = modem.step(response(S::SUCCESS));
    assert_eq!(deliver(&mut router, &second).len(), 1);
    assert_eq!(router.peer_addresses, initial);
    assert!(messages(&modem.step(response(S::SUCCESS))).is_empty());

    let replacement = large(2, 3120);
    let first = modem.step(set(replacement.clone()));
    let sent = deliver(&mut router, &first);
    assert_eq!(sent.len(), 1);
    assert_eq!(AddressChanges::from_message(&sent[0]).removed, initial);
    assert!(
        router.peer_addresses.is_empty(),
        "removals precede additions across replies"
    );
    assert_eq!(modem.local_addresses(), &replacement);
    assert_eq!(
        deliver(&mut router, &modem.step(response(S::SUCCESS))).len(),
        1
    );
    assert_eq!(router.peer_addresses, replacement);
    assert_eq!(router.session_metrics, metrics);
    assert!(messages(&modem.step(response(S::SUCCESS))).is_empty());
    assert!(!modem.tx.session_busy());
}

#[test]
fn a_new_desired_set_supersedes_unsent_chunks() {
    let (mut router, mut modem) = pair();
    let initial = large(1, 3000);
    deliver(&mut router, &modem.step(set(initial)));
    modem.step(response(S::SUCCESS));
    deliver(&mut router, &modem.step(set(large(2, 3000))));
    assert!(!router.peer_addresses.is_empty());
    let partial = router.peer_addresses.clone();
    assert!(partial.v6.len() < 3000);
    assert!(modem.step(set(addresses(3))).is_empty());
    let sent = deliver(&mut router, &modem.step(response(S::SUCCESS)));
    assert_eq!(sent.len(), 1);
    assert_eq!(
        AddressChanges::from_message(&sent[0]),
        AddressChanges {
            removed: partial,
            added: addresses(3).canonical(),
        }
    );
    assert_eq!(router.peer_addresses, addresses(3).canonical());
    assert!(messages(&modem.step(response(S::SUCCESS))).is_empty());
}

#[test]
fn replacements_are_modem_only_and_do_not_escape_termination() {
    let (mut router, _) = pair();
    common::assert_rejected(router.step(set(addresses(1))), CommandError::Unsupported);
    common::assert_rejected(
        ModemSessionFsm::new().step(set(addresses(1))),
        CommandError::NotReady,
    );
    for stop in [
        E::AppShutdown {
            reason: S::SHUTTING_DOWN,
        },
        E::RecvMessage(Message::new(M::SESSION_UPDATE_RESPONSE)),
        response(S::INVALID_DATA),
        E::TcpClosed,
    ] {
        let (_, mut modem) = pair();
        modem.step(set(addresses(1)));
        modem.step(set(addresses(2)));
        let stopped = modem.step(stop);
        assert!(
            !stopped
                .iter()
                .any(|a| matches!(a, A::Emit(EmittedEvent::SessionUpdateResponse { .. })))
        );
        assert!(
            !messages(&stopped)
                .iter()
                .any(|m| m.message_type == M::SESSION_UPDATE)
        );
        assert!(
            !messages(&modem.step(response(S::SUCCESS)))
                .iter()
                .any(|m| m.message_type == M::SESSION_UPDATE)
        );
        common::assert_rejected(modem.step(set(addresses(3))), CommandError::NotReady);
    }
}
