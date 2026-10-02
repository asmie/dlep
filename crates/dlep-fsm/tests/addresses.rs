mod common;
use dlep_core::{DataItem, LinkMetrics, MacAddress, Message, MessageType as M, StatusCode as S};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::build_destination_update;
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{AddressChanges, DestinationAddrs, FsmAction as A, FsmEvent as E};
use std::time::Duration;

fn mac(n: u8) -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, n])
}
fn addresses(n: u8) -> DestinationAddrs {
    DestinationAddrs {
        v4: vec![format!("192.0.2.{n}").parse().unwrap()],
        v6: vec![format!("2001:db8::{n}").parse().unwrap()],
        v4_subnets: vec![format!("198.51.{n}.0/24").parse().unwrap()],
        v6_subnets: vec![format!("2001:db8:{n}::/64").parse().unwrap()],
    }
}
fn add(n: u8) -> AddressChanges {
    AddressChanges {
        added: addresses(n),
        removed: Default::default(),
    }
}
fn replace(old: u8, new: u8) -> AddressChanges {
    AddressChanges {
        added: addresses(new),
        removed: addresses(old),
    }
}
fn sent(actions: &[A], kind: M) -> Message {
    actions
        .iter()
        .find_map(|a| match a {
            A::SendMessage(m) if m.message_type == kind => Some(m.clone()),
            _ => None,
        })
        .expect("expected message")
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
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::new();
    m.step(E::TcpAccepted);
    let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let response = sent(
        &m.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    r.step(E::RecvMessage(response));
    (r, m)
}
fn announce_up(r: &mut RouterSessionFsm, m: &mut ModemSessionFsm, n: u8, addrs: DestinationAddrs) {
    let up = sent(
        &m.step(E::AppAddDestination {
            mac: mac(n),
            metrics: LinkMetrics::default(),
            addrs,
        }),
        M::DESTINATION_UP,
    );
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
}

#[test]
fn address_changes_codec_roundtrip_and_atomic_session_validation() {
    let changes = replace(1, 2);
    let message = changes.append_to(Message::new(M::SESSION_UPDATE));
    let decoded = Message::decode(message.encode().unwrap().freeze()).unwrap();
    assert_eq!(AddressChanges::from_message(&decoded), changes);
    let mut current = addresses(1);
    changes.apply_strict(&mut current).unwrap();
    assert_eq!(current, addresses(2));
    let invalid = AddressChanges {
        added: addresses(3),
        removed: addresses(99),
    };
    assert_eq!(invalid.apply_strict(&mut current), Err(S::INVALID_DATA));
    assert_eq!(current, addresses(2));
    assert!(add(2).apply_strict(&mut current).is_err());
}

#[test]
fn contradictory_operations_and_equivalent_subnet_duplicates_are_detected() {
    let mut changes = add(1);
    changes.removed.v6 = changes.added.v6.clone();
    assert!(changes.validate().is_err());
    let mut changes = AddressChanges::default();
    changes.added.v4_subnets = vec![
        "192.0.2.1/24".parse().unwrap(),
        "192.0.2.99/24".parse().unwrap(),
    ];
    assert!(changes.validate().is_err());
    let mut current = DestinationAddrs::default();
    AddressChanges {
        added: DestinationAddrs {
            v4_subnets: vec!["192.0.2.9/24".parse().unwrap()],
            ..Default::default()
        },
        ..Default::default()
    }
    .apply_strict(&mut current)
    .unwrap();
    assert_eq!(current.v4_subnets[0], "192.0.2.0/24".parse().unwrap());
}

#[test]
fn initialization_addresses_are_retained_and_emitted_by_both_roles() {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::new();
    m.step(E::TcpAccepted);
    let init = add(1).append_to(sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION));
    let actions = m.step(E::RecvMessage(init));
    assert_eq!(m.peer_addresses, addresses(1));
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::SessionAddressesUpdate { addresses: set, .. }) if *set == addresses(1))));
    let response = add(2).append_to(sent(&actions, M::SESSION_INITIALIZATION_RESPONSE));
    let actions = r.step(E::RecvMessage(response));
    assert_eq!(r.peer_addresses, addresses(2));
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::SessionAddressesUpdate { changes, .. }) if **changes == add(2))));
}

#[test]
fn peer_updates_add_and_remove_all_four_families_on_both_roles() {
    let (mut r, mut m) = sessions();
    for changes in [
        add(1),
        replace(1, 2),
        AddressChanges {
            added: Default::default(),
            removed: addresses(2),
        },
    ] {
        let message = changes.append_to(Message::new(M::SESSION_UPDATE));
        for actions in [
            r.step(E::RecvMessage(message.clone())),
            m.step(E::RecvMessage(message)),
        ] {
            assert_eq!(
                status(&sent(&actions, M::SESSION_UPDATE_RESPONSE)),
                S::SUCCESS
            );
            assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::SessionAddressesUpdate { changes: got, .. }) if **got == changes)));
        }
        assert_eq!(r.peer_addresses, changes.added);
        assert_eq!(m.peer_addresses, changes.added);
    }
}

#[test]
fn inconsistent_session_addresses_terminate_without_partial_changes() {
    for bad in [
        add(1),
        AddressChanges {
            added: addresses(3),
            removed: addresses(2),
        },
        replace(1, 1),
    ] {
        let (mut r, mut m) = sessions();
        let message = add(1).append_to(Message::new(M::SESSION_UPDATE));
        r.step(E::RecvMessage(message.clone()));
        m.step(E::RecvMessage(message));
        let bad = bad.append_to(Message::new(M::SESSION_UPDATE));
        assert_eq!(
            status(&sent(
                &r.step(E::RecvMessage(bad.clone())),
                M::SESSION_TERMINATION
            )),
            S::INVALID_DATA
        );
        assert_eq!(
            status(&sent(&m.step(E::RecvMessage(bad)), M::SESSION_TERMINATION)),
            S::INVALID_DATA
        );
        assert_eq!(r.peer_addresses, addresses(1));
        assert_eq!(m.peer_addresses, addresses(1));
    }
}

#[test]
fn session_sender_emits_only_effective_changes_and_shares_transaction_slot() {
    let (mut r, mut m) = sessions();
    let message = sent(
        &r.step(E::AppSessionAddresses { changes: add(1) }),
        M::SESSION_UPDATE,
    );
    assert_eq!(message.data_items.len(), 4); // no router-originated metric items
    let ack = sent(&m.step(E::RecvMessage(message)), M::SESSION_UPDATE_RESPONSE);
    common::assert_rejected(
        r.step(E::AppSessionAddresses {
            changes: replace(1, 2),
        }),
        dlep_fsm::CommandError::Busy,
    );
    r.step(E::RecvMessage(ack));
    assert!(
        r.step(E::AppSessionAddresses { changes: add(1) })
            .is_empty()
    );
    let message = sent(
        &r.step(E::AppSessionAddresses {
            changes: replace(1, 2),
        }),
        M::SESSION_UPDATE,
    );
    assert_eq!(AddressChanges::from_message(&message), replace(1, 2));
    assert_eq!(m.peer_addresses, addresses(1));
    m.step(E::RecvMessage(message));
    assert_eq!(m.peer_addresses, addresses(2));
}

#[test]
fn destination_removals_emit_deltas_and_snapshots_without_zeroing_metrics() {
    let (mut r, mut m) = sessions();
    announce_up(&mut r, &mut m, 1, addresses(1));
    let metrics = LinkMetrics {
        latency: Duration::from_millis(8),
        ..Default::default()
    };
    r.step(E::RecvMessage(build_destination_update(mac(1), &metrics)));
    let update = sent(
        &m.step(E::AppUpdateAddresses {
            mac: mac(1),
            changes: replace(1, 2),
        }),
        M::DESTINATION_UPDATE,
    );
    assert!(
        update
            .data_items
            .iter()
            .all(|i| !(12..=20).contains(&i.type_id().0))
    );
    let actions = r.step(E::RecvMessage(update));
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(2));
    assert_eq!(r.destinations[&mac(1)].metrics.latency, metrics.latency);
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::DestinationAddressesUpdate { changes, addresses: set, .. }) if **changes == replace(1, 2) && *set == addresses(2))));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, A::Emit(EmittedEvent::DestinationUpdate { .. })))
    );
}

#[test]
fn destination_logical_inconsistencies_are_nonfatal_and_metrics_still_apply() {
    let (mut r, mut m) = sessions();
    announce_up(&mut r, &mut m, 1, addresses(1));
    let changes = AddressChanges {
        added: addresses(1),
        removed: addresses(99),
    };
    let message = changes.append_to(
        Message::new(M::DESTINATION_UPDATE)
            .with_item(DataItem::MacAddress(mac(1)))
            .with_item(DataItem::Latency(Duration::from_millis(9))),
    );
    r.step(E::RecvMessage(message));
    assert_eq!(r.state(), RouterSessionState::InSession);
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(1));
    assert_eq!(
        r.destinations[&mac(1)].metrics.latency,
        Duration::from_millis(9)
    );
}

#[test]
fn addresses_cannot_be_stolen_from_another_destination_or_peer() {
    let (mut r, mut m) = sessions();
    announce_up(&mut r, &mut m, 1, addresses(1));
    announce_up(&mut r, &mut m, 2, DestinationAddrs::default());
    r.step(E::RecvMessage(
        add(3).append_to(Message::new(M::SESSION_UPDATE)),
    ));
    for n in [1, 3] {
        let message = add(n)
            .append_to(Message::new(M::DESTINATION_UPDATE).with_item(DataItem::MacAddress(mac(2))));
        r.step(E::RecvMessage(message));
        assert!(r.destinations[&mac(2)].addrs.is_empty());
    }
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(1));
    assert_eq!(r.state(), RouterSessionState::InSession);
}

#[test]
fn address_changes_before_up_ack_coalesce_to_the_latest_state() {
    let (mut r, mut m) = sessions();
    let up = sent(
        &m.step(E::AppAddDestination {
            mac: mac(1),
            metrics: LinkMetrics::default(),
            addrs: addresses(1),
        }),
        M::DESTINATION_UP,
    );
    assert!(
        m.step(E::AppUpdateAddresses {
            mac: mac(1),
            changes: replace(1, 2)
        })
        .is_empty()
    );
    assert!(
        m.step(E::AppUpdateAddresses {
            mac: mac(1),
            changes: replace(2, 3)
        })
        .is_empty()
    );
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    let update = sent(&m.step(E::RecvMessage(ack)), M::DESTINATION_UPDATE);
    assert_eq!(AddressChanges::from_message(&update), replace(1, 3));
    r.step(E::RecvMessage(update));
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(3));
}

#[test]
fn withdrawn_destinations_reannounce_current_addresses_and_preserve_request_hints() {
    let (mut r, mut m) = sessions();
    announce_up(&mut r, &mut m, 1, addresses(1));
    let down = sent(
        &r.step(E::AppDropDestination {
            mac: mac(1),
            reason: S::SUCCESS,
        }),
        M::DESTINATION_DOWN,
    );
    let ack = sent(&m.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
    r.step(E::RecvMessage(ack));
    assert!(
        m.step(E::AppUpdateAddresses {
            mac: mac(1),
            changes: replace(1, 2)
        })
        .is_empty()
    );
    let request = sent(
        &r.step(E::AppAnnounceDestination { mac: mac(1) }),
        M::DESTINATION_ANNOUNCE,
    );
    let hints = AddressChanges {
        removed: DestinationAddrs {
            v6: addresses(5).v6,
            ..Default::default()
        },
        ..Default::default()
    };
    let actions = m.step(E::RecvMessage(hints.append_to(request)));
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::DestinationAnnounced { requested_addresses, .. }) if *requested_addresses == hints)));
    let response = sent(&actions, M::DESTINATION_ANNOUNCE_RESPONSE);
    r.step(E::RecvMessage(response));
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(2));
    assert_eq!(m.state(), ModemSessionState::InSession);
}
