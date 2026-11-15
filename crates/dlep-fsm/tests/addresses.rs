mod common;
use dlep_core::{
    DataItem, LinkMetrics, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
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
fn hints(old: u8, new: u8) -> AddressChanges {
    let mut changes = replace(old, new);
    for addresses in [&mut changes.added, &mut changes.removed] {
        addresses.v4_subnets.clear();
        addresses.v6_subnets.clear();
    }
    changes
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
    sessions_with_format(MacAddressFormat::Eui48)
}
fn sessions_with_format(format: MacAddressFormat) -> (RouterSessionFsm, ModemSessionFsm) {
    let config = dlep_fsm::SessionConfig {
        mac_address_format: format,
        ..Default::default()
    };
    let mut r = RouterSessionFsm::with_config(config.clone());
    let mut m = ModemSessionFsm::with_config(config);
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
fn large_coalesced_address_replacements_keep_every_update_encodable() {
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        let destination = match format {
            MacAddressFormat::Eui48 => mac(1),
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        };
        let initial_metrics = LinkMetrics {
            resources: Some(80),
            rlq_rx: Some(60),
            rlq_tx: Some(70),
            mtu: Some(1500),
            ..Default::default()
        };
        let config = dlep_fsm::SessionConfig {
            mac_address_format: format,
            initial_metrics,
            ..Default::default()
        };
        let mut r = RouterSessionFsm::with_config(config.clone());
        let mut m = ModemSessionFsm::with_config(config);
        m.step(E::TcpAccepted);
        let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
        let response = sent(
            &m.step(E::RecvMessage(init)),
            M::SESSION_INITIALIZATION_RESPONSE,
        );
        r.step(E::RecvMessage(response));
        let large = |n| DestinationAddrs {
            v6: (1..=3000)
                .map(|suffix| std::net::Ipv6Addr::new(0x2001, 0xdb8, n, 0, 0, 0, 0, suffix))
                .collect(),
            ..addresses(n as u8)
        };
        let old = large(1);
        let new = large(2);
        let up = sent(
            &m.step(E::AppAddDestination {
                mac: destination,
                metrics: initial_metrics,
                addrs: old.clone(),
            }),
            M::DESTINATION_UP,
        );
        let up = Message::decode(up.encode().unwrap().freeze()).unwrap();
        let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
        // Each accepted batch and resulting snapshot fits individually. The
        // accumulated removals plus additions exceed one 16-bit message body.
        for start in [0, 1000, 2000] {
            let changes = AddressChanges {
                added: DestinationAddrs {
                    v6: new.v6[start..start + 1000].to_vec(),
                    ..if start == 0 {
                        addresses(2)
                    } else {
                        DestinationAddrs::default()
                    }
                },
                removed: DestinationAddrs {
                    v6: old.v6[start..start + 1000].to_vec(),
                    ..if start == 0 {
                        addresses(1)
                    } else {
                        DestinationAddrs::default()
                    }
                },
            };
            assert!(
                m.step(E::AppUpdateAddresses {
                    mac: destination,
                    changes
                })
                .is_empty()
            );
        }
        let metrics = LinkMetrics {
            latency: Duration::from_micros(900),
            rlq_rx: Some(0),
            mtu: Some(1400),
            ..initial_metrics
        };
        assert!(
            m.step(E::AppUpdateMetrics {
                mac: destination,
                metrics
            })
            .is_empty()
        );
        let actions = m.step(E::RecvMessage(ack));
        let mut updates = 0;
        let mut metric_updates = 0;
        let mut advertised = old;
        for action in actions {
            let A::SendMessage(message) = action else {
                continue;
            };
            assert_eq!(message.message_type, M::DESTINATION_UPDATE);
            let encoded = message
                .encode()
                .expect("coalesced update must fit on the wire");
            assert!(encoded.len() <= usize::from(u16::MAX) + 4);
            let message = Message::decode(encoded.freeze()).unwrap();
            assert_eq!(
                dlep_fsm::session_common::extract_destination_mac(&message),
                Some(destination)
            );
            if let Some(actual) = dlep_fsm::session_common::extract_link_metrics(&message) {
                assert_eq!(actual, metrics);
                metric_updates += 1;
            }
            AddressChanges::from_message(&message)
                .apply_strict(&mut advertised)
                .unwrap();
            r.step(E::RecvMessage(message));
            assert_eq!(r.state(), RouterSessionState::InSession);
            updates += 1;
        }
        assert_eq!(updates, 2);
        assert_eq!(metric_updates, 1);
        assert_eq!(advertised, new);
        assert_eq!(r.destinations[&destination].addrs, new);
        assert_eq!(r.destinations[&destination].metrics, metrics);
        assert_eq!(m.destinations[&destination].advertised_addrs, new);
        assert!(!m.destinations[&destination].pending_metrics);
        assert_eq!(m.state(), ModemSessionState::InSession);
        // A subsequent no-op must not replay any portion of the split update.
        assert!(
            m.step(E::AppUpdateAddresses {
                mac: destination,
                changes: AddressChanges::default()
            })
            .is_empty()
        );
    }
}

#[test]
fn near_limit_destinations_reannounce_without_overflowing_the_status_item() {
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        let destination = match format {
            MacAddressFormat::Eui48 => mac(1),
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        };
        let metrics = LinkMetrics {
            resources: Some(80),
            rlq_rx: Some(60),
            rlq_tx: Some(70),
            mtu: Some(1500),
            ..Default::default()
        };
        let config = dlep_fsm::SessionConfig {
            mac_address_format: format,
            initial_metrics: metrics,
            ..Default::default()
        };
        let mut r = RouterSessionFsm::with_config(config.clone());
        let mut m = ModemSessionFsm::with_config(config);
        m.step(E::TcpAccepted);
        let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
        let response = sent(
            &m.step(E::RecvMessage(init)),
            M::SESSION_INITIALIZATION_RESPONSE,
        );
        r.step(E::RecvMessage(response));
        // Address items total 65,441 bytes. With all declared metrics and the
        // MAC, Up fits with just 3 (EUI-48) or 1 (EUI-64) body bytes to spare.
        let mut expected = DestinationAddrs {
            v4: (1..=4)
                .map(|n| std::net::Ipv4Addr::new(192, 0, 2, n))
                .collect(),
            v6: (1..=3113)
                .map(|n| std::net::Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, n))
                .collect(),
            v4_subnets: vec!["198.51.100.0/24".parse().unwrap()],
            v6_subnets: vec!["2001:db8:2::/64".parse().unwrap()],
        };
        let up = sent(
            &m.step(E::AppAddDestination {
                mac: destination,
                metrics,
                addrs: expected.clone(),
            }),
            M::DESTINATION_UP,
        );
        let up = Message::decode(up.encode().unwrap().freeze()).unwrap();
        let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
        m.step(E::RecvMessage(ack));
        let down = sent(
            &r.step(E::AppDropDestination {
                mac: destination,
                reason: S::SUCCESS,
            }),
            M::DESTINATION_DOWN,
        );
        let ack = sent(&m.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
        r.step(E::RecvMessage(ack));
        assert!(!r.destinations.contains_key(&destination));
        let latest = LinkMetrics {
            latency: Duration::from_micros(900),
            resources: Some(0),
            ..metrics
        };
        assert!(
            m.step(E::AppUpdateMetrics {
                mac: destination,
                metrics: latest
            })
            .is_empty()
        );
        let announce = sent(
            &r.step(E::AppAnnounceDestination { mac: destination }),
            M::DESTINATION_ANNOUNCE,
        );
        let mut observed = DestinationAddrs::default();
        let mut count = 0;
        for action in m.step(E::RecvMessage(announce)) {
            let A::SendMessage(message) = action else {
                continue;
            };
            let encoded = message
                .encode()
                .expect("Announce must include Status without exceeding the wire limit");
            assert!(encoded.len() <= usize::from(u16::MAX) + 4);
            let message = Message::decode(encoded.freeze()).unwrap();
            if count == 0 {
                assert_eq!(message.message_type, M::DESTINATION_ANNOUNCE_RESPONSE);
                assert_eq!(status(&message), S::SUCCESS);
                assert_eq!(
                    dlep_fsm::session_common::extract_link_metrics(&message),
                    Some(latest)
                );
            } else {
                assert_eq!(message.message_type, M::DESTINATION_UPDATE);
                assert!(dlep_fsm::session_common::extract_link_metrics(&message).is_none());
                assert!(dlep_fsm::session_common::extract_status(&message).is_none());
            }
            assert_eq!(
                dlep_fsm::session_common::extract_destination_mac(&message),
                Some(destination)
            );
            AddressChanges::from_message(&message)
                .apply_strict(&mut observed)
                .unwrap();
            r.step(E::RecvMessage(message));
            assert_eq!(r.state(), RouterSessionState::InSession);
            count += 1;
        }
        assert_eq!(count, 2);
        assert_eq!(observed, expected);
        assert_eq!(r.destinations[&destination].addrs, expected);
        assert_eq!(r.destinations[&destination].metrics, latest);
        assert_eq!(m.destinations[&destination].advertised_addrs, expected);
        assert!(m.destinations[&destination].announced);
        assert!(!m.destinations[&destination].pending_metrics);
        // Later updates use the completed advertisement, including addresses
        // delivered after the response, without duplicating the full snapshot.
        let removed = DestinationAddrs {
            v6_subnets: expected.v6_subnets.clone(),
            ..Default::default()
        };
        let update = sent(
            &m.step(E::AppUpdateAddresses {
                mac: destination,
                changes: AddressChanges {
                    added: DestinationAddrs::default(),
                    removed: removed.clone(),
                },
            }),
            M::DESTINATION_UPDATE,
        );
        assert_eq!(AddressChanges::from_message(&update).removed, removed);
        r.step(E::RecvMessage(update));
        expected.v6_subnets.clear();
        assert_eq!(r.destinations[&destination].addrs, expected);
        assert_eq!(m.state(), ModemSessionState::InSession);
    }
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
    let hints = hints(2, 5);
    let request = sent(
        &r.step(E::AppAnnounceDestinationWithAddresses {
            mac: mac(1),
            changes: hints.clone(),
        }),
        M::DESTINATION_ANNOUNCE,
    );
    let actions = m.step(E::RecvMessage(request));
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::DestinationAnnounced { requested_addresses, .. }) if *requested_addresses == hints)));
    let response = sent(&actions, M::DESTINATION_ANNOUNCE_RESPONSE);
    r.step(E::RecvMessage(response));
    assert_eq!(r.destinations[&mac(1)].addrs, addresses(2));
    assert_eq!(m.destinations[&mac(1)].addrs, addresses(2));
    assert_eq!(m.state(), ModemSessionState::InSession);
}

#[test]
fn announce_address_hints_validate_without_mutating_addresses_or_transactions() {
    use dlep_fsm::CommandError as C;
    let command = |changes| E::AppAnnounceDestinationWithAddresses {
        mac: mac(2),
        changes,
    };
    let (mut r, mut m) = sessions();
    common::assert_rejected(RouterSessionFsm::new().step(command(add(1))), C::NotReady);
    common::assert_rejected(m.step(command(add(1))), C::Unsupported);
    let mut duplicates = add(1);
    duplicates.added.v4.push(duplicates.added.v4[0]);
    let mut subnet_duplicates = add(1);
    subnet_duplicates
        .added
        .v6_subnets
        .push("2001:db8:1::7/64".parse().unwrap());
    let mut duplicate_ips = hints(1, 2);
    duplicate_ips.added.v4.push(duplicate_ips.added.v4[0]);
    for invalid in [
        duplicates,
        subnet_duplicates,
        replace(1, 1),
        duplicate_ips,
        hints(1, 1),
    ] {
        common::assert_rejected(r.step(command(invalid)), C::InvalidInput);
        assert!(r.tx.per_destination.is_empty());
        assert!(r.local_addresses().is_empty());
        assert!(r.destinations.is_empty());
    }
    let hints = hints(1, 2);
    let request = sent(&r.step(command(hints.clone())), M::DESTINATION_ANNOUNCE);
    assert_eq!(AddressChanges::from_message(&request), hints.canonical());
    common::assert_rejected(r.step(command(add(3))), C::Busy);
    assert!(r.local_addresses().is_empty());
    assert!(r.destinations.is_empty());
    let actions = m.step(E::RecvMessage(request));
    assert!(actions.iter().any(|a| matches!(a,
        A::Emit(EmittedEvent::DestinationAnnounced { requested_addresses, .. })
        if *requested_addresses == hints.canonical())));
    assert!(m.destinations.is_empty());
    assert!(m.local_addresses().is_empty());
    let denied = sent(&actions, M::DESTINATION_ANNOUNCE_RESPONSE);
    assert_eq!(status(&denied), S::REQUEST_DENIED);
    r.step(E::RecvMessage(denied));
    // Unlike a session-address no-op, empty hints still request a response.
    let request = sent(
        &r.step(command(AddressChanges::default())),
        M::DESTINATION_ANNOUNCE,
    );
    let denied = sent(
        &m.step(E::RecvMessage(request)),
        M::DESTINATION_ANNOUNCE_RESPONSE,
    );
    r.step(E::RecvMessage(denied));
    announce_up(&mut r, &mut m, 2, addresses(4));
    common::assert_rejected(r.step(command(add(3))), C::AlreadyExists);
    r.step(E::AppShutdown {
        reason: S::SHUTTING_DOWN,
    });
    common::assert_rejected(r.step(command(add(3))), C::NotReady);
}

#[test]
fn announce_address_budget_includes_the_mac_in_both_formats() {
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        let (mut r, mut m) = sessions_with_format(format);
        let destination = match format {
            MacAddressFormat::Eui48 => mac(1),
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        };
        let changes = AddressChanges {
            added: DestinationAddrs {
                v6: (1..=3120u128).map(std::net::Ipv6Addr::from).collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut oversized = changes.clone();
        oversized.added.v4.push("192.0.2.1".parse().unwrap());
        assert!(
            oversized
                .append_to(Message::new(M::SESSION_UPDATE))
                .encode()
                .is_ok()
        );
        common::assert_rejected(
            r.step(E::AppAnnounceDestinationWithAddresses {
                mac: destination,
                changes: oversized,
            }),
            dlep_fsm::CommandError::InvalidInput,
        );
        assert!(r.tx.per_destination.is_empty());
        let request = sent(
            &r.step(E::AppAnnounceDestinationWithAddresses {
                mac: destination,
                changes: changes.clone(),
            }),
            M::DESTINATION_ANNOUNCE,
        );
        let decoded = Message::decode(request.encode().unwrap().freeze()).unwrap();
        let actions = m.step(E::RecvMessage(decoded));
        assert!(actions.iter().any(|a| matches!(a,
            A::Emit(EmittedEvent::DestinationAnnounced { requested_addresses, .. })
            if *requested_addresses == changes)));
        assert!(m.destinations.is_empty());
    }
}
