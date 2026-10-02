use dlep_core::MacAddress;
use dlep_daemon::{
    AddressChanges, DaemonEvent, DestinationAddrs, DestinationEvent, DestinationId, LinkMetrics,
    ModemConfig, ModemDaemon, RouterConfig, RouterDaemon,
};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::timeout;

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
fn remove(n: u8) -> AddressChanges {
    AddressChanges {
        removed: addresses(n),
        added: Default::default(),
    }
}
fn id() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}
async fn modem() -> ModemDaemon {
    let mut c = ModemConfig::default();
    c.shared.network.use_tls = false;
    c.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    c.shared.network.tcp_port = 0;
    c.shared.network.discovery_port = 0;
    ModemDaemon::builder().config(c).spawn().await.unwrap()
}
async fn router() -> RouterDaemon {
    let mut c = RouterConfig::default();
    c.shared.network.use_tls = false;
    RouterDaemon::builder().config(c).spawn().await.unwrap()
}
async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.unwrap();
            assert!(
                !matches!(event, DaemonEvent::SessionDown { .. }),
                "session failed: {event:?}"
            );
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}
async fn up(rx: &mut broadcast::Receiver<DaemonEvent>) -> dlep_ext::SessionId {
    match event(rx, |e| matches!(e, DaemonEvent::SessionUp { .. })).await {
        DaemonEvent::SessionUp { session_id, .. } => session_id,
        _ => unreachable!(),
    }
}
async fn session_addresses(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    expected_id: dlep_ext::SessionId,
    expected: AddressChanges,
    snapshot: DestinationAddrs,
) {
    match event(rx, |e| matches!(e, DaemonEvent::SessionAddresses { .. })).await {
        DaemonEvent::SessionAddresses {
            session_id,
            changes,
            addresses,
            ..
        } => {
            assert_eq!(session_id, expected_id);
            assert_eq!(changes, expected);
            assert_eq!(addresses, snapshot);
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn peer_address_changes_and_removals_flow_in_both_directions() {
    let m = modem().await;
    let r = router().await;
    let mut me = m.subscribe();
    let mut re = r.subscribe();
    r.connect_static(m.local_addr()).await.unwrap();
    let router_id = up(&mut re).await;
    let modem_id = up(&mut me).await;
    r.update_session_addresses(router_id, add(1)).await.unwrap();
    session_addresses(&mut me, modem_id, add(1), addresses(1)).await;
    // Alternating directions also guarantees the preceding response has been
    // processed before another command uses the same session transaction slot.
    m.update_session_addresses(modem_id, add(2)).await.unwrap();
    session_addresses(&mut re, router_id, add(2), addresses(2)).await;
    r.update_session_addresses(router_id, remove(1))
        .await
        .unwrap();
    session_addresses(&mut me, modem_id, remove(1), DestinationAddrs::default()).await;
    m.update_session_addresses(modem_id, remove(2))
        .await
        .unwrap();
    session_addresses(&mut re, router_id, remove(2), DestinationAddrs::default()).await;
    r.shutdown().await.unwrap();
    m.shutdown().await.unwrap();
}

#[tokio::test]
async fn destination_address_snapshots_and_removals_are_scoped_to_the_modem() {
    let first = modem().await;
    let second = modem().await;
    let r = router().await;
    let mut events = r.subscribe();
    r.connect_static(first.local_addr()).await.unwrap();
    let first_id = up(&mut events).await;
    r.connect_static(second.local_addr()).await.unwrap();
    let second_id = up(&mut events).await;
    for (m, expected_id) in [(&first, first_id), (&second, second_id)] {
        m.add_destination_with_addresses(id(), LinkMetrics::default(), addresses(1))
            .await
            .unwrap();
        let up = event(&mut events, |e| {
            matches!(
                e,
                DaemonEvent::Destination {
                    event: DestinationEvent::Up { .. },
                    ..
                }
            )
        })
        .await;
        match up {
            DaemonEvent::Destination {
                session_id,
                peer,
                event:
                    DestinationEvent::Up {
                        v4_addrs,
                        v6_addrs,
                        v4_subnets,
                        v6_subnets,
                        ..
                    },
            } => {
                assert_eq!(session_id, expected_id);
                assert_eq!(peer.addr, m.local_addr());
                assert_eq!(
                    DestinationAddrs {
                        v4: v4_addrs,
                        v6: v6_addrs,
                        v4_subnets,
                        v6_subnets
                    },
                    addresses(1)
                );
            }
            _ => unreachable!(),
        }
    }
    let changes = AddressChanges {
        added: addresses(2),
        removed: addresses(1),
    };
    first
        .update_destination_addresses(id(), changes.clone())
        .await
        .unwrap();
    let changed = event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::AddressesChanged { .. },
                ..
            }
        )
    })
    .await;
    match changed {
        DaemonEvent::Destination {
            session_id,
            peer,
            event:
                DestinationEvent::AddressesChanged {
                    id: got,
                    changes: actual,
                    addresses: snapshot,
                },
        } => {
            assert_eq!(session_id, first_id);
            assert_eq!(peer.addr, first.local_addr());
            assert_eq!(got, id());
            assert_eq!(actual, changes);
            assert_eq!(snapshot, addresses(2));
        }
        _ => unreachable!(),
    }
    // The same addresses remain associated with the second modem and can be
    // removed there independently without an Invalid Data termination.
    second
        .update_destination_addresses(id(), remove(1))
        .await
        .unwrap();
    let changed = event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::AddressesChanged { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(changed, DaemonEvent::Destination { session_id, event: DestinationEvent::AddressesChanged { changes, addresses, .. }, .. } if session_id == second_id && changes == remove(1) && addresses.is_empty())
    );
    r.shutdown().await.unwrap();
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
}

#[tokio::test]
async fn ambiguous_application_address_batches_are_rejected_before_sending() {
    let m = modem().await;
    let r = router().await;
    let mut events = r.subscribe();
    r.connect_static(m.local_addr()).await.unwrap();
    let session_id = up(&mut events).await;
    let bad = AddressChanges {
        added: addresses(1),
        removed: addresses(1),
    };
    assert!(
        r.update_session_addresses(session_id, bad.clone())
            .await
            .is_err()
    );
    assert!(m.update_destination_addresses(id(), bad).await.is_err());
    let mut duplicate = addresses(1);
    duplicate.v6.push(duplicate.v6[0]);
    assert!(
        m.add_destination_with_addresses(id(), LinkMetrics::default(), duplicate)
            .await
            .is_err()
    );
    m.add_destination_with_addresses(id(), LinkMetrics::default(), addresses(1))
        .await
        .unwrap();
    event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Up { .. },
                ..
            }
        )
    })
    .await;
    r.shutdown().await.unwrap();
    m.shutdown().await.unwrap();
}
