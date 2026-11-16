use std::time::Duration;

use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::{
    AddressChanges, CommandError, DaemonError, DaemonSnapshot, DestinationAddrs, DestinationId,
    DestinationPhase, LinkMetrics, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon,
    SessionCommand,
};
use tokio::sync::{broadcast, watch};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

fn id() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}

fn addresses(n: u8) -> DestinationAddrs {
    DestinationAddrs {
        v4: vec![format!("192.0.2.{n}").parse().unwrap()],
        v6: vec![format!("2001:db8::{n}").parse().unwrap()],
        v4_subnets: vec![format!("198.51.{n}.0/24").parse().unwrap()],
        v6_subnets: vec![format!("2001:db8:{n}::/64").parse().unwrap()],
    }
}

async fn modem(ip: &str) -> ModemDaemon {
    let mut config = ModemConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = ip.parse().unwrap();
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
    config.metrics.max_data_rate_tx_bps = 1_000_000;
    config.metrics.mtu = Some(1500);
    ModemDaemon::builder().config(config).spawn().await.unwrap()
}

async fn router() -> RouterDaemon {
    let mut config = RouterConfig::default();
    config.shared.network.use_tls = false;
    RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .unwrap()
}

async fn wait(
    state: &mut watch::Receiver<DaemonSnapshot>,
    predicate: impl Fn(&DaemonSnapshot) -> bool,
) -> DaemonSnapshot {
    timeout(WAIT, async {
        loop {
            let snapshot = state.borrow_and_update().clone();
            if predicate(&snapshot) {
                return snapshot;
            }
            state.changed().await.unwrap();
        }
    })
    .await
    .expect("state did not converge")
}

// State publication is local acceptance, not the peer's acknowledgement of a
// session transaction. Retry only explicit Busy rejections, never unknown or
// partially accepted outcomes.
async fn accept<F, Fut>(mut command: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), DaemonError>>,
{
    timeout(WAIT, async {
        loop {
            match command().await {
                Ok(()) => return,
                Err(DaemonError::CommandRejected(report))
                    if report.accepted.is_empty()
                        && report.undelivered == 0
                        && report.unknown == 0
                        && !report.rejected.is_empty()
                        && report
                            .rejected
                            .iter()
                            .all(|(_, r)| r.reason == CommandError::Busy) =>
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                result => panic!("unexpected command result: {result:?}"),
            }
        }
    })
    .await
    .expect("session transaction did not complete");
}

async fn recovery(ip: &str) {
    let modem = modem(ip).await;
    let router = router().await;
    let mut events = router.subscribe();
    // No snapshot subscribers during initialization: state must still be kept.
    router.connect_static(modem.local_addr()).await.unwrap();
    let mut rs = router.state();
    let mut ms = modem.state();
    let initial = wait(&mut rs, |s| s.sessions.len() == 1).await;
    let rid = *initial.sessions.keys().next().unwrap();
    let m = wait(&mut ms, |s| s.sessions.len() == 1).await;
    let mid = *m.sessions.keys().next().unwrap();
    assert_eq!(initial.sessions[&rid].metrics.mtu, Some(1500));
    assert_eq!(initial.sessions[&rid].metrics, m.sessions[&mid].metrics);
    assert_eq!(initial.sessions[&rid].peer.addr, modem.local_addr());
    assert_eq!(
        initial.sessions[&rid].peer.peer_description.as_deref(),
        Some("dlep-modem")
    );

    let metrics = LinkMetrics {
        current_data_rate_tx_bps: 1,
        max_data_rate_tx_bps: 1_000_000,
        ..Default::default()
    };
    modem
        .add_destination_with_addresses(id(), metrics, addresses(1))
        .await
        .unwrap();
    let before = wait(&mut rs, |s| {
        s.sessions[&rid].destinations.contains_key(&id())
    })
    .await;
    wait(&mut ms, |s| {
        s.sessions[&mid]
            .destinations
            .get(&id())
            .is_some_and(|d| d.phase == DestinationPhase::Up)
    })
    .await;
    assert_eq!(
        before.sessions[&rid].destinations[&id()].metrics.mtu,
        Some(1500)
    );

    // Overflow the public broadcast while the retained state receiver is idle.
    for rate in 2..=400 {
        modem
            .update_destination(
                id(),
                LinkMetrics {
                    current_data_rate_tx_bps: rate,
                    ..metrics
                },
            )
            .await
            .unwrap();
    }
    let latest = wait(&mut rs, |s| {
        s.sessions[&rid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps
            == 400
    })
    .await;
    assert!(matches!(
        events.recv().await,
        Err(broadcast::error::RecvError::Lagged(_))
    ));
    assert!(latest.generation > before.generation);
    assert_eq!(
        before.sessions[&rid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps,
        1
    );
    assert_eq!(*router.state().borrow(), latest);
    assert_eq!(
        latest.sessions[&rid].destinations[&id()].addresses,
        addresses(1)
    );

    // Session-wide updates change destination state without destination events.
    modem
        .update_session_metrics(LinkMetrics {
            latency: Duration::from_micros(42),
            ..metrics
        })
        .await
        .unwrap();
    wait(&mut rs, |s| {
        s.sessions[&rid].destinations[&id()].metrics.latency == Duration::from_micros(42)
    })
    .await;
    accept(|| {
        modem.update_session_addresses(
            mid,
            AddressChanges {
                added: addresses(2),
                removed: Default::default(),
            },
        )
    })
    .await;
    wait(&mut rs, |s| s.sessions[&rid].peer_addresses == addresses(2)).await;
    router
        .update_session_addresses(
            rid,
            AddressChanges {
                added: addresses(3),
                removed: Default::default(),
            },
        )
        .await
        .unwrap();
    wait(&mut ms, |s| s.sessions[&mid].peer_addresses == addresses(3)).await;

    // Withdrawal removes router state but retains modem knowledge. Changes
    // made while withdrawn emit no public events on the modem.
    router.drop_destination(rid, id()).await.unwrap();
    wait(&mut rs, |s| s.sessions[&rid].destinations.is_empty()).await;
    wait(&mut ms, |s| {
        s.sessions[&mid].destinations[&id()].phase == DestinationPhase::Withdrawn
    })
    .await;
    modem
        .update_destination_addresses(
            id(),
            AddressChanges {
                added: addresses(4),
                removed: addresses(1),
            },
        )
        .await
        .unwrap();
    modem
        .update_destination(
            id(),
            LinkMetrics {
                current_data_rate_tx_bps: 777,
                ..metrics
            },
        )
        .await
        .unwrap();
    // Command acceptance is a barrier: retained local state is already updated.
    let withdrawn = ms.borrow().clone();
    assert_eq!(
        withdrawn.sessions[&mid].destinations[&id()].addresses,
        addresses(4)
    );
    assert_eq!(
        withdrawn.sessions[&mid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps,
        777
    );
    assert_eq!(
        withdrawn.sessions[&mid].destinations[&id()].phase,
        DestinationPhase::Withdrawn
    );
    router
        .send_command_to(rid, SessionCommand::AnnounceDestination { mac: id().0 })
        .await
        .unwrap();
    let restored = wait(&mut rs, |s| {
        s.sessions[&rid].destinations.contains_key(&id())
    })
    .await;
    assert_eq!(
        restored.sessions[&rid].destinations[&id()].addresses,
        addresses(4)
    );
    assert_eq!(
        restored.sessions[&rid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps,
        777
    );

    router.shutdown().await.unwrap();
    let ended = wait(&mut rs, |s| s.sessions.is_empty()).await;
    assert!(ended.generation > latest.generation);
    wait(&mut ms, |s| s.sessions.is_empty()).await;
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn ipv4_state_recovers_after_lag_and_preserves_withdrawn_knowledge() {
    recovery("127.0.0.1").await;
}

#[tokio::test]
async fn ipv6_state_recovers_after_lag_and_preserves_withdrawn_knowledge() {
    recovery("::1").await;
}

#[tokio::test]
async fn same_mac_on_two_modems_is_isolated_and_reconnect_gets_a_new_session() {
    let a = modem("127.0.0.1").await;
    let b = modem("127.0.0.1").await;
    let router = router().await;
    let mut state = router.state();
    router.connect_static(a.local_addr()).await.unwrap();
    router.connect_static(b.local_addr()).await.unwrap();
    let initial = wait(&mut state, |s| s.sessions.len() == 2).await;
    let aid = *initial
        .sessions
        .iter()
        .find(|(_, s)| s.peer.addr == a.local_addr())
        .unwrap()
        .0;
    let bid = *initial
        .sessions
        .iter()
        .find(|(_, s)| s.peer.addr == b.local_addr())
        .unwrap()
        .0;
    for (modem, rate) in [(&a, 100), (&b, 200)] {
        modem
            .add_destination(
                id(),
                LinkMetrics {
                    current_data_rate_tx_bps: rate,
                    max_data_rate_tx_bps: 1000,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    let both = wait(&mut state, |s| {
        s.sessions
            .values()
            .all(|s| s.destinations.contains_key(&id()))
    })
    .await;
    assert_eq!(
        both.sessions[&aid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps,
        100
    );
    assert_eq!(
        both.sessions[&bid].destinations[&id()]
            .metrics
            .current_data_rate_tx_bps,
        200
    );
    router
        .send_command_to(
            aid,
            SessionCommand::Shutdown {
                reason: StatusCode::SHUTTING_DOWN,
            },
        )
        .await
        .unwrap();
    wait(&mut state, |s| {
        s.sessions.len() == 1 && s.sessions.contains_key(&bid)
    })
    .await;
    router.connect_static(a.local_addr()).await.unwrap();
    let next = wait(&mut state, |s| s.sessions.len() == 2).await;
    assert!(!next.sessions.contains_key(&aid));
    assert_eq!(next.sessions[&bid], both.sessions[&bid]);
    let fresh = next.sessions.iter().find(|(id, _)| **id != bid).unwrap().1;
    assert!(fresh.destinations.is_empty());
    router.shutdown().await.unwrap();
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[tokio::test]
async fn unchanged_destinations_are_shared_between_generations() {
    let modem = modem("127.0.0.1").await;
    let router = router().await;
    router.connect_static(modem.local_addr()).await.unwrap();
    let mut rs = router.state();
    let mut ms = modem.state();
    wait(&mut rs, |s| s.sessions.len() == 1).await;
    wait(&mut ms, |s| s.sessions.len() == 1).await;
    let other: DestinationId = MacAddress::new_eui48([2, 0, 0, 0, 0, 2]).into();
    let metrics = |rate| LinkMetrics {
        current_data_rate_tx_bps: rate,
        max_data_rate_tx_bps: 1_000_000,
        ..Default::default()
    };
    for destination in [id(), other] {
        modem
            .add_destination_with_addresses(destination, metrics(1), addresses(1))
            .await
            .unwrap();
    }
    let up = |s: &DaemonSnapshot, d: DestinationId| {
        s.sessions
            .values()
            .next()
            .and_then(|session| session.destinations.get(&d))
            .is_some_and(|d| d.phase == DestinationPhase::Up)
    };
    let before = wait(&mut ms, |s| up(s, id()) && up(s, other)).await;
    let routed = wait(&mut rs, |s| up(s, id()) && up(s, other)).await;

    accept(|| modem.update_destination(id(), metrics(2))).await;
    for (state, previous) in [(&mut ms, before), (&mut rs, routed)] {
        let after = wait(state, |s| {
            s.sessions.values().next().is_some_and(|session| {
                session.destinations[&id()].metrics.current_data_rate_tx_bps == 2
            })
        })
        .await;
        assert!(after.generation > previous.generation);
        let (old, new) = (
            previous.sessions.values().next().unwrap(),
            after.sessions.values().next().unwrap(),
        );
        assert!(
            std::sync::Arc::ptr_eq(&old.destinations[&other], &new.destinations[&other]),
            "unchanged destination was copied"
        );
        assert!(!std::sync::Arc::ptr_eq(
            &old.destinations[&id()],
            &new.destinations[&id()]
        ));
    }
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}
