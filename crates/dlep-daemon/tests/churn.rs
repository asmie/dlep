//! Bounded churn regression, isolated in its own process for descriptor accounting.
use std::{collections::HashSet, net::SocketAddr, time::Duration};

use dlep_core::{MacAddress, StatusCode as S};
use dlep_daemon::{
    DaemonError, DaemonEvent, DestinationEvent, DestinationId, LinkCharacteristics, LinkMetrics,
    ModemConfig, ModemDaemon, RouterConfig, RouterDaemon, runtime::SessionCommand,
};
use dlep_ext::SessionId;
use tokio::{sync::broadcast, time::timeout};

const WAIT: Duration = Duration::from_secs(5);
const DESTINATIONS: u8 = 16;
type Events = broadcast::Receiver<DaemonEvent>;

fn destination(index: u8) -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, index]).into()
}

fn metrics(sequence: usize) -> LinkMetrics {
    LinkMetrics {
        max_data_rate_rx_bps: 1_000_000,
        max_data_rate_tx_bps: 1_000_000,
        current_data_rate_rx_bps: 10_000 + (sequence % 10_000) as u64,
        current_data_rate_tx_bps: 20_000 + (sequence % 10_000) as u64,
        latency: Duration::from_micros(100 + (sequence % 10_000) as u64),
        ..Default::default()
    }
}

async fn event(events: &mut Events) -> DaemonEvent {
    timeout(WAIT, events.recv()).await.unwrap().unwrap()
}

async fn session_up(events: &mut Events) -> (SessionId, SocketAddr) {
    match event(events).await {
        DaemonEvent::SessionUp {
            session_id,
            peer,
            negotiated_extensions,
        } => {
            assert!(!peer.is_tls);
            assert!(negotiated_extensions.is_empty());
            (session_id, peer.addr)
        }
        other => panic!("expected SessionUp, got {other:?}"),
    }
}

async fn destination_event(
    events: &mut Events,
    expected_session: SessionId,
    expected_peer: SocketAddr,
) -> DestinationEvent {
    match event(events).await {
        DaemonEvent::Destination {
            session_id,
            peer,
            event,
        } => {
            assert_eq!(session_id, expected_session);
            assert_eq!(peer.addr, expected_peer);
            event
        }
        other => panic!("expected destination event, got {other:?}"),
    }
}

async fn session_down(events: &mut Events, expected_session: SessionId, expected_peer: SocketAddr) {
    match event(events).await {
        DaemonEvent::SessionDown {
            session_id,
            peer,
            reason,
        } => {
            assert_eq!(session_id, expected_session);
            assert_eq!(peer.addr, expected_peer);
            assert_eq!(reason, S::SHUTTING_DOWN);
        }
        other => panic!("expected SessionDown, got {other:?}"),
    }
}

// The request follows all prior Up/Down responses on the same TCP stream.
// Its reply proves the modem processed those responses before MAC reuse or
// metric updates; command acceptance alone would not prove that.
async fn barrier(router: &RouterDaemon, events: &mut Events, session: SessionId, peer: SocketAddr) {
    router
        .request_link_characteristics(
            session,
            destination(0),
            LinkCharacteristics {
                latency: Some(Duration::from_micros(1)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    match destination_event(events, session, peer).await {
        DestinationEvent::LinkCharacteristicsResponse {
            id,
            status,
            metrics: actual,
            ..
        } => {
            assert_eq!(id, destination(0));
            assert_eq!(status, S::REQUEST_DENIED);
            assert_eq!(actual, metrics(0));
        }
        other => panic!("expected barrier response, got {other:?}"),
    }
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

async fn descriptors_return_to(expected: usize) {
    timeout(WAIT, async {
        while descriptor_count() != expected {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "descriptor count: expected {expected}, got {}",
            descriptor_count()
        )
    });
}

async fn churn(bind: &str, cycles: usize) {
    let process_descriptors = descriptor_count();
    let mut config = ModemConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = bind.parse().unwrap();
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
    config.shared.timers.termination_timeout_ms = Some(2_000);
    let initial_metrics = config.metrics.link_metrics();
    let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
    let mut config = RouterConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = bind.parse().unwrap();
    config.shared.network.discovery_port = 0;
    config.shared.timers.termination_timeout_ms = Some(2_000);
    config.limits.max_sessions = 1;
    let router = RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .unwrap();
    let mut router_events = router.subscribe();
    let mut modem_events = modem.subscribe();
    let states = router.connection_states();
    let peer = modem.local_addr();
    let daemon_descriptors = descriptor_count();
    let mut router_ids = HashSet::new();
    let mut modem_ids = HashSet::new();
    let mut previous = None;

    for cycle in 0..cycles {
        eprintln!("{bind}: churn cycle {}/{cycles}", cycle + 1);
        timeout(Duration::from_secs(30), async {
            timeout(WAIT, router.connect_static(peer))
                .await
                .unwrap()
                .unwrap();
            let (router_id, router_peer) = session_up(&mut router_events).await;
            let (modem_id, modem_peer) = session_up(&mut modem_events).await;
            assert_eq!(router_peer, peer);
            assert!(router_ids.insert(router_id), "router reused a session ID");
            assert!(modem_ids.insert(modem_id), "modem reused a session ID");
            match event(&mut router_events).await {
                DaemonEvent::Metrics {
                    session_id,
                    peer: source,
                    event,
                } => {
                    assert_eq!(session_id, router_id);
                    assert_eq!(source.addr, peer);
                    assert_eq!(event.session_wide, initial_metrics);
                }
                other => panic!("expected initial session metrics, got {other:?}"),
            }
            {
                let snapshot = states.borrow();
                assert_eq!(snapshot.len(), 1);
                assert_eq!(snapshot[&peer].active_sessions, 1);
                assert_eq!(snapshot[&peer].establishment_count, (cycle + 1) as u64);
            }
            assert_eq!(router.connection_capacity(), 0);
            if let Some((old_router, old_modem)) = previous {
                let command = SessionCommand::Shutdown {
                    reason: S::SHUTTING_DOWN,
                };
                assert!(matches!(
                    router.send_command_to(old_router, command.clone()).await,
                    Err(DaemonError::NoMatchingSession)
                ));
                assert!(matches!(
                    modem.send_command_to(old_modem, command).await,
                    Err(DaemonError::NoMatchingSession)
                ));
            }

            for wave in 0..2 {
                let first = if wave == 0 { 0 } else { 1 };
                let sequence = cycle * 4 + wave * 2 + 1;
                for index in first..=DESTINATIONS {
                    modem
                        .add_destination(
                            destination(index),
                            metrics(if index == 0 { 0 } else { sequence }),
                        )
                        .await
                        .unwrap();
                }
                let mut seen = HashSet::new();
                for _ in first..=DESTINATIONS {
                    match destination_event(&mut router_events, router_id, peer).await {
                        DestinationEvent::Up {
                            id,
                            metrics: actual,
                            v4_addrs,
                            v6_addrs,
                            v4_subnets,
                            v6_subnets,
                        } => {
                            assert!((first..=DESTINATIONS).any(|i| destination(i) == id));
                            assert!(seen.insert(id), "duplicate Up");
                            assert_eq!(
                                actual,
                                metrics(if id == destination(0) { 0 } else { sequence })
                            );
                            assert!(
                                v4_addrs.is_empty()
                                    && v6_addrs.is_empty()
                                    && v4_subnets.is_empty()
                                    && v6_subnets.is_empty()
                            );
                        }
                        other => panic!("expected Up, got {other:?}"),
                    }
                }
                barrier(&router, &mut router_events, router_id, peer).await;
                for index in 1..=DESTINATIONS {
                    modem
                        .update_destination(destination(index), metrics(sequence + 1))
                        .await
                        .unwrap();
                }
                seen.clear();
                for _ in 1..=DESTINATIONS {
                    match destination_event(&mut router_events, router_id, peer).await {
                        DestinationEvent::Update {
                            id,
                            metrics: actual,
                        } => {
                            assert!((1..=DESTINATIONS).any(|i| destination(i) == id));
                            assert!(seen.insert(id), "duplicate Update");
                            assert_eq!(actual, metrics(sequence + 1));
                        }
                        other => panic!("expected Update, got {other:?}"),
                    }
                }
                if wave == 0 {
                    for index in 1..=DESTINATIONS {
                        modem
                            .drop_destination(destination(index), S::SUCCESS)
                            .await
                            .unwrap();
                    }
                    seen.clear();
                    for _ in 1..=DESTINATIONS {
                        match destination_event(&mut router_events, router_id, peer).await {
                            DestinationEvent::Down { id, reason } => {
                                assert!((1..=DESTINATIONS).any(|i| destination(i) == id));
                                assert!(seen.insert(id), "duplicate Down");
                                assert_eq!(reason, S::SUCCESS);
                            }
                            other => panic!("expected Down, got {other:?}"),
                        }
                    }
                    barrier(&router, &mut router_events, router_id, peer).await;
                }
            }
            // Leave destinations live so session teardown must discard their state.
            let command = SessionCommand::Shutdown {
                reason: S::SHUTTING_DOWN,
            };
            if cycle % 2 == 0 {
                router.send_command_to(router_id, command).await.unwrap();
            } else {
                modem.send_command_to(modem_id, command).await.unwrap();
            }
            session_down(&mut router_events, router_id, peer).await;
            session_down(&mut modem_events, modem_id, modem_peer).await;
            timeout(WAIT, router.wait_for_connection_capacity())
                .await
                .unwrap();
            assert_eq!(router.connection_capacity(), 1);
            assert_eq!(states.borrow()[&peer].active_sessions, 0);
            descriptors_return_to(daemon_descriptors).await;
            assert!(matches!(
                router_events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                modem_events.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ));
            previous = Some((router_id, modem_id));
        })
        .await
        .unwrap_or_else(|_| panic!("{bind}: churn cycle {} stalled", cycle + 1));
    }
    timeout(WAIT, router.shutdown()).await.unwrap().unwrap();
    timeout(WAIT, modem.shutdown()).await.unwrap().unwrap();
    descriptors_return_to(process_descriptors).await;
}

// Keep a single test in this binary: concurrent tests would invalidate /proc
// descriptor baselines. Both families retain strict privileged TCP GTSM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_sessions_and_destination_reuse_release_resources() {
    let cycles = std::env::var("DLEP_CHURN_CYCLES").map_or(100, |s| s.parse::<usize>().unwrap());
    assert!(cycles > 0);
    churn("127.0.0.1", cycles).await;
    churn("::1", cycles).await;
}
