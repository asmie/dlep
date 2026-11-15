use std::time::Duration;

use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon,
    RouterConfig, RouterDaemon,
};
use tokio::sync::broadcast;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);
fn id() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}
async fn modem() -> ModemDaemon {
    let mut config = ModemConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
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
async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = rx.recv().await.unwrap();
            assert!(
                !matches!(event, DaemonEvent::SessionDown { .. }),
                "session unexpectedly ended: {event:?}"
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
async fn destination_up(rx: &mut broadcast::Receiver<DaemonEvent>) -> LinkMetrics {
    match event(rx, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Up { .. },
                ..
            }
        )
    })
    .await
    {
        DaemonEvent::Destination {
            event: DestinationEvent::Up { metrics, .. },
            ..
        } => metrics,
        _ => unreachable!(),
    }
}
async fn down(rx: &mut broadcast::Receiver<DaemonEvent>) -> dlep_ext::SessionId {
    match event(rx, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Down { .. },
                ..
            }
        )
    })
    .await
    {
        DaemonEvent::Destination {
            session_id,
            event: DestinationEvent::Down { id: got, reason },
            ..
        } => {
            assert_eq!(got, id());
            assert_eq!(reason, StatusCode::SUCCESS);
            session_id
        }
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn router_withdrawal_only_affects_the_selected_modem_session() {
    let first = modem().await;
    let second = modem().await;
    let router = router().await;
    let mut router_events = router.subscribe();
    let mut first_events = first.subscribe();
    router.connect_static(first.local_addr()).await.unwrap();
    let first_session = up(&mut router_events).await;
    let first_modem_session = up(&mut first_events).await;
    router.connect_static(second.local_addr()).await.unwrap();
    let second_session = up(&mut router_events).await;
    for modem in [&first, &second] {
        modem
            .add_destination(id(), LinkMetrics::default())
            .await
            .unwrap();
        destination_up(&mut router_events).await;
    }
    router.drop_destination(first_session, id()).await.unwrap();
    assert_eq!(down(&mut router_events).await, first_session);
    assert_eq!(down(&mut first_events).await, first_modem_session);

    let changed = LinkMetrics {
        latency: Duration::from_millis(42),
        ..Default::default()
    };
    first.update_destination(id(), changed).await.unwrap();
    second.update_destination(id(), changed).await.unwrap();
    let update = event(&mut router_events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Update { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(update, DaemonEvent::Destination { session_id, peer, event: DestinationEvent::Update { metrics, .. } } if session_id == second_session && peer.addr == second.local_addr() && metrics.latency == changed.latency)
    );
    assert!(
        timeout(Duration::from_millis(100), router_events.recv())
            .await
            .is_err(),
        "withdrawn destination must not produce traffic"
    );
    router.shutdown().await.unwrap();
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
}

#[tokio::test]
async fn router_can_reannounce_after_withdrawing_and_receive_latest_metrics() {
    let modem = modem().await;
    let router = router().await;
    let mut events = router.subscribe();
    router.connect_static(modem.local_addr()).await.unwrap();
    let session_id = up(&mut events).await;
    modem
        .add_destination(id(), LinkMetrics::default())
        .await
        .unwrap();
    destination_up(&mut events).await;
    router.drop_destination(session_id, id()).await.unwrap();
    assert_eq!(down(&mut events).await, session_id);
    let changed = LinkMetrics {
        latency: Duration::from_millis(77),
        ..Default::default()
    };
    // A withdrawn link is still tracked by the modem's local backend.
    modem.update_destination(id(), changed).await.unwrap();
    // The command and incoming Announce use different scheduler inputs;
    // confirm current metrics with an update after reactivation as well.
    router.announce_destination(id()).await.unwrap();
    destination_up(&mut events).await;
    modem.update_destination(id(), changed).await.unwrap();
    let update = event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Update { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(update, DaemonEvent::Destination { session_id: got, event: DestinationEvent::Update { metrics, .. }, .. } if got == session_id && metrics.latency == changed.latency)
    );
    // Withdrawal also works when this incarnation came from Announce.
    router.drop_destination(session_id, id()).await.unwrap();
    assert_eq!(down(&mut events).await, session_id);
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn down_responses_follow_removal_and_preserve_peer_status_text() {
    use dlep_core::{DataItem, MacAddressFormat, Message, MessageType as M, StatusCode as S};
    use dlep_fsm::{FsmAction as A, FsmEvent as E, SessionConfig, session_modem::ModemSessionFsm};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    async fn read(peer: &mut TcpStream) -> Message {
        timeout(WAIT, async {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let mut bytes = header.to_vec();
            bytes.resize(
                4 + usize::from(u16::from_be_bytes([header[2], header[3]])),
                0,
            );
            peer.read_exact(&mut bytes[4..]).await.unwrap();
            Message::decode(bytes.into()).unwrap()
        })
        .await
        .unwrap()
    }

    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        let mac = match format {
            MacAddressFormat::Eui48 => id().0,
            MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        };
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.mac_address_format = format;
        let router = RouterDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap();
        let mut events = router.subscribe();
        let mut peers = Vec::new();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).await.unwrap();
            let addr = listener.local_addr().unwrap();
            dlep_net::gtsm::configure_tcp(&listener, addr.is_ipv6(), true).unwrap();
            router.connect_static(addr).await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut modem = ModemSessionFsm::with_config(SessionConfig {
                mac_address_format: format,
                ..Default::default()
            });
            modem.step(E::TcpAccepted);
            let init = read(&mut stream).await;
            for action in modem.step(E::RecvMessage(init)) {
                if let A::SendMessage(message) = action {
                    stream.write_all(&message.encode().unwrap()).await.unwrap();
                }
            }
            let sid = up(&mut events).await;
            let message = dlep_fsm::session_common::build_destination_up(
                mac,
                &LinkMetrics::default(),
                &Default::default(),
            );
            stream.write_all(&message.encode().unwrap()).await.unwrap();
            destination_up(&mut events).await;
            assert_eq!(
                read(&mut stream).await.message_type,
                M::DESTINATION_UP_RESPONSE
            );
            peers.push((stream, sid, addr));
        }
        for (stream, sid, addr) in &mut peers {
            for status in [S::SUCCESS, S::REQUEST_DENIED, S(42)] {
                router.drop_destination(*sid, mac.into()).await.unwrap();
                assert_eq!(read(stream).await.message_type, M::DESTINATION_DOWN);
                let text = format!("modem {addr}: dostęp ✓\n\"removed\"");
                let response = Message::new(M::DESTINATION_DOWN_RESPONSE)
                    .with_item(DataItem::MacAddress(mac))
                    .with_item(DataItem::Status {
                        code: status,
                        text: text.clone(),
                    });
                stream.write_all(&response.encode().unwrap()).await.unwrap();
                let removed = event(&mut events, |e| {
                    matches!(e, DaemonEvent::Destination { .. })
                })
                .await;
                assert!(matches!(removed, DaemonEvent::Destination {
                    session_id, peer, event: DestinationEvent::Down { id, reason }
                } if session_id == *sid && peer.addr == *addr && id.0 == mac && reason == status));
                let completed = event(&mut events, |e| {
                    matches!(e, DaemonEvent::Destination { .. })
                })
                .await;
                assert!(matches!(completed, DaemonEvent::Destination {
                    session_id, peer, event: DestinationEvent::DownResponse { id, status: code, text: explanation }
                } if session_id == *sid && peer.addr == *addr && id.0 == mac && code == status && explanation == text));
                let state = router.state().borrow().clone();
                assert!(!state.sessions[sid].destinations.contains_key(&mac.into()));
                assert!(
                    state
                        .sessions
                        .iter()
                        .filter(|(other, _)| **other != *sid)
                        .all(|(_, s)| s.destinations.contains_key(&mac.into()))
                );
                let message = dlep_fsm::session_common::build_destination_up(
                    mac,
                    &LinkMetrics::default(),
                    &Default::default(),
                );
                stream.write_all(&message.encode().unwrap()).await.unwrap();
                destination_up(&mut events).await;
                assert_eq!(read(stream).await.message_type, M::DESTINATION_UP_RESPONSE);
            }
        }
        drop(peers);
        router.shutdown().await.unwrap();
    }
}
