use std::time::Duration;

use dlep_core::{DataItem, MacAddress, Message, MessageType as M, StatusCode as S};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkCharacteristics, LinkMetrics, ModemConfig,
    ModemDaemon, RouterConfig, RouterDaemon,
};
use dlep_fsm::session_common::{build_destination_up, build_link_characteristics_response};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::{DestinationAddrs, FsmAction, FsmEvent};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::broadcast,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(2);
fn destination() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}
fn requested() -> LinkCharacteristics {
    LinkCharacteristics {
        current_data_rate_tx_bps: Some(123_000),
        ..Default::default()
    }
}
fn router_config() -> RouterConfig {
    let mut c = RouterConfig::default();
    c.shared.network.use_tls = false;
    c.shared.timers.link_characteristics_timeout_ms = 200;
    c
}
async fn modem() -> ModemDaemon {
    let mut c = ModemConfig::default();
    c.shared.network.use_tls = false;
    c.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    c.shared.network.tcp_port = 0;
    c.shared.network.discovery_port = 0;
    ModemDaemon::builder().config(c).spawn().await.unwrap()
}
async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = rx.recv().await.unwrap();
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
async fn send(peer: &mut TcpStream, message: Message) {
    peer.write_all(&message.encode().unwrap()).await.unwrap();
}
async fn raw_modem() -> (
    RouterDaemon,
    broadcast::Receiver<DaemonEvent>,
    TcpStream,
    dlep_ext::SessionId,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    dlep_net::gtsm::configure_tcp(&listener, false, true).unwrap();
    let router = RouterDaemon::builder()
        .config(router_config())
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    router
        .connect_static(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let mut modem = ModemSessionFsm::new();
    modem.step(FsmEvent::TcpAccepted);
    let response = modem
        .step(FsmEvent::RecvMessage(read(&mut peer).await))
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap();
    send(&mut peer, response).await;
    let session_id = up(&mut events).await;
    send(
        &mut peer,
        build_destination_up(
            destination().0,
            &LinkMetrics::default(),
            &DestinationAddrs::default(),
        ),
    )
    .await;
    assert_eq!(
        read(&mut peer).await.message_type,
        M::DESTINATION_UP_RESPONSE
    );
    (router, events, peer, session_id)
}

#[tokio::test]
async fn denial_round_trip_targets_one_of_two_modems_sharing_a_mac() {
    let first = modem().await;
    let second = modem().await;
    let router = RouterDaemon::builder()
        .config(router_config())
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    router.connect_static(first.local_addr()).await.unwrap();
    let first_session = up(&mut events).await;
    router.connect_static(second.local_addr()).await.unwrap();
    let second_session = up(&mut events).await;
    for modem in [&first, &second] {
        modem
            .add_destination(
                destination(),
                LinkMetrics {
                    current_data_rate_tx_bps: 70_000,
                    ..Default::default()
                },
            )
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
    }
    assert!(
        router
            .request_link_characteristics(
                first_session,
                destination(),
                LinkCharacteristics::default()
            )
            .await
            .is_err()
    );
    // Completing one request must release its slot for another.
    for _ in 0..2 {
        router
            .request_link_characteristics(first_session, destination(), requested())
            .await
            .unwrap();
        let reply = event(&mut events, |e| {
            matches!(
                e,
                DaemonEvent::Destination {
                    event: DestinationEvent::LinkCharacteristicsResponse { .. },
                    ..
                }
            )
        })
        .await;
        match reply {
            DaemonEvent::Destination {
                session_id,
                peer,
                event:
                    DestinationEvent::LinkCharacteristicsResponse {
                        id,
                        status,
                        metrics,
                        ..
                    },
            } => {
                assert_eq!(session_id, first_session);
                assert_ne!(session_id, second_session);
                assert_eq!(peer.addr, first.local_addr());
                assert_eq!(id, destination());
                assert_eq!(status, S::REQUEST_DENIED);
                assert_eq!(metrics.current_data_rate_tx_bps, 70_000);
            }
            _ => unreachable!(),
        }
    }
    assert!(
        timeout(Duration::from_millis(250), events.recv())
            .await
            .is_err(),
        "second modem must not receive the request; cancelled timers must stay cancelled"
    );
    router.shutdown().await.unwrap();
    first.shutdown().await.unwrap();
    second.shutdown().await.unwrap();
}

#[tokio::test]
async fn successful_peer_response_reaches_application_with_updated_metrics() {
    let (router, mut events, mut peer, session_id) = raw_modem().await;
    router
        .request_link_characteristics(session_id, destination(), requested())
        .await
        .unwrap();
    let request = read(&mut peer).await;
    assert_eq!(request.message_type, M::LINK_CHARACTERISTICS_REQUEST);
    assert_eq!(request.data_items.len(), 2);
    assert!(
        request
            .data_items
            .iter()
            .any(|item| matches!(item, DataItem::CurrentDataRateTransmit(123_000)))
    );
    send(
        &mut peer,
        build_link_characteristics_response(
            destination().0,
            S::SUCCESS,
            &LinkMetrics {
                current_data_rate_tx_bps: 123_000,
                ..Default::default()
            },
        ),
    )
    .await;
    let reply = event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::LinkCharacteristicsResponse { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(reply, DaemonEvent::Destination { session_id: got, event: DestinationEvent::LinkCharacteristicsResponse { status: S::SUCCESS, metrics, .. }, .. } if got == session_id && metrics.current_data_rate_tx_bps == 123_000)
    );
    drop(peer);
    router.shutdown().await.unwrap();
}

#[tokio::test]
async fn missing_response_times_out_even_while_peer_sends_heartbeats() {
    let (router, mut events, mut peer, session_id) = raw_modem().await;
    router
        .request_link_characteristics(session_id, destination(), requested())
        .await
        .unwrap();
    assert_eq!(
        read(&mut peer).await.message_type,
        M::LINK_CHARACTERISTICS_REQUEST
    );
    send(&mut peer, Message::new(M::HEARTBEAT)).await;
    let termination = read(&mut peer).await;
    assert_eq!(termination.message_type, M::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|i| matches!(
        i,
        DataItem::Status {
            code: S::TIMED_OUT,
            ..
        }
    )));
    send(&mut peer, Message::new(M::SESSION_TERMINATION_RESPONSE)).await;
    let down = event(&mut events, |e| {
        matches!(e, DaemonEvent::SessionDown { .. })
    })
    .await;
    assert!(
        matches!(down, DaemonEvent::SessionDown { session_id: got, reason: S::TIMED_OUT, .. } if got == session_id)
    );
    router.shutdown().await.unwrap();
}
