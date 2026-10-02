use dlep_core::{MacAddress, Message, MessageType as M, StatusCode as S};
use dlep_daemon::{
    CommandError as C, DaemonError, DaemonEvent, DestinationId, LinkMetrics, ModemConfig,
    ModemDaemon, SessionCommand,
};
use dlep_ext::SessionId;
use dlep_fsm::session_common::{build_destination_down_response, build_destination_up_response};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{FsmAction as A, FsmEvent as E};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::broadcast,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
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
async fn peer(
    m: &ModemDaemon,
    events: &mut broadcast::Receiver<DaemonEvent>,
) -> (TcpStream, SessionId) {
    let socket = TcpSocket::new_v4().unwrap();
    dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
    let mut peer = socket.connect(m.local_addr()).await.unwrap();
    let mut r = RouterSessionFsm::new();
    let init = r
        .step(E::TcpConnected)
        .into_iter()
        .find_map(|a| match a {
            A::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap();
    send(&mut peer, init).await;
    assert_eq!(
        read(&mut peer).await.message_type,
        M::SESSION_INITIALIZATION_RESPONSE
    );
    let sid = match event(events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await {
        DaemonEvent::SessionUp { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    (peer, sid)
}
fn rejected(error: DaemonError, sid: SessionId, reason: C) {
    let DaemonError::CommandRejected(report) = error else {
        panic!("unexpected error {error:?}");
    };
    assert!(report.accepted.is_empty());
    assert_eq!(report.unknown, 0);
    assert_eq!(report.undelivered, 0);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].0, sid);
    assert_eq!(report.rejected[0].1.reason, reason);
}
async fn ack_up(peer: &mut TcpStream) {
    send(peer, build_destination_up_response(id().0, S::SUCCESS)).await;
    // A response on the same stream proves the Up acknowledgement was handled.
    send(peer, Message::new(M::SESSION_UPDATE)).await;
    assert_eq!(read(peer).await.message_type, M::SESSION_UPDATE_RESPONSE);
}

#[tokio::test]
async fn modem_busy_commands_return_errors_then_retry_reaches_wire() {
    let m = modem().await;
    let mut events = m.subscribe();
    let (mut peer, sid) = peer(&m, &mut events).await;
    m.add_destination(id(), LinkMetrics::default())
        .await
        .unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_UP);
    rejected(
        m.drop_destination(id(), S::SUCCESS).await.unwrap_err(),
        sid,
        C::Busy,
    );
    let rejection = event(&mut events, |e| {
        matches!(e, DaemonEvent::CommandRejected { .. })
    })
    .await;
    assert!(
        matches!(rejection, DaemonEvent::CommandRejected { session_id, rejection, .. } if session_id == sid && rejection.reason == C::Busy && rejection.command.destination == Some(id().0))
    );
    ack_up(&mut peer).await;
    m.drop_destination(id(), S::SUCCESS).await.unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_DOWN);
    rejected(
        m.update_destination(id(), LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    rejected(
        m.update_destination_addresses(id(), Default::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    send(
        &mut peer,
        build_destination_down_response(id().0, S::SUCCESS),
    )
    .await;
    send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
    assert_eq!(
        read(&mut peer).await.message_type,
        M::SESSION_UPDATE_RESPONSE
    );
    rejected(
        m.update_destination(id(), LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::UnknownDestination,
    );
    // Session metrics and addresses share the same transaction slot.
    m.update_session_metrics(LinkMetrics::default())
        .await
        .unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::SESSION_UPDATE);
    rejected(
        m.update_session_addresses(sid, Default::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    rejected(
        m.update_session_metrics(LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    // A pending transaction must not stop graceful shutdown.
    let shutdown = tokio::spawn(m.shutdown());
    assert_eq!(read(&mut peer).await.message_type, M::SESSION_TERMINATION);
    send(&mut peer, Message::new(M::SESSION_TERMINATION_RESPONSE)).await;
    timeout(WAIT, shutdown).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn broadcast_partial_acceptance_reports_sessions_and_targeted_retry_is_isolated() {
    let m = modem().await;
    let mut events = m.subscribe();
    assert!(matches!(
        m.add_destination(id(), LinkMetrics::default()).await,
        Err(DaemonError::NoMatchingSession)
    ));
    let (mut first, one) = peer(&m, &mut events).await;
    let (mut second, two) = peer(&m, &mut events).await;
    m.send_command_to(
        one,
        SessionCommand::AddDestination {
            mac: id().0,
            metrics: LinkMetrics::default(),
            addrs: Default::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(read(&mut first).await.message_type, M::DESTINATION_UP);
    let error = m
        .add_destination(id(), LinkMetrics::default())
        .await
        .unwrap_err();
    let DaemonError::CommandRejected(report) = error else {
        panic!("{error:?}")
    };
    assert_eq!(report.accepted, [two]);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].0, one);
    assert_eq!(report.rejected[0].1.reason, C::Busy);
    assert_eq!(read(&mut second).await.message_type, M::DESTINATION_UP);
    ack_up(&mut first).await;
    ack_up(&mut second).await;
    m.send_command_to(
        one,
        SessionCommand::DropDestination {
            mac: id().0,
            reason: S::SUCCESS,
        },
    )
    .await
    .unwrap();
    assert_eq!(read(&mut first).await.message_type, M::DESTINATION_DOWN);
    assert!(
        timeout(Duration::from_millis(50), read(&mut second))
            .await
            .is_err()
    );
    assert!(matches!(
        m.update_session_addresses(SessionId(u64::MAX), Default::default())
            .await,
        Err(DaemonError::NoMatchingSession)
    ));
    drop(first);
    drop(second);
    m.shutdown().await.unwrap();
}
