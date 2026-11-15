use std::time::Duration;

use dlep_core::{DataItem, Message, MessageType as M, StatusCode as S};
use dlep_daemon::{
    AddressChanges, DaemonEvent, DestinationAddrs, LinkMetrics, ModemConfig, ModemDaemon,
    RouterConfig, RouterDaemon, SessionCommand,
};
use dlep_ext::SessionId;
use dlep_fsm::{
    FsmAction as A, FsmEvent as E, session_modem::ModemSessionFsm, session_router::RouterSessionFsm,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::broadcast,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

fn sent(actions: Vec<A>) -> Message {
    actions
        .into_iter()
        .find_map(|a| match a {
            A::SendMessage(message) => Some(message),
            _ => None,
        })
        .unwrap()
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

async fn event(events: &mut broadcast::Receiver<DaemonEvent>) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = events.recv().await.unwrap();
            assert!(
                !matches!(event, DaemonEvent::SessionDown { .. }),
                "{event:?}"
            );
            // Initialization on a router also reports initial metrics.
            if !matches!(event, DaemonEvent::Metrics { .. }) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

async fn up(events: &mut broadcast::Receiver<DaemonEvent>) -> SessionId {
    let DaemonEvent::SessionUp { session_id, .. } = event(events).await else {
        panic!("expected SessionUp");
    };
    session_id
}

async fn reply(
    peer: &mut TcpStream,
    events: &mut broadcast::Receiver<DaemonEvent>,
    sid: SessionId,
    addr: std::net::SocketAddr,
    status: S,
) {
    let text = format!("peer {addr}: dostęp ✓\n\"reply\" {}", status.0);
    send(
        peer,
        Message::new(M::SESSION_UPDATE_RESPONSE).with_item(DataItem::Status {
            code: status,
            text: text.clone(),
        }),
    )
    .await;
    let outcome = event(events).await;
    assert!(matches!(outcome, DaemonEvent::SessionUpdateResponse {
        session_id, peer, status: got, text: got_text
    } if session_id == sid && peer.addr == addr && got == status && got_text == text));
}

#[tokio::test]
async fn modem_reports_each_wire_reply_while_coalescing_updates_per_router() {
    for ip in ["127.0.0.1", "::1"] {
        let mut config = ModemConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = ip.parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
        let mut events = modem.subscribe();
        let mut peers = Vec::new();
        for n in 0..2 {
            let socket = if modem.local_addr().is_ipv6() {
                TcpSocket::new_v6()
            } else {
                TcpSocket::new_v4()
            }
            .unwrap();
            dlep_net::gtsm::configure_tcp(&socket, modem.local_addr().is_ipv6(), true).unwrap();
            let mut peer = socket.connect(modem.local_addr()).await.unwrap();
            send(
                &mut peer,
                sent(RouterSessionFsm::new().step(E::TcpConnected)),
            )
            .await;
            assert_eq!(
                read(&mut peer).await.message_type,
                M::SESSION_INITIALIZATION_RESPONSE
            );
            let sid = up(&mut events).await;
            modem
                .send_command_to(
                    sid,
                    SessionCommand::SessionUpdate {
                        metrics: LinkMetrics::default(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(read(&mut peer).await.message_type, M::SESSION_UPDATE);
            let mut latest = LinkMetrics::default();
            for latency in [100, 200, 300] {
                latest.latency = Duration::from_micros(latency + n);
                modem
                    .send_command_to(sid, SessionCommand::QueueSessionUpdate { metrics: latest })
                    .await
                    .unwrap();
            }
            peers.push((peer, sid, latest));
        }
        for (peer, sid, latest) in &mut peers {
            let addr = peer.local_addr().unwrap();
            reply(peer, &mut events, *sid, addr, S::REQUEST_DENIED).await;
            assert_eq!(modem.state().borrow().sessions[sid].metrics, *latest);
            let next = read(peer).await;
            assert_eq!(next.message_type, M::SESSION_UPDATE);
            assert_eq!(
                dlep_fsm::session_common::extract_link_metrics(&next),
                Some(*latest)
            );
            reply(peer, &mut events, *sid, addr, S(42)).await;
            // The final completion frees this session and preserves local values.
            modem
                .send_command_to(*sid, SessionCommand::SessionUpdate { metrics: *latest })
                .await
                .unwrap();
            assert_eq!(read(peer).await.message_type, M::SESSION_UPDATE);
            reply(peer, &mut events, *sid, addr, S::SUCCESS).await;
        }
        assert!(
            events.try_recv().is_err(),
            "coalesced calls do not manufacture outcomes"
        );
        for (_, sid, latest) in &peers {
            assert_eq!(modem.state().borrow().sessions[sid].metrics, *latest);
        }
        drop(peers);
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn router_session_address_outcomes_preserve_peer_attribution_and_allow_retry() {
    let mut config = RouterConfig::default();
    config.shared.network.use_tls = false;
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
        let (mut peer, _) = listener.accept().await.unwrap();
        let mut modem = ModemSessionFsm::new();
        modem.step(E::TcpAccepted);
        let init = read(&mut peer).await;
        send(&mut peer, sent(modem.step(E::RecvMessage(init)))).await;
        peers.push((peer, up(&mut events).await, addr));
    }
    for (peer, sid, addr) in &mut peers {
        for (n, status) in [S::REQUEST_DENIED, S(42), S::SUCCESS]
            .into_iter()
            .enumerate()
        {
            let changes = AddressChanges {
                added: DestinationAddrs {
                    v4: vec![format!("192.0.2.{}", n + 1).parse().unwrap()],
                    ..Default::default()
                },
                removed: Default::default(),
            };
            router
                .update_session_addresses(*sid, changes.clone())
                .await
                .unwrap();
            let update = read(peer).await;
            assert_eq!(update.message_type, M::SESSION_UPDATE);
            assert_eq!(AddressChanges::from_message(&update), changes);
            reply(peer, &mut events, *sid, *addr, status).await;
            // Desired addresses remain local after refusal. Repeating them is
            // a no-op; the next real update must be the next message on the wire.
            router
                .update_session_addresses(*sid, changes)
                .await
                .unwrap();
        }
    }
    assert!(events.try_recv().is_err());
    assert_eq!(router.state().borrow().sessions.len(), 2);
    drop(peers);
    router.shutdown().await.unwrap();
}
