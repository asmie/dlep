//! Wire-level regressions using independent peers, not only our two daemons.
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};
use dlep_daemon::{
    DaemonEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon, PeerOffer, RouterConfig,
    RouterDaemon,
};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::{FsmAction, FsmEvent};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::broadcast::Receiver,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(2);
fn router_config() -> RouterConfig {
    let mut c = RouterConfig::default();
    c.shared.network.use_tls = false;
    c
}
fn modem_config() -> ModemConfig {
    let mut c = ModemConfig::default();
    c.shared.network.use_tls = false;
    c.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    c.shared.network.tcp_port = 0;
    c.shared.network.discovery_port = 0;
    c
}
async fn up(rx: &mut Receiver<DaemonEvent>) -> (dlep_ext::SessionId, SocketAddr) {
    timeout(WAIT, async {
        loop {
            if let DaemonEvent::SessionUp {
                session_id, peer, ..
            } = rx.recv().await.unwrap()
            {
                return (session_id, peer.addr);
            }
        }
    })
    .await
    .unwrap()
}
async fn down(rx: &mut Receiver<DaemonEvent>) -> StatusCode {
    timeout(WAIT, async {
        loop {
            if let DaemonEvent::SessionDown { reason, .. } = rx.recv().await.unwrap() {
                return reason;
            }
        }
    })
    .await
    .unwrap()
}
async fn read_message(peer: &mut TcpStream) -> Message {
    let mut header = [0u8; 4];
    timeout(WAIT, peer.read_exact(&mut header))
        .await
        .unwrap()
        .unwrap();
    let mut bytes = header.to_vec();
    bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
    timeout(WAIT, peer.read_exact(&mut bytes[4..]))
        .await
        .unwrap()
        .unwrap();
    Message::decode(bytes.into()).unwrap()
}
async fn raw_modem() -> (RouterDaemon, Receiver<DaemonEvent>, TcpStream) {
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
    let init = read_message(&mut peer).await;
    let mut fsm = ModemSessionFsm::new();
    fsm.step(FsmEvent::TcpAccepted);
    let response = fsm
        .step(FsmEvent::RecvMessage(init))
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap();
    peer.write_all(&response.encode().unwrap()).await.unwrap();
    up(&mut events).await;
    (router, events, peer)
}

#[tokio::test]
async fn malformed_frame_terminates_and_notifies_exactly_once() {
    let (router, mut events, mut peer) = raw_modem().await;
    peer.write_all(&[0, 3, 0, 4, 0, 16, 0, 0]).await.unwrap();
    let termination = read_message(&mut peer).await;
    assert_eq!(termination.message_type, MessageType::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|i| matches!(
        i,
        DataItem::Status {
            code: StatusCode::INVALID_DATA,
            ..
        }
    )));
    peer.write_all(
        &Message::new(MessageType::SESSION_TERMINATION_RESPONSE)
            .encode()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(down(&mut events).await, StatusCode::INVALID_DATA);
    router.shutdown().await.unwrap();
    assert!(!events.try_iter_down());
}
// A small helper keeps the assertion independent of other queued event kinds.
trait RemainingEvents {
    fn try_iter_down(&mut self) -> bool;
}
impl RemainingEvents for Receiver<DaemonEvent> {
    fn try_iter_down(&mut self) -> bool {
        while let Ok(e) = self.try_recv() {
            if matches!(e, DaemonEvent::SessionDown { .. }) {
                return true;
            }
        }
        false
    }
}

#[tokio::test]
async fn reset_connection_notifies_application() {
    let (router, mut events, peer) = raw_modem().await;
    // SO_LINGER=0 explicitly produces an abortive close.
    #[allow(deprecated)]
    peer.set_linger(Some(Duration::ZERO)).unwrap();
    drop(peer);
    assert_eq!(down(&mut events).await, StatusCode::TIMED_OUT);
    router.shutdown().await.unwrap();
    assert!(!events.try_iter_down());
}

#[tokio::test]
async fn invalid_tcp_ttl_resets_and_notifies_application() {
    let (router, mut events, mut peer) = raw_modem().await;
    peer.set_ttl(254).unwrap();
    peer.write_all(&Message::new(MessageType::HEARTBEAT).encode().unwrap())
        .await
        .unwrap();
    down(&mut events).await;
    let mut buf = [0; 1];
    let error = timeout(WAIT, peer.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
    router.shutdown().await.unwrap();
    assert!(!events.try_iter_down());
}

#[tokio::test]
async fn idle_tls_client_does_not_block_healthy_client() {
    use dlep_net::tls::test_helpers::*;
    let pki = self_signed_for_ip("127.0.0.1".parse().unwrap());
    let server = server_config_for(pki.cert_der, pki.key_der);
    let client = client_config_for(pki.roots);
    let mut config = modem_config();
    config.shared.network.use_tls = true;
    let modem = ModemDaemon::builder()
        .config(config)
        .with_rustls_server(server)
        .spawn()
        .await
        .unwrap();
    let socket = TcpSocket::new_v4().unwrap();
    dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
    let idle = socket.connect(modem.local_addr()).await.unwrap();
    let connector = dlep_net::Connector::tls(client);
    let healthy = timeout(WAIT, connector.connect(modem.local_addr()))
        .await
        .unwrap()
        .unwrap();
    drop(idle);
    drop(healthy);
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_ipv6_start_releases_listening_socket() {
    let reservation = TcpListener::bind("[::1]:0").await.unwrap();
    let addr = reservation.local_addr().unwrap();
    drop(reservation);
    let mut config = modem_config();
    config.shared.network.bind_addr = addr.ip();
    config.shared.network.tcp_port = addr.port();
    assert!(ModemDaemon::builder().config(config).spawn().await.is_err());
    assert!(TcpListener::bind(addr).await.is_ok());
}

#[tokio::test]
async fn offer_fallback_respects_transport_flag() {
    use dlep_fsm::discovery_common::OfferEndpoint;
    let modem = ModemDaemon::builder()
        .config(modem_config())
        .spawn()
        .await
        .unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable = unused.local_addr().unwrap();
    drop(unused);
    let router = RouterDaemon::builder()
        .config(router_config())
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    let offer = PeerOffer {
        peer_description: None,
        endpoints: vec![
            OfferEndpoint {
                addr: unavailable,
                use_tls: true,
            },
            OfferEndpoint {
                addr: unavailable,
                use_tls: false,
            },
            OfferEndpoint {
                addr: modem.local_addr(),
                use_tls: false,
            },
        ],
    };
    assert_eq!(
        router.connect_discovered(&offer).await.unwrap(),
        modem.local_addr()
    );
    up(&mut events).await;
    // Do not silently send plaintext to a TLS-only endpoint.
    let tls_only = PeerOffer {
        peer_description: None,
        endpoints: vec![OfferEndpoint {
            addr: modem.local_addr(),
            use_tls: true,
        }],
    };
    assert!(router.connect_discovered(&tls_only).await.is_err());
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn destination_and_metrics_events_identify_both_sessions() {
    let a = ModemDaemon::builder()
        .config(modem_config())
        .spawn()
        .await
        .unwrap();
    let b = ModemDaemon::builder()
        .config(modem_config())
        .spawn()
        .await
        .unwrap();
    let mut ae = a.subscribe();
    let mut be = b.subscribe();
    let router = RouterDaemon::builder()
        .config(router_config())
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    router.connect_static(a.local_addr()).await.unwrap();
    let (aid, _) = up(&mut events).await;
    up(&mut ae).await;
    // Capture initial metrics before consuming b's SessionUp.
    let initial = timeout(WAIT, events.recv()).await.unwrap().unwrap();
    assert!(
        matches!(initial, DaemonEvent::Metrics { session_id, peer, .. } if session_id == aid && peer.addr == a.local_addr())
    );
    router.connect_static(b.local_addr()).await.unwrap();
    let (bid, _) = up(&mut events).await;
    up(&mut be).await;
    assert_ne!(aid, bid);
    let id = DestinationId(MacAddress::new_eui48([2, 0, 0, 0, 0, 1]));
    a.add_destination(id, LinkMetrics::default()).await.unwrap();
    b.add_destination(id, LinkMetrics::default()).await.unwrap();
    let mut seen = std::collections::HashSet::new();
    timeout(WAIT, async {
        while seen.len() != 2 {
            if let DaemonEvent::Destination {
                session_id, peer, ..
            } = events.recv().await.unwrap()
            {
                assert!(
                    session_id == aid && peer.addr == a.local_addr()
                        || session_id == bid && peer.addr == b.local_addr()
                );
                seen.insert(session_id);
            }
        }
    })
    .await
    .unwrap();
    assert!(
        router
            .update_session_metrics(LinkMetrics::default())
            .await
            .is_err()
    );
    router.shutdown().await.unwrap();
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[derive(Clone, Copy)]
enum Failure {
    Read,
    Write,
    BlockedWrite,
}
struct BrokenTransport(Failure);
impl tokio::io::AsyncRead for BrokenTransport {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        _: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if matches!(self.0, Failure::Read) {
            std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "injected reset",
            )))
        } else {
            std::task::Poll::Pending
        }
    }
}
impl tokio::io::AsyncWrite for BrokenTransport {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.0 {
            Failure::Write => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected write error",
            ))),
            Failure::BlockedWrite => std::task::Poll::Pending,
            Failure::Read => std::task::Poll::Ready(Ok(data.len())),
        }
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}
impl dlep_net::Transport for BrokenTransport {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:854".parse().unwrap())
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:10000".parse().unwrap())
    }
    fn is_tls(&self) -> bool {
        false
    }
}

#[tokio::test(start_paused = true)]
async fn io_failures_and_blocked_writes_always_notify_once() {
    for failure in [Failure::Read, Failure::Write, Failure::BlockedWrite] {
        let (events, mut rx) = dlep_daemon::runtime::new_event_channel();
        let (_commands, commands) = tokio::sync::mpsc::channel(1);
        let peer = dlep_daemon::PeerInfo {
            addr: "127.0.0.1:854".parse().unwrap(),
            is_tls: false,
            peer_description: None,
        };
        let result = dlep_daemon::session::run_session(
            dlep_fsm::session_router::RouterSessionFsm::new(),
            Box::new(BrokenTransport(failure)),
            FsmEvent::TcpConnected,
            commands,
            events,
            peer,
            dlep_ext::ExtensionRegistry::new(),
            dlep_ext::Role::Router,
            dlep_daemon::session::new_session_id_counter(),
        )
        .await;
        assert!(result.is_err());
        assert!(matches!(
            rx.try_recv().unwrap(),
            DaemonEvent::SessionDown { .. }
        ));
        assert!(!rx.try_iter_down());
    }
}
