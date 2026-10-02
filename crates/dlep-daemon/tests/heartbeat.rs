//! Heartbeat send cadence and received-peer liveness are separate clocks.
//! RFC 8175 §12.20 requires periodic sends; Appendix B.7 resets the missed
//! heartbeat counter on receipt of any valid message, not the send timer.
use dlep_core::{ExtensionId, Message, MessageType as M, StatusCode as S};
use dlep_daemon::{
    DaemonEvent, PeerInfo, SessionCommand,
    runtime::{SessionRequest, new_event_channel},
    session::{SessionFsm, new_session_id_counter, run_session},
};
use dlep_ext::{DlepExtension, ExtHandled, ExtensionCtx, ExtensionRegistry, Role};
use dlep_fsm::{
    FsmAction, FsmEvent, SessionConfig, session_modem::ModemSessionFsm,
    session_router::RouterSessionFsm,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, WriteHalf},
    sync::{broadcast, mpsc},
    task::JoinHandle,
    time::{advance, timeout},
};

const EXT_ID: ExtensionId = ExtensionId(0xf000);
const EXT_MSG: M = M(0xf000);

struct KeepaliveExtension;
impl DlepExtension for KeepaliveExtension {
    fn advertised_ids(&self) -> &[ExtensionId] {
        &[EXT_ID]
    }
    fn on_unknown_message(
        &self,
        kind: M,
        _: &[dlep_core::DataItem],
        _: &mut dyn ExtensionCtx,
    ) -> ExtHandled {
        if kind == EXT_MSG {
            ExtHandled::Handled
        } else {
            ExtHandled::Passthrough
        }
    }
}

struct MemoryTransport(DuplexStream);
impl AsyncRead for MemoryTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for MemoryTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
impl dlep_net::Transport for MemoryTransport {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:854".parse().unwrap())
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("127.0.0.1:12345".parse().unwrap())
    }
    fn is_tls(&self) -> bool {
        false
    }
}

fn config(interval_ms: u32) -> SessionConfig {
    SessionConfig {
        heartbeat_interval_ms: interval_ms,
        advertised_extensions: vec![EXT_ID],
        ..Default::default()
    }
}
fn sent(actions: Vec<FsmAction>) -> Message {
    actions
        .into_iter()
        .find_map(|action| match action {
            FsmAction::SendMessage(message) => Some(message),
            _ => None,
        })
        .unwrap()
}
async fn settle() {
    // Keep a runnable test task while allowing the session, timer and reader
    // tasks to poll. Awaiting an idle stream would auto-advance virtual time.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
}
async fn tick(ms: u64) {
    advance(Duration::from_millis(ms)).await;
    settle().await;
}

struct Running {
    commands: mpsc::Sender<SessionRequest>,
    events: broadcast::Receiver<DaemonEvent>,
    task: JoinHandle<Result<(), dlep_daemon::DaemonError>>,
}
fn spawn(fsm: impl SessionFsm + Send + 'static, stream: DuplexStream, role: Role) -> Running {
    let (commands, rx) = mpsc::channel(8);
    let (events, received) = new_event_channel();
    let mut extensions = ExtensionRegistry::default();
    extensions.register(Arc::new(KeepaliveExtension));
    let task = tokio::spawn(run_session(
        fsm,
        Box::new(MemoryTransport(stream)),
        if role.is_router() {
            FsmEvent::TcpConnected
        } else {
            FsmEvent::TcpAccepted
        },
        rx,
        events,
        PeerInfo {
            addr: "127.0.0.1:854".parse().unwrap(),
            is_tls: false,
            peer_description: None,
        },
        extensions,
        role,
        new_session_id_counter(),
    ));
    Running {
        commands,
        events: received,
        task,
    }
}
impl Running {
    async fn up(&mut self) {
        assert!(matches!(
            self.events.recv().await.unwrap(),
            DaemonEvent::SessionUp { .. }
        ));
        settle().await;
    }
    fn alive(&mut self) {
        assert!(!self.task.is_finished());
        while let Ok(event) = self.events.try_recv() {
            assert!(
                !matches!(event, DaemonEvent::SessionDown { .. }),
                "premature session down: {event:?}"
            );
        }
    }
}

struct Peer {
    running: Running,
    writer: WriteHalf<DuplexStream>,
    wire: mpsc::UnboundedReceiver<Message>,
    reader: JoinHandle<()>,
}
impl Peer {
    async fn start(router: bool, local_ms: u32, peer_ms: u32) -> Self {
        let (local, remote) = tokio::io::duplex(8192);
        let running = if router {
            spawn(
                RouterSessionFsm::with_config(config(local_ms)),
                local,
                Role::Router,
            )
        } else {
            spawn(
                ModemSessionFsm::with_config(config(local_ms)),
                local,
                Role::Modem,
            )
        };
        let (mut reader, writer) = tokio::io::split(remote);
        let (tx, wire) = mpsc::unbounded_channel();
        let reader = tokio::spawn(async move {
            loop {
                let mut header = [0; 4];
                if reader.read_exact(&mut header).await.is_err() {
                    break;
                }
                let mut bytes = header.to_vec();
                bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
                reader.read_exact(&mut bytes[4..]).await.unwrap();
                if tx.send(Message::decode(bytes.into()).unwrap()).is_err() {
                    break;
                }
            }
        });
        let mut peer = Self {
            running,
            writer,
            wire,
            reader,
        };
        if router {
            let mut modem = ModemSessionFsm::with_config(config(peer_ms));
            modem.step(FsmEvent::TcpAccepted);
            let init = peer.wire.recv().await.unwrap();
            peer.send(sent(modem.step(FsmEvent::RecvMessage(init))))
                .await;
        } else {
            let mut router = RouterSessionFsm::with_config(config(peer_ms));
            peer.send(sent(router.step(FsmEvent::TcpConnected))).await;
            assert_eq!(
                peer.wire.recv().await.unwrap().message_type,
                M::SESSION_INITIALIZATION_RESPONSE
            );
        }
        peer.running.up().await;
        peer
    }
    async fn send(&mut self, message: Message) {
        self.writer
            .write_all(&message.encode().unwrap())
            .await
            .unwrap();
        settle().await;
    }
    fn take(&mut self) -> Vec<Message> {
        std::iter::from_fn(|| self.wire.try_recv().ok()).collect()
    }
    async fn finish(mut self) {
        self.send(Message::new(M::SESSION_TERMINATION_RESPONSE))
            .await;
        timeout(Duration::from_millis(1), self.running.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        self.reader.await.unwrap();
        let mut downs = 0;
        while let Ok(event) = self.running.events.try_recv() {
            if let DaemonEvent::SessionDown { reason, .. } = event {
                assert_eq!(reason, S::TIMED_OUT);
                downs += 1;
            }
        }
        assert_eq!(downs, 1);
    }
}

#[tokio::test(start_paused = true)]
async fn received_traffic_refreshes_peer_deadline_without_delaying_periodic_sends() {
    for router in [false, true] {
        for kind in [M::HEARTBEAT, M::SESSION_UPDATE, EXT_MSG] {
            let mut peer = Peer::start(router, 1000, 3000).await;
            tick(999).await;
            peer.send(Message::new(kind)).await;
            let replies = peer.take();
            if kind == M::SESSION_UPDATE {
                assert_eq!(replies.len(), 1);
                assert_eq!(replies[0].message_type, M::SESSION_UPDATE_RESPONSE);
            } else {
                assert!(replies.is_empty());
            }
            tick(1).await;
            let heartbeat = peer.take();
            assert_eq!(
                heartbeat.len(),
                1,
                "received {kind:?} delayed the local send timer"
            );
            assert_eq!(heartbeat[0].message_type, M::HEARTBEAT);
            // Reach the original receive deadline without timing out. The
            // current deadline is 999 + 2*3000 = 6999ms, irrespective of sends.
            for _ in 0..5 {
                tick(1000).await;
            }
            peer.running.alive();
            assert!(peer.take().iter().all(|m| m.message_type == M::HEARTBEAT));
            tick(998).await;
            peer.running.alive();
            assert!(peer.take().is_empty());
            tick(1).await;
            let termination = peer.take();
            assert_eq!(termination.len(), 1);
            assert_eq!(termination[0].message_type, M::SESSION_TERMINATION);
            assert!(termination[0].data_items.iter().any(|item| matches!(item,
                dlep_core::DataItem::Status { code, .. } if *code == S::TIMED_OUT)));
            // Canceled periodic timer must not produce sends during termination.
            tick(1000).await;
            assert!(peer.take().is_empty());
            peer.finish().await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn unequal_heartbeat_intervals_keep_both_roles_alive() {
    for (router_ms, modem_ms) in [(1000, 3000), (3000, 1000)] {
        let (r, m) = tokio::io::duplex(8192);
        let mut router = spawn(
            RouterSessionFsm::with_config(config(router_ms)),
            r,
            Role::Router,
        );
        let mut modem = spawn(
            ModemSessionFsm::with_config(config(modem_ms)),
            m,
            Role::Modem,
        );
        router.up().await;
        modem.up().await;
        // Three times the slower peer's silence deadline. Resetting the slower
        // send timer on every fast-peer heartbeat would suppress it forever.
        for _ in 0..18 {
            tick(1000).await;
            router.alive();
            modem.alive();
        }
        router
            .commands
            .send(
                SessionCommand::Shutdown {
                    reason: S::SHUTTING_DOWN,
                }
                .into(),
            )
            .await
            .unwrap();
        timeout(Duration::from_millis(1), router.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        timeout(Duration::from_millis(1), modem.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
