//! Virtual-time checks of termination deadlines through the session runtime.
use dlep_core::{Message, MessageType, StatusCode};
use dlep_daemon::{
    DaemonEvent, PeerInfo, SessionCommand,
    runtime::new_event_channel,
    session::{SessionFsm, new_session_id_counter, run_session},
};
use dlep_ext::{ExtensionRegistry, Role};
use dlep_fsm::{
    FsmAction, FsmEvent, SessionConfig, session_modem::ModemSessionFsm,
    session_router::RouterSessionFsm,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::mpsc,
    time::{advance, timeout},
};

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
async fn read(peer: &mut DuplexStream) -> Message {
    let mut header = [0; 4];
    peer.read_exact(&mut header).await.unwrap();
    let mut bytes = header.to_vec();
    bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
    peer.read_exact(&mut bytes[4..]).await.unwrap();
    Message::decode(bytes.into()).unwrap()
}
fn sent(actions: Vec<FsmAction>) -> Message {
    actions
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap()
}

async fn exercise(
    fsm: impl SessionFsm + Send + 'static,
    role: Role,
    deadline: Duration,
    acknowledge: bool,
) {
    let (transport, mut peer) = tokio::io::duplex(4096);
    let (commands, rx) = mpsc::channel(8);
    let (events, mut received) = new_event_channel();
    let task = tokio::spawn(run_session(
        fsm,
        Box::new(MemoryTransport(transport)),
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
        ExtensionRegistry::default(),
        role,
        new_session_id_counter(),
    ));
    if role.is_router() {
        let mut other = ModemSessionFsm::new();
        other.step(FsmEvent::TcpAccepted);
        let response = sent(other.step(FsmEvent::RecvMessage(read(&mut peer).await)));
        peer.write_all(&response.encode().unwrap()).await.unwrap();
    } else {
        let mut other = RouterSessionFsm::new();
        let init = sent(other.step(FsmEvent::TcpConnected));
        peer.write_all(&init.encode().unwrap()).await.unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_INITIALIZATION_RESPONSE
        );
    }
    assert!(matches!(
        received.recv().await.unwrap(),
        DaemonEvent::SessionUp { .. }
    ));
    commands
        .send(
            SessionCommand::Shutdown {
                reason: StatusCode::SHUTTING_DOWN,
            }
            .into(),
        )
        .await
        .unwrap();
    assert_eq!(
        read(&mut peer).await.message_type,
        MessageType::SESSION_TERMINATION
    );
    tokio::task::yield_now().await;
    advance(deadline - Duration::from_millis(1)).await;
    tokio::task::yield_now().await;
    assert!(!task.is_finished(), "closed before the response deadline");
    while let Ok(event) = received.try_recv() {
        assert!(
            !matches!(event, DaemonEvent::SessionDown { .. }),
            "premature SessionDown"
        );
    }
    if acknowledge {
        peer.write_all(
            &Message::new(MessageType::SESSION_TERMINATION_RESPONSE)
                .encode()
                .unwrap(),
        )
        .await
        .unwrap();
    } else {
        advance(Duration::from_millis(1)).await;
    }
    timeout(Duration::from_millis(1), task)
        .await
        .expect("session ignored response or deadline")
        .unwrap()
        .unwrap();
    let expected_reason = if acknowledge {
        StatusCode::SHUTTING_DOWN
    } else {
        StatusCode::TIMED_OUT
    };
    assert!(
        matches!(received.recv().await.unwrap(), DaemonEvent::SessionDown { reason, .. } if reason == expected_reason)
    );
    assert!(received.try_recv().is_err(), "duplicate SessionDown");
}

async fn cases(router: bool) {
    for (heartbeat, explicit, deadline) in [
        (60_000, None, Duration::from_secs(240)),
        (1_500, None, Duration::from_secs(6)),
        (
            60_000,
            Some(Duration::from_millis(500)),
            Duration::from_millis(500),
        ),
    ] {
        for acknowledge in [true, false] {
            let cfg = SessionConfig {
                heartbeat_interval_ms: heartbeat,
                termination_timeout: explicit,
                ..Default::default()
            };
            if router {
                exercise(
                    RouterSessionFsm::with_config(cfg),
                    Role::Router,
                    deadline,
                    acknowledge,
                )
                .await;
            } else {
                exercise(
                    ModemSessionFsm::with_config(cfg),
                    Role::Modem,
                    deadline,
                    acknowledge,
                )
                .await;
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn router_waits_for_late_response_or_full_termination_deadline() {
    cases(true).await;
}

#[tokio::test(start_paused = true)]
async fn modem_waits_for_late_response_or_full_termination_deadline() {
    cases(false).await;
}
