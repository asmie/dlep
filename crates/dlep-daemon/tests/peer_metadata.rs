//! Peer Type metadata is published only from an accepted initialization.
use dlep_core::{DataItem, Message, MessageType, StatusCode, data_item::PeerFlags};
use dlep_daemon::{
    DaemonEvent, PeerInfo,
    runtime::new_event_channel,
    session::{new_session_id_counter, run_session},
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
    sync::{broadcast, mpsc},
    time::timeout,
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

/// Replace the Peer Type of an initialization message.
fn with_peer_type(mut message: Message, description: &str, smi: bool) -> Message {
    for item in &mut message.data_items {
        if let DataItem::PeerType {
            description: d,
            flags,
        } = item
        {
            *d = description.into();
            *flags = PeerFlags { smi };
        }
    }
    message
}

/// A router session task and its in-memory peer stream.
struct Harness {
    peer: DuplexStream,
    events: broadcast::Receiver<DaemonEvent>,
    task: tokio::task::JoinHandle<Result<(), dlep_daemon::DaemonError>>,
    _commands: mpsc::Sender<dlep_daemon::runtime::SessionRequest>,
}

fn start_router() -> Harness {
    let (transport, peer) = tokio::io::duplex(4096);
    let (commands, rx) = mpsc::channel(8);
    let (events, received) = new_event_channel();
    let task = tokio::spawn(run_session(
        RouterSessionFsm::with_config(SessionConfig {
            termination_timeout: Some(Duration::from_millis(50)),
            ..Default::default()
        }),
        Box::new(MemoryTransport(transport)),
        FsmEvent::TcpConnected,
        rx,
        events,
        PeerInfo {
            secured_medium: None,
            addr: "127.0.0.1:854".parse().unwrap(),
            is_tls: false,
            peer_description: None,
        },
        ExtensionRegistry::new(),
        Role::Router,
        new_session_id_counter(),
    ));
    Harness {
        peer,
        events: received,
        task,
        _commands: commands,
    }
}

async fn session_down(events: &mut broadcast::Receiver<DaemonEvent>) -> PeerInfo {
    loop {
        match timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("SessionDown")
            .unwrap()
        {
            DaemonEvent::SessionDown { peer, .. } => return peer,
            _ => continue,
        }
    }
}

#[tokio::test]
async fn stray_initialization_response_does_not_replace_accepted_peer_type() {
    let Harness {
        mut peer,
        mut events,
        task,
        _commands,
    } = start_router();
    let mut modem = ModemSessionFsm::with_config(SessionConfig {
        secured_medium: true,
        peer_description: "accepted-modem".into(),
        ..Default::default()
    });
    modem.step(FsmEvent::TcpAccepted);
    let response = sent(modem.step(FsmEvent::RecvMessage(read(&mut peer).await)));
    peer.write_all(&response.encode().unwrap()).await.unwrap();
    let DaemonEvent::SessionUp { peer: up, .. } = events.recv().await.unwrap() else {
        panic!("expected SessionUp");
    };
    assert_eq!(up.peer_description.as_deref(), Some("accepted-modem"));
    assert_eq!(up.secured_medium, Some(true));

    // A second Session Initialization Response is a protocol error. Its Peer
    // Type was never accepted and must not appear in the teardown event.
    let stray = with_peer_type(response, "stray-modem", false);
    peer.write_all(&stray.encode().unwrap()).await.unwrap();
    assert_eq!(
        read(&mut peer).await.message_type,
        MessageType::SESSION_TERMINATION
    );
    peer.write_all(
        &Message::new(MessageType::SESSION_TERMINATION_RESPONSE)
            .encode()
            .unwrap(),
    )
    .await
    .unwrap();
    let down = session_down(&mut events).await;
    assert_eq!(down.peer_description.as_deref(), Some("accepted-modem"));
    assert_eq!(down.secured_medium, Some(true));
    let _ = timeout(Duration::from_secs(5), task).await.unwrap();
}

#[tokio::test]
async fn rejected_initialization_response_publishes_no_peer_type() {
    let Harness {
        mut peer,
        mut events,
        task,
        _commands,
    } = start_router();
    let mut modem = ModemSessionFsm::with_config(SessionConfig {
        secured_medium: true,
        peer_description: "rejected-modem".into(),
        ..Default::default()
    });
    modem.step(FsmEvent::TcpAccepted);
    let mut response = sent(modem.step(FsmEvent::RecvMessage(read(&mut peer).await)));
    // A non-success status rejects the session during initialization.
    response
        .data_items
        .retain(|item| !matches!(item, DataItem::Status { .. }));
    response.data_items.insert(
        0,
        DataItem::Status {
            code: StatusCode::UNEXPECTED_MESSAGE,
            text: String::new(),
        },
    );
    peer.write_all(&response.encode().unwrap()).await.unwrap();
    let down = session_down(&mut events).await;
    assert_eq!(down.peer_description, None);
    assert_eq!(down.secured_medium, None);
    let _ = timeout(Duration::from_secs(5), task).await.unwrap();
}
