//! Shared subprocess regressions: signals must trigger protocol shutdown, not
//! merely a successful-looking exit after a dropped socket.
use std::{
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

use dlep_core::{DataItem, Message, MessageType, StatusCode};
use dlep_fsm::{FsmAction, FsmEvent, session_modem::ModemSessionFsm};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(5);

// Each binary constructs its own role; the shared helper exercises both.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum Role {
    Router,
    Modem,
}

struct Process(Child);
impl Process {
    fn spawn(binary: &str, config: &Path) -> Self {
        Self(
            Command::new(binary)
                .arg("--config")
                .arg(config)
                .env("TOKIO_WORKER_THREADS", "2")
                .env("DLEP_LOG", "warn")
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        )
    }
    fn signal(&mut self, signal: Signal) {
        assert!(
            self.0.try_wait().unwrap().is_none(),
            "daemon exited before signal"
        );
        kill(Pid::from_raw(self.0.id() as i32), signal).unwrap();
    }
    async fn exited_cleanly(&mut self, limit: Duration) {
        let status = timeout(limit, async {
            loop {
                if let Some(status) = self.0.try_wait().unwrap() {
                    break status;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("daemon did not finish shutdown in time");
        assert!(
            status.success(),
            "daemon exited without graceful shutdown: {status}"
        );
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

async fn read_message(peer: &mut TcpStream) -> Message {
    timeout(WAIT, async {
        let mut header = [0; 4];
        peer.read_exact(&mut header).await.unwrap();
        let mut bytes = header.to_vec();
        bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
        peer.read_exact(&mut bytes[4..]).await.unwrap();
        Message::decode(bytes.into()).unwrap()
    })
    .await
    .expect("expected DLEP message")
}
async fn send(peer: &mut TcpStream, message: Message) {
    timeout(WAIT, peer.write_all(&message.encode().unwrap()))
        .await
        .unwrap()
        .unwrap();
}
async fn connect(addr: SocketAddr, child: &mut Process) -> TcpStream {
    timeout(WAIT, async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "modem failed to start"
            );
            let socket = TcpSocket::new_v4().unwrap();
            dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
            match socket.connect(addr).await {
                Ok(stream) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    sleep(Duration::from_millis(10)).await
                }
                Err(e) => panic!("connecting to modem: {e}"),
            }
        }
    })
    .await
    .unwrap()
}
fn config(role: Role, addr: SocketAddr, tls: bool) -> String {
    let router = if matches!(role, Role::Router) {
        format!("mode = 'static'\nstatic_peers = ['{addr}']\n")
    } else {
        String::new()
    };
    format!(
        "{router}[network]\nbind_addr = '127.0.0.1'\ntcp_port = {}\ndiscovery_port = 0\nuse_tls = {tls}\n[timers]\ntermination_timeout_ms = 500\n",
        addr.port()
    )
}

pub async fn established(binary: &str, role: Role, signal: Signal, acknowledge: bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.set_ttl(255).unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config(role, addr, false)).unwrap();
    let listener = if matches!(role, Role::Router) {
        Some(listener)
    } else {
        drop(listener);
        None
    };
    let mut child = Process::spawn(binary, &path);
    let mut peer = match listener {
        Some(listener) => timeout(WAIT, listener.accept()).await.unwrap().unwrap().0,
        None => connect(addr, &mut child).await,
    };
    match role {
        Role::Router => {
            let init = read_message(&mut peer).await;
            assert_eq!(init.message_type, MessageType::SESSION_INITIALIZATION);
            let mut fsm = ModemSessionFsm::new();
            fsm.step(FsmEvent::TcpAccepted);
            let response = fsm
                .step(FsmEvent::RecvMessage(init))
                .into_iter()
                .find_map(|a| {
                    if let FsmAction::SendMessage(m) = a {
                        Some(m)
                    } else {
                        None
                    }
                })
                .unwrap();
            send(&mut peer, response).await;
            // This reply proves the router consumed initialization before we
            // signal it, avoiding a timing-dependent handshake/shutdown race.
            send(
                &mut peer,
                dlep_fsm::session_common::build_session_update(&Default::default()),
            )
            .await;
            assert_eq!(
                read_message(&mut peer).await.message_type,
                MessageType::SESSION_UPDATE_RESPONSE
            );
        }
        Role::Modem => {
            send(
                &mut peer,
                Message::new(MessageType::SESSION_INITIALIZATION)
                    .with_item(DataItem::HeartbeatInterval(Duration::from_secs(60)))
                    .with_item(DataItem::PeerType {
                        flags: Default::default(),
                        description: "test-router".into(),
                    }),
            )
            .await;
            let response = read_message(&mut peer).await;
            assert_eq!(
                response.message_type,
                MessageType::SESSION_INITIALIZATION_RESPONSE
            );
            assert!(response.data_items.iter().any(|i| matches!(
                i,
                DataItem::Status {
                    code: StatusCode::SUCCESS,
                    ..
                }
            )));
        }
    }
    let stop_started = tokio::time::Instant::now();
    child.signal(signal);
    let termination = read_message(&mut peer).await;
    assert_eq!(termination.message_type, MessageType::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|i| matches!(
        i,
        DataItem::Status {
            code: StatusCode::SHUTTING_DOWN,
            ..
        }
    )));
    assert!(
        child.0.try_wait().unwrap().is_none(),
        "must wait for termination acknowledgement"
    );
    if acknowledge {
        // A second stop request must not bypass the in-flight exchange.
        child.signal(signal);
        sleep(Duration::from_millis(50)).await;
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "must keep waiting for the peer response"
        );
        send(
            &mut peer,
            Message::new(MessageType::SESSION_TERMINATION_RESPONSE),
        )
        .await;
    }
    child.exited_cleanly(WAIT).await;
    if !acknowledge {
        assert!(
            stop_started.elapsed() >= Duration::from_millis(450),
            "must honor the termination timeout"
        );
    }
    let mut byte = [0];
    assert_eq!(
        timeout(WAIT, peer.read(&mut byte)).await.unwrap().unwrap(),
        0
    );
}

pub async fn stalled_tls(binary: &str, role: Role) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.set_ttl(255).unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pki = dlep_net::tls::test_helpers::self_signed_for_ip(addr.ip());
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, pki.cert_pem).unwrap();
    std::fs::write(&key, pki.key_pem).unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            "{}\n[tls]\nca_bundle = '{}'\ncert = '{}'\nkey = '{}'\n",
            config(role, addr, true),
            cert.display(),
            cert.display(),
            key.display()
        ),
    )
    .unwrap();
    let listener = if matches!(role, Role::Router) {
        Some(listener)
    } else {
        drop(listener);
        None
    };
    let mut child = Process::spawn(binary, &path);
    let mut peer = match listener {
        Some(listener) => {
            let mut peer = timeout(WAIT, listener.accept()).await.unwrap().unwrap().0;
            // Wait until the router is inside the handshake, then never reply.
            assert!(
                timeout(WAIT, peer.read(&mut [0; 1024]))
                    .await
                    .unwrap()
                    .unwrap()
                    > 0
            );
            peer
        }
        None => connect(addr, &mut child).await,
    };
    child.signal(Signal::SIGTERM);
    // Shorter than the transport's five-second handshake timeout.
    child.exited_cleanly(Duration::from_secs(2)).await;
    let mut buf = [0; 4096];
    timeout(WAIT, async {
        while peer.read(&mut buf).await.unwrap() != 0 {}
    })
    .await
    .unwrap();
}
