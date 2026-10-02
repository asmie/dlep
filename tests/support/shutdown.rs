//! Shared subprocess regressions: signals must trigger protocol shutdown, not
//! merely a successful-looking exit after a dropped socket.
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
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

struct Process {
    child: Child,
    log: PathBuf,
}
impl Process {
    fn spawn(binary: &str, config: &Path) -> Self {
        let log = config.with_extension("log");
        let child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("DLEP_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(std::fs::File::create(&log).unwrap())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self { child, log }
    }
    async fn modem_addr(&mut self) -> SocketAddr {
        timeout(WAIT, async {
            loop {
                let output = std::fs::read_to_string(&self.log).unwrap();
                // Only use a complete line, not a partially written address.
                for line in output.split_inclusive('\n').filter(|s| s.ends_with('\n')) {
                    if let Some((_, addr)) = line.split_once("modem listening on ") {
                        let addr: SocketAddr = addr.trim().parse().unwrap();
                        assert!(addr.ip().is_loopback());
                        assert_ne!(addr.port(), 0, "modem must report its assigned port");
                        return addr;
                    }
                }
                assert!(
                    self.child.try_wait().unwrap().is_none(),
                    "modem failed to start"
                );
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("modem did not report its listening address")
    }
    fn signal(&mut self, signal: Signal) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "daemon exited before signal"
        );
        kill(Pid::from_raw(self.child.id() as i32), signal).unwrap();
    }
    async fn exited_cleanly(&mut self, limit: Duration) {
        let status = timeout(limit, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
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
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if std::thread::panicking() {
            eprintln!(
                "daemon output:\n{}",
                std::fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
    }
}

async fn read_message(peer: &mut TcpStream, phase: &str) -> Message {
    timeout(WAIT, async {
        let mut header = [0; 4];
        peer.read_exact(&mut header)
            .await
            .unwrap_or_else(|error| panic!("{phase}: reading DLEP header: {error}"));
        let mut bytes = header.to_vec();
        bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
        peer.read_exact(&mut bytes[4..])
            .await
            .unwrap_or_else(|error| panic!("{phase}: reading DLEP payload: {error}"));
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
async fn connect(child: &mut Process) -> TcpStream {
    // A bind-and-drop port reservation can still accept connections during a
    // concurrent subprocess spawn, or be reused before the modem binds. Let
    // the modem bind port zero and wait for its own readiness announcement.
    let addr = child.modem_addr().await;
    let socket = TcpSocket::new_v4().unwrap();
    dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
    timeout(WAIT, socket.connect(addr))
        .await
        .expect("connecting to ready modem timed out")
        .expect("connecting to ready modem")
}

async fn listener(role: Role) -> (Option<TcpListener>, SocketAddr) {
    match role {
        Role::Router => {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.set_ttl(255).unwrap();
            let addr = listener.local_addr().unwrap();
            (Some(listener), addr)
        }
        Role::Modem => (None, "127.0.0.1:0".parse().unwrap()),
    }
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
    let (listener, addr) = listener(role).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, config(role, addr, false)).unwrap();
    let mut child = Process::spawn(binary, &path);
    let mut peer = match listener {
        Some(listener) => timeout(WAIT, listener.accept()).await.unwrap().unwrap().0,
        None => connect(&mut child).await,
    };
    match role {
        Role::Router => {
            let init = read_message(&mut peer, "router initialization").await;
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
                read_message(&mut peer, "router ready").await.message_type,
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
            let response = read_message(&mut peer, "modem initialization").await;
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
    let termination = read_message(&mut peer, "session termination").await;
    assert_eq!(termination.message_type, MessageType::SESSION_TERMINATION);
    assert!(termination.data_items.iter().any(|i| matches!(
        i,
        DataItem::Status {
            code: StatusCode::SHUTTING_DOWN,
            ..
        }
    )));
    assert!(
        child.child.try_wait().unwrap().is_none(),
        "must wait for termination acknowledgement"
    );
    if acknowledge {
        // A second stop request must not bypass the in-flight exchange.
        child.signal(signal);
        sleep(Duration::from_millis(50)).await;
        assert!(
            child.child.try_wait().unwrap().is_none(),
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
    let (listener, addr) = listener(role).await;
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
        None => {
            let mut peer = connect(&mut child).await;
            let mut tls = rustls::ClientConnection::new(
                dlep_net::tls::test_helpers::client_config_for(pki.roots),
                addr.ip().into(),
            )
            .unwrap();
            let mut hello = Vec::new();
            tls.write_tls(&mut hello).unwrap();
            timeout(WAIT, peer.write_all(&hello))
                .await
                .unwrap()
                .unwrap();
            // A server handshake record proves this connection was accepted
            // and TLS is in progress. Never send the client's Finished record.
            let mut header = [0; 5];
            timeout(WAIT, peer.read_exact(&mut header))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(header[0], 22, "expected a TLS handshake record");
            assert_eq!(&header[1..3], &[3, 3]);
            assert_ne!(u16::from_be_bytes([header[3], header[4]]), 0);
            peer
        }
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
