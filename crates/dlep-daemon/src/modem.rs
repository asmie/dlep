use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::{MacAddress, StatusCode};
use dlep_ext::{DlepExtension, ExtensionRegistry};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_net::{Acceptor, ServerConfig};
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{ModemConfig, TimersConfig};
use crate::events::{DestinationId, LinkMetrics, PeerInfo};
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventRx, EventTx, SessionCommand, new_event_channel,
};
use crate::session::{run_session, session_config_from_timers};

pub struct ModemDaemon {
    events_tx: EventTx,
    /// Address the listen socket actually bound to (resolves `tcp_port = 0`).
    local_addr: SocketAddr,
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    /// First entry is the listen task; subsequent entries are per-session.
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    listen_task: JoinHandle<()>,
    discovery_shutdown: Mutex<Option<mpsc::Sender<()>>>,
    discovery_task: Mutex<Option<JoinHandle<Result<(), DaemonError>>>>,
}

impl ModemDaemon {
    pub fn builder() -> ModemBuilder {
        ModemBuilder::default()
    }

    pub fn subscribe(&self) -> EventRx {
        self.events_tx.subscribe()
    }

    /// The address (and port) the modem actually bound to. Useful for tests
    /// using `tcp_port = 0` to discover the OS-assigned port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn add_destination(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
    ) -> Result<(), DaemonError> {
        self.fanout(SessionCommand::AddDestination {
            mac: id.0,
            metrics,
            addrs: dlep_fsm::DestinationAddrs::default(),
        })
        .await
    }

    pub async fn update_destination(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
    ) -> Result<(), DaemonError> {
        self.fanout(SessionCommand::UpdateDestination { mac: id.0, metrics })
            .await
    }

    pub async fn drop_destination(
        &self,
        id: DestinationId,
        reason: StatusCode,
    ) -> Result<(), DaemonError> {
        self.fanout(SessionCommand::DropDestination { mac: id.0, reason })
            .await
    }

    pub async fn announce_destination(&self, mac: MacAddress) -> Result<(), DaemonError> {
        // Destination_Announce is out of M5 scope; tracked as future work.
        let _ = mac;
        Ok(())
    }

    /// Fan a command to every active session. Snapshot the sender list under
    /// the lock so we don't hold the mutex across `await`. If a session
    /// already exited and dropped its receiver, the `send` fails — we drop
    /// the error rather than surface it, since a dead session is not the
    /// caller's problem.
    async fn fanout(&self, cmd: SessionCommand) -> Result<(), DaemonError> {
        let senders: Vec<_> = {
            let guard = self.session_cmds.lock().await;
            guard.clone()
        };
        for tx in senders {
            let _ = tx.send(cmd.clone()).await;
        }
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), DaemonError> {
        // Stop the discovery task first so it doesn't try to reply to a
        // late Peer_Discovery after the TCP machinery is gone.
        if let Some(tx) = self.discovery_shutdown.lock().await.take() {
            let _ = tx.send(()).await;
        }
        if let Some(handle) = self.discovery_task.lock().await.take() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("modem discovery task returned error during shutdown: {e}"),
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("modem discovery task panicked during shutdown: {e}"),
            }
        }
        // Stop accepting new connections first so a slow shutdown isn't racing
        // a fresh peer.
        self.listen_task.abort();
        let _ = self.listen_task.await;

        let cmds: Vec<_> = std::mem::take(&mut *self.session_cmds.lock().await);
        for cmd_tx in cmds {
            let _ = cmd_tx
                .send(SessionCommand::Shutdown {
                    reason: StatusCode::SHUTTING_DOWN,
                })
                .await;
        }
        let tasks: Vec<_> = std::mem::take(&mut *self.tasks.lock().await);
        for handle in tasks {
            match handle.await {
                Ok(()) => {}
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("modem session task panicked: {e}"),
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct ModemBuilder {
    config: Option<ModemConfig>,
    extensions: ExtensionRegistry,
    server_tls: Option<Arc<ServerConfig>>,
}

impl ModemBuilder {
    pub fn config(mut self, cfg: ModemConfig) -> Self {
        self.config = Some(cfg);
        self
    }

    pub fn register_extension(mut self, ext: Arc<dyn DlepExtension>) -> Self {
        self.extensions.register(ext);
        self
    }

    pub fn with_rustls_server(mut self, cfg: Arc<ServerConfig>) -> Self {
        self.server_tls = Some(cfg);
        self
    }

    pub async fn spawn(self) -> Result<ModemDaemon, DaemonError> {
        let cfg = self
            .config
            .ok_or_else(|| DaemonError::Config("ModemConfig required".into()))?;
        let _ = self.extensions; // M8 hands these to per-session FSMs.

        let bind_addr = SocketAddr::new(cfg.shared.network.bind_addr, cfg.shared.network.tcp_port);
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;

        let acceptor = if cfg.shared.network.use_tls {
            let server_cfg = self.server_tls.clone().ok_or_else(|| {
                DaemonError::Config(
                    "use_tls = true requires ModemBuilder::with_rustls_server(...)".into(),
                )
            })?;
            Acceptor::tls(listener, server_cfg)
        } else {
            Acceptor::plain(listener)
        };

        let (events_tx, _events_rx) = new_event_channel();
        let session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

        let listen_task = tokio::spawn(modem_accept_loop(
            acceptor,
            events_tx.clone(),
            cfg.shared.timers.clone(),
            cfg.peer_description.clone(),
            session_cmds.clone(),
            tasks.clone(),
        ));

        // Discovery: bind the UDP multicast socket and spawn the listener.
        // The modem starts in Listening; it has no app-driven start event
        // (router-side is the active probe). The bind is best-effort — if it
        // fails (privileged port, no MULTICAST flag on the interface, etc.)
        // we log and continue so the rest of the daemon stays usable.
        let (discovery_shutdown, discovery_task) =
            match spawn_modem_discovery(&cfg, local_addr, events_tx.clone()).await? {
                Some((tx, handle)) => (Some(tx), Some(handle)),
                None => (None, None),
            };

        Ok(ModemDaemon {
            events_tx,
            local_addr,
            session_cmds,
            tasks,
            listen_task,
            discovery_shutdown: Mutex::new(discovery_shutdown),
            discovery_task: Mutex::new(discovery_task),
        })
    }
}

async fn spawn_modem_discovery(
    cfg: &ModemConfig,
    local_addr: SocketAddr,
    events_tx: EventTx,
) -> Result<Option<(mpsc::Sender<()>, JoinHandle<Result<(), DaemonError>>)>, DaemonError> {
    use std::net::IpAddr;

    use dlep_fsm::discovery_modem::ModemDiscoveryFsm;
    use dlep_net::discovery::{DiscoveryParams, DiscoverySocket};

    let interface_v4 = match cfg.shared.network.bind_addr {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(DaemonError::Config(
                "M6 discovery only supports v4 bind_addr".into(),
            ));
        }
    };
    let params = DiscoveryParams {
        group_v4: cfg.shared.network.discovery_v4_group,
        interface_v4,
        port: cfg.shared.network.discovery_port,
        group_port: None,
        multicast_loop: true,
        // Modem listens on the multicast group for Peer_Discovery.
        join_group: true,
    };
    let socket = match DiscoverySocket::bind(&params) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "modem discovery socket bind failed ({e}); discovery disabled. \
                 Set discovery_port to an unprivileged port or run with \
                 CAP_NET_BIND_SERVICE if discovery is required."
            );
            return Ok(None);
        }
    };

    let fsm = ModemDiscoveryFsm::new(
        local_addr,
        cfg.peer_description.clone(),
        cfg.shared.network.use_tls,
    );

    let (tx, rx) = mpsc::channel::<()>(1);
    let handle = tokio::spawn(async move {
        crate::discovery::run_discovery(fsm, socket, None, rx, events_tx).await
    });
    Ok(Some((tx, handle)))
}

async fn modem_accept_loop(
    acceptor: Acceptor,
    events_tx: EventTx,
    timers: TimersConfig,
    peer_description: String,
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    loop {
        let transport = match acceptor.accept().await {
            Ok(t) => t,
            Err(e) => {
                warn!("modem accept failed: {e}");
                continue;
            }
        };
        let peer_addr = match transport.peer_addr() {
            Ok(a) => a,
            Err(e) => {
                warn!("modem accept: peer_addr failed: {e}");
                continue;
            }
        };
        info!(peer = %peer_addr, "modem accepted connection");

        let peer_info = PeerInfo {
            addr: peer_addr,
            is_tls: transport.is_tls(),
            peer_description: None,
        };
        let session_cfg = session_config_from_timers(&timers, peer_description.clone());
        let fsm = ModemSessionFsm::with_config(session_cfg);

        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        session_cmds.lock().await.push(cmd_tx);

        let events_tx_for_task = events_tx.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_session(
                fsm,
                transport,
                dlep_fsm::FsmEvent::TcpAccepted,
                cmd_rx,
                events_tx_for_task,
                peer_info,
            )
            .await
            {
                warn!("modem session task error: {e}");
            }
        });
        tasks.lock().await.push(handle);
    }
}
