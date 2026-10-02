use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::StatusCode;
use dlep_ext::{DlepExtension, ExtensionRegistry, Role};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_net::{Acceptor, ServerConfig};
use tokio::net::TcpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::{ModemConfig, TimersConfig};
use crate::events::{DestinationId, LinkMetrics, PeerInfo};
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventRx, EventTx, SessionCommand, new_event_channel,
};
use crate::session::{
    SessionIdCounter, new_session_id_counter, run_session, session_config_from_timers,
};

pub struct ModemDaemon {
    initial_metrics: LinkMetrics,
    events_tx: EventTx,
    /// Address the listen socket actually bound to (resolves `tcp_port = 0`).
    local_addr: SocketAddr,
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    /// First entry is the listen task; subsequent entries are per-session.
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    listen_task: JoinHandle<()>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
    discovery_shutdown: Mutex<Option<mpsc::Sender<()>>>,
    discovery_task: Mutex<Option<JoinHandle<Result<(), DaemonError>>>>,
    extensions: ExtensionRegistry,
    session_id_counter: SessionIdCounter,
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
        self.add_destination_with_addresses(id, metrics, dlep_fsm::DestinationAddrs::default())
            .await
    }

    /// Advertise a destination together with its initial IPv4/IPv6 addresses
    /// and attached subnets. Subsequent changes use update_destination_addresses.
    pub async fn add_destination_with_addresses(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
        addresses: dlep_fsm::DestinationAddrs,
    ) -> Result<(), DaemonError> {
        self.validate_metrics(&metrics)?;
        let changes = dlep_fsm::AddressChanges {
            added: addresses.canonical(),
            removed: Default::default(),
        };
        crate::runtime::validate_address_changes(&changes)?;
        dlep_fsm::session_common::build_destination_up(id.0, &metrics, &changes.added).encode()?;
        self.fanout(SessionCommand::AddDestination {
            mac: id.0,
            metrics,
            addrs: changes.added,
        })
        .await
    }

    /// Send effective address additions/removals to subscribed routers. Changes
    /// during Up acknowledgement are coalesced and sent once Up completes.
    pub async fn update_destination_addresses(
        &self,
        id: DestinationId,
        changes: dlep_fsm::AddressChanges,
    ) -> Result<(), DaemonError> {
        crate::runtime::validate_address_changes(&changes)?;
        self.fanout(SessionCommand::UpdateDestinationAddresses {
            mac: id.0,
            changes: changes.canonical(),
        })
        .await
    }

    pub async fn update_destination(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
    ) -> Result<(), DaemonError> {
        self.validate_metrics(&metrics)?;
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

    /// Push session-wide metric changes to every connected router via a
    /// Session Update Message (RFC 8175 §12.7). These are the session-level
    /// defaults, distinct from the per-destination metrics carried by
    /// [`Self::update_destination`]. Omitted optional values remain unchanged;
    /// supplied optional metrics must be declared in `ModemConfig.metrics`.
    /// Updates affect current sessions, not configuration for future sessions.
    pub async fn update_session_metrics(&self, metrics: LinkMetrics) -> Result<(), DaemonError> {
        self.validate_metrics(&metrics)?;
        self.fanout(SessionCommand::SessionUpdate { metrics }).await
    }

    /// Advertise local peer-address/subnet changes on one session. This sends
    /// an address-only Session Update; it does not alter destination metrics.
    /// Repeated adds/absent removes are local no-ops. Busy session transactions
    /// follow the current no-queue command convention.
    pub async fn update_session_addresses(
        &self,
        session_id: dlep_ext::SessionId,
        changes: dlep_fsm::AddressChanges,
    ) -> Result<(), DaemonError> {
        crate::runtime::validate_address_changes(&changes)?;
        self.fanout(SessionCommand::UpdateSessionAddresses {
            session_id,
            changes: changes.canonical(),
        })
        .await
    }

    fn validate_metrics(&self, metrics: &LinkMetrics) -> Result<(), DaemonError> {
        if !metrics.supported_by(&self.initial_metrics) {
            return Err(DaemonError::Config(
                "optional metric was not declared in ModemConfig.metrics".into(),
            ));
        }
        dlep_fsm::session_common::build_session_update(metrics).encode()?;
        Ok(())
    }

    /// Fan a command to every active session. Snapshot the sender list under
    /// the lock so we don't hold the mutex across `await`. If a session
    /// already exited and dropped its receiver, the `send` fails — we drop
    /// the error rather than surface it, since a dead session is not the
    /// caller's problem.
    async fn fanout(&self, cmd: SessionCommand) -> Result<(), DaemonError> {
        let senders: Vec<_> = {
            let mut guard = self.session_cmds.lock().await;
            guard.retain(|tx| !tx.is_closed());
            guard.clone()
        };
        for tx in senders {
            let _ = tx.send(cmd.clone()).await;
        }
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), DaemonError> {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
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
        cfg.metrics.validate().map_err(DaemonError::Config)?;
        let initial_metrics = cfg.metrics.link_metrics();
        let extensions_for_accept = self.extensions.clone();

        let bind_addr = SocketAddr::new(cfg.shared.network.bind_addr, cfg.shared.network.tcp_port);
        let socket = if bind_addr.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        dlep_net::gtsm::configure_tcp(
            &socket,
            bind_addr.is_ipv6(),
            cfg.shared.network.gtsm_enforce,
        )?;
        socket.bind(bind_addr)?;
        let listener = socket.listen(128)?;
        let local_addr = listener.local_addr()?;

        let acceptor = if cfg.shared.network.use_tls {
            let server_cfg = self.server_tls.clone().ok_or_else(|| {
                DaemonError::Config(
                    "use_tls = true requires ModemBuilder::with_rustls_server(...)".into(),
                )
            })?;
            Acceptor::tls_with_gtsm(listener, server_cfg, cfg.shared.network.gtsm_enforce)?
        } else {
            Acceptor::plain_with_gtsm(listener, cfg.shared.network.gtsm_enforce)?
        };

        let (events_tx, _events_rx) = new_event_channel();
        let session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>> =
            Arc::new(Mutex::new(Vec::new()));
        let tasks: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let session_id_counter = new_session_id_counter();

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

        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listen_task = tokio::spawn(modem_accept_loop(
            acceptor,
            events_tx.clone(),
            cfg.shared.timers.clone(),
            cfg.peer_description.clone(),
            initial_metrics,
            session_cmds.clone(),
            tasks.clone(),
            extensions_for_accept,
            session_id_counter.clone(),
            stopping.clone(),
        ));

        Ok(ModemDaemon {
            initial_metrics,
            events_tx,
            local_addr,
            session_cmds,
            tasks,
            listen_task,
            stopping,
            discovery_shutdown: Mutex::new(discovery_shutdown),
            discovery_task: Mutex::new(discovery_task),
            extensions: self.extensions,
            session_id_counter,
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

#[allow(clippy::too_many_arguments)]
async fn modem_accept_loop(
    acceptor: Acceptor,
    events_tx: EventTx,
    timers: TimersConfig,
    peer_description: String,
    initial_metrics: LinkMetrics,
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    extensions: ExtensionRegistry,
    session_id_counter: SessionIdCounter,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let pending = match acceptor.accept_pending().await {
            Ok(p) => p,
            Err(e) => {
                warn!("modem accept failed: {e}");
                continue;
            }
        };
        // Bound concurrent handshakes/sessions; excess TCP streams are closed.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let events_tx = events_tx.clone();
        let extensions = extensions.clone();
        let timers = timers.clone();
        let peer_description = peer_description.clone();
        let counter = session_id_counter.clone();
        let commands = session_cmds.clone();
        let stopping = stopping.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let transport = match pending.handshake().await {
                Ok(t) => t,
                Err(e) => {
                    warn!("modem handshake failed: {e}");
                    return;
                }
            };
            let peer_addr = match transport.peer_addr() {
                Ok(a) => a,
                Err(_) => return,
            };
            info!(peer = %peer_addr, "modem accepted connection");
            let peer = PeerInfo {
                addr: peer_addr,
                is_tls: transport.is_tls(),
                peer_description: None,
            };
            let mut cfg =
                session_config_from_timers(&timers, peer_description, extensions.advertised());
            cfg.initial_metrics = initial_metrics;
            let (tx, rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
            {
                let mut senders = commands.lock().await;
                if stopping.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                senders.retain(|s| !s.is_closed());
                senders.push(tx);
            }
            if let Err(e) = run_session(
                ModemSessionFsm::with_config(cfg),
                transport,
                dlep_fsm::FsmEvent::TcpAccepted,
                rx,
                events_tx,
                peer,
                extensions,
                Role::Modem,
                counter,
            )
            .await
            {
                warn!("modem session task error: {e}");
            }
            commands.lock().await.retain(|s| !s.is_closed());
        });
        let mut running = tasks.lock().await;
        running.retain(|h| !h.is_finished());
        running.push(handle);
    }
}
