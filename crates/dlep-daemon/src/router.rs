use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::StatusCode;
use dlep_ext::{DlepExtension, ExtensionRegistry};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_net::{ClientConfig, Connector, TLS_NOT_IMPLEMENTED_MSG};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::config::{NetworkConfig, RouterConfig, TimersConfig};
use crate::events::PeerInfo;
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventRx, EventTx, SessionCommand, new_event_channel,
};
use crate::session::{run_session, session_config_from_timers};

type SessionTaskHandle = JoinHandle<Result<(), DaemonError>>;

/// Public router handle. Holds channel senders, the timers config, and
/// background task handles.
pub struct RouterDaemon {
    events_tx: EventTx,
    timers: TimersConfig,
    network: NetworkConfig,
    /// Per-active-session command channels, used to fan out shutdown.
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    /// Background tasks: one per active session.
    tasks: Arc<Mutex<Vec<SessionTaskHandle>>>,
    /// Set by `start_discovery`; cleared by `shutdown`. Sends `()` to ask the
    /// discovery task to stop.
    discovery_shutdown: Mutex<Option<mpsc::Sender<()>>>,
    /// Handle to the running discovery task, populated alongside
    /// `discovery_shutdown`.
    discovery_task: Mutex<Option<JoinHandle<Result<(), DaemonError>>>>,
    peer_description: String,
    use_tls: bool,
}

impl RouterDaemon {
    pub fn builder() -> RouterBuilder {
        RouterBuilder::default()
    }

    pub fn subscribe(&self) -> EventRx {
        self.events_tx.subscribe()
    }

    pub async fn start_discovery(&self) -> Result<(), DaemonError> {
        use std::net::IpAddr;
        use std::time::Duration;

        use dlep_fsm::FsmEvent;
        use dlep_fsm::discovery_router::{RouterDiscoveryConfig, RouterDiscoveryFsm};
        use dlep_net::discovery::{DiscoveryParams, DiscoverySocket};

        let mut slot = self.discovery_shutdown.lock().await;
        if slot.is_some() {
            return Err(DaemonError::Config("discovery already running".into()));
        }

        let interface_v4 = match self.network.bind_addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(DaemonError::Config(
                    "M6 discovery only supports v4 bind_addr".into(),
                ));
            }
        };
        let params = DiscoveryParams {
            group_v4: self.network.discovery_v4_group,
            interface_v4,
            // Router-side: bind ephemeral (port 0) so the modem's unicast
            // Peer_Offer reply lands on a port not shared with any other
            // discovery socket — critical for same-host loopback tests
            // where SO_REUSEPORT would otherwise hash the reply to the
            // modem's own socket. Routers don't receive multicast (only
            // unicast offers), so this is also more correct.
            port: 0,
            group_port: Some(self.network.discovery_port),
            // Loopback testing runs router and modem in the same process,
            // so the kernel must deliver our own multicast sends to our own
            // receive queue. Production deployments where the modem is on a
            // separate host wouldn't strictly need this, but leaving it on
            // simplifies the public API.
            multicast_loop: true,
            // Router only sends multicast Peer_Discovery and receives
            // unicast Peer_Offer; no need to join the discovery group.
            join_group: false,
        };
        let socket = DiscoverySocket::bind(&params)?;

        let fsm = RouterDiscoveryFsm::with_config(RouterDiscoveryConfig {
            peer_description: self.peer_description.clone(),
            discovery_interval: Duration::from_millis(self.timers.discovery_interval_ms.into()),
        });

        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let events_tx = self.events_tx.clone();
        let handle = tokio::spawn(async move {
            crate::discovery::run_discovery(
                fsm,
                socket,
                Some(FsmEvent::AppStartDiscovery),
                shutdown_rx,
                events_tx,
            )
            .await
        });

        *slot = Some(shutdown_tx);
        *self.discovery_task.lock().await = Some(handle);
        Ok(())
    }

    /// Open a session against a known modem address. The TCP connection is
    /// established before this function returns; the session task then runs
    /// independently until shutdown or peer disconnect.
    pub async fn connect_static(&self, peer: SocketAddr) -> Result<(), DaemonError> {
        if self.use_tls {
            return Err(io::Error::other(TLS_NOT_IMPLEMENTED_MSG).into());
        }

        let connector = Connector::plain();
        let transport = connector.connect(peer).await?;
        let peer_info = PeerInfo {
            addr: transport.peer_addr()?,
            is_tls: transport.is_tls(),
            peer_description: None,
        };

        let session_cfg = session_config_from_timers(&self.timers, self.peer_description.clone());
        let fsm = RouterSessionFsm::with_config(session_cfg);

        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let events_tx = self.events_tx.clone();
        let handle = tokio::spawn(run_session(
            fsm,
            transport,
            dlep_fsm::FsmEvent::TcpConnected,
            cmd_rx,
            events_tx,
            peer_info,
        ));

        self.session_cmds.lock().await.push(cmd_tx);
        self.tasks.lock().await.push(handle);
        Ok(())
    }

    /// Initiate a graceful shutdown: every active session is asked to send
    /// Session Termination, await the response, and tear down the TCP
    /// connection. Returns once all session tasks have completed.
    pub async fn shutdown(self) -> Result<(), DaemonError> {
        // Stop the discovery task first so it doesn't try to dispatch new
        // PeerDiscovered events after the session machinery is gone.
        if let Some(tx) = self.discovery_shutdown.lock().await.take() {
            let _ = tx.send(()).await;
        }
        if let Some(handle) = self.discovery_task.lock().await.take() {
            match handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("discovery task returned error during shutdown: {e}"),
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("discovery task panicked during shutdown: {e}"),
            }
        }
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
                Ok(Ok(())) => {}
                Ok(Err(e)) => warn!("session task returned error during shutdown: {e}"),
                Err(e) if e.is_cancelled() => {}
                Err(e) => warn!("session task panicked during shutdown: {e}"),
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct RouterBuilder {
    config: Option<RouterConfig>,
    extensions: ExtensionRegistry,
    client_tls: Option<Arc<ClientConfig>>,
}

impl RouterBuilder {
    pub fn config(mut self, cfg: RouterConfig) -> Self {
        self.config = Some(cfg);
        self
    }

    pub fn register_extension(mut self, ext: Arc<dyn DlepExtension>) -> Self {
        self.extensions.register(ext);
        self
    }

    pub fn with_rustls_client(mut self, cfg: Arc<ClientConfig>) -> Self {
        self.client_tls = Some(cfg);
        self
    }

    pub async fn spawn(self) -> Result<RouterDaemon, DaemonError> {
        let cfg = self
            .config
            .ok_or_else(|| DaemonError::Config("RouterConfig required".into()))?;
        let (events_tx, _events_rx) = new_event_channel();
        let _ = self.extensions; // M8 hands these off to the session task.
        let _ = self.client_tls; // M7 hands this to the Connector.
        Ok(RouterDaemon {
            events_tx,
            timers: cfg.shared.timers.clone(),
            network: cfg.shared.network.clone(),
            session_cmds: Arc::new(Mutex::new(Vec::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            discovery_shutdown: Mutex::new(None),
            discovery_task: Mutex::new(None),
            peer_description: cfg.peer_description.clone(),
            use_tls: cfg.shared.network.use_tls,
        })
    }
}
