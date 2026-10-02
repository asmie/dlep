use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::StatusCode;
use dlep_ext::{DlepExtension, ExtensionRegistry, Role};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_net::{ClientConfig, Connector};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::config::{NetworkConfig, RouterConfig, TimersConfig};
use crate::events::{DestinationId, LinkMetrics, PeerInfo};
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventRx, EventTx, SessionCommand, new_event_channel,
};
use crate::session::{
    SessionIdCounter, new_session_id_counter, run_session, session_config_from_timers,
};

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
    client_tls: Option<Arc<ClientConfig>>,
    extensions: ExtensionRegistry,
    session_id_counter: SessionIdCounter,
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

    /// Try the offer's compatible endpoints in preference order. TLS-required
    /// configuration never falls back to plaintext; --no-tls never sends
    /// plaintext to an endpoint advertising TLS.
    pub async fn connect_discovered(
        &self,
        offer: &crate::events::PeerOffer,
    ) -> Result<SocketAddr, DaemonError> {
        let mut error = DaemonError::Config("offer has no compatible connection points".into());
        for endpoint in &offer.endpoints {
            if endpoint.use_tls != self.network.use_tls {
                continue;
            }
            match self.connect_static(endpoint.addr).await {
                Ok(()) => return Ok(endpoint.addr),
                Err(e) => error = e,
            }
        }
        Err(error)
    }

    /// Open a session against a known modem address. The TCP connection is
    /// established before this function returns; the session task then runs
    /// independently until shutdown or peer disconnect.
    pub async fn connect_static(&self, peer: SocketAddr) -> Result<(), DaemonError> {
        let connector = if self.network.use_tls {
            let cfg = self.client_tls.clone().ok_or_else(|| {
                DaemonError::Config(
                    "use_tls = true requires RouterBuilder::with_rustls_client(...)".into(),
                )
            })?;
            Connector::tls(cfg)
        } else {
            Connector::plain()
        };

        let transport = connector
            .with_gtsm(self.network.gtsm_enforce)
            .connect(peer)
            .await?;
        let peer_info = PeerInfo {
            addr: transport.peer_addr()?,
            is_tls: transport.is_tls(),
            peer_description: None,
        };

        let advertised = self.extensions.advertised();
        let session_cfg =
            session_config_from_timers(&self.timers, self.peer_description.clone(), advertised);
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
            self.extensions.clone(),
            Role::Router,
            self.session_id_counter.clone(),
        ));

        let mut commands = self.session_cmds.lock().await;
        commands.retain(|tx| !tx.is_closed());
        commands.push(cmd_tx);
        let mut tasks = self.tasks.lock().await;
        tasks.retain(|task| !task.is_finished());
        tasks.push(handle);
        Ok(())
    }

    /// Declare interest in a destination the modem has not reported, via a
    /// Destination Announce Message (RFC 8175 §12.13 — router-originated).
    /// The modem MUST answer with a Destination Announce Response (§12.14).
    pub async fn announce_destination(&self, id: DestinationId) -> Result<(), DaemonError> {
        self.fanout(SessionCommand::AnnounceDestination { mac: id.0 })
            .await
    }

    /// Withdraw interest in a destination on one modem session (§12.15).
    /// Completion emits DestinationEvent::Down with the response status as
    /// its reason. The MAC stays known until the matching response arrives;
    /// peer failure is detected by session heartbeats, not a request timeout.
    /// As with other commands, busy/unknown destinations and stale session IDs
    /// are not queued. Use a SessionUp/Destination event's session ID.
    pub async fn drop_destination(
        &self,
        session_id: dlep_ext::SessionId,
        id: DestinationId,
    ) -> Result<(), DaemonError> {
        self.fanout(SessionCommand::DropDestinationForSession {
            session_id,
            mac: id.0,
        })
        .await
    }

    /// Request rate/latency changes from one modem (RFC 8175 §12.18).
    /// Use the session ID from SessionUp/Destination events. Completion is
    /// delivered as DestinationEvent::LinkCharacteristicsResponse. Per RFC §8,
    /// the transaction has no deadline: a slow peer remains valid while its
    /// heartbeats continue. Session reset discards outstanding transactions.
    /// Like existing destination commands, busy/unknown destinations or stale
    /// session IDs are not queued. Await completion before requesting again.
    pub async fn request_link_characteristics(
        &self,
        session_id: dlep_ext::SessionId,
        id: DestinationId,
        requested: dlep_core::LinkCharacteristics,
    ) -> Result<(), DaemonError> {
        if requested.is_empty() {
            return Err(DaemonError::Config(
                "at least one link characteristic must be requested".into(),
            ));
        }
        // Reject unencodable application values before they reach the session.
        dlep_fsm::session_common::build_link_characteristics_request(id.0, &requested).encode()?;
        self.fanout(SessionCommand::RequestLinkCharacteristics {
            session_id,
            mac: id.0,
            requested,
        })
        .await
    }

    /// Compatibility entry point: always returns a configuration error.
    /// RFC 8175 §12.7 permits only modems to originate session metric items.
    pub async fn update_session_metrics(&self, _metrics: LinkMetrics) -> Result<(), DaemonError> {
        Err(DaemonError::Config(
            "only a modem may originate session metrics (RFC 8175 section 12.7)".into(),
        ))
    }

    /// Fan a command to every active session. Snapshot the sender list under
    /// the lock so we don't hold the mutex across `await`; a session that
    /// already exited and dropped its receiver is not the caller's problem.
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
        Ok(RouterDaemon {
            events_tx,
            timers: cfg.shared.timers.clone(),
            network: cfg.shared.network.clone(),
            session_cmds: Arc::new(Mutex::new(Vec::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            discovery_shutdown: Mutex::new(None),
            discovery_task: Mutex::new(None),
            session_id_counter: new_session_id_counter(),
            peer_description: cfg.peer_description.clone(),
            client_tls: self.client_tls,
            extensions: self.extensions,
        })
    }
}
