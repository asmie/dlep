use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::StatusCode;
use dlep_ext::{DlepExtension, ExtensionRegistry, Role};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_net::{ClientConfig, Connector, ServerName, Transport};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::warn;

use crate::config::{NetworkConfig, RouterConfig, TimersConfig};
use crate::connections::{ConnectionRegistry, HistoryReaper, PeerConnectionState};
use crate::events::{DestinationId, LinkMetrics, PeerInfo};
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventRx, EventTx, SessionCommand, SessionHandle,
    new_event_channel,
};
use crate::session::{
    SessionIdCounter, new_session_id_counter, run_session_tracked, session_config_from_timers,
};

type SessionTaskHandle = JoinHandle<Result<(), DaemonError>>;

/// Public router handle. Holds channel senders, the timers config, and
/// background task handles.
pub struct RouterDaemon {
    destination_policy: dlep_fsm::DestinationPolicy,
    events_tx: EventTx,
    state: Arc<crate::state::StateRegistry>,
    connections: Arc<ConnectionRegistry>,
    session_slots: Arc<tokio::sync::Semaphore>,
    _history_reaper: HistoryReaper,
    timers: TimersConfig,
    network: NetworkConfig,
    /// Per-active-session command channels, used to fan out shutdown.
    session_cmds: Arc<Mutex<Vec<SessionHandle>>>,
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

    /// Retained protocol state for late or lagged consumers. Read the initial
    /// snapshot and subsequent changes; clone and release watch borrows before
    /// awaiting. Do not replay older broadcast events over a newer snapshot.
    /// This feed coalesces state changes and does not retain command outcomes.
    pub fn state(&self) -> watch::Receiver<crate::DaemonSnapshot> {
        self.state.subscribe()
    }

    /// Subscribe to retained connection state for reconnect decisions. Unlike
    /// `subscribe()`, this feed cannot lag or lose the latest lifecycle state.
    /// Changes may coalesce; `establishment_count` preserves successful
    /// initializations even when a session is already closed when read.
    /// Inactive non-static entries expire or are evicted under history pressure.
    /// Subscribers must discard retry state for endpoints removed from snapshots;
    /// the generation stays unique even when eviction and re-admission coalesce.
    /// Read the initial snapshot as well as subsequent changes. Drop watch
    /// borrow guards before awaiting to avoid blocking session state updates.
    pub fn connection_states(&self) -> watch::Receiver<HashMap<SocketAddr, PeerConnectionState>> {
        self.connections.subscribe()
    }

    /// Connections being established and registered sessions share this budget.
    pub fn connection_capacity(&self) -> usize {
        self.session_slots.available_permits()
    }

    /// Wait without retaining a slot. Drivers must still handle admission races.
    pub async fn wait_for_connection_capacity(&self) {
        drop(
            self.session_slots
                .acquire()
                .await
                .expect("session budget stays open"),
        );
    }

    pub async fn start_discovery(&self) -> Result<(), DaemonError> {
        use std::time::Duration;

        use dlep_fsm::discovery_router::{RouterDiscoveryConfig, RouterDiscoveryFsm};

        let mut slot = self.discovery_shutdown.lock().await;
        if slot.is_some() {
            // A stopped task (reported by `DiscoveryStopped`) may be restarted.
            let mut task_slot = self.discovery_task.lock().await;
            if !task_slot.as_ref().is_some_and(JoinHandle::is_finished) {
                return Err(DaemonError::Config("discovery already running".into()));
            }
            slot.take();
            if let Some(handle) = task_slot.take() {
                let _ = handle.await;
            }
        }

        let sockets = self.network.bind_discoveries(false)?;

        let config = RouterDiscoveryConfig {
            peer_description: self.peer_description.clone(),
            discovery_interval: Duration::from_millis(self.timers.discovery_interval_ms.into()),
        };
        let members = sockets
            .into_iter()
            .map(|socket| (RouterDiscoveryFsm::with_config(config.clone()), socket))
            .collect();

        // Acquire both registry locks before spawning. Cancellation must not
        // leave a running task that shutdown cannot find and join.
        let mut task_slot = self.discovery_task.lock().await;
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
        let events_tx = self.events_tx.clone();
        let extensions = self.extensions.clone();
        let handle = tokio::spawn(async move {
            crate::discovery::run_supervised_discovery_group(
                members,
                true,
                shutdown_rx,
                events_tx,
                None,
                extensions,
                Role::Router,
            )
            .await
        });

        *slot = Some(shutdown_tx);
        *task_slot = Some(handle);
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
    /// independently until shutdown or peer disconnect. Cancellation before
    /// registration drops the pending transport; spawned sessions are always
    /// registered for graceful shutdown before this future can yield again.
    pub async fn connect_static(&self, peer: SocketAddr) -> Result<(), DaemonError> {
        let permit = self.connection_permit()?;
        let transport = self.connector()?.connect(peer).await?;
        self.register_transport(transport, permit).await
    }

    /// Connect to an IP endpoint using an explicit certificate identity rather
    /// than the endpoint IP. The name must be a DNS name or bare IP literal.
    /// TLS verification and GTSM remain enabled according to router config.
    /// Like `connect_static`, success precedes DLEP initialization.
    pub async fn connect_static_with_server_name(
        &self,
        peer: SocketAddr,
        server_name: &str,
    ) -> Result<(), DaemonError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_| DaemonError::Config("invalid TLS server name or IP address".into()))?;
        let permit = self.connection_permit()?;
        let transport = self
            .connector()?
            .connect_with_server_name(peer, server_name)
            .await?;
        self.register_transport(transport, permit).await
    }

    /// Resolve and connect to a named peer, preserving the requested host for
    /// TLS verification and SNI. Tries at most 16 distinct resolver answers
    /// within 15 seconds, without downgrading TLS. Numeric literals also work.
    /// One session slot covers resolution and every fallback attempt; dropping
    /// this future releases it and any pending transport. The system resolver
    /// itself may finish blocking work after cancellation.
    ///
    /// Returns the connected numeric endpoint before DLEP initialization.
    /// Events and snapshots use that endpoint. Call again to resolve afresh;
    /// automatic reconnection and name-to-session tracking belong to the caller.
    pub async fn connect_named(&self, host: &str, port: u16) -> Result<SocketAddr, DaemonError> {
        let permit = self.connection_permit()?;
        let transport = self.connector()?.connect_host(host, port).await?;
        let peer = transport.peer_addr()?;
        self.register_transport(transport, permit).await?;
        Ok(peer)
    }

    /// Resolve a named IPv6 zone afresh and connect with IP-based TLS identity.
    /// Returns before DLEP initialization; callers own automatic reconnection.
    pub async fn connect_scoped(
        &self,
        peer: &crate::ScopedPeer,
    ) -> Result<SocketAddr, DaemonError> {
        let address = peer.resolve()?;
        self.connect_static(address).await?;
        Ok(address)
    }

    fn connection_permit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, DaemonError> {
        self.session_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| DaemonError::SessionLimitReached)
    }

    fn connector(&self) -> Result<Connector, DaemonError> {
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
        Ok(connector.with_gtsm(self.network.gtsm_enforce))
    }

    async fn register_transport(
        &self,
        transport: Box<dyn Transport>,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), DaemonError> {
        let peer_info = PeerInfo {
            secured_medium: None,
            addr: transport.peer_addr()?,
            is_tls: transport.is_tls(),
            peer_description: None,
        };

        let advertised = self.extensions.advertised();
        let mut session_cfg =
            session_config_from_timers(&self.timers, self.peer_description.clone(), advertised);
        session_cfg.mac_address_format = self.network.mac_address_format;
        session_cfg.destination_policy = self.destination_policy.clone();
        let fsm = RouterSessionFsm::with_config(session_cfg);

        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let session_id = crate::session::next_session_id(&self.session_id_counter);
        let events_tx = self.events_tx.clone();
        let mut commands = self.session_cmds.lock().await;
        let mut tasks = self.tasks.lock().await;
        let tracker = self.connections.register(peer_info.addr)?;
        let session = run_session_tracked(
            fsm,
            transport,
            dlep_fsm::FsmEvent::TcpConnected,
            cmd_rx,
            events_tx,
            peer_info,
            self.extensions.clone(),
            Role::Router,
            session_id,
            Some(tracker),
            None,
            Some(self.state.clone()),
        );
        let handle = tokio::spawn(async move {
            let _permit = permit;
            session.await
        });

        commands.retain(|tx| !tx.is_closed());
        commands.push(SessionHandle {
            id: session_id,
            tx: cmd_tx,
        });
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

    /// Declare interest on one session with address additions/removals as hints.
    /// Hints may contain IPv4/IPv6 addresses, not attached subnets (§12.13).
    /// Hints do not update local addresses or destination state. The modem's
    /// response reports its actual destination data. Invalid or oversized hints
    /// are rejected before dispatch; busy destinations must be retried after
    /// completion. An empty hint set still sends a Destination Announce.
    pub async fn announce_destination_with_addresses(
        &self,
        session_id: dlep_ext::SessionId,
        id: DestinationId,
        changes: dlep_fsm::AddressChanges,
    ) -> Result<(), DaemonError> {
        dlep_fsm::session_common::validate_announce_addresses(id.0, &changes).map_err(|_| {
            DaemonError::Config("invalid or oversized Announce address hints".into())
        })?;
        self.send_command_to(
            session_id,
            SessionCommand::AnnounceDestinationWithAddresses {
                mac: id.0,
                changes: changes.canonical(),
            },
        )
        .await
    }

    /// Withdraw interest in a destination on one modem session (§12.15).
    /// Completion emits DestinationEvent::Down with the response status as
    /// its reason. The MAC stays known until the matching response arrives;
    /// peer failure is detected by session heartbeats, not a request timeout.
    /// Busy/unknown destinations return CommandRejected; stale session IDs
    /// return NoMatchingSession. Use a SessionUp/Destination event's session ID.
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
    /// Busy/unknown destinations return CommandRejected; stale session IDs
    /// return NoMatchingSession. Await completion before requesting again.
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

    /// Advertise local peer-address/subnet changes on one session. This sends
    /// an address-only Session Update; it does not alter destination metrics.
    /// Repeated adds/absent removes are successful local no-ops. Busy sessions
    /// return CommandRejected with CommandError::Busy; retry after completion.
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

    /// Submit a command to one session, including a retry after a partial
    /// broadcast rejection. Returns local acceptance, not the peer's response.
    /// The session validates role, state, transaction scope, and payload.
    pub async fn send_command_to(
        &self,
        session_id: dlep_ext::SessionId,
        command: SessionCommand,
    ) -> Result<(), DaemonError> {
        self.dispatch(command, Some(session_id)).await
    }

    async fn fanout(&self, cmd: SessionCommand) -> Result<(), DaemonError> {
        self.dispatch(cmd, None).await
    }

    // Snapshot channels without holding the lock across acceptance waits.
    async fn dispatch(
        &self,
        cmd: SessionCommand,
        target: Option<dlep_ext::SessionId>,
    ) -> Result<(), DaemonError> {
        let senders: Vec<_> = {
            let mut guard = self.session_cmds.lock().await;
            guard.retain(|tx| !tx.is_closed());
            guard.clone()
        };
        crate::runtime::dispatch_command(senders, cmd, target).await
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
        for session in cmds {
            let _ = session
                .tx
                .send(
                    SessionCommand::Shutdown {
                        reason: StatusCode::SHUTTING_DOWN,
                    }
                    .into(),
                )
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
    extensions: crate::ExtensionCatalog,
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

    /// Replace the ordered startup recipes with an application catalog.
    pub fn extension_catalog(mut self, catalog: crate::ExtensionCatalog) -> Self {
        self.extensions = catalog;
        self
    }

    /// Construct a plugin from `[extensions.NAME]` before networking starts.
    pub fn register_extension_factory(
        mut self,
        name: impl Into<String>,
        create: impl Fn(&crate::ExtensionConfig) -> Result<Arc<dyn DlepExtension>, String>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        self.extensions.register_factory(name, create);
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
        dlep_net::gtsm::validate_tcp_enforcement(cfg.shared.network.gtsm_enforce)?;
        let extensions = self
            .extensions
            .build(&cfg.shared.extensions)
            .map_err(|error| DaemonError::Config(error.to_string()))?;
        let destination_policy = cfg
            .destinations
            .policy(cfg.shared.network.mac_address_format)
            .map_err(DaemonError::Config)?;
        cfg.shared
            .timers
            .validate()
            .map_err(|e| DaemonError::Config(format!("invalid timers: {e}")))?;
        cfg.shared
            .network
            .validate_discovery_interface()
            .map_err(|e| DaemonError::Config(e.to_string()))?;
        cfg.limits.validate().map_err(DaemonError::Config)?;
        let connections = ConnectionRegistry::new(cfg.limits.clone(), &cfg.static_peers);
        let reaper = connections.reap_periodically();
        let (events_tx, _events_rx) = new_event_channel();
        Ok(RouterDaemon {
            destination_policy,
            events_tx,
            state: crate::state::StateRegistry::new(),
            connections,
            session_slots: Arc::new(tokio::sync::Semaphore::new(cfg.limits.max_sessions)),
            _history_reaper: reaper,
            timers: cfg.shared.timers.clone(),
            network: cfg.shared.network.clone(),
            session_cmds: Arc::new(Mutex::new(Vec::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            discovery_shutdown: Mutex::new(None),
            discovery_task: Mutex::new(None),
            session_id_counter: new_session_id_counter(),
            peer_description: cfg.peer_description.clone(),
            client_tls: self.client_tls,
            extensions,
        })
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use std::time::Duration;
    use tokio::{io::AsyncReadExt, net::TcpListener, time::timeout};

    async fn router() -> RouterDaemon {
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.discovery_port = 0;
        RouterDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn named_peer_budget_releases_on_cancellation_and_invalid_input() {
        use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_dns};
        let mut config = RouterConfig::default();
        config.limits.max_sessions = 1;
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .with_rustls_client(client_config_for(self_signed_for_dns("localhost").roots))
                .spawn()
                .await
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        let connecting = daemon.clone();
        // A literal avoids resolver-family ordering delaying this cancellation
        // barrier. Named DNS fallback is exercised by the transport tests.
        let task =
            tokio::spawn(async move { connecting.connect_named("127.0.0.1", addr.port()).await });
        let (_peer, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(daemon.connection_capacity(), 0);
        assert!(matches!(
            daemon.connect_named("localhost", addr.port()).await,
            Err(DaemonError::SessionLimitReached)
        ));
        assert!(matches!(
            daemon.connect_static(addr).await,
            Err(DaemonError::SessionLimitReached)
        ));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(daemon.connection_capacity(), 1);
        for name in [
            "",
            "https://localhost",
            "localhost:854",
            "[::1]",
            "bad name",
        ] {
            assert!(
                matches!(daemon.connect_named(name, addr.port()).await, Err(DaemonError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
            );
            assert!(matches!(
                daemon.connect_static_with_server_name(addr, name).await,
                Err(DaemonError::Config(_))
            ));
            assert_eq!(daemon.connection_capacity(), 1);
        }
        assert!(daemon.connection_states().borrow().is_empty());
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn session_limit_refuses_connections_and_abort_reclaims_the_slot() {
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.limits.max_sessions = 1;
        let daemon = RouterDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        daemon.connect_static(addr).await.unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        assert!(matches!(
            daemon.connect_static(addr).await,
            Err(DaemonError::SessionLimitReached)
        ));
        assert_eq!(daemon.connection_capacity(), 0);
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
        let task = daemon.tasks.lock().await.pop().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        timeout(
            Duration::from_secs(1),
            daemon.wait_for_connection_capacity(),
        )
        .await
        .unwrap();
        daemon.connect_static(addr).await.unwrap();
        let (_replacement, _) = listener.accept().await.unwrap();
        assert_eq!(
            daemon.connection_states().borrow()[&addr].active_sessions,
            1
        );
        let task = daemon.tasks.lock().await.pop().unwrap();
        task.abort();
        let _ = task.await;
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn budget_covers_stalled_tls_and_releases_on_cancellation_and_connect_error() {
        use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_ip};
        let mut config = RouterConfig::default();
        config.limits.max_sessions = 1;
        let pki = self_signed_for_ip("127.0.0.1".parse().unwrap());
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .with_rustls_client(client_config_for(pki.roots))
                .spawn()
                .await
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        let connecting = daemon.clone();
        let task = tokio::spawn(async move { connecting.connect_static(addr).await });
        let (_peer, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            daemon.connect_static(addr).await,
            Err(DaemonError::SessionLimitReached)
        ));
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(daemon.connection_capacity(), 1);
        assert!(daemon.connection_states().borrow().is_empty());
        drop(listener);
        assert!(daemon.connect_static(addr).await.is_err());
        assert_eq!(daemon.connection_capacity(), 1);
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_session_updates_state_even_when_broadcast_lags() {
        let daemon = router().await;
        let mut events = daemon.subscribe();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        daemon.connect_static(addr).await.unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        // Registration is visible before the session's first poll.
        assert_eq!(
            daemon.connection_states().borrow()[&addr].active_sessions,
            1
        );
        let task = daemon.tasks.lock().await.pop().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        for _ in 0..=crate::runtime::EVENT_CHANNEL_CAPACITY {
            daemon
                .events_tx
                .send(crate::DaemonEvent::Extension(Arc::new(())))
                .unwrap();
        }
        assert!(matches!(
            events.recv().await,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_))
        ));
        // A late subscriber sees the terminal state without any event replay.
        let states = daemon.connection_states();
        assert_eq!(states.borrow()[&addr], PeerConnectionState::default());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_established_session_removes_protocol_snapshot_before_down_event() {
        let daemon = router().await;
        let mut config = crate::ModemConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let modem = crate::ModemDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap();
        let mut events = daemon.subscribe();
        daemon.connect_static(modem.local_addr()).await.unwrap();
        let session_id = timeout(Duration::from_secs(3), async {
            loop {
                if let crate::DaemonEvent::SessionUp { session_id, .. } =
                    events.recv().await.unwrap()
                {
                    break session_id;
                }
            }
        })
        .await
        .unwrap();
        let before = daemon.state().borrow().clone();
        assert!(before.sessions.contains_key(&session_id));
        let task = daemon.tasks.lock().await.pop().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        timeout(Duration::from_secs(3), async {
            loop {
                if let crate::DaemonEvent::SessionDown { .. } = events.recv().await.unwrap() {
                    assert!(daemon.state().borrow().sessions.is_empty());
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert!(daemon.state().borrow().generation > before.generation);
        daemon.shutdown().await.unwrap();
        modem.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_connection_never_leaves_an_unregistered_session() {
        let daemon = router().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let held = daemon.tasks.lock().await;
        let (result, accepted) = tokio::join!(
            timeout(
                Duration::from_millis(100),
                daemon.connect_static(listener.local_addr().unwrap())
            ),
            timeout(Duration::from_secs(2), listener.accept()),
        );
        assert!(
            result.is_err(),
            "connection must wait for registration lock"
        );
        let (mut peer, _) = accepted.unwrap().unwrap();
        // Cancelling before registration closes the transport without starting
        // a DLEP session that shutdown could not join.
        assert_eq!(
            timeout(Duration::from_secs(2), peer.read(&mut [0; 1]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(held);
        assert!(daemon.session_cmds.lock().await.is_empty());
        assert!(daemon.tasks.lock().await.is_empty());
        assert!(daemon.connection_states().borrow().is_empty());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_discovery_never_leaves_an_unregistered_task() {
        let daemon = router().await;
        let held = daemon.discovery_task.lock().await;
        assert!(
            timeout(Duration::from_millis(30), daemon.start_discovery())
                .await
                .is_err()
        );
        drop(held);
        assert!(daemon.discovery_shutdown.lock().await.is_none());
        assert!(daemon.discovery_task.lock().await.is_none());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stopped_discovery_can_be_restarted() {
        let daemon = router().await;
        daemon.start_discovery().await.unwrap();
        assert!(matches!(
            daemon.start_discovery().await,
            Err(DaemonError::Config(message)) if message.contains("already running")
        ));
        // Simulate an unexpected stop of the running discovery task.
        daemon.discovery_task.lock().await.as_ref().unwrap().abort();
        timeout(Duration::from_secs(2), async {
            while !daemon
                .discovery_task
                .lock()
                .await
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        daemon.start_discovery().await.unwrap();
        assert!(
            !daemon
                .discovery_task
                .lock()
                .await
                .as_ref()
                .unwrap()
                .is_finished()
        );
        daemon.shutdown().await.unwrap();
    }
}
