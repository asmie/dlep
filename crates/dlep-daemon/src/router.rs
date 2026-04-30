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

use crate::config::{RouterConfig, TimersConfig};
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
    /// Per-active-session command channels, used to fan out shutdown.
    session_cmds: Arc<Mutex<Vec<mpsc::Sender<SessionCommand>>>>,
    /// Background tasks: one per active session.
    tasks: Arc<Mutex<Vec<SessionTaskHandle>>>,
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
        // TODO (M6): flip discovery FSM to Probing and start timer.
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
            session_cmds: Arc::new(Mutex::new(Vec::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            peer_description: cfg.peer_description.clone(),
            use_tls: cfg.shared.network.use_tls,
        })
    }
}
