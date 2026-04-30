use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use dlep_core::{MacAddress, StatusCode};
use dlep_ext::{DlepExtension, ExtensionRegistry};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_net::{Acceptor, ServerConfig, TLS_NOT_IMPLEMENTED_MSG, TransportKind};
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
        // M5 wires this into the session task via SessionCommand::AddDestination.
        let _ = (id, metrics);
        Ok(())
    }

    pub async fn update_destination(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
    ) -> Result<(), DaemonError> {
        let _ = (id, metrics);
        Ok(())
    }

    pub async fn drop_destination(
        &self,
        id: DestinationId,
        reason: StatusCode,
    ) -> Result<(), DaemonError> {
        let _ = (id, reason);
        Ok(())
    }

    pub async fn announce_destination(&self, mac: MacAddress) -> Result<(), DaemonError> {
        let _ = mac;
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), DaemonError> {
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
        let _ = self.server_tls; // M7 wires this into the Acceptor.
        if cfg.shared.network.use_tls {
            return Err(io::Error::other(TLS_NOT_IMPLEMENTED_MSG).into());
        }

        let bind_addr = SocketAddr::new(cfg.shared.network.bind_addr, cfg.shared.network.tcp_port);
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;

        let acceptor = Acceptor {
            kind: TransportKind::Plain,
            listener,
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

        Ok(ModemDaemon {
            events_tx,
            local_addr,
            session_cmds,
            tasks,
            listen_task,
        })
    }
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
