use std::net::SocketAddr;
use std::sync::Arc;

use dlep_ext::{DlepExtension, ExtensionRegistry};
use dlep_net::ClientConfig;
use tokio::task::JoinHandle;

use crate::config::RouterConfig;
use crate::runtime::{DaemonError, EventRx, EventTx, new_event_channel};

/// Public router handle. Holds channel senders and background task handles.
pub struct RouterDaemon {
    events_tx: EventTx,
    _tasks: Vec<JoinHandle<()>>,
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

    pub async fn connect_static(&self, _peer: SocketAddr) -> Result<(), DaemonError> {
        // TODO (M3): spawn a session task against a static peer.
        Ok(())
    }

    pub async fn shutdown(self) -> Result<(), DaemonError> {
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
        let _cfg = self
            .config
            .ok_or_else(|| DaemonError::Config("RouterConfig required".into()))?;
        let (events_tx, _events_rx) = new_event_channel();
        Ok(RouterDaemon {
            events_tx,
            _tasks: Vec::new(),
        })
    }
}
