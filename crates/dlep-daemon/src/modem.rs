use std::sync::Arc;

use dlep_core::{MacAddress, StatusCode};
use dlep_ext::{DlepExtension, ExtensionRegistry};
use dlep_net::ServerConfig;
use tokio::task::JoinHandle;

use crate::config::ModemConfig;
use crate::events::{DestinationId, LinkMetrics};
use crate::runtime::{DaemonError, EventRx, EventTx, new_event_channel};

pub struct ModemDaemon {
    events_tx: EventTx,
    _tasks: Vec<JoinHandle<()>>,
}

impl ModemDaemon {
    pub fn builder() -> ModemBuilder {
        ModemBuilder::default()
    }

    pub fn subscribe(&self) -> EventRx {
        self.events_tx.subscribe()
    }

    pub async fn add_destination(
        &self,
        id: DestinationId,
        metrics: LinkMetrics,
    ) -> Result<(), DaemonError> {
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
        let _cfg = self
            .config
            .ok_or_else(|| DaemonError::Config("ModemConfig required".into()))?;
        let (events_tx, _events_rx) = new_event_channel();
        Ok(ModemDaemon {
            events_tx,
            _tasks: Vec::new(),
        })
    }
}
