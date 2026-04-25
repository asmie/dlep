use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use dlep_core::{DEFAULT_PORT, DISCOVERY_IPV4_GROUP, DISCOVERY_IPV6_GROUP};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkConfig {
    pub interface: Option<String>,
    pub discovery_v4_group: Ipv4Addr,
    pub discovery_v6_group: Ipv6Addr,
    pub discovery_port: u16,
    pub tcp_port: u16,
    pub use_tls: bool,
    #[serde(default = "default_gtsm_enforce")]
    pub gtsm_enforce: bool,
}

fn default_gtsm_enforce() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            interface: None,
            discovery_v4_group: DISCOVERY_IPV4_GROUP,
            discovery_v6_group: DISCOVERY_IPV6_GROUP,
            discovery_port: DEFAULT_PORT,
            tcp_port: DEFAULT_PORT,
            // Defaults to false until the TLS path is wired end-to-end.
            // Flip to `true` (matching the RFC recommendation) once rustls
            // Connector/Acceptor leave the stub stage.
            use_tls: false,
            gtsm_enforce: true,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca_bundle: Option<PathBuf>,
    #[serde(default)]
    pub require_client_cert: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TimersConfig {
    pub heartbeat_interval_ms: u32,
    pub discovery_interval_ms: u32,
}

impl Default for TimersConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 60_000,
            discovery_interval_ms: 5_000,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SharedConfig {
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub timers: TimersConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DiscoveryMode {
    #[default]
    Discovery,
    Static,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct RouterConfig {
    #[serde(flatten)]
    pub shared: SharedConfig,
    #[serde(default)]
    pub mode: DiscoveryMode,
    #[serde(default)]
    pub static_peers: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ModemConfig {
    #[serde(flatten)]
    pub shared: SharedConfig,
    #[serde(default = "default_peer_description")]
    pub peer_description: String,
}

fn default_peer_description() -> String {
    "dlep-modem".into()
}
