use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// Address the modem's TCP listener binds to. Defaults to `0.0.0.0`
    /// (all interfaces); tests pin this to `127.0.0.1` so they don't rely on
    /// the OS-specific behaviour of `connect("0.0.0.0:N")`.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: IpAddr,
    pub use_tls: bool,
    #[serde(default = "default_gtsm_enforce")]
    pub gtsm_enforce: bool,
}

fn default_bind_addr() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
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
            bind_addr: default_bind_addr(),
            // TLS on by default (RFC 8175 §10 recommendation). Embedders
            // that need plain TCP must override `use_tls = false` in their
            // config. Embedders that keep TLS on MUST call
            // `with_rustls_client` / `with_rustls_server` on the daemon
            // builder; spawn fails fast otherwise.
            use_tls: true,
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
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u32,
    #[serde(default = "default_discovery_interval_ms")]
    pub discovery_interval_ms: u32,
    /// Deadline waiting for Session Initialization Response after Session
    /// Initialization is sent (router) or Session Initialization is awaited
    /// (modem).
    #[serde(default = "default_session_init_timeout_ms")]
    pub session_init_timeout_ms: u32,
    /// Deadline waiting for Session Termination Response after our Session
    /// Termination is sent.
    #[serde(default = "default_termination_timeout_ms")]
    pub termination_timeout_ms: u32,
}

fn default_heartbeat_interval_ms() -> u32 {
    60_000
}
fn default_discovery_interval_ms() -> u32 {
    5_000
}
fn default_session_init_timeout_ms() -> u32 {
    5_000
}
fn default_termination_timeout_ms() -> u32 {
    1_000
}

impl Default for TimersConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            discovery_interval_ms: default_discovery_interval_ms(),
            session_init_timeout_ms: default_session_init_timeout_ms(),
            termination_timeout_ms: default_termination_timeout_ms(),
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RouterConfig {
    #[serde(flatten)]
    pub shared: SharedConfig,
    #[serde(default)]
    pub mode: DiscoveryMode,
    #[serde(default)]
    pub static_peers: Vec<SocketAddr>,
    #[serde(default = "default_router_peer_description")]
    pub peer_description: String,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            shared: SharedConfig::default(),
            mode: DiscoveryMode::default(),
            static_peers: Vec::new(),
            peer_description: default_router_peer_description(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModemConfig {
    #[serde(flatten)]
    pub shared: SharedConfig,
    #[serde(default = "default_modem_peer_description")]
    pub peer_description: String,
}

impl Default for ModemConfig {
    fn default() -> Self {
        Self {
            shared: SharedConfig::default(),
            peer_description: default_modem_peer_description(),
        }
    }
}

fn default_router_peer_description() -> String {
    "dlep-router".into()
}

fn default_modem_peer_description() -> String {
    "dlep-modem".into()
}
