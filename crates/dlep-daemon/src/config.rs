use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use dlep_core::{DEFAULT_PORT, DISCOVERY_IPV4_GROUP, DISCOVERY_IPV6_GROUP};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Discovery interface name. Selects IPv4 membership, egress, and ingress.
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

impl NetworkConfig {
    pub(crate) fn discovery_interface(&self) -> dlep_net::addr::InterfaceSpec {
        self.interface
            .as_ref()
            .map_or(dlep_net::addr::InterfaceSpec::Any, |name| {
                dlep_net::addr::InterfaceSpec::ByName(name.clone())
            })
    }

    /// Validate an explicit interface without opening a privileged socket.
    /// IPv6 discovery is not implemented yet.
    pub fn validate_discovery_interface(&self) -> std::io::Result<()> {
        if self.interface.is_some() {
            let IpAddr::V4(preferred) = self.bind_addr else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "IPv4 discovery requires an IPv4 bind_addr",
                ));
            };
            self.discovery_interface().resolve_v4(preferred)?;
        }
        Ok(())
    }
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
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub ca_bundle: Option<PathBuf>,
    #[serde(default)]
    pub require_client_cert: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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

/// Initial session-wide modem metrics. Rates are bits/second, latency is
/// microseconds, resource/link quality values are percentages, and MTU is bytes.
/// Omitted optional values declare that metric unsupported for the session.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub max_data_rate_rx_bps: u64,
    pub max_data_rate_tx_bps: u64,
    pub current_data_rate_rx_bps: u64,
    pub current_data_rate_tx_bps: u64,
    pub latency_us: u64,
    pub resources: Option<u8>,
    pub rlq_rx: Option<u8>,
    pub rlq_tx: Option<u8>,
    pub mtu: Option<u16>,
}

impl MetricsConfig {
    pub fn link_metrics(&self) -> dlep_core::LinkMetrics {
        dlep_core::LinkMetrics {
            max_data_rate_rx_bps: self.max_data_rate_rx_bps,
            max_data_rate_tx_bps: self.max_data_rate_tx_bps,
            current_data_rate_rx_bps: self.current_data_rate_rx_bps,
            current_data_rate_tx_bps: self.current_data_rate_tx_bps,
            latency: std::time::Duration::from_micros(self.latency_us),
            resources: self.resources,
            rlq_rx: self.rlq_rx,
            rlq_tx: self.rlq_tx,
            mtu: self.mtu,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.current_data_rate_rx_bps > self.max_data_rate_rx_bps
            || self.current_data_rate_tx_bps > self.max_data_rate_tx_bps
        {
            return Err("current data rate must not exceed maximum data rate".into());
        }
        dlep_fsm::session_common::build_session_update(&self.link_metrics())
            .encode()
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ModemConfig {
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(flatten)]
    pub shared: SharedConfig,
    #[serde(default = "default_modem_peer_description")]
    pub peer_description: String,
}

impl Default for ModemConfig {
    fn default() -> Self {
        Self {
            metrics: MetricsConfig::default(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_network_section_uses_defaults() {
        let cfg: RouterConfig = toml::from_str(
            r#"
            [network]
            use_tls = false
            "#,
        )
        .expect("partial [network] section must parse");
        assert!(!cfg.shared.network.use_tls);
        assert_eq!(cfg.shared.network.tcp_port, DEFAULT_PORT);
        assert_eq!(cfg.shared.network.discovery_v4_group, DISCOVERY_IPV4_GROUP);
    }

    #[test]
    fn empty_config_parses_to_defaults() {
        let router: RouterConfig = toml::from_str("").expect("empty router config");
        assert!(router.shared.network.use_tls);
        assert!(matches!(router.mode, DiscoveryMode::Discovery));
        let modem: ModemConfig = toml::from_str("").expect("empty modem config");
        assert_eq!(modem.peer_description, "dlep-modem");
    }

    #[test]
    fn removed_transaction_timeout_is_rejected() {
        let error =
            toml::from_str::<RouterConfig>("[timers]\nlink_characteristics_timeout_ms = 60000\n")
                .expect_err("transaction deadlines are not supported");
        assert!(
            error
                .to_string()
                .contains("link_characteristics_timeout_ms")
        );
    }

    #[test]
    fn typo_inside_section_is_rejected() {
        let err = toml::from_str::<RouterConfig>(
            r#"
            [network]
            bind_adddr = "0.0.0.0"
            "#,
        )
        .expect_err("typo'd key inside [network] must be rejected");
        assert!(err.to_string().contains("bind_adddr"), "got: {err}");
    }
}
