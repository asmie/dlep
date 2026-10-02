use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use dlep_core::{DEFAULT_PORT, DISCOVERY_IPV4_GROUP, DISCOVERY_IPV6_GROUP};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Fixed destination MAC format; must match the modem's router-facing link.
    #[serde(with = "MacAddressFormatDef")]
    pub mac_address_format: dlep_core::MacAddressFormat,
    /// Discovery interface name. Selects discovery membership, egress, and ingress.
    pub interface: Option<String>,
    pub discovery_v4_group: Ipv4Addr,
    pub discovery_v6_group: Ipv6Addr,
    /// Modem discovery listen port and router multicast destination port.
    /// Router discovery sockets bind an ephemeral local port.
    pub discovery_port: u16,
    /// Modem TCP listener port. Routers use offered/static endpoint ports.
    pub tcp_port: u16,
    /// Address the modem's TCP listener binds to; its family also selects
    /// discovery transport for both roles. Defaults to `0.0.0.0`
    /// (all interfaces); tests pin this to `127.0.0.1` so they don't rely on
    /// the OS-specific behaviour of `connect("0.0.0.0:N")`.
    #[serde(default = "default_bind_addr")]
    pub bind_addr: IpAddr,
    pub use_tls: bool,
    #[serde(default = "default_gtsm_enforce")]
    pub gtsm_enforce: bool,
}

// Keep serde out of the protocol's core types/dependencies.
#[derive(Deserialize, Serialize)]
#[serde(remote = "dlep_core::MacAddressFormat", rename_all = "lowercase")]
enum MacAddressFormatDef {
    Eui48,
    Eui64,
}

impl NetworkConfig {
    pub(crate) fn discovery_interface(&self) -> dlep_net::addr::InterfaceSpec {
        self.interface
            .as_ref()
            .map_or(dlep_net::addr::InterfaceSpec::Any, |name| {
                dlep_net::addr::InterfaceSpec::ByName(name.clone())
            })
    }

    /// Validate interface selection and IPv6 scope without opening a socket.
    pub fn validate_discovery_interface(&self) -> std::io::Result<()> {
        match self.bind_addr {
            IpAddr::V4(preferred) if self.interface.is_some() => {
                self.discovery_interface().resolve_v4(preferred)?;
            }
            IpAddr::V6(preferred) => {
                self.discovery_interface().resolve_v6(preferred)?;
            }
            _ => {}
        }
        Ok(())
    }
    /// Create discovery for the configured family. Routers use an ephemeral
    /// port and receive unicast offers; only modems join the multicast group.
    pub(crate) fn bind_discovery(
        &self,
        modem: bool,
    ) -> std::io::Result<dlep_net::discovery::DiscoverySocket> {
        use dlep_net::discovery::{DiscoveryParams, DiscoveryParamsV6, DiscoverySocket};
        let port = if modem { self.discovery_port } else { 0 };
        match self.bind_addr {
            IpAddr::V4(local) => DiscoverySocket::bind_on_interface(
                &DiscoveryParams {
                    group_v4: self.discovery_v4_group,
                    interface_v4: local,
                    port,
                    group_port: Some(self.discovery_port),
                    multicast_loop: true,
                    join_group: modem,
                },
                &self.discovery_interface(),
            ),
            IpAddr::V6(local) => DiscoverySocket::bind_v6(
                &DiscoveryParamsV6 {
                    group: self.discovery_v6_group,
                    local_address: local,
                    port,
                    group_port: Some(self.discovery_port),
                    multicast_loop: true,
                    join_group: modem,
                },
                &self.discovery_interface(),
            ),
        }
    }

    pub(crate) fn tcp_bind_addr(&self) -> std::io::Result<SocketAddr> {
        let mut addr = SocketAddr::new(self.bind_addr, self.tcp_port);
        if let SocketAddr::V6(ref mut v6) = addr {
            if v6.ip().is_unicast_link_local() {
                v6.set_scope_id(self.discovery_interface().resolve_v6(*v6.ip())?.index);
            }
        }
        Ok(addr)
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
            mac_address_format: Default::default(),
            interface: None,
            discovery_v4_group: DISCOVERY_IPV4_GROUP,
            discovery_v6_group: DISCOVERY_IPV6_GROUP,
            discovery_port: DEFAULT_PORT,
            tcp_port: DEFAULT_PORT,
            bind_addr: default_bind_addr(),
            // TLS on by default (see RFC 8175 §14 security considerations). Embedders
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
    /// At least 1000 ms (RFC 8175 §7.3.1).
    #[serde(default = "default_heartbeat_interval_ms")]
    pub heartbeat_interval_ms: u32,
    /// At least 1000 ms (RFC 8175 §7.1).
    #[serde(default = "default_discovery_interval_ms")]
    pub discovery_interval_ms: u32,
    /// Deadline waiting for Session Initialization Response after Session
    /// Initialization is sent (router) or Session Initialization is awaited
    /// (modem).
    #[serde(default = "default_session_init_timeout_ms")]
    pub session_init_timeout_ms: u32,
    /// Deadline waiting for Session Termination Response after our Session
    /// Termination is sent. Omit to use four local heartbeat intervals
    /// (RFC 8175 §7.4). An explicit override must be positive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub termination_timeout_ms: Option<u32>,
}

impl TimersConfig {
    /// Reject values that would disable failure detection or flood discovery.
    /// Called for both file checks and programmatically configured daemons.
    pub fn validate(&self) -> Result<(), String> {
        for (name, value, minimum) in [
            ("heartbeat_interval_ms", self.heartbeat_interval_ms, 1_000),
            ("discovery_interval_ms", self.discovery_interval_ms, 1_000),
            ("session_init_timeout_ms", self.session_init_timeout_ms, 1),
        ] {
            if value < minimum {
                return Err(format!(
                    "timers.{name} must be at least {minimum} ms (got {value})"
                ));
            }
        }
        if self.termination_timeout_ms == Some(0) {
            return Err("timers.termination_timeout_ms must be at least 1 ms (got 0)".into());
        }
        Ok(())
    }
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

impl Default for TimersConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: default_heartbeat_interval_ms(),
            discovery_interval_ms: default_discovery_interval_ms(),
            session_init_timeout_ms: default_session_init_timeout_ms(),
            termination_timeout_ms: None,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
#[serde(from = "RouterConfigFile")]
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
#[serde(from = "ModemConfigFile")]
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

// Serde's deny_unknown_fields does not support flattened structs. Deserialize
// a strict, flat file schema while preserving the public `shared` layout and
// the existing flattened serialization format.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouterConfigFile {
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    tls: TlsConfig,
    #[serde(default)]
    timers: TimersConfig,
    #[serde(default)]
    mode: DiscoveryMode,
    #[serde(default)]
    static_peers: Vec<SocketAddr>,
    #[serde(default = "default_router_peer_description")]
    peer_description: String,
}

impl From<RouterConfigFile> for RouterConfig {
    fn from(file: RouterConfigFile) -> Self {
        Self {
            shared: SharedConfig {
                network: file.network,
                tls: file.tls,
                timers: file.timers,
            },
            mode: file.mode,
            static_peers: file.static_peers,
            peer_description: file.peer_description,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModemConfigFile {
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    tls: TlsConfig,
    #[serde(default)]
    timers: TimersConfig,
    #[serde(default)]
    metrics: MetricsConfig,
    #[serde(default = "default_modem_peer_description")]
    peer_description: String,
}

impl From<ModemConfigFile> for ModemConfig {
    fn from(file: ModemConfigFile) -> Self {
        Self {
            shared: SharedConfig {
                network: file.network,
                tls: file.tls,
                timers: file.timers,
            },
            metrics: file.metrics,
            peer_description: file.peer_description,
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
    fn mac_format_defaults_roundtrips_and_rejects_unknown_values() {
        use dlep_core::MacAddressFormat as F;
        assert_eq!(
            RouterConfig::default().shared.network.mac_address_format,
            F::Eui48
        );
        assert_eq!(
            ModemConfig::default().shared.network.mac_address_format,
            F::Eui48
        );
        for (name, format) in [("eui48", F::Eui48), ("eui64", F::Eui64)] {
            let input = format!("[network]\nmac_address_format = '{name}'");
            let r: RouterConfig = toml::from_str(&input).unwrap();
            let m: ModemConfig = toml::from_str(&input).unwrap();
            assert_eq!(r.shared.network.mac_address_format, format);
            assert_eq!(m.shared.network.mac_address_format, format);
            let r: RouterConfig = toml::from_str(&toml::to_string(&r).unwrap()).unwrap();
            let m: ModemConfig = toml::from_str(&toml::to_string(&m).unwrap()).unwrap();
            assert_eq!(r.shared.network.mac_address_format, format);
            assert_eq!(m.shared.network.mac_address_format, format);
        }
        for input in ["'auto'", "'eui46'", "48"] {
            let input = format!("[network]\nmac_address_format = {input}");
            assert!(toml::from_str::<RouterConfig>(&input).is_err());
            assert!(toml::from_str::<ModemConfig>(&input).is_err());
        }
    }

    #[test]
    fn unknown_top_level_keys_and_sections_are_rejected() {
        for (text, unknown) in [
            ("peer_descripton = 'typo'", "peer_descripton"),
            ("[netwrok]\nuse_tls = false", "netwrok"),
            ("[timer]", "timer"),
            ("[shared.network]\nuse_tls = false", "shared"),
        ] {
            for error in [
                toml::from_str::<RouterConfig>(text).unwrap_err(),
                toml::from_str::<ModemConfig>(text).unwrap_err(),
            ] {
                assert!(error.to_string().contains(unknown), "{error}");
            }
        }
    }

    #[test]
    fn settings_for_the_wrong_role_are_rejected() {
        assert!(toml::from_str::<RouterConfig>("[metrics]\nlatency_us = 10").is_err());
        assert!(toml::from_str::<ModemConfig>("mode = 'static'").is_err());
        assert!(toml::from_str::<ModemConfig>("static_peers = ['127.0.0.1:854']").is_err());
    }

    #[test]
    fn strict_file_schema_preserves_examples_and_serialized_values() {
        fn preserves_supplied_values(actual: &toml::Value, supplied: &toml::Value) {
            if let toml::Value::Table(fields) = supplied {
                for (name, value) in fields {
                    preserves_supplied_values(&actual[name], value);
                }
            } else {
                assert_eq!(actual, supplied);
            }
        }
        fn roundtrip<T: serde::de::DeserializeOwned + Serialize>(text: &str) {
            let config: T = toml::from_str(text).unwrap();
            let serialized = toml::to_string(&config).unwrap();
            preserves_supplied_values(
                &toml::from_str::<toml::Value>(&serialized).unwrap(),
                &toml::from_str::<toml::Value>(text).unwrap(),
            );
            let decoded: T = toml::from_str(&serialized).unwrap();
            assert_eq!(toml::to_string(&decoded).unwrap(), serialized);
        }
        roundtrip::<RouterConfig>(include_str!("../../../examples/router.toml"));
        roundtrip::<ModemConfig>(include_str!("../../../examples/modem.toml"));
        roundtrip::<RouterConfig>(
            "mode = 'static'\nstatic_peers = ['[::1]:854']\npeer_description = 'router ü'\n[network]\nbind_addr = '::1'\n[timers]\nheartbeat_interval_ms = 2000\n[tls]\nrequire_client_cert = true",
        );
        roundtrip::<ModemConfig>(
            "peer_description = 'modem ü'\n[network]\ntcp_port = 9999\n[timers]\ndiscovery_interval_ms = 3000\n[metrics]\nresources = 0\nmtu = 1500\n[tls]\ncert = 'modem.pem'",
        );
    }

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
