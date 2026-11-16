//! Shared CLI helpers used by the `dlep-router` and `dlep-modem` binaries.

use std::path::Path;

use thiserror::Error;

use crate::config::{DiscoveryMode, ModemConfig, RouterConfig};
use crate::tls::{TlsSetupError, client_config, server_config};

#[derive(Debug, Error)]
pub enum ConfigLoadError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

/// Load a TOML configuration file, or return `T::default()` when no path is
/// given. Shared between router and modem binaries so the read + parse
/// boilerplate lives in one place.
pub fn load_toml_config<T>(path: Option<&Path>) -> Result<T, ConfigLoadError>
where
    T: serde::de::DeserializeOwned + Default,
{
    let Some(p) = path else {
        return Ok(T::default());
    };
    let text = std::fs::read_to_string(p).map_err(|source| ConfigLoadError::Read {
        path: p.to_path_buf(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ConfigLoadError::Parse {
        path: p.to_path_buf(),
        source,
    })
}

/// Errors surfaced by `--check-config` style validation.
#[derive(Debug, Error)]
pub enum ConfigCheckError {
    #[error(transparent)]
    Extension(#[from] crate::ExtensionSetupError),
    #[error("invalid [destinations] policy: {0}")]
    DestinationPolicy(String),
    #[error("invalid router limits: {0}")]
    Limits(String),
    #[error("invalid timers: {0}")]
    Timers(String),
    #[error("invalid discovery interface: {0}")]
    Interface(#[source] std::io::Error),
    #[error("unsupported network configuration: {0}")]
    Transport(#[source] std::io::Error),
    #[error("invalid modem discovery configuration: {0}")]
    Discovery(String),
    #[error("invalid modem metrics: {0}")]
    Metrics(String),
    #[error("invalid [radio] adapter: {0}")]
    Radio(String),
    #[error("invalid [adapter] router integration: {0}")]
    RouterAdapter(String),
    #[error(transparent)]
    Tls(#[from] TlsSetupError),
    #[error("mode = \"static\" requires at least one entry in static_peers")]
    StaticModeWithoutPeers,
}

/// Validate a router configuration without starting the daemon: TLS
/// material must load when `use_tls` is on, and static mode needs peers.
pub fn check_router_config(cfg: &RouterConfig) -> Result<(), ConfigCheckError> {
    check_router_config_with_extensions(cfg, &crate::ExtensionCatalog::default())
}

/// Check router configuration with the application's named plugin factories.
/// Factories are invoked for validation; no daemon sockets or tasks are started.
pub fn check_router_config_with_extensions(
    cfg: &RouterConfig,
    catalog: &crate::ExtensionCatalog,
) -> Result<(), ConfigCheckError> {
    dlep_net::gtsm::validate_tcp_enforcement(cfg.shared.network.gtsm_enforce)
        .map_err(ConfigCheckError::Transport)?;
    catalog.build(&cfg.shared.extensions)?;
    cfg.destinations
        .policy(cfg.shared.network.mac_address_format)
        .map_err(ConfigCheckError::DestinationPolicy)?;
    if let Some(adapter) = &cfg.adapter {
        adapter
            .validate()
            .map_err(ConfigCheckError::RouterAdapter)?;
        if !adapter.command.is_file() {
            return Err(ConfigCheckError::RouterAdapter(format!(
                "command is not a file: {}",
                adapter.command.display()
            )));
        }
    }
    cfg.limits.validate().map_err(ConfigCheckError::Limits)?;
    cfg.shared
        .timers
        .validate()
        .map_err(ConfigCheckError::Timers)?;
    cfg.shared
        .network
        .validate_discovery_interface()
        .map_err(ConfigCheckError::Interface)?;
    if matches!(cfg.mode, DiscoveryMode::Static)
        && cfg.static_peers.is_empty()
        && cfg.named_peers.is_empty()
        && cfg.scoped_peers.is_empty()
    {
        return Err(ConfigCheckError::StaticModeWithoutPeers);
    }
    if cfg.shared.network.use_tls {
        client_config(&cfg.shared.tls)?;
    }
    Ok(())
}

/// Validate a modem configuration without starting the daemon.
pub fn check_modem_config(cfg: &ModemConfig) -> Result<(), ConfigCheckError> {
    check_modem_config_with_extensions(cfg, &crate::ExtensionCatalog::default())
}

/// Check modem configuration with the application's named plugin factories.
/// Factories are invoked for validation; no daemon sockets or tasks are started.
pub fn check_modem_config_with_extensions(
    cfg: &ModemConfig,
    catalog: &crate::ExtensionCatalog,
) -> Result<(), ConfigCheckError> {
    dlep_net::gtsm::validate_tcp_enforcement(cfg.shared.network.gtsm_enforce)
        .map_err(ConfigCheckError::Transport)?;
    cfg.discovery
        .validate()
        .map_err(ConfigCheckError::Discovery)?;
    catalog.build(&cfg.shared.extensions)?;
    cfg.shared
        .timers
        .validate()
        .map_err(ConfigCheckError::Timers)?;
    cfg.shared
        .network
        .validate_discovery_interface()
        .map_err(ConfigCheckError::Interface)?;
    cfg.metrics.validate().map_err(ConfigCheckError::Metrics)?;
    if let Some(radio) = &cfg.radio {
        radio.validate().map_err(ConfigCheckError::Radio)?;
        if !radio.command.is_file() {
            return Err(ConfigCheckError::Radio(format!(
                "command {} is not a file",
                radio.command.display()
            )));
        }
    }
    if cfg.shared.network.use_tls {
        server_config(&cfg.shared.tls)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DiscoveryMode, ModemConfig, NetworkConfig, RouterConfig, SharedConfig, TlsConfig,
    };
    use crate::tls::TlsSetupError;

    fn no_tls_shared() -> SharedConfig {
        SharedConfig {
            network: NetworkConfig {
                use_tls: false,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        }
    }

    #[test]
    fn static_mode_without_peers_fails_check() {
        let cfg = RouterConfig {
            shared: no_tls_shared(),
            mode: DiscoveryMode::Static,
            ..RouterConfig::default()
        };
        assert!(matches!(
            check_router_config(&cfg).unwrap_err(),
            ConfigCheckError::StaticModeWithoutPeers
        ));
    }

    #[test]
    fn no_tls_configs_pass_check() {
        let router = RouterConfig {
            shared: no_tls_shared(),
            ..RouterConfig::default()
        };
        check_router_config(&router).expect("router check");
        let modem = ModemConfig {
            shared: no_tls_shared(),
            ..ModemConfig::default()
        };
        check_modem_config(&modem).expect("modem check");
    }

    #[test]
    fn default_tls_configs_fail_without_material() {
        assert!(matches!(
            check_router_config(&RouterConfig::default()).unwrap_err(),
            ConfigCheckError::Tls(TlsSetupError::MissingCaBundle)
        ));
        assert!(matches!(
            check_modem_config(&ModemConfig::default()).unwrap_err(),
            ConfigCheckError::Tls(TlsSetupError::MissingCert)
        ));
    }

    #[test]
    fn tls_router_config_with_ca_bundle_passes_check() {
        let pki = crate::tls::tests::write_pki();
        let cfg = RouterConfig {
            shared: SharedConfig {
                tls: TlsConfig {
                    ca_bundle: Some(pki.cert.clone()),
                    ..TlsConfig::default()
                },
                ..SharedConfig::default()
            },
            ..RouterConfig::default()
        };
        check_router_config(&cfg).expect("router TLS check");
    }
}
