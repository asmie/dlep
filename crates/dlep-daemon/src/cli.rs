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
    #[error("invalid timers: {0}")]
    Timers(String),
    #[error("invalid discovery interface: {0}")]
    Interface(#[source] std::io::Error),
    #[error("invalid modem metrics: {0}")]
    Metrics(String),
    #[error(transparent)]
    Tls(#[from] TlsSetupError),
    #[error("mode = \"static\" requires at least one entry in static_peers")]
    StaticModeWithoutPeers,
}

/// Validate a router configuration without starting the daemon: TLS
/// material must load when `use_tls` is on, and static mode needs peers.
pub fn check_router_config(cfg: &RouterConfig) -> Result<(), ConfigCheckError> {
    cfg.shared
        .timers
        .validate()
        .map_err(ConfigCheckError::Timers)?;
    cfg.shared
        .network
        .validate_discovery_interface()
        .map_err(ConfigCheckError::Interface)?;
    if matches!(cfg.mode, DiscoveryMode::Static) && cfg.static_peers.is_empty() {
        return Err(ConfigCheckError::StaticModeWithoutPeers);
    }
    if cfg.shared.network.use_tls {
        client_config(&cfg.shared.tls)?;
    }
    Ok(())
}

/// Validate a modem configuration without starting the daemon.
pub fn check_modem_config(cfg: &ModemConfig) -> Result<(), ConfigCheckError> {
    cfg.shared
        .timers
        .validate()
        .map_err(ConfigCheckError::Timers)?;
    cfg.shared
        .network
        .validate_discovery_interface()
        .map_err(ConfigCheckError::Interface)?;
    cfg.metrics.validate().map_err(ConfigCheckError::Metrics)?;
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
