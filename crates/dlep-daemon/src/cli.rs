//! Shared CLI helpers used by the `dlep-router` and `dlep-modem` binaries.

use std::path::Path;

use thiserror::Error;

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
