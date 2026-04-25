//! Integration layer: wires codec + FSM + transport + extensions into a
//! running daemon, and exposes the public `RouterDaemon` / `ModemDaemon`
//! handles that embedders use.

#![allow(dead_code)]

pub mod cli;
pub mod config;
pub mod events;
pub mod modem;
pub mod router;
pub mod runtime;
pub mod session;

pub use cli::{load_toml_config, ConfigLoadError};
pub use config::{ModemConfig, NetworkConfig, RouterConfig, SharedConfig, TimersConfig, TlsConfig};
pub use events::{DaemonEvent, DestinationEvent, LinkMetrics, MetricsEvent, PeerInfo};
pub use modem::{ModemBuilder, ModemDaemon};
pub use router::{RouterBuilder, RouterDaemon};
