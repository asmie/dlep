use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{load_toml_config, ModemConfig, ModemDaemon};
use tracing_subscriber::EnvFilter;

/// DLEP (RFC 8175) modem-side daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long, short = 'c', env = "DLEP_MODEM_CONFIG")]
    config: Option<PathBuf>,

    /// Override the network interface used for discovery.
    #[arg(long)]
    interface: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, env = "DLEP_LOG", default_value = "info")]
    log_level: String,

    /// Disable TLS — development only.
    #[arg(long)]
    no_tls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let mut config: ModemConfig =
        load_toml_config(cli.config.as_deref()).context("loading modem configuration")?;
    apply_overrides(&mut config, cli.interface, cli.no_tls);

    tracing::info!(
        peer = %config.peer_description,
        tls = config.shared.network.use_tls,
        "starting dlep-modem"
    );

    let daemon = ModemDaemon::builder()
        .config(config)
        .spawn()
        .await
        .context("failed to start modem daemon")?;

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown requested");
    daemon.shutdown().await?;
    Ok(())
}

fn init_tracing(requested: &str) {
    let filter = match EnvFilter::try_new(requested) {
        Ok(f) => f,
        Err(err) => {
            eprintln!(
                "warning: invalid log level {requested:?} ({err}); falling back to 'info'"
            );
            EnvFilter::new("info")
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn apply_overrides(cfg: &mut ModemConfig, interface: Option<String>, no_tls: bool) {
    if let Some(iface) = interface {
        cfg.shared.network.interface = Some(iface);
    }
    if no_tls {
        cfg.shared.network.use_tls = false;
    }
}
