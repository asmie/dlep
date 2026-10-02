use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{ModemConfig, ModemDaemon, check_modem_config, load_toml_config};
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

    /// PEM server certificate presented to routers (overrides tls.cert).
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key for --cert (overrides tls.key).
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// PEM bundle of CA certificates used to verify router client
    /// certificates when require_client_cert is set
    /// (overrides tls.ca_bundle).
    #[arg(long, value_name = "PATH")]
    ca_bundle: Option<PathBuf>,

    /// Validate the configuration (including TLS material) and exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let mut config: ModemConfig =
        load_toml_config(cli.config.as_deref()).context("loading modem configuration")?;
    apply_overrides(&mut config, &cli);

    if cli.check_config {
        check_modem_config(&config).context("configuration check failed")?;
        println!("configuration OK");
        return Ok(());
    }

    let mut shutdown =
        dlep_daemon::shutdown::ShutdownSignals::new().context("registering shutdown signals")?;

    tracing::info!(
        peer = %config.peer_description,
        tls = config.shared.network.use_tls,
        interface = ?config.shared.network.interface,
        port = config.shared.network.tcp_port,
        "starting dlep-modem"
    );

    let tls = if config.shared.network.use_tls {
        Some(
            dlep_daemon::tls::server_config(&config.shared.tls)
                .context("building TLS server configuration")?,
        )
    } else {
        None
    };

    let mut builder = ModemDaemon::builder().config(config);
    if let Some(tls) = tls {
        builder = builder.with_rustls_server(tls);
    }
    let daemon = builder
        .spawn()
        .await
        .context("failed to start modem daemon")?;
    tracing::info!("modem listening on {}", daemon.local_addr());

    shutdown.recv().await;
    tracing::info!("shutdown requested");
    daemon.shutdown().await?;
    Ok(())
}

fn init_tracing(requested: &str) {
    let filter = match EnvFilter::try_new(requested) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("warning: invalid log level {requested:?} ({err}); falling back to 'info'");
            EnvFilter::new("info")
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn apply_overrides(cfg: &mut ModemConfig, cli: &Cli) {
    if let Some(iface) = &cli.interface {
        cfg.shared.network.interface = Some(iface.clone());
    }
    if cli.no_tls {
        cfg.shared.network.use_tls = false;
    }
    if let Some(path) = &cli.cert {
        cfg.shared.tls.cert = Some(path.clone());
    }
    if let Some(path) = &cli.key {
        cfg.shared.tls.key = Some(path.clone());
    }
    if let Some(path) = &cli.ca_bundle {
        cfg.shared.tls.ca_bundle = Some(path.clone());
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;

    #[test]
    fn interface_cli_overrides_config() {
        let cli = Cli::try_parse_from(["dlep-modem", "--interface", "selected0"]).unwrap();
        let mut config = ModemConfig::default();
        config.shared.network.interface = Some("configured0".into());
        apply_overrides(&mut config, &cli);
        assert_eq!(
            config.shared.network.interface.as_deref(),
            Some("selected0")
        );
    }
}
