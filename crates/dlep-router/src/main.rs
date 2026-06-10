use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{
    DaemonEvent, DiscoveryMode, RouterConfig, RouterDaemon, check_router_config, load_toml_config,
};
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tracing_subscriber::EnvFilter;

/// DLEP (RFC 8175) router-side daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long, short = 'c', env = "DLEP_ROUTER_CONFIG")]
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

    /// PEM bundle of CA certificates used to verify the modem
    /// (overrides [tls] ca_bundle).
    #[arg(long, value_name = "PATH")]
    ca_bundle: Option<PathBuf>,

    /// PEM client certificate presented to the modem for mutual TLS
    /// (overrides [tls] cert).
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key for --cert (overrides [tls] key).
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Modem address to connect to directly instead of multicast
    /// discovery. Repeatable; implies mode = "static".
    #[arg(long, value_name = "ADDR")]
    peer: Vec<SocketAddr>,

    /// Validate the configuration (including TLS material) and exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let mut config: RouterConfig =
        load_toml_config(cli.config.as_deref()).context("loading router configuration")?;
    apply_overrides(&mut config, &cli);

    if cli.check_config {
        check_router_config(&config).context("configuration check failed")?;
        println!("configuration OK");
        return Ok(());
    }

    tracing::info!(
        interface = ?config.shared.network.interface,
        tls = config.shared.network.use_tls,
        mode = ?config.mode,
        "starting dlep-router"
    );

    let tls = if config.shared.network.use_tls {
        Some(
            dlep_daemon::tls::client_config(&config.shared.tls)
                .context("building TLS client configuration")?,
        )
    } else {
        None
    };

    let mode = config.mode.clone();
    let static_peers = config.static_peers.clone();

    let mut builder = RouterDaemon::builder().config(config);
    if let Some(tls) = tls {
        builder = builder.with_rustls_client(tls);
    }
    let daemon = builder
        .spawn()
        .await
        .context("failed to start router daemon")?;
    let mut events = daemon.subscribe();

    match mode {
        DiscoveryMode::Static => {
            for peer in &static_peers {
                daemon
                    .connect_static(*peer)
                    .await
                    .with_context(|| format!("connecting to static peer {peer}"))?;
            }
        }
        DiscoveryMode::Discovery => {
            daemon
                .start_discovery()
                .await
                .context("starting discovery")?;
        }
    }

    run_event_loop(&daemon, &mut events).await;

    tracing::info!("shutdown requested");
    daemon.shutdown().await?;
    Ok(())
}

/// Drive the daemon until Ctrl-C: connect to modems as discovery finds
/// them (deduplicated by address) and log session lifecycle.
async fn run_event_loop(daemon: &RouterDaemon, events: &mut Receiver<DaemonEvent>) {
    let mut connected: HashSet<SocketAddr> = HashSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            evt = events.recv() => match evt {
                Ok(DaemonEvent::PeerDiscovered(peer)) => {
                    if !connected.insert(peer.addr) {
                        continue;
                    }
                    tracing::info!(addr = %peer.addr, "modem discovered; connecting");
                    if let Err(e) = daemon.connect_static(peer.addr).await {
                        tracing::warn!(addr = %peer.addr, "connect failed: {e}");
                        connected.remove(&peer.addr);
                    }
                }
                Ok(DaemonEvent::SessionUp { peer, .. }) => {
                    tracing::info!(addr = %peer.addr, tls = peer.is_tls, "session up");
                }
                Ok(DaemonEvent::SessionDown { reason }) => {
                    tracing::info!(?reason, "session down");
                }
                Ok(_) => {}
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "event stream lagged");
                }
                Err(RecvError::Closed) => return,
            },
        }
    }
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

fn apply_overrides(cfg: &mut RouterConfig, cli: &Cli) {
    if let Some(iface) = &cli.interface {
        cfg.shared.network.interface = Some(iface.clone());
    }
    if cli.no_tls {
        cfg.shared.network.use_tls = false;
    }
    if let Some(path) = &cli.ca_bundle {
        cfg.shared.tls.ca_bundle = Some(path.clone());
    }
    if let Some(path) = &cli.cert {
        cfg.shared.tls.cert = Some(path.clone());
    }
    if let Some(path) = &cli.key {
        cfg.shared.tls.key = Some(path.clone());
    }
    if !cli.peer.is_empty() {
        cfg.mode = DiscoveryMode::Static;
        cfg.static_peers.extend(cli.peer.iter().copied());
    }
}
