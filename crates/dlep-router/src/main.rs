use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

    let mut shutdown =
        dlep_daemon::shutdown::ShutdownSignals::new().context("registering shutdown signals")?;

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

    // Race the entire connection/event driver, including startup, against
    // shutdown. Inline TCP/TLS attempts must not delay signal handling.
    let result = tokio::select! {
        biased;
        _ = shutdown.recv() => Ok(()),
        result = run(&daemon, &mut events, mode, &static_peers) => result,
    };

    tracing::info!("shutdown requested");
    daemon
        .shutdown()
        .await
        .context("shutting down router daemon")?;
    result
}

async fn run(
    daemon: &RouterDaemon,
    events: &mut Receiver<DaemonEvent>,
    mode: DiscoveryMode,
    static_peers: &[SocketAddr],
) -> Result<()> {
    match mode {
        DiscoveryMode::Static => {
            anyhow::ensure!(
                !static_peers.is_empty(),
                "mode = \"static\" requires at least one entry in static_peers"
            );
            for peer in static_peers {
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

    run_event_loop(daemon, events).await;
    Ok(())
}

/// Connect to modems as discovery finds them,
/// log session lifecycle, and re-dial peers whose session dropped.
///
/// `connected` tracks addresses with an active or in-flight session, so the
/// discovery path and the reconnect path never dial the same modem twice.
/// A dropped peer is removed from it — without that, the dedup check would
/// permanently suppress re-connection to a modem that restarted.
async fn run_event_loop(daemon: &RouterDaemon, events: &mut Receiver<DaemonEvent>) {
    let mut connected: HashSet<SocketAddr> = HashSet::new();
    let mut reconnect = ReconnectQueue::default();
    loop {
        // Wake at the earliest pending reconnect deadline; park forever when
        // nothing is queued so an idle router doesn't spin.
        let next_due = reconnect.next_due();
        let retry_tick = async move {
            match next_due {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(retry_tick);

        tokio::select! {
            _ = &mut retry_tick => {
                for peer in reconnect.take_due(Instant::now()) {
                    if connected.contains(&peer) {
                        // Discovery already re-established this one.
                        reconnect.forget(&peer);
                        continue;
                    }
                    tracing::info!(addr = %peer, "reconnecting to modem");
                    match daemon.connect_static(peer).await {
                        Ok(()) => {
                            connected.insert(peer);
                            // Drop it from the queue so a deadline firing
                            // before SessionUp can't open a second session.
                            reconnect.forget(&peer);
                        }
                        Err(e) => {
                            tracing::warn!(
                                addr = %peer, error = %e,
                                "reconnect failed; will retry with backoff"
                            );
                        }
                    }
                }
            }
            evt = events.recv() => match evt {
                Ok(DaemonEvent::PeerDiscovered(offer)) => {
                    if offer.endpoints.iter().any(|e| connected.contains(&e.addr)) { continue; }
                    match daemon.connect_discovered(&offer).await {
                        Ok(addr) => { connected.insert(addr); reconnect.forget(&addr); }
                        Err(e) => tracing::warn!(error = %e, "offer endpoints failed; discovery will retry"),
                    }
                }
                Ok(DaemonEvent::SessionUp { peer, .. }) => {
                    tracing::info!(addr = %peer.addr, tls = peer.is_tls, "session up");
                    connected.insert(peer.addr);
                    // Session established: the next drop is a fresh incident
                    // and should retry at the base delay, not a grown one.
                    reconnect.forget(&peer.addr);
                }
                Ok(DaemonEvent::SessionDown { peer, reason, .. }) => {
                    tracing::info!(addr = %peer.addr, ?reason, "session down; scheduling reconnect");
                    connected.remove(&peer.addr);
                    reconnect.schedule(peer.addr, Instant::now());
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

/// Delay before the first reconnect attempt after a session drops.
const RECONNECT_BASE: Duration = Duration::from_secs(1);
/// Ceiling for the exponential backoff, so a modem that stays down is retried
/// at a steady low rate rather than never or in a hot loop.
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// Peers whose session dropped and that we intend to dial again, each with an
/// exponentially-growing delay.
///
/// The clock is passed in rather than read from `Instant::now()` internally so
/// the scheduling logic is unit-testable without sleeping.
#[derive(Debug, Default)]
struct ReconnectQueue {
    entries: HashMap<SocketAddr, ReconnectEntry>,
}

#[derive(Debug)]
struct ReconnectEntry {
    /// Attempts already handed out by `take_due`.
    attempts: u32,
    due: Instant,
}

impl ReconnectQueue {
    /// `attempts` = retries already made; 0 yields the base delay.
    fn backoff_for(attempts: u32) -> Duration {
        // `checked_shl`-free: cap the shift before it can overflow, then clamp.
        let shift = attempts.min(16);
        RECONNECT_BASE
            .saturating_mul(1u32 << shift)
            .min(RECONNECT_MAX)
    }

    /// Queue a dropped peer. A peer already queued keeps its accumulated
    /// backoff, so a flapping modem cannot rewind itself to the base delay by
    /// dropping repeatedly.
    fn schedule(&mut self, addr: SocketAddr, now: Instant) {
        self.entries.entry(addr).or_insert_with(|| ReconnectEntry {
            attempts: 0,
            due: now + Self::backoff_for(0),
        });
    }

    /// Hand back every peer whose delay has elapsed, re-arming each at the
    /// next backoff step. A caller that reconnects successfully calls
    /// [`Self::forget`]; one that fails need do nothing, since the peer is
    /// already scheduled for another try.
    fn take_due(&mut self, now: Instant) -> Vec<SocketAddr> {
        let mut due: Vec<SocketAddr> = Vec::new();
        for (addr, entry) in self.entries.iter_mut() {
            if entry.due <= now {
                entry.attempts = entry.attempts.saturating_add(1);
                entry.due = now + Self::backoff_for(entry.attempts);
                due.push(*addr);
            }
        }
        // Deterministic order keeps logs and tests stable.
        due.sort();
        due
    }

    /// Stop retrying a peer — call on `SessionUp` so the next drop starts a
    /// fresh backoff sequence.
    fn forget(&mut self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    /// Earliest pending deadline, for sizing the event loop's sleep.
    fn next_due(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.due).min()
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

#[cfg(test)]
mod tests {
    use clap::Parser;
    use dlep_daemon::DiscoveryMode;

    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("dlep-router").chain(args.iter().copied()))
            .expect("CLI args parse")
    }

    #[test]
    fn peer_flag_forces_static_mode_and_appends() {
        let cli = parse(&["--peer", "192.0.2.1:854", "--peer", "192.0.2.2:854"]);
        let mut cfg = RouterConfig::default();
        apply_overrides(&mut cfg, &cli);
        assert!(matches!(cfg.mode, DiscoveryMode::Static));
        assert_eq!(
            cfg.static_peers,
            vec![
                "192.0.2.1:854".parse().unwrap(),
                "192.0.2.2:854".parse().unwrap()
            ]
        );
    }

    #[test]
    fn tls_path_flags_override_toml_section() {
        let cli = parse(&[
            "--ca-bundle",
            "/x/ca.pem",
            "--cert",
            "/x/c.pem",
            "--key",
            "/x/k.pem",
        ]);
        let mut cfg = RouterConfig::default();
        apply_overrides(&mut cfg, &cli);
        assert_eq!(
            cfg.shared.tls.ca_bundle.as_deref(),
            Some(std::path::Path::new("/x/ca.pem"))
        );
        assert_eq!(
            cfg.shared.tls.cert.as_deref(),
            Some(std::path::Path::new("/x/c.pem"))
        );
        assert_eq!(
            cfg.shared.tls.key.as_deref(),
            Some(std::path::Path::new("/x/k.pem"))
        );
    }

    #[test]
    fn no_tls_flag_disables_tls_and_defaults_leave_config_untouched() {
        let cli = parse(&["--no-tls"]);
        let mut cfg = RouterConfig::default();
        apply_overrides(&mut cfg, &cli);
        assert!(!cfg.shared.network.use_tls);
        assert!(matches!(cfg.mode, DiscoveryMode::Discovery));
        assert!(cfg.static_peers.is_empty());
        assert!(cfg.shared.tls.cert.is_none());
    }

    // --- ReconnectQueue ---------------------------------------------------

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 854))
    }

    #[test]
    fn backoff_doubles_from_base_and_saturates_at_cap() {
        assert_eq!(ReconnectQueue::backoff_for(0), RECONNECT_BASE);
        assert_eq!(ReconnectQueue::backoff_for(1), Duration::from_secs(2));
        assert_eq!(ReconnectQueue::backoff_for(2), Duration::from_secs(4));
        assert_eq!(ReconnectQueue::backoff_for(3), Duration::from_secs(8));
        // Far past the cap, and past what shifting a u32 could hold.
        assert_eq!(ReconnectQueue::backoff_for(50), RECONNECT_MAX);
        assert_eq!(ReconnectQueue::backoff_for(u32::MAX), RECONNECT_MAX);
    }

    #[test]
    fn peer_is_not_due_until_the_backoff_elapses() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        assert!(q.take_due(now).is_empty(), "must wait out the backoff");
        assert_eq!(
            q.take_due(now + RECONNECT_BASE),
            vec![addr(1)],
            "due once the base backoff elapses"
        );
    }

    #[test]
    fn taking_a_peer_rearms_it_with_a_longer_backoff() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);

        let first = now + RECONNECT_BASE;
        assert_eq!(q.take_due(first), vec![addr(1)]);
        // A failed attempt leaves the peer queued, but at 2× the delay.
        assert!(
            q.take_due(first + RECONNECT_BASE).is_empty(),
            "second attempt must not fire after only one base interval"
        );
        assert_eq!(q.take_due(first + Duration::from_secs(2)), vec![addr(1)]);
    }

    #[test]
    fn forget_stops_further_retries() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        q.forget(&addr(1));
        assert!(q.take_due(now + Duration::from_secs(600)).is_empty());
        assert!(q.next_due().is_none());
    }

    #[test]
    fn rescheduling_a_queued_peer_does_not_reset_its_backoff() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        let first = now + RECONNECT_BASE;
        assert_eq!(q.take_due(first), vec![addr(1)]);

        // A flapping peer that drops again must not rewind to the base delay.
        q.schedule(addr(1), first);
        assert!(q.take_due(first + RECONNECT_BASE).is_empty());
    }

    #[test]
    fn a_peer_reconnected_then_dropped_again_restarts_at_the_base_delay() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        let first = now + RECONNECT_BASE;
        assert_eq!(q.take_due(first), vec![addr(1)]);
        // Session came back up, so the queue forgets the peer entirely...
        q.forget(&addr(1));
        // ...and a later drop is a fresh incident, not attempt #2.
        q.schedule(addr(1), first);
        assert_eq!(q.take_due(first + RECONNECT_BASE), vec![addr(1)]);
    }

    #[test]
    fn next_due_reports_the_earliest_deadline() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        assert!(q.next_due().is_none());
        q.schedule(addr(1), now + Duration::from_secs(10));
        q.schedule(addr(2), now);
        assert_eq!(q.next_due(), Some(now + RECONNECT_BASE));
    }
}

#[cfg(test)]
mod interface_tests {
    use super::*;

    #[test]
    fn interface_cli_overrides_config() {
        let cli = Cli::try_parse_from(["dlep-router", "--interface", "selected0"]).unwrap();
        let mut config = RouterConfig::default();
        config.shared.network.interface = Some("configured0".into());
        apply_overrides(&mut config, &cli);
        assert_eq!(
            config.shared.network.interface.as_deref(),
            Some("selected0")
        );
    }
}
