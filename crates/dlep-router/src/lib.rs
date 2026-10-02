mod connect;

use connect::ConnectAttempts;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{
    DaemonEvent, DiscoveryMode, PeerConnectionState, RouterConfig, RouterDaemon,
    check_router_config, load_toml_config,
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
    /// (overrides tls.ca_bundle).
    #[arg(long, value_name = "PATH")]
    ca_bundle: Option<PathBuf>,

    /// PEM client certificate presented to the modem for mutual TLS
    /// (overrides tls.cert).
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key for --cert (overrides tls.key).
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

/// Run the daemon CLI with the supplied argument vector, including argv[0].
/// Help/version and argument errors follow clap's normal process-exit behavior.
/// Registers process-wide tracing and signal handlers; call once per process.
pub async fn run_from<I, T>(args: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
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
    // shutdown. Dropping the driver cancels its outstanding TCP/TLS attempts.
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
        }
        DiscoveryMode::Discovery => {
            daemon
                .start_discovery()
                .await
                .context("starting discovery")?;
        }
    }

    let peers = if matches!(mode, DiscoveryMode::Static) {
        static_peers
    } else {
        &[]
    };
    run_event_loop(daemon, events, peers).await;
    Ok(())
}

/// Connect to modems as discovery finds them,
/// log session lifecycle, and re-dial peers whose session dropped.
///
/// `connected` tracks registered sessions; `attempts` reserves endpoints while
/// TCP/TLS is pending, so discovery and retries cannot dial a modem twice.
/// A dropped peer is removed from it — without that, the dedup check would
/// permanently suppress re-connection to a modem that restarted.
async fn run_event_loop(
    daemon: &RouterDaemon,
    events: &mut Receiver<DaemonEvent>,
    static_peers: &[SocketAddr],
) {
    let pinned: HashSet<_> = static_peers.iter().copied().collect();
    let mut connected: HashSet<SocketAddr> = HashSet::new();
    let mut reconnect = ReconnectQueue::default();
    let mut attempts = ConnectAttempts::default();
    let mut startup: VecDeque<_> = static_peers.iter().copied().collect();
    let mut states = daemon.connection_states();
    let mut establishments = HashMap::new();
    let mut refresh = true;
    loop {
        // Read current state before acting on offers or retry deadlines. The
        // initial snapshot also covers sessions that ended during startup.
        if refresh || states.has_changed().unwrap_or(false) {
            let snapshot = states.borrow_and_update().clone();
            prune_reconnect_state(
                &snapshot,
                &pinned,
                &mut establishments,
                &mut connected,
                &mut reconnect,
            );
            attempts.retain_retries(|peer| snapshot.contains_key(peer) || pinned.contains(peer));
            reconcile_connections(
                &snapshot,
                &mut establishments,
                &mut connected,
                &mut reconnect,
                Instant::now(),
            );
            refresh = false;
        }
        // Retained snapshots can still report a previous closed session while
        // a new TCP/TLS attempt is pending. Do not rearm those retry deadlines.
        for peer in attempts.endpoints() {
            reconnect.suspend(peer);
        }
        let mut startup_capacity = attempts.capacity().min(daemon.connection_capacity());
        while startup_capacity > 0 {
            let Some(peer) = startup.pop_front() else {
                break;
            };
            if !connected.contains(&peer)
                && !reconnect.contains(&peer)
                && attempts.start_static(daemon, peer)
            {
                startup_capacity -= 1;
            }
        }
        // Leave excess due peers queued without advancing their attempt count.
        // A full pool waits for completion rather than spinning on past deadlines.
        let next_due = if attempts.capacity() > 0 && daemon.connection_capacity() > 0 {
            reconnect.next_due()
        } else {
            None
        };
        let retry_tick = async move {
            match next_due {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(retry_tick);

        tokio::select! {
            _ = daemon.wait_for_connection_capacity(), if daemon.connection_capacity() == 0 => {}
            changed = states.changed() => {
                if changed.is_err() { return; }
                refresh = true;
            }
            completion = attempts.next() => {
                match completion.result {
                    Ok(addr) => {
                        tracing::debug!(%addr, "transport connected; awaiting DLEP initialization");
                        // Read the snapshot again: initialization or teardown may
                        // have completed before this future was polled as ready.
                        refresh = true;
                    }
                    Err(error) => {
                        if let Some(peer) = completion.retry_peer {
                            reconnect.schedule(peer, Instant::now());
                            tracing::warn!(%peer, %error, "connection failed; will retry with backoff");
                        } else {
                            tracing::warn!(%error, "offer endpoints failed; discovery will retry");
                        }
                    }
                }
            }
            _ = &mut retry_tick => {
                for peer in reconnect.take_due_limited(Instant::now(), attempts.capacity().min(daemon.connection_capacity())) {
                    reconnect.suspend(&peer);
                    if connected.contains(&peer) || attempts.contains(&peer) { continue; }
                    tracing::info!(addr = %peer, "reconnecting to modem");
                    attempts.start_static(daemon, peer);
                }
            }
            evt = events.recv() => match evt {
                Ok(DaemonEvent::PeerDiscovered(mut offer)) => {
                    if daemon.connection_capacity() == 0 { continue; }
                    if offer.endpoints.iter().any(|e| connected.contains(&e.addr) || attempts.contains(&e.addr)) { continue; }
                    // The retry queue owns endpoints with a failure history.
                    // Repeated offers must not bypass their backoff; new
                    // endpoints in the same offer remain eligible.
                    offer.endpoints.retain(|e| !reconnect.contains(&e.addr));
                    if offer.endpoints.is_empty() { continue; }
                    if !attempts.start_offer(daemon, offer) {
                        tracing::debug!("connection slots full; a later discovery offer can retry");
                    }
                }
                Ok(DaemonEvent::SessionUp { peer, .. }) => {
                    tracing::info!(addr = %peer.addr, tls = peer.is_tls, "session up");
                }
                Ok(DaemonEvent::SessionDown { peer, reason, .. }) => {
                    tracing::info!(addr = %peer.addr, ?reason, "session down");
                }
                Ok(_) => {}
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "event stream lagged; reconnect state is tracked separately");
                }
                Err(RecvError::Closed) => return,
            },
        }
    }
}

/// Expiry/eviction is authoritative for discovered peers. Static endpoints
/// with no successful TCP connection still need retry state outside the snapshot.
fn prune_reconnect_state(
    states: &HashMap<SocketAddr, PeerConnectionState>,
    pinned: &HashSet<SocketAddr>,
    establishments: &mut HashMap<SocketAddr, u64>,
    connected: &mut HashSet<SocketAddr>,
    reconnect: &mut ReconnectQueue,
) {
    establishments.retain(|peer, _| states.contains_key(peer));
    connected.retain(|peer| states.contains_key(peer));
    reconnect
        .entries
        .retain(|peer, _| states.contains_key(peer) || pinned.contains(peer));
}

/// Reconcile retained state, never replay potentially stale broadcast events.
/// An initialization and disconnect may coalesce into one snapshot; its
/// establishment counter still resets backoff before scheduling the retry.
fn reconcile_connections(
    states: &HashMap<SocketAddr, PeerConnectionState>,
    establishments: &mut HashMap<SocketAddr, u64>,
    connected: &mut HashSet<SocketAddr>,
    reconnect: &mut ReconnectQueue,
    now: Instant,
) {
    for (&peer, state) in states {
        let seen = establishments.entry(peer).or_default();
        if *seen != state.establishment_count {
            reconnect.forget(&peer);
            *seen = state.establishment_count;
        }
        if state.active_sessions > 0 {
            connected.insert(peer);
            reconnect.suspend(&peer);
        } else {
            connected.remove(&peer);
            reconnect.schedule(peer, now);
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
    /// Retries already handed out for execution.
    attempts: u32,
    /// None while TCP/TLS connection or DLEP initialization is pending.
    due: Option<Instant>,
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
    /// dropping repeatedly. A failed initialization resumes the retained
    /// backoff from the time connection failure or session closure is observed.
    fn schedule(&mut self, addr: SocketAddr, now: Instant) {
        self.entries
            .entry(addr)
            .and_modify(|entry| {
                if entry.due.is_none() {
                    entry.due = Some(now + Self::backoff_for(entry.attempts));
                }
            })
            .or_insert_with(|| ReconnectEntry {
                attempts: 0,
                due: Some(now + Self::backoff_for(0)),
            });
    }

    #[cfg(test)]
    fn take_due(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.take_due_limited(now, usize::MAX)
    }

    /// Hand out the oldest due peers up to available capacity. The caller
    /// suspends their deadlines while connecting, then schedules failed
    /// attempts from completion time. Only SessionUp clears their history.
    fn take_due_limited(&mut self, now: Instant, limit: usize) -> Vec<SocketAddr> {
        let mut due: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&addr, entry)| entry.due.filter(|at| *at <= now).map(|at| (at, addr)))
            .collect();
        // Oldest first keeps waiting peers ahead of freshly failed retries.
        due.sort();
        due.truncate(limit);
        due.into_iter()
            .map(|(_, addr)| {
                let entry = self.entries.get_mut(&addr).unwrap();
                entry.attempts = entry.attempts.saturating_add(1);
                entry.due = Some(now + Self::backoff_for(entry.attempts));
                addr
            })
            .collect()
    }

    /// Stop retrying a peer — call on `SessionUp` so the next drop starts a
    /// fresh backoff sequence.
    fn forget(&mut self, addr: &SocketAddr) {
        self.entries.remove(addr);
    }

    /// Retain attempts without a runnable deadline during initialization.
    fn suspend(&mut self, addr: &SocketAddr) {
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.due = None;
        }
    }

    fn contains(&self, addr: &SocketAddr) -> bool {
        self.entries.contains_key(addr)
    }

    /// Earliest pending deadline, for sizing the event loop's sleep.
    fn next_due(&self) -> Option<Instant> {
        self.entries.values().filter_map(|e| e.due).min()
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
    fn eviction_bounds_all_retry_maps_and_preserves_static_peers_without_snapshots() {
        let now = Instant::now();
        let mut reconnect = ReconnectQueue::default();
        let mut seen = HashMap::new();
        let mut connected = HashSet::new();
        let pinned = HashSet::from([addr(1)]);
        reconnect.schedule(addr(1), now);
        for port in 2..1002 {
            let peer = SocketAddr::from(([192, 0, 2, 2], port));
            let states = HashMap::from([(peer, PeerConnectionState::default())]);
            prune_reconnect_state(&states, &pinned, &mut seen, &mut connected, &mut reconnect);
            reconcile_connections(&states, &mut seen, &mut connected, &mut reconnect, now);
            assert_eq!(seen.len(), 1);
            assert_eq!(reconnect.entries.len(), 2);
            assert!(reconnect.contains(&addr(1)));
        }
        prune_reconnect_state(
            &HashMap::new(),
            &pinned,
            &mut seen,
            &mut connected,
            &mut reconnect,
        );
        assert!(seen.is_empty() && connected.is_empty());
        assert_eq!(reconnect.take_due(now + RECONNECT_BASE), vec![addr(1)]);
    }

    #[test]
    fn full_connection_pool_does_not_advance_waiting_retry_counts() {
        let now = Instant::now();
        let mut queue = ReconnectQueue::default();
        queue.schedule(addr(2), now);
        queue.schedule(addr(1), now + Duration::from_millis(1));
        let later = now + RECONNECT_BASE + Duration::from_secs(1);
        assert!(queue.take_due_limited(later, 0).is_empty());
        assert_eq!(queue.entries[&addr(2)].attempts, 0);
        assert_eq!(queue.take_due_limited(later, 1), vec![addr(2)]);
        assert_eq!(queue.entries[&addr(1)].attempts, 0);
        assert_eq!(
            queue.next_due(),
            Some(now + RECONNECT_BASE + Duration::from_millis(1))
        );
        assert_eq!(queue.take_due_limited(later, 1), vec![addr(1)]);
    }

    #[test]
    fn coalesced_establishment_and_disconnect_reset_backoff_once() {
        let peer = addr(1);
        let now = Instant::now();
        let mut queue = ReconnectQueue::default();
        queue.schedule(peer, now);
        queue.take_due(now + RECONNECT_BASE);
        queue.suspend(&peer);
        let mut connected = HashSet::from([peer]);
        let mut seen = HashMap::new();
        let states = HashMap::from([(
            peer,
            PeerConnectionState {
                active_sessions: 0,
                establishment_count: 1,
            },
        )]);
        let closed_at = now + Duration::from_secs(10);
        reconcile_connections(&states, &mut seen, &mut connected, &mut queue, closed_at);
        assert!(connected.is_empty());
        assert_eq!(queue.next_due(), Some(closed_at + RECONNECT_BASE));
        // An unchanged snapshot must not repeatedly reset the retry deadline.
        reconcile_connections(
            &states,
            &mut seen,
            &mut connected,
            &mut queue,
            closed_at + Duration::from_millis(500),
        );
        assert_eq!(queue.take_due(closed_at + RECONNECT_BASE), vec![peer]);
    }

    #[test]
    fn pending_snapshot_preserves_backoff_and_keeps_other_peers_retrying() {
        let now = Instant::now();
        let mut queue = ReconnectQueue::default();
        queue.schedule(addr(1), now);
        queue.schedule(addr(2), now);
        queue.take_due(now + RECONNECT_BASE);
        let states = HashMap::from([
            (
                addr(1),
                PeerConnectionState {
                    active_sessions: 1,
                    establishment_count: 0,
                },
            ),
            (addr(2), PeerConnectionState::default()),
        ]);
        let mut connected = HashSet::new();
        let mut seen = HashMap::new();
        reconcile_connections(&states, &mut seen, &mut connected, &mut queue, now);
        assert_eq!(connected, HashSet::from([addr(1)]));
        assert!(queue.contains(&addr(1)));
        assert_eq!(queue.take_due(now + Duration::from_secs(3)), vec![addr(2)]);
        let closed_at = now + Duration::from_secs(4);
        let states = HashMap::from([(addr(1), PeerConnectionState::default())]);
        reconcile_connections(&states, &mut seen, &mut connected, &mut queue, closed_at);
        assert_eq!(
            queue.entries[&addr(1)].due,
            Some(closed_at + Duration::from_secs(2))
        );
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
    fn pending_initialization_retains_history_without_a_retry_deadline() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        assert_eq!(q.take_due(now + RECONNECT_BASE), vec![addr(1)]);
        q.suspend(&addr(1));
        assert!(
            q.contains(&addr(1)),
            "offers must not bypass a pending retry"
        );
        assert!(q.next_due().is_none());
        let later = now + Duration::from_secs(60);
        assert!(q.take_due(later).is_empty());
        q.schedule(addr(1), later);
        assert!(q.take_due(later + RECONNECT_BASE).is_empty());
        assert_eq!(q.take_due(later + Duration::from_secs(2)), vec![addr(1)]);
    }

    #[test]
    fn pending_initialization_does_not_block_another_peers_retry() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        q.schedule(addr(2), now);
        let first = now + RECONNECT_BASE;
        assert_eq!(q.take_due(first), vec![addr(1), addr(2)]);
        q.suspend(&addr(1));
        assert_eq!(q.next_due(), Some(first + Duration::from_secs(2)));
        assert_eq!(q.take_due(first + Duration::from_secs(2)), vec![addr(2)]);
    }

    #[test]
    fn a_peer_reconnected_then_dropped_again_restarts_at_the_base_delay() {
        let now = Instant::now();
        let mut q = ReconnectQueue::default();
        q.schedule(addr(1), now);
        let first = now + RECONNECT_BASE;
        assert_eq!(q.take_due(first), vec![addr(1)]);
        // TCP alone retains the history; SessionUp clears it.
        q.suspend(&addr(1));
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

#[cfg(test)]
mod reconnect_runtime_tests {
    use super::*;
    use dlep_core::{DataItem, Message, MessageType, StatusCode};
    use dlep_daemon::PeerOffer;
    use dlep_fsm::{
        FsmAction, FsmEvent, discovery_common::OfferEndpoint, session_modem::ModemSessionFsm,
    };
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    const WAIT: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn session_capacity_defers_static_peers_until_disconnect() {
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        first.set_ttl(255).unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        second.set_ttl(255).unwrap();
        let peers = vec![first.local_addr().unwrap(), second.local_addr().unwrap()];
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.limits.max_sessions = 1;
        config.static_peers = peers.clone();
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let driver_daemon = daemon.clone();
        let mut events = daemon.subscribe();
        let driver = tokio::spawn(async move {
            run_event_loop(&driver_daemon, &mut driver_daemon.subscribe(), &peers).await;
        });
        let (mut peer, _) = timeout(WAIT, first.accept()).await.unwrap().unwrap();
        initialize(&mut peer, false).await;
        lifecycle(&mut events, true).await;
        assert!(
            timeout(Duration::from_millis(200), second.accept())
                .await
                .is_err()
        );
        assert_eq!(daemon.connection_capacity(), 0);
        drop(peer);
        // A static peer deferred at capacity must be admitted after cleanup,
        // without a new offer or a lifecycle broadcast replay.
        let (mut replacement, _) = timeout(WAIT, second.accept()).await.unwrap().unwrap();
        initialize(&mut replacement, false).await;
        lifecycle(&mut events, true).await;
        assert_eq!(daemon.connection_capacity(), 0);
        driver.abort();
        let _ = driver.await;
        drop(replacement);
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn expired_discovered_peer_stops_retrying_until_a_fresh_offer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.limits.peer_retention_secs = 1;
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let mut states = daemon.connection_states();
        let mut events = daemon.subscribe();
        daemon.connect_static(addr).await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        initialize(&mut peer, false).await;
        lifecycle(&mut events, true).await;
        let driver_daemon = daemon.clone();
        let (offers, mut event_feed) = tokio::sync::broadcast::channel(16);
        let driver = tokio::spawn(async move {
            run_event_loop(&driver_daemon, &mut event_feed, &[]).await;
        });
        drop(listener);
        drop(peer);
        lifecycle(&mut events, false).await;
        // Failed connection retries cannot refresh the retention window.
        // The event loop receives no lifecycle broadcasts, only its snapshots.
        timeout(WAIT, async {
            while states.borrow_and_update().contains_key(&addr) {
                states.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        listener.set_ttl(255).unwrap();
        assert!(
            timeout(Duration::from_millis(3200), listener.accept())
                .await
                .is_err()
        );
        offers
            .send(DaemonEvent::PeerDiscovered(PeerOffer {
                endpoints: vec![OfferEndpoint {
                    addr,
                    use_tls: false,
                }],
                peer_description: None,
            }))
            .unwrap();
        let (mut peer, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        initialize(&mut peer, false).await;
        lifecycle(&mut events, true).await;
        driver.abort();
        let _ = driver.await;
        drop(peer);
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    async fn read_message(peer: &mut TcpStream) -> Message {
        timeout(WAIT, async {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let mut bytes = header.to_vec();
            bytes.resize(4 + u16::from_be_bytes([header[2], header[3]]) as usize, 0);
            peer.read_exact(&mut bytes[4..]).await.unwrap();
            Message::decode(bytes.into()).unwrap()
        })
        .await
        .unwrap()
    }

    async fn lifecycle(events: &mut Receiver<DaemonEvent>, up: bool) {
        timeout(WAIT, async {
            loop {
                match events.recv().await.unwrap() {
                    DaemonEvent::SessionUp { .. } if up => break,
                    DaemonEvent::SessionDown { .. } if !up => break,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
    }

    async fn initialize(peer: &mut TcpStream, reject: bool) {
        let init = read_message(peer).await;
        assert_eq!(init.message_type, MessageType::SESSION_INITIALIZATION);
        let mut modem = ModemSessionFsm::new();
        modem.step(FsmEvent::TcpAccepted);
        let mut response = modem
            .step(FsmEvent::RecvMessage(init))
            .into_iter()
            .find_map(|a| {
                if let FsmAction::SendMessage(message) = a {
                    Some(message)
                } else {
                    None
                }
            })
            .unwrap();
        if reject {
            for item in &mut response.data_items {
                if let DataItem::Status { code, .. } = item {
                    *code = StatusCode::REQUEST_DENIED;
                }
            }
        }
        peer.write_all(&response.encode().unwrap()).await.unwrap();
        if reject {
            assert_eq!(
                read_message(peer).await.message_type,
                MessageType::SESSION_TERMINATION
            );
            peer.write_all(
                &Message::new(MessageType::SESSION_TERMINATION_RESPONSE)
                    .encode()
                    .unwrap(),
            )
            .await
            .unwrap();
        }
    }

    async fn independent_peers_during_stalled_tls(static_mode: bool) {
        use dlep_daemon::{ModemConfig, ModemDaemon, SessionCommand};
        use dlep_net::tls::test_helpers::{
            client_config_for, self_signed_for_ip, server_config_for,
        };
        let pki = self_signed_for_ip("127.0.0.1".parse().unwrap());
        let mut mc = ModemConfig::default();
        mc.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        mc.shared.network.tcp_port = 0;
        mc.shared.network.discovery_port = 0;
        let modem = ModemDaemon::builder()
            .config(mc)
            .with_rustls_server(server_config_for(pki.cert_der, pki.key_der))
            .spawn()
            .await
            .unwrap();
        let mut modem_events = modem.subscribe();
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(RouterConfig::default())
                .with_rustls_client(client_config_for(pki.roots))
                .spawn()
                .await
                .unwrap(),
        );
        let mut observed = daemon.subscribe();
        let slow = TcpListener::bind("127.0.0.1:0").await.unwrap();
        slow.set_ttl(255).unwrap();
        let slow_addr = slow.local_addr().unwrap();
        let healthy = modem.local_addr();
        let (inject, mut events) = tokio::sync::broadcast::channel(128);
        let offer = |addr| {
            DaemonEvent::PeerDiscovered(PeerOffer {
                endpoints: vec![OfferEndpoint {
                    addr,
                    use_tls: true,
                }],
                peer_description: None,
            })
        };
        let driver = daemon.clone();
        let task = tokio::spawn(async move {
            if static_mode {
                run(
                    &driver,
                    &mut events,
                    DiscoveryMode::Static,
                    &[slow_addr, healthy],
                )
                .await
                .unwrap();
            } else {
                run_event_loop(&driver, &mut events, &[]).await;
            }
        });
        if !static_mode {
            inject.send(offer(slow_addr)).unwrap();
        }
        let (mut stalled, _) = timeout(WAIT, slow.accept()).await.unwrap().unwrap();
        if !static_mode {
            for _ in 0..16 {
                inject.send(offer(slow_addr)).unwrap();
                inject.send(offer(healthy)).unwrap();
            }
        }
        lifecycle(&mut observed, true).await;
        let session_id = timeout(WAIT, async {
            loop {
                if let DaemonEvent::SessionUp { session_id, .. } =
                    modem_events.recv().await.unwrap()
                {
                    break session_id;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            daemon.connection_states().borrow()[&healthy].active_sessions,
            1
        );
        assert!(!daemon.connection_states().borrow().contains_key(&slow_addr));
        // A real session close must be noticed and retried even while another
        // endpoint still holds its TLS handshake open.
        modem
            .send_command_to(
                session_id,
                SessionCommand::Shutdown {
                    reason: StatusCode::SHUTTING_DOWN,
                },
            )
            .await
            .unwrap();
        lifecycle(&mut observed, false).await;
        lifecycle(&mut observed, true).await;
        assert!(
            timeout(Duration::from_millis(100), slow.accept())
                .await
                .is_err(),
            "duplicate slow connection"
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // Cancelling the driver drops the in-flight TLS socket immediately.
        let mut hello = Vec::new();
        timeout(WAIT, stalled.read_to_end(&mut hello))
            .await
            .unwrap()
            .unwrap();
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        modem.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn static_startup_and_retries_progress_during_stalled_tls() {
        independent_peers_during_stalled_tls(true).await;
    }

    #[tokio::test]
    async fn discovery_and_retries_progress_during_stalled_tls() {
        independent_peers_during_stalled_tls(false).await;
    }

    #[tokio::test]
    async fn full_pool_keeps_static_peers_queued_until_a_slot_is_released() {
        use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_ip};
        let pki = self_signed_for_ip("127.0.0.1".parse().unwrap());
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(RouterConfig::default())
                .with_rustls_client(client_config_for(pki.roots))
                .spawn()
                .await
                .unwrap(),
        );
        let mut listeners = Vec::new();
        let mut peers = Vec::new();
        for _ in 0..=connect::MAX_CONNECT_ATTEMPTS {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.set_ttl(255).unwrap();
            peers.push(listener.local_addr().unwrap());
            listeners.push(listener);
        }
        let mut events = daemon.subscribe();
        let driver = daemon.clone();
        let task = tokio::spawn(async move {
            run(&driver, &mut events, DiscoveryMode::Static, &peers)
                .await
                .unwrap();
        });
        let mut sockets = Vec::new();
        for listener in &listeners[..connect::MAX_CONNECT_ATTEMPTS] {
            sockets.push(timeout(WAIT, listener.accept()).await.unwrap().unwrap().0);
        }
        let last = listeners.last().unwrap();
        assert!(
            timeout(Duration::from_millis(100), last.accept())
                .await
                .is_err(),
            "connection limit exceeded"
        );
        // This handshake failure frees a slot without ending static startup.
        drop(sockets.remove(0));
        let (_next, _) = timeout(WAIT, last.accept()).await.unwrap().unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(sockets);
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn initially_unavailable_static_peer_is_retried() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let mut cfg = RouterConfig::default();
        cfg.shared.network.use_tls = false;
        let daemon = Arc::new(RouterDaemon::builder().config(cfg).spawn().await.unwrap());
        let mut observed = daemon.subscribe();
        let mut events = daemon.subscribe();
        let driver = daemon.clone();
        let started = Instant::now();
        let task = tokio::spawn(async move {
            run(&driver, &mut events, DiscoveryMode::Static, &[addr])
                .await
                .unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let listener = TcpListener::bind(addr).await.unwrap();
        listener.set_ttl(255).unwrap();
        let (mut peer, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        assert!(started.elapsed() >= RECONNECT_BASE - Duration::from_millis(100));
        initialize(&mut peer, false).await;
        lifecycle(&mut observed, true).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        drop(peer);
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn startup_disconnect_is_recovered_without_lifecycle_events() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let mut observed = daemon.subscribe();
        daemon.connect_static(addr).await.unwrap();
        let (mut peer, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        initialize(&mut peer, false).await;
        lifecycle(&mut observed, true).await;
        drop(peer);
        lifecycle(&mut observed, false).await;
        let mut states = daemon.connection_states();
        timeout(WAIT, async {
            loop {
                if states.borrow_and_update()[&addr].active_sessions == 0 {
                    break;
                }
                states.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        // The driver starts after both transitions, with an empty event feed.
        let (_sender, mut events) = tokio::sync::broadcast::channel(1);
        let mut tasks = tokio::task::JoinSet::new();
        let driver = daemon.clone();
        let started = Instant::now();
        tasks.spawn(async move {
            run_event_loop(&driver, &mut events, &[]).await;
        });
        let (peer, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        assert!(started.elapsed() >= RECONNECT_BASE - Duration::from_millis(100));
        drop(peer);
        tasks.shutdown().await;
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejected_sessions_back_off_despite_offers_and_success_resets_delay() {
        backoff_with_event_overflow(false).await;
    }

    #[tokio::test]
    async fn lost_lifecycle_events_still_reconnect_and_reset_backoff() {
        backoff_with_event_overflow(true).await;
    }

    async fn backoff_with_event_overflow(overrun_lifecycle: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.set_ttl(255).unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        let daemon = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let mut observed = daemon.subscribe();
        let mut live_events = daemon.subscribe();
        let (inject, mut events) = tokio::sync::broadcast::channel(128);
        let mut tasks = tokio::task::JoinSet::new();
        let forward = inject.clone();
        // Forward actual daemon lifecycle events; inject repeated offers as an
        // independently timed discovery source would, without mocking sessions.
        tasks.spawn(async move {
            while let Ok(event) = live_events.recv().await {
                forward.send(event).unwrap();
                if overrun_lifecycle {
                    // No await: on this current-thread runtime the driver
                    // cannot consume the lifecycle event before it is evicted.
                    for _ in 0..256 {
                        forward.send(DaemonEvent::Extension(Arc::new(()))).unwrap();
                    }
                }
            }
        });
        let driver = daemon.clone();
        tasks.spawn(async move {
            run_event_loop(&driver, &mut events, &[]).await;
        });

        daemon.connect_static(addr).await.unwrap();
        let (mut peer, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
        initialize(&mut peer, true).await;
        lifecycle(&mut observed, false).await;
        let mut failed_at = Instant::now();
        drop(peer);
        tasks.spawn(async move {
            loop {
                // Frequent offers used to re-dial immediately during backoff.
                tokio::time::sleep(Duration::from_millis(25)).await;
                let _ = inject.send(DaemonEvent::PeerDiscovered(PeerOffer {
                    endpoints: vec![OfferEndpoint {
                        addr,
                        use_tls: false,
                    }],
                    peer_description: Some("rejecting-modem".into()),
                }));
            }
        });

        for (seconds, reject) in [(1, true), (2, true), (4, false)] {
            let delay = Duration::from_secs(seconds);
            let (mut peer, _) = timeout(delay + WAIT, listener.accept())
                .await
                .unwrap()
                .unwrap();
            assert!(
                failed_at.elapsed() >= delay - Duration::from_millis(100),
                "expected {delay:?} backoff, got {:?}",
                failed_at.elapsed()
            );
            initialize(&mut peer, reject).await;
            if reject {
                lifecycle(&mut observed, false).await;
                failed_at = Instant::now();
            } else {
                lifecycle(&mut observed, true).await;
                // Offers must not open duplicates after successful initialization.
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
                drop(peer);
                lifecycle(&mut observed, false).await;
                failed_at = Instant::now();
            }
        }
        // A genuinely established session resets the accumulated 8 s delay.
        let (peer, _) = timeout(WAIT, listener.accept())
            .await
            .expect("SessionUp did not reset backoff")
            .unwrap();
        assert!(failed_at.elapsed() >= RECONNECT_BASE - Duration::from_millis(100));
        drop(peer);
        tasks.shutdown().await;
        Arc::try_unwrap(daemon)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }
}
