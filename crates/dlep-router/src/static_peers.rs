//! Static-mode connection driver. Every configured peer (numeric address, DNS
//! name, or named IPv6 zone) is scheduled by its configured identity and
//! follows the numeric endpoint it last connected to, so numeric peers
//! reconnect the same way whatever else is configured. Discovery mode uses
//! `run_event_loop`; both share `ReconnectQueue`'s backoff policy.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use dlep_daemon::{
    DaemonError, DaemonEvent, NamedPeer, PeerConnectionState, PeerEndpoint, RouterDaemon,
    ScopedPeer,
};
use dlep_net::transport::{HOST_CONNECT_TIMEOUT, MAX_RESOLVED_ENDPOINTS};
use tokio::{
    sync::{
        broadcast::{Receiver, error::RecvError},
        watch,
    },
    time::Instant,
};

use crate::{ReconnectQueue, connect::MAX_CONNECT_ATTEMPTS};

type States = HashMap<SocketAddr, PeerConnectionState>;

/// Daemon operations used by the driver. Tests substitute a fake daemon so
/// retry timing can be checked under paused Tokio time.
pub(crate) trait Dialer: Sync {
    fn connection_states(&self) -> watch::Receiver<States>;
    fn connection_capacity(&self) -> usize;
    fn wait_for_connection_capacity(&self) -> impl Future<Output = ()> + Send;
    /// Open TCP/TLS to `addr` and register the session. TLS verifies
    /// `server_name` when given and the endpoint IP otherwise. The connection
    /// budget is claimed on the first poll, before any I/O is awaited.
    fn dial(
        &self,
        addr: SocketAddr,
        server_name: Option<&str>,
    ) -> impl Future<Output = Result<(), DaemonError>> + Send;
}

impl Dialer for RouterDaemon {
    fn connection_states(&self) -> watch::Receiver<States> {
        RouterDaemon::connection_states(self)
    }

    fn connection_capacity(&self) -> usize {
        RouterDaemon::connection_capacity(self)
    }

    fn wait_for_connection_capacity(&self) -> impl Future<Output = ()> + Send {
        RouterDaemon::wait_for_connection_capacity(self)
    }

    async fn dial(&self, addr: SocketAddr, server_name: Option<&str>) -> Result<(), DaemonError> {
        match server_name {
            Some(name) => self.connect_static_with_server_name(addr, name).await,
            None => self.connect_static(addr).await,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Never attempted. Started in configuration order outside the backoff
    /// queue, so the first failure waits the base delay.
    Startup,
    /// Waiting for its deadline in the backoff queue.
    Waiting,
    /// Resolution or TCP/TLS connection in progress.
    Connecting,
    /// Tracking an endpoint's retained session state, whether this identity
    /// dialed it or another configured identity already holds it.
    Following { addr: SocketAddr, seen: u64 },
}

struct Entry {
    peer: PeerEndpoint,
    state: State,
}

/// Successful attempt outcomes; both leave the peer following `addr`.
enum Attempt {
    /// This identity opened the endpoint's session.
    Dialed { addr: SocketAddr, seen: u64 },
    /// Every candidate already has a session under another configured identity.
    Covered { addr: SocketAddr, seen: u64 },
}

enum Failure {
    /// Every candidate is being dialed under another configured identity.
    Busy,
    Daemon(DaemonError),
}

type Pending<'a> = (
    usize,
    Pin<Box<dyn Future<Output = Result<Attempt, Failure>> + Send + 'a>>,
);
type Reservations = Arc<Mutex<HashSet<SocketAddr>>>;
type Resolution = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
type Resolver = dyn Fn(NamedPeer) -> Resolution + Send + Sync;
type ZoneResolver = dyn Fn(&ScopedPeer) -> std::io::Result<SocketAddr> + Send + Sync;

/// `Connector::connect_host` cannot be reused: each answer must be checked
/// against active sessions and reserved before it is dialed. Resolution and
/// fallback therefore happen here, within the transport's published limits.
fn system_resolve(peer: NamedPeer) -> Resolution {
    Box::pin(async move {
        let mut seen = HashSet::new();
        Ok(tokio::net::lookup_host((peer.host(), peer.port()))
            .await?
            .filter(|addr| seen.insert(*addr))
            .take(MAX_RESOLVED_ENDPOINTS)
            .collect())
    })
}

struct ReservedAddress {
    addr: SocketAddr,
    reservations: Reservations,
}
impl Drop for ReservedAddress {
    fn drop(&mut self) {
        self.reservations.lock().unwrap().remove(&self.addr);
    }
}

/// Counts an attempt against the connection budget until it dials (the daemon
/// then holds a permit for it) or ends. Resolution holds no daemon permit.
struct Admission(Option<Arc<AtomicUsize>>);
impl Admission {
    fn new(unadmitted: &Arc<AtomicUsize>) -> Self {
        unadmitted.fetch_add(1, Ordering::Relaxed);
        Self(Some(unadmitted.clone()))
    }

    fn admit(&mut self) {
        if let Some(unadmitted) = self.0.take() {
            unadmitted.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        self.admit();
    }
}

async fn connect<D: Dialer>(
    dialer: &D,
    peer: PeerEndpoint,
    reservations: Reservations,
    mut admission: Admission,
    resolve: &Resolver,
    zone: &ZoneResolver,
) -> Result<Attempt, Failure> {
    let work = async {
        let (addresses, server_name) = match &peer {
            PeerEndpoint::Address(addr) => (vec![*addr], None),
            PeerEndpoint::Named(name) => (
                resolve(name.clone())
                    .await
                    .map_err(|e| Failure::Daemon(e.into()))?,
                Some(name.host()),
            ),
            PeerEndpoint::Scoped(peer) => (
                vec![zone(peer).map_err(|e| Failure::Daemon(e.into()))?],
                None,
            ),
        };
        let states = dialer.connection_states();
        let mut covered = None;
        let mut reserved = false;
        let mut error = None;
        for addr in addresses {
            let state = states.borrow().get(&addr).copied().unwrap_or_default();
            if state.active_sessions > 0 {
                covered.get_or_insert((addr, state.establishment_count));
                continue;
            }
            if !reservations.lock().unwrap().insert(addr) {
                reserved = true;
                continue;
            }
            let _reservation = ReservedAddress {
                addr,
                reservations: reservations.clone(),
            };
            admission.admit();
            match dialer.dial(addr, server_name).await {
                Ok(()) => {
                    return Ok(Attempt::Dialed {
                        addr,
                        seen: state.establishment_count,
                    });
                }
                Err(DaemonError::SessionLimitReached) => {
                    return Err(Failure::Daemon(DaemonError::SessionLimitReached));
                }
                Err(failed) => error = Some(failed),
            }
        }
        // An alias of an endpoint that is already up waits for that session to
        // end; it never borrows another identity's authenticated session.
        match (covered, error) {
            (Some((addr, seen)), _) => Ok(Attempt::Covered { addr, seen }),
            (None, Some(error)) => Err(Failure::Daemon(error)),
            (None, None) if reserved => Err(Failure::Busy),
            (None, None) => Err(Failure::Daemon(DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "peer host has no addresses",
            )))),
        }
    };
    tokio::time::timeout(HOST_CONNECT_TIMEOUT, work)
        .await
        .map_err(|_| {
            Failure::Daemon(DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "static peer connection timed out",
            )))
        })?
}

/// Per-peer state plus backoff history keyed by entry index.
struct Schedule {
    entries: Vec<Entry>,
    queue: ReconnectQueue<usize>,
}

impl Schedule {
    fn new(peers: impl IntoIterator<Item = PeerEndpoint>) -> Self {
        // Coalesce duplicates while keeping configuration order for startup.
        let mut unique = BTreeSet::new();
        Self {
            entries: peers
                .into_iter()
                .filter(|peer| unique.insert(peer.clone()))
                .map(|peer| Entry {
                    peer,
                    state: State::Startup,
                })
                .collect(),
            queue: ReconnectQueue::default(),
        }
    }

    /// Reconcile followed endpoints from retained state, never from possibly
    /// lost lifecycle broadcasts. A new establishment resets backoff even when
    /// the session has already ended in the same coalesced snapshot.
    fn reconcile(&mut self, states: &States, now: Instant) {
        for (i, entry) in self.entries.iter_mut().enumerate() {
            let State::Following { addr, seen } = &mut entry.state else {
                continue;
            };
            if let Some(state) = states.get(addr) {
                if state.establishment_count != *seen {
                    *seen = state.establishment_count;
                    self.queue.forget(&i);
                }
                if state.active_sessions > 0 {
                    continue;
                }
            }
            // Stop following once the session ends or its history is evicted;
            // the next attempt resolves names and zones afresh.
            entry.state = State::Waiting;
            self.queue.schedule(i, now);
        }
    }

    /// Never-attempted peers first, then due retries oldest first, up to
    /// `limit`. Excess due peers stay queued without advancing their backoff.
    fn take_ready(&mut self, now: Instant, limit: usize) -> Vec<usize> {
        let mut ready: Vec<_> = (0..self.entries.len())
            .filter(|&i| self.entries[i].state == State::Startup)
            .take(limit)
            .collect();
        ready.extend(self.queue.take_due_limited(now, limit - ready.len()));
        for &i in &ready {
            self.entries[i].state = State::Connecting;
            self.queue.suspend(&i);
        }
        ready
    }

    fn completed(&mut self, i: usize, result: Result<Attempt, Failure>, now: Instant) {
        let entry = &mut self.entries[i];
        match result {
            Ok(Attempt::Dialed { addr, seen }) => {
                tracing::debug!(peer = %entry.peer, %addr, "transport connected; awaiting DLEP initialization");
                entry.state = State::Following { addr, seen };
            }
            Ok(Attempt::Covered { addr, seen }) => {
                tracing::debug!(peer = %entry.peer, %addr, "endpoint has a session under another configured identity; waiting for it to end");
                entry.state = State::Following { addr, seen };
            }
            Err(failure) => {
                entry.state = State::Waiting;
                self.queue.schedule(i, now);
                match failure {
                    Failure::Busy => {
                        tracing::debug!(peer = %entry.peer, "endpoints are being connected under another configured identity; will retry with backoff")
                    }
                    Failure::Daemon(error) => {
                        tracing::warn!(peer = %entry.peer, %error, "connection failed; will retry with backoff")
                    }
                }
            }
        }
    }
}

pub async fn run(
    daemon: &RouterDaemon,
    events: &mut Receiver<DaemonEvent>,
    addresses: &[SocketAddr],
    names: &[NamedPeer],
    scoped: &[ScopedPeer],
) {
    run_with_resolver(
        daemon,
        events,
        addresses,
        names,
        scoped,
        &system_resolve,
        &ScopedPeer::resolve,
    )
    .await;
}

async fn run_with_resolver<D: Dialer>(
    dialer: &D,
    events: &mut Receiver<DaemonEvent>,
    addresses: &[SocketAddr],
    names: &[NamedPeer],
    scoped: &[ScopedPeer],
    resolve: &Resolver,
    zone: &ZoneResolver,
) {
    let mut schedule = Schedule::new(
        addresses
            .iter()
            .copied()
            .map(PeerEndpoint::Address)
            .chain(names.iter().cloned().map(PeerEndpoint::Named))
            .chain(scoped.iter().cloned().map(PeerEndpoint::Scoped)),
    );
    let reservations = Reservations::default();
    let unadmitted = Arc::new(AtomicUsize::new(0));
    let mut pending: Vec<Pending<'_>> = Vec::new();
    let mut states = dialer.connection_states();
    // At most eight attempts run at once. Attempts still resolving count
    // against the session budget too, since they will claim a permit to dial.
    let capacity = |pending: &Vec<Pending<'_>>| {
        (MAX_CONNECT_ATTEMPTS - pending.len()).min(
            dialer
                .connection_capacity()
                .saturating_sub(unadmitted.load(Ordering::Relaxed)),
        )
    };
    loop {
        let now = Instant::now();
        schedule.reconcile(&states.borrow_and_update(), now);
        for i in schedule.take_ready(now, capacity(&pending)) {
            let peer = schedule.entries[i].peer.clone();
            tracing::info!(%peer, "connecting to configured modem");
            let admission = Admission::new(&unadmitted);
            let attempt = connect(dialer, peer, reservations.clone(), admission, resolve, zone);
            pending.push((i, Box::pin(attempt)));
        }
        // A full pool waits for completion rather than spinning on past deadlines.
        let next_due = if capacity(&pending) > 0 {
            schedule.queue.next_due()
        } else {
            None
        };
        let timer = async {
            match next_due {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = timer => {},
            _ = dialer.wait_for_connection_capacity(), if dialer.connection_capacity() == 0 => {},
            changed = states.changed() => { if changed.is_err() { return; } },
            (i, result) = poll_fn(|cx| {
                // Poll every attempt so a stalled endpoint cannot block others.
                for index in 0..pending.len() {
                    if let Poll::Ready(result) = pending[index].1.as_mut().poll(cx) {
                        let (i, _) = pending.remove(index);
                        return Poll::Ready((i, result));
                    }
                }
                Poll::Pending
            }) => schedule.completed(i, result, Instant::now()),
            event = events.recv() => match event {
                Ok(DaemonEvent::SessionUp { peer, .. }) => tracing::info!(addr = %peer.addr, tls = peer.is_tls, "session up"),
                Ok(DaemonEvent::SessionDown { peer, reason, .. }) => tracing::info!(addr = %peer.addr, ?reason, "session down"),
                Ok(_) => {},
                Err(RecvError::Lagged(skipped)) => tracing::warn!(skipped, "event stream lagged; reconnect state is tracked separately"),
                Err(RecvError::Closed) => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlep_daemon::{ModemConfig, ModemDaemon, RouterConfig};
    use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_dns, server_config_for};
    use std::{sync::atomic::AtomicU64, time::Duration};
    use tokio::sync::broadcast;

    /// Endpoints in `up` accept and initialize at once; others refuse.
    struct FakeDaemon {
        states: watch::Sender<States>,
        up: Mutex<HashSet<SocketAddr>>,
        dials: Mutex<Vec<(SocketAddr, std::time::Duration)>>,
        generation: AtomicU64,
        start: Instant,
    }

    impl FakeDaemon {
        fn new(up: impl IntoIterator<Item = SocketAddr>) -> Self {
            Self {
                states: watch::channel(States::new()).0,
                up: Mutex::new(up.into_iter().collect()),
                dials: Mutex::default(),
                generation: AtomicU64::new(0),
                start: Instant::now(),
            }
        }

        fn set_up(&self, addr: SocketAddr, up: bool) {
            let mut endpoints = self.up.lock().unwrap();
            if up {
                endpoints.insert(addr);
            } else {
                endpoints.remove(&addr);
            }
        }

        /// The modem restarts: its session ends and connections are refused.
        fn restart(&self, addr: SocketAddr) {
            self.set_up(addr, false);
            self.states.send_modify(|states| {
                states.get_mut(&addr).unwrap().active_sessions = 0;
            });
        }

        fn evict(&self, addr: SocketAddr) {
            self.states.send_modify(|states| {
                states.remove(&addr);
            });
        }

        fn dials_to(&self, addr: SocketAddr) -> Vec<Duration> {
            let dials = self.dials.lock().unwrap();
            dials.iter().filter(|d| d.0 == addr).map(|d| d.1).collect()
        }
    }

    impl Dialer for FakeDaemon {
        fn connection_states(&self) -> watch::Receiver<States> {
            self.states.subscribe()
        }

        fn connection_capacity(&self) -> usize {
            64
        }

        fn wait_for_connection_capacity(&self) -> impl Future<Output = ()> + Send {
            std::future::pending()
        }

        fn dial(
            &self,
            addr: SocketAddr,
            _: Option<&str>,
        ) -> impl Future<Output = Result<(), DaemonError>> + Send {
            self.dials
                .lock()
                .unwrap()
                .push((addr, self.start.elapsed()));
            let result = if self.up.lock().unwrap().contains(&addr) {
                let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
                self.states.send_modify(|states| {
                    let state = states.entry(addr).or_default();
                    state.active_sessions += 1;
                    state.establishment_count = generation;
                });
                Ok(())
            } else {
                Err(DaemonError::Io(
                    std::io::ErrorKind::ConnectionRefused.into(),
                ))
            };
            std::future::ready(result)
        }
    }

    fn secs(values: &[u64]) -> Vec<Duration> {
        values.iter().copied().map(Duration::from_secs).collect()
    }

    /// Dial times of a numeric peer whose modem restarts at 10 s and returns
    /// at 16 s, then drops again with its history evicted at 30 s. Returns
    /// them with the number of dials made for the configured DNS name.
    async fn numeric_retry_schedule(
        names: &[NamedPeer],
        scoped: &[ScopedPeer],
    ) -> (Vec<Duration>, usize) {
        let numeric: SocketAddr = "192.0.2.1:854".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:854".parse().unwrap();
        let fake = FakeDaemon::new([numeric]);
        let (_feed, mut events) = broadcast::channel(1);
        let resolve =
            move |_: NamedPeer| -> Resolution { Box::pin(async move { Ok(vec![other]) }) };
        let zone = |_: &ScopedPeer| -> std::io::Result<SocketAddr> {
            Err(std::io::ErrorKind::NotFound.into())
        };
        let script = async {
            let at = |secs| fake.start + Duration::from_secs(secs);
            tokio::time::sleep_until(at(10)).await;
            fake.restart(numeric);
            tokio::time::sleep_until(at(16)).await;
            fake.set_up(numeric, true);
            tokio::time::sleep_until(at(30)).await;
            fake.evict(numeric);
            tokio::time::sleep_until(at(40)).await;
        };
        let addresses = [numeric];
        tokio::select! {
            () = run_with_resolver(&fake, &mut events, &addresses, names, scoped, &resolve, &zone) => {
                panic!("driver stopped")
            }
            () = script => {}
        }
        (fake.dials_to(numeric), fake.dials_to(other).len())
    }

    #[tokio::test(start_paused = true)]
    async fn numeric_reconnects_identically_with_named_and_scoped_peers_configured() {
        let alone = numeric_retry_schedule(&[], &[]).await;
        // Connected at once; refused at 11 s and 13 s (1 s, then 2 s), back at
        // 17 s (4 s). Establishment reset the history, so eviction at 30 s
        // waits the base delay again.
        assert_eq!(alone, (secs(&[0, 11, 13, 17, 31]), 0));
        let name = NamedPeer::new("radio.test.invalid", 854).unwrap();
        let zone = ScopedPeer::new("fe80::1".parse().unwrap(), "dlep-test", 854).unwrap();
        let (mixed, named_dials) = numeric_retry_schedule(&[name], &[zone]).await;
        assert_eq!(mixed, alone.0);
        assert!(named_dials > 1, "the DNS peer must keep retrying meanwhile");
    }

    #[tokio::test(start_paused = true)]
    async fn alias_of_an_active_endpoint_follows_it_without_retrying() {
        let addr: SocketAddr = "192.0.2.1:854".parse().unwrap();
        let fake = FakeDaemon::new([addr]);
        let (_feed, mut events) = broadcast::channel(1);
        let resolutions = Arc::new(AtomicUsize::new(0));
        let counter = resolutions.clone();
        let resolve = move |_: NamedPeer| -> Resolution {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(vec![addr]) })
        };
        let name = NamedPeer::new("alias.test.invalid", addr.port()).unwrap();
        let script = async {
            tokio::time::sleep(Duration::from_secs(60)).await;
            assert_eq!(fake.dials_to(addr), secs(&[0]));
            assert_eq!(resolutions.load(Ordering::SeqCst), 1);
            // Both identities retry after the base delay; the alias follows again.
            fake.restart(addr);
            fake.set_up(addr, true);
            tokio::time::sleep(Duration::from_secs(60)).await;
        };
        let (addresses, names) = ([addr], [name]);
        tokio::select! {
            () = run_with_resolver(&fake, &mut events, &addresses, &names, &[], &resolve, &ScopedPeer::resolve) => {
                panic!("driver stopped")
            }
            () = script => {}
        }
        assert_eq!(fake.dials_to(addr), secs(&[0, 61]));
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
    }

    async fn up(events: &mut Receiver<DaemonEvent>) -> SocketAddr {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let DaemonEvent::SessionUp { peer, .. } = events.recv().await.unwrap() {
                    return peer.addr;
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn scoped_retries_refresh_failed_lookups_and_reconnect_without_dns() {
        use dlep_net::tls::test_helpers::self_signed_for_ip;
        let pki = self_signed_for_ip("fe80::1".parse().unwrap());
        let server = server_config_for(pki.cert_der, pki.key_der);
        let mut config = ModemConfig::default();
        config.shared.network.bind_addr = "fe80::1".parse().unwrap();
        config.shared.network.interface = Some("dlep-test".into());
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let first = ModemDaemon::builder()
            .config(config.clone())
            .with_rustls_server(server.clone())
            .spawn()
            .await
            .unwrap();
        let address = first.local_addr();
        config.shared.network.tcp_port = address.port();
        let mut router_config = RouterConfig::default();
        router_config.limits.max_sessions = 4;
        let router = Arc::new(
            RouterDaemon::builder()
                .config(router_config)
                .with_rustls_client(client_config_for(pki.roots))
                .spawn()
                .await
                .unwrap(),
        );
        let mut events = router.subscribe();
        let driver = router.clone();
        let lookups = Arc::new(AtomicUsize::new(0));
        let seen = lookups.clone();
        let task = tokio::spawn(async move {
            let dns = |_: NamedPeer| -> Resolution { panic!("a named zone must never enter DNS") };
            let zone = move |peer: &ScopedPeer| {
                if seen.fetch_add(1, Ordering::SeqCst) == 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "interface not yet present",
                    ))
                } else {
                    peer.resolve()
                }
            };
            let peer =
                ScopedPeer::new("fe80::1".parse().unwrap(), "dlep-test", address.port()).unwrap();
            run_with_resolver(
                &*driver,
                &mut driver.subscribe(),
                &[],
                &[],
                &[peer],
                &dns,
                &zone,
            )
            .await;
        });
        assert_eq!(up(&mut events).await, address);
        assert!(lookups.load(Ordering::SeqCst) >= 2);
        first.shutdown().await.unwrap();
        let second = ModemDaemon::builder()
            .config(config)
            .with_rustls_server(server)
            .spawn()
            .await
            .unwrap();
        assert_eq!(up(&mut events).await, address);
        assert!(lookups.load(Ordering::SeqCst) >= 3);
        assert_eq!(
            router.connection_states().borrow()[&address].active_sessions,
            1
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        Arc::try_unwrap(router)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        second.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn retries_resolve_again_and_keep_tls_identity_when_the_address_changes() {
        let pki = self_signed_for_dns("radio.test.invalid");
        let server = server_config_for(pki.cert_der, pki.key_der);
        let mut config = ModemConfig::default();
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let a = ModemDaemon::builder()
            .config(config.clone())
            .with_rustls_server(server.clone())
            .spawn()
            .await
            .unwrap();
        config.shared.network.bind_addr = "::1".parse().unwrap();
        config.shared.network.tcp_port = a.local_addr().port();
        let b = ModemDaemon::builder()
            .config(config)
            .with_rustls_server(server)
            .spawn()
            .await
            .unwrap();
        let mut config = RouterConfig::default();
        config.limits.max_sessions = 1;
        config.limits.max_discovered_peers = 1;
        config.limits.peer_retention_secs = 1;
        let router = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .with_rustls_client(client_config_for(pki.roots))
                .spawn()
                .await
                .unwrap(),
        );
        let mut events = router.subscribe();
        let answer = Arc::new(Mutex::new(a.local_addr()));
        let calls = Arc::new(AtomicUsize::new(0));
        let driver = router.clone();
        let resolved = answer.clone();
        let counter = calls.clone();
        let port = a.local_addr().port();
        let task = tokio::spawn(async move {
            let resolve = move |peer: NamedPeer| -> Resolution {
                assert_eq!(peer.host(), "radio.test.invalid");
                assert_eq!(peer.port(), port);
                let attempt = counter.fetch_add(1, Ordering::SeqCst);
                let addr = *resolved.lock().unwrap();
                Box::pin(async move {
                    if attempt == 0 {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "temporary resolver failure",
                        ))
                    } else {
                        Ok(vec![addr])
                    }
                })
            };
            run_with_resolver(
                &*driver,
                &mut driver.subscribe(),
                &[],
                &[NamedPeer::new("radio.test.invalid", port).unwrap()],
                &[],
                &resolve,
                &ScopedPeer::resolve,
            )
            .await;
        });
        assert_eq!(up(&mut events).await, a.local_addr());
        *answer.lock().unwrap() = b.local_addr();
        a.shutdown().await.unwrap();
        assert_eq!(up(&mut events).await, b.local_addr());
        assert!(calls.load(Ordering::SeqCst) >= 3);
        assert_eq!(
            router.connection_states().borrow()[&b.local_addr()].active_sessions,
            1
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        Arc::try_unwrap(router)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        b.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn aliases_do_not_duplicate_active_numeric_sessions() {
        let mut config = ModemConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
        let addr = modem.local_addr();
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.limits.max_sessions = 4;
        let router = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let mut events = router.subscribe();
        let driver = router.clone();
        let (resolved, mut resolutions) = watch::channel(0usize);
        let task = tokio::spawn(async move {
            let resolve = move |_: NamedPeer| -> Resolution {
                resolved.send_modify(|count| *count += 1);
                Box::pin(async move { Ok(vec![addr]) })
            };
            let name = NamedPeer::new("alias.test.invalid", addr.port()).unwrap();
            run_with_resolver(
                &*driver,
                &mut driver.subscribe(),
                &[addr, addr],
                &[name.clone(), name],
                &[],
                &resolve,
                &ScopedPeer::resolve,
            )
            .await;
        });
        assert_eq!(up(&mut events).await, addr);
        // The alias first meets the numeric peer's reservation and retries
        // after the base delay; its second resolution finds the session active.
        // On this current-thread runtime the alias decides, and a duplicate
        // dial would claim budget, before this task observes the count.
        tokio::time::timeout(
            Duration::from_secs(10),
            resolutions.wait_for(|count| *count >= 2),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            router.connection_states().borrow()[&addr].active_sessions,
            1
        );
        assert_eq!(router.connection_capacity(), 3);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        Arc::try_unwrap(router)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
        modem.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn slow_resolution_is_bounded_and_cancelled_with_the_driver() {
        struct Resolving(Arc<AtomicUsize>);
        impl Drop for Resolving {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.limits.max_sessions = 2;
        let router = Arc::new(
            RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap(),
        );
        let active = Arc::new(AtomicUsize::new(0));
        let driver = router.clone();
        let counter = active.clone();
        let task = tokio::spawn(async move {
            let resolve = move |_: NamedPeer| -> Resolution {
                counter.fetch_add(1, Ordering::SeqCst);
                let guard = Resolving(counter.clone());
                Box::pin(async move {
                    let _guard = guard;
                    std::future::pending().await
                })
            };
            let names: Vec<_> = (0..20)
                .map(|i| NamedPeer::new(&format!("radio{i}.test.invalid"), 854).unwrap())
                .collect();
            run_with_resolver(
                &*driver,
                &mut driver.subscribe(),
                &[],
                &names,
                &[],
                &resolve,
                &ScopedPeer::resolve,
            )
            .await;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(active.load(Ordering::SeqCst), 2);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert!(router.connection_states().borrow().is_empty());
        Arc::try_unwrap(router)
            .ok()
            .unwrap()
            .shutdown()
            .await
            .unwrap();
    }
}
