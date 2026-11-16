//! Static connections keyed by configured identity, rather than DNS answers.
//! Numeric-only configurations retain the existing discovery-capable driver.

use std::{
    collections::{BTreeSet, HashSet},
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Instant,
};

use dlep_daemon::{
    DaemonError, DaemonEvent, NamedPeer, PeerConnectionState, PeerEndpoint, RouterDaemon,
};
use dlep_net::transport::{HOST_CONNECT_TIMEOUT, MAX_RESOLVED_ENDPOINTS};
use tokio::sync::broadcast::{Receiver, error::RecvError};

use crate::{ReconnectQueue, connect::MAX_CONNECT_ATTEMPTS};

struct Entry {
    peer: PeerEndpoint,
    endpoint: Option<SocketAddr>,
    seen: u64,
    retries: u32,
    tried: bool,
    pending: bool,
    due: Option<Instant>,
}

impl Entry {
    fn schedule(&mut self, now: Instant) {
        self.due
            .get_or_insert_with(|| now + ReconnectQueue::backoff_for(self.retries));
    }

    fn reconcile(&mut self, state: Option<&PeerConnectionState>, now: Instant) {
        if self.pending || self.endpoint.is_none() {
            return;
        }
        if let Some(state) = state {
            if state.establishment_count != self.seen {
                self.seen = state.establishment_count;
                self.retries = 0;
            }
            if state.active_sessions > 0 {
                self.due = None;
                return;
            }
        }
        // Stop following an old answer once its session ends. A different
        // configured identity may later connect to the same numeric address.
        self.endpoint = None;
        self.schedule(now);
    }
}

struct Connected {
    addr: SocketAddr,
    baseline: u64,
}
type Attempt<'a> = (
    usize,
    Pin<Box<dyn Future<Output = Result<Connected, DaemonError>> + Send + 'a>>,
);
type Reservations = Arc<Mutex<HashSet<SocketAddr>>>;
type Resolution = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;
type Resolver = dyn Fn(NamedPeer) -> Resolution + Send + Sync;

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

async fn connect(
    daemon: &RouterDaemon,
    peer: PeerEndpoint,
    reservations: Reservations,
    resolve: &Resolver,
) -> Result<Connected, DaemonError> {
    let work = async {
        let addresses = match &peer {
            PeerEndpoint::Address(addr) => vec![*addr],
            PeerEndpoint::Named(name) => resolve(name.clone()).await?,
        };
        let states = daemon.connection_states();
        let mut error = DaemonError::Config("peer has no available addresses".into());
        for addr in addresses {
            let baseline = {
                let state = states.borrow();
                if state.get(&addr).is_some_and(|s| s.active_sessions > 0) {
                    continue;
                }
                state.get(&addr).map_or(0, |s| s.establishment_count)
            };
            if !reservations.lock().unwrap().insert(addr) {
                continue;
            }
            let _reservation = ReservedAddress {
                addr,
                reservations: reservations.clone(),
            };
            let result = match &peer {
                PeerEndpoint::Address(_) => daemon.connect_static(addr).await,
                PeerEndpoint::Named(name) => {
                    daemon
                        .connect_static_with_server_name(addr, name.host())
                        .await
                }
            };
            match result {
                Ok(()) => return Ok(Connected { addr, baseline }),
                Err(DaemonError::SessionLimitReached) => {
                    return Err(DaemonError::SessionLimitReached);
                }
                Err(failed) => error = failed,
            }
        }
        Err(error)
    };
    tokio::time::timeout(HOST_CONNECT_TIMEOUT, work)
        .await
        .map_err(|_| {
            DaemonError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "static peer connection timed out",
            ))
        })?
}

pub async fn run(
    daemon: &RouterDaemon,
    events: &mut Receiver<DaemonEvent>,
    addresses: &[SocketAddr],
    names: &[NamedPeer],
) {
    run_with_resolver(daemon, events, addresses, names, &system_resolve).await;
}

async fn run_with_resolver(
    daemon: &RouterDaemon,
    events: &mut Receiver<DaemonEvent>,
    addresses: &[SocketAddr],
    names: &[NamedPeer],
    resolve: &Resolver,
) {
    let peers: BTreeSet<_> = addresses
        .iter()
        .copied()
        .map(PeerEndpoint::Address)
        .chain(names.iter().cloned().map(PeerEndpoint::Named))
        .collect();
    let mut entries: Vec<_> = peers
        .into_iter()
        .map(|peer| Entry {
            peer,
            endpoint: None,
            seen: 0,
            retries: 0,
            tried: false,
            pending: false,
            due: Some(Instant::now()),
        })
        .collect();
    let reservations = Reservations::default();
    let mut attempts: Vec<Attempt<'_>> = Vec::new();
    let mut states = daemon.connection_states();
    loop {
        let now = Instant::now();
        {
            let snapshot = states.borrow_and_update();
            for entry in &mut entries {
                entry.reconcile(entry.endpoint.and_then(|addr| snapshot.get(&addr)), now);
            }
        }
        // Treat resolution futures as occupied slots too. TCP/TLS permits are
        // also counted by the daemon, so this may conservatively defer work.
        let capacity = MAX_CONNECT_ATTEMPTS
            .min(daemon.connection_capacity())
            .saturating_sub(attempts.len());
        let mut due: Vec<_> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| entry.due.filter(|at| *at <= now).map(|at| (at, i)))
            .collect();
        due.sort();
        for (_, i) in due.into_iter().take(capacity) {
            let entry = &mut entries[i];
            if entry.tried {
                entry.retries = entry.retries.saturating_add(1);
            }
            entry.tried = true;
            entry.pending = true;
            entry.due = None;
            tracing::info!(peer = %entry.peer, "connecting to configured modem");
            attempts.push((
                i,
                Box::pin(connect(
                    daemon,
                    entry.peer.clone(),
                    reservations.clone(),
                    resolve,
                )),
            ));
        }
        let next_due = if attempts.len() < MAX_CONNECT_ATTEMPTS.min(daemon.connection_capacity()) {
            entries.iter().filter_map(|entry| entry.due).min()
        } else {
            None
        };
        let timer = async {
            match next_due {
                Some(at) => tokio::time::sleep_until(at.into()).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = timer => {},
            _ = daemon.wait_for_connection_capacity(), if daemon.connection_capacity() == 0 => {},
            changed = states.changed() => { if changed.is_err() { return; } },
            (i, result) = poll_fn(|cx| {
                for index in 0..attempts.len() {
                    if let Poll::Ready(result) = attempts[index].1.as_mut().poll(cx) {
                        let (i, _) = attempts.remove(index);
                        return Poll::Ready((i, result));
                    }
                }
                Poll::Pending
            }) => {
                let entry = &mut entries[i];
                entry.pending = false;
                match result {
                    Ok(connected) => {
                        entry.endpoint = Some(connected.addr);
                        entry.seen = connected.baseline;
                    }
                    Err(error) => {
                        entry.endpoint = None;
                        entry.schedule(Instant::now());
                        tracing::warn!(peer = %entry.peer, %error, "connection failed; will retry with backoff");
                    }
                }
            },
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
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

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
                &driver,
                &mut driver.subscribe(),
                &[],
                &[NamedPeer::new("radio.test.invalid", port).unwrap()],
                &resolve,
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
        let task = tokio::spawn(async move {
            let resolve =
                move |_: NamedPeer| -> Resolution { Box::pin(async move { Ok(vec![addr]) }) };
            let name = NamedPeer::new("alias.test.invalid", addr.port()).unwrap();
            run_with_resolver(
                &driver,
                &mut driver.subscribe(),
                &[addr, addr],
                &[name.clone(), name],
                &resolve,
            )
            .await;
        });
        assert_eq!(up(&mut events).await, addr);
        tokio::time::sleep(Duration::from_millis(1200)).await;
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
            run_with_resolver(&driver, &mut driver.subscribe(), &[], &names, &resolve).await;
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
