//! Connection lifetime tracking, independent of the lossy event broadcast.

use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::watch;

/// Latest connection state for one modem endpoint. Retained after disconnect
/// so a subscriber can recover even if initialization and teardown both
/// happened while it was busy. Inactive non-static entries have bounded capacity
/// and retention; consumers must handle their disappearance from the snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerConnectionState {
    /// Registered session tasks, including initialization and termination.
    pub active_sessions: usize,
    /// Daemon-wide generation of the last successful DLEP initialization.
    /// It increases across eviction/re-admission, so coalesced snapshots cannot
    /// confuse a new session with an older incarnation of the same endpoint.
    /// A change resets reconnect backoff even when the corresponding session
    /// has already ended by the time the subscriber reads the snapshot.
    pub establishment_count: u64,
}

/// Bounded lifecycle history. Static peers are configuration-owned and exempt
/// from discovered-peer eviction; active entries are never evicted.
pub(crate) struct ConnectionRegistry {
    states: watch::Sender<HashMap<SocketAddr, PeerConnectionState>>,
    inner: std::sync::Mutex<History>,
    pinned: std::collections::HashSet<SocketAddr>,
    limits: crate::config::RouterLimits,
}

#[derive(Default)]
struct History {
    states: HashMap<SocketAddr, PeerConnectionState>,
    // Survives unsuccessful initialization retries; successful establishment
    // clears it, and the subsequent disconnect starts a new retention window.
    inactive_since: HashMap<SocketAddr, tokio::time::Instant>,
    next_establishment: u64,
}

impl ConnectionRegistry {
    pub(crate) fn new(
        limits: crate::config::RouterLimits,
        pinned: &[SocketAddr],
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            states: watch::channel(HashMap::new()).0,
            inner: Default::default(),
            pinned: pinned.iter().copied().collect(),
            limits,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<HashMap<SocketAddr, PeerConnectionState>> {
        self.states.subscribe()
    }

    fn prune_locked(&self, history: &mut History, now: tokio::time::Instant) -> bool {
        let before = history.states.len();
        history.states.retain(|peer, state| {
            self.pinned.contains(peer)
                || state.active_sessions > 0
                || history.inactive_since.get(peer).is_none_or(|at| {
                    now.duration_since(*at)
                        < std::time::Duration::from_secs(self.limits.peer_retention_secs.into())
                })
        });
        history
            .inactive_since
            .retain(|peer, _| history.states.contains_key(peer));
        history.states.len() != before
    }

    pub(crate) fn prune(&self) {
        let mut history = self.inner.lock().unwrap();
        if self.prune_locked(&mut history, tokio::time::Instant::now()) {
            self.states.send_replace(history.states.clone());
        }
    }

    pub(crate) fn register(
        self: &std::sync::Arc<Self>,
        peer: SocketAddr,
    ) -> Result<ConnectionTracker, crate::DaemonError> {
        let mut history = self.inner.lock().unwrap();
        let now = tokio::time::Instant::now();
        self.prune_locked(&mut history, now);
        if !history.states.contains_key(&peer)
            && !self.pinned.contains(&peer)
            && history
                .states
                .keys()
                .filter(|p| !self.pinned.contains(p))
                .count()
                >= self.limits.max_discovered_peers
        {
            let oldest = history
                .inactive_since
                .iter()
                .filter(|(p, _)| {
                    !self.pinned.contains(p) && history.states[*p].active_sessions == 0
                })
                .min_by_key(|(p, at)| (**at, **p))
                .map(|(p, _)| *p);
            if let Some(oldest) = oldest {
                history.states.remove(&oldest);
                history.inactive_since.remove(&oldest);
            } else {
                self.states.send_replace(history.states.clone());
                return Err(crate::DaemonError::PeerHistoryFull);
            }
        }
        if !history.states.contains_key(&peer) {
            history.inactive_since.insert(peer, now);
        }
        history.states.entry(peer).or_default().active_sessions += 1;
        self.states.send_replace(history.states.clone());
        Ok(ConnectionTracker {
            registry: self.clone(),
            peer,
        })
    }

    pub(crate) fn reap_periodically(self: &std::sync::Arc<Self>) -> HistoryReaper {
        let registry = std::sync::Arc::downgrade(self);
        HistoryReaper(tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let Some(registry) = registry.upgrade() else {
                    break;
                };
                registry.prune();
            }
        }))
    }
}

pub(crate) struct HistoryReaper(tokio::task::JoinHandle<()>);
impl Drop for HistoryReaper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Task-owned registration, including cancellation before the first poll.
pub(crate) struct ConnectionTracker {
    registry: std::sync::Arc<ConnectionRegistry>,
    peer: SocketAddr,
}

impl ConnectionTracker {
    pub(crate) fn established(&self) {
        let mut history = self.registry.inner.lock().unwrap();
        history.next_establishment += 1;
        let generation = history.next_establishment;
        history
            .states
            .get_mut(&self.peer)
            .unwrap()
            .establishment_count = generation;
        history.inactive_since.remove(&self.peer);
        self.registry.states.send_replace(history.states.clone());
    }
}

impl Drop for ConnectionTracker {
    fn drop(&mut self) {
        let mut history = self.registry.inner.lock().unwrap();
        let state = history.states.get_mut(&self.peer).unwrap();
        state.active_sessions -= 1;
        if state.active_sessions == 0 {
            history
                .inactive_since
                .entry(self.peer)
                .or_insert_with(tokio::time::Instant::now);
        }
        self.registry
            .prune_locked(&mut history, tokio::time::Instant::now());
        self.registry.states.send_replace(history.states.clone());
    }
}

type RouterAddress = (std::net::IpAddr, u32);
type RouterCounts = std::sync::Arc<std::sync::Mutex<HashMap<RouterAddress, usize>>>;

/// Modem-side TCP peers. Unlike reconnect history, entries disappear when the
/// last connection closes. UDP and TCP source ports differ, so match addresses
/// only, retaining the interface scope for IPv6 link-local addresses.
#[derive(Clone, Default)]
pub(crate) struct ConnectedRouters {
    peers: RouterCounts,
}

fn router_address(peer: SocketAddr) -> RouterAddress {
    match peer {
        SocketAddr::V6(v6) => {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                (v4.into(), 0)
            } else {
                (
                    (*v6.ip()).into(),
                    if v6.ip().is_unicast_link_local() {
                        v6.scope_id()
                    } else {
                        0
                    },
                )
            }
        }
        SocketAddr::V4(v4) => ((*v4.ip()).into(), 0),
    }
}

impl ConnectedRouters {
    pub(crate) fn contains(&self, peer: SocketAddr) -> bool {
        self.peers
            .lock()
            .unwrap()
            .contains_key(&router_address(peer))
    }

    pub(crate) fn register(&self, peer: SocketAddr) -> RouterConnection {
        let address = router_address(peer);
        *self.peers.lock().unwrap().entry(address).or_default() += 1;
        RouterConnection {
            routers: self.clone(),
            address,
        }
    }
}

/// Held from TCP accept through TLS, initialization, and session teardown.
/// Cancellation and error exits release registration without relying on events.
pub(crate) struct RouterConnection {
    routers: ConnectedRouters,
    address: RouterAddress,
}

impl Drop for RouterConnection {
    fn drop(&mut self) {
        let mut peers = self.routers.peers.lock().unwrap();
        let count = peers.get_mut(&self.address).unwrap();
        *count -= 1;
        if *count == 0 {
            peers.remove(&self.address);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(port: u16) -> SocketAddr {
        ([127, 0, 0, 1], port).into()
    }

    #[test]
    fn churn_evicts_inactive_discovered_peers_but_retains_active_and_static_entries() {
        let pinned = endpoint(1);
        let registry = ConnectionRegistry::new(
            crate::RouterLimits {
                max_discovered_peers: 2,
                ..Default::default()
            },
            &[pinned],
        );
        drop(registry.register(pinned).unwrap());
        let active = registry.register(endpoint(2)).unwrap();
        active.established();
        let states = registry.subscribe();
        for port in 3..1003 {
            let guard = registry.register(endpoint(port)).unwrap();
            guard.established();
            drop(guard);
            let snapshot = states.borrow();
            assert_eq!(snapshot.len(), 3);
            assert!(snapshot.contains_key(&pinned));
            assert_eq!(snapshot[&endpoint(2)].active_sessions, 1);
            assert!(snapshot.contains_key(&endpoint(port)));
            assert!(registry.inner.lock().unwrap().inactive_since.len() <= 2);
        }
        drop(active);
    }

    #[test]
    fn full_active_history_refuses_new_peers_and_releases_capacity_on_drop() {
        let registry = ConnectionRegistry::new(
            crate::RouterLimits {
                max_discovered_peers: 1,
                ..Default::default()
            },
            &[],
        );
        let active = registry.register(endpoint(1)).unwrap();
        assert!(matches!(
            registry.register(endpoint(2)),
            Err(crate::DaemonError::PeerHistoryFull)
        ));
        drop(active);
        let next = registry.register(endpoint(2)).unwrap();
        assert_eq!(registry.subscribe().borrow().len(), 1);
        drop(next);
    }

    #[test]
    fn eviction_and_readmission_preserve_unique_establishment_generations() {
        let registry = ConnectionRegistry::new(
            crate::RouterLimits {
                max_discovered_peers: 1,
                ..Default::default()
            },
            &[],
        );
        let first = registry.register(endpoint(1)).unwrap();
        first.established();
        let states = registry.subscribe();
        let generation = states.borrow()[&endpoint(1)].establishment_count;
        drop(first);
        drop(registry.register(endpoint(2)).unwrap());
        let new = registry.register(endpoint(1)).unwrap();
        new.established();
        drop(new);
        // Subscriber misses eviction and re-admission but can still reset backoff.
        assert!(states.borrow()[&endpoint(1)].establishment_count > generation);
    }

    #[tokio::test(start_paused = true)]
    async fn unsuccessful_retries_do_not_extend_retention_and_static_peers_do_not_expire() {
        use tokio::time::{Duration, advance};
        let registry = ConnectionRegistry::new(
            crate::RouterLimits {
                peer_retention_secs: 10,
                ..Default::default()
            },
            &[endpoint(1)],
        );
        drop(registry.register(endpoint(1)).unwrap());
        drop(registry.register(endpoint(2)).unwrap());
        advance(Duration::from_secs(9)).await;
        let retry = registry.register(endpoint(2)).unwrap();
        advance(Duration::from_secs(2)).await;
        registry.prune();
        assert_eq!(
            registry.subscribe().borrow()[&endpoint(2)].active_sessions,
            1
        );
        drop(retry);
        let snapshot = registry.subscribe();
        assert_eq!(snapshot.borrow().len(), 1);
        assert!(snapshot.borrow().contains_key(&endpoint(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn establishment_restarts_retention_at_disconnect_and_reaper_expires_idle_history() {
        use tokio::time::{Duration, advance};
        let registry = ConnectionRegistry::new(
            crate::RouterLimits {
                peer_retention_secs: 10,
                ..Default::default()
            },
            &[],
        );
        let _reaper = registry.reap_periodically();
        let guard = registry.register(endpoint(1)).unwrap();
        advance(Duration::from_secs(9)).await;
        guard.established();
        advance(Duration::from_secs(30)).await;
        assert_eq!(
            registry.subscribe().borrow()[&endpoint(1)].active_sessions,
            1
        );
        drop(guard);
        advance(Duration::from_secs(9)).await;
        registry.prune();
        assert!(registry.subscribe().borrow().contains_key(&endpoint(1)));
        advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(registry.subscribe().borrow().is_empty());
    }

    #[test]
    fn discovery_identity_ignores_ports_and_ipv6_flow_but_preserves_link_scope() {
        let peers = ConnectedRouters::default();
        let v4 = peers.register("127.0.0.1:1234".parse().unwrap());
        assert!(peers.contains("127.0.0.1:5678".parse().unwrap()));
        assert!(peers.contains("[::ffff:127.0.0.1]:5678".parse().unwrap()));
        assert!(!peers.contains("127.0.0.2:5678".parse().unwrap()));
        let link = peers.register("[fe80::1%3]:1234".parse().unwrap());
        assert!(
            peers.contains(
                std::net::SocketAddrV6::new("fe80::1".parse().unwrap(), 5678, 42, 3).into()
            )
        );
        assert!(!peers.contains("[fe80::1%4]:5678".parse().unwrap()));
        let duplicate = peers.register("[fe80::1%3]:4321".parse().unwrap());
        drop(link);
        assert!(peers.contains("[fe80::1%3]:5678".parse().unwrap()));
        drop(duplicate);
        drop(v4);
        assert!(peers.peers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cancelling_an_unpolled_handshake_releases_discovery_suppression() {
        let peers = ConnectedRouters::default();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let guard = peers.register(peer);
        let task = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!peers.contains(peer));
        assert!(peers.peers.lock().unwrap().is_empty());
    }

    #[test]
    fn closing_one_session_does_not_hide_another_at_the_same_endpoint() {
        let registry = ConnectionRegistry::new(Default::default(), &[]);
        let peer = "127.0.0.1:854".parse().unwrap();
        let first = registry.register(peer).unwrap();
        let second = registry.register(peer).unwrap();
        first.established();
        drop(first);
        // Changes survive with no subscribers, and a second pending session
        // continues to suppress duplicate connection attempts.
        let receiver = registry.subscribe();
        assert_eq!(
            receiver.borrow()[&peer],
            PeerConnectionState {
                active_sessions: 1,
                establishment_count: 1,
            }
        );
        second.established();
        drop(second);
        assert_eq!(
            receiver.borrow()[&peer],
            PeerConnectionState {
                active_sessions: 0,
                establishment_count: 2,
            }
        );
        assert_eq!(receiver.borrow().len(), 1);
    }
}
