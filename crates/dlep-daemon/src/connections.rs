//! Connection lifetime tracking, independent of the lossy event broadcast.

use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::watch;

/// Latest connection state for one modem endpoint. Retained after disconnect
/// so a subscriber can recover even if initialization and teardown both
/// happened while it was busy. Storage is one entry per contacted endpoint,
/// not one entry per session or event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PeerConnectionState {
    /// Registered session tasks, including initialization and termination.
    pub active_sessions: usize,
    /// Number of successful DLEP initializations, retained across disconnects.
    /// A change resets reconnect backoff even when the corresponding session
    /// has already ended by the time the subscriber reads the snapshot.
    pub establishment_count: u64,
}

pub(crate) type ConnectionTx = watch::Sender<HashMap<SocketAddr, PeerConnectionState>>;

/// Registration guard owned by the session future, including before its first
/// poll. Dropping a cancelled or failed task always updates the snapshot.
pub(crate) struct ConnectionTracker {
    states: ConnectionTx,
    peer: SocketAddr,
}

impl ConnectionTracker {
    pub(crate) fn new(states: ConnectionTx, peer: SocketAddr) -> Self {
        states.send_modify(|states| states.entry(peer).or_default().active_sessions += 1);
        Self { states, peer }
    }

    pub(crate) fn established(&self) {
        self.states.send_modify(|states| {
            states.get_mut(&self.peer).unwrap().establishment_count += 1;
        });
    }
}

impl Drop for ConnectionTracker {
    fn drop(&mut self) {
        self.states.send_modify(|states| {
            states.get_mut(&self.peer).unwrap().active_sessions -= 1;
        });
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
        let (states, _) = watch::channel(HashMap::new());
        let peer = "127.0.0.1:854".parse().unwrap();
        let first = ConnectionTracker::new(states.clone(), peer);
        let second = ConnectionTracker::new(states.clone(), peer);
        first.established();
        drop(first);
        // Changes survive with no subscribers, and a second pending session
        // continues to suppress duplicate connection attempts.
        let receiver = states.subscribe();
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
