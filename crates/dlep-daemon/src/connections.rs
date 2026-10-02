//! Retained router connection state, independent of the lossy event broadcast.

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

#[cfg(test)]
mod tests {
    use super::*;

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
