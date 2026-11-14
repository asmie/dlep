//! Retained local protocol state, independent of the public event broadcast.

use std::collections::HashMap;
use std::sync::Arc;

use dlep_core::ExtensionId;
use dlep_ext::SessionId;
use tokio::sync::watch;

use crate::{DestinationAddrs, DestinationId, LinkMetrics, PeerInfo};

/// Latest state of all established sessions in one daemon. Read the initial
/// value as well as changes. Clone it and release the watch borrow before awaiting.
/// Updates may coalesce; this is current state, not a history of events or
/// command outcomes. Session IDs are unique for the lifetime of this daemon.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DaemonSnapshot {
    /// Increases on each visible state change, including session removal.
    pub generation: u64,
    /// Initializing sessions are absent. Established sessions remain until
    /// termination completes or their task exits. Closed sessions are removed.
    /// Arc values make cloning a snapshot independent of destination counts.
    pub sessions: HashMap<SessionId, Arc<SessionSnapshot>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Established,
    Terminating,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationPhase {
    /// Modem is awaiting the router's Destination Up Response.
    PendingUp,
    Up,
    /// Modem retains knowledge, but the router declined or withdrew interest.
    Withdrawn,
    /// A locally initiated Destination Down is awaiting its response.
    PendingDown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationSnapshot {
    pub phase: DestinationPhase,
    /// Effective local values, including changes awaiting acknowledgement.
    pub metrics: LinkMetrics,
    pub addresses: DestinationAddrs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSnapshot {
    pub peer: PeerInfo,
    pub negotiated_extensions: Vec<ExtensionId>,
    pub phase: SessionPhase,
    /// Effective modem metrics (received on routers, local on modems).
    pub metrics: LinkMetrics,
    /// Addresses advertised by the remote peer, not this daemon's addresses.
    pub peer_addresses: DestinationAddrs,
    pub destinations: HashMap<DestinationId, DestinationSnapshot>,
}

/// Updated synchronously by session tasks before public events and command
/// receipts. Never reconstructed by consuming the lossy event channel.
pub(crate) struct StateRegistry {
    state: watch::Sender<DaemonSnapshot>,
}

impl StateRegistry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: watch::channel(DaemonSnapshot::default()).0,
        })
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<DaemonSnapshot> {
        self.state.subscribe()
    }

    pub(crate) fn update(&self, id: SessionId, session: SessionSnapshot) {
        self.state.send_if_modified(|state| {
            if state.sessions.get(&id).is_some_and(|old| **old == session) {
                return false;
            }
            state.sessions.insert(id, Arc::new(session));
            state.generation = state
                .generation
                .checked_add(1)
                .expect("state generation overflow");
            true
        });
    }

    pub(crate) fn remove(&self, id: SessionId) {
        self.state.send_if_modified(|state| {
            if state.sessions.remove(&id).is_none() {
                return false;
            }
            state.generation = state
                .generation
                .checked_add(1)
                .expect("state generation overflow");
            true
        });
    }
}
