use std::collections::HashMap;

use dlep_core::MacAddress;

use crate::events::{FsmAction, FsmEvent};
use crate::transaction::TransactionTracker;

/// Router-side session states (RFC 8175 §7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterSessionState {
    Closed,
    TcpConnecting,
    SessionInitPending,
    InSession,
    Terminating,
    Terminated,
}

#[derive(Debug)]
pub struct RouterSessionFsm {
    pub state: RouterSessionState,
    pub tx: TransactionTracker,
    pub destinations: HashMap<MacAddress, DestinationState>,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationState {
    pub up: bool,
}

impl Default for RouterSessionFsm {
    fn default() -> Self {
        Self {
            state: RouterSessionState::Closed,
            tx: TransactionTracker::default(),
            destinations: HashMap::new(),
        }
    }
}

impl RouterSessionFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        // Real transitions arrive milestone-by-milestone. The skeleton is
        // intentionally empty so downstream crates can be wired end-to-end.
        let _ = event;
        Vec::new()
    }
}
