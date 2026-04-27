use std::collections::HashMap;

use dlep_core::MacAddress;

use crate::events::{FsmAction, FsmEvent};
use crate::transaction::TransactionTracker;

/// Modem-side session states (RFC 8175 §7.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModemSessionState {
    Listening,
    AwaitingSessionInit,
    InSession,
    Terminating,
    Terminated,
}

#[derive(Debug)]
pub struct ModemSessionFsm {
    pub state: ModemSessionState,
    pub tx: TransactionTracker,
    pub destinations: HashMap<MacAddress, DestinationState>,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationState {
    pub announced: bool,
}

impl Default for ModemSessionFsm {
    fn default() -> Self {
        Self {
            state: ModemSessionState::Listening,
            tx: TransactionTracker::default(),
            destinations: HashMap::new(),
        }
    }
}

impl ModemSessionFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        let _ = event;
        Vec::new()
    }
}
