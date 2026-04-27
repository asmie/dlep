use crate::events::{FsmAction, FsmEvent};

/// Router-side discovery states (RFC 8175 §7.3).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouterDiscoveryState {
    #[default]
    Idle,
    Probing,
    OfferReceived,
}

#[derive(Debug, Default)]
pub struct RouterDiscoveryFsm {
    pub state: RouterDiscoveryState,
}

impl RouterDiscoveryFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        let _ = event;
        Vec::new()
    }
}
