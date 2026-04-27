use crate::events::{FsmAction, FsmEvent};

/// Modem-side discovery states.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ModemDiscoveryState {
    #[default]
    Listening,
    OfferBurst,
}

#[derive(Debug, Default)]
pub struct ModemDiscoveryFsm {
    pub state: ModemDiscoveryState,
}

impl ModemDiscoveryFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        let _ = event;
        Vec::new()
    }
}
