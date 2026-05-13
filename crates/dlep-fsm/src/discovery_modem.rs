use std::net::SocketAddr;

use dlep_core::SignalType;

use crate::discovery_common::build_peer_offer;
use crate::events::{FsmAction, FsmEvent, SendTarget};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ModemDiscoveryState {
    #[default]
    Listening,
    OfferBurst,
}

#[derive(Debug)]
pub struct ModemDiscoveryFsm {
    pub state: ModemDiscoveryState,
    tcp_endpoint: SocketAddr,
    peer_description: String,
    use_tls: bool,
}

impl ModemDiscoveryFsm {
    pub fn new(tcp_endpoint: SocketAddr, peer_description: String, use_tls: bool) -> Self {
        Self {
            state: ModemDiscoveryState::Listening,
            tcp_endpoint,
            peer_description,
            use_tls,
        }
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            // Any inbound Peer_Discovery — reply with a Peer_Offer
            // unicast back to the router that asked.
            FsmEvent::RecvSignal { signal, from }
                if signal.signal_type == SignalType::PEER_DISCOVERY =>
            {
                self.state = ModemDiscoveryState::OfferBurst;
                vec![FsmAction::SendSignal {
                    signal: build_peer_offer(
                        &self.peer_description,
                        self.tcp_endpoint,
                        self.use_tls,
                    ),
                    target: SendTarget::Unicast(from),
                }]
            }

            // Ignore Peer_Offers (only modems send those) and anything else.
            FsmEvent::RecvSignal { .. } => Vec::new(),

            // App shutdown — reset to Listening so a subsequent restart is clean.
            FsmEvent::AppShutdown { .. } => {
                self.state = ModemDiscoveryState::Listening;
                Vec::new()
            }

            _ => Vec::new(),
        }
    }
}
