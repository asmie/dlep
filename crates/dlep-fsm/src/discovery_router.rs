use std::time::Duration;

use dlep_core::SignalType;

use crate::discovery_common::{
    build_peer_discovery, extract_offer_endpoint, extract_peer_description,
};
use crate::events::{EmittedEvent, FsmAction, FsmEvent, SendTarget};
use crate::timers::{TimerId, TimerKind};

/// Timer ID for the periodic Peer_Discovery resend (RFC 8175 §7.3.1).
pub const TIMER_DISCOVERY: TimerId = TimerId::new(10);

/// Router-side discovery states (RFC 8175 §7.3).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouterDiscoveryState {
    #[default]
    Idle,
    Probing,
    OfferReceived,
}

#[derive(Clone, Debug)]
pub struct RouterDiscoveryConfig {
    pub peer_description: String,
    pub discovery_interval: Duration,
}

impl Default for RouterDiscoveryConfig {
    fn default() -> Self {
        Self {
            peer_description: "dlep-router".into(),
            discovery_interval: Duration::from_millis(5_000),
        }
    }
}

#[derive(Debug)]
pub struct RouterDiscoveryFsm {
    pub state: RouterDiscoveryState,
    config: RouterDiscoveryConfig,
}

impl Default for RouterDiscoveryFsm {
    fn default() -> Self {
        Self::with_config(RouterDiscoveryConfig::default())
    }
}

impl RouterDiscoveryFsm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: RouterDiscoveryConfig) -> Self {
        Self {
            state: RouterDiscoveryState::Idle,
            config,
        }
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match (self.state, event) {
            // Idle → Probing on app-driven start command.
            (RouterDiscoveryState::Idle, FsmEvent::AppStartDiscovery) => {
                self.state = RouterDiscoveryState::Probing;
                vec![
                    FsmAction::SendSignal {
                        signal: build_peer_discovery(&self.config.peer_description),
                        target: SendTarget::DiscoveryGroup,
                    },
                    FsmAction::StartTimer {
                        id: TIMER_DISCOVERY,
                        kind: TimerKind::Discovery,
                        duration: self.config.discovery_interval,
                        periodic: true,
                    },
                ]
            }

            // Probing: periodic timer → re-send.
            (RouterDiscoveryState::Probing, FsmEvent::TimerExpired(_, TimerKind::Discovery)) => {
                vec![FsmAction::SendSignal {
                    signal: build_peer_discovery(&self.config.peer_description),
                    target: SendTarget::DiscoveryGroup,
                }]
            }

            // Probing: inbound Peer_Offer → emit + transition.
            (RouterDiscoveryState::Probing, FsmEvent::RecvSignal { signal, .. })
                if signal.signal_type == SignalType::PEER_OFFER =>
            {
                let Some(endpoint) = extract_offer_endpoint(&signal) else {
                    // Malformed offer — keep probing.
                    return Vec::new();
                };
                let peer_description = extract_peer_description(&signal);
                self.state = RouterDiscoveryState::OfferReceived;
                vec![
                    FsmAction::CancelTimer(TIMER_DISCOVERY),
                    FsmAction::Emit(EmittedEvent::PeerDiscovered {
                        addr: endpoint.addr,
                        peer_description,
                        use_tls: endpoint.use_tls,
                    }),
                ]
            }

            // App shutdown: any state → Idle, cancel timer if armed.
            // Must come before the `Probing` catch-all below so a shutdown
            // received while probing actually triggers this arm.
            (_, FsmEvent::AppShutdown { .. }) => {
                let was_probing = matches!(self.state, RouterDiscoveryState::Probing);
                self.state = RouterDiscoveryState::Idle;
                if was_probing {
                    vec![FsmAction::CancelTimer(TIMER_DISCOVERY)]
                } else {
                    Vec::new()
                }
            }

            // Probing: ignore anything else (notably stray Peer_Discovery
            // from other routers — RFC 8175 §7.3 says routers don't reply
            // to each other).
            (RouterDiscoveryState::Probing, _) => Vec::new(),

            _ => Vec::new(),
        }
    }
}
