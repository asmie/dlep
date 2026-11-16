use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use dlep_core::SignalType;

use crate::discovery_common::build_peer_offer_with_secured_medium;
use crate::events::{FsmAction, FsmEvent, SendTarget};
use crate::timers::{TimerId, TimerKind};

/// Bound additional offers and retained probe endpoints independently of input.
pub const MAX_OFFER_RETRIES: u8 = 5;
pub const MAX_PENDING_OFFER_BURSTS: usize = 64;

/// Validate the optional retry policy shared by the FSM and daemon config.
pub fn validate_offer_retries(retries: u8, interval: Duration) -> Result<(), String> {
    if retries > MAX_OFFER_RETRIES {
        return Err(format!(
            "discovery.offer_retries must be at most {MAX_OFFER_RETRIES}"
        ));
    }
    if interval < Duration::from_secs(1) {
        return Err("discovery.offer_retry_interval_ms must be at least 1000 ms".into());
    }
    Ok(())
}

#[derive(Debug)]
struct OfferBurst {
    id: TimerId,
    remaining: u8,
}

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
    secured_medium: bool,
    offer_retries: u8,
    retry_interval: Duration,
    pending: HashMap<SocketAddr, OfferBurst>,
    // Never reuse a burst id: a cancelled expiry already in the runtime's
    // queue must not trigger offers for a later probe, even at the same peer.
    next_timer_id: Option<u32>,
}

impl ModemDiscoveryFsm {
    pub fn new(tcp_endpoint: SocketAddr, peer_description: String, use_tls: bool) -> Self {
        Self {
            state: ModemDiscoveryState::Listening,
            tcp_endpoint,
            peer_description,
            use_tls,
            secured_medium: false,
            offer_retries: 0,
            retry_interval: Duration::from_secs(1),
            pending: HashMap::new(),
            next_timer_id: Some(11),
        }
    }

    pub fn with_secured_medium(mut self, secured_medium: bool) -> Self {
        self.secured_medium = secured_medium;
        self
    }

    /// Additional unicast offers after each probe's immediate reply. A probe
    /// already being retried still gets a reply but cannot extend its burst.
    pub fn with_offer_retries(mut self, retries: u8, interval: Duration) -> Result<Self, String> {
        validate_offer_retries(retries, interval)?;
        self.offer_retries = retries;
        self.retry_interval = interval;
        Ok(self)
    }

    fn offer(&self, peer: SocketAddr) -> FsmAction {
        FsmAction::SendSignal {
            signal: build_peer_offer_with_secured_medium(
                &self.peer_description,
                self.tcp_endpoint,
                self.use_tls,
                self.secured_medium,
            ),
            target: SendTarget::Unicast(peer),
        }
    }

    fn retry_timer(&self, id: TimerId) -> FsmAction {
        FsmAction::StartTimer {
            id,
            kind: TimerKind::Discovery,
            duration: self.retry_interval,
            periodic: false,
        }
    }

    pub fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        match event {
            // Any inbound Peer_Discovery — reply with a Peer_Offer
            // unicast back to the router that asked.
            FsmEvent::RecvSignal { signal, from }
                if signal.signal_type == SignalType::PEER_DISCOVERY =>
            {
                if !crate::discovery_common::valid_signal(&signal) {
                    return Vec::new();
                }
                let mut actions = vec![self.offer(from)];
                if self.offer_retries > 0
                    && !self.pending.contains_key(&from)
                    && self.pending.len() < MAX_PENDING_OFFER_BURSTS
                {
                    if let Some(id) = self.next_timer_id {
                        let timer = TimerId::new(id);
                        self.next_timer_id = id.checked_add(1);
                        self.pending.insert(
                            from,
                            OfferBurst {
                                id: timer,
                                remaining: self.offer_retries,
                            },
                        );
                        self.state = ModemDiscoveryState::OfferBurst;
                        actions.push(self.retry_timer(timer));
                    }
                }
                actions
            }

            FsmEvent::TimerExpired(id, TimerKind::Discovery) => {
                let Some(peer) = self
                    .pending
                    .iter()
                    .find_map(|(peer, burst)| (burst.id == id).then_some(*peer))
                else {
                    return Vec::new();
                };
                let burst = self.pending.get_mut(&peer).expect("pending burst");
                burst.remaining -= 1;
                let finished = burst.remaining == 0;
                let mut actions = vec![self.offer(peer)];
                if finished {
                    self.pending.remove(&peer);
                    actions.push(FsmAction::CancelTimer(id));
                    if self.pending.is_empty() {
                        self.state = ModemDiscoveryState::Listening;
                    }
                } else {
                    actions.push(self.retry_timer(id));
                }
                actions
            }

            FsmEvent::AppStopDiscoveryOffers { peer } => {
                let actions = self
                    .pending
                    .remove(&peer)
                    .map(|burst| FsmAction::CancelTimer(burst.id))
                    .into_iter()
                    .collect();
                if self.pending.is_empty() {
                    self.state = ModemDiscoveryState::Listening;
                }
                actions
            }

            // Ignore Peer_Offers (only modems send those) and anything else.
            FsmEvent::RecvSignal { .. } => Vec::new(),

            // App shutdown — reset to Listening so a subsequent restart is clean.
            FsmEvent::AppShutdown { .. } => {
                self.state = ModemDiscoveryState::Listening;
                self.pending
                    .drain()
                    .map(|(_, burst)| FsmAction::CancelTimer(burst.id))
                    .collect()
            }

            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery_common::build_peer_discovery;

    fn peer(port: u16) -> SocketAddr {
        ([192, 0, 2, 1], port).into()
    }
    fn modem(retries: u8) -> ModemDiscoveryFsm {
        ModemDiscoveryFsm::new(peer(854), "modem".into(), true)
            .with_offer_retries(retries, Duration::from_secs(1))
            .unwrap()
    }
    fn probe(fsm: &mut ModemDiscoveryFsm, from: SocketAddr) -> Vec<FsmAction> {
        fsm.step(FsmEvent::RecvSignal {
            signal: build_peer_discovery("router"),
            from,
        })
    }
    fn timer(actions: &[FsmAction]) -> Option<TimerId> {
        actions.iter().find_map(|action| match action {
            FsmAction::StartTimer {
                id,
                periodic: false,
                ..
            } => Some(*id),
            _ => None,
        })
    }
    fn offers(actions: &[FsmAction], expected: SocketAddr) {
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, FsmAction::SendSignal { .. }))
                .count(),
            1
        );
        assert!(actions.iter().any(|a| matches!(a, FsmAction::SendSignal { target: SendTarget::Unicast(to), .. } if *to == expected)));
    }

    #[test]
    fn retry_limits_and_default_immediate_reply() {
        let mut fsm = modem(0);
        let actions = probe(&mut fsm, peer(1000));
        offers(&actions, peer(1000));
        assert_eq!(actions.len(), 1);
        assert_eq!(fsm.state, ModemDiscoveryState::Listening);
        assert!(validate_offer_retries(6, Duration::from_secs(1)).is_err());
        assert!(validate_offer_retries(1, Duration::from_millis(999)).is_err());
        assert!(validate_offer_retries(5, Duration::from_secs(1)).is_ok());
        let malformed = dlep_core::Signal::new(SignalType::PEER_DISCOVERY).with_item(
            dlep_core::DataItem::HeartbeatInterval(Duration::from_secs(1)),
        );
        assert!(
            modem(2)
                .step(FsmEvent::RecvSignal {
                    signal: malformed,
                    from: peer(1000)
                })
                .is_empty()
        );
    }

    #[test]
    fn bursts_finish_independently_and_probes_do_not_extend_them() {
        let mut fsm = modem(2);
        let first = timer(&probe(&mut fsm, peer(1000))).unwrap();
        let second = timer(&probe(&mut fsm, peer(1001))).unwrap();
        assert_ne!(first, second);
        let duplicate = probe(&mut fsm, peer(1000));
        offers(&duplicate, peer(1000));
        assert!(timer(&duplicate).is_none());
        for (id, address) in [(first, peer(1000)), (second, peer(1001))] {
            let actions = fsm.step(FsmEvent::TimerExpired(id, TimerKind::Discovery));
            offers(&actions, address);
            assert_eq!(timer(&actions), Some(id));
            let actions = fsm.step(FsmEvent::TimerExpired(id, TimerKind::Discovery));
            offers(&actions, address);
            assert!(timer(&actions).is_none());
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, FsmAction::CancelTimer(cancelled) if *cancelled == id))
            );
            assert!(
                fsm.step(FsmEvent::TimerExpired(id, TimerKind::Discovery))
                    .is_empty()
            );
        }
        assert_eq!(fsm.state, ModemDiscoveryState::Listening);
    }

    #[test]
    fn cancellation_and_shutdown_ignore_stale_expiries_and_do_not_reuse_ids() {
        let mut fsm = modem(2);
        let old = timer(&probe(&mut fsm, peer(1000))).unwrap();
        let stop = fsm.step(FsmEvent::AppStopDiscoveryOffers { peer: peer(1000) });
        assert!(matches!(stop.as_slice(), [FsmAction::CancelTimer(id)] if *id == old));
        let new = timer(&probe(&mut fsm, peer(1000))).unwrap();
        assert_ne!(old, new);
        assert!(
            fsm.step(FsmEvent::TimerExpired(old, TimerKind::Discovery))
                .is_empty()
        );
        let other = timer(&probe(&mut fsm, peer(1001))).unwrap();
        let actions = fsm.step(FsmEvent::AppShutdown {
            reason: dlep_core::StatusCode::SHUTTING_DOWN,
        });
        assert_eq!(actions.len(), 2);
        assert!(fsm.pending.is_empty());
        for id in [new, other] {
            assert!(
                fsm.step(FsmEvent::TimerExpired(id, TimerKind::Discovery))
                    .is_empty()
            );
        }
        assert_eq!(fsm.state, ModemDiscoveryState::Listening);
    }

    #[test]
    fn burst_capacity_and_id_exhaustion_preserve_immediate_replies() {
        let mut fsm = modem(2);
        for port in 1000..1000 + MAX_PENDING_OFFER_BURSTS as u16 {
            assert!(timer(&probe(&mut fsm, peer(port))).is_some());
        }
        let actions = probe(&mut fsm, peer(2000));
        offers(&actions, peer(2000));
        assert!(timer(&actions).is_none());
        assert_eq!(fsm.pending.len(), MAX_PENDING_OFFER_BURSTS);
        fsm.step(FsmEvent::AppStopDiscoveryOffers { peer: peer(1000) });
        assert!(timer(&probe(&mut fsm, peer(2000))).is_some());
        let mut exhausted = modem(1);
        exhausted.next_timer_id = Some(u32::MAX);
        assert_eq!(
            timer(&probe(&mut exhausted, peer(1000))),
            Some(TimerId(u32::MAX))
        );
        assert!(timer(&probe(&mut exhausted, peer(1001))).is_none());
        offers(&probe(&mut exhausted, peer(1002)), peer(1002));
    }
}
