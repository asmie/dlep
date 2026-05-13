//! Table-driven tests for the router and modem discovery FSMs.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use dlep_core::SignalType;
use dlep_fsm::discovery_common::{build_peer_discovery, build_peer_offer};
use dlep_fsm::discovery_modem::{ModemDiscoveryFsm, ModemDiscoveryState};
use dlep_fsm::discovery_router::{RouterDiscoveryFsm, RouterDiscoveryState, TIMER_DISCOVERY};
use dlep_fsm::events::{EmittedEvent, FsmAction, FsmEvent, SendTarget};
use dlep_fsm::timers::TimerKind;

fn peer_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 854)
}

#[test]
fn router_idle_to_probing_on_app_start() {
    let mut fsm = RouterDiscoveryFsm::new();
    let actions = fsm.step(FsmEvent::AppStartDiscovery);
    assert_eq!(fsm.state, RouterDiscoveryState::Probing);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendSignal { signal, target: SendTarget::DiscoveryGroup }
            if signal.signal_type == SignalType::PEER_DISCOVERY
    )));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer { id, kind: TimerKind::Discovery, periodic: true, .. }
            if *id == TIMER_DISCOVERY
    )));
}

#[test]
fn router_probing_resends_on_timer() {
    let mut fsm = RouterDiscoveryFsm::new();
    let _ = fsm.step(FsmEvent::AppStartDiscovery);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_DISCOVERY,
        TimerKind::Discovery,
    ));
    assert_eq!(fsm.state, RouterDiscoveryState::Probing);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendSignal { signal, .. }
            if signal.signal_type == SignalType::PEER_DISCOVERY
    )));
}

#[test]
fn router_probing_to_offer_received_on_peer_offer() {
    let mut fsm = RouterDiscoveryFsm::new();
    let _ = fsm.step(FsmEvent::AppStartDiscovery);
    let offer = build_peer_offer("dlep-modem", peer_addr(), false);
    let actions = fsm.step(FsmEvent::RecvSignal {
        signal: offer,
        from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 12345),
    });
    assert_eq!(fsm.state, RouterDiscoveryState::OfferReceived);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(t) if *t == TIMER_DISCOVERY))
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::PeerDiscovered { addr, .. }) if *addr == peer_addr()
    )));
}

#[test]
fn router_probing_ignores_peer_discovery() {
    let mut fsm = RouterDiscoveryFsm::new();
    let _ = fsm.step(FsmEvent::AppStartDiscovery);
    let discovery = build_peer_discovery("other-router");
    let actions = fsm.step(FsmEvent::RecvSignal {
        signal: discovery,
        from: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 12345),
    });
    assert_eq!(fsm.state, RouterDiscoveryState::Probing);
    assert!(!actions.iter().any(|a| matches!(a, FsmAction::Emit(_))));
}

#[test]
fn router_probing_app_shutdown_returns_to_idle() {
    let mut fsm = RouterDiscoveryFsm::new();
    let _ = fsm.step(FsmEvent::AppStartDiscovery);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: dlep_core::StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state, RouterDiscoveryState::Idle);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(t) if *t == TIMER_DISCOVERY))
    );
}

#[test]
fn router_offer_received_holds_state() {
    let mut fsm = RouterDiscoveryFsm::new();
    let _ = fsm.step(FsmEvent::AppStartDiscovery);
    let offer = build_peer_offer("dlep-modem", peer_addr(), false);
    let _ = fsm.step(FsmEvent::RecvSignal {
        signal: offer,
        from: peer_addr(),
    });
    let _ = fsm.step(FsmEvent::RecvSignal {
        signal: build_peer_offer("another", peer_addr(), false),
        from: peer_addr(),
    });
    assert_eq!(fsm.state, RouterDiscoveryState::OfferReceived);
}

#[test]
fn modem_listening_replies_to_peer_discovery() {
    let mut fsm = ModemDiscoveryFsm::new(peer_addr(), "dlep-modem".to_string(), false);
    let discovery = build_peer_discovery("dlep-router");
    let from = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 5000);
    let actions = fsm.step(FsmEvent::RecvSignal {
        signal: discovery,
        from,
    });
    assert_eq!(fsm.state, ModemDiscoveryState::OfferBurst);
    let send = actions.iter().find_map(|a| match a {
        FsmAction::SendSignal { signal, target } => Some((signal, target)),
        _ => None,
    });
    let (signal, target) = send.expect("expected Peer_Offer send");
    assert_eq!(signal.signal_type, SignalType::PEER_OFFER);
    match target {
        SendTarget::Unicast(addr) => assert_eq!(*addr, from),
        other => panic!("expected Unicast target, got {other:?}"),
    }
}

#[test]
fn modem_listening_ignores_peer_offer() {
    let mut fsm = ModemDiscoveryFsm::new(peer_addr(), "dlep-modem".to_string(), false);
    let offer = build_peer_offer("imposter", peer_addr(), false);
    let actions = fsm.step(FsmEvent::RecvSignal {
        signal: offer,
        from: peer_addr(),
    });
    assert_eq!(fsm.state, ModemDiscoveryState::Listening);
    assert!(actions.is_empty());
}

#[test]
fn modem_offer_burst_returns_to_listening_after_app_shutdown() {
    let mut fsm = ModemDiscoveryFsm::new(peer_addr(), "dlep-modem".to_string(), false);
    let _ = fsm.step(FsmEvent::RecvSignal {
        signal: build_peer_discovery("r"),
        from: peer_addr(),
    });
    assert_eq!(fsm.state, ModemDiscoveryState::OfferBurst);
    let _ = fsm.step(FsmEvent::AppShutdown {
        reason: dlep_core::StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state, ModemDiscoveryState::Listening);
}

#[test]
fn modem_offer_burst_replies_to_another_discovery() {
    let mut fsm = ModemDiscoveryFsm::new(peer_addr(), "dlep-modem".to_string(), false);
    let _ = fsm.step(FsmEvent::RecvSignal {
        signal: build_peer_discovery("r"),
        from: peer_addr(),
    });
    let actions = fsm.step(FsmEvent::RecvSignal {
        signal: build_peer_discovery("r"),
        from: peer_addr(),
    });
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendSignal { .. }))
    );
}
