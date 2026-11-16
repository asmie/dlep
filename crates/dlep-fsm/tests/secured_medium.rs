use dlep_core::{DataItem, Signal, SignalType};
use dlep_fsm::discovery_router::RouterDiscoveryFsm;
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{FsmAction, FsmEvent, SessionConfig};

#[test]
fn router_never_advertises_modem_medium_security_and_missing_peer_type_stays_unknown() {
    assert_eq!(
        dlep_fsm::discovery_common::extract_secured_medium(
            &dlep_fsm::discovery_common::build_peer_discovery("router")
        ),
        None
    );
    let mut router = RouterSessionFsm::with_config(SessionConfig {
        secured_medium: true,
        ..Default::default()
    });
    let init = router
        .step(FsmEvent::TcpConnected)
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap();
    assert!(
        init.data_items
            .iter()
            .any(|i| matches!(i, DataItem::PeerType { flags, .. } if !flags.smi))
    );
    let mut discovery = RouterDiscoveryFsm::new();
    discovery.step(FsmEvent::AppStartDiscovery);
    let actions = discovery.step(FsmEvent::RecvSignal {
        signal: Signal::new(SignalType::PEER_OFFER),
        from: "192.0.2.1:854".parse().unwrap(),
    });
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::PeerDiscovered {
            secured_medium: None,
            ..
        })
    )));
}
