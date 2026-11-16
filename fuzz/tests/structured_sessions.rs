#[path = "../fuzz_targets/session_inputs.rs"]
mod session_inputs;

use dlep_core::{MacAddress, Message};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{FsmAction, FsmEvent, LinkMetrics, SessionConfig};

fn message(actions: Vec<FsmAction>) -> Message {
    let messages: Vec<_> = actions
        .into_iter()
        .filter_map(|a| match a {
            FsmAction::SendMessage(message) => Some(message),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), 1, "expected one wire message");
    Message::decode(messages[0].encode().unwrap().freeze()).unwrap()
}

#[test]
fn structured_commands_reach_address_updates_and_deferred_link_completion() {
    for eui64 in [false, true] {
        let config = SessionConfig {
            mac_address_format: if eui64 {
                dlep_core::MacAddressFormat::Eui64
            } else {
                dlep_core::MacAddressFormat::Eui48
            },
            initial_metrics: LinkMetrics {
                resources: Some(0),
                rlq_rx: Some(0),
                rlq_tx: Some(0),
                mtu: Some(1500),
                ..Default::default()
            },
            defer_link_characteristics: true,
            ..Default::default()
        };
        let mut router = RouterSessionFsm::with_config(config.clone());
        let mut modem = ModemSessionFsm::with_config(config);
        modem.step(FsmEvent::TcpAccepted);
        let init = message(router.step(FsmEvent::TcpConnected));
        let reply = message(modem.step(FsmEvent::RecvMessage(init)));
        router.step(FsmEvent::RecvMessage(reply));
        let mac = if eui64 {
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 0])
        } else {
            MacAddress::new_eui48([2, 0, 0, 0, 0, 0])
        };
        let mut payload = [79, 1, 0, 0, 0, 0, 0, 0, 3, 232, 100, 24, 64, 0, 15, 2];
        let up = message(modem.step(session_inputs::event(1, mac, &payload).unwrap()));
        let response = message(router.step(FsmEvent::RecvMessage(up)));
        modem.step(FsmEvent::RecvMessage(response));

        payload[1] = 2;
        let update = message(modem.step(session_inputs::event(0x40, mac, &payload).unwrap()));
        let actions = router.step(FsmEvent::RecvMessage(update));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::Emit(EmittedEvent::DestinationAddressesUpdate { addresses, .. })
            if addresses.v4.len() == 2 && addresses.v6.len() == 2
            && addresses.v4_subnets.len() == 1 && addresses.v6_subnets.len() == 1)));

        let request = message(router.step(session_inputs::event(0xc3, mac, &payload).unwrap()));
        let pending = modem.step(FsmEvent::RecvMessage(request));
        assert!(pending.iter().any(|a| matches!(
            a,
            FsmAction::Emit(EmittedEvent::LinkCharacteristicsRequested { pending: true, .. })
        )));
        assert!(
            !pending
                .iter()
                .any(|a| matches!(a, FsmAction::SendMessage(_)))
        );
        let response = message(modem.step(session_inputs::event(0x44, mac, &payload).unwrap()));
        let actions = router.step(FsmEvent::RecvMessage(response));
        assert!(actions.iter().any(|a| matches!(a, FsmAction::Emit(EmittedEvent::LinkCharacteristicsResponse { status, text, metrics, .. })
            if status.0 == 0 && text == "拒否 🦀" && metrics.current_data_rate_rx_bps == 500 && metrics.resources == Some(100))));
    }
}
