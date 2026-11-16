#[path = "../fuzz_targets/session_inputs.rs"]
mod session_inputs;
#[path = "../fuzz_targets/session_transport.rs"]
mod session_transport;

use dlep_core::MacAddress;
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::{FsmEvent, SessionConfig};

fn payload(value: u64, number: u8, mask: u8) -> [u8; 16] {
    let mut data = [0; 16];
    data[1] = number;
    data[2..10].copy_from_slice(&value.to_be_bytes());
    data[11] = 24;
    data[12] = 64;
    data[14] = mask;
    data
}

#[test]
fn held_acknowledgements_coalesce_metrics_and_preserve_destination_order() {
    for eui64 in [false, true] {
        let config = SessionConfig {
            mac_address_format: if eui64 {
                dlep_core::MacAddressFormat::Eui64
            } else {
                dlep_core::MacAddressFormat::Eui48
            },
            ..Default::default()
        };
        let mac = if eui64 {
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 0])
        } else {
            MacAddress::new_eui48([2, 0, 0, 0, 0, 0])
        };
        let mut pair = session_transport::Pair::new(config);
        pair.step(FsmEvent::TcpAccepted, false, true);
        pair.step(FsmEvent::TcpConnected, true, true);
        pair.step(
            session_inputs::event(1, mac, &payload(100, 0, 0)).unwrap(),
            false,
            true,
        );
        pair.events.clear();

        pair.step(
            session_inputs::event(0x45, mac, &payload(1000, 0, 0)).unwrap(),
            false,
            false,
        );
        pair.step(
            session_inputs::event(0x47, mac, &payload(2000, 0, 0)).unwrap(),
            false,
            false,
        );
        assert_eq!(
            pair.pending(false),
            1,
            "second metric report must wait for the acknowledgement"
        );
        assert!(
            pair.events.iter().all(|(router, _)| !router),
            "router cannot observe undelivered messages"
        );
        assert!(pair.deliver(false));
        assert_eq!(pair.pending(true), 1, "router reply must remain held");
        assert_eq!(pair.pending(false), 0);
        assert!(pair.deliver(true));
        assert_eq!(
            pair.pending(false),
            1,
            "acknowledgement must release the latest queued report"
        );
        pair.drain();
        let updates: Vec<_> = pair
            .events
            .iter()
            .filter_map(|(router, event)| match event {
                EmittedEvent::SessionMetricsUpdate { metrics } if *router => {
                    Some(metrics.max_data_rate_rx_bps)
                }
                _ => None,
            })
            .collect();
        assert_eq!(updates, [1000, 2000]);

        pair.events.clear();
        for value in [3000, 4000] {
            pair.step(
                session_inputs::event(3, mac, &payload(value, 0, 0)).unwrap(),
                false,
                false,
            );
        }
        assert_eq!(pair.pending(false), 2);
        pair.drain();
        let updates: Vec<_> = pair
            .events
            .iter()
            .filter_map(|(router, event)| match event {
                EmittedEvent::DestinationUpdate { metrics, .. } if *router => {
                    Some(metrics.current_data_rate_rx_bps)
                }
                _ => None,
            })
            .collect();
        assert_eq!(updates, [1500, 2000]);
        assert_eq!(pair.pending(true) + pair.pending(false), 0);

        pair.events.clear();
        pair.step(
            session_inputs::event(0x46, mac, &payload(0, 1, 3)).unwrap(),
            false,
            false,
        );
        pair.step(
            session_inputs::event(0x46, mac, &payload(0, 2, 3)).unwrap(),
            false,
            false,
        );
        assert_eq!(pair.pending(false), 1);
        assert!(pair.deliver(false));
        assert!(pair.deliver(true));
        pair.drain();
        let addresses = pair
            .events
            .iter()
            .filter_map(|(router, event)| match event {
                EmittedEvent::SessionAddressesUpdate { addresses, .. } if *router => {
                    Some(addresses)
                }
                _ => None,
            })
            .next_back()
            .expect("router must observe the desired address correction");
        assert_eq!(
            addresses.v4,
            ["192.0.2.2".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            addresses.v6,
            ["2001:db8::2".parse::<std::net::Ipv6Addr>().unwrap()]
        );
    }
}
