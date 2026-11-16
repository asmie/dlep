//! Bounded application payloads for the opt-in structured session input format.
use dlep_core::{LinkCharacteristics, MacAddress, StatusCode};
use dlep_fsm::{AddressChanges, DestinationAddrs, FsmEvent, LinkMetrics};
use std::time::Duration;

fn addresses(data: &[u8; 16]) -> DestinationAddrs {
    let mut set = DestinationAddrs::default();
    let v4 = std::net::Ipv4Addr::new(192, 0, 2, data[1]);
    let v6 = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, u16::from(data[1]));
    if data[14] & 1 != 0 {
        set.v4.push(v4);
    }
    if data[14] & 2 != 0 {
        set.v6.push(v6);
    }
    if data[14] & 4 != 0 {
        set.v4_subnets
            .push(ipnet::Ipv4Net::new(v4, data[11] % 33).unwrap());
    }
    if data[14] & 8 != 0 {
        set.v6_subnets
            .push(ipnet::Ipv6Net::new(v6, data[12] % 129).unwrap());
    }
    if data[14] & 16 != 0 {
        set.v4.extend(set.v4.clone());
        set.v6.extend(set.v6.clone());
        set.v4_subnets.extend(set.v4_subnets.clone());
        set.v6_subnets.extend(set.v6_subnets.clone());
    }
    set
}

pub fn event(op: u8, mac: MacAddress, data: &[u8; 16]) -> Option<FsmEvent> {
    let value = u64::from_be_bytes(data[2..10].try_into().unwrap());
    let latency = if data[0] & 128 == 0 {
        Duration::from_micros(value)
    } else {
        Duration::from_secs(value)
    };
    let metrics = LinkMetrics {
        max_data_rate_rx_bps: value,
        max_data_rate_tx_bps: value,
        current_data_rate_rx_bps: value / 2,
        current_data_rate_tx_bps: value / 3,
        latency,
        resources: (data[0] & 1 != 0).then_some(data[10]),
        rlq_rx: (data[0] & 2 != 0).then_some(data[10]),
        rlq_tx: (data[0] & 4 != 0).then_some(data[10]),
        mtu: (data[0] & 8 != 0).then_some(u16::from_be_bytes([data[10], data[11]])),
    };
    let set = addresses(data);
    let changes = if data[14] & 64 != 0 {
        AddressChanges {
            added: set.clone(),
            removed: set.clone(),
        }
    } else if data[14] & 32 != 0 {
        AddressChanges {
            added: Default::default(),
            removed: set.clone(),
        }
    } else {
        AddressChanges {
            added: set.clone(),
            removed: Default::default(),
        }
    };
    Some(match op & 0x4f {
        1 | 0x49 => FsmEvent::AppAddDestination {
            mac,
            metrics,
            addrs: set,
        },
        3 | 0x4a => FsmEvent::AppUpdateMetrics { mac, metrics },
        5 | 0x47 => FsmEvent::AppQueueSessionUpdate { metrics },
        6 | 0x48 => FsmEvent::AppSessionDefaults { metrics },
        7 | 0x46 => FsmEvent::AppSetSessionAddresses { addresses: set },
        0x40 => FsmEvent::AppUpdateAddresses { mac, changes },
        0x41 => FsmEvent::AppSessionAddresses { changes },
        0x42 => FsmEvent::AppAnnounceDestinationWithAddresses { mac, changes },
        0x43 => FsmEvent::AppRequestLinkCharacteristics {
            mac,
            requested: LinkCharacteristics {
                current_data_rate_rx_bps: (data[0] & 1 != 0).then_some(value),
                current_data_rate_tx_bps: (data[0] & 2 != 0).then_some(value.rotate_left(8)),
                latency: (data[0] & 4 != 0).then_some(latency),
            },
        },
        0x44 => FsmEvent::AppLinkCharacteristicsResponse {
            mac,
            status: StatusCode(data[13]),
            text: ["", "fuzz", "拒否 🦀"][usize::from(data[15] % 3)].into(),
            metrics: (data[0] & 64 != 0).then_some(metrics),
        },
        0x45 => FsmEvent::AppSessionUpdate { metrics },
        0x4b => FsmEvent::AppDropDestination {
            mac,
            reason: StatusCode(data[13]),
        },
        _ => return None,
    })
}
