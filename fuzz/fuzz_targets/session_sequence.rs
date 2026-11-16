#![no_main]

use bytes::Bytes;
use dlep_core::{MacAddress, Message, StatusCode};
use dlep_fsm::{
    DestinationAddrs, FsmEvent, LinkMetrics, SessionConfig, TIMER_HEARTBEAT,
    TIMER_HEARTBEAT_MISSED, TIMER_SESSION_INIT, TIMER_TERMINATION, TimerKind,
};
use libfuzzer_sys::fuzz_target;
#[path = "session_inputs.rs"]
mod session_inputs;

#[path = "session_transport.rs"]
mod session_transport;

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut remaining)) = data.split_first() else {
        return;
    };
    let config = SessionConfig {
        initial_metrics: LinkMetrics {
            resources: (mode & 8 != 0).then_some(0),
            rlq_rx: (mode & 8 != 0).then_some(0),
            rlq_tx: (mode & 8 != 0).then_some(0),
            mtu: (mode & 8 != 0).then_some(1500),
            ..Default::default()
        },
        defer_link_characteristics: mode & 16 != 0,
        mac_address_format: if mode & 2 == 0 {
            dlep_core::MacAddressFormat::Eui48
        } else {
            dlep_core::MacAddressFormat::Eui64
        },
        ..Default::default()
    };
    let mut pair = session_transport::Pair::new(config);
    pair.step(FsmEvent::TcpAccepted, false, true);
    if mode & 1 != 0 {
        pair.step(FsmEvent::TcpConnected, true, true);
    }
    for _ in 0..64 {
        // Retained observations are only needed by the focused harness tests.
        pair.events.clear();
        let Some((&op, tail)) = remaining.split_first() else {
            break;
        };
        remaining = tail;
        let delayed = mode & 32 != 0;
        if delayed && mode & 4 != 0 {
            match op & 0x4f {
                0x4c => {
                    pair.deliver(true);
                    continue;
                }
                0x4d => {
                    pair.deliver(false);
                    continue;
                }
                0x4e => {
                    pair.drain();
                    continue;
                }
                _ => {}
            }
        }
        let from_router = op & 128 != 0;
        let mac = if mode & 2 == 0 {
            MacAddress::new_eui48([2, 0, 0, 0, 0, (op >> 4) & 3])
        } else {
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, (op >> 4) & 3])
        };
        let generated = if mode & 4 != 0 && op & 0x4f != 0 {
            if remaining.len() < 16 {
                break;
            }
            let payload: &[u8; 16] = remaining[..16].try_into().unwrap();
            remaining = &remaining[16..];
            session_inputs::event(op, mac, payload)
        } else {
            None
        };
        let event = if let Some(event) = generated {
            event
        } else {
            match op & 15 {
                0 => {
                    if remaining.len() < 2 {
                        break;
                    }
                    let length = usize::from(u16::from_be_bytes([remaining[0], remaining[1]]));
                    let tail = &remaining[2..];
                    let length = length.min(tail.len());
                    remaining = &tail[length..];
                    match Message::decode(Bytes::copy_from_slice(&tail[..length])) {
                        Ok(message) => FsmEvent::RecvMessage(message),
                        Err(_) => FsmEvent::ProtocolError(StatusCode::INVALID_DATA),
                    }
                }
                1 => FsmEvent::AppAddDestination {
                    mac,
                    metrics: LinkMetrics::default(),
                    addrs: DestinationAddrs::default(),
                },
                2 => FsmEvent::AppDropDestination {
                    mac,
                    reason: StatusCode::SUCCESS,
                },
                3 => FsmEvent::AppUpdateMetrics {
                    mac,
                    metrics: LinkMetrics::default(),
                },
                4 => FsmEvent::AppAnnounceDestination { mac },
                5 => FsmEvent::AppQueueSessionUpdate {
                    metrics: LinkMetrics::default(),
                },
                6 => FsmEvent::AppSessionDefaults {
                    metrics: LinkMetrics::default(),
                },
                7 => FsmEvent::AppSetSessionAddresses {
                    addresses: DestinationAddrs::default(),
                },
                8 => FsmEvent::TimerExpired(TIMER_HEARTBEAT, TimerKind::Heartbeat),
                9 => FsmEvent::TimerExpired(TIMER_HEARTBEAT_MISSED, TimerKind::HeartbeatMissed),
                10 => FsmEvent::TimerExpired(TIMER_SESSION_INIT, TimerKind::SessionInit),
                11 => FsmEvent::TimerExpired(TIMER_TERMINATION, TimerKind::Termination),
                12 => FsmEvent::AppShutdown {
                    reason: StatusCode::SHUTTING_DOWN,
                },
                13 => FsmEvent::TcpClosed,
                14 => FsmEvent::ProtocolError(StatusCode::INVALID_DATA),
                _ => FsmEvent::RecvExtensionMessage,
            }
        };
        pair.step(event, from_router, !delayed);
    }
    pair.drain();
});
