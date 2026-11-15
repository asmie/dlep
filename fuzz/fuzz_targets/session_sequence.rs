#![no_main]

use bytes::Bytes;
use dlep_core::{MacAddress, Message, StatusCode};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{
    DestinationAddrs, FsmAction, FsmEvent, LinkMetrics, SessionConfig, TIMER_HEARTBEAT,
    TIMER_HEARTBEAT_MISSED, TIMER_SESSION_INIT, TIMER_TERMINATION, TimerKind,
};
use libfuzzer_sys::fuzz_target;
use std::collections::VecDeque;

// Check emitted wire messages and deliver them through the real codec. A hard
// budget bounds peer response chains as well as fuzz-generated input events.
fn exchange(
    router: &mut RouterSessionFsm,
    modem: &mut ModemSessionFsm,
    actions: Vec<FsmAction>,
    from_router: bool,
) {
    let mut pending = VecDeque::from([(from_router, actions)]);
    for _ in 0..128 {
        let Some((from_router, actions)) = pending.pop_front() else {
            return;
        };
        for action in actions {
            if let FsmAction::SendMessage(message) = action {
                let bytes = message
                    .encode()
                    .expect("FSM emitted an unencodable message")
                    .freeze();
                let message = Message::decode(bytes).expect("FSM emitted an undecodable message");
                let event = FsmEvent::RecvMessage(message);
                let reply = if from_router {
                    modem.step(event)
                } else {
                    router.step(event)
                };
                pending.push_back((!from_router, reply));
            }
        }
    }
    assert!(pending.is_empty(), "unbounded peer response chain");
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut remaining)) = data.split_first() else {
        return;
    };
    let config = SessionConfig {
        mac_address_format: if mode & 2 == 0 {
            dlep_core::MacAddressFormat::Eui48
        } else {
            dlep_core::MacAddressFormat::Eui64
        },
        ..Default::default()
    };
    let mut router = RouterSessionFsm::with_config(config.clone());
    let mut modem = ModemSessionFsm::with_config(config);
    modem.step(FsmEvent::TcpAccepted);
    if mode & 1 != 0 {
        let actions = router.step(FsmEvent::TcpConnected);
        exchange(&mut router, &mut modem, actions, true);
    }
    for _ in 0..64 {
        let Some((&op, tail)) = remaining.split_first() else {
            break;
        };
        remaining = tail;
        let from_router = op & 128 != 0;
        let mac = if mode & 2 == 0 {
            MacAddress::new_eui48([2, 0, 0, 0, 0, (op >> 4) & 3])
        } else {
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, (op >> 4) & 3])
        };
        let event = match op & 15 {
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
        };
        let actions = if from_router {
            router.step(event)
        } else {
            modem.step(event)
        };
        exchange(&mut router, &mut modem, actions, from_router);
    }
});
