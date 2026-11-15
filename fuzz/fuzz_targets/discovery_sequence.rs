#![no_main]

use bytes::Bytes;
use dlep_core::{Signal, SignalType, StatusCode};
use dlep_fsm::discovery_modem::ModemDiscoveryFsm;
use dlep_fsm::discovery_router::{RouterDiscoveryFsm, TIMER_DISCOVERY};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::{FsmAction, FsmEvent, SendTarget, TimerKind};
use libfuzzer_sys::fuzz_target;
use std::collections::HashSet;
use std::net::{SocketAddr, SocketAddrV6};

fn check(actions: &[FsmAction], from: SocketAddr) {
    for action in actions {
        match action {
            FsmAction::SendSignal { signal, target } => {
                let wire = signal
                    .encode()
                    .expect("discovery emitted an unencodable signal");
                Signal::decode(wire.freeze()).expect("discovery emitted an undecodable signal");
                match target {
                    SendTarget::DiscoveryGroup => {
                        assert_eq!(signal.signal_type, SignalType::PEER_DISCOVERY)
                    }
                    SendTarget::Unicast(destination) => {
                        assert_eq!(*destination, from);
                        assert_eq!(signal.signal_type, SignalType::PEER_OFFER);
                    }
                }
            }
            FsmAction::Emit(EmittedEvent::PeerDiscovered { endpoints, .. }) => {
                assert!(!endpoints.is_empty());
                let mut seen = HashSet::new();
                let mut previous = (false, false);
                for endpoint in endpoints {
                    assert!(!endpoint.addr.ip().is_unspecified());
                    assert!(!endpoint.addr.ip().is_multicast());
                    assert_ne!(endpoint.addr.port(), 0);
                    assert!(
                        seen.insert((endpoint.addr, endpoint.use_tls)),
                        "duplicate offer endpoint"
                    );
                    let key = (!endpoint.use_tls, !endpoint.addr.is_ipv6());
                    assert!(previous <= key, "offer preference order changed");
                    previous = key;
                    if let SocketAddr::V6(addr) = endpoint.addr
                        && addr.ip().is_unicast_link_local()
                    {
                        let expected = match from {
                            SocketAddr::V6(source) => source.scope_id(),
                            _ => 0,
                        };
                        assert_eq!(addr.scope_id(), expected);
                    }
                }
            }
            _ => {}
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut remaining)) = data.split_first() else {
        return;
    };
    let source: SocketAddr = if mode & 1 == 0 {
        "192.0.2.1:49854".parse().unwrap()
    } else {
        SocketAddrV6::new("fe80::1".parse().unwrap(), 49854, 0, u32::from(mode)).into()
    };
    let endpoint = if mode & 2 == 0 {
        "192.0.2.2:854"
    } else {
        "[fe80::2]:854"
    }
    .parse()
    .unwrap();
    let mut router = RouterDiscoveryFsm::new();
    let mut modem = ModemDiscoveryFsm::new(endpoint, "fuzz-modem".into(), mode & 4 != 0);
    check(&router.step(FsmEvent::AppStartDiscovery), source);
    for _ in 0..64 {
        let Some((&op, tail)) = remaining.split_first() else {
            break;
        };
        remaining = tail;
        match op & 3 {
            0 => {
                if remaining.len() < 2 {
                    break;
                }
                let length = usize::from(u16::from_be_bytes([remaining[0], remaining[1]]));
                let tail = &remaining[2..];
                let length = length.min(tail.len());
                remaining = &tail[length..];
                if let Ok(signal) = Signal::decode(Bytes::copy_from_slice(&tail[..length])) {
                    let event = FsmEvent::RecvSignal {
                        signal,
                        from: source,
                    };
                    let actions = if op & 128 == 0 {
                        router.step(event)
                    } else {
                        modem.step(event)
                    };
                    check(&actions, source);
                }
            }
            1 => {
                // A real exchange reaches offer emission even when mutations
                // make the raw signal records undecodable.
                let actions = modem.step(FsmEvent::RecvSignal {
                    signal: dlep_fsm::discovery_common::build_peer_discovery("fuzz-router"),
                    from: source,
                });
                check(&actions, source);
                for action in actions {
                    if let FsmAction::SendSignal { signal, .. } = action {
                        let signal = Signal::decode(signal.encode().unwrap().freeze()).unwrap();
                        check(
                            &router.step(FsmEvent::RecvSignal {
                                signal,
                                from: source,
                            }),
                            source,
                        );
                    }
                }
            }
            2 => check(
                &router.step(FsmEvent::TimerExpired(
                    TIMER_DISCOVERY,
                    TimerKind::Discovery,
                )),
                source,
            ),
            _ => {
                check(
                    &router.step(FsmEvent::AppShutdown {
                        reason: StatusCode::SUCCESS,
                    }),
                    source,
                );
                check(
                    &modem.step(FsmEvent::AppShutdown {
                        reason: StatusCode::SUCCESS,
                    }),
                    source,
                );
                if op & 4 != 0 {
                    check(&router.step(FsmEvent::AppStartDiscovery), source);
                }
            }
        }
    }
});
