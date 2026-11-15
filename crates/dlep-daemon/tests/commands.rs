use dlep_core::{
    DataItem, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
use dlep_daemon::{
    AddressChanges, CommandError as C, DaemonError, DaemonEvent, DestinationAddrs,
    DestinationEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon, SessionCommand,
};
use dlep_ext::SessionId;
use dlep_fsm::session_common::{build_destination_down_response, build_destination_up_response};
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{FsmAction as A, FsmEvent as E};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    sync::broadcast,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(3);
fn id() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}
async fn modem() -> ModemDaemon {
    modem_on("127.0.0.1", MacAddressFormat::Eui48).await
}
async fn modem_on(ip: &str, format: MacAddressFormat) -> ModemDaemon {
    let mut c = ModemConfig::default();
    c.shared.network.mac_address_format = format;
    c.shared.network.use_tls = false;
    c.shared.network.bind_addr = ip.parse().unwrap();
    c.shared.network.tcp_port = 0;
    c.shared.network.discovery_port = 0;
    ModemDaemon::builder().config(c).spawn().await.unwrap()
}
async fn read(peer: &mut TcpStream) -> Message {
    timeout(WAIT, async {
        let mut header = [0; 4];
        peer.read_exact(&mut header).await.unwrap();
        let mut bytes = header.to_vec();
        bytes.resize(
            4 + usize::from(u16::from_be_bytes([header[2], header[3]])),
            0,
        );
        peer.read_exact(&mut bytes[4..]).await.unwrap();
        Message::decode(bytes.into()).unwrap()
    })
    .await
    .unwrap()
}
async fn send(peer: &mut TcpStream, message: Message) {
    peer.write_all(&message.encode().unwrap()).await.unwrap();
}
async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = rx.recv().await.unwrap();
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}
async fn peer(
    m: &ModemDaemon,
    events: &mut broadcast::Receiver<DaemonEvent>,
) -> (TcpStream, SessionId) {
    let is_v6 = m.local_addr().is_ipv6();
    let socket = if is_v6 {
        TcpSocket::new_v6()
    } else {
        TcpSocket::new_v4()
    }
    .unwrap();
    dlep_net::gtsm::configure_tcp(&socket, is_v6, true).unwrap();
    let mut peer = socket.connect(m.local_addr()).await.unwrap();
    let mut r = RouterSessionFsm::new();
    let init = r
        .step(E::TcpConnected)
        .into_iter()
        .find_map(|a| match a {
            A::SendMessage(m) => Some(m),
            _ => None,
        })
        .unwrap();
    send(&mut peer, init).await;
    assert_eq!(
        read(&mut peer).await.message_type,
        M::SESSION_INITIALIZATION_RESPONSE
    );
    let sid = match event(events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await {
        DaemonEvent::SessionUp { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    (peer, sid)
}
fn rejected(error: DaemonError, sid: SessionId, reason: C) {
    let DaemonError::CommandRejected(report) = error else {
        panic!("unexpected error {error:?}");
    };
    assert!(report.accepted.is_empty());
    assert_eq!(report.unknown, 0);
    assert_eq!(report.undelivered, 0);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].0, sid);
    assert_eq!(report.rejected[0].1.reason, reason);
}
async fn ack_up(peer: &mut TcpStream) {
    send(peer, build_destination_up_response(id().0, S::SUCCESS)).await;
    // A response on the same stream proves the Up acknowledgement was handled.
    send(peer, Message::new(M::SESSION_UPDATE)).await;
    assert_eq!(read(peer).await.message_type, M::SESSION_UPDATE_RESPONSE);
}

#[tokio::test]
async fn destination_up_outcomes_publish_current_state_and_keep_routers_isolated() {
    use dlep_daemon::DestinationPhase as P;
    use dlep_fsm::session_common::{build_destination_announce, extract_link_metrics};

    for (format, mac) in [
        (
            MacAddressFormat::Eui48,
            MacAddress::new_eui48([2, 0, 0, 0, 0, 1]),
        ),
        (
            MacAddressFormat::Eui64,
            MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
        ),
    ] {
        for ip in ["127.0.0.1", "::1"] {
            let m = modem_on(ip, format).await;
            let mut events = m.subscribe();
            let (mut a, aid) = peer(&m, &mut events).await;
            let (mut b, bid) = peer(&m, &mut events).await;
            m.add_destination(mac.into(), LinkMetrics::default())
                .await
                .unwrap();
            for stream in [&mut a, &mut b] {
                assert_eq!(read(stream).await.message_type, M::DESTINATION_UP);
            }
            let expected = LinkMetrics {
                latency: Duration::from_micros(321),
                ..Default::default()
            };
            let addrs = DestinationAddrs {
                v4: vec!["192.0.2.1".parse().unwrap()],
                ..Default::default()
            };
            m.update_destination(mac.into(), expected).await.unwrap();
            m.update_destination_addresses(
                mac.into(),
                AddressChanges {
                    added: addrs.clone(),
                    removed: Default::default(),
                },
            )
            .await
            .unwrap();
            for (stream, sid, status, phase) in [
                (&mut a, aid, S::NOT_INTERESTED, P::Withdrawn),
                (&mut b, bid, S::SUCCESS, P::Up),
            ] {
                let addr = stream.local_addr().unwrap();
                let text = format!("router {sid:?}: dostęp ✓\n\"reply\"");
                send(
                    stream,
                    Message::new(M::DESTINATION_UP_RESPONSE)
                        .with_item(DataItem::MacAddress(mac))
                        .with_item(DataItem::Status {
                            code: status,
                            text: text.clone(),
                        }),
                )
                .await;
                let reply = event(&mut events, |e| {
                    matches!(e, DaemonEvent::Destination { .. })
                })
                .await;
                assert!(matches!(reply, DaemonEvent::Destination {
                    session_id, peer, event: DestinationEvent::UpResponse { id, status: got, text: got_text }
                } if session_id == sid && peer.addr == addr && id.0 == mac && got == status && got_text == text));
                // The completion event follows publication, including queued values.
                let state = m.state().borrow().clone();
                let destination = &state.sessions[&sid].destinations[&mac.into()];
                assert_eq!(destination.phase, phase);
                assert_eq!(destination.metrics, expected);
                assert_eq!(destination.addresses, addrs);
                assert_eq!(
                    state.sessions[&aid].destinations[&mac.into()].phase,
                    P::Withdrawn
                );
                assert_eq!(
                    state.sessions[&bid].destinations[&mac.into()].phase,
                    if sid == aid { P::PendingUp } else { P::Up }
                );
                if status == S::SUCCESS {
                    let update = read(stream).await;
                    assert_eq!(update.message_type, M::DESTINATION_UPDATE);
                    assert_eq!(extract_link_metrics(&update), Some(expected));
                    assert_eq!(AddressChanges::from_message(&update).added, addrs);
                }
            }
            send(&mut a, build_destination_announce(mac)).await;
            let restored = read(&mut a).await;
            assert_eq!(restored.message_type, M::DESTINATION_ANNOUNCE_RESPONSE);
            assert_eq!(extract_link_metrics(&restored), Some(expected));
            assert_eq!(AddressChanges::from_message(&restored).added, addrs);
            drop((a, b));
            m.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn session_defaults_preserve_destination_phases_and_other_sessions() {
    use dlep_daemon::DestinationPhase as P;
    use dlep_fsm::session_common::{
        build_destination_announce, build_destination_down, build_session_update_response,
        extract_link_metrics,
    };
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        for ip in ["127.0.0.1", "::1"] {
            let destination = DestinationId::from(match format {
                MacAddressFormat::Eui48 => id().0,
                MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
            });
            let m = modem_on(ip, format).await;
            let mut events = m.subscribe();
            let (mut a, aid) = peer(&m, &mut events).await;
            let (mut b, bid) = peer(&m, &mut events).await;
            let expected = LinkMetrics {
                latency: Duration::from_micros(999),
                ..Default::default()
            };
            m.add_destination(destination, expected).await.unwrap();
            for stream in [&mut a, &mut b] {
                assert_eq!(read(stream).await.message_type, M::DESTINATION_UP);
            }
            // A remains pending Up; B acknowledges and must stay unaffected.
            send(
                &mut b,
                build_destination_up_response(destination.0, S::SUCCESS),
            )
            .await;
            send(&mut b, Message::new(M::SESSION_UPDATE)).await;
            assert_eq!(read(&mut b).await.message_type, M::SESSION_UPDATE_RESPONSE);
            for (phase, latency) in [
                (P::PendingUp, 42),
                (P::Up, 84),
                (P::Withdrawn, 126),
                (P::PendingDown, 168),
            ] {
                if phase == P::Withdrawn {
                    send(&mut a, build_destination_down(destination.0, S::SUCCESS)).await;
                    assert_eq!(
                        read(&mut a).await.message_type,
                        M::DESTINATION_DOWN_RESPONSE
                    );
                    send(&mut a, Message::new(M::SESSION_UPDATE)).await;
                    assert_eq!(read(&mut a).await.message_type, M::SESSION_UPDATE_RESPONSE);
                } else if phase == P::PendingDown {
                    send(&mut a, build_destination_announce(destination.0)).await;
                    let announced = read(&mut a).await;
                    assert_eq!(announced.message_type, M::DESTINATION_ANNOUNCE_RESPONSE);
                    assert_eq!(extract_link_metrics(&announced), Some(expected));
                    m.send_command_to(
                        aid,
                        SessionCommand::DropDestination {
                            mac: destination.0,
                            reason: S::SUCCESS,
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(read(&mut a).await.message_type, M::DESTINATION_DOWN);
                }
                let defaults = LinkMetrics {
                    latency: Duration::from_micros(latency),
                    ..Default::default()
                };
                let generation = m.state().borrow().generation;
                m.send_command_to(aid, SessionCommand::SessionDefaults { metrics: defaults })
                    .await
                    .unwrap();
                let state = m.state().borrow().clone();
                // Default and destination changes form one retained-state update.
                assert_eq!(state.generation, generation + 1);
                assert_eq!(state.sessions[&aid].metrics, defaults);
                assert_eq!(
                    state.sessions[&aid].destinations[&destination].metrics,
                    expected
                );
                assert_eq!(state.sessions[&aid].destinations[&destination].phase, phase);
                assert_eq!(state.sessions[&bid].metrics, LinkMetrics::default());
                assert_eq!(
                    state.sessions[&bid].destinations[&destination].metrics,
                    expected
                );
                let update = read(&mut a).await;
                assert_eq!(update.message_type, M::SESSION_UPDATE);
                assert_eq!(extract_link_metrics(&update), Some(defaults));
                if phase == P::PendingUp {
                    send(
                        &mut a,
                        build_destination_up_response(destination.0, S::SUCCESS),
                    )
                    .await;
                }
                if matches!(phase, P::PendingUp | P::Up) {
                    let correction = read(&mut a).await;
                    assert_eq!(correction.message_type, M::DESTINATION_UPDATE);
                    assert_eq!(extract_link_metrics(&correction), Some(expected));
                }
                send(&mut a, build_session_update_response(S::SUCCESS)).await;
                // Stream barriers prove no extra updates or announcements were sent.
                for stream in [&mut a, &mut b] {
                    send(stream, Message::new(M::SESSION_UPDATE)).await;
                    assert_eq!(read(stream).await.message_type, M::SESSION_UPDATE_RESPONSE);
                }
            }
            send(
                &mut a,
                build_destination_down_response(destination.0, S::SUCCESS),
            )
            .await;
            send(&mut a, Message::new(M::SESSION_UPDATE)).await;
            assert_eq!(read(&mut a).await.message_type, M::SESSION_UPDATE_RESPONSE);
            assert!(
                !m.state().borrow().sessions[&aid]
                    .destinations
                    .contains_key(&destination)
            );
            drop((a, b));
            m.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn queued_session_metrics_preserve_later_reports_on_the_original_session() {
    use dlep_fsm::session_common::{build_session_update_response, extract_link_metrics};
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        for ip in ["127.0.0.1", "::1"] {
            let destination = DestinationId::from(match format {
                MacAddressFormat::Eui48 => id().0,
                MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
            });
            let m = modem_on(ip, format).await;
            let mut events = m.subscribe();
            let (mut peer, sid) = peer(&m, &mut events).await;
            m.add_destination(destination, LinkMetrics::default())
                .await
                .unwrap();
            assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_UP);
            send(
                &mut peer,
                build_destination_up_response(destination.0, S::SUCCESS),
            )
            .await;
            send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
            assert_eq!(
                read(&mut peer).await.message_type,
                M::SESSION_UPDATE_RESPONSE
            );
            m.update_session_addresses(
                sid,
                AddressChanges {
                    added: DestinationAddrs {
                        v4: vec!["192.0.2.5".parse().unwrap()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            assert_eq!(read(&mut peer).await.message_type, M::SESSION_UPDATE);
            let mut defaults = LinkMetrics::default();
            for latency in [100, 200, 300] {
                defaults.latency = Duration::from_micros(latency);
                m.queue_session_metrics(defaults).await.unwrap();
            }
            rejected(
                m.update_session_metrics(LinkMetrics::default())
                    .await
                    .unwrap_err(),
                sid,
                C::Busy,
            );
            assert!(matches!(
                m.queue_session_metrics(LinkMetrics {
                    resources: Some(50),
                    ..defaults
                })
                .await,
                Err(DaemonError::Config(_))
            ));
            let expected = LinkMetrics {
                latency: Duration::from_micros(999),
                ..defaults
            };
            m.update_destination(destination, expected).await.unwrap();
            assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_UPDATE);
            // Accepted queued values are visible locally before wire delivery.
            let state = m.state().borrow().clone();
            assert_eq!(state.sessions[&sid].metrics, defaults);
            assert_eq!(
                state.sessions[&sid].destinations[&destination].metrics,
                expected
            );
            send(&mut peer, build_session_update_response(S::SUCCESS)).await;
            let update = read(&mut peer).await;
            assert_eq!(update.message_type, M::SESSION_UPDATE);
            assert_eq!(extract_link_metrics(&update), Some(defaults));
            let correction = read(&mut peer).await;
            assert_eq!(correction.message_type, M::DESTINATION_UPDATE);
            assert_eq!(extract_link_metrics(&correction), Some(expected));
            send(&mut peer, build_session_update_response(S::SUCCESS)).await;
            send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
            assert_eq!(
                read(&mut peer).await.message_type,
                M::SESSION_UPDATE_RESPONSE
            );
            let state = m.state().borrow().clone();
            assert_eq!(state.sessions.len(), 1);
            assert_eq!(state.sessions[&sid].metrics, defaults);
            assert_eq!(
                state.sessions[&sid].destinations[&destination].metrics,
                expected
            );
            // A later default supersedes the previous per-destination override.
            m.queue_session_metrics(defaults).await.unwrap();
            assert_eq!(read(&mut peer).await.message_type, M::SESSION_UPDATE);
            assert_eq!(
                m.state().borrow().sessions[&sid].destinations[&destination].metrics,
                defaults
            );
            drop(peer);
            m.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn modem_busy_commands_return_errors_then_retry_reaches_wire() {
    let m = modem().await;
    let mut events = m.subscribe();
    let (mut peer, sid) = peer(&m, &mut events).await;
    m.add_destination(id(), LinkMetrics::default())
        .await
        .unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_UP);
    rejected(
        m.drop_destination(id(), S::SUCCESS).await.unwrap_err(),
        sid,
        C::Busy,
    );
    let rejection = event(&mut events, |e| {
        matches!(e, DaemonEvent::CommandRejected { .. })
    })
    .await;
    assert!(
        matches!(rejection, DaemonEvent::CommandRejected { session_id, rejection, .. } if session_id == sid && rejection.reason == C::Busy && rejection.command.destination == Some(id().0))
    );
    ack_up(&mut peer).await;
    m.drop_destination(id(), S::SUCCESS).await.unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::DESTINATION_DOWN);
    rejected(
        m.update_destination(id(), LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    rejected(
        m.update_destination_addresses(id(), Default::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    send(
        &mut peer,
        build_destination_down_response(id().0, S::SUCCESS),
    )
    .await;
    send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
    assert_eq!(
        read(&mut peer).await.message_type,
        M::SESSION_UPDATE_RESPONSE
    );
    rejected(
        m.update_destination(id(), LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::UnknownDestination,
    );
    // Session metrics and addresses share the same transaction slot.
    m.update_session_metrics(LinkMetrics::default())
        .await
        .unwrap();
    assert_eq!(read(&mut peer).await.message_type, M::SESSION_UPDATE);
    rejected(
        m.update_session_addresses(sid, Default::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    rejected(
        m.update_session_metrics(LinkMetrics::default())
            .await
            .unwrap_err(),
        sid,
        C::Busy,
    );
    // A pending transaction must not stop graceful shutdown.
    let shutdown = tokio::spawn(m.shutdown());
    assert_eq!(read(&mut peer).await.message_type, M::SESSION_TERMINATION);
    send(&mut peer, Message::new(M::SESSION_TERMINATION_RESPONSE)).await;
    timeout(WAIT, shutdown).await.unwrap().unwrap().unwrap();
}

#[tokio::test]
async fn broadcast_partial_acceptance_reports_sessions_and_targeted_retry_is_isolated() {
    let m = modem().await;
    let mut events = m.subscribe();
    assert!(matches!(
        m.add_destination(id(), LinkMetrics::default()).await,
        Err(DaemonError::NoMatchingSession)
    ));
    let (mut first, one) = peer(&m, &mut events).await;
    let (mut second, two) = peer(&m, &mut events).await;
    m.send_command_to(
        one,
        SessionCommand::AddDestination {
            mac: id().0,
            metrics: LinkMetrics::default(),
            addrs: Default::default(),
        },
    )
    .await
    .unwrap();
    assert_eq!(read(&mut first).await.message_type, M::DESTINATION_UP);
    let error = m
        .add_destination(id(), LinkMetrics::default())
        .await
        .unwrap_err();
    let DaemonError::CommandRejected(report) = error else {
        panic!("{error:?}")
    };
    assert_eq!(report.accepted, [two]);
    assert_eq!(report.rejected.len(), 1);
    assert_eq!(report.rejected[0].0, one);
    assert_eq!(report.rejected[0].1.reason, C::Busy);
    assert_eq!(read(&mut second).await.message_type, M::DESTINATION_UP);
    ack_up(&mut first).await;
    ack_up(&mut second).await;
    m.send_command_to(
        one,
        SessionCommand::DropDestination {
            mac: id().0,
            reason: S::SUCCESS,
        },
    )
    .await
    .unwrap();
    assert_eq!(read(&mut first).await.message_type, M::DESTINATION_DOWN);
    assert!(
        timeout(Duration::from_millis(50), read(&mut second))
            .await
            .is_err()
    );
    assert!(matches!(
        m.update_session_addresses(SessionId(u64::MAX), Default::default())
            .await,
        Err(DaemonError::NoMatchingSession)
    ));
    drop(first);
    drop(second);
    m.shutdown().await.unwrap();
}

#[tokio::test]
async fn coalesced_address_updates_split_without_closing_the_session() {
    address_replacement_on_wire(true).await;
}

#[tokio::test]
async fn address_updates_include_mac_overhead_when_splitting() {
    address_replacement_on_wire(false).await;
}

async fn address_replacement_on_wire(pending_up: bool) {
    for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
        for ip in ["127.0.0.1", "::1"] {
            let destination = DestinationId::from(match format {
                MacAddressFormat::Eui48 => MacAddress::new_eui48([2, 0, 0, 0, 0, 1]),
                MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
            });
            let m = modem_on(ip, format).await;
            let mut events = m.subscribe();
            let (mut peer, sid) = peer(&m, &mut events).await;
            let count = if pending_up { 3000 } else { 1560 };
            let addresses = |prefix| DestinationAddrs {
                v6: (1..=count)
                    .map(|suffix| {
                        std::net::Ipv6Addr::new(0x2001, 0xdb8, prefix, 0, 0, 0, 0, suffix)
                    })
                    .collect(),
                ..Default::default()
            };
            let old = addresses(1);
            let new = DestinationAddrs {
                v4: vec!["192.0.2.1".parse().unwrap()],
                ..addresses(2)
            };
            m.add_destination_with_addresses(destination, LinkMetrics::default(), old.clone())
                .await
                .unwrap();
            let up = read(&mut peer).await;
            assert_eq!(up.message_type, M::DESTINATION_UP);
            let mut observed = AddressChanges::from_message(&up).added;
            assert_eq!(observed, old);
            if !pending_up {
                send(
                    &mut peer,
                    build_destination_up_response(destination.0, S::SUCCESS),
                )
                .await;
                send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
                assert_eq!(
                    read(&mut peer).await.message_type,
                    M::SESSION_UPDATE_RESPONSE
                );
            }
            let chunk = if pending_up { 1000 } else { 1560 };
            for start in (0..usize::from(count)).step_by(chunk) {
                let changes = AddressChanges {
                    added: DestinationAddrs {
                        v6: new.v6[start..start + chunk].to_vec(),
                        v4: if start == 0 {
                            new.v4.clone()
                        } else {
                            Vec::new()
                        },
                        ..Default::default()
                    },
                    removed: DestinationAddrs {
                        v6: old.v6[start..start + chunk].to_vec(),
                        ..Default::default()
                    },
                };
                // The live case is 65,529 bytes of address items: it fits the
                // public API's batch limit but needs splitting once the MAC is
                // included. Pending batches are smaller and accumulate later.
                m.update_destination_addresses(destination, changes)
                    .await
                    .unwrap();
            }
            if pending_up {
                m.update_destination(
                    destination,
                    LinkMetrics {
                        latency: Duration::from_micros(900),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
                send(
                    &mut peer,
                    build_destination_up_response(destination.0, S::SUCCESS),
                )
                .await;
            }
            // This response comes after all destination chunks on the stream
            // and demonstrates that the same session is still usable.
            send(&mut peer, Message::new(M::SESSION_UPDATE)).await;
            let mut updates = 0;
            let mut metrics = 0;
            loop {
                let message = read(&mut peer).await;
                if message.message_type == M::SESSION_UPDATE_RESPONSE {
                    break;
                }
                assert_eq!(message.message_type, M::DESTINATION_UPDATE);
                assert_eq!(
                    dlep_fsm::session_common::extract_destination_mac(&message),
                    Some(destination.0)
                );
                AddressChanges::from_message(&message)
                    .apply_strict(&mut observed)
                    .unwrap();
                if let Some(current) = dlep_fsm::session_common::extract_link_metrics(&message) {
                    assert_eq!(current.latency, Duration::from_micros(900));
                    metrics += 1;
                }
                updates += 1;
            }
            assert_eq!(updates, 2);
            assert_eq!(metrics, usize::from(pending_up));
            assert_eq!(observed, new);
            let state = m.state().borrow().clone();
            assert_eq!(
                state.sessions[&sid].destinations[&destination].addresses,
                new
            );
            m.update_destination(
                destination,
                LinkMetrics {
                    latency: Duration::from_micros(1000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            let later = read(&mut peer).await;
            assert_eq!(later.message_type, M::DESTINATION_UPDATE);
            assert_eq!(
                dlep_fsm::session_common::extract_link_metrics(&later)
                    .unwrap()
                    .latency,
                Duration::from_micros(1000)
            );
            drop(peer);
            m.shutdown().await.unwrap();
        }
    }
}
