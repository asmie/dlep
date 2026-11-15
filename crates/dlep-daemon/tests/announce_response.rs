use std::time::Duration;

use dlep_core::{
    DataItem, MacAddress, MacAddressFormat, Message, MessageType as M, StatusCode as S,
};
use dlep_daemon::{DaemonEvent, DestinationEvent, RouterConfig, RouterDaemon, SessionCommand};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::{FsmAction, FsmEvent, LinkMetrics, SessionConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(5);

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

async fn event(
    events: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = events.recv().await.unwrap();
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn announce_outcomes_preserve_peer_text_and_publish_state_before_completion() {
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
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.mac_address_format = format;
        let router = RouterDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap();
        let mut events = router.subscribe();
        let mut peers = Vec::new();
        let mut previous = Vec::new();
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(bind).await.unwrap();
            let addr = listener.local_addr().unwrap();
            dlep_net::gtsm::configure_tcp(&listener, addr.is_ipv6(), true).unwrap();
            router.connect_static(addr).await.unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let initial = LinkMetrics {
                current_data_rate_tx_bps: 321,
                mtu: Some(1500),
                ..Default::default()
            };
            let mut modem = ModemSessionFsm::with_config(SessionConfig {
                mac_address_format: format,
                initial_metrics: initial,
                ..Default::default()
            });
            modem.step(FsmEvent::TcpAccepted);
            let init = read(&mut peer).await;
            let reply = modem
                .step(FsmEvent::RecvMessage(init))
                .into_iter()
                .find_map(|a| match a {
                    FsmAction::SendMessage(message) => Some(message),
                    _ => None,
                })
                .unwrap();
            peer.write_all(&reply.encode().unwrap()).await.unwrap();
            let DaemonEvent::SessionUp { session_id, .. } =
                event(&mut events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await
            else {
                unreachable!()
            };
            let latency = Duration::from_micros(if addr.is_ipv6() { 666 } else { 444 });
            for status in [S::REQUEST_DENIED, S(42), S::SUCCESS] {
                router
                    .send_command_to(session_id, SessionCommand::AnnounceDestination { mac })
                    .await
                    .unwrap();
                let request = read(&mut peer).await;
                assert_eq!(request.message_type, M::DESTINATION_ANNOUNCE);
                assert_eq!(
                    dlep_fsm::session_common::extract_destination_mac(&request),
                    Some(mac)
                );
                let text = format!("peer {addr}: dostęp ✓\n\"status\" {}", status.0);
                let mut reply = Message::new(M::DESTINATION_ANNOUNCE_RESPONSE)
                    .with_item(DataItem::MacAddress(mac))
                    .with_item(DataItem::Status {
                        code: status,
                        text: text.clone(),
                    });
                if status == S::SUCCESS {
                    reply = reply.with_item(DataItem::Latency(latency));
                }
                peer.write_all(&reply.encode().unwrap()).await.unwrap();
                if status == S::SUCCESS {
                    let up = event(&mut events, |e| {
                        matches!(e, DaemonEvent::Destination { .. })
                    })
                    .await;
                    assert!(
                        matches!(up, DaemonEvent::Destination { session_id: sid, peer, event: DestinationEvent::Up { id, .. } }
                        if sid == session_id && peer.addr == addr && id.0 == mac)
                    );
                }
                let reply = event(&mut events, |e| {
                    matches!(e, DaemonEvent::Destination { .. })
                })
                .await;
                assert!(matches!(reply, DaemonEvent::Destination {
                    session_id: sid, peer, event: DestinationEvent::AnnounceResponse { id, status: got, text: got_text }
                } if sid == session_id && peer.addr == addr && id.0 == mac && got == status && got_text == text));
                // No watch wait: the response event must follow state publication.
                let state = router.state().borrow().clone();
                if status == S::SUCCESS {
                    assert_eq!(
                        state.sessions[&session_id].destinations[&mac.into()].metrics,
                        LinkMetrics { latency, ..initial }
                    );
                } else {
                    assert!(state.sessions[&session_id].destinations.is_empty());
                }
                for (sid, metrics) in &previous {
                    assert_eq!(
                        state.sessions[sid].destinations[&mac.into()].metrics,
                        *metrics
                    );
                }
            }
            previous.push((session_id, LinkMetrics { latency, ..initial }));
            peers.push(peer);
        }
        drop(peers);
        router.shutdown().await.unwrap();
    }
}
