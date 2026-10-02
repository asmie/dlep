//! Junk UDP traffic must not delay valid discovery, periodic probes, or stop.
use dlep_core::{Signal, SignalType};
use dlep_daemon::{DaemonEvent, discovery::run_discovery, runtime::new_event_channel};
use dlep_fsm::{
    FsmEvent,
    discovery_modem::ModemDiscoveryFsm,
    discovery_router::{RouterDiscoveryConfig, RouterDiscoveryFsm},
};
use dlep_net::discovery::{DiscoveryParams, DiscoverySocket};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

const WAIT: Duration = Duration::from_secs(2);
const PROMPT: Duration = Duration::from_millis(500);

fn params() -> DiscoveryParams {
    DiscoveryParams {
        group_v4: Ipv4Addr::new(224, 0, 0, 117),
        interface_v4: Ipv4Addr::LOCALHOST,
        port: 0,
        group_port: None,
        multicast_loop: true,
        join_group: true,
    }
}

fn junk(sender: &std::net::UdpSocket, dest: SocketAddr, ttl: u32) {
    sender.set_ttl(ttl).unwrap();
    // Small enough to fit in the receive buffer; previously these imposed a
    // 3.2-second aggregate sleep before processing the valid signal behind them.
    for _ in 0..32 {
        sender.send_to(b"not DLEP", dest).unwrap();
    }
}

#[tokio::test]
async fn modem_answers_valid_probe_promptly_after_junk() {
    let socket = DiscoverySocket::bind(&params()).unwrap();
    let dest = (Ipv4Addr::LOCALHOST, socket.local_port()).into();
    let peer = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    peer.set_nonblocking(true).unwrap();
    // Queue traffic before starting the runtime to guarantee the ordering.
    junk(&peer, dest, 254);
    junk(&peer, dest, 255);
    peer.send_to(
        &Signal::new(SignalType::PEER_DISCOVERY).encode().unwrap(),
        dest,
    )
    .unwrap();
    let peer = tokio::net::UdpSocket::from_std(peer).unwrap();
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (events, _) = new_event_channel();
    let task = tokio::spawn(run_discovery(
        ModemDiscoveryFsm::new("127.0.0.1:854".parse().unwrap(), "test".into(), false),
        socket,
        None,
        stop_rx,
        events,
    ));
    let mut buf = [0; 1500];
    let (n, _) = timeout(PROMPT, peer.recv_from(&mut buf))
        .await
        .expect("junk delayed valid discovery")
        .unwrap();
    assert_eq!(
        Signal::decode(buf[..n].to_vec().into())
            .unwrap()
            .signal_type,
        SignalType::PEER_OFFER
    );
    stop_tx.send(()).await.unwrap();
    timeout(PROMPT, task).await.unwrap().unwrap().unwrap();
}

async fn router_survives_junk(ttl: u32) {
    let peer = DiscoverySocket::bind(&params()).unwrap();
    let mut config = params();
    config.join_group = false;
    config.group_port = Some(peer.local_port());
    let socket = DiscoverySocket::bind(&config).unwrap();
    let dest = (Ipv4Addr::LOCALHOST, socket.local_port()).into();
    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    junk(&sender, dest, 254);
    junk(&sender, dest, 255);
    sender
        .send_to(&Signal::new(SignalType::PEER_OFFER).encode().unwrap(), dest)
        .unwrap();
    let fsm = RouterDiscoveryFsm::with_config(RouterDiscoveryConfig {
        peer_description: "test-router".into(),
        discovery_interval: Duration::from_secs(1),
    });
    let (stop_tx, stop_rx) = mpsc::channel(1);
    let (events, mut received) = new_event_channel();
    let task = tokio::spawn(run_discovery(
        fsm,
        socket,
        Some(FsmEvent::AppStartDiscovery),
        stop_rx,
        events,
    ));
    let event = timeout(PROMPT, received.recv())
        .await
        .expect("junk delayed valid offer")
        .unwrap();
    assert!(matches!(event, DaemonEvent::PeerDiscovered(_)));
    assert_eq!(
        timeout(WAIT, peer.recv())
            .await
            .unwrap()
            .unwrap()
            .0
            .signal_type,
        SignalType::PEER_DISCOVERY
    );
    // Keep junk arriving while awaiting the periodic resend and shutdown.
    sender.set_ttl(ttl).unwrap();
    let mut flood = tokio::task::JoinSet::new();
    flood.spawn(async move {
        loop {
            for _ in 0..8 {
                sender.send_to(b"not DLEP", dest).unwrap();
            }
            tokio::task::yield_now().await;
        }
    });
    assert_eq!(
        timeout(WAIT, peer.recv())
            .await
            .expect("flood starved resend")
            .unwrap()
            .0
            .signal_type,
        SignalType::PEER_DISCOVERY
    );
    stop_tx.send(()).await.unwrap();
    timeout(PROMPT, task)
        .await
        .expect("flood starved shutdown")
        .unwrap()
        .unwrap();
    // Dropping JoinSet aborts the producer, including on an assertion failure.
}

#[tokio::test]
async fn router_accepts_offers_resends_and_stops_under_bad_ttl_traffic() {
    router_survives_junk(254).await;
}

#[tokio::test]
async fn router_accepts_offers_resends_and_stops_under_malformed_on_link_traffic() {
    router_survives_junk(255).await;
}
