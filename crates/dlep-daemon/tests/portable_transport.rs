//! Unprivileged loopback coverage for macOS/FreeBSD transport and Linux opt-out.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dlep_core::{Signal, SignalType};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, ModemConfig, ModemDaemon, NetworkConfig,
    RouterConfig, RouterDaemon,
};
use dlep_net::addr::InterfaceSpec;
use dlep_net::discovery::{DiscoveryParams, DiscoveryParamsV6, DiscoverySocket};
use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_ip, server_config_for};
use tokio::sync::broadcast::Receiver;

async fn event(
    rx: &mut Receiver<DaemonEvent>,
    accepts: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = rx.recv().await.unwrap();
            if accepts(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

async fn session(ip: IpAddr, tls: bool) {
    let network = NetworkConfig {
        bind_addr: ip,
        tcp_port: 0,
        discovery_port: 0,
        use_tls: tls,
        gtsm_enforce: false,
        ..Default::default()
    };
    let mut config = ModemConfig::default();
    config.shared.network = network.clone();
    let mut builder = ModemDaemon::builder().config(config);
    let pki = self_signed_for_ip(ip);
    let client = client_config_for(pki.roots);
    if tls {
        builder = builder.with_rustls_server(server_config_for(pki.cert_der, pki.key_der));
    }
    let modem = builder.spawn().await.unwrap();
    let mut modem_events = modem.subscribe();
    let mut config = RouterConfig::default();
    config.shared.network = network;
    let mut builder = RouterDaemon::builder().config(config);
    if tls {
        builder = builder.with_rustls_client(client);
    }
    let router = builder.spawn().await.unwrap();
    let mut events = router.subscribe();
    router.connect_static(modem.local_addr()).await.unwrap();
    let up = event(&mut events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await;
    assert!(matches!(up, DaemonEvent::SessionUp { peer, .. } if peer.is_tls == tls));
    event(&mut modem_events, |e| {
        matches!(e, DaemonEvent::SessionUp { .. })
    })
    .await;
    let destination = DestinationId(dlep_core::MacAddress::new_eui48([2, 0, 0, 0, 79, 1]));
    modem
        .add_destination(destination, Default::default())
        .await
        .unwrap();
    event(&mut events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Up { .. },
                ..
            }
        )
    })
    .await;
    assert_eq!(router.state().borrow().sessions.len(), 1);
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn unprivileged_ipv4_plaintext_session() {
    session(Ipv4Addr::LOCALHOST.into(), false).await;
}
#[tokio::test]
async fn unprivileged_ipv6_plaintext_session() {
    session(Ipv6Addr::LOCALHOST.into(), false).await;
}
#[tokio::test]
async fn unprivileged_ipv4_tls_session() {
    session(Ipv4Addr::LOCALHOST.into(), true).await;
}
#[tokio::test]
async fn unprivileged_ipv6_tls_session() {
    session(Ipv6Addr::LOCALHOST.into(), true).await;
}

fn discovery(ip: IpAddr) -> DiscoverySocket {
    match ip {
        IpAddr::V4(local) => DiscoverySocket::bind(&DiscoveryParams {
            group_v4: dlep_core::DISCOVERY_IPV4_GROUP,
            interface_v4: local,
            port: 0,
            group_port: None,
            multicast_loop: true,
            join_group: false,
        }),
        IpAddr::V6(local) => DiscoverySocket::bind_v6(
            &DiscoveryParamsV6 {
                group: dlep_core::DISCOVERY_IPV6_GROUP,
                local_address: local,
                port: 0,
                group_port: None,
                multicast_loop: true,
                join_group: false,
            },
            &InterfaceSpec::Any,
        ),
    }
    .unwrap()
}

#[tokio::test]
async fn discovery_retains_ttl_local_address_and_ingress_interface_on_both_families() {
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let receiver = discovery(ip);
        let sender = discovery(ip);
        let signal = Signal::new(SignalType::PEER_DISCOVERY);
        sender
            .send_unicast(&signal, SocketAddr::new(ip, receiver.local_port()))
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), receiver.recv_with_metadata())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.ttl, 255);
        assert_eq!(received.from.ip(), ip);
        assert_eq!(received.local_addr, ip);
        assert_eq!(Some(received.interface_index), receiver.interface_index());
    }
}

#[tokio::test]
async fn multicast_discovery_resolves_a_unicast_local_address_and_reply_source() {
    let mut params = DiscoveryParams {
        group_v4: dlep_core::DISCOVERY_IPV4_GROUP,
        interface_v4: Ipv4Addr::LOCALHOST,
        port: 0,
        group_port: None,
        multicast_loop: true,
        join_group: true,
    };
    let receiver = DiscoverySocket::bind(&params).unwrap();
    params.join_group = false;
    params.group_port = Some(receiver.local_port());
    let sender = DiscoverySocket::bind(&params).unwrap();
    sender
        .send_to_group(&Signal::new(SignalType::PEER_DISCOVERY))
        .await
        .unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), receiver.recv_with_metadata())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(Some(received.interface_index), receiver.interface_index());
    assert_eq!(received.ttl, 255);
    receiver
        .send_unicast(&Signal::new(SignalType::PEER_OFFER), received.from)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(3), sender.recv_with_metadata())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.from.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(reply.signal.signal_type, SignalType::PEER_OFFER);
    assert_eq!(reply.ttl, 255);
}

#[tokio::test]
async fn discovery_still_rejects_low_ttl_before_decoding() {
    // This path remains enforced even when TCP receive enforcement is disabled.
    let receiver = discovery(Ipv4Addr::LOCALHOST.into());
    let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let target = (Ipv4Addr::LOCALHOST, receiver.local_port());
    sender.set_ttl(254).unwrap();
    sender
        .send_to(b"malformed off-link signal", target)
        .unwrap();
    sender.set_ttl(255).unwrap();
    let signal = Signal::new(SignalType::PEER_DISCOVERY);
    sender.send_to(&signal.encode().unwrap(), target).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(3), receiver.recv_with_metadata())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received.ttl, 255);
    assert_eq!(received.signal.encode().unwrap(), signal.encode().unwrap());
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn strict_tcp_enforcement_requires_explicit_opt_out_before_startup() {
    let mut router = RouterConfig::default();
    router.shared.network.use_tls = false;
    let mut modem = ModemConfig::default();
    modem.shared.network.use_tls = false;
    for error in [
        dlep_daemon::check_router_config(&router).unwrap_err(),
        dlep_daemon::check_modem_config(&modem).unwrap_err(),
    ] {
        assert!(error.to_string().contains("gtsm_enforce = false"));
    }
    assert!(
        RouterDaemon::builder()
            .config(router.clone())
            .spawn()
            .await
            .is_err()
    );
    assert!(
        ModemDaemon::builder()
            .config(modem.clone())
            .spawn()
            .await
            .is_err()
    );
    router.shared.network.gtsm_enforce = false;
    modem.shared.network.gtsm_enforce = false;
    dlep_daemon::check_router_config(&router).unwrap();
    dlep_daemon::check_modem_config(&modem).unwrap();
}
