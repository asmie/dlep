//! Named IPv6 zones choose the route while TLS verifies the bare numeric IP.
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, ModemConfig, ModemDaemon, RouterConfig,
    RouterDaemon, ScopedPeer,
};
use dlep_net::tls::test_helpers::{
    client_config_for, self_signed_for_dns, self_signed_for_ip, server_config_for,
};
use std::time::Duration;

#[tokio::test]
async fn named_zone_connects_scoped_tls_and_delivers_destinations_with_ip_identity() {
    let ip = "fe80::1".parse().unwrap();
    for ip_certificate in [false, true] {
        let pki = if ip_certificate {
            self_signed_for_ip(ip)
        } else {
            self_signed_for_dns("dlep-test")
        };
        let client = client_config_for(pki.roots);
        let mut config = ModemConfig::default();
        config.shared.network.bind_addr = ip;
        config.shared.network.interface = Some("dlep-test".into());
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let modem = ModemDaemon::builder()
            .config(config)
            .with_rustls_server(server_config_for(pki.cert_der, pki.key_der))
            .spawn()
            .await
            .unwrap();
        let mut modem_events = modem.subscribe();
        let router = RouterDaemon::builder()
            .config(RouterConfig::default())
            .with_rustls_client(client)
            .spawn()
            .await
            .unwrap();
        let mut events = router.subscribe();
        let peer = ScopedPeer::new(
            "fe80::1".parse().unwrap(),
            "dlep-test",
            modem.local_addr().port(),
        )
        .unwrap();
        let result = router.connect_scoped(&peer).await;
        if ip_certificate {
            let connected = result.unwrap();
            assert_eq!(connected, modem.local_addr());
            assert!(matches!(connected, std::net::SocketAddr::V6(addr) if addr.scope_id() > 0));
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let DaemonEvent::SessionUp { peer, .. } = events.recv().await.unwrap() {
                        assert!(peer.is_tls);
                        assert_eq!(peer.addr, connected);
                        break;
                    }
                }
            })
            .await
            .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if matches!(
                        modem_events.recv().await.unwrap(),
                        DaemonEvent::SessionUp { .. }
                    ) {
                        break;
                    }
                }
            })
            .await
            .unwrap();
            modem
                .add_destination(
                    DestinationId(dlep_core::MacAddress::new_eui48([2, 0, 0, 0, 81, 1])),
                    Default::default(),
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let DaemonEvent::Destination {
                        peer,
                        event: DestinationEvent::Up { .. },
                        ..
                    } = events.recv().await.unwrap()
                    {
                        assert_eq!(peer.addr, connected);
                        break;
                    }
                }
            })
            .await
            .unwrap();
        } else {
            assert!(
                result.is_err(),
                "an interface-name DNS certificate must not verify the IP peer"
            );
            assert!(router.state().borrow().sessions.is_empty());
            assert_eq!(router.connection_capacity(), 64);
        }
        router.shutdown().await.unwrap();
        modem.shutdown().await.unwrap();
    }
}
