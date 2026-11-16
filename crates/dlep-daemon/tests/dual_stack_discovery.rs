//! Simultaneous UDP families with one configured TCP listener per modem.
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, ModemConfig, ModemDaemon, NetworkConfig,
    RouterConfig, RouterDaemon, check_modem_config, check_router_config,
};
use dlep_ext::{DiscoveryCtx, DiscoveryInfo, DlepExtension};
use dlep_net::tls::test_helpers::{client_config_for, self_signed_for_ip, server_config_for};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::broadcast::Receiver;

fn network(bind: &str, port: u16, dual: bool) -> NetworkConfig {
    NetworkConfig {
        bind_addr: bind.parse().unwrap(),
        interface: Some("dlep-test".into()),
        discovery_dual_stack: dual,
        discovery_port: port,
        tcp_port: 0,
        use_tls: false,
        ..Default::default()
    }
}
async fn event(
    rx: &mut Receiver<DaemonEvent>,
    accept: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = rx.recv().await.unwrap();
            if accept(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}
struct Observer(Mutex<Vec<DiscoveryInfo>>);
impl DlepExtension for Observer {
    fn advertised_ids(&self) -> &[dlep_core::ExtensionId] {
        &[dlep_core::ExtensionId(0xF050)]
    }
    fn supports_discovery(&self) -> bool {
        true
    }
    fn on_discovery_signal(&self, _: &dlep_core::Signal, ctx: &mut dyn DiscoveryCtx) {
        self.0.lock().unwrap().push(ctx.info());
    }
}

#[tokio::test]
async fn one_router_discovers_and_uses_ipv4_only_and_ipv6_only_modems() {
    let mut modems = Vec::new();
    for (bind, label) in [("192.0.2.1", "v4-modem"), ("fe80::1", "v6-modem")] {
        let mut config = ModemConfig {
            peer_description: label.into(),
            ..Default::default()
        };
        config.shared.network = network(bind, 50088, false);
        modems.push(ModemDaemon::builder().config(config).spawn().await.unwrap());
    }
    let observer = Arc::new(Observer(Mutex::new(Vec::new())));
    let mut config = RouterConfig::default();
    config.shared.network = network("0.0.0.0", 50088, true);
    let router = RouterDaemon::builder()
        .config(config)
        .register_extension(observer.clone())
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    router.start_discovery().await.unwrap();
    let mut offers = HashMap::new();
    while offers.len() < 2 {
        if let DaemonEvent::PeerDiscovered(offer) = event(&mut events, |event| {
            matches!(event, DaemonEvent::PeerDiscovered(_))
        })
        .await
        {
            offers.insert(offer.peer_description.clone().unwrap(), offer);
        }
    }
    assert!(offers["v4-modem"].endpoints[0].addr.is_ipv4());
    let std::net::SocketAddr::V6(v6) = offers["v6-modem"].endpoints[0].addr else {
        panic!("IPv6 endpoint");
    };
    assert!(v6.scope_id() > 0);
    let metadata = observer.0.lock().unwrap().clone();
    assert!(metadata.iter().any(|info| info.peer.unwrap().is_ipv4()));
    assert!(metadata.iter().any(|info| info.peer.unwrap().is_ipv6()));
    for offer in offers.values() {
        router.connect_discovered(offer).await.unwrap();
    }
    for _ in 0..2 {
        event(&mut events, |event| {
            matches!(event, DaemonEvent::SessionUp { .. })
        })
        .await;
    }
    assert_eq!(router.state().borrow().sessions.len(), 2);
    for (index, modem) in modems.iter().enumerate() {
        modem
            .add_destination(
                DestinationId(dlep_core::MacAddress::new_eui48([
                    2,
                    0,
                    0,
                    0,
                    78,
                    index as u8,
                ])),
                Default::default(),
            )
            .await
            .unwrap();
    }
    let mut endpoints = HashSet::new();
    while endpoints.len() < 2 {
        if let DaemonEvent::Destination { peer, .. } = event(&mut events, |event| {
            matches!(
                event,
                DaemonEvent::Destination {
                    event: DestinationEvent::Up { .. },
                    ..
                }
            )
        })
        .await
        {
            endpoints.insert(peer.addr);
        }
    }
    router.shutdown().await.unwrap();
    for modem in modems {
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn dual_family_modem_offers_usable_wildcard_tcp_endpoints_and_tls_on_both_transports() {
    for (index, bind) in ["0.0.0.0", "::"].into_iter().enumerate() {
        let port = 50089 + index as u16;
        let ip: std::net::IpAddr = if index == 0 { "192.0.2.1" } else { "fe80::1" }
            .parse()
            .unwrap();
        let pki = self_signed_for_ip(ip);
        let client = client_config_for(pki.roots);
        let mut config = ModemConfig {
            secured_medium: true,
            ..Default::default()
        };
        config.shared.network = network(bind, port, true);
        config.shared.network.use_tls = true;
        let modem = ModemDaemon::builder()
            .config(config)
            .with_rustls_server(server_config_for(pki.cert_der, pki.key_der))
            .spawn()
            .await
            .unwrap();
        let mut me = modem.subscribe();
        let mut routers = Vec::new();
        for family in ["192.0.2.1", "fe80::1"] {
            let mut config = RouterConfig::default();
            config.shared.network = network(family, port, false);
            config.shared.network.use_tls = true;
            let router = RouterDaemon::builder()
                .config(config)
                .with_rustls_client(client.clone())
                .spawn()
                .await
                .unwrap();
            let mut events = router.subscribe();
            router.start_discovery().await.unwrap();
            let DaemonEvent::PeerDiscovered(offer) = event(&mut events, |event| {
                matches!(event, DaemonEvent::PeerDiscovered(_))
            })
            .await
            else {
                unreachable!();
            };
            assert_eq!(offer.secured_medium, Some(true));
            assert_eq!(offer.endpoints[0].addr.ip(), ip);
            assert_eq!(offer.endpoints[0].addr.port(), modem.local_addr().port());
            assert!(offer.endpoints[0].use_tls);
            routers.push((router, events, offer));
        }
        // Obtain both offers before establishing TCP: existing connections
        // correctly suppress later probes from the same source IP.
        for (router, events, offer) in &mut routers {
            router.connect_discovered(offer).await.unwrap();
            let session = event(events, |event| {
                matches!(event, DaemonEvent::SessionUp { .. })
            })
            .await;
            assert!(matches!(session, DaemonEvent::SessionUp { peer, .. } if peer.is_tls));
            event(&mut me, |event| {
                matches!(event, DaemonEvent::SessionUp { .. })
            })
            .await;
        }
        for (router, _, _) in routers {
            router.shutdown().await.unwrap();
        }
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn secondary_discovery_bind_failure_releases_primary_udp_and_tcp_listeners() {
    for primary_v4 in [true, false] {
        let blocked =
            tokio::net::UdpSocket::bind(if primary_v4 { "[::1]:0" } else { "127.0.0.1:0" })
                .await
                .unwrap();
        let port = blocked.local_addr().unwrap().port();
        let tcp = tokio::net::TcpListener::bind(if primary_v4 { "127.0.0.1:0" } else { "[::1]:0" })
            .await
            .unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        drop(tcp);
        let bind = if primary_v4 { "0.0.0.0" } else { "::" };
        let mut config = ModemConfig::default();
        config.shared.network = network(bind, port, true);
        config.shared.network.tcp_port = tcp_port;
        assert!(ModemDaemon::builder().config(config).spawn().await.is_err());
        let udp_bind = if primary_v4 { "0.0.0.0" } else { "::1" };
        let _udp = tokio::net::UdpSocket::bind((udp_bind, port))
            .await
            .expect("primary UDP bind leaked");
        let _tcp = tokio::net::TcpListener::bind((bind, tcp_port))
            .await
            .expect("TCP listener leaked after partial discovery startup");
    }
}

#[tokio::test]
async fn dual_stack_configuration_requires_a_valid_interface_and_round_trips() {
    assert!(!NetworkConfig::default().discovery_dual_stack);
    let text = "[network]\nuse_tls=false\ndiscovery_dual_stack=true";
    let router: RouterConfig = toml::from_str(text).unwrap();
    let modem: ModemConfig = toml::from_str(text).unwrap();
    assert!(
        check_router_config(&router)
            .unwrap_err()
            .to_string()
            .contains("explicit interface")
    );
    assert!(
        check_modem_config(&modem)
            .unwrap_err()
            .to_string()
            .contains("explicit interface")
    );
    assert!(
        RouterDaemon::builder()
            .config(router)
            .spawn()
            .await
            .is_err()
    );
    assert!(ModemDaemon::builder().config(modem).spawn().await.is_err());
    for bind in ["192.0.2.1", "fe80::1", "0.0.0.0", "::"] {
        let mut config = RouterConfig::default();
        config.shared.network = network(bind, 0, true);
        check_router_config(&config).unwrap();
        let copy: RouterConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
        assert!(copy.shared.network.discovery_dual_stack);
    }
    assert!(toml::from_str::<RouterConfig>("[network]\ndiscovery_dual_stack='both'").is_err());
}
