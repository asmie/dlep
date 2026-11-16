use dlep_daemon::{DaemonEvent, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon};
use std::time::Duration;
use tokio::sync::broadcast;

async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    tokio::time::timeout(Duration::from_secs(5), async {
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

#[tokio::test]
async fn modem_flag_survives_discovery_initialization_and_retained_state() {
    for bind in ["192.0.2.1", "fe80::1"] {
        for secured_medium in [false, true] {
            let mut config = ModemConfig {
                secured_medium,
                ..Default::default()
            };
            config.shared.network.bind_addr = bind.parse().unwrap();
            config.shared.network.interface = Some("dlep-test".into());
            config.shared.network.tcp_port = 0;
            config.shared.network.discovery_port = 49855;
            config.shared.network.use_tls = false;
            let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
            let mut modem_events = modem.subscribe();
            let mut config = RouterConfig::default();
            config.shared.network.bind_addr = bind.parse().unwrap();
            config.shared.network.interface = Some("dlep-test".into());
            config.shared.network.discovery_port = 49855;
            config.shared.network.use_tls = false;
            let router = RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap();
            let mut router_events = router.subscribe();
            router.start_discovery().await.unwrap();
            let DaemonEvent::PeerDiscovered(offer) = event(&mut router_events, |e| {
                matches!(e, DaemonEvent::PeerDiscovered(_))
            })
            .await
            else {
                unreachable!()
            };
            assert_eq!(offer.secured_medium, Some(secured_medium));
            router.connect_discovered(&offer).await.unwrap();
            let DaemonEvent::SessionUp {
                session_id, peer, ..
            } = event(&mut router_events, |e| {
                matches!(e, DaemonEvent::SessionUp { .. })
            })
            .await
            else {
                unreachable!()
            };
            assert_eq!(peer.secured_medium, Some(secured_medium));
            assert!(!peer.is_tls, "RF access control does not enable TLS");
            assert_eq!(
                router.state().borrow().sessions[&session_id]
                    .peer
                    .secured_medium,
                Some(secured_medium)
            );
            let DaemonEvent::SessionUp { peer, .. } = event(&mut modem_events, |e| {
                matches!(e, DaemonEvent::SessionUp { .. })
            })
            .await
            else {
                unreachable!()
            };
            assert_eq!(
                peer.secured_medium, None,
                "router Peer Type has no modem flag semantics"
            );
            router.shutdown().await.unwrap();
            modem.shutdown().await.unwrap();
        }
    }
}

#[test]
fn secured_medium_is_modem_only_and_defaults_false() {
    let config: ModemConfig = toml::from_str("secured_medium = true").unwrap();
    assert!(config.secured_medium);
    assert!(
        toml::from_str::<ModemConfig>(&toml::to_string(&config).unwrap())
            .unwrap()
            .secured_medium
    );
    assert!(!ModemConfig::default().secured_medium);
    assert!(toml::from_str::<RouterConfig>("secured_medium = true").is_err());
    assert!(toml::from_str::<ModemConfig>("secured_medium = 'true'").is_err());
}
