use dlep_core::{MacAddress, MacAddressFormat, StatusCode};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon,
    RouterConfig, RouterDaemon,
};
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
async fn selected_destinations_are_declined_without_losing_explicit_announce() {
    for (bind, default_accept) in [
        ("127.0.0.1", false),
        ("127.0.0.1", true),
        ("::1", false),
        ("::1", true),
    ] {
        for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
            let mac = |n| match format {
                MacAddressFormat::Eui48 => MacAddress::new_eui48([2, 0, 0, 0, 0, n]),
                MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, n]),
            };
            let allowed = DestinationId(mac(1));
            let denied = DestinationId(mac(2));
            let mut config = ModemConfig::default();
            config.shared.network.bind_addr = bind.parse().unwrap();
            config.shared.network.tcp_port = 0;
            config.shared.network.discovery_port = 0;
            config.shared.network.use_tls = false;
            config.shared.network.mac_address_format = format;
            let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
            let mut modem_events = modem.subscribe();
            let mut config = RouterConfig::default();
            config.shared.network.use_tls = false;
            config.shared.network.mac_address_format = format;
            config.destinations.default_accept = default_accept;
            if default_accept {
                config.destinations.deny = vec![denied.0.to_string()];
            } else {
                config.destinations.allow = vec![allowed.0.to_string()];
            }
            let router = RouterDaemon::builder()
                .config(config)
                .spawn()
                .await
                .unwrap();
            let mut router_events = router.subscribe();
            router.connect_static(modem.local_addr()).await.unwrap();
            let DaemonEvent::SessionUp { session_id, .. } = event(&mut router_events, |e| {
                matches!(e, DaemonEvent::SessionUp { .. })
            })
            .await
            else {
                unreachable!()
            };
            event(&mut modem_events, |e| {
                matches!(e, DaemonEvent::SessionUp { .. })
            })
            .await;
            for (id, expected) in [
                (denied, StatusCode::NOT_INTERESTED),
                (allowed, StatusCode::SUCCESS),
            ] {
                modem
                    .add_destination(id, LinkMetrics::default())
                    .await
                    .unwrap();
                let received = event(&mut modem_events, |e| matches!(e, DaemonEvent::Destination { event: DestinationEvent::UpResponse { id: found, .. }, .. } if *found == id)).await;
                assert!(
                    matches!(received, DaemonEvent::Destination { event: DestinationEvent::UpResponse { status, .. }, .. } if status == expected)
                );
            }
            let state = router.state();
            assert!(
                !state.borrow().sessions[&session_id]
                    .destinations
                    .contains_key(&denied)
            );
            assert!(
                state.borrow().sessions[&session_id]
                    .destinations
                    .contains_key(&allowed)
            );
            let metrics = LinkMetrics {
                current_data_rate_rx_bps: 123,
                ..Default::default()
            };
            modem.update_destination(denied, metrics).await.unwrap();
            router
                .send_command_to(
                    session_id,
                    dlep_daemon::SessionCommand::AnnounceDestination { mac: denied.0 },
                )
                .await
                .unwrap();
            event(&mut router_events, |e| matches!(e, DaemonEvent::Destination { event: DestinationEvent::AnnounceResponse { id, status, .. }, .. } if *id == denied && *status == StatusCode::SUCCESS)).await;
            assert_eq!(
                state.borrow().sessions[&session_id].destinations[&denied]
                    .metrics
                    .current_data_rate_rx_bps,
                123
            );
            router.shutdown().await.unwrap();
            modem.shutdown().await.unwrap();
        }
    }
}

#[test]
fn policy_config_is_strict_and_round_trips() {
    let mut config: RouterConfig = toml::from_str("[network]\nuse_tls=false\n[destinations]\ndefault_accept=false\nallow=['02:00:00:00:00:01']").unwrap();
    dlep_daemon::check_router_config(&config).unwrap();
    let copy: RouterConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert!(!copy.destinations.default_accept);
    assert_eq!(copy.destinations.allow, config.destinations.allow);
    for invalid in [
        "bad",
        "2:00:00:00:00:01",
        "02:00:00:00:00:00:00:01",
        "+2:00:00:00:00:01",
    ] {
        config.destinations.deny = vec![invalid.into()];
        assert!(
            dlep_daemon::check_router_config(&config).is_err(),
            "{invalid}"
        );
    }
    config.destinations.deny = config.destinations.allow.clone();
    assert!(dlep_daemon::check_router_config(&config).is_err());
    assert!(toml::from_str::<RouterConfig>("[destinations]\nunknown=true").is_err());
    assert!(toml::from_str::<ModemConfig>("[destinations]\ndefault_accept=false").is_err());
}
