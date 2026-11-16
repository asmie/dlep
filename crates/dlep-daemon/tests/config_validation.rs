use dlep_daemon::{
    ConfigCheckError, ConfigLoadError, DaemonError, ModemConfig, ModemDaemon, RouterConfig,
    RouterDaemon, TimersConfig, check_modem_config, check_router_config, load_toml_config,
};

#[test]
fn named_static_peers_validate_offline_and_round_trip_with_numeric_peers() {
    let config: RouterConfig = toml::from_str("mode='static'\nstatic_peers=['127.0.0.1:854','[::1]:1854','MoDeM.Example:854']\n[network]\nuse_tls=false").unwrap();
    assert_eq!(config.static_peers.len(), 2);
    assert_eq!(config.named_peers[0].to_string(), "modem.example:854");
    check_router_config(&config).unwrap();
    let serialized = toml::to_string(&config).unwrap();
    assert!(!serialized.contains("named_peers"));
    let copy: RouterConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(copy.static_peers, config.static_peers);
    assert_eq!(copy.named_peers, config.named_peers);
    let config: RouterConfig = toml::from_str(
        "mode='static'\nstatic_peers=['does-not-exist.invalid:854']\n[network]\nuse_tls=false",
    )
    .unwrap();
    check_router_config(&config).unwrap();
    assert!(toml::from_str::<ModemConfig>("static_peers=['modem.example:854']").is_err());
    for invalid in [
        "modem.example",
        "https://modem.example:854",
        "modem.example:-1",
        "modem.example:65536",
        "modem.example:+854",
        "modem.example:",
        "bad name:854",
        "[::1]:bad",
        "::1:854",
        "127.0.0.999:854",
    ] {
        assert!(
            invalid.parse::<dlep_daemon::PeerEndpoint>().is_err(),
            "{invalid}"
        );
        assert!(
            toml::from_str::<RouterConfig>(&format!("static_peers=['{invalid}']")).is_err(),
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn router_limits_are_validated_by_config_checks_and_startup() {
    for settings in [
        "max_sessions=0",
        "max_discovered_peers=0",
        "peer_retention_secs=0",
    ] {
        let config: RouterConfig =
            toml::from_str(&format!("[network]\nuse_tls=false\n[limits]\n{settings}")).unwrap();
        assert!(matches!(
            check_router_config(&config),
            Err(ConfigCheckError::Limits(_))
        ));
        assert!(matches!(
            RouterDaemon::builder().config(config).spawn().await,
            Err(DaemonError::Config(_))
        ));
    }
    let config: RouterConfig = toml::from_str("[network]\nuse_tls=false\n[limits]\nmax_sessions=2\nmax_discovered_peers=3\npeer_retention_secs=4").unwrap();
    check_router_config(&config).unwrap();
    let config: RouterConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert_eq!(config.limits.max_sessions, 2);
    assert_eq!(config.limits.max_discovered_peers, 3);
    assert_eq!(config.limits.peer_retention_secs, 4);
    assert!(toml::from_str::<RouterConfig>("[limits]\nmax_session=1").is_err());
    assert!(toml::from_str::<ModemConfig>("[limits]\nmax_sessions=1").is_err());
    RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
}

#[tokio::test]
async fn timer_checks_and_builders_reject_the_same_invalid_values() {
    for (field, value) in [
        ("heartbeat_interval_ms", 0),
        ("heartbeat_interval_ms", 999),
        ("discovery_interval_ms", 0),
        ("discovery_interval_ms", 999),
        ("session_init_timeout_ms", 0),
        ("termination_timeout_ms", 0),
    ] {
        let timers: TimersConfig = toml::from_str(&format!("{field} = {value}")).unwrap();
        let mut router = RouterConfig::default();
        router.shared.timers = timers.clone();
        // Deliberately unusable network/TLS config proves timer checks happen
        // before privileged socket setup or certificate loading.
        router.shared.network.interface = Some("dlep-no-such-if".into());
        let modem = ModemConfig {
            shared: router.shared.clone(),
            ..ModemConfig::default()
        };
        for result in [check_router_config(&router), check_modem_config(&modem)] {
            let Err(ConfigCheckError::Timers(message)) = result else {
                panic!("expected timer validation for {field}");
            };
            assert!(message.contains(field), "{message}");
            assert!(message.contains(&format!("got {value}")), "{message}");
        }
        let result = RouterDaemon::builder().config(router).spawn().await;
        assert!(matches!(result, Err(DaemonError::Config(message)) if message.contains(field)));
        let result = ModemDaemon::builder().config(modem).spawn().await;
        assert!(matches!(result, Err(DaemonError::Config(message)) if message.contains(field)));
    }
}

#[test]
fn timer_boundaries_and_defaults_pass_checks() {
    for timers in [
        TimersConfig::default(),
        TimersConfig {
            heartbeat_interval_ms: 1_000,
            discovery_interval_ms: 1_000,
            session_init_timeout_ms: 1,
            termination_timeout_ms: Some(1),
        },
        TimersConfig {
            heartbeat_interval_ms: u32::MAX,
            discovery_interval_ms: u32::MAX,
            session_init_timeout_ms: u32::MAX,
            termination_timeout_ms: Some(u32::MAX),
        },
    ] {
        let mut router = RouterConfig::default();
        router.shared.network.use_tls = false;
        router.shared.timers = timers;
        let modem = ModemConfig {
            shared: router.shared.clone(),
            ..ModemConfig::default()
        };
        check_router_config(&router).unwrap();
        check_modem_config(&modem).unwrap();
    }
}

#[test]
fn config_file_errors_identify_unknown_section_and_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typo.toml");
    std::fs::write(&path, "[netwrok]\nuse_tls = false").unwrap();
    for error in [
        load_toml_config::<RouterConfig>(Some(&path)).unwrap_err(),
        load_toml_config::<ModemConfig>(Some(&path)).unwrap_err(),
    ] {
        assert!(error.to_string().contains("netwrok"));
        assert!(matches!(error, ConfigLoadError::Parse { path: p, .. } if p == path));
    }
}

#[test]
fn automatic_termination_timeout_tracks_heartbeat_and_survives_roundtrip() {
    use dlep_daemon::session::session_config_from_timers;
    use std::time::Duration;
    for heartbeat in [1_000, 2_500, 60_000, u32::MAX] {
        let config: RouterConfig =
            toml::from_str(&format!("[timers]\nheartbeat_interval_ms = {heartbeat}\n")).unwrap();
        let timers = &config.shared.timers;
        assert_eq!(timers.termination_timeout_ms, None);
        timers.validate().unwrap();
        let fsm = session_config_from_timers(timers, "test".into(), vec![]);
        assert_eq!(
            fsm.termination_timeout(),
            Duration::from_millis(u64::from(heartbeat) * 4)
        );
        let encoded = toml::to_string(&config).unwrap();
        assert!(!encoded.contains("termination_timeout_ms"));
        let roundtrip: RouterConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(roundtrip.shared.timers.termination_timeout_ms, None);
    }
    let mut timers = TimersConfig::default();
    assert_eq!(
        session_config_from_timers(&timers, "test".into(), vec![]).termination_timeout(),
        Duration::from_secs(240)
    );
    timers.heartbeat_interval_ms = 3_000;
    assert_eq!(
        session_config_from_timers(&timers, "test".into(), vec![]).termination_timeout(),
        Duration::from_secs(12)
    );
}

#[test]
fn explicit_termination_override_is_preserved_in_toml_and_runtime() {
    use dlep_daemon::session::session_config_from_timers;
    use std::time::Duration;
    for override_ms in [1, 500, 240_000, u32::MAX] {
        let config: ModemConfig = toml::from_str(&format!(
            "[timers]\nheartbeat_interval_ms = 2000\ntermination_timeout_ms = {override_ms}\n"
        ))
        .unwrap();
        let timers = &config.shared.timers;
        timers.validate().unwrap();
        assert_eq!(timers.termination_timeout_ms, Some(override_ms));
        assert_eq!(
            session_config_from_timers(timers, "test".into(), vec![]).termination_timeout(),
            Duration::from_millis(override_ms.into())
        );
        let encoded = toml::to_string(&config).unwrap();
        let decoded: ModemConfig = toml::from_str(&encoded).unwrap();
        assert_eq!(
            decoded.shared.timers.termination_timeout_ms,
            Some(override_ms)
        );
    }
}

#[tokio::test]
async fn modem_offer_retry_settings_validate_round_trip_and_reject_router_use() {
    assert_eq!(ModemConfig::default().discovery.offer_retries, 0);
    let text = "[network]\nuse_tls=false\ngtsm_enforce=false\n[discovery]\noffer_retries=2\noffer_retry_interval_ms=1000\n";
    let config: ModemConfig = toml::from_str(text).unwrap();
    check_modem_config(&config).unwrap();
    let copy: ModemConfig = toml::from_str(&toml::to_string(&config).unwrap()).unwrap();
    assert_eq!(copy.discovery.offer_retries, 2);
    assert_eq!(copy.discovery.offer_retry_interval_ms, 1000);
    assert!(toml::from_str::<RouterConfig>(text).is_err());
    for (retries, interval) in [(6, 1000), (2, 999), (0, 0)] {
        let mut invalid = config.clone();
        invalid.discovery.offer_retries = retries;
        invalid.discovery.offer_retry_interval_ms = interval;
        assert!(
            check_modem_config(&invalid)
                .unwrap_err()
                .to_string()
                .contains("discovery.offer_")
        );
        assert!(
            ModemDaemon::builder()
                .config(invalid)
                .spawn()
                .await
                .is_err()
        );
    }
    assert!(toml::from_str::<ModemConfig>("[discovery]\noffer_retries=256").is_err());
    assert!(toml::from_str::<ModemConfig>("[discovery]\noffer_retry_interval=1000").is_err());
}

#[test]
fn named_ipv6_zones_parse_offline_and_round_trip_separately_from_dns() {
    use dlep_daemon::{PeerEndpoint, ScopedPeer};
    let text = "mode='static'\nstatic_peers=['[fe80::1%Radio0]:1854','[fe80::2%3]:854','radio.example:854']\n[network]\nuse_tls=false\ngtsm_enforce=false";
    let config: RouterConfig = toml::from_str(text).unwrap();
    check_router_config(&config).unwrap();
    assert_eq!(config.static_peers.len(), 1);
    assert_eq!(config.named_peers.len(), 1);
    let peer = &config.scoped_peers[0];
    assert_eq!(
        peer.address(),
        "fe80::1".parse::<std::net::Ipv6Addr>().unwrap()
    );
    assert_eq!(peer.interface(), "Radio0");
    assert_eq!(peer.port(), 1854);
    assert_eq!(peer.to_string(), "[fe80::1%Radio0]:1854");
    let serialized = toml::to_string(&config).unwrap();
    assert!(!serialized.contains("scoped_peers"));
    let copy: RouterConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(copy.scoped_peers, config.scoped_peers);
    let missing = ScopedPeer::new("fe80::1".parse().unwrap(), "dlep-missing", 854).unwrap();
    assert!(missing.resolve().is_err());
    for invalid in [
        "[fe80::1%]:854",
        "[fe80::1%bad name]:854",
        "[fe80::1%bad%name]:854",
        "[fe80::1%bad/name]:854",
        "[fe80::1%bad\0name]:854",
        "[fe80::1%interface-too-long]:854",
        "[::1%lo]:854",
        "[2001:db8::1%eth0]:854",
        "[ff02::1%eth0]:854",
        "[::%eth0]:854",
        "[127.0.0.1%eth0]:854",
        "[fe80::1%4294967296]:854",
        "[fe80::1%eth0]:65536",
        "[fe80::1%eth0]:+854",
        "[fe80::1%eth0]",
        "fe80::1%eth0:854",
    ] {
        assert!(
            invalid.parse::<PeerEndpoint>().is_err(),
            "accepted {invalid:?}"
        );
    }
    // A zone-only static configuration is valid even before its device exists.
    let only: RouterConfig = toml::from_str("mode='static'\nstatic_peers=['[fe80::1%dlep-missing]:854']\n[network]\nuse_tls=false\ngtsm_enforce=false").unwrap();
    check_router_config(&only).unwrap();
}
