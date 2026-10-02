use dlep_daemon::{
    ConfigCheckError, ConfigLoadError, DaemonError, ModemConfig, ModemDaemon, RouterConfig,
    RouterDaemon, TimersConfig, check_modem_config, check_router_config, load_toml_config,
};

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
