use std::process::Command;

pub fn check_config_rejects_typos_and_invalid_timers(binary: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    for (text, field) in [
        ("peer_descripton = 'typo'", "peer_descripton"),
        ("[netwrok]\nuse_tls = false", "netwrok"),
        (
            "[timers]\nheartbeat_interval_ms = 0",
            "heartbeat_interval_ms",
        ),
        (
            "[timers]\nheartbeat_interval_ms = 999",
            "heartbeat_interval_ms",
        ),
        (
            "[timers]\ndiscovery_interval_ms = 0",
            "discovery_interval_ms",
        ),
        (
            "[timers]\ndiscovery_interval_ms = 999",
            "discovery_interval_ms",
        ),
        (
            "[timers]\nsession_init_timeout_ms = 0",
            "session_init_timeout_ms",
        ),
        (
            "[timers]\ntermination_timeout_ms = 0",
            "termination_timeout_ms",
        ),
    ] {
        std::fs::write(&path, text).unwrap();
        let output = Command::new(binary)
            .args(["--check-config", "--no-tls", "--config"])
            .arg(&path)
            .env("TOKIO_WORKER_THREADS", "2")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "invalid config passed: {text}"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(field), "missing field in error: {stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("configuration OK"));
    }
    std::fs::write(&path, "[timers]\nheartbeat_interval_ms = 1000\ndiscovery_interval_ms = 1000\nsession_init_timeout_ms = 1\ntermination_timeout_ms = 1").unwrap();
    let output = Command::new(binary)
        .args(["--check-config", "--no-tls", "--config"])
        .arg(&path)
        .env("TOKIO_WORKER_THREADS", "2")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "configuration OK"
    );
}
