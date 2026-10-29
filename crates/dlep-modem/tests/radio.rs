//! End-to-end radio adapter regressions: the real binary runs a scripted
//! adapter, and a library router observes the resulting DLEP session.
#![cfg(unix)]
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::Duration,
};

use dlep_core::{MacAddress, StatusCode as S};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkCharacteristics, RouterConfig, RouterDaemon,
};
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio::{sync::broadcast, time::timeout};

const WAIT: Duration = Duration::from_secs(5);
const BINARY: &str = env!("CARGO_BIN_EXE_dlep-modem");

// Reports one destination, logs every line it receives, and reacts to link
// requests according to its mode.
const ADAPTER: &str = r#"#!/usr/bin/env python3
import json, os, sys
mode, log = sys.argv[1], sys.argv[2]
MAC = "02:00:00:00:00:01"
if mode == "caps":
    def ambient(pid):
        with open(f"/proc/{pid}/status") as status:
            return next(l.split()[1] for l in status if l.startswith("CapAmb:"))
    with open(log + ".caps", "w") as caps:
        caps.write(f"{ambient(os.getppid())} {ambient('self')}\n")
def send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()
send({"type": "destination_up", "mac": MAC,
      "metrics": {"current_data_rate_tx_bps": 70000},
      "addresses": {"ipv4": ["192.0.2.10"], "ipv4_subnets": ["198.51.100.0/24"]}})
with open(log, "a") as out:
    for line in sys.stdin:
        out.write(line)
        out.flush()
        message = json.loads(line)
        if message["type"] == "session_up" and mode == "metrics":
            send({"type": "future_extension", "ignored": True})
            send({"type": "session_metrics", "metrics": {"latency_us": 4000}})
            send({"type": "destination_update", "mac": MAC,
                  "metrics": {"current_data_rate_rx_bps": 42}})
        if message["type"] != "link_request":
            continue
        request = message["request"]
        if mode == "grant":
            send({"type": "link_response", "request": request, "status": "success",
                  "text": "applied", "metrics": {"current_data_rate_tx_bps":
                      message["requested"]["current_data_rate_tx_bps"]}})
        elif mode == "down":
            send({"type": "destination_down", "mac": MAC})
            send({"type": "link_response", "request": request, "status": "denied",
                  "text": "link lost"})
        elif mode == "exit":
            sys.exit(3)
        elif mode == "garbage":
            sys.stdout.write("not json\n")
            sys.stdout.flush()
"#;

fn destination() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}

struct Modem {
    child: Child,
    output: PathBuf,
    adapter_log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Modem {
    fn start(mode: &str) -> Self {
        Self::start_with(mode, &[])
    }

    /// `wrapper` runs the binary through another program, e.g. setpriv.
    fn start_with(mode: &str, wrapper: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("adapter.py");
        std::fs::write(&script, ADAPTER).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let adapter_log = dir.path().join("adapter.log");
        let config = dir.path().join("modem.toml");
        std::fs::write(
            &config,
            format!(
                "[network]\nbind_addr = '127.0.0.1'\ntcp_port = 0\ndiscovery_port = 0\n\
                 use_tls = false\n\n[radio]\ncommand = {script:?}\nargs = [{mode:?}, {adapter_log:?}]\n\
                 link_request_timeout_ms = 300\n"
            ),
        )
        .unwrap();
        let output = dir.path().join("modem.log");
        let mut command = match wrapper {
            [] => Command::new(BINARY),
            [program, args @ ..] => {
                let mut command = Command::new(program);
                command.args(args).arg(BINARY);
                command
            }
        };
        let child = command
            .arg("--config")
            .arg(&config)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("DLEP_LOG", "info")
            .env("NO_COLOR", "1")
            .stdout(std::fs::File::create(&output).unwrap())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        Self {
            child,
            output,
            adapter_log,
            _dir: dir,
        }
    }

    async fn addr(&self) -> SocketAddr {
        timeout(WAIT, async {
            loop {
                let output = std::fs::read_to_string(&self.output).unwrap();
                for line in output.split_inclusive('\n').filter(|s| s.ends_with('\n')) {
                    if let Some((_, addr)) = line.split_once("modem listening on ") {
                        return addr.trim().parse().unwrap();
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("modem did not start: {}", self.log()))
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_default()
    }

    fn adapter_messages(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.adapter_log)
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    async fn exit(&mut self) -> ExitStatus {
        timeout(WAIT, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("modem did not exit: {}", self.log()))
    }

    async fn stop(mut self) {
        kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM).unwrap();
        let status = self.exit().await;
        assert!(status.success(), "{status}: {}", self.log());
    }
}

impl Drop for Modem {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Router {
    daemon: RouterDaemon,
    events: broadcast::Receiver<DaemonEvent>,
    session_id: dlep_ext::SessionId,
}

impl Router {
    async fn connect(modem: &Modem) -> Self {
        let mut config = RouterConfig::default();
        config.shared.network.use_tls = false;
        let daemon = RouterDaemon::builder()
            .config(config)
            .spawn()
            .await
            .unwrap();
        let mut events = daemon.subscribe();
        daemon.connect_static(modem.addr().await).await.unwrap();
        let session_id =
            match event(&mut events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await {
                DaemonEvent::SessionUp { session_id, .. } => session_id,
                _ => unreachable!(),
            };
        Self {
            daemon,
            events,
            session_id,
        }
    }

    async fn destination(&mut self, wanted: fn(&DestinationEvent) -> bool) -> DestinationEvent {
        match event(
            &mut self.events,
            |e| matches!(e, DaemonEvent::Destination { event, .. } if wanted(event)),
        )
        .await
        {
            DaemonEvent::Destination { event, .. } => event,
            _ => unreachable!(),
        }
    }

    async fn up(&mut self) {
        let up = self
            .destination(|e| matches!(e, DestinationEvent::Up { .. }))
            .await;
        let DestinationEvent::Up {
            id,
            metrics,
            v4_addrs,
            v4_subnets,
            ..
        } = up
        else {
            unreachable!()
        };
        assert_eq!(id, destination());
        assert_eq!(metrics.current_data_rate_tx_bps, 70_000);
        assert_eq!(
            v4_addrs,
            ["192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            v4_subnets,
            ["198.51.100.0/24".parse::<ipnet::Ipv4Net>().unwrap()]
        );
    }

    async fn request(&mut self) -> (S, String, dlep_daemon::LinkMetrics) {
        self.daemon
            .request_link_characteristics(
                self.session_id,
                destination(),
                LinkCharacteristics {
                    current_data_rate_tx_bps: Some(123_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        match self
            .destination(|e| matches!(e, DestinationEvent::LinkCharacteristicsResponse { .. }))
            .await
        {
            DestinationEvent::LinkCharacteristicsResponse {
                status,
                text,
                metrics,
                ..
            } => (status, text, metrics),
            _ => unreachable!(),
        }
    }
}

async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = rx.recv().await.unwrap();
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .expect("expected daemon event")
}

#[tokio::test]
async fn adapter_destination_reaches_router_and_grants_link_request() {
    let modem = Modem::start("grant");
    let mut router = Router::connect(&modem).await;
    router.up().await;
    let (status, text, metrics) = router.request().await;
    assert_eq!(status, S::SUCCESS);
    assert_eq!(text, "applied");
    assert_eq!(metrics.current_data_rate_tx_bps, 123_000);

    let messages = modem.adapter_messages();
    assert_eq!(messages[0]["type"], "session_up");
    assert_eq!(messages[0]["session"], 1);
    let request = &messages[1];
    assert_eq!(request["type"], "link_request");
    assert_eq!(request["mac"], "02:00:00:00:00:01");
    assert_eq!(
        request["requested"],
        serde_json::json!({"current_data_rate_tx_bps": 123000})
    );
    assert_eq!(request["current"]["current_data_rate_tx_bps"], 70_000);
    router.daemon.shutdown().await.unwrap();
    modem.stop().await;
}

#[tokio::test]
async fn silent_adapter_is_denied_after_the_local_timeout() {
    let modem = Modem::start("silent");
    let mut router = Router::connect(&modem).await;
    router.up().await;
    for _ in 0..2 {
        let (status, text, metrics) = router.request().await;
        assert_eq!(status, S::REQUEST_DENIED);
        assert_eq!(text, "radio adapter timed out");
        assert_eq!(metrics.current_data_rate_tx_bps, 70_000);
    }
    router.daemon.shutdown().await.unwrap();
    modem.stop().await;
}

#[tokio::test]
async fn destination_down_during_a_request_follows_the_answer() {
    let modem = Modem::start("down");
    let mut router = Router::connect(&modem).await;
    router.up().await;
    let (status, text, _) = router.request().await;
    assert_eq!(status, S::REQUEST_DENIED);
    assert_eq!(text, "link lost");
    // The pending request made the first Down attempt Busy; it is retried.
    let down = router
        .destination(|e| matches!(e, DestinationEvent::Down { .. }))
        .await;
    assert!(matches!(down, DestinationEvent::Down { id, .. } if id == destination()));
    router.daemon.shutdown().await.unwrap();
    modem.stop().await;
}

#[tokio::test]
async fn adapter_session_metrics_and_updates_reach_router() {
    let modem = Modem::start("metrics");
    let mut router = Router::connect(&modem).await;
    router.up().await;
    let metrics = event(&mut router.events, |e| {
        matches!(e, DaemonEvent::Metrics { .. })
    })
    .await;
    assert!(matches!(
        metrics,
        DaemonEvent::Metrics { event, .. } if event.session_wide.latency == Duration::from_micros(4000)
    ));
    let update = router
        .destination(|e| matches!(e, DestinationEvent::Update { .. }))
        .await;
    assert!(matches!(
        update,
        DestinationEvent::Update { metrics, .. }
            if metrics.current_data_rate_rx_bps == 42
                && metrics.current_data_rate_tx_bps == 0
                && metrics.latency == Duration::from_micros(4000)
    ));
    let mut later = Router::connect(&modem).await;
    let replay = later
        .destination(|e| matches!(e, DestinationEvent::Up { .. }))
        .await;
    assert!(matches!(
        replay,
        DestinationEvent::Up { metrics, .. }
            if metrics.current_data_rate_rx_bps == 42
                && metrics.current_data_rate_tx_bps == 0
                && metrics.latency == Duration::from_micros(4000)
    ));
    later.daemon.shutdown().await.unwrap();
    router.daemon.shutdown().await.unwrap();
    modem.stop().await;
}

#[tokio::test]
async fn adapter_failure_terminates_sessions_and_exits_with_error() {
    for mode in ["exit", "garbage"] {
        let mut modem = Modem::start(mode);
        let mut router = Router::connect(&modem).await;
        router.up().await;
        router
            .daemon
            .request_link_characteristics(
                router.session_id,
                destination(),
                LinkCharacteristics {
                    latency: Some(Duration::from_micros(1)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let down = event(&mut router.events, |e| {
            matches!(e, DaemonEvent::SessionDown { .. })
        })
        .await;
        assert!(
            matches!(
                down,
                DaemonEvent::SessionDown {
                    reason: S::SHUTTING_DOWN,
                    ..
                }
            ),
            "{mode}: {down:?}"
        );
        let status = modem.exit().await;
        assert!(!status.success(), "{mode}");
        assert!(
            modem.log().contains("radio adapter failed"),
            "{mode}: {}",
            modem.log()
        );
        router.daemon.shutdown().await.unwrap();
    }
}

#[test]
fn check_config_validates_the_radio_section() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("adapter.py");
    std::fs::write(&script, ADAPTER).unwrap();
    let config = dir.path().join("modem.toml");
    let check = |radio: &str| {
        std::fs::write(&config, format!("[radio]\n{radio}\n")).unwrap();
        let output = Command::new(BINARY)
            .args(["--check-config", "--no-tls", "--config"])
            .arg(&config)
            .env("TOKIO_WORKER_THREADS", "2")
            .output()
            .unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let valid = format!("command = {:?}", script);
    assert!(check(&valid).0);
    for (radio, expected) in [
        ("command = 'adapter.py'".to_string(), "absolute"),
        (format!("command = {:?}", missing(dir.path())), "not a file"),
        (
            format!("{valid}\nlink_request_timeout_ms = 0"),
            "link_request_timeout_ms",
        ),
        (format!("{valid}\ncomand = 'typo'"), "comand"),
        ("args = []".to_string(), "command"),
    ] {
        let (ok, stderr) = check(&radio);
        assert!(!ok, "{radio}");
        assert!(stderr.contains(expected), "{radio}: {stderr}");
    }
}

fn missing(dir: &Path) -> PathBuf {
    dir.join("missing-adapter")
}

// The example unit grants ambient capabilities; the adapter must not keep them.
#[tokio::test]
async fn adapter_does_not_inherit_ambient_capabilities() {
    let wrapper = [
        "setpriv",
        "--inh-caps",
        "+net_raw",
        "--ambient-caps",
        "+net_raw",
    ];
    if Command::new("setpriv").arg("--version").output().is_err() {
        eprintln!("skipping: setpriv is unavailable");
        return;
    }
    let modem = Modem::start_with("caps", &wrapper);
    modem.addr().await;
    let caps = modem.adapter_log.with_extension("log.caps");
    let line = timeout(WAIT, async {
        loop {
            if let Ok(line) = std::fs::read_to_string(&caps) {
                if line.ends_with('\n') {
                    return line;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("adapter reports its capabilities");
    let (modem_ambient, adapter_ambient) = line.trim().split_once(' ').unwrap();
    if u64::from_str_radix(modem_ambient, 16).unwrap() == 0 {
        eprintln!("skipping: setpriv could not raise an ambient capability");
        return;
    }
    assert_eq!(u64::from_str_radix(adapter_ambient, 16).unwrap(), 0);
    modem.stop().await;
}
