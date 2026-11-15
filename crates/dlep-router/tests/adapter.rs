use std::fs::{File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use dlep_core::MacAddress;
use dlep_daemon::{
    DaemonEvent, DestinationAddrs, LinkMetrics, LinkRequest, LinkResponse, ModemConfig, ModemDaemon,
};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::Value;
use tokio::sync::broadcast;
use tokio::time::timeout;

const BINARY: &str = env!("CARGO_BIN_EXE_dlep-router");
const WAIT: Duration = Duration::from_secs(10);
const SCRIPT: &str = r#"#!/usr/bin/env python3
import json, os, sys, time
mode, log = sys.argv[1:]
with open(log + '.pid', 'w') as f:
    f.write(str(os.getpid()))
if mode == 'caps':
    def ambient(pid):
        with open(f'/proc/{pid}/status') as f:
            return next(l.split()[1] for l in f if l.startswith('CapAmb:'))
    with open(log + '.caps', 'w') as f:
        f.write(ambient(os.getppid()) + ' ' + ambient('self'))
def send(message):
    print(json.dumps(message), flush=True)
def addresses(n):
    return {'ipv4': [f'192.0.2.{n}'], 'ipv6': [f'2001:db8::{n}'],
            'ipv4_subnets': [f'198.51.{n}.7/24'], 'ipv6_subnets': [f'2001:db8:{n}::7/64']}
stage = 0
sessions, destinations = [], []
with open(log, 'a') as out:
    for line in sys.stdin:
        out.write(line)
        out.flush()
        m = json.loads(line)
        kind = m['type']
        if kind == 'snapshot_begin':
            sessions, destinations = [], []
        elif kind == 'session':
            sessions.append(m)
        elif kind == 'destination':
            destinations.append(m)
        elif kind == 'snapshot_end' and sessions:
            if mode == 'addresses' and stage == 0:
                stage = 1
                target = sessions[0]
                send({'type': 'session_addresses', 'request': 1, 'session': target['session'], 'add': addresses(1)})
            if mode == 'exit':
                sys.exit(3)
            if mode == 'invalid':
                print('not json', flush=True)
                mode = 'observe'
            if mode == 'oversize':
                print('x' * 65537, flush=True)
                mode = 'observe'
            if mode == 'closed':
                os.close(1)
                time.sleep(60)
            if mode == 'control':
                if stage == 0 and destinations:
                    target = destinations[0]
                    stage = 1
                    send({'type': 'resync'})
                elif stage == 1 and destinations:
                    stage = 2
                    send({'type': 'link_request', 'request': 1, 'session': target['session'], 'mac': target['mac'],
                          'requested': {'current_data_rate_tx_bps': 321}})
                elif stage == 3 and not destinations:
                    stage = 4
                    send({'type': 'destination_announce', 'request': 3, 'session': target['session'], 'mac': target['mac']})
        elif kind == 'link_response' and mode == 'control':
            stage = 3
            send({'type': 'destination_down', 'request': 2, 'session': m['session'], 'mac': m['mac']})
        elif kind == 'session_update_response' and mode == 'addresses':
            stage += 1
            if stage == 2:
                send({'type': 'session_addresses', 'request': 2, 'session': target['session'],
                      'remove': addresses(1), 'add': addresses(2)})
            elif stage == 3:
                send({'type': 'session_addresses', 'request': 3, 'session': target['session'], 'remove': addresses(2)})
            elif stage == 4:
                send({'type': 'session_addresses', 'request': 4, 'session': target['session']})
                send({'type': 'resync'})
if mode == 'ignore_eof':
    time.sleep(60)
"#;

struct Router {
    child: Child,
    log: PathBuf,
    output: PathBuf,
    _dir: tempfile::TempDir,
}

impl Router {
    fn start(mode: &str, peer: std::net::SocketAddr, wrapper: &[&str]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("adapter.py");
        std::fs::write(&script, SCRIPT).unwrap();
        std::fs::set_permissions(&script, Permissions::from_mode(0o755)).unwrap();
        let log = dir.path().join("adapter.log");
        let config = dir.path().join("router.toml");
        std::fs::write(&config, format!(
            "mode = 'static'\nstatic_peers = ['{peer}']\n[network]\nuse_tls = false\n[timers]\nheartbeat_interval_ms = 1000\ntermination_timeout_ms = 200\n[adapter]\ncommand = {script:?}\nargs = [{mode:?}, {log:?}]\n"
        )).unwrap();
        let output = dir.path().join("router.log");
        let file = File::create(&output).unwrap();
        let mut command = if let Some(program) = wrapper.first() {
            let mut command = Command::new(program);
            command.args(&wrapper[1..]).arg(BINARY);
            command
        } else {
            Command::new(BINARY)
        };
        let child = command
            .args(["--config"])
            .arg(config)
            .env("TOKIO_WORKER_THREADS", "2")
            .stdin(Stdio::null())
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        Self {
            child,
            log,
            output,
            _dir: dir,
        }
    }

    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .split_inclusive('\n')
            .filter(|s| s.ends_with('\n'))
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }

    fn output(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_default()
    }

    async fn records_until(&self, predicate: impl Fn(&[Value]) -> bool) -> Vec<Value> {
        timeout(WAIT, async {
            loop {
                let records = self.records();
                if predicate(&records) {
                    return records;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("adapter output timed out: {}", self.output()))
    }

    async fn exit(&mut self) -> ExitStatus {
        timeout(WAIT, async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("router did not exit: {}", self.output()))
    }

    async fn stop(&mut self) {
        kill(Pid::from_raw(self.child.id() as i32), Signal::SIGTERM).unwrap();
        assert!(self.exit().await.success(), "{}", self.output());
    }
}

impl Drop for Router {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn modem(ip: &str) -> ModemDaemon {
    let mut config = ModemConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = ip.parse().unwrap();
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
    config.shared.timers.heartbeat_interval_ms = 1000;
    config.metrics.max_data_rate_tx_bps = 10000;
    ModemDaemon::builder()
        .config(config)
        .link_control(Arc::new(|request: LinkRequest| async move {
            LinkResponse::granted(LinkMetrics {
                current_data_rate_tx_bps: request.requested.current_data_rate_tx_bps.unwrap_or(0),
                ..request.current
            })
        }))
        .spawn()
        .await
        .unwrap()
}

async fn up(events: &mut broadcast::Receiver<DaemonEvent>) -> dlep_ext::SessionId {
    timeout(WAIT, async {
        loop {
            if let DaemonEvent::SessionUp { session_id, .. } = events.recv().await.unwrap() {
                return session_id;
            }
        }
    })
    .await
    .unwrap()
}

fn last_snapshot(records: &[Value]) -> &[Value] {
    let Some(end) = records.iter().rposition(|r| r["type"] == "snapshot_end") else {
        return &[];
    };
    let begin = records[..end]
        .iter()
        .rposition(|r| r["type"] == "snapshot_begin")
        .unwrap();
    &records[begin + 1..end]
}

#[tokio::test]
async fn binary_adapter_advertises_session_addresses_over_both_families() {
    use dlep_daemon::AddressChanges;
    let addresses = |n| DestinationAddrs {
        v4: vec![format!("192.0.2.{n}").parse().unwrap()],
        v6: vec![format!("2001:db8::{n}").parse().unwrap()],
        v4_subnets: vec![format!("198.51.{n}.0/24").parse().unwrap()],
        v6_subnets: vec![format!("2001:db8:{n}::/64").parse().unwrap()],
    };
    for ip in ["127.0.0.1", "::1"] {
        let modem = modem(ip).await;
        let mut events = modem.subscribe();
        let mut router = Router::start("addresses", modem.local_addr(), &[]);
        let session = up(&mut events).await;
        for (added, removed, expected) in [
            (addresses(1), DestinationAddrs::default(), addresses(1)),
            (addresses(2), addresses(1), addresses(2)),
            (
                DestinationAddrs::default(),
                addresses(2),
                DestinationAddrs::default(),
            ),
        ] {
            let event = timeout(WAIT, events.recv()).await.unwrap().unwrap();
            let DaemonEvent::SessionAddresses {
                session_id,
                changes,
                addresses,
                ..
            } = event
            else {
                panic!("unexpected modem event: {event:?}");
            };
            assert_eq!(session_id, session);
            assert_eq!(changes, AddressChanges { added, removed });
            assert_eq!(addresses, expected);
        }
        let records = router
            .records_until(|records| {
                let Some(result) = records
                    .iter()
                    .position(|r| r["type"] == "command_result" && r["request"] == 4)
                else {
                    return false;
                };
                records[result + 1..]
                    .iter()
                    .any(|r| r["type"] == "snapshot_end")
            })
            .await;
        for request in 1..=4 {
            let result = records
                .iter()
                .find(|r| r["type"] == "command_result" && r["request"] == request)
                .unwrap();
            assert_eq!(result["outcome"], "accepted");
        }
        let sid = last_snapshot(&records)
            .iter()
            .find(|r| r["type"] == "session")
            .unwrap()["session"]
            .clone();
        let replies: Vec<_> = records
            .iter()
            .filter(|r| r["type"] == "session_update_response")
            .collect();
        assert_eq!(replies.len(), 3, "empty changes must not send an update");
        for reply in replies {
            assert_eq!(reply["session"], sid);
            assert_eq!(reply["status"], 0);
            assert_eq!(reply["text"], "");
        }
        assert!(
            !records.iter().any(|r| r["type"] == "address"),
            "snapshots only contain remote addresses"
        );
        assert!(
            modem.state().borrow().sessions[&session]
                .peer_addresses
                .is_empty()
        );
        assert!(events.try_recv().is_err());
        router.stop().await;
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn binary_adapter_exports_snapshots_and_controls_destinations_over_both_families() {
    for ip in ["127.0.0.1", "::1"] {
        let modem = modem(ip).await;
        let mut events = modem.subscribe();
        let mut router = Router::start("control", modem.local_addr(), &[]);
        let session = up(&mut events).await;
        modem
            .update_session_addresses(
                session,
                dlep_daemon::AddressChanges {
                    added: DestinationAddrs {
                        v6: vec!["2001:db8::1".parse().unwrap()],
                        ..Default::default()
                    },
                    removed: Default::default(),
                },
            )
            .await
            .unwrap();
        modem
            .add_destination_with_addresses(
                MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into(),
                LinkMetrics {
                    max_data_rate_tx_bps: 10000,
                    current_data_rate_tx_bps: 70,
                    ..Default::default()
                },
                DestinationAddrs {
                    v4: vec!["192.0.2.2".parse().unwrap()],
                    v6_subnets: vec!["2001:db8:1::/64".parse().unwrap()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let records = router
            .records_until(|records| {
                let accepted = records
                    .iter()
                    .filter(|r| r["type"] == "command_result" && r["outcome"] == "accepted")
                    .count();
                accepted == 3
                    && last_snapshot(records).iter().any(|r| {
                        r["type"] == "destination"
                            && r["phase"] == "up"
                            && r["metrics"]["current_data_rate_tx_bps"] == 321
                    })
            })
            .await;
        assert!(
            records
                .iter()
                .any(|r| r["type"] == "link_response" && r["status"] == 0)
        );
        assert!(records.iter().any(|r| r["type"] == "address"
            && r["mac"].is_null()
            && r["address"] == "2001:db8::1"));
        assert!(
            records
                .iter()
                .any(|r| r["type"] == "address" && r["kind"] == "ipv6_subnet")
        );
        let generations: Vec<_> = records
            .iter()
            .filter(|r| r["type"] == "snapshot_end")
            .map(|r| r["generation"].as_u64().unwrap())
            .collect();
        assert!(
            generations.windows(2).any(|p| p[0] == p[1]),
            "resync must resend a current snapshot"
        );
        router.stop().await;
        let records = router.records();
        let start = records
            .iter()
            .rposition(|r| r["type"] == "snapshot_begin")
            .unwrap();
        assert_eq!(
            records[start + 1]["type"],
            "snapshot_end",
            "shutdown sends an empty replacement"
        );
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn adapter_failures_terminate_sessions_and_fail_the_binary() {
    for (mode, diagnostic) in [
        // Exit notification, pipe EOF, and a pending write can race when the
        // child exits. All are terminal adapter failures, with the same cleanup.
        ("exit", "router adapter failed"),
        ("invalid", "invalid router adapter message"),
        ("oversize", "exceeds"),
        ("closed", "closed its output"),
    ] {
        let modem = modem("127.0.0.1").await;
        let mut events = modem.subscribe();
        let mut router = Router::start(mode, modem.local_addr(), &[]);
        up(&mut events).await;
        assert!(!router.exit().await.success(), "{mode}");
        assert!(
            router.output().contains(diagnostic),
            "{mode}: {}",
            router.output()
        );
        timeout(WAIT, async {
            while !matches!(
                events.recv().await.unwrap(),
                DaemonEvent::SessionDown { .. }
            ) {}
        })
        .await
        .unwrap();
        assert!(modem.state().borrow().sessions.is_empty());
        modem.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn shutdown_kills_an_adapter_that_ignores_eof() {
    let modem = modem("127.0.0.1").await;
    let mut router = Router::start("ignore_eof", modem.local_addr(), &[]);
    router
        .records_until(|r| r.iter().any(|v| v["type"] == "session"))
        .await;
    let pid: i32 = std::fs::read_to_string(router.log.with_extension("log.pid"))
        .unwrap()
        .parse()
        .unwrap();
    router.stop().await;
    assert_eq!(
        kill(Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    );
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn adapter_does_not_inherit_router_ambient_capabilities() {
    let modem = modem("127.0.0.1").await;
    let mut router = Router::start(
        "caps",
        modem.local_addr(),
        &[
            "setpriv",
            "--inh-caps",
            "+net_raw",
            "--ambient-caps",
            "+net_raw",
        ],
    );
    router.records_until(|r| !r.is_empty()).await;
    let caps = std::fs::read_to_string(router.log.with_extension("log.caps")).unwrap();
    let values: Vec<_> = caps
        .split_whitespace()
        .map(|s| u64::from_str_radix(s, 16).unwrap())
        .collect();
    assert_ne!(values[0], 0);
    assert_eq!(values[1], 0);
    router.stop().await;
    modem.shutdown().await.unwrap();
}

#[test]
fn check_config_validates_adapter_without_executing_it() {
    let dir = tempfile::tempdir().unwrap();
    let script = dir.path().join("adapter.py");
    let marker = dir.path().join("executed");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {marker:?}\n")).unwrap();
    std::fs::set_permissions(&script, Permissions::from_mode(0o755)).unwrap();
    let config = dir.path().join("router.toml");
    let check = |section: &str| {
        std::fs::write(
            &config,
            format!("[network]\nuse_tls = false\n[adapter]\n{section}\n"),
        )
        .unwrap();
        Command::new(BINARY)
            .args(["--check-config", "--config"])
            .arg(&config)
            .output()
            .unwrap()
    };
    let valid = format!("command = {script:?}");
    assert!(check(&valid).status.success());
    assert!(!marker.exists());
    for (section, diagnostic) in [
        ("command = 'relative'".into(), "absolute"),
        (
            format!("command = {:?}", dir.path().join("missing")),
            "not a file",
        ),
        (format!("{valid}\nargz = []"), "argz"),
        ("args = []".into(), "command"),
    ] {
        let output = check(&section);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains(diagnostic));
    }
    let parsed: dlep_daemon::RouterConfig = toml::from_str(&format!("[adapter]\n{valid}")).unwrap();
    let again: dlep_daemon::RouterConfig =
        toml::from_str(&toml::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(again.adapter.unwrap().command, script);
}
