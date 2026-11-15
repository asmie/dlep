//! Real dlep launcher -> daemon -> adapter pipelines, with no in-process DLEP
//! peer or mocked daemon API. Test control sockets only operate the adapters.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::net::SocketAddr;
use std::os::unix::{fs::PermissionsExt, process::CommandExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(12);
const MAC: &str = "02:00:00:00:00:01";
const MAC64: &str = "02:00:00:00:00:00:00:01";
const OTHER_MAC: &str = "02:00:00:00:00:02";

struct Control {
    stream: BufReader<UnixStream>,
    next: u64,
}

impl Control {
    async fn call(&mut self, mut request: Value) -> Value {
        self.next += 1;
        request["id"] = json!(self.next);
        let bytes = format!("{request}\n");
        timeout(WAIT, async {
            self.stream
                .get_mut()
                .write_all(bytes.as_bytes())
                .await
                .unwrap();
            let mut line = String::new();
            assert_ne!(
                self.stream.read_line(&mut line).await.unwrap(),
                0,
                "adapter control closed"
            );
            let response: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["reply"], self.next);
            response
        })
        .await
        .expect("adapter control timed out")
    }

    async fn send(&mut self, message: Value) {
        self.call(json!({"op":"send", "messages":[message]})).await;
    }

    async fn batch(&mut self, messages: Vec<Value>) {
        self.call(json!({"op":"send", "messages":messages})).await;
    }

    async fn crash(&mut self) {
        self.stream
            .get_mut()
            .write_all(b"{\"op\":\"crash\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        assert_eq!(
            timeout(WAIT, self.stream.read_line(&mut line))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}

struct Node {
    child: Option<Child>,
    control: Control,
    output: PathBuf,
    final_state: PathBuf,
    _dir: tempfile::TempDir,
}

impl Node {
    async fn start(role: &str, config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("control");
        let listener = UnixListener::bind(&socket).unwrap();
        let script = dir.path().join("adapter.py");
        std::fs::write(&script, include_str!("support/pipeline_adapter.py")).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let final_state = dir.path().join("final.json");
        let config_path = dir.path().join("config.toml");
        let section = if role == "modem" { "radio" } else { "adapter" };
        let adapter_role = if role == "modem" { "radio" } else { "router" };
        std::fs::write(&config_path, format!(
            "{config}\n[{section}]\ncommand = {script:?}\nargs = [{adapter_role:?}, {socket:?}, {final_state:?}]\n"
        )).unwrap();
        let output = dir.path().join("daemon.log");
        let file = File::create(&output).unwrap();
        // Each test owns its process group, so panic cleanup also kills paused
        // adapters rather than leaving grandchildren running in the namespace.
        let child = Command::new(env!("CARGO_BIN_EXE_dlep"))
            .args([role, "--config"])
            .arg(config_path)
            .process_group(0)
            .env("TOKIO_WORKER_THREADS", "2")
            .env("DLEP_LOG", "info")
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        // Install the process guard before awaiting adapter startup.
        let mut guard = ProcessGuard(Some(child));
        let (stream, _) = timeout(WAIT, listener.accept())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "adapter did not start: {}",
                    std::fs::read_to_string(&output).unwrap()
                )
            })
            .unwrap();
        let mut stream = BufReader::new(stream);
        let mut hello = String::new();
        timeout(WAIT, stream.read_line(&mut hello))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&hello).unwrap()["hello"],
            adapter_role
        );
        Self {
            child: guard.0.take(),
            control: Control { stream, next: 0 },
            output,
            final_state,
            _dir: dir,
        }
    }

    async fn modem(name: &str, ip: &str, port: u16) -> (Self, SocketAddr) {
        Self::modem_with_format(name, ip, port, "eui48").await
    }

    async fn modem_with_format(
        name: &str,
        ip: &str,
        port: u16,
        format: &str,
    ) -> (Self, SocketAddr) {
        let node = Self::start("modem", &format!(
            "peer_description = {name:?}\n[network]\nbind_addr = {ip:?}\ntcp_port = {port}\ndiscovery_port = 0\nuse_tls = false\nmac_address_format = {format:?}\n\
             [timers]\nheartbeat_interval_ms = 1000\ntermination_timeout_ms = 200\n\
             [metrics]\nmax_data_rate_rx_bps = 1000000\nmax_data_rate_tx_bps = 1000000\ncurrent_data_rate_rx_bps = 100\ncurrent_data_rate_tx_bps = 200\n\
             latency_us = 2500\nresources = 80\nrlq_rx = 60\nrlq_tx = 70\nmtu = 1500\n"
        )).await;
        let addr = timeout(WAIT, async {
            loop {
                for line in node
                    .log()
                    .split_inclusive('\n')
                    .filter(|l| l.ends_with('\n'))
                {
                    if let Some((_, addr)) = line.split_once("modem listening on ") {
                        return addr.trim().parse().unwrap();
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("modem did not listen: {}", node.log()));
        (node, addr)
    }

    async fn router(peers: &[SocketAddr]) -> Self {
        Self::router_with_format(peers, "eui48").await
    }

    async fn router_with_format(peers: &[SocketAddr], format: &str) -> Self {
        let peers: Vec<_> = peers.iter().map(ToString::to_string).collect();
        Self::start("router", &format!(
            "mode = 'static'\nstatic_peers = {}\n[network]\nuse_tls = false\nmac_address_format = {format:?}\n[timers]\nheartbeat_interval_ms = 1000\ntermination_timeout_ms = 200\n",
            json!(peers)
        )).await
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.output).unwrap_or_default()
    }

    async fn wait(&mut self, predicate: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        let result = timeout(WAIT, async {
            loop {
                last = self.control.call(json!({"op":"status"})).await;
                if predicate(&last) {
                    return last.clone();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        result.unwrap_or_else(|_| panic!("state did not converge: {last}\n{}", self.log()))
    }

    async fn result(&mut self, request: u64, outcome: &str) -> Value {
        let status = self
            .wait(|s| notice(s, "command_result", |n| n["request"] == request).is_some())
            .await;
        let result = notice(&status, "command_result", |n| n["request"] == request).unwrap();
        assert_eq!(result["outcome"], outcome, "{result}");
        result.clone()
    }

    async fn exit(&mut self) -> ExitStatus {
        let result = timeout(WAIT, async {
            loop {
                if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                    return status;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("daemon did not exit: {}", self.log()));
        self.child.take();
        result
    }

    async fn stop(&mut self) {
        kill(
            Pid::from_raw(self.child.as_ref().unwrap().id() as i32),
            Signal::SIGTERM,
        )
        .unwrap();
        assert!(self.exit().await.success(), "{}", self.log());
    }

    fn assert_final_empty(&self) {
        let final_state: Value =
            serde_json::from_str(&std::fs::read_to_string(&self.final_state).unwrap()).unwrap();
        assert_eq!(final_state["last_state"], json!({}));
        assert_eq!(final_state["incomplete"], false);
    }
}

struct ProcessGuard(Option<Child>);
impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = kill(Pid::from_raw(-(child.id() as i32)), Signal::SIGKILL);
            let _ = child.wait();
        }
    }
}
impl Drop for Node {
    fn drop(&mut self) {
        drop(ProcessGuard(self.child.take()));
    }
}

fn notice<'a>(
    status: &'a Value,
    kind: &str,
    predicate: impl Fn(&Value) -> bool,
) -> Option<&'a Value> {
    status["notices"]
        .as_array()?
        .iter()
        .rev()
        .find(|n| n["type"] == kind && predicate(n))
}

fn session<'a>(status: &'a Value, name: &str) -> Option<&'a Value> {
    status["state"]
        .as_object()?
        .values()
        .find(|s| s["peer_description"] == name)
}

fn destination<'a>(status: &'a Value, name: &str, mac: &str) -> Option<&'a Value> {
    session(status, name)?["destinations"].get(mac)
}

fn defaults() -> Value {
    json!({"max_data_rate_rx_bps":1000000,"max_data_rate_tx_bps":1000000,
        "current_data_rate_rx_bps":100,"current_data_rate_tx_bps":200,
        "latency_us":2500,"resources":80,"rlq_rx":60,"rlq_tx":70,"mtu":1500})
}

fn addresses(n: u8) -> Value {
    json!({"ipv4":[format!("192.0.2.{n}")], "ipv6":[format!("2001:db8::{n}")],
        "ipv4_subnets":[format!("198.51.{n}.0/24")], "ipv6_subnets":[format!("2001:db8:{n}::/64")]})
}

fn expected_addresses(n: u8) -> Value {
    json!([{"kind":"ipv4", "address":format!("192.0.2.{n}")},
        {"kind":"ipv6", "address":format!("2001:db8::{n}")},
        {"kind":"ipv4_subnet", "address":format!("198.51.{n}.0/24")},
        {"kind":"ipv6_subnet", "address":format!("2001:db8:{n}::/64")}])
}

async fn report(node: &mut Node, mac: &str, rate: u64, n: u8) {
    node.control
        .send(json!({"type":"destination_up", "mac":mac,
        "metrics":{"current_data_rate_tx_bps":rate,"rlq_tx":0},"addresses":addresses(n)}))
        .await;
}

async fn respond(radio: &mut Node, wanted: Value, granted: bool) -> Value {
    let status = radio
        .wait(|s| notice(s, "link_request", |n| n["requested"] == wanted).is_some())
        .await;
    let request = notice(&status, "link_request", |n| n["requested"] == wanted)
        .unwrap()
        .clone();
    let response = if granted {
        json!({"type":"link_response", "request":request["request"], "status":"success", "text":"applied by radio", "metrics":wanted})
    } else {
        json!({"type":"link_response", "request":request["request"], "status":"denied", "text":"latency fixed"})
    };
    radio.control.send(response).await;
    request
}

#[tokio::test]
async fn both_adapter_processes_exchange_complete_state_and_commands_over_ipv4_and_ipv6() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await; // Emitted before the router starts.
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let sid = session(&initial, "modem-a").unwrap()["session"]
            .as_u64()
            .unwrap();
        assert_eq!(initial["state"].as_object().unwrap().len(), 1);
        assert_eq!(session(&initial, "modem-a").unwrap()["metrics"], defaults());
        let mut expected = defaults();
        expected["current_data_rate_tx_bps"] = json!(700);
        expected["rlq_tx"] = json!(0);
        assert_eq!(
            destination(&initial, "modem-a", MAC).unwrap()["metrics"],
            expected
        );
        assert_eq!(
            destination(&initial, "modem-a", MAC).unwrap()["addresses"],
            expected_addresses(1)
        );

        router
            .control
            .send(
                json!({"type":"link_request","request":1,"session":sid,"mac":MAC,
            "requested":{"current_data_rate_tx_bps":321}}),
            )
            .await;
        router.result(1, "accepted").await;
        radio
            .wait(|s| notice(s, "link_request", |_| true).is_some())
            .await;
        router
            .control
            .send(json!({"type":"destination_down","request":2,"session":sid,"mac":MAC}))
            .await;
        assert_eq!(router.result(2, "rejected").await["code"], "busy");
        let received = respond(&mut radio, json!({"current_data_rate_tx_bps":321}), true).await;
        assert_eq!(received["mac"], MAC);
        assert_eq!(received["current"], expected);
        expected["current_data_rate_tx_bps"] = json!(321);
        let granted = router
            .wait(|s| {
                notice(s, "link_response", |n| n["text"] == "applied by radio").is_some()
                    && destination(s, "modem-a", MAC).is_some_and(|d| d["metrics"] == expected)
            })
            .await;
        assert_eq!(
            notice(&granted, "link_response", |_| true).unwrap()["status"],
            0
        );

        router
            .control
            .send(
                json!({"type":"link_request","request":3,"session":sid,"mac":MAC,
            "requested":{"latency_us":99}}),
            )
            .await;
        router.result(3, "accepted").await;
        respond(&mut radio, json!({"latency_us":99}), false).await;
        let denied = router
            .wait(|s| notice(s, "link_response", |n| n["text"] == "latency fixed").is_some())
            .await;
        assert_eq!(
            notice(&denied, "link_response", |n| n["text"] == "latency fixed").unwrap()["status"],
            2
        );
        assert_eq!(
            destination(&denied, "modem-a", MAC).unwrap()["metrics"],
            expected
        );

        router
            .control
            .send(json!({"type":"destination_down","request":4,"session":sid,"mac":MAC}))
            .await;
        router.result(4, "accepted").await;
        router
            .wait(|s| session(s, "modem-a").is_some() && destination(s, "modem-a", MAC).is_none())
            .await;
        radio.control.batch(vec![
            json!({"type":"session_metrics","metrics":{"latency_us":4444,"rlq_rx":55}}),
            json!({"type":"destination_update","mac":MAC,"metrics":{"current_data_rate_tx_bps":622}}),
            json!({"type":"destination_addresses","mac":MAC,"remove":addresses(1),"add":addresses(2)}),
        ]).await;
        let mut session_expected = defaults();
        session_expected["latency_us"] = json!(4444);
        session_expected["rlq_rx"] = json!(55);
        let withdrawn = router
            .wait(|s| session(s, "modem-a").is_some_and(|m| m["metrics"] == session_expected))
            .await;
        assert!(destination(&withdrawn, "modem-a", MAC).is_none());
        router
            .control
            .send(json!({"type":"destination_announce","request":5,"session":sid,"mac":MAC}))
            .await;
        router.result(5, "accepted").await;
        expected = session_expected;
        expected["current_data_rate_tx_bps"] = json!(622);
        let restored = router
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some_and(|d| {
                    d["metrics"] == expected && d["addresses"] == expected_addresses(2)
                })
            })
            .await;
        assert_eq!(restored["state"].as_object().unwrap().len(), 1);

        radio
            .control
            .send(json!({"type":"destination_down","mac":MAC}))
            .await;
        router
            .wait(|s| destination(s, "modem-a", MAC).is_none())
            .await;
        report(&mut radio, MAC, 900, 3).await;
        let latest = router
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some_and(|d| {
                    d["metrics"]["current_data_rate_tx_bps"] == 900
                        && d["addresses"] == expected_addresses(3)
                })
            })
            .await;
        let ended = latest["generations"].as_array().unwrap().len();
        router.control.send(json!({"type":"resync"})).await;
        let resynced = router
            .wait(|s| s["generations"].as_array().unwrap().len() > ended)
            .await;
        assert_eq!(resynced["state"], latest["state"]);
        assert_eq!(resynced["generation"], latest["generation"]);
        router.stop().await;
        router.assert_final_empty();
        radio.stop().await;
    }
}

#[tokio::test]
async fn two_modems_with_the_same_mac_keep_commands_metrics_and_withdrawals_isolated() {
    let (mut a, aa) = Node::modem("modem-a", "127.0.0.1", 0).await;
    let (mut b, ba) = Node::modem("modem-b", "127.0.0.1", 0).await;
    report(&mut a, MAC, 700, 1).await;
    report(&mut b, MAC, 800, 2).await;
    let mut router = Node::router(&[aa, ba]).await;
    let initial = router
        .wait(|s| {
            destination(s, "modem-a", MAC).is_some() && destination(s, "modem-b", MAC).is_some()
        })
        .await;
    let sid = session(&initial, "modem-a").unwrap()["session"].clone();
    let other = session(&initial, "modem-b").unwrap().clone();
    assert_ne!(sid, other["session"]);
    assert_eq!(
        other["destinations"][MAC]["addresses"],
        expected_addresses(2)
    );
    router
        .control
        .send(
            json!({"type":"link_request","request":1,"session":sid,"mac":MAC,
        "requested":{"current_data_rate_tx_bps":333}}),
        )
        .await;
    router.result(1, "accepted").await;
    respond(&mut a, json!({"current_data_rate_tx_bps":333}), true).await;
    let granted = router
        .wait(|s| {
            destination(s, "modem-a", MAC)
                .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 333)
        })
        .await;
    assert_eq!(session(&granted, "modem-b").unwrap(), &other);
    let b_state = b.control.call(json!({"op":"status"})).await;
    assert!(notice(&b_state, "link_request", |_| true).is_none());
    router
        .control
        .send(json!({"type":"destination_down","request":2,"session":sid,"mac":MAC}))
        .await;
    router.result(2, "accepted").await;
    let withdrawn = router
        .wait(|s| destination(s, "modem-a", MAC).is_none())
        .await;
    assert_eq!(session(&withdrawn, "modem-b").unwrap(), &other);
    router
        .control
        .send(json!({"type":"destination_announce","request":3,"session":sid,"mac":MAC}))
        .await;
    router.result(3, "accepted").await;
    router
        .wait(|s| destination(s, "modem-a", MAC).is_some())
        .await;
    b.control
        .send(json!({"type":"destination_down","mac":MAC}))
        .await;
    let gone = router
        .wait(|s| destination(s, "modem-b", MAC).is_none())
        .await;
    assert_eq!(
        destination(&gone, "modem-a", MAC).unwrap()["metrics"]["current_data_rate_tx_bps"],
        333
    );
    router.stop().await;
    router.assert_final_empty();
    a.stop().await;
    b.stop().await;
}

#[tokio::test]
async fn radio_failure_and_modem_restart_replace_old_session_and_destination_state() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let old_sid = session(&initial, "modem-a").unwrap()["session"].clone();
        radio.control.crash().await;
        assert!(!radio.exit().await.success());
        let empty = router.wait(|s| s["state"] == json!({})).await;
        assert!(empty["generation"].as_u64().unwrap() > initial["generation"].as_u64().unwrap());
        assert!(router.child.as_mut().unwrap().try_wait().unwrap().is_none());
        let (mut restarted, new_addr) = Node::modem("modem-a", ip, addr.port()).await;
        assert_eq!(new_addr, addr);
        report(&mut restarted, OTHER_MAC, 500, 4).await;
        let fresh = router
            .wait(|s| destination(s, "modem-a", OTHER_MAC).is_some())
            .await;
        let fresh_session = session(&fresh, "modem-a").unwrap();
        assert_ne!(fresh_session["session"], old_sid);
        assert_eq!(fresh_session["destinations"].as_object().unwrap().len(), 1);
        assert_eq!(
            fresh_session["destinations"][OTHER_MAC]["addresses"],
            expected_addresses(4)
        );
        router
            .control
            .send(json!({"type":"destination_down","request":1,"session":old_sid,"mac":MAC}))
            .await;
        assert_eq!(router.result(1, "rejected").await["code"], "stale_session");
        router.control.send(json!({"type":"link_request","request":2,"session":fresh_session["session"],"mac":OTHER_MAC,
            "requested":{"current_data_rate_tx_bps":456}})).await;
        router.result(2, "accepted").await;
        respond(
            &mut restarted,
            json!({"current_data_rate_tx_bps":456}),
            true,
        )
        .await;
        router
            .wait(|s| {
                destination(s, "modem-a", OTHER_MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 456)
            })
            .await;
        router.stop().await;
        router.assert_final_empty();
        restarted.stop().await;
    }
}

#[tokio::test]
async fn paused_consumer_recovers_exact_state_after_a_real_event_gap() {
    let (mut radio, addr) = Node::modem("modem-a", "127.0.0.1", 0).await;
    report(&mut radio, MAC, 700, 1).await;
    let mut router = Node::router(&[addr]).await;
    let initial = router
        .wait(|s| destination(s, "modem-a", MAC).is_some())
        .await;
    router.control.call(json!({"op":"pause"})).await;
    // Fill the real adapter input pipe and bounded resync queue while its
    // control socket remains responsive. No daemon or network task is paused.
    router
        .control
        .batch(vec![json!({"type":"resync"}); 256])
        .await;
    router
        .wait(|s| s["queued_bytes"].as_u64().unwrap() > 2048)
        .await;
    let mut updates: Vec<_> = (0..2048)
        .map(|n| {
            json!({"type":"destination_update","mac":MAC,
        "metrics":{"current_data_rate_tx_bps":1000+n}})
        })
        .collect();
    updates.push(
        json!({"type":"destination_addresses","mac":MAC,"remove":addresses(1),"add":addresses(5)}),
    );
    radio.control.batch(updates).await;
    router.control.call(json!({"op":"resume"})).await;
    let mut expected = defaults();
    expected["current_data_rate_tx_bps"] = json!(3047);
    expected["rlq_tx"] = json!(0);
    let recovered = router
        .wait(|s| {
            notice(s, "event_gap", |_| true).is_some()
                && destination(s, "modem-a", MAC).is_some_and(|d| {
                    d["metrics"] == expected && d["addresses"] == expected_addresses(5)
                })
        })
        .await;
    assert!(
        notice(&recovered, "event_gap", |_| true).unwrap()["skipped"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(recovered["state"].as_object().unwrap().len(), 1);
    assert_eq!(
        session(&recovered, "modem-a").unwrap()["destinations"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        session(&recovered, "modem-a").unwrap()["session"],
        session(&initial, "modem-a").unwrap()["session"]
    );
    assert!(recovered["generation"].as_u64().unwrap() > initial["generation"].as_u64().unwrap());
    router.stop().await;
    router.assert_final_empty();
    radio.stop().await;
}

fn announcements(session: &Value, count: u64) -> Vec<Value> {
    (1..=count)
        .map(|request| json!({"type":"destination_announce", "request":request,
            "session":session, "mac":format!("02:00:00:01:{:02x}:{:02x}", request >> 8, request & 255)}))
        .collect()
}

#[tokio::test]
async fn radio_mac_policy_preserves_valid_reports_commands_and_replay() {
    for (format, valid, invalid) in [("eui48", MAC, MAC64), ("eui64", MAC64, MAC)] {
        for ip in ["127.0.0.1", "::1"] {
            let (mut radio, addr) = Node::modem_with_format("modem-a", ip, 0, format).await;
            report(&mut radio, invalid, 999, 2).await;
            report(&mut radio, valid, 700, 1).await;
            let mut router = Node::router_with_format(&[addr], format).await;
            let initial = router
                .wait(|s| destination(s, "modem-a", valid).is_some())
                .await;
            assert_eq!(
                session(&initial, "modem-a").unwrap()["destinations"]
                    .as_object()
                    .unwrap()
                    .len(),
                1
            );
            let sid = session(&initial, "modem-a").unwrap()["session"].clone();
            radio.control.batch(vec![
                json!({"type":"destination_up", "mac":invalid, "metrics":{"latency_us":999}}),
                json!({"type":"destination_update", "mac":valid, "metrics":{"current_data_rate_rx_bps":444}}),
            ]).await;
            router
                .wait(|s| {
                    destination(s, "modem-a", valid)
                        .is_some_and(|d| d["metrics"]["current_data_rate_rx_bps"] == 444)
                })
                .await;
            router
                .control
                .send(json!({"type":"link_request", "request":1,
                "session":sid, "mac":valid, "requested":{"current_data_rate_tx_bps":321}}))
                .await;
            router.result(1, "accepted").await;
            let request = respond(&mut radio, json!({"current_data_rate_tx_bps":321}), true).await;
            assert_eq!(request["mac"], valid);
            let granted = router
                .wait(|s| notice(s, "link_response", |n| n["mac"] == valid).is_some())
                .await;
            let mut expected = defaults();
            expected["current_data_rate_rx_bps"] = json!(444);
            expected["current_data_rate_tx_bps"] = json!(321);
            expected["rlq_tx"] = json!(0);
            assert_eq!(
                destination(&granted, "modem-a", valid).unwrap()["metrics"],
                expected
            );
            let mut late = Node::router_with_format(&[addr], format).await;
            let replay = late
                .wait(|s| destination(s, "modem-a", valid).is_some())
                .await;
            assert_eq!(
                session(&replay, "modem-a").unwrap()["destinations"]
                    .as_object()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                destination(&replay, "modem-a", valid).unwrap()["metrics"],
                expected
            );
            assert_eq!(
                destination(&replay, "modem-a", valid).unwrap()["addresses"],
                expected_addresses(1)
            );
            for consumer in [&mut router, &mut late] {
                consumer.stop().await;
                consumer.assert_final_empty();
            }
            radio.stop().await;
        }
    }
}

#[tokio::test]
async fn oversized_radio_address_batches_preserve_replay_and_allow_recovery() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        let ipv6: Vec<_> = (1..=3119).map(|n| format!("2001:db8::{n:x}")).collect();
        let mut initial = addresses(1);
        initial["ipv6"] = json!(&ipv6[..1600]);
        radio
            .control
            .send(json!({"type":"destination_up", "mac":MAC,
            "addresses":initial}))
            .await;
        let mut router = Node::router(&[addr]).await;
        let original = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let mut expected = vec![json!({"kind":"ipv4", "address":"192.0.2.1"})];
        expected.extend(
            ipv6[..1600]
                .iter()
                .map(|address| json!({"kind":"ipv6", "address":address})),
        );
        expected.extend([
            json!({"kind":"ipv4_subnet", "address":"198.51.1.0/24"}),
            json!({"kind":"ipv6_subnet", "address":"2001:db8:1::/64"}),
        ]);
        assert_eq!(
            destination(&original, "modem-a", MAC).unwrap()["addresses"],
            json!(expected)
        );

        radio
            .control
            .batch(vec![
                json!({"type":"destination_addresses", "mac":MAC,
                "add":{"ipv6":&ipv6[1600..]},
                "remove":{"ipv4":["192.0.2.1"],"ipv6":&ipv6[..1],
                    "ipv4_subnets":["198.51.1.0/24"],"ipv6_subnets":["2001:db8:1::/64"]}}),
                // Receipt of this later report proves the address batch was handled.
                json!({"type":"destination_update", "mac":MAC,"metrics":{"latency_us":4321}}),
            ])
            .await;
        let rejected = router
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some_and(|d| d["metrics"]["latency_us"] == 4321)
            })
            .await;
        assert_eq!(
            destination(&rejected, "modem-a", MAC).unwrap()["addresses"],
            json!(expected)
        );
        let mut late = Node::router(&[addr]).await;
        let replay = late
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["addresses"],
            json!(expected)
        );
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["metrics"],
            destination(&rejected, "modem-a", MAC).unwrap()["metrics"]
        );

        // A later batch can free enough room and add the same addresses.
        radio
            .control
            .send(json!({"type":"destination_addresses", "mac":MAC,
            "add":{"ipv6":&ipv6[1600..]},"remove":{"ipv6":&ipv6[..300]}}))
            .await;
        expected.drain(1..301);
        let subnets = expected.split_off(expected.len() - 2);
        expected.extend(
            ipv6[1600..]
                .iter()
                .map(|address| json!({"kind":"ipv6", "address":address})),
        );
        expected.extend(subnets);
        for consumer in [&mut router, &mut late] {
            consumer
                .wait(|s| {
                    destination(s, "modem-a", MAC)
                        .is_some_and(|d| d["addresses"] == json!(expected))
                })
                .await;
            consumer.stop().await;
            consumer.assert_final_empty();
        }
        radio.stop().await;
    }
}

#[tokio::test]
async fn partial_link_grants_preserve_new_reports_and_other_sessions_cache_changes() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut a = Node::router(&[addr]).await;
        let mut b = Node::router(&[addr]).await;
        let tx = json!({"current_data_rate_tx_bps":321});
        let latency = json!({"latency_us":444});
        for (router, wanted) in [(&mut a, &tx), (&mut b, &latency)] {
            let initial = router
                .wait(|s| destination(s, "modem-a", MAC).is_some())
                .await;
            let sid = session(&initial, "modem-a").unwrap()["session"].clone();
            router
                .control
                .send(json!({"type":"link_request", "request":1,
                "session":sid, "mac":MAC, "requested":wanted}))
                .await;
            router.result(1, "accepted").await;
            radio
                .wait(|s| notice(s, "link_request", |n| n["requested"] == *wanted).is_some())
                .await;
        }
        // Both requests captured the original values before this report.
        radio
            .control
            .send(json!({"type":"destination_update", "mac":MAC,
            "metrics":{"current_data_rate_rx_bps":250,"rlq_rx":0,"mtu":1400}}))
            .await;
        for router in [&mut a, &mut b] {
            router
                .wait(|s| {
                    destination(s, "modem-a", MAC)
                        .is_some_and(|d| d["metrics"]["current_data_rate_rx_bps"] == 250)
                })
                .await;
        }
        let mut reported = defaults();
        reported["current_data_rate_tx_bps"] = json!(700);
        reported["current_data_rate_rx_bps"] = json!(250);
        reported["rlq_rx"] = json!(0);
        reported["rlq_tx"] = json!(0);
        reported["mtu"] = json!(1400);
        respond(&mut radio, tx, true).await;
        let first = a
            .wait(|s| notice(s, "link_response", |_| true).is_some())
            .await;
        let mut expected_a = reported.clone();
        expected_a["current_data_rate_tx_bps"] = json!(321);
        assert_eq!(
            destination(&first, "modem-a", MAC).unwrap()["metrics"],
            expected_a
        );

        respond(&mut radio, latency, true).await;
        let second = b
            .wait(|s| notice(s, "link_response", |_| true).is_some())
            .await;
        let mut expected_b = reported;
        expected_b["latency_us"] = json!(444);
        assert_eq!(
            destination(&second, "modem-a", MAC).unwrap()["metrics"],
            expected_b
        );
        let unchanged = a.control.call(json!({"op":"status"})).await;
        assert_eq!(
            destination(&unchanged, "modem-a", MAC).unwrap()["metrics"],
            expected_a
        );

        // The cache accumulates both explicit grants, without copying either
        // router's older, session-specific omitted values over the other grant.
        let mut late = Node::router(&[addr]).await;
        let replay = late
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let mut expected_cache = expected_a;
        expected_cache["latency_us"] = json!(444);
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["metrics"],
            expected_cache
        );
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["addresses"],
            expected_addresses(1)
        );
        for router in [&mut a, &mut b, &mut late] {
            router.stop().await;
            router.assert_final_empty();
        }
        radio.stop().await;
    }
}

#[tokio::test]
async fn old_link_grant_cannot_change_a_replacement_or_its_replay() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let sid = session(&initial, "modem-a").unwrap()["session"].clone();
        router
            .control
            .send(json!({"type":"link_request", "request":1,
            "session":sid, "mac":MAC, "requested":{"current_data_rate_tx_bps":321}}))
            .await;
        router.result(1, "accepted").await;
        radio
            .wait(|s| notice(s, "link_request", |_| true).is_some())
            .await;
        radio
            .control
            .batch(vec![
                json!({"type":"destination_down", "mac":MAC}),
                json!({"type":"destination_up", "mac":MAC,
                "metrics":{"current_data_rate_tx_bps":900,"rlq_tx":0}, "addresses":addresses(2)}),
            ])
            .await;
        // The old answer still completes its transaction; the pending Down
        // must then be followed by the replacement's own metrics and addresses.
        respond(&mut radio, json!({"current_data_rate_tx_bps":321}), true).await;
        let replacement = router
            .wait(|s| {
                destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["addresses"] == expected_addresses(2))
            })
            .await;
        let mut expected = defaults();
        expected["current_data_rate_tx_bps"] = json!(900);
        expected["rlq_tx"] = json!(0);
        assert_eq!(
            destination(&replacement, "modem-a", MAC).unwrap()["metrics"],
            expected
        );

        let mut late = Node::router(&[addr]).await;
        let replay = late
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["metrics"],
            expected
        );
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["addresses"],
            expected_addresses(2)
        );
        router
            .control
            .send(json!({"type":"link_request", "request":2,
            "session":sid, "mac":MAC, "requested":{"current_data_rate_tx_bps":444}}))
            .await;
        router.result(2, "accepted").await;
        respond(&mut radio, json!({"current_data_rate_tx_bps":444}), true).await;
        router
            .wait(|s| {
                destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
            })
            .await;
        let unchanged = late.control.call(json!({"op":"status"})).await;
        assert_eq!(
            destination(&unchanged, "modem-a", MAC).unwrap()["metrics"],
            expected
        );
        router.stop().await;
        router.assert_final_empty();
        late.stop().await;
        late.assert_final_empty();
        radio.stop().await;
    }
}

#[tokio::test]
async fn radio_input_failure_stops_the_modem_and_clears_router_state() {
    for op in ["close_input", "pause"] {
        let (mut radio, addr) = Node::modem("modem-a", "127.0.0.1", 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let sid = &session(&initial, "modem-a").unwrap()["session"];
        radio.control.call(json!({"op":op})).await;
        // Enough notices to fill the adapter's 4 KiB pipe and the output queue.
        // The adapter stays alive, keeps stdout open, and never reads stdin.
        router.control.batch(announcements(sid, 192)).await;
        router
            .wait(|s| {
                s["state"] == json!({})
                    && notice(s, "session_down", |n| n["status"] == 255).is_some()
            })
            .await;
        assert!(!radio.exit().await.success());
        let log = radio.log();
        assert!(
            [
                "writing to radio adapter",
                "radio adapter input stalled",
                "radio adapter writer stopped"
            ]
            .iter()
            .any(|cause| log.contains(cause)),
            "{log}"
        );
        assert!(log.contains("shutting down"), "{log}");
        assert!(router.child.as_mut().unwrap().try_wait().unwrap().is_none());
        router.stop().await;
        router.assert_final_empty();
    }
}

#[tokio::test]
async fn temporarily_paused_radio_recovers_notices_and_answers_a_pending_request() {
    let (mut radio, addr) = Node::modem("modem-a", "127.0.0.1", 0).await;
    report(&mut radio, MAC, 700, 1).await;
    let mut router = Node::router(&[addr]).await;
    let initial = router
        .wait(|s| destination(s, "modem-a", MAC).is_some())
        .await;
    let sid = &session(&initial, "modem-a").unwrap()["session"];
    radio.control.call(json!({"op":"pause"})).await;
    router.control.batch(announcements(sid, 144)).await;
    radio
        .wait(|s| s["queued_bytes"].as_u64().unwrap() > 2048)
        .await;
    router
        .control
        .send(json!({"type":"link_request", "request":145,
        "session":sid, "mac":MAC, "requested":{"current_data_rate_tx_bps":444}}))
        .await;
    router.result(145, "accepted").await;
    radio.control.call(json!({"op":"resume"})).await;
    respond(&mut radio, json!({"current_data_rate_tx_bps":444}), true).await;
    let latest = router
        .wait(|s| {
            destination(s, "modem-a", MAC)
                .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
        })
        .await;
    assert_eq!(session(&latest, "modem-a").unwrap()["session"], *sid);
    let received = radio
        .wait(|s| {
            s["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["type"] == "destination_announced")
                .count()
                == 144
        })
        .await;
    assert_eq!(
        notice(&received, "session_sync", |_| true).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    router.stop().await;
    router.assert_final_empty();
    radio.stop().await;
}
