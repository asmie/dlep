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
        let acknowledged = radio
            .wait(|s| notice(s, "destination_up_response", |n| n["mac"] == MAC).is_some())
            .await;
        let response = notice(&acknowledged, "destination_up_response", |_| true).unwrap();
        assert_eq!(response["status"], 0);
        assert_eq!(response["text"], "");
        assert!(
            notice(&acknowledged, "session_sync", |n| {
                n["sessions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p["session"] == response["session"])
            })
            .is_some()
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
        let completed = radio
            .wait(|s| notice(s, "session_update_response", |_| true).is_some())
            .await;
        assert_eq!(
            notice(&completed, "session_update_response", |_| true).unwrap(),
            &json!({"type":"session_update_response", "session":response["session"], "status":0, "text":""})
        );
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
async fn radio_withdrawal_notices_preserve_other_routers_and_replay() {
    for (format, mac) in [("eui48", MAC), ("eui64", MAC64)] {
        for ip in ["127.0.0.1", "::1"] {
            let (mut radio, addr) = Node::modem_with_format("modem-a", ip, 0, format).await;
            report(&mut radio, mac, 700, 1).await;
            let mut a = Node::router_with_format(&[addr], format).await;
            let initial = a.wait(|s| destination(s, "modem-a", mac).is_some()).await;
            let aid = session(&initial, "modem-a").unwrap()["session"].clone();
            let accepted = radio
                .wait(|s| notice(s, "destination_up_response", |_| true).is_some())
                .await;
            let radio_aid =
                notice(&accepted, "destination_up_response", |_| true).unwrap()["session"].clone();

            let mut b = Node::router_with_format(&[addr], format).await;
            b.wait(|s| destination(s, "modem-a", mac).is_some()).await;
            radio
                .wait(|s| {
                    notice(s, "destination_up_response", |n| n["session"] != radio_aid).is_some()
                })
                .await;
            a.control
                .send(json!({"type":"destination_down", "request":1, "session":aid, "mac":mac}))
                .await;
            a.result(1, "accepted").await;
            a.wait(|s| destination(s, "modem-a", mac).is_none()).await;
            let response = a
                .wait(|s| notice(s, "down_response", |_| true).is_some())
                .await;
            assert_eq!(
                notice(&response, "down_response", |_| true).unwrap(),
                &json!({"type":"down_response", "session":aid, "mac":mac, "status":0, "text":""})
            );
            let withdrawn = radio
                .wait(|s| notice(s, "destination_withdrawn", |_| true).is_some())
                .await;
            let expected_notice =
                json!({"type":"destination_withdrawn", "session":radio_aid, "mac":mac});
            assert_eq!(
                notice(&withdrawn, "destination_withdrawn", |_| true).unwrap(),
                &expected_notice
            );

            // Interest changes must not remove the physical destination or
            // suppress reports to the other router.
            radio
                .control
                .batch(vec![
                    json!({"type":"destination_update", "mac":mac,
                    "metrics":{"current_data_rate_tx_bps":900,"latency_us":444}}),
                    json!({"type":"destination_addresses", "mac":mac,
                    "remove":addresses(1), "add":addresses(2)}),
                ])
                .await;
            let mut expected = defaults();
            expected["current_data_rate_tx_bps"] = json!(900);
            expected["latency_us"] = json!(444);
            expected["rlq_tx"] = json!(0);
            b.wait(|s| {
                destination(s, "modem-a", mac).is_some_and(|d| {
                    d["metrics"] == expected && d["addresses"] == expected_addresses(2)
                })
            })
            .await;
            let unchanged = a.control.call(json!({"op":"status"})).await;
            assert!(destination(&unchanged, "modem-a", mac).is_none());

            let mut late = Node::router_with_format(&[addr], format).await;
            let replay = late
                .wait(|s| destination(s, "modem-a", mac).is_some())
                .await;
            assert_eq!(
                destination(&replay, "modem-a", mac).unwrap()["metrics"],
                expected
            );
            assert_eq!(
                destination(&replay, "modem-a", mac).unwrap()["addresses"],
                expected_addresses(2)
            );
            a.control
                .send(json!({"type":"destination_announce", "request":2, "session":aid, "mac":mac}))
                .await;
            a.result(2, "accepted").await;
            a.wait(|s| {
                destination(s, "modem-a", mac).is_some_and(|d| {
                    d["metrics"] == expected && d["addresses"] == expected_addresses(2)
                })
            })
            .await;
            radio
                .wait(|s| {
                    notice(s, "destination_announced", |n| {
                        n["session"] == radio_aid && n["mac"] == mac
                    })
                    .is_some()
                })
                .await;

            // A physical Down followed by a new Up must not be echoed back
            // as a router withdrawal. The new Up responses are event barriers.
            radio
                .control
                .send(json!({"type":"destination_down", "mac":mac}))
                .await;
            for consumer in [&mut a, &mut b, &mut late] {
                consumer
                    .wait(|s| destination(s, "modem-a", mac).is_none())
                    .await;
            }
            report(&mut radio, mac, 950, 3).await;
            for consumer in [&mut a, &mut b, &mut late] {
                consumer
                    .wait(|s| {
                        destination(s, "modem-a", mac).is_some_and(|d| {
                            d["metrics"]["current_data_rate_tx_bps"] == 950
                                && d["addresses"] == expected_addresses(3)
                        })
                    })
                    .await;
            }
            let completed = radio
                .wait(|s| {
                    s["notices"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter(|n| n["type"] == "destination_up_response" && n["mac"] == mac)
                        .count()
                        == 6
                })
                .await;
            let withdrawals: Vec<_> = completed["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] == "destination_withdrawn")
                .collect();
            assert_eq!(withdrawals, vec![&expected_notice]);
            let responses: Vec<_> = completed["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] == "destination_down_response")
                .collect();
            assert_eq!(
                responses.len(),
                3,
                "one reply per physical Down on each router"
            );
            let mut sessions = std::collections::HashSet::new();
            for response in responses {
                assert!(sessions.insert(response["session"].as_u64().unwrap()));
                assert_eq!(
                    response,
                    &json!({"type":"destination_down_response", "session":response["session"],
                    "mac":mac, "status":0, "text":""})
                );
            }
            for consumer in [&mut a, &mut b, &mut late] {
                consumer.stop().await;
                consumer.assert_final_empty();
            }
            radio.stop().await;
        }
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
async fn denied_announces_report_completion_and_allow_retry() {
    for (format, mac) in [("eui48", MAC), ("eui64", MAC64)] {
        for ip in ["127.0.0.1", "::1"] {
            let (mut radio, addr) = Node::modem_with_format("modem-a", ip, 0, format).await;
            let mut router = Node::router_with_format(&[addr], format).await;
            let initial = router.wait(|s| session(s, "modem-a").is_some()).await;
            let sid = session(&initial, "modem-a").unwrap()["session"].clone();
            for request in 1..=2 {
                router
                    .control
                    .send(json!({"type":"destination_announce", "request":request,
                    "session":sid, "mac":mac}))
                    .await;
                router.result(request, "accepted").await;
                let replied = router
                    .wait(|s| {
                        s["notices"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .filter(|n| {
                                n["type"] == "announce_response"
                                    && n["session"] == sid
                                    && n["mac"] == mac
                            })
                            .count()
                            == request as usize
                    })
                    .await;
                assert_eq!(
                    notice(&replied, "announce_response", |_| true).unwrap(),
                    &json!({"type":"announce_response", "session":sid,
                    "mac":mac, "status":2, "text":""})
                );
                assert!(destination(&replied, "modem-a", mac).is_none());
                assert_eq!(session(&replied, "modem-a").unwrap()["session"], sid);
            }
            router.stop().await;
            router.assert_final_empty();
            radio.stop().await;
        }
    }
}

#[tokio::test]
async fn near_limit_destinations_reannounce_on_the_original_session() {
    for (format, mac) in [("eui48", MAC), ("eui64", MAC64)] {
        for ip in ["127.0.0.1", "::1"] {
            let (mut radio, addr) = Node::modem_with_format("modem-a", ip, 0, format).await;
            let ipv4: Vec<_> = (1..=4).map(|n| format!("192.0.2.{n}")).collect();
            let ipv6: Vec<_> = (1..=3113).map(|n| format!("2001:db8:1::{n:x}")).collect();
            radio
                .control
                .send(json!({"type":"destination_up", "mac":mac,
                "metrics":{"latency_us":321,"rlq_rx":0},
                "addresses":{"ipv4":ipv4,"ipv6":ipv6,
                    "ipv4_subnets":["198.51.100.0/24"],"ipv6_subnets":["2001:db8:2::/64"]}}))
                .await;
            let mut expected_addresses: Vec<_> = ipv4
                .iter()
                .map(|address| json!({"kind":"ipv4", "address":address}))
                .collect();
            expected_addresses.extend(
                ipv6.iter()
                    .map(|address| json!({"kind":"ipv6", "address":address})),
            );
            expected_addresses.extend([
                json!({"kind":"ipv4_subnet", "address":"198.51.100.0/24"}),
                json!({"kind":"ipv6_subnet", "address":"2001:db8:2::/64"}),
            ]);
            let mut expected_metrics = defaults();
            expected_metrics["latency_us"] = json!(321);
            expected_metrics["rlq_rx"] = json!(0);
            let mut router = Node::router_with_format(&[addr], format).await;
            let initial = router
                .wait(|s| destination(s, "modem-a", mac).is_some())
                .await;
            assert_eq!(
                destination(&initial, "modem-a", mac).unwrap()["addresses"],
                json!(expected_addresses)
            );
            assert_eq!(
                destination(&initial, "modem-a", mac).unwrap()["metrics"],
                expected_metrics
            );
            let sid = session(&initial, "modem-a").unwrap()["session"].clone();
            router
                .control
                .send(json!({"type":"destination_down", "request":1, "session":sid,"mac":mac}))
                .await;
            router.result(1, "accepted").await;
            router
                .wait(|s| {
                    session(s, "modem-a").is_some() && destination(s, "modem-a", mac).is_none()
                })
                .await;
            router
                .control
                .send(json!({"type":"destination_announce", "request":2, "session":sid,"mac":mac}))
                .await;
            router.result(2, "accepted").await;
            // An encoding failure must not masquerade as success via automatic
            // reconnect and a fresh Up. Require every address on the same session.
            let restored = router
                .wait(|s| {
                    session(s, "modem-a").is_some_and(|p| p["session"] == sid)
                        && notice(s, "announce_response", |n| {
                            n["session"] == sid && n["mac"] == mac && n["status"] == 0
                        })
                        .is_some()
                        && destination(s, "modem-a", mac)
                            .is_some_and(|d| d["addresses"] == json!(expected_addresses))
                })
                .await;
            assert_eq!(
                destination(&restored, "modem-a", mac).unwrap()["metrics"],
                expected_metrics
            );
            radio.control.batch(vec![
                json!({"type":"destination_addresses", "mac":mac,"remove":{"ipv6_subnets":["2001:db8:2::/64"]}}),
                json!({"type":"destination_update", "mac":mac,"metrics":{"latency_us":654}}),
            ]).await;
            expected_addresses.pop();
            let updated = router
                .wait(|s| {
                    destination(s, "modem-a", mac).is_some_and(|d| {
                        d["addresses"] == json!(expected_addresses)
                            && d["metrics"]["latency_us"] == 654
                    })
                })
                .await;
            assert_eq!(session(&updated, "modem-a").unwrap()["session"], sid);
            expected_metrics["latency_us"] = json!(654);
            assert_eq!(
                destination(&updated, "modem-a", mac).unwrap()["metrics"],
                expected_metrics
            );
            router.stop().await;
            router.assert_final_empty();
            radio.stop().await;
        }
    }
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
async fn oversized_radio_link_replies_preserve_replay_and_allow_recovery() {
    for (format, mac, mac_bytes) in [("eui48", MAC, 6), ("eui64", MAC64, 8)] {
        for ip in ["127.0.0.1", "::1"] {
            let (mut radio, addr) = Node::modem_with_format("modem-a", ip, 0, format).await;
            report(&mut radio, mac, 700, 1).await;
            let mut router = Node::router_with_format(&[addr], format).await;
            let initial = router
                .wait(|s| destination(s, "modem-a", mac).is_some())
                .await;
            let sid = session(&initial, "modem-a").unwrap()["session"].clone();
            let mut expected = defaults();
            expected["current_data_rate_tx_bps"] = json!(700);
            expected["rlq_tx"] = json!(0);
            for (request, oversized, latency) in [(1, true, 321), (2, false, 322)] {
                let wanted = json!({"latency_us":latency});
                router
                    .control
                    .send(json!({"type":"link_request", "request":request,
                        "session":sid, "mac":mac, "requested":wanted}))
                    .await;
                router.result(request, "accepted").await;
                let pending = radio
                    .wait(|s| notice(s, "link_request", |n| n["requested"] == wanted).is_some())
                    .await;
                let pending =
                    notice(&pending, "link_request", |n| n["requested"] == wanted).unwrap();
                // TLV headers plus MAC, Status, five u64 metrics, three u8
                // metrics, and MTU. Omitted metrics still occupy wire space.
                let overhead = (4 + mac_bytes) + (4 + 1) + 5 * (4 + 8) + 3 * (4 + 1) + (4 + 2);
                let text = if oversized {
                    "x".repeat(usize::from(u16::MAX) - overhead + 1)
                } else {
                    "applied".into()
                };
                let line = json!({"type":"link_response", "request":pending["request"],
                    "status":"success", "text":text, "metrics":wanted})
                .to_string();
                assert!(line.len() <= 64 * 1024, "reply must pass JSON-line framing");
                radio
                    .control
                    .call(json!({"op":"send_line", "line":line}))
                    .await;
                let code = if oversized { 2 } else { 0 };
                let replied = router
                    .wait(|s| {
                        notice(s, "link_response", |n| {
                            n["mac"] == mac && n["status"] == code
                        })
                        .is_some()
                    })
                    .await;
                assert_eq!(session(&replied, "modem-a").unwrap()["session"], sid);
                assert_eq!(
                    notice(&replied, "link_response", |n| n["status"] == code).unwrap()["text"],
                    if oversized { "" } else { "applied" }
                );
                if !oversized {
                    expected["latency_us"] = json!(latency);
                }
                assert_eq!(
                    destination(&replied, "modem-a", mac).unwrap()["metrics"],
                    expected
                );
                let mut late = Node::router_with_format(&[addr], format).await;
                let replay = late
                    .wait(|s| destination(s, "modem-a", mac).is_some())
                    .await;
                assert_eq!(
                    destination(&replay, "modem-a", mac).unwrap()["metrics"],
                    expected
                );
                assert_eq!(
                    destination(&replay, "modem-a", mac).unwrap()["addresses"],
                    expected_addresses(1)
                );
                late.stop().await;
                late.assert_final_empty();
            }
            router.stop().await;
            router.assert_final_empty();
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
async fn a_report_immediately_after_a_link_grant_wins_for_live_state_and_replay() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let sid = session(&initial, "modem-a").unwrap()["session"].clone();
        let requested = json!({"current_data_rate_tx_bps":321,"latency_us":444});
        router
            .control
            .send(json!({"type":"link_request", "request":1,
            "session":sid, "mac":MAC, "requested":requested}))
            .await;
        router.result(1, "accepted").await;
        let pending = radio
            .wait(|s| notice(s, "link_request", |_| true).is_some())
            .await;
        let request = notice(&pending, "link_request", |_| true).unwrap()["request"].clone();
        // Send adjacent lines without waiting for the grant to reach the router.
        // The address change marks completion of the later destination report.
        radio
            .control
            .batch(vec![
                json!({"type":"link_response", "request":request, "status":"success",
                "text":"applied before report", "metrics":requested}),
                json!({"type":"destination_update", "mac":MAC,
                "metrics":{"current_data_rate_tx_bps":654,"current_data_rate_rx_bps":250}}),
                json!({"type":"destination_addresses", "mac":MAC,
                "remove":addresses(1), "add":addresses(2)}),
            ])
            .await;
        let updated = router
            .wait(|s| {
                notice(s, "link_response", |n| n["text"] == "applied before report").is_some()
                    && destination(s, "modem-a", MAC)
                        .is_some_and(|d| d["addresses"] == expected_addresses(2))
            })
            .await;
        assert_eq!(
            notice(&updated, "link_response", |_| true).unwrap()["status"],
            0
        );
        let mut expected = defaults();
        expected["current_data_rate_tx_bps"] = json!(654);
        expected["current_data_rate_rx_bps"] = json!(250);
        expected["latency_us"] = json!(444);
        expected["rlq_tx"] = json!(0);
        assert_eq!(
            destination(&updated, "modem-a", MAC).unwrap()["metrics"],
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
        for consumer in [&mut router, &mut late] {
            consumer.stop().await;
            consumer.assert_final_empty();
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
async fn radio_session_addresses_reach_all_routers_and_survive_reconnect() {
    let sync_count = |s: &Value| {
        s["notices"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["type"] == "session_sync")
            .count()
    };
    let has_addresses = |s: &Value, expected: &Value| {
        session(s, "modem-a").is_some_and(|m| m["addresses"] == *expected)
    };
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let before = radio.control.call(json!({"op":"status"})).await;
        let mut with_host_bits = addresses(2);
        with_host_bits["ipv4_subnets"] = json!(["198.51.2.7/24"]);
        with_host_bits["ipv6_subnets"] = json!(["2001:db8:2::7/64"]);
        radio
            .control
            .batch(vec![
                json!({"type":"session_addresses","add":addresses(1)}),
                json!({"type":"session_addresses","remove":addresses(1),"add":with_host_bits}),
                json!({"type":"resync"}),
            ])
            .await;
        radio.wait(|s| sync_count(s) > sync_count(&before)).await;

        let mut first = Node::router(&[addr]).await;
        let initial = first
            .wait(|s| {
                has_addresses(s, &expected_addresses(2)) && destination(s, "modem-a", MAC).is_some()
            })
            .await;
        let first_id = session(&initial, "modem-a").unwrap()["session"].clone();
        assert_eq!(
            destination(&initial, "modem-a", MAC).unwrap()["addresses"],
            expected_addresses(1)
        );
        let mut second = Node::router(&[addr]).await;
        let initial = second
            .wait(|s| {
                has_addresses(s, &expected_addresses(2)) && destination(s, "modem-a", MAC).is_some()
            })
            .await;
        let second_id = session(&initial, "modem-a").unwrap()["session"].clone();
        // Local modem addresses and the remote router snapshot are independent.
        first
            .control
            .send(json!({"type":"session_addresses","request":1,
            "session":first_id,"add":addresses(9)}))
            .await;
        first.result(1, "accepted").await;
        let state = radio
            .wait(|s| {
                notice(s, "session_sync", |_| true).is_some_and(|n| {
                    n["sessions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|m| m["addresses"] == addresses(9))
                })
            })
            .await;
        let remote = notice(&state, "session_sync", |_| true).unwrap()["sessions"].clone();
        assert_eq!(remote.as_array().unwrap().len(), 2);
        assert_eq!(
            remote
                .as_array()
                .unwrap()
                .iter()
                .filter(|m| m["addresses"] == addresses(9))
                .count(),
            1
        );
        assert!(
            remote.as_array().unwrap().iter().any(|m| m["addresses"]
                == json!({"ipv4":[],"ipv6":[],"ipv4_subnets":[],"ipv6_subnets":[]}))
        );

        first
            .control
            .send(json!({"type":"destination_down","request":2,
            "session":first_id,"mac":MAC}))
            .await;
        first.result(2, "accepted").await;
        first
            .wait(|s| destination(s, "modem-a", MAC).is_none())
            .await;
        second
            .control
            .send(json!({"type":"link_request","request":1,
            "session":second_id,"mac":MAC,"requested":{"current_data_rate_tx_bps":444}}))
            .await;
        second.result(1, "accepted").await;
        respond(&mut radio, json!({"current_data_rate_tx_bps":444}), true).await;
        second
            .wait(|s| {
                destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
            })
            .await;

        let before = radio.control.call(json!({"op":"status"})).await;
        radio
            .control
            .batch(vec![
                json!({"type":"session_addresses","remove":addresses(2),"add":addresses(3)}),
                json!({"type":"resync"}),
            ])
            .await;
        let updated = first
            .wait(|s| has_addresses(s, &expected_addresses(3)))
            .await;
        assert!(destination(&updated, "modem-a", MAC).is_none());
        let updated = second
            .wait(|s| has_addresses(s, &expected_addresses(3)))
            .await;
        assert_eq!(
            destination(&updated, "modem-a", MAC).unwrap()["metrics"]["current_data_rate_tx_bps"],
            444
        );
        assert_eq!(
            destination(&updated, "modem-a", MAC).unwrap()["addresses"],
            expected_addresses(1)
        );
        let refreshed = radio.wait(|s| sync_count(s) > sync_count(&before)).await;
        assert_eq!(
            notice(&refreshed, "session_sync", |_| true).unwrap()["sessions"],
            remote
        );
        radio
            .wait(|s| {
                s["notices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|n| n["type"] == "session_update_response" && n["status"] == 0)
                    .count()
                    == 4
            })
            .await;

        let mut late = Node::router(&[addr]).await;
        late.wait(|s| {
            has_addresses(s, &expected_addresses(3))
                && destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
        })
        .await;
        radio
            .control
            .send(json!({"type":"session_addresses","remove":addresses(3)}))
            .await;
        for router in [&mut first, &mut second, &mut late] {
            router.wait(|s| has_addresses(s, &json!([]))).await;
            router.stop().await;
            router.assert_final_empty();
        }
        radio
            .wait(|s| {
                notice(s, "session_sync", |_| true).is_some_and(|n| n["sessions"] == json!([]))
            })
            .await;
        // After all routers leave, new reports still update the replay cache.
        radio
            .control
            .send(json!({"type":"session_addresses","add":addresses(4)}))
            .await;
        let mut reconnected = Node::router(&[addr]).await;
        reconnected
            .wait(|s| {
                has_addresses(s, &expected_addresses(4))
                    && destination(s, "modem-a", MAC)
                        .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
            })
            .await;
        reconnected.stop().await;
        reconnected.assert_final_empty();
        radio.stop().await;
    }
}

#[tokio::test]
async fn radio_session_sync_tracks_router_addresses_and_removals() {
    fn members(status: &Value) -> &[Value] {
        notice(status, "session_sync", |_| true).unwrap()["sessions"]
            .as_array()
            .unwrap()
    }
    fn has_addresses(status: &Value, session: &Value, addresses: &Value) -> bool {
        members(status)
            .iter()
            .any(|s| s["session"] == *session && s["addresses"] == *addresses)
    }
    let empty = json!({"ipv4":[],"ipv6":[],"ipv4_subnets":[],"ipv6_subnets":[]});
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        let mut first = Node::router(&[addr]).await;
        let initial = first
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let first_id = session(&initial, "modem-a").unwrap()["session"].clone();
        let state = radio
            .wait(|s| {
                notice(s, "session_sync", |n| {
                    n["sessions"].as_array().unwrap().len() == 1
                })
                .is_some()
            })
            .await;
        let first_peer = members(&state)[0]["session"].clone();
        let mut second = Node::router(&[addr]).await;
        let initial = second
            .wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let second_id = session(&initial, "modem-a").unwrap()["session"].clone();
        let state = radio
            .wait(|s| {
                notice(s, "session_sync", |n| {
                    n["sessions"].as_array().unwrap().len() == 2
                })
                .is_some()
            })
            .await;
        let second_peer = members(&state)
            .iter()
            .find(|s| s["session"] != first_peer)
            .unwrap()["session"]
            .clone();
        assert!(members(&state).iter().all(|s| s["addresses"] == empty));

        // Learning router addresses must not replay a withdrawn destination.
        first
            .control
            .send(json!({"type":"destination_down","request":1,"session":first_id,"mac":MAC}))
            .await;
        first.result(1, "accepted").await;
        first
            .wait(|s| destination(s, "modem-a", MAC).is_none())
            .await;
        let mut with_host_bits = addresses(1);
        with_host_bits["ipv4_subnets"] = json!(["198.51.1.7/24"]);
        with_host_bits["ipv6_subnets"] = json!(["2001:db8:1::7/64"]);
        first.control.send(json!({"type":"session_addresses","request":2,"session":first_id,"add":with_host_bits})).await;
        first.result(2, "accepted").await;
        let state = radio
            .wait(|s| has_addresses(s, &first_peer, &addresses(1)))
            .await;
        assert_eq!(
            members(&state)
                .iter()
                .find(|s| s["session"] == second_peer)
                .unwrap()["addresses"],
            empty
        );
        first
            .wait(|s| notice(s, "session_update_response", |_| true).is_some())
            .await;

        second.control.send(json!({"type":"session_addresses","request":1,"session":second_id,"add":addresses(2)})).await;
        second.result(1, "accepted").await;
        radio
            .wait(|s| has_addresses(s, &second_peer, &addresses(2)))
            .await;
        first.control.send(json!({"type":"session_addresses","request":3,"session":first_id,"remove":addresses(1),"add":addresses(3)})).await;
        first.result(3, "accepted").await;
        let state = radio
            .wait(|s| has_addresses(s, &first_peer, &addresses(3)))
            .await;
        assert_eq!(
            members(&state)
                .iter()
                .find(|s| s["session"] == second_peer)
                .unwrap()["addresses"],
            addresses(2)
        );
        first
            .wait(|s| {
                s["notices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|n| n["type"] == "session_update_response")
                    .count()
                    == 2
            })
            .await;
        first.control.send(json!({"type":"session_addresses","request":4,"session":first_id,"remove":addresses(3)})).await;
        first.result(4, "accepted").await;
        let cleared = radio.wait(|s| has_addresses(s, &first_peer, &empty)).await;
        let count = cleared["notices"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["type"] == "session_sync")
            .count();
        radio.control.send(json!({"type":"resync"})).await;
        let refreshed = radio
            .wait(|s| {
                s["notices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|n| n["type"] == "session_sync")
                    .count()
                    > count
            })
            .await;
        assert_eq!(members(&refreshed), members(&cleared));
        assert!(notice(&refreshed, "event_gap", |_| true).is_none());
        assert_eq!(
            refreshed["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] == "session_up")
                .count(),
            2
        );
        let state = first.control.call(json!({"op":"status"})).await;
        assert!(destination(&state, "modem-a", MAC).is_none());
        assert_eq!(session(&state, "modem-a").unwrap()["addresses"], json!([]));
        let state = second.control.call(json!({"op":"status"})).await;
        assert_eq!(
            destination(&state, "modem-a", MAC).unwrap()["metrics"]["current_data_rate_tx_bps"],
            700
        );

        first.stop().await;
        first.assert_final_empty();
        let state = radio.wait(|s| members(s).len() == 1).await;
        assert_eq!(members(&state)[0]["session"], second_peer);
        assert_eq!(members(&state)[0]["addresses"], addresses(2));
        let mut late = Node::router(&[addr]).await;
        late.wait(|s| destination(s, "modem-a", MAC).is_some())
            .await;
        let state = radio.wait(|s| members(s).len() == 2).await;
        let fresh = members(&state)
            .iter()
            .find(|s| s["session"] != second_peer)
            .unwrap();
        assert_ne!(fresh["session"], first_peer);
        assert_eq!(fresh["addresses"], empty);
        second.stop().await;
        second.assert_final_empty();
        late.stop().await;
        late.assert_final_empty();
        radio.wait(|s| members(s).is_empty()).await;
        radio.stop().await;
    }
}

#[tokio::test]
async fn radio_resync_refreshes_membership_without_replaying_existing_sessions() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        report(&mut radio, OTHER_MAC, 800, 2).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some()
                    && destination(s, "modem-a", OTHER_MAC).is_some()
            })
            .await;
        let sid = session(&initial, "modem-a").unwrap()["session"].clone();
        router
            .control
            .send(json!({"type":"destination_down", "request":1,
            "session":sid, "mac":OTHER_MAC}))
            .await;
        router.result(1, "accepted").await;
        router
            .wait(|s| destination(s, "modem-a", OTHER_MAC).is_none())
            .await;
        router
            .control
            .send(json!({"type":"link_request", "request":2,
            "session":sid, "mac":MAC, "requested":{"current_data_rate_tx_bps":444}}))
            .await;
        router.result(2, "accepted").await;
        let before = radio
            .wait(|s| notice(s, "link_request", |_| true).is_some())
            .await;
        let members = notice(&before, "session_sync", |n| {
            !n["sessions"].as_array().unwrap().is_empty()
        })
        .unwrap()["sessions"]
            .clone();
        let sync_count = |s: &Value| {
            s["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] == "session_sync")
                .count()
        };
        let count = sync_count(&before);
        radio.control.batch(vec![json!({"type":"resync"}); 3]).await;
        let refreshed = radio.wait(|s| sync_count(s) == count + 3).await;
        for record in refreshed["notices"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["type"] == "session_sync")
            .skip(count)
        {
            assert_eq!(record, &json!({"type":"session_sync", "sessions":members}));
        }
        assert!(notice(&refreshed, "event_gap", |_| true).is_none());
        assert_eq!(
            refreshed["notices"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|n| n["type"] == "session_up")
                .count(),
            1
        );
        respond(&mut radio, json!({"current_data_rate_tx_bps":444}), true).await;
        let granted = router
            .wait(|s| {
                destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
            })
            .await;
        assert!(destination(&granted, "modem-a", OTHER_MAC).is_none());

        // A refresh after the grant must not reset the session's metrics or
        // reintroduce the withdrawn destination. A later router still replays both.
        radio.control.send(json!({"type":"resync"})).await;
        radio.wait(|s| sync_count(s) == count + 4).await;
        let mut late = Node::router(&[addr]).await;
        let replay = late
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some()
                    && destination(s, "modem-a", OTHER_MAC).is_some()
            })
            .await;
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["metrics"]["current_data_rate_tx_bps"],
            444
        );
        assert_eq!(
            destination(&replay, "modem-a", OTHER_MAC).unwrap()["addresses"],
            expected_addresses(2)
        );
        let current = router.control.call(json!({"op":"status"})).await;
        assert_eq!(current["state"], granted["state"]);
        router.stop().await;
        router.assert_final_empty();
        late.stop().await;
        late.assert_final_empty();
        let empty = radio
            .wait(|s| {
                s["notices"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|n| n["type"] == "session_sync")
                    .is_some_and(|n| n["sessions"] == json!([]))
            })
            .await;
        let count = sync_count(&empty);
        radio.control.send(json!({"type":"resync"})).await;
        let empty = radio.wait(|s| sync_count(s) == count + 1).await;
        assert_eq!(
            empty["notices"]
                .as_array()
                .unwrap()
                .iter()
                .rev()
                .find(|n| n["type"] == "session_sync")
                .unwrap(),
            &json!({"type":"session_sync", "sessions":[]})
        );
        radio.stop().await;
    }
}

#[tokio::test]
async fn paused_radio_reports_event_loss_and_resyncs_without_replaying_withdrawals() {
    for ip in ["127.0.0.1", "::1"] {
        let (mut radio, addr) = Node::modem("modem-a", ip, 0).await;
        report(&mut radio, MAC, 700, 1).await;
        report(&mut radio, OTHER_MAC, 800, 2).await;
        let mut router = Node::router(&[addr]).await;
        let initial = router
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some()
                    && destination(s, "modem-a", OTHER_MAC).is_some()
            })
            .await;
        let sid = session(&initial, "modem-a").unwrap()["session"].clone();
        router
            .control
            .send(json!({"type":"destination_down", "request":1,
            "session":sid, "mac":OTHER_MAC}))
            .await;
        router.result(1, "accepted").await;
        router
            .wait(|s| destination(s, "modem-a", OTHER_MAC).is_none())
            .await;
        let before = radio
            .wait(|s| notice(s, "destination_withdrawn", |_| true).is_some())
            .await;
        let members = notice(&before, "session_sync", |n| {
            !n["sessions"].as_array().unwrap().is_empty()
        })
        .unwrap()["sessions"]
            .clone();

        radio.control.call(json!({"op":"pause"})).await;
        // Overflow the real broadcast behind the blocked radio output. Each
        // peer response proves the modem processed the corresponding request.
        let mut requests = announcements(&sid, 768);
        for request in &mut requests {
            request["request"] = json!(request["request"].as_u64().unwrap() + 1);
        }
        router.control.batch(requests).await;
        router.result(769, "accepted").await;
        // The router can lose intermediate notices too. The final reply on
        // this ordered TCP stream proves the entire burst reached the modem.
        router
            .wait(|s| notice(s, "announce_response", |n| n["mac"] == "02:00:00:01:03:00").is_some())
            .await;
        router
            .control
            .send(json!({"type":"link_request", "request":770,
            "session":sid, "mac":MAC, "requested":{"current_data_rate_tx_bps":444}}))
            .await;
        router.result(770, "accepted").await;
        radio.control.call(json!({"op":"resume"})).await;
        respond(&mut radio, json!({"current_data_rate_tx_bps":444}), true).await;
        let live = router
            .wait(|s| {
                destination(s, "modem-a", MAC)
                    .is_some_and(|d| d["metrics"]["current_data_rate_tx_bps"] == 444)
            })
            .await;
        assert_eq!(session(&live, "modem-a").unwrap()["session"], sid);
        assert!(destination(&live, "modem-a", OTHER_MAC).is_none());

        let recovered = radio
            .wait(|s| {
                let notices = s["notices"].as_array().unwrap();
                notices
                    .windows(2)
                    .any(|pair| pair[0]["type"] == "event_gap" && pair[1]["type"] == "session_sync")
            })
            .await;
        let notices = recovered["notices"].as_array().unwrap();
        let pair = notices
            .windows(2)
            .find(|pair| pair[0]["type"] == "event_gap")
            .unwrap();
        assert!(pair[0]["skipped"].as_u64().unwrap() > 0);
        assert_eq!(pair[1], json!({"type":"session_sync", "sessions":members}));
        assert!(
            notices
                .iter()
                .filter(|n| n["type"] == "destination_announced")
                .count()
                < 768
        );

        // Recovery preserves physical knowledge after a router withdraws
        // interest and caches the link grant for later replay.
        let mut late = Node::router(&[addr]).await;
        let replay = late
            .wait(|s| {
                destination(s, "modem-a", MAC).is_some()
                    && destination(s, "modem-a", OTHER_MAC).is_some()
            })
            .await;
        assert_eq!(
            destination(&replay, "modem-a", MAC).unwrap()["metrics"]["current_data_rate_tx_bps"],
            444
        );
        assert_eq!(
            destination(&replay, "modem-a", OTHER_MAC).unwrap()["addresses"],
            expected_addresses(2)
        );
        let unchanged = router.control.call(json!({"op":"status"})).await;
        assert!(destination(&unchanged, "modem-a", OTHER_MAC).is_none());
        router.stop().await;
        router.assert_final_empty();
        late.stop().await;
        late.assert_final_empty();
        radio.stop().await;
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
