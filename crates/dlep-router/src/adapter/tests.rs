use super::*;
use dlep_daemon::{DestinationSnapshot, PeerInfo, SessionSnapshot};
use std::collections::HashMap;
use std::sync::Arc;

fn fixture(generation: u64) -> DaemonSnapshot {
    let session = SessionSnapshot {
        peer: PeerInfo {
            addr: "[::1]:854".parse().unwrap(),
            is_tls: true,
            peer_description: Some("test modem".into()),
        },
        negotiated_extensions: vec![dlep_core::ExtensionId(0xf000)],
        phase: SessionPhase::Established,
        metrics: LinkMetrics {
            mtu: Some(1500),
            resources: Some(0),
            ..Default::default()
        },
        peer_addresses: DestinationAddrs {
            v4: vec!["192.0.2.1".parse().unwrap()],
            ..Default::default()
        },
        destinations: HashMap::from([(
            mac("02:00:00:00:00:01").unwrap().into(),
            DestinationSnapshot {
                phase: DestinationPhase::PendingDown,
                metrics: LinkMetrics {
                    current_data_rate_tx_bps: generation,
                    ..Default::default()
                },
                addresses: DestinationAddrs {
                    v4: vec!["192.0.2.2".parse().unwrap()],
                    v6: vec!["2001:db8::2".parse().unwrap()],
                    v4_subnets: vec!["198.51.100.0/24".parse().unwrap()],
                    v6_subnets: vec!["2001:db8:1::/64".parse().unwrap()],
                },
            },
        )]),
    };
    DaemonSnapshot {
        generation,
        sessions: HashMap::from([(SessionId(1), Arc::new(session))]),
    }
}

#[test]
fn parses_commands_strictly_and_leaves_unknown_messages_forward_compatible() {
    for line in [
        r#"{"type":"resync","typo":true}"#,
        r#"{"type":"link_request","request":1,"session":1,"mac":"02:00:00:00:00:01","requested":{"latency":1}}"#,
        r#"{"type":"destination_down","session":1,"mac":"02:00:00:00:00:01"}"#,
        r#"{"type":3}"#,
        "[]",
        "bad json",
    ] {
        assert!(parse(line).is_err(), "{line}");
    }
    assert!(matches!(
        parse(r#"{"type":"future","anything":true}"#).unwrap(),
        Inbound::Unknown
    ));
    assert!(matches!(parse(r#"{"type":"link_request","request":1,"session":1,"mac":"02:00:00:00:00:01","requested":{"latency_us":0}}"#).unwrap(), Inbound::LinkRequest { .. }));
    assert_eq!(
        mac("02:00:00:00:00:01").unwrap().to_string(),
        "02:00:00:00:00:01"
    );
    assert!(mac("02:00:00:00:00:00:00:01").is_ok());
    assert!(mac("002:00:00:00:00:01").is_err());
    assert!(mac("02:00:00:00:00").is_err());
}

#[tokio::test]
async fn line_reader_bounds_allocations_and_rejects_invalid_utf8() {
    for (bytes, valid) in [
        ([vec![b'x'; MAX_LINE], vec![b'\n']].concat(), true),
        (vec![b'x'; MAX_LINE + 1], false),
        (vec![0xff, b'\n'], false),
        (b"last line without newline".to_vec(), true),
    ] {
        let (tx, mut rx) = mpsc::channel(2);
        read_lines(BufReader::new(bytes.as_slice()), tx).await;
        assert_eq!(rx.recv().await.unwrap().is_ok(), valid);
        assert!(rx.recv().await.is_none());
    }
}

#[tokio::test]
async fn snapshot_frames_export_complete_values_and_empty_replacement() {
    let mut output = Vec::new();
    write_snapshot(&mut output, &fixture(7)).await.unwrap();
    write_snapshot(
        &mut output,
        &DaemonSnapshot {
            generation: 8,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let records: Vec<Value> = std::str::from_utf8(&output)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(
        records[0],
        json!({"type":"snapshot_begin", "version":1, "generation":7})
    );
    let session = &records[1];
    assert_eq!(session["peer"], "[::1]:854");
    assert_eq!(session["extensions"], json!([61440]));
    assert_eq!(session["metrics"]["resources"], 0);
    assert_eq!(session["metrics"]["mtu"], 1500);
    assert!(session["metrics"].get("rlq_rx").is_none());
    let destination = records.iter().find(|r| r["type"] == "destination").unwrap();
    assert_eq!(destination["metrics"]["current_data_rate_tx_bps"], 7);
    assert_eq!(destination["phase"], "pending_down");
    let addresses: Vec<_> = records.iter().filter(|r| r["type"] == "address").collect();
    assert_eq!(addresses.len(), 5);
    assert!(addresses[0]["mac"].is_null());
    assert!(
        addresses[1..]
            .iter()
            .all(|r| r["mac"] == destination["mac"])
    );
    assert_eq!(
        records[records.len() - 2],
        json!({"type":"snapshot_begin", "version":1, "generation":8})
    );
    assert_eq!(
        records.last().unwrap(),
        &json!({"type":"snapshot_end", "generation":8})
    );
}

#[tokio::test]
async fn session_update_notices_preserve_status_text_between_complete_snapshots() {
    let (_state_tx, state) = watch::channel(fixture(1));
    let (out, input) = mpsc::channel(2);
    let (writer, reader) = tokio::io::duplex(128);
    let task = tokio::spawn(write_output(writer, state, input));
    let text = "peer: dostęp ✓\n\"status\"";
    for status in [
        dlep_core::StatusCode::REQUEST_DENIED,
        dlep_core::StatusCode(42),
    ] {
        let value = notice(DaemonEvent::SessionUpdateResponse {
            session_id: SessionId(1),
            peer: fixture(1).sessions[&SessionId(1)].peer.clone(),
            status,
            text: text.into(),
        })
        .unwrap();
        out.send(Output::Notice(value)).await.unwrap();
    }
    drop(out);
    let mut lines = BufReader::new(reader).lines();
    let mut snapshot_open = false;
    let mut replies = Vec::new();
    while let Some(line) = lines.next_line().await.unwrap() {
        let value: Value = serde_json::from_str(&line).unwrap();
        match value["type"].as_str().unwrap() {
            "snapshot_begin" => {
                assert!(!snapshot_open);
                snapshot_open = true;
            }
            "snapshot_end" => {
                assert!(snapshot_open);
                snapshot_open = false;
            }
            "session_update_response" => {
                assert!(!snapshot_open);
                replies.push(value);
            }
            _ => assert!(snapshot_open),
        }
    }
    task.await.unwrap().unwrap();
    assert!(!snapshot_open);
    assert_eq!(
        replies,
        vec![
            json!({"type":"session_update_response", "session":1, "status":2, "text":text}),
            json!({"type":"session_update_response", "session":1, "status":42, "text":text}),
        ]
    );
}

#[tokio::test]
async fn slow_writer_coalesces_state_and_resync_repeats_current_generation() {
    let (state_tx, state) = watch::channel(fixture(1));
    let (tx, rx) = mpsc::channel(2);
    let (writer, reader) = tokio::io::duplex(128);
    let task = tokio::spawn(write_output(writer, state, rx));
    let mut lines = BufReader::new(reader).lines();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(first["generation"], 1);
    for generation in 2..=50 {
        state_tx.send_replace(fixture(generation));
    }
    let mut generations = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let value: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            if value["type"] == "snapshot_end" {
                generations.push(value["generation"].as_u64().unwrap());
                if value["generation"] == 50 {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(generations, vec![1, 50]);
    tx.send(Output::Resync).await.unwrap();
    let first: Value = serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(
        first,
        json!({"type":"snapshot_begin", "version":1, "generation":50})
    );
    drop(tx);
    while lines.next_line().await.unwrap().is_some() {}
    task.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn stopped_reader_has_a_bounded_write_deadline() {
    let (_state_tx, state) = watch::channel(fixture(1));
    let (_tx, rx) = mpsc::channel(2);
    let (writer, _reader) = tokio::io::duplex(1);
    let error = write_output(writer, state, rx).await.unwrap_err();
    assert!(error.to_string().contains("stopped reading"));
}

async fn wait_state(
    daemon: &RouterDaemon,
    ready: impl Fn(&DaemonSnapshot) -> bool,
) -> DaemonSnapshot {
    let mut state = daemon.state();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let snapshot = state.borrow_and_update().clone();
            if ready(&snapshot) {
                return snapshot;
            }
            state.changed().await.unwrap();
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn commands_target_one_session_and_distinguish_acceptance_busy_and_stale_ids() {
    use dlep_daemon::{LinkRequest, LinkResponse, ModemConfig, ModemDaemon, RouterConfig};
    let release = Arc::new(tokio::sync::Notify::new());
    let mut config = ModemConfig::default();
    config.shared.network.use_tls = false;
    config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
    config.metrics.max_data_rate_tx_bps = 1000;
    let gate = release.clone();
    let a = ModemDaemon::builder()
        .config(config.clone())
        .link_control(Arc::new(move |r: LinkRequest| {
            let gate = gate.clone();
            async move {
                gate.notified().await;
                LinkResponse::granted(LinkMetrics {
                    current_data_rate_tx_bps: 333,
                    ..r.current
                })
            }
        }))
        .spawn()
        .await
        .unwrap();
    let b = ModemDaemon::builder().config(config).spawn().await.unwrap();
    let mut config = RouterConfig::default();
    config.shared.network.use_tls = false;
    let router = RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .unwrap();
    router.connect_static(a.local_addr()).await.unwrap();
    router.connect_static(b.local_addr()).await.unwrap();
    let snapshot = wait_state(&router, |s| s.sessions.len() == 2).await;
    let aid = *snapshot
        .sessions
        .iter()
        .find(|(_, s)| s.peer.addr == a.local_addr())
        .unwrap()
        .0;
    let bid = *snapshot
        .sessions
        .iter()
        .find(|(_, s)| s.peer.addr == b.local_addr())
        .unwrap()
        .0;
    let address = "02:00:00:00:00:01";
    let id = mac(address).unwrap().into();
    for modem in [&a, &b] {
        modem
            .add_destination(
                id,
                LinkMetrics {
                    max_data_rate_tx_bps: 1000,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    wait_state(&router, |s| {
        s.sessions
            .values()
            .all(|s| s.destinations.contains_key(&id))
    })
    .await;
    let mut last = 0;
    let mut events = router.subscribe();
    let link = |request| Inbound::LinkRequest {
        request,
        session: aid.0,
        mac: address.into(),
        requested: Requested {
            current_data_rate_tx_bps: Some(333),
            current_data_rate_rx_bps: None,
            latency_us: None,
        },
    };
    assert_eq!(
        execute(&router, link(1), &mut last).await["outcome"],
        "accepted"
    );
    assert_eq!(
        execute(&router, link(1), &mut last).await["code"],
        "request_id_not_increasing"
    );
    assert_eq!(
        execute(
            &router,
            Inbound::DestinationDown {
                request: 2,
                session: aid.0,
                mac: address.into()
            },
            &mut last
        )
        .await["code"],
        "busy"
    );
    assert_eq!(
        execute(
            &router,
            Inbound::DestinationDown {
                request: 3,
                session: u64::MAX,
                mac: address.into()
            },
            &mut last
        )
        .await["code"],
        "stale_session"
    );
    let empty = Inbound::LinkRequest {
        request: 4,
        session: aid.0,
        mac: address.into(),
        requested: Requested {
            current_data_rate_tx_bps: None,
            current_data_rate_rx_bps: None,
            latency_us: None,
        },
    };
    assert_eq!(
        execute(&router, empty, &mut last).await["code"],
        "invalid_input"
    );
    release.notify_one();
    let snapshot = wait_state(&router, |s| {
        s.sessions[&aid].destinations[&id]
            .metrics
            .current_data_rate_tx_bps
            == 333
    })
    .await;
    assert_eq!(
        snapshot.sessions[&bid].destinations[&id]
            .metrics
            .current_data_rate_tx_bps,
        0
    );
    let response = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(value) = notice(events.recv().await.unwrap()) {
                if value["type"] == "link_response" {
                    break value;
                }
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(response["session"], aid.0);
    assert_eq!(response["metrics"]["current_data_rate_tx_bps"], 333);
    assert_eq!(
        execute(
            &router,
            Inbound::DestinationDown {
                request: 5,
                session: aid.0,
                mac: address.into()
            },
            &mut last
        )
        .await["outcome"],
        "accepted"
    );
    wait_state(&router, |s| {
        !s.sessions[&aid].destinations.contains_key(&id)
    })
    .await;
    assert_eq!(
        execute(
            &router,
            Inbound::DestinationAnnounce {
                request: 6,
                session: aid.0,
                mac: address.into()
            },
            &mut last
        )
        .await["outcome"],
        "accepted"
    );
    let snapshot = wait_state(&router, |s| s.sessions[&aid].destinations.contains_key(&id)).await;
    assert_eq!(
        snapshot.sessions[&aid].destinations[&id]
            .metrics
            .current_data_rate_tx_bps,
        333
    );
    router.shutdown().await.unwrap();
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}
