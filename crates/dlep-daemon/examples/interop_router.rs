//! Router fixture for the pinned MIT LL-DLEP interoperability scenarios.
use dlep_core::MacAddress;
use dlep_daemon::{
    AddressChanges, DaemonEvent, DestinationAddrs, DestinationEvent, DestinationId,
    LinkCharacteristics, LinkMetrics, RouterConfig, RouterDaemon,
};
use std::io::{BufRead, Write};
use std::time::Duration;

fn report(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

fn metrics(kind: &str, value: LinkMetrics) {
    report(&format!(
        "{kind} {} {} {} {} {}",
        value.max_data_rate_rx_bps,
        value.max_data_rate_tx_bps,
        value.current_data_rate_rx_bps,
        value.current_data_rate_tx_bps,
        value.latency.as_micros(),
    ));
}

fn addresses(kind: &str, value: &DestinationAddrs) {
    fn list<T: ToString>(values: &[T]) -> String {
        if values.is_empty() {
            "-".into()
        } else {
            values
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        }
    }
    report(&format!(
        "{kind} {} {} {} {}",
        list(&value.v4),
        list(&value.v6),
        list(&value.v4_subnets),
        list(&value.v6_subnets)
    ));
}

fn address_set(n: u8) -> DestinationAddrs {
    DestinationAddrs {
        v4: vec![format!("192.0.2.{n}").parse().unwrap()],
        v6: vec![format!("2001:db8::{n}").parse().unwrap()],
        v4_subnets: vec![format!("198.51.{n}.0/24").parse().unwrap()],
        v6_subnets: vec![format!("2001:db8:{n}::/64").parse().unwrap()],
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args()
        .nth(1)
        .ok_or("missing modem endpoint")?
        .parse()?;
    let mut config = RouterConfig::default();
    config.shared.network.use_tls = false;
    config.shared.timers.heartbeat_interval_ms = 1_000;
    config.shared.timers.termination_timeout_ms = Some(2_000);
    let router = RouterDaemon::builder().config(config).spawn().await?;
    let mut events = router.subscribe();
    let (up_tx, up_rx) = tokio::sync::oneshot::channel();
    let destination = DestinationId(MacAddress::new_eui48([2, 0, 0, 0, 0, 1]));
    let unknown = DestinationId(MacAddress::new_eui48([2, 0, 0, 0, 0, 2]));
    let event_task = tokio::spawn(async move {
        let mut up_tx = Some(up_tx);
        while let Ok(event) = events.recv().await {
            match event {
                DaemonEvent::SessionUp { session_id, .. } => {
                    up_tx.take().expect("one session").send(session_id).unwrap();
                    report("UP");
                }
                DaemonEvent::SessionDown { reason, .. } => report(&format!("DOWN {}", reason.0)),
                DaemonEvent::Metrics { event, .. } => metrics("METRICS", event.session_wide),
                DaemonEvent::SessionAddresses {
                    addresses: value, ..
                } => addresses("PEER_ADDR", &value),
                DaemonEvent::SessionUpdateResponse { status, .. } => {
                    report(&format!("SESSION_STATUS {}", status.0))
                }
                DaemonEvent::CommandRejected { rejection, .. } => panic!("{rejection:?}"),
                DaemonEvent::Destination { event, .. } => match event {
                    DestinationEvent::Up {
                        id, metrics: value, ..
                    } => {
                        assert_eq!(id, destination);
                        metrics("DEST_UP", value);
                    }
                    DestinationEvent::Update { id, metrics: value } => {
                        assert_eq!(id, destination);
                        metrics("DEST_UPDATE", value);
                    }
                    DestinationEvent::Down { id, .. } => {
                        assert_eq!(id, destination);
                        report("DEST_DOWN");
                    }
                    DestinationEvent::AddressesChanged {
                        id,
                        addresses: value,
                        ..
                    } => {
                        assert_eq!(id, destination);
                        addresses("DEST_ADDR", &value);
                    }
                    DestinationEvent::AnnounceResponse { id, status, .. } => {
                        report(&format!("ANNOUNCE {} {}", id.0, status.0));
                    }
                    DestinationEvent::DownResponse { id, status, .. } => {
                        report(&format!("WITHDRAW {} {}", id.0, status.0));
                    }
                    DestinationEvent::LinkCharacteristicsResponse {
                        id,
                        status,
                        metrics: value,
                        ..
                    } => {
                        assert_eq!(id, destination);
                        report(&format!("LINK_STATUS {}", status.0));
                        metrics("LINK_METRICS", value);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    });
    router.connect_static(endpoint).await?;
    let session_id = tokio::time::timeout(Duration::from_secs(10), up_rx).await??;
    let (tx, mut commands) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if tx.send(line.expect("stdin command")).is_err() {
                break;
            }
        }
    });
    while let Some(command) = commands.recv().await {
        match command.as_str() {
            "link" => {
                router
                    .request_link_characteristics(
                        session_id,
                        destination,
                        LinkCharacteristics {
                            current_data_rate_rx_bps: Some(2_000_000),
                            current_data_rate_tx_bps: Some(3_000_000),
                            latency: Some(Duration::from_micros(4_500)),
                        },
                    )
                    .await?
            }
            "session-add" | "session-replace" | "session-clear" => {
                let changes = match command.as_str() {
                    "session-add" => AddressChanges {
                        added: address_set(40),
                        removed: Default::default(),
                    },
                    "session-replace" => AddressChanges {
                        added: address_set(41),
                        removed: address_set(40),
                    },
                    _ => AddressChanges {
                        added: Default::default(),
                        removed: address_set(41),
                    },
                };
                router.update_session_addresses(session_id, changes).await?;
            }
            "withdraw" => router.drop_destination(session_id, destination).await?,
            "announce" | "announce-denied" => {
                let mut added = address_set(30);
                let mut removed = address_set(31);
                for value in [&mut added, &mut removed] {
                    value.v4_subnets.clear();
                    value.v6_subnets.clear();
                }
                router
                    .announce_destination_with_addresses(
                        session_id,
                        if command == "announce" {
                            destination
                        } else {
                            unknown
                        },
                        AddressChanges { added, removed },
                    )
                    .await?;
            }
            "state" => {
                let state = router.state();
                let snapshot = state.borrow();
                let session = &snapshot.sessions[&session_id];
                addresses("STATE_PEER", &session.peer_addresses);
                addresses("STATE_LOCAL", &session.local_addresses);
                if let Some(destination) = session.destinations.get(&destination) {
                    addresses("STATE_DEST", &destination.addresses);
                    metrics("STATE_METRICS", destination.metrics);
                } else {
                    report("STATE_DEST absent");
                }
                assert!(!session.destinations.contains_key(&unknown));
            }
            "shutdown" => break,
            _ => return Err(format!("unknown fixture command: {command}").into()),
        }
        report(&format!("OK {command}"));
    }
    router.shutdown().await?;
    event_task.await?;
    report("STOPPED");
    Ok(())
}
