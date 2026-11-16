//! External router integration over JSON Lines. Retained state is streamed as
//! atomic replacement snapshots; transient protocol replies remain separate.

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dlep_core::MacAddress;
use dlep_daemon::adapter_process::{
    AdapterError, AdapterLines, AdapterProcess, QUEUE_SIZE, write_line as write_record,
};
use dlep_daemon::{
    AddressChanges, DaemonError, DaemonEvent, DaemonSnapshot, DestinationAddrs, DestinationEvent,
    LinkCharacteristics, LinkMetrics, RouterAdapterConfig, RouterDaemon,
};
use dlep_ext::SessionId;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::AsyncWrite;
use tokio::sync::{broadcast, mpsc, watch};

const LABEL: &str = "router adapter";
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Inbound {
    Resync,
    SessionAddresses {
        request: u64,
        session: u64,
        #[serde(default)]
        add: Addresses,
        #[serde(default)]
        remove: Addresses,
    },
    DestinationAnnounce {
        request: u64,
        session: u64,
        mac: String,
        #[serde(default)]
        add: Addresses,
        #[serde(default)]
        remove: Addresses,
    },
    DestinationDown {
        request: u64,
        session: u64,
        mac: String,
    },
    LinkRequest {
        request: u64,
        session: u64,
        mac: String,
        requested: Requested,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Addresses {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
    ipv4_subnets: Vec<String>,
    ipv6_subnets: Vec<String>,
}

impl Addresses {
    fn parse(&self) -> Result<DestinationAddrs> {
        Ok(DestinationAddrs {
            v4: self
                .ipv4
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?,
            v6: self
                .ipv6
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?,
            v4_subnets: self
                .ipv4_subnets
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?,
            v6_subnets: self
                .ipv6_subnets
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Requested {
    current_data_rate_rx_bps: Option<u64>,
    current_data_rate_tx_bps: Option<u64>,
    latency_us: Option<u64>,
}

fn parse(line: &str) -> Result<Inbound> {
    let value: Value = serde_json::from_str(line)?;
    let object = value.as_object().context("message must be an object")?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .context("message needs a string type")?;
    let fields: &[&str] = match kind {
        "resync" => &["type"],
        "session_addresses" => &["type", "request", "session", "add", "remove"],
        "destination_announce" => &["type", "request", "session", "mac", "add", "remove"],
        "destination_down" => &["type", "request", "session", "mac"],
        "link_request" => &["type", "request", "session", "mac", "requested"],
        _ => return Ok(Inbound::Unknown),
    };
    if let Some(key) = object.keys().find(|key| !fields.contains(&key.as_str())) {
        bail!("unknown field {key:?} in {kind}");
    }
    Ok(serde_json::from_value(value)?)
}

fn metrics(m: &LinkMetrics) -> Value {
    let mut value = json!({
        "max_data_rate_rx_bps": m.max_data_rate_rx_bps,
        "max_data_rate_tx_bps": m.max_data_rate_tx_bps,
        "current_data_rate_rx_bps": m.current_data_rate_rx_bps,
        "current_data_rate_tx_bps": m.current_data_rate_tx_bps,
        "latency_us": u64::try_from(m.latency.as_micros()).unwrap_or(u64::MAX),
        "resources": m.resources, "rlq_rx": m.rlq_rx, "rlq_tx": m.rlq_tx, "mtu": m.mtu,
    });
    value.as_object_mut().unwrap().retain(|_, v| !v.is_null());
    value
}

async fn write_line(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &Value,
) -> Result<(), AdapterError> {
    write_record(writer, LABEL, value.to_string()).await
}

async fn write_addresses(
    writer: &mut (impl AsyncWrite + Unpin),
    session: u64,
    mac: Option<String>,
    addresses: &DestinationAddrs,
) -> Result<(), AdapterError> {
    // Separate address records avoid a line or queued batch growing with an
    // unbounded address table. Every record belongs to the enclosing snapshot.
    let addresses = addresses
        .v4
        .iter()
        .map(|a| ("ipv4", a.to_string()))
        .chain(addresses.v6.iter().map(|a| ("ipv6", a.to_string())))
        .chain(
            addresses
                .v4_subnets
                .iter()
                .map(|a| ("ipv4_subnet", a.to_string())),
        )
        .chain(
            addresses
                .v6_subnets
                .iter()
                .map(|a| ("ipv6_subnet", a.to_string())),
        );
    for (kind, address) in addresses {
        write_line(writer, &json!({"type":"address", "session":session, "mac":mac, "kind":kind, "address":address})).await?;
    }
    Ok(())
}

async fn write_snapshot(
    writer: &mut (impl AsyncWrite + Unpin),
    snapshot: &DaemonSnapshot,
) -> Result<(), AdapterError> {
    write_line(
        writer,
        &json!({"type":"snapshot_begin", "version":1, "generation":snapshot.generation}),
    )
    .await?;
    let mut sessions: Vec<_> = snapshot.sessions.iter().collect();
    sessions.sort_by_key(|(id, _)| id.0);
    for (id, session) in sessions {
        let phase = session.phase.as_str();
        write_line(writer, &json!({
            "type":"session", "session":id.0, "peer":session.peer.addr.to_string(),
            "is_tls":session.peer.is_tls, "peer_description":session.peer.peer_description,
            "secured_medium":session.peer.secured_medium,
            "phase":phase, "extensions":session.negotiated_extensions.iter().map(|id| id.0).collect::<Vec<_>>(),
            "metrics":metrics(&session.metrics),
        })).await?;
        write_addresses(writer, id.0, None, &session.peer_addresses).await?;
        let mut destinations: Vec<_> = session.destinations.iter().collect();
        destinations.sort_by_key(|(id, _)| id.0);
        for (destination, state) in destinations {
            let phase = state.phase.as_str();
            write_line(
                writer,
                &json!({"type":"destination", "session":id.0, "mac":destination.0.to_string(),
                "phase":phase, "metrics":metrics(&state.metrics)}),
            )
            .await?;
            write_addresses(
                writer,
                id.0,
                Some(destination.0.to_string()),
                &state.addresses,
            )
            .await?;
        }
    }
    write_line(
        writer,
        &json!({"type":"snapshot_end", "generation":snapshot.generation}),
    )
    .await
}

enum Output {
    Notice(Value),
    Resync,
}

async fn write_output(
    mut stdin: impl AsyncWrite + Unpin,
    mut state: watch::Receiver<DaemonSnapshot>,
    mut messages: mpsc::Receiver<Output>,
) -> Result<(), AdapterError> {
    let initial = state.borrow_and_update().clone();
    write_snapshot(&mut stdin, &initial).await?;
    loop {
        tokio::select! {
            changed = state.changed() => {
                if changed.is_err() {
                    // Daemon shutdown removes sessions before closing its feed.
                    let final_state = state.borrow().clone();
                    write_snapshot(&mut stdin, &final_state).await?;
                    return Ok(());
                }
                let latest = state.borrow_and_update().clone();
                write_snapshot(&mut stdin, &latest).await?;
            }
            message = messages.recv() => match message {
                Some(Output::Notice(value)) => write_line(&mut stdin, &value).await?,
                Some(Output::Resync) => {
                    let latest = state.borrow_and_update().clone();
                    write_snapshot(&mut stdin, &latest).await?;
                }
                None => {
                    let latest = state.borrow().clone();
                    write_snapshot(&mut stdin, &latest).await?;
                    return Ok(());
                }
            }
        }
    }
}

fn command_result(request: u64, outcome: &str, code: &str) -> Value {
    json!({"type":"command_result", "request":request, "outcome":outcome, "code":code})
}

async fn execute(daemon: &RouterDaemon, message: Inbound, last_request: &mut u64) -> Value {
    let (request, session) = match &message {
        Inbound::SessionAddresses {
            request, session, ..
        }
        | Inbound::DestinationAnnounce {
            request, session, ..
        }
        | Inbound::DestinationDown {
            request, session, ..
        }
        | Inbound::LinkRequest {
            request, session, ..
        } => (*request, SessionId(*session)),
        _ => unreachable!("only commands are executed"),
    };
    // A single high-water mark prevents re-execution without an ever-growing
    // result/deduplication cache. Rejected requests also consume their ID.
    if request <= *last_request {
        return command_result(request, "rejected", "request_id_not_increasing");
    }
    *last_request = request;
    let result = match message {
        Inbound::SessionAddresses { add, remove, .. } => {
            let (Ok(added), Ok(removed)) = (add.parse(), remove.parse()) else {
                return command_result(request, "rejected", "invalid_input");
            };
            tokio::time::timeout(
                ACCEPT_TIMEOUT,
                daemon.update_session_addresses(session, AddressChanges { added, removed }),
            )
            .await
        }
        Inbound::DestinationAnnounce {
            mac: address,
            add,
            remove,
            ..
        } => {
            let Ok(mac) = address.parse::<MacAddress>() else {
                return command_result(request, "rejected", "invalid_mac");
            };
            let (Ok(added), Ok(removed)) = (add.parse(), remove.parse()) else {
                return command_result(request, "rejected", "invalid_input");
            };
            tokio::time::timeout(
                ACCEPT_TIMEOUT,
                daemon.announce_destination_with_addresses(
                    session,
                    mac.into(),
                    AddressChanges { added, removed },
                ),
            )
            .await
        }
        command => {
            let (address, requested) = match command {
                Inbound::DestinationDown { mac, .. } => (mac, None),
                Inbound::LinkRequest { mac, requested, .. } => (mac, Some(requested)),
                _ => unreachable!("only destination commands remain"),
            };
            let Ok(mac) = address.parse::<MacAddress>() else {
                return command_result(request, "rejected", "invalid_mac");
            };
            tokio::time::timeout(ACCEPT_TIMEOUT, async {
                if let Some(requested) = requested {
                    daemon
                        .request_link_characteristics(
                            session,
                            mac.into(),
                            LinkCharacteristics {
                                current_data_rate_rx_bps: requested.current_data_rate_rx_bps,
                                current_data_rate_tx_bps: requested.current_data_rate_tx_bps,
                                latency: requested.latency_us.map(Duration::from_micros),
                            },
                        )
                        .await
                } else {
                    daemon.drop_destination(session, mac.into()).await
                }
            })
            .await
        }
    };
    match result {
        Ok(Ok(())) => command_result(request, "accepted", "accepted"),
        Err(_) => command_result(request, "unknown", "acceptance_timeout"),
        Ok(Err(DaemonError::NoMatchingSession)) => {
            command_result(request, "rejected", "stale_session")
        }
        Ok(Err(DaemonError::CommandRejected(report))) => {
            if report.unknown > 0 || !report.accepted.is_empty() {
                command_result(request, "unknown", "receipt_lost")
            } else if let Some((_, rejected)) = report.rejected.first() {
                command_result(request, "rejected", rejected.reason.as_str())
            } else {
                command_result(request, "rejected", "session_unavailable")
            }
        }
        Ok(Err(DaemonError::Config(_) | DaemonError::Codec(_))) => {
            command_result(request, "rejected", "invalid_input")
        }
        Ok(Err(DaemonError::ShuttingDown)) => command_result(request, "rejected", "shutting_down"),
        Ok(Err(_)) => command_result(request, "unknown", "daemon_error"),
    }
}

fn notice(event: DaemonEvent) -> Option<Value> {
    match event {
        DaemonEvent::Destination {
            session_id,
            event: DestinationEvent::DownResponse { id, status, text },
            ..
        } => Some(
            json!({"type":"down_response", "session":session_id.0, "mac":id.0.to_string(), "status":status.0, "text":text}),
        ),
        DaemonEvent::SessionUpdateResponse {
            session_id,
            status,
            text,
            ..
        } => Some(
            json!({"type":"session_update_response", "session":session_id.0, "status":status.0, "text":text}),
        ),
        DaemonEvent::Destination {
            session_id,
            event: DestinationEvent::AnnounceResponse { id, status, text },
            ..
        } => Some(
            json!({"type":"announce_response", "session":session_id.0, "mac":id.0.to_string(), "status":status.0, "text":text}),
        ),
        DaemonEvent::Destination {
            session_id,
            event:
                DestinationEvent::LinkCharacteristicsResponse {
                    id,
                    status,
                    text,
                    metrics: m,
                },
            ..
        } => Some(
            json!({"type":"link_response", "session":session_id.0, "mac":id.0.to_string(), "status":status.0, "text":text, "metrics":metrics(&m)}),
        ),
        DaemonEvent::Destination {
            session_id,
            event: DestinationEvent::Down { id, reason },
            ..
        } => Some(
            json!({"type":"destination_down", "session":session_id.0, "mac":id.0.to_string(), "status":reason.0}),
        ),
        DaemonEvent::SessionDown {
            session_id,
            peer,
            reason,
        } => Some(
            json!({"type":"session_down", "session":session_id.0, "peer":peer.addr.to_string(), "status":reason.0}),
        ),
        _ => None,
    }
}

pub(crate) struct Adapter {
    process: AdapterProcess,
    lines: AdapterLines,
    out: Option<mpsc::Sender<Output>>,
}

impl Adapter {
    pub(crate) fn spawn(config: &RouterAdapterConfig) -> Result<Self> {
        config.validate().map_err(|e| anyhow!(e))?;
        let (process, lines) = AdapterProcess::spawn(LABEL, &config.command, &config.args)
            .with_context(|| format!("starting router adapter {}", config.command.display()))?;
        Ok(Self {
            process,
            lines,
            out: None,
        })
    }

    pub(crate) async fn run(&mut self, daemon: &RouterDaemon) -> Result<()> {
        let (out, messages) = mpsc::channel(QUEUE_SIZE);
        let state = daemon.state();
        self.process
            .start_writer(move |stdin| write_output(stdin, state, messages));
        self.out = Some(out.clone());
        let mut events = daemon.subscribe();
        let mut last_request = 0;
        loop {
            let message = tokio::select! {
                error = self.process.failed() => return Err(error.into()),
                line = self.lines.recv() => {
                    let line = line.ok_or(AdapterError::OutputClosed { label: LABEL })??;
                    let message = parse(&line).context("invalid router adapter message")?;
                    match message {
                        Inbound::Unknown => continue,
                        Inbound::Resync => Output::Resync,
                        command => Output::Notice(execute(daemon, command, &mut last_request).await),
                    }
                }
                event = events.recv() => match event {
                    Ok(event) => match notice(event) {
                        Some(value) => Output::Notice(value),
                        None => continue,
                    },
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        let gap = Output::Notice(json!({"type":"event_gap", "skipped":skipped}));
                        if out.send(gap).await.is_err() {
                            return Err(self.process.writer_error().await.into());
                        }
                        Output::Resync
                    }
                    Err(broadcast::error::RecvError::Closed) => bail!("router daemon stopped"),
                }
            };
            // The queue closes only when the writer task ends; report its cause.
            if out.send(message).await.is_err() {
                return Err(self.process.writer_error().await.into());
            }
        }
    }

    /// Send the final state and close the adapter's input, then kill the
    /// adapter if it does not exit promptly.
    pub(crate) async fn stop(mut self) {
        self.out.take();
        self.process.stop().await;
    }
}

#[cfg(test)]
mod tests;
