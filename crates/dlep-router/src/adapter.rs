//! External router integration over JSON Lines. Retained state is streamed as
//! atomic replacement snapshots; transient protocol replies remain separate.

use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dlep_core::MacAddress;
use dlep_daemon::{
    AddressChanges, CommandError, DaemonError, DaemonEvent, DaemonSnapshot, DestinationAddrs,
    DestinationEvent, DestinationPhase, LinkCharacteristics, LinkMetrics, RouterAdapterConfig,
    RouterDaemon, SessionPhase,
};
use dlep_ext::SessionId;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;

const MAX_LINE: usize = 64 * 1024;
const QUEUE_SIZE: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_GRACE: Duration = Duration::from_secs(2);

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

fn mac(text: &str) -> Result<MacAddress> {
    let bytes = text
        .split(':')
        .map(|part| {
            if !(1..=2).contains(&part.len()) {
                bail!("invalid MAC address");
            }
            Ok(u8::from_str_radix(part, 16)?)
        })
        .collect::<Result<Vec<_>>>()?;
    match bytes.len() {
        6 => Ok(MacAddress::new_eui48(bytes.try_into().unwrap())),
        8 => Ok(MacAddress::new_eui64(bytes.try_into().unwrap())),
        _ => bail!("MAC address needs six or eight octets"),
    }
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

async fn write_line(writer: &mut (impl AsyncWrite + Unpin), value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    tokio::time::timeout(IO_TIMEOUT, writer.write_all(&bytes))
        .await
        .context("router adapter stopped reading its input")??;
    Ok(())
}

async fn write_addresses(
    writer: &mut (impl AsyncWrite + Unpin),
    session: u64,
    mac: Option<String>,
    addresses: &DestinationAddrs,
) -> Result<()> {
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
) -> Result<()> {
    write_line(
        writer,
        &json!({"type":"snapshot_begin", "version":1, "generation":snapshot.generation}),
    )
    .await?;
    let mut sessions: Vec<_> = snapshot.sessions.iter().collect();
    sessions.sort_by_key(|(id, _)| id.0);
    for (id, session) in sessions {
        let phase = match session.phase {
            SessionPhase::Established => "established",
            SessionPhase::Terminating => "terminating",
        };
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
            let phase = match state.phase {
                DestinationPhase::PendingUp => "pending_up",
                DestinationPhase::Up => "up",
                DestinationPhase::Withdrawn => "withdrawn",
                DestinationPhase::PendingDown => "pending_down",
            };
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
) -> Result<()> {
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

fn rejection(reason: CommandError) -> &'static str {
    match reason {
        CommandError::Busy => "busy",
        CommandError::NotReady => "not_ready",
        CommandError::UnknownDestination => "unknown_destination",
        CommandError::AlreadyExists => "already_exists",
        CommandError::Unsupported => "unsupported",
        CommandError::InvalidInput => "invalid_input",
        CommandError::NoPendingRequest => "no_pending_request",
        CommandError::MacAddressFormatMismatch => "mac_format_mismatch",
    }
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
            let Ok(mac) = mac(&address) else {
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
            let Ok(mac) = mac(&address) else {
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
                command_result(request, "rejected", rejection(rejected.reason))
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

async fn read_lines(
    mut stdout: impl tokio::io::AsyncBufRead + Unpin,
    lines: mpsc::Sender<Result<String>>,
) {
    loop {
        let mut bytes = Vec::new();
        let read = (&mut stdout)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut bytes)
            .await;
        let result = match read {
            Ok(0) => return,
            Ok(_) if bytes.last() != Some(&b'\n') && bytes.len() > MAX_LINE => {
                Err(anyhow!("router adapter line exceeds {MAX_LINE} bytes"))
            }
            Ok(_) => {
                if bytes.last() == Some(&b'\n') {
                    bytes.pop();
                }
                String::from_utf8(bytes).context("router adapter output is not UTF-8")
            }
            Err(error) => Err(error.into()),
        };
        let failed = result.is_err();
        if lines.send(result).await.is_err() || failed {
            return;
        }
    }
}

pub(crate) struct Adapter {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<Result<String>>,
    reader: JoinHandle<()>,
    writer: Option<JoinHandle<Result<()>>>,
    out: Option<mpsc::Sender<Output>>,
}

impl Adapter {
    pub(crate) fn spawn(config: &RouterAdapterConfig) -> Result<Self> {
        config.validate().map_err(|e| anyhow!(e))?;
        let mut command = Command::new(&config.command);
        command
            .args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        drop_ambient_capabilities(&mut command);
        let mut child = command
            .spawn()
            .with_context(|| format!("starting router adapter {}", config.command.display()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, lines) = mpsc::channel(QUEUE_SIZE);
        let reader = tokio::spawn(read_lines(BufReader::new(stdout), tx));
        Ok(Self {
            child,
            stdin,
            lines,
            reader,
            writer: None,
            out: None,
        })
    }

    pub(crate) async fn run(&mut self, daemon: &RouterDaemon) -> Result<()> {
        let (out, messages) = mpsc::channel(QUEUE_SIZE);
        self.writer = Some(tokio::spawn(write_output(
            self.stdin.take().expect("run once"),
            daemon.state(),
            messages,
        )));
        self.out = Some(out.clone());
        let mut events = daemon.subscribe();
        let mut last_request = 0;
        loop {
            tokio::select! {
                status = self.child.wait() => bail!("router adapter exited with {}", status.context("waiting for router adapter")?),
                result = self.writer.as_mut().expect("writer active") => {
                    self.writer.take();
                    result.context("router adapter writer task failed")??;
                    bail!("router adapter input closed");
                }
                line = self.lines.recv() => {
                    let line = line.context("router adapter closed its output")??;
                    if line.trim().is_empty() { continue; }
                    let message = parse(&line).context("invalid router adapter message")?;
                    let message = match message {
                        Inbound::Unknown => continue,
                        Inbound::Resync => Output::Resync,
                        command => Output::Notice(execute(daemon, command, &mut last_request).await),
                    };
                    out.send(message).await.context("router adapter writer stopped")?;
                }
                event = events.recv() => match event {
                    Ok(event) => if let Some(value) = notice(event) {
                        out.send(Output::Notice(value)).await.context("router adapter writer stopped")?;
                    },
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        out.send(Output::Notice(json!({"type":"event_gap", "skipped":skipped}))).await.context("router adapter writer stopped")?;
                        out.send(Output::Resync).await.context("router adapter writer stopped")?;
                    }
                    Err(broadcast::error::RecvError::Closed) => bail!("router daemon stopped"),
                }
            }
        }
    }

    pub(crate) async fn stop(mut self) {
        let deadline = tokio::time::Instant::now() + STOP_GRACE;
        self.out.take();
        self.stdin.take();
        if let Some(mut writer) = self.writer.take() {
            if tokio::time::timeout_at(deadline, &mut writer)
                .await
                .is_err()
            {
                writer.abort();
                let _ = writer.await;
            }
        }
        if tokio::time::timeout_at(deadline, self.child.wait())
            .await
            .is_err()
        {
            tracing::warn!("router adapter did not exit after input EOF; killing it");
            let _ = self.child.kill().await;
        }
        self.reader.abort();
        let _ = (&mut self.reader).await;
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.reader.abort();
        if let Some(writer) = &self.writer {
            writer.abort();
        }
        // Child::kill_on_drop also covers failures during daemon startup.
    }
}

#[cfg(target_os = "linux")]
fn drop_ambient_capabilities(command: &mut Command) {
    use nix::libc;
    // SAFETY: only an async-signal-safe syscall and errno access after fork.
    unsafe {
        command.pre_exec(|| {
            let result = libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            let error = std::io::Error::last_os_error();
            if result == -1 && error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_ambient_capabilities(_command: &mut Command) {}

#[cfg(test)]
mod tests;
