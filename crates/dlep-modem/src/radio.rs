//! External radio adapter. The modem runs one configured program and exchanges
//! JSON Lines with it: the adapter reports destinations and session metrics on
//! standard output and answers Link Characteristics Requests (RFC 8175
//! §12.18–12.19) sent to its standard input. See `doc/radio-adapter.md`.
//!
//! The adapter's destination table is kept here and replayed to every router
//! session that comes up, so destinations reported before a router connects
//! are not lost. Adapter exit, closed output, or malformed JSON is fatal: the
//! modem terminates its sessions and exits so a supervisor restarts both.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::link_control::LinkControlFuture;
use dlep_daemon::{
    AddressChanges, CommandError, DaemonError, DaemonEvent, DestinationAddrs, DestinationEvent,
    DestinationId, LinkControl, LinkMetrics, LinkRequest, LinkResponse, ModemDaemon, RadioConfig,
    SessionCommand,
};
use dlep_ext::SessionId;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Longest accepted adapter line, excluding the newline.
const MAX_LINE: usize = 64 * 1024;
/// Delay before re-sending a command a session rejected as Busy.
const RETRY_DELAY: Duration = Duration::from_millis(250);
/// Grace period for the adapter to exit after its input closes.
const STOP_GRACE: Duration = Duration::from_secs(2);

/// Destination MAC as colon-separated hex octets (EUI-48 or EUI-64).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
struct Mac(MacAddress);

impl TryFrom<String> for Mac {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let octets = text
            .split(':')
            .map(|part| match part.len() {
                1 | 2 => u8::from_str_radix(part, 16).ok(),
                _ => None,
            })
            .collect::<Option<Vec<u8>>>()
            .ok_or_else(|| format!("invalid MAC address {text:?}"))?;
        match octets.len() {
            6 => Ok(Self(MacAddress::new_eui48(octets.try_into().unwrap()))),
            8 => Ok(Self(MacAddress::new_eui64(octets.try_into().unwrap()))),
            _ => Err(format!("MAC address {text:?} must have 6 or 8 octets")),
        }
    }
}

impl From<Mac> for String {
    fn from(mac: Mac) -> Self {
        mac.0.to_string()
    }
}

/// Metric values using the `[metrics]` configuration names and units. Omitted
/// fields keep their previous value; optional metrics must be declared in the
/// modem configuration before they can be reported.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Metrics {
    #[serde(skip_serializing_if = "Option::is_none")]
    max_data_rate_rx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_data_rate_tx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_data_rate_rx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_data_rate_tx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rlq_rx: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rlq_tx: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtu: Option<u16>,
}

impl Metrics {
    fn overlay(&self, mut base: LinkMetrics) -> LinkMetrics {
        if let Some(v) = self.max_data_rate_rx_bps {
            base.max_data_rate_rx_bps = v;
        }
        if let Some(v) = self.max_data_rate_tx_bps {
            base.max_data_rate_tx_bps = v;
        }
        if let Some(v) = self.current_data_rate_rx_bps {
            base.current_data_rate_rx_bps = v;
        }
        if let Some(v) = self.current_data_rate_tx_bps {
            base.current_data_rate_tx_bps = v;
        }
        if let Some(v) = self.latency_us {
            base.latency = Duration::from_micros(v);
        }
        base.resources = self.resources.or(base.resources);
        base.rlq_rx = self.rlq_rx.or(base.rlq_rx);
        base.rlq_tx = self.rlq_tx.or(base.rlq_tx);
        base.mtu = self.mtu.or(base.mtu);
        base
    }

    fn from_link(metrics: &LinkMetrics) -> Self {
        Self {
            max_data_rate_rx_bps: Some(metrics.max_data_rate_rx_bps),
            max_data_rate_tx_bps: Some(metrics.max_data_rate_tx_bps),
            current_data_rate_rx_bps: Some(metrics.current_data_rate_rx_bps),
            current_data_rate_tx_bps: Some(metrics.current_data_rate_tx_bps),
            latency_us: Some(duration_us(metrics.latency)),
            resources: metrics.resources,
            rlq_rx: metrics.rlq_rx,
            rlq_tx: metrics.rlq_tx,
            mtu: metrics.mtu,
        }
    }
}

fn duration_us(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Requested characteristics; omitted fields are not change requests.
#[derive(Debug, Serialize)]
struct Requested {
    #[serde(skip_serializing_if = "Option::is_none")]
    current_data_rate_rx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_data_rate_tx_bps: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_us: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Addresses {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    ipv4_subnets: Vec<String>,
    ipv6_subnets: Vec<String>,
}

impl Addresses {
    fn parse(&self) -> Result<DestinationAddrs> {
        Ok(DestinationAddrs {
            v4: self.ipv4.clone(),
            v6: self.ipv6.clone(),
            v4_subnets: self
                .ipv4_subnets
                .iter()
                .map(|s| {
                    s.parse::<Ipv4Net>()
                        .with_context(|| format!("subnet {s:?}"))
                })
                .collect::<Result<_>>()?,
            v6_subnets: self
                .ipv6_subnets
                .iter()
                .map(|s| {
                    s.parse::<Ipv6Net>()
                        .with_context(|| format!("subnet {s:?}"))
                })
                .collect::<Result<_>>()?,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Success,
    Denied,
}

/// Adapter → modem. Unknown message types are ignored for forward
/// compatibility; unknown fields in known messages are errors.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Inbound {
    DestinationUp {
        mac: Mac,
        #[serde(default)]
        metrics: Metrics,
        #[serde(default)]
        addresses: Addresses,
    },
    DestinationUpdate {
        mac: Mac,
        metrics: Metrics,
    },
    DestinationAddresses {
        mac: Mac,
        #[serde(default)]
        add: Addresses,
        #[serde(default)]
        remove: Addresses,
    },
    DestinationDown {
        mac: Mac,
    },
    SessionMetrics {
        metrics: Metrics,
    },
    LinkResponse {
        request: u64,
        status: Status,
        #[serde(default)]
        text: String,
        metrics: Option<Metrics>,
    },
    #[serde(other)]
    Unknown,
}

const INBOUND_FIELDS: &[(&str, &[&str])] = &[
    ("destination_up", &["mac", "metrics", "addresses"]),
    ("destination_update", &["mac", "metrics"]),
    ("destination_addresses", &["mac", "add", "remove"]),
    ("destination_down", &["mac"]),
    ("session_metrics", &["metrics"]),
    ("link_response", &["request", "status", "text", "metrics"]),
];

/// Parse one adapter line. Serde cannot deny unknown fields on an internally
/// tagged enum, so known message types check their field names here.
fn parse_inbound(line: &str) -> Result<Inbound> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("message must be a JSON object"))?;
    let kind = object
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("message needs a string \"type\""))?;
    if let Some((_, fields)) = INBOUND_FIELDS.iter().find(|(name, _)| *name == kind) {
        if let Some(unknown) = object
            .keys()
            .find(|key| *key != "type" && !fields.contains(&key.as_str()))
        {
            bail!("unknown field {unknown:?} in {kind} message");
        }
    }
    Ok(serde_json::from_value(value)?)
}

/// Modem → adapter.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Outbound {
    SessionUp {
        session: u64,
        peer: SocketAddr,
    },
    SessionDown {
        session: u64,
        peer: SocketAddr,
        status: u8,
    },
    DestinationAnnounced {
        session: u64,
        mac: Mac,
    },
    LinkRequest {
        request: u64,
        session: u64,
        peer: SocketAddr,
        mac: Mac,
        requested: Requested,
        current: Metrics,
    },
}

type Ask = (LinkRequest, oneshot::Sender<LinkResponse>);

/// Forwards link requests to the bridge task and bounds the adapter's answer.
struct RadioLink {
    asks: mpsc::UnboundedSender<Ask>,
    timeout: Duration,
}

impl LinkControl for RadioLink {
    fn request(&self, request: LinkRequest) -> LinkControlFuture {
        let (answer, response) = oneshot::channel();
        let sent = self.asks.send((request, answer)).is_ok();
        let timeout = self.timeout;
        Box::pin(async move {
            if !sent {
                return LinkResponse::denied().with_text("radio adapter unavailable");
            }
            match tokio::time::timeout(timeout, response).await {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => LinkResponse::denied().with_text("radio adapter unavailable"),
                Err(_) => {
                    warn!("radio adapter did not answer a link request in time");
                    LinkResponse::denied().with_text("radio adapter timed out")
                }
            }
        })
    }
}

/// A running adapter process and its I/O tasks.
pub(crate) struct Adapter {
    child: Child,
    lines: mpsc::Receiver<Result<String>>,
    out: mpsc::UnboundedSender<String>,
    writer: JoinHandle<()>,
    reader: JoinHandle<()>,
    asks: mpsc::UnboundedReceiver<Ask>,
    link: Arc<RadioLink>,
}

impl Adapter {
    /// Start the adapter. Its standard error is inherited for logging.
    pub(crate) fn spawn(config: &RadioConfig) -> Result<Self> {
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
            .with_context(|| format!("starting radio adapter {}", config.command.display()))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        // A separate writer keeps an adapter that is slow to read its input
        // from stalling destination reports.
        let (out, mut queued) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(mut line) = queued.recv().await {
                line.push('\n');
                if let Err(e) = stdin.write_all(line.as_bytes()).await {
                    warn!("writing to radio adapter failed: {e}");
                    break;
                }
            }
        });
        let (lines_tx, lines) = mpsc::channel(64);
        let reader = tokio::spawn(read_lines(BufReader::new(stdout), lines_tx));

        let (asks_tx, asks) = mpsc::unbounded_channel();
        Ok(Self {
            child,
            lines,
            out,
            writer,
            reader,
            asks,
            link: Arc::new(RadioLink {
                asks: asks_tx,
                timeout: Duration::from_millis(config.link_request_timeout_ms.into()),
            }),
        })
    }

    pub(crate) fn link_control(&self) -> Arc<dyn LinkControl> {
        self.link.clone()
    }

    /// Bridge the adapter and the daemon until the adapter fails.
    pub(crate) async fn run(
        &mut self,
        daemon: &ModemDaemon,
        mut events: broadcast::Receiver<DaemonEvent>,
        initial: LinkMetrics,
    ) -> Result<Infallible> {
        let mut bridge = Bridge {
            daemon,
            out: self.out.clone(),
            destinations: BTreeMap::new(),
            initial,
            session_metrics: initial,
            pending: HashMap::new(),
            next_request: 1,
            retries: Vec::new(),
        };
        loop {
            let next_retry = bridge.retries.iter().map(|r| r.0).min();
            tokio::select! {
                line = self.lines.recv() => match line {
                    Some(Ok(line)) => {
                        let message = parse_inbound(&line)
                            .with_context(|| format!("invalid radio adapter message: {line}"))?;
                        bridge.inbound(message).await;
                    }
                    Some(Err(e)) => return Err(e),
                    None => bail!("radio adapter closed its output"),
                },
                Some(ask) = self.asks.recv() => bridge.ask(ask),
                event = events.recv() => match event {
                    Ok(event) => bridge.event(event).await,
                    Err(broadcast::error::RecvError::Lagged(missed)) => warn!(
                        missed,
                        "radio bridge missed daemon events; a new router may lack destinations"
                    ),
                    Err(broadcast::error::RecvError::Closed) => bail!("modem daemon stopped"),
                },
                () = sleep_until(next_retry), if next_retry.is_some() => bridge.retry().await,
                status = self.child.wait() => {
                    bail!("radio adapter exited with {}", status.context("waiting for radio adapter")?);
                }
            }
        }
    }

    /// Close the adapter's input, then kill it if it does not exit promptly.
    pub(crate) async fn stop(mut self) {
        let deadline = Instant::now() + STOP_GRACE;
        drop(self.out);
        if tokio::time::timeout_at(deadline, &mut self.writer)
            .await
            .is_err()
        {
            self.writer.abort();
            let _ = self.writer.await;
        }
        if tokio::time::timeout_at(deadline, self.child.wait())
            .await
            .is_err()
        {
            warn!("radio adapter did not exit after its input closed; killing it");
            let _ = self.child.kill().await;
        }
        self.reader.abort();
    }
}

/// The modem's ambient capabilities (CAP_NET_RAW and CAP_NET_BIND_SERVICE in
/// the example unit) would otherwise survive exec into the adapter.
#[cfg(target_os = "linux")]
fn drop_ambient_capabilities(command: &mut Command) {
    use nix::libc;
    // SAFETY: the closure runs in the forked child before exec and makes only
    // an async-signal-safe prctl system call, reading errno on failure.
    unsafe {
        command.pre_exec(|| {
            let cleared = libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            let error = std::io::Error::last_os_error();
            // Kernels before 4.3 have no ambient set, so nothing is inherited.
            if cleared == -1 && error.raw_os_error() != Some(libc::EINVAL) {
                return Err(error);
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn drop_ambient_capabilities(_command: &mut Command) {}

async fn sleep_until(deadline: Option<Instant>) {
    tokio::time::sleep_until(deadline.expect("guarded by is_some")).await;
}

async fn read_lines(
    mut stdout: BufReader<tokio::process::ChildStdout>,
    lines: mpsc::Sender<Result<String>>,
) {
    loop {
        let mut line = Vec::new();
        let read = (&mut stdout)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut line)
            .await;
        let result = match read {
            Ok(0) => return,
            Ok(_) if line.last() != Some(&b'\n') && line.len() > MAX_LINE => {
                Err(anyhow!("radio adapter line exceeds {MAX_LINE} bytes"))
            }
            Ok(_) => {
                if line.last() == Some(&b'\n') {
                    line.pop();
                }
                String::from_utf8(line).context("radio adapter output is not UTF-8")
            }
            Err(e) => Err(anyhow!(e).context("reading radio adapter output")),
        };
        if let Ok(text) = &result {
            if text.trim().is_empty() {
                continue;
            }
        }
        let failed = result.is_err();
        if lines.send(result).await.is_err() || failed {
            return;
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Retry {
    Add(MacAddress),
    Drop(MacAddress),
    SessionMetrics,
}

struct Known {
    metrics: LinkMetrics,
    addresses: DestinationAddrs,
}

struct Pending {
    answer: oneshot::Sender<LinkResponse>,
    mac: MacAddress,
    current: LinkMetrics,
}

struct Bridge<'a> {
    daemon: &'a ModemDaemon,
    out: mpsc::UnboundedSender<String>,
    destinations: BTreeMap<MacAddress, Known>,
    initial: LinkMetrics,
    session_metrics: LinkMetrics,
    pending: HashMap<u64, Pending>,
    next_request: u64,
    retries: Vec<(Instant, SessionId, Retry)>,
}

impl Bridge<'_> {
    fn send(&self, message: &Outbound) {
        let line = serde_json::to_string(message).expect("serializable message");
        let _ = self.out.send(line);
    }

    async fn inbound(&mut self, message: Inbound) {
        match message {
            Inbound::DestinationUp {
                mac: Mac(mac),
                metrics,
                addresses,
            } => {
                if self.destinations.contains_key(&mac) {
                    warn!(%mac, "radio adapter reported an existing destination up; ignored");
                    return;
                }
                let addresses = match addresses.parse() {
                    Ok(addresses) => addresses.canonical(),
                    Err(e) => {
                        warn!(%mac, "radio adapter destination addresses rejected: {e:#}");
                        return;
                    }
                };
                // Omitted values inherit the current session-wide metrics.
                let metrics = metrics.overlay(self.session_metrics);
                let result = self
                    .daemon
                    .add_destination_with_addresses(mac.into(), metrics, addresses.clone())
                    .await;
                if self.accepted("destination up", &result) {
                    self.destinations.insert(mac, Known { metrics, addresses });
                    self.schedule_busy(&result, Retry::Add(mac));
                }
            }
            Inbound::DestinationUpdate {
                mac: Mac(mac),
                metrics,
            } => {
                let Some(known) = self.destinations.get(&mac) else {
                    warn!(%mac, "radio adapter updated an unknown destination; ignored");
                    return;
                };
                let metrics = metrics.overlay(known.metrics);
                let result = self.daemon.update_destination(mac.into(), metrics).await;
                if self.accepted("destination update", &result) {
                    self.destinations.get_mut(&mac).expect("known").metrics = metrics;
                }
            }
            Inbound::DestinationAddresses {
                mac: Mac(mac),
                add,
                remove,
            } => {
                if !self.destinations.contains_key(&mac) {
                    warn!(%mac, "radio adapter changed addresses of an unknown destination; ignored");
                    return;
                }
                let changes = match (add.parse(), remove.parse()) {
                    (Ok(added), Ok(removed)) => AddressChanges { added, removed }.canonical(),
                    (Err(e), _) | (_, Err(e)) => {
                        warn!(%mac, "radio adapter address change rejected: {e:#}");
                        return;
                    }
                };
                let result = self
                    .daemon
                    .update_destination_addresses(mac.into(), changes.clone())
                    .await;
                if self.accepted("destination addresses", &result) {
                    let known = self.destinations.get_mut(&mac).expect("known");
                    changes.apply_lenient(&mut known.addresses);
                }
            }
            Inbound::DestinationDown { mac: Mac(mac) } => {
                if self.destinations.remove(&mac).is_none() {
                    warn!(%mac, "radio adapter reported an unknown destination down; ignored");
                    return;
                }
                let result = self
                    .daemon
                    .drop_destination(mac.into(), StatusCode::SUCCESS)
                    .await;
                self.accepted("destination down", &result);
                // A pending link request holds this destination; retry after it.
                self.schedule_busy(&result, Retry::Drop(mac));
            }
            Inbound::SessionMetrics { metrics } => {
                let metrics = metrics.overlay(self.session_metrics);
                let result = self.daemon.update_session_metrics(metrics).await;
                if self.accepted("session metrics", &result) {
                    self.session_metrics = metrics;
                    // Session Update carries all mandatory metrics and every
                    // supplied optional metric to existing destinations too.
                    let update = Metrics::from_link(&metrics);
                    for known in self.destinations.values_mut() {
                        known.metrics = update.overlay(known.metrics);
                    }
                    self.schedule_busy(&result, Retry::SessionMetrics);
                }
            }
            Inbound::LinkResponse {
                request,
                status,
                text,
                metrics,
            } => {
                let Some(pending) = self.pending.remove(&request) else {
                    debug!(
                        request,
                        "radio adapter answered an unknown or expired link request"
                    );
                    return;
                };
                if pending.answer.is_closed() {
                    debug!(request, "radio adapter answered an expired link request");
                    return;
                }
                let metrics = metrics.map(|m| m.overlay(pending.current));
                if let Some(metrics) = &metrics {
                    if let Err(e) = self.daemon.validate_metrics(metrics) {
                        warn!(request, "radio adapter link response rejected: {e}");
                        let _ = pending.answer.send(LinkResponse::denied());
                        return;
                    }
                }
                let delivered = pending.answer.send(LinkResponse {
                    status: match status {
                        Status::Success => StatusCode::SUCCESS,
                        Status::Denied => StatusCode::REQUEST_DENIED,
                    },
                    text,
                    metrics,
                });
                if delivered.is_ok() {
                    if let (Status::Success, Some(metrics), Some(known)) =
                        (status, metrics, self.destinations.get_mut(&pending.mac))
                    {
                        known.metrics = metrics;
                    }
                }
            }
            Inbound::Unknown => debug!("ignoring unknown radio adapter message type"),
        }
    }

    fn ask(&mut self, (request, answer): Ask) {
        // Answers that timed out leave closed senders behind.
        self.pending.retain(|_, p| !p.answer.is_closed());
        let id = self.next_request;
        self.next_request += 1;
        self.send(&Outbound::LinkRequest {
            request: id,
            session: request.session_id.0,
            peer: request.peer.addr,
            mac: Mac(request.id.0),
            requested: Requested {
                current_data_rate_rx_bps: request.requested.current_data_rate_rx_bps,
                current_data_rate_tx_bps: request.requested.current_data_rate_tx_bps,
                latency_us: request.requested.latency.map(duration_us),
            },
            current: Metrics::from_link(&request.current),
        });
        self.pending.insert(
            id,
            Pending {
                answer,
                mac: request.id.0,
                current: request.current,
            },
        );
    }

    async fn event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::SessionUp {
                session_id, peer, ..
            } => {
                // Bring the new router up to date with the adapter's state.
                if self.session_metrics != self.initial {
                    let result = self
                        .daemon
                        .send_command_to(
                            session_id,
                            SessionCommand::SessionUpdate {
                                metrics: self.session_metrics,
                            },
                        )
                        .await;
                    self.accepted("session metrics replay", &result);
                }
                for (mac, known) in &self.destinations {
                    let result = self
                        .daemon
                        .send_command_to(
                            session_id,
                            SessionCommand::AddDestination {
                                mac: *mac,
                                metrics: known.metrics,
                                addrs: known.addresses.clone(),
                            },
                        )
                        .await;
                    self.accepted("destination replay", &result);
                }
                self.send(&Outbound::SessionUp {
                    session: session_id.0,
                    peer: peer.addr,
                });
            }
            DaemonEvent::SessionDown {
                session_id,
                peer,
                reason,
            } => self.send(&Outbound::SessionDown {
                session: session_id.0,
                peer: peer.addr,
                status: reason.0,
            }),
            DaemonEvent::Destination {
                session_id,
                event: DestinationEvent::Announced { id, .. },
                ..
            } => self.send(&Outbound::DestinationAnnounced {
                session: session_id.0,
                mac: Mac(id.0),
            }),
            _ => {}
        }
    }

    async fn retry(&mut self) {
        let now = Instant::now();
        let (due, later): (Vec<_>, Vec<_>) = self.retries.drain(..).partition(|r| r.0 <= now);
        self.retries = later;
        for (_, session_id, retry) in due {
            let command = match retry {
                Retry::Add(mac) => {
                    let Some(known) = self.destinations.get(&mac) else {
                        continue;
                    };
                    SessionCommand::AddDestination {
                        mac,
                        metrics: known.metrics,
                        addrs: known.addresses.clone(),
                    }
                }
                Retry::Drop(mac) if self.destinations.contains_key(&mac) => continue,
                Retry::Drop(mac) => SessionCommand::DropDestination {
                    mac,
                    reason: StatusCode::SUCCESS,
                },
                Retry::SessionMetrics => SessionCommand::SessionUpdate {
                    metrics: self.session_metrics,
                },
            };
            let result = self.daemon.send_command_to(session_id, command).await;
            self.accepted("retried command", &result);
            self.schedule_busy(&result, retry);
        }
    }

    fn schedule_busy(&mut self, result: &Result<(), DaemonError>, retry: Retry) {
        if let Err(DaemonError::CommandRejected(report)) = result {
            for (session_id, rejection) in &report.rejected {
                if rejection.reason == CommandError::Busy {
                    self.retries
                        .push((Instant::now() + RETRY_DELAY, *session_id, retry));
                }
            }
        }
    }

    /// Whether the input was valid. Session-specific outcomes are handled by
    /// replay on SessionUp or by retries; only unexpected ones are logged.
    fn accepted(&self, what: &str, result: &Result<(), DaemonError>) -> bool {
        match result {
            Ok(()) | Err(DaemonError::NoMatchingSession) => true,
            Err(DaemonError::CommandRejected(report)) => {
                for (session_id, rejection) in &report.rejected {
                    match rejection.reason {
                        CommandError::NotReady
                        | CommandError::AlreadyExists
                        | CommandError::Busy => {}
                        reason => warn!(session = session_id.0, "{what} rejected: {reason}"),
                    }
                }
                true
            }
            Err(e @ (DaemonError::Config(_) | DaemonError::Codec(_))) => {
                warn!("radio adapter {what} rejected: {e}");
                false
            }
            Err(e) => {
                warn!("radio adapter {what} failed: {e}");
                true
            }
        }
    }
}

impl From<MacAddress> for Mac {
    fn from(mac: MacAddress) -> Self {
        Self(mac)
    }
}

impl From<Mac> for DestinationId {
    fn from(mac: Mac) -> Self {
        mac.0.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlep_core::{Message, MessageType};
    use dlep_daemon::ModemConfig;
    use dlep_fsm::session_common::{
        build_destination_down_response, build_destination_up_response, extract_link_metrics,
    };
    use tokio::net::TcpStream;

    const WAIT: Duration = Duration::from_secs(5);

    async fn modem() -> ModemDaemon {
        let mut config = ModemConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        ModemDaemon::builder().config(config).spawn().await.unwrap()
    }

    fn bridge(daemon: &ModemDaemon) -> Bridge<'_> {
        Bridge {
            daemon,
            out: mpsc::unbounded_channel().0,
            destinations: BTreeMap::new(),
            initial: ModemConfig::default().metrics.link_metrics(),
            session_metrics: ModemConfig::default().metrics.link_metrics(),
            pending: HashMap::new(),
            next_request: 1,
            retries: Vec::new(),
        }
    }

    fn mac() -> MacAddress {
        MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
    }

    fn up(metrics: Metrics) -> Inbound {
        Inbound::DestinationUp {
            mac: Mac(mac()),
            metrics,
            addresses: Addresses::default(),
        }
    }

    async fn read(peer: &mut TcpStream) -> Message {
        tokio::time::timeout(WAIT, async {
            let mut header = [0; 4];
            peer.read_exact(&mut header).await.unwrap();
            let mut bytes = header.to_vec();
            bytes.resize(
                4 + usize::from(u16::from_be_bytes([header[2], header[3]])),
                0,
            );
            peer.read_exact(&mut bytes[4..]).await.unwrap();
            Message::decode(bytes.into()).unwrap()
        })
        .await
        .unwrap()
    }

    async fn send(peer: &mut TcpStream, message: Message) {
        peer.write_all(&message.encode().unwrap()).await.unwrap();
    }

    async fn flush_peer(peer: &mut TcpStream) {
        // A response on the same stream proves earlier acknowledgements were
        // processed before the bridge submits its next command.
        send(peer, Message::new(MessageType::SESSION_UPDATE)).await;
        assert_eq!(
            read(peer).await.message_type,
            MessageType::SESSION_UPDATE_RESPONSE
        );
    }

    #[tokio::test]
    async fn destination_readd_retries_after_withdrawal_with_current_state() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
        let mut peer = socket.connect(daemon.local_addr()).await.unwrap();
        let mut router = dlep_fsm::session_router::RouterSessionFsm::new();
        for action in router.step(dlep_fsm::FsmEvent::TcpConnected) {
            if let dlep_fsm::FsmAction::SendMessage(message) = action {
                send(&mut peer, message).await;
            }
        }
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_INITIALIZATION_RESPONSE
        );
        tokio::time::timeout(WAIT, async {
            loop {
                if matches!(events.recv().await.unwrap(), DaemonEvent::SessionUp { .. }) {
                    break;
                }
            }
        })
        .await
        .unwrap();

        bridge.inbound(up(Metrics::default())).await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_UP
        );
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        bridge
            .inbound(Inbound::DestinationDown { mac: Mac(mac()) })
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_DOWN
        );

        // Hold the Down acknowledgement so the re-add is deterministically Busy.
        bridge.inbound(up(Metrics::default())).await;
        assert!(matches!(bridge.retries.as_slice(), [(_, _, Retry::Add(m))] if *m == mac()));
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    latency_us: Some(1234),
                    ..Default::default()
                },
            })
            .await;
        for retry in &mut bridge.retries {
            retry.0 = Instant::now();
        }
        bridge.retry().await;
        assert_eq!(bridge.retries.len(), 1);

        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        for retry in &mut bridge.retries {
            retry.0 = Instant::now();
        }
        bridge.retry().await;
        let readded = read(&mut peer).await;
        assert_eq!(readded.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&readded).unwrap().latency,
            Duration::from_micros(1234)
        );
        assert!(bridge.retries.is_empty());
        drop(peer);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn session_metrics_update_cached_destinations_and_partial_updates() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        bridge
            .inbound(up(Metrics {
                current_data_rate_tx_bps: Some(70_000),
                latency_us: Some(12),
                ..Default::default()
            }))
            .await;
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(4000),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(bridge.destinations[&mac()].metrics, bridge.session_metrics);
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    current_data_rate_rx_bps: Some(42),
                    ..Default::default()
                },
            })
            .await;
        let cached = bridge.destinations[&mac()].metrics;
        assert_eq!(cached.latency, Duration::from_micros(4000));
        assert_eq!(cached.current_data_rate_rx_bps, 42);
        assert_eq!(
            cached.current_data_rate_tx_bps,
            bridge.session_metrics.current_data_rate_tx_bps
        );
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn link_responses_cache_only_live_valid_successes() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        bridge.inbound(up(Metrics::default())).await;
        let original = bridge.destinations[&mac()].metrics;
        for (closed, metrics) in [
            (
                true,
                Metrics {
                    latency_us: Some(123),
                    ..Default::default()
                },
            ),
            (
                false,
                Metrics {
                    mtu: Some(1500),
                    ..Default::default()
                },
            ),
            (
                false,
                Metrics {
                    rlq_rx: Some(101),
                    ..Default::default()
                },
            ),
        ] {
            let (answer, mut response) = oneshot::channel();
            if closed {
                response.close();
            }
            bridge.pending.insert(
                1,
                Pending {
                    answer,
                    mac: mac(),
                    current: original,
                },
            );
            bridge
                .inbound(Inbound::LinkResponse {
                    request: 1,
                    status: Status::Success,
                    text: String::new(),
                    metrics: Some(metrics),
                })
                .await;
            if closed {
                assert!(response.await.is_err());
            } else {
                assert_eq!(response.await.unwrap(), LinkResponse::denied());
            }
            assert!(bridge.pending.is_empty());
            assert_eq!(bridge.destinations[&mac()].metrics, original);
        }
        let (answer, response) = oneshot::channel();
        bridge.pending.insert(
            2,
            Pending {
                answer,
                mac: mac(),
                current: original,
            },
        );
        bridge
            .inbound(Inbound::LinkResponse {
                request: 2,
                status: Status::Success,
                text: String::new(),
                metrics: Some(Metrics {
                    latency_us: Some(456),
                    ..Default::default()
                }),
            })
            .await;
        assert_eq!(response.await.unwrap().status, StatusCode::SUCCESS);
        assert_eq!(
            bridge.destinations[&mac()].metrics.latency,
            Duration::from_micros(456)
        );
        daemon.shutdown().await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shutdown_bounds_a_writer_blocked_on_adapter_stdin() {
        let mut adapter = Adapter::spawn(&RadioConfig {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), "printf 'ready\\n'; exec sleep 30".into()],
            link_request_timeout_ms: 100,
        })
        .unwrap();
        assert_eq!(adapter.lines.recv().await.unwrap().unwrap(), "ready");
        // Much larger than a pipe buffer; the adapter never consumes stdin.
        adapter.out.send("x".repeat(1024 * 1024)).unwrap();
        tokio::task::yield_now().await;
        tokio::time::timeout(STOP_GRACE + WAIT, adapter.stop())
            .await
            .expect("shutdown must cancel blocked writes and kill the adapter");
    }

    #[test]
    fn mac_addresses_parse_both_formats_and_reject_malformed_text() {
        assert_eq!(
            Mac::try_from("02:00:00:0a:0B:1".to_string()).unwrap().0,
            MacAddress::new_eui48([2, 0, 0, 10, 11, 1])
        );
        assert!(
            Mac::try_from("02:00:00:00:00:00:00:01".to_string())
                .unwrap()
                .0
                .is_eui64()
        );
        for bad in [
            "",
            "02:00:00:00:00",
            "02:00:00:00:00:00:00",
            "02-00-00-00-00-01",
            "002:00:00:00:00:01",
            "zz:00:00:00:00:01",
        ] {
            assert!(Mac::try_from(bad.to_string()).is_err(), "{bad}");
        }
        assert_eq!(
            String::from(Mac(MacAddress::new_eui48([2, 0, 0, 0, 0, 0xab]))),
            "02:00:00:00:00:ab"
        );
    }

    #[test]
    fn metrics_overlay_keeps_omitted_values() {
        let base = LinkMetrics {
            max_data_rate_rx_bps: 10,
            latency: Duration::from_micros(7),
            mtu: Some(1500),
            ..Default::default()
        };
        let merged = Metrics {
            current_data_rate_tx_bps: Some(5),
            rlq_rx: Some(90),
            ..Default::default()
        }
        .overlay(base);
        assert_eq!(merged.max_data_rate_rx_bps, 10);
        assert_eq!(merged.current_data_rate_tx_bps, 5);
        assert_eq!(merged.latency, Duration::from_micros(7));
        assert_eq!(merged.mtu, Some(1500));
        assert_eq!(merged.rlq_rx, Some(90));
        assert_eq!(
            Metrics::from_link(&merged).overlay(LinkMetrics::default()),
            merged
        );
    }

    #[test]
    fn inbound_messages_parse_strictly_but_ignore_unknown_types() {
        let up = parse_inbound(
            r#"{"type":"destination_up","mac":"02:00:00:00:00:01","metrics":{"latency_us":5},"addresses":{"ipv4":["192.0.2.1"],"ipv6_subnets":["2001:db8::/32"]}}"#,
        )
        .unwrap();
        let Inbound::DestinationUp {
            addresses, metrics, ..
        } = up
        else {
            panic!("{up:?}")
        };
        assert_eq!(metrics.latency_us, Some(5));
        let addresses = addresses.parse().unwrap();
        assert_eq!(addresses.v4, ["192.0.2.1".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(addresses.v6_subnets.len(), 1);

        let response =
            parse_inbound(r#"{"type":"link_response","request":3,"status":"denied"}"#).unwrap();
        assert!(matches!(
            response,
            Inbound::LinkResponse {
                request: 3,
                status: Status::Denied,
                metrics: None,
                ..
            }
        ));
        assert!(matches!(
            parse_inbound(r#"{"type":"future_message","anything":[1,2]}"#).unwrap(),
            Inbound::Unknown
        ));

        for bad in [
            "not json",
            "[1]",
            r#"{"mac":"02:00:00:00:00:01"}"#,
            r#"{"type":"destination_down","mac":"02:00:00:00:00:01","reason":1}"#,
            r#"{"type":"destination_update","mac":"02:00:00:00:00:01","metrics":{"latency":5}}"#,
            r#"{"type":"destination_up","mac":"02:00:00:00:00:01","addresses":{"v4":[]}}"#,
            r#"{"type":"destination_down","mac":"bogus"}"#,
            r#"{"type":"link_response","request":1,"status":"maybe"}"#,
            r#"{"type":"destination_update","mac":"02:00:00:00:00:01","metrics":{"rlq_rx":300}}"#,
        ] {
            assert!(parse_inbound(bad).is_err(), "{bad}");
        }
        assert!(
            Addresses {
                ipv4_subnets: vec!["10.0.0.0/33".into()],
                ..Default::default()
            }
            .parse()
            .is_err()
        );
    }

    #[test]
    fn outbound_link_request_uses_documented_names() {
        let line = serde_json::to_string(&Outbound::LinkRequest {
            request: 1,
            session: 2,
            peer: "192.0.2.1:854".parse().unwrap(),
            mac: Mac(MacAddress::new_eui48([2, 0, 0, 0, 0, 1])),
            requested: Requested {
                current_data_rate_rx_bps: None,
                current_data_rate_tx_bps: Some(9),
                latency_us: None,
            },
            current: Metrics::from_link(&LinkMetrics::default()),
        })
        .unwrap();
        assert_eq!(
            line,
            r#"{"type":"link_request","request":1,"session":2,"peer":"192.0.2.1:854","mac":"02:00:00:00:00:01","requested":{"current_data_rate_tx_bps":9},"current":{"max_data_rate_rx_bps":0,"max_data_rate_tx_bps":0,"current_data_rate_rx_bps":0,"current_data_rate_tx_bps":0,"latency_us":0}}"#
        );
    }
}
