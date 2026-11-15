//! External radio adapter. The modem runs one configured program and exchanges
//! JSON Lines with it: the adapter reports destinations and session metrics on
//! standard output and answers Link Characteristics Requests (RFC 8175
//! §12.18–12.19) sent to its standard input. See `doc/radio-adapter.md`.
//!
//! The adapter's destination table is kept here and replayed to every router
//! session that comes up, so destinations reported before a router connects
//! are not lost. Adapter exit, failed/stalled input, closed output, or malformed
//! JSON is fatal: the modem terminates its sessions so a supervisor restarts both.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dlep_core::{MacAddress, MacAddressFormat, StatusCode};
use dlep_daemon::link_control::LinkControlFuture;
use dlep_daemon::{
    AddressChanges, CommandError, DaemonError, DaemonEvent, DaemonSnapshot, DestinationAddrs,
    DestinationEvent, DestinationId, DestinationPhase, LinkControl, LinkMetrics, LinkRequest,
    LinkResponse, ModemDaemon, PeerInfo, RadioConfig, SessionCommand, SessionPhase,
};
use dlep_ext::SessionId;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, warn};

/// Longest accepted adapter line, excluding the newline.
const MAX_LINE: usize = 64 * 1024;
const QUEUE_SIZE: usize = 64;
const MAX_PENDING: usize = 64;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
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
    /// Authoritative session membership, including after lost lifecycle events.
    SessionSync {
        sessions: Vec<SessionPeer>,
    },
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

#[derive(Debug, Serialize)]
struct SessionPeer {
    session: u64,
    peer: SocketAddr,
}

type Ask = (LinkRequest, oneshot::Sender<LinkResponse>);

/// Forwards link requests to the bridge task and bounds the adapter's answer.
struct RadioLink {
    asks: mpsc::Sender<Ask>,
    timeout: Duration,
}

impl LinkControl for RadioLink {
    fn request(&self, request: LinkRequest) -> LinkControlFuture {
        let (answer, response) = oneshot::channel();
        let sent = self.asks.try_send((request, answer));
        let timeout = self.timeout;
        Box::pin(async move {
            if let Err(error) = sent {
                let text = match error {
                    mpsc::error::TrySendError::Full(_) => "radio adapter busy",
                    mpsc::error::TrySendError::Closed(_) => "radio adapter unavailable",
                };
                return LinkResponse::denied().with_text(text);
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
    out: Option<mpsc::Sender<String>>,
    writer: Option<JoinHandle<Result<()>>>,
    reader: JoinHandle<()>,
    asks: mpsc::Receiver<Ask>,
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
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");

        // Brief pauses can drain without growing an unbounded output backlog.
        // A stalled record fails the writer and, in turn, the adapter bridge.
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        let writer = tokio::spawn(write_output(stdin, queued));
        let (lines_tx, lines) = mpsc::channel(QUEUE_SIZE);
        let reader = tokio::spawn(read_lines(BufReader::new(stdout), lines_tx));

        let (asks_tx, asks) = mpsc::channel(QUEUE_SIZE);
        Ok(Self {
            child,
            lines,
            out: Some(out),
            writer: Some(writer),
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
        mac_address_format: MacAddressFormat,
    ) -> Result<Infallible> {
        let mut bridge = Bridge {
            daemon,
            mac_address_format,
            out: self.out.as_ref().expect("adapter active").clone(),
            destinations: BTreeMap::new(),
            session_metrics: initial,
            pending: HashMap::new(),
            next_request: 1,
            retries: BTreeMap::new(),
            sessions: HashMap::new(),
            synced: false,
        };
        // Supervise I/O outside the bridge loop so a writer failure or child
        // exit also interrupts replay and command acceptance waits.
        let work = async {
            let mut state = daemon.state();
            loop {
                if !bridge.synced || state.has_changed().unwrap_or(false) {
                    let snapshot = state.borrow_and_update().clone();
                    bridge.reconcile(&snapshot).await?;
                }
                let next_retry = bridge.retries.values().copied().min();
                tokio::select! {
                    changed = state.changed() => {
                        if changed.is_err() { bail!("modem state feed stopped"); }
                        // `changed` marks the value seen; reconcile it explicitly.
                        let snapshot = state.borrow_and_update().clone();
                        bridge.reconcile(&snapshot).await?;
                    },
                    line = self.lines.recv() => match line {
                        Some(Ok(line)) => {
                            let message = parse_inbound(&line)
                                .with_context(|| format!("invalid radio adapter message: {line}"))?;
                            bridge.inbound(message).await;
                        }
                        Some(Err(e)) => return Err(e),
                        None => bail!("radio adapter closed its output"),
                    },
                    Some(ask) = self.asks.recv() => bridge.ask(ask).await?,
                    event = events.recv() => match event {
                        Ok(event) => bridge.event(event).await?,
                        Err(broadcast::error::RecvError::Lagged(missed)) => warn!(
                            missed,
                            "radio bridge missed transient notices; session state is reconciled separately"
                        ),
                        Err(broadcast::error::RecvError::Closed) => bail!("modem daemon stopped"),
                    },
                    () = sleep_until(next_retry), if next_retry.is_some() => bridge.retry().await,
                }
            }
        };
        tokio::select! {
            result = work => result,
            status = self.child.wait() => {
                bail!("radio adapter exited with {}", status.context("waiting for radio adapter")?);
            }
            result = self.writer.as_mut().expect("writer active") => {
                self.writer.take();
                result.context("radio adapter writer task failed")??;
                bail!("radio adapter input closed");
            }
        }
    }

    /// Close the adapter's input, then kill it if it does not exit promptly.
    pub(crate) async fn stop(mut self) {
        let deadline = Instant::now() + STOP_GRACE;
        self.out.take();
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
            warn!("radio adapter did not exit after its input closed; killing it");
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
        // kill_on_drop also covers failures before the daemon starts.
    }
}

async fn write_output(
    mut stdin: impl AsyncWrite + Unpin,
    mut queued: mpsc::Receiver<String>,
) -> Result<()> {
    while let Some(mut line) = queued.recv().await {
        line.push('\n');
        tokio::time::timeout(IO_TIMEOUT, stdin.write_all(line.as_bytes()))
            .await
            .context("radio adapter input stalled")?
            .context("writing to radio adapter")?;
    }
    Ok(())
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Retry {
    InitializeSession,
    Add(MacAddress),
    Drop(MacAddress),
    SessionMetrics,
}

struct Known {
    metrics: LinkMetrics,
    addresses: DestinationAddrs,
}

struct Pending {
    session_id: SessionId,
    answer: oneshot::Sender<LinkResponse>,
    mac: MacAddress,
    current: LinkMetrics,
    /// False once this request's physical destination has been withdrawn.
    update_cache: bool,
}

struct Bridge<'a> {
    daemon: &'a ModemDaemon,
    mac_address_format: MacAddressFormat,
    out: mpsc::Sender<String>,
    destinations: BTreeMap<MacAddress, Known>,
    session_metrics: LinkMetrics,
    pending: HashMap<u64, Pending>,
    next_request: u64,
    /// One deadline per operation and session; reports share the latest cache.
    retries: BTreeMap<(SessionId, Retry), Instant>,
    sessions: HashMap<SessionId, PeerInfo>,
    synced: bool,
}

impl Bridge<'_> {
    async fn send(&self, message: &Outbound) -> Result<()> {
        let line = serde_json::to_string(message).expect("serializable message");
        self.out
            .send(line)
            .await
            .context("radio adapter writer stopped")
    }

    async fn inbound(&mut self, message: Inbound) {
        match message {
            Inbound::DestinationUp {
                mac: Mac(mac),
                metrics,
                addresses,
            } => {
                if !self.mac_address_format.accepts(mac) {
                    warn!(%mac, expected = ?self.mac_address_format,
                        "radio adapter destination uses incompatible MAC format; ignored");
                    return;
                }
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
                    self.update_retries(&result, Retry::Add(mac), None);
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
                let Some(known) = self.destinations.get(&mac) else {
                    warn!(%mac, "radio adapter changed addresses of an unknown destination; ignored");
                    return;
                };
                let changes = match (add.parse(), remove.parse()) {
                    (Ok(added), Ok(removed)) => AddressChanges { added, removed }.canonical(),
                    (Err(e), _) | (_, Err(e)) => {
                        warn!(%mac, "radio adapter address change rejected: {e:#}");
                        return;
                    }
                };
                // Individually encodable deltas can accumulate a snapshot
                // that no longer fits a Destination Up for a later router.
                // Reject the entire batch before sending or retaining it.
                let mut addresses = known.addresses.clone();
                changes.apply_lenient(&mut addresses);
                if let Err(e) = self.daemon.validate_destination_snapshot(
                    mac.into(),
                    &known.metrics,
                    &addresses,
                ) {
                    warn!(%mac, "radio adapter destination addresses rejected: {e}");
                    return;
                }
                let result = self
                    .daemon
                    .update_destination_addresses(mac.into(), changes.clone())
                    .await;
                if self.accepted("destination addresses", &result) {
                    self.destinations.get_mut(&mac).expect("known").addresses = addresses;
                }
            }
            Inbound::DestinationDown { mac: Mac(mac) } => {
                if self.destinations.remove(&mac).is_none() {
                    warn!(%mac, "radio adapter reported an unknown destination down; ignored");
                    return;
                }
                // Finish old transactions, but do not let their answers alter
                // a replacement reported under the same MAC in the meantime.
                for pending in self.pending.values_mut().filter(|p| p.mac == mac) {
                    pending.update_cache = false;
                }
                // A new physical withdrawal cancels any deferred re-add.
                self.retries
                    .retain(|(_, retry), _| *retry != Retry::Add(mac));
                let result = self
                    .daemon
                    .drop_destination(mac.into(), StatusCode::SUCCESS)
                    .await;
                self.accepted("destination down", &result);
                // A pending link request holds this destination; retry after it.
                self.update_retries(&result, Retry::Drop(mac), None);
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
                    self.update_retries(&result, Retry::SessionMetrics, None);
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
                // `current` in the request is only a snapshot. Reports can
                // change the destination while the radio decides its answer.
                let current = self
                    .daemon
                    .state()
                    .borrow()
                    .sessions
                    .get(&pending.session_id)
                    .and_then(|session| session.destinations.get(&pending.mac.into()))
                    .map_or(pending.current, |destination| destination.metrics);
                // Grants on other sessions may have changed the replay cache
                // independently. Apply only the supplied fields to each view.
                let cached = metrics
                    .filter(|_| status == Status::Success && pending.update_cache)
                    .and_then(|patch| {
                        self.destinations
                            .get(&pending.mac)
                            .map(|known| patch.overlay(known.metrics))
                    });
                let metrics = metrics.map(|patch| patch.overlay(current));
                for metrics in metrics.iter().chain(cached.iter()) {
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
                    if let (Some(metrics), Some(known)) =
                        (cached, self.destinations.get_mut(&pending.mac))
                    {
                        known.metrics = metrics;
                    }
                }
            }
            Inbound::Unknown => debug!("ignoring unknown radio adapter message type"),
        }
    }

    async fn ask(&mut self, (request, mut answer): Ask) -> Result<()> {
        // Answers that timed out leave closed senders behind.
        self.pending.retain(|_, p| !p.answer.is_closed());
        if answer.is_closed() {
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            let _ = answer.send(LinkResponse::denied().with_text("radio adapter busy"));
            return Ok(());
        }
        let id = self.next_request;
        self.next_request += 1;
        let message = Outbound::LinkRequest {
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
        };
        tokio::select! {
            biased;
            // Do not forward a request that expires while waiting for output
            // capacity. Already delivered requests cannot be recalled.
            _ = answer.closed() => return Ok(()),
            result = self.send(&message) => result?,
        }
        self.pending.insert(
            id,
            Pending {
                session_id: request.session_id,
                answer,
                mac: request.id.0,
                current: request.current,
                // A backend request can wait in the bounded queue while the
                // bridge processes Down and a replacement Up. Its session still
                // needs the old Down after the link transaction completes.
                update_cache: self.destinations.contains_key(&request.id.0)
                    && !self
                        .retries
                        .contains_key(&(request.session_id, Retry::Drop(request.id.0)))
                    && self
                        .daemon
                        .state()
                        .borrow()
                        .sessions
                        .get(&request.session_id)
                        .is_some_and(|session| session.phase == SessionPhase::Established),
            },
        );
        Ok(())
    }

    /// Reconcile membership from retained runtime state, never lifecycle events.
    /// Replay only for a new session; replaying existing sessions would undo a
    /// router's withdrawal or overwrite a session-specific link-control grant.
    async fn reconcile(&mut self, snapshot: &DaemonSnapshot) -> Result<()> {
        let sessions: HashMap<_, _> = snapshot
            .sessions
            .iter()
            .map(|(id, session)| (*id, session.peer.clone()))
            .collect();
        self.retries.retain(|(id, _), _| {
            snapshot
                .sessions
                .get(id)
                .is_some_and(|session| session.phase == SessionPhase::Established)
        });
        self.pending.retain(|_, pending| {
            snapshot.sessions.contains_key(&pending.session_id) && !pending.answer.is_closed()
        });
        if self.synced && self.sessions == sessions {
            return Ok(());
        }
        for (&session_id, session) in &snapshot.sessions {
            if !self.sessions.contains_key(&session_id)
                && session.phase == SessionPhase::Established
            {
                self.replay_session(session_id, session).await;
                self.send(&Outbound::SessionUp {
                    session: session_id.0,
                    peer: session.peer.addr,
                })
                .await?;
            }
        }
        let mut peers: Vec<_> = sessions
            .iter()
            .map(|(id, peer)| SessionPeer {
                session: id.0,
                peer: peer.addr,
            })
            .collect();
        peers.sort_by_key(|peer| peer.session);
        self.send(&Outbound::SessionSync { sessions: peers })
            .await?;
        self.sessions = sessions;
        self.synced = true;
        Ok(())
    }

    async fn replay_session(
        &mut self,
        session_id: SessionId,
        session: &dlep_daemon::SessionSnapshot,
    ) {
        if self.session_metrics != session.metrics {
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
            self.update_retries(&result, Retry::InitializeSession, Some(session_id));
            if result.is_err() {
                return;
            }
            // A report or a link-control grant may have reached this session
            // before we observed it. Session Update overwrites every existing
            // destination, so restore those effective per-session values.
            for (id, destination) in &session.destinations {
                let result = self
                    .daemon
                    .send_command_to(
                        session_id,
                        SessionCommand::UpdateDestination {
                            mac: id.0,
                            metrics: destination.metrics,
                        },
                    )
                    .await;
                self.accepted("destination metrics replay", &result);
            }
        }
        let commands: Vec<_> = self
            .destinations
            .iter()
            // Reports may already have reached this session before its
            // initialization was observed by the bridge.
            .filter(|(mac, _)| !session.destinations.contains_key(&(**mac).into()))
            .map(|(mac, known)| {
                (
                    *mac,
                    SessionCommand::AddDestination {
                        mac: *mac,
                        metrics: known.metrics,
                        addrs: known.addresses.clone(),
                    },
                )
            })
            .collect();
        for (mac, command) in commands {
            let result = self.daemon.send_command_to(session_id, command).await;
            self.accepted("destination replay", &result);
            self.update_retries(&result, Retry::Add(mac), Some(session_id));
        }
    }

    async fn event(&mut self, event: DaemonEvent) -> Result<()> {
        match event {
            DaemonEvent::SessionDown {
                session_id,
                peer,
                reason,
            } => {
                self.send(&Outbound::SessionDown {
                    session: session_id.0,
                    peer: peer.addr,
                    status: reason.0,
                })
                .await?
            }
            DaemonEvent::Destination {
                session_id,
                event: DestinationEvent::Announced { id, .. },
                ..
            } => {
                self.send(&Outbound::DestinationAnnounced {
                    session: session_id.0,
                    mac: Mac(id.0),
                })
                .await?
            }
            _ => {}
        }
        Ok(())
    }

    async fn retry(&mut self) {
        let now = Instant::now();
        let mut due: Vec<_> = self
            .retries
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(&(session, retry), &deadline)| (deadline, session, retry))
            .collect();
        due.sort_unstable();
        self.retries.retain(|_, deadline| *deadline > now);
        for (_, session_id, retry) in due {
            let command = match retry {
                Retry::InitializeSession => {
                    let snapshot = self.daemon.state().borrow().clone();
                    if let Some(session) = snapshot.sessions.get(&session_id) {
                        if session.phase == SessionPhase::Established {
                            self.replay_session(session_id, session).await;
                        }
                    }
                    continue;
                }
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
                // This session still holds the withdrawn entry even if the
                // adapter re-reported the MAC: its re-add was AlreadyExists.
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
            self.update_retries(&result, retry, Some(session_id));
            if let (Retry::Drop(mac), Ok(())) = (retry, &result) {
                if self.destinations.contains_key(&mac) {
                    // Re-add current state once the router acknowledges the Down.
                    self.schedule_retry(session_id, Retry::Add(mac));
                }
            }
        }
    }

    fn schedule_retry(&mut self, session: SessionId, retry: Retry) {
        // Keep the first deadline: continuous reports must not postpone work.
        self.retries
            .entry((session, retry))
            .or_insert_with(|| Instant::now() + RETRY_DELAY);
    }

    fn update_retries(
        &mut self,
        result: &Result<(), DaemonError>,
        retry: Retry,
        target: Option<SessionId>,
    ) {
        match result {
            Ok(()) | Err(DaemonError::NoMatchingSession) => {
                // Successful broadcasts supersede this operation everywhere;
                // targeted replay must leave other sessions' work alone.
                self.retries.retain(|(session, kind), _| {
                    *kind != retry || target.is_some_and(|id| id != *session)
                });
            }
            Err(DaemonError::CommandRejected(report)) => {
                for session in &report.accepted {
                    self.retries.remove(&(*session, retry));
                }
                for (session, rejection) in &report.rejected {
                    if rejection.reason != CommandError::Busy {
                        self.retries.remove(&(*session, retry));
                        continue;
                    }
                    if let Retry::Drop(mac) = retry {
                        let snapshot = self.daemon.state().borrow().clone();
                        if snapshot
                            .sessions
                            .get(session)
                            .and_then(|s| s.destinations.get(&mac.into()))
                            .is_none_or(|d| d.phase == DestinationPhase::PendingDown)
                        {
                            // The old incarnation is being withdrawn, or its ACK
                            // arrived after the Busy receipt and removed it.
                            // Repeating Down after its ACK could remove a new Up.
                            self.retries.remove(&(*session, retry));
                            if self.destinations.contains_key(&mac) {
                                self.schedule_retry(*session, Retry::Add(mac));
                            }
                            continue;
                        }
                    }
                    self.schedule_retry(*session, retry);
                }
            }
            _ => {}
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
        build_destination_down_response, build_destination_up_response,
        build_link_characteristics_request, extract_link_metrics,
    };
    use tokio::net::TcpStream;

    const WAIT: Duration = Duration::from_secs(5);

    async fn modem() -> ModemDaemon {
        modem_with(None).await
    }

    async fn modem_with(backend: Option<Arc<dyn LinkControl>>) -> ModemDaemon {
        modem_with_format(backend, MacAddressFormat::Eui48).await
    }

    async fn modem_with_format(
        backend: Option<Arc<dyn LinkControl>>,
        format: MacAddressFormat,
    ) -> ModemDaemon {
        let mut config = ModemConfig::default();
        config.shared.network.mac_address_format = format;
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let mut builder = ModemDaemon::builder().config(config);
        if let Some(backend) = backend {
            builder = builder.link_control(backend);
        }
        builder.spawn().await.unwrap()
    }

    /// Establish a session from a hand-driven router FSM over raw TCP.
    async fn session(
        daemon: &ModemDaemon,
        events: &mut broadcast::Receiver<DaemonEvent>,
    ) -> TcpStream {
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
        wait_for(events, |e| matches!(e, DaemonEvent::SessionUp { .. })).await;
        peer
    }

    async fn wait_for(
        events: &mut broadcast::Receiver<DaemonEvent>,
        predicate: impl Fn(&DaemonEvent) -> bool,
    ) {
        tokio::time::timeout(WAIT, async {
            while !predicate(&events.recv().await.unwrap()) {}
        })
        .await
        .unwrap();
    }

    fn fire_retries(bridge: &mut Bridge<'_>) {
        for deadline in bridge.retries.values_mut() {
            *deadline = Instant::now();
        }
    }

    fn bridge(daemon: &ModemDaemon) -> Bridge<'_> {
        let (out, mut messages) = mpsc::channel(QUEUE_SIZE);
        tokio::spawn(async move { while messages.recv().await.is_some() {} });
        Bridge {
            daemon,
            mac_address_format: MacAddressFormat::Eui48,
            out,
            destinations: BTreeMap::new(),
            session_metrics: ModemConfig::default().metrics.link_metrics(),
            pending: HashMap::new(),
            next_request: 1,
            retries: BTreeMap::new(),
            sessions: HashMap::new(),
            synced: false,
        }
    }

    fn mac() -> MacAddress {
        MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
    }

    fn link_request() -> LinkRequest {
        LinkRequest {
            session_id: SessionId(1),
            peer: PeerInfo {
                addr: "127.0.0.1:1234".parse().unwrap(),
                is_tls: false,
                peer_description: None,
            },
            id: mac().into(),
            requested: dlep_daemon::LinkCharacteristics {
                current_data_rate_tx_bps: Some(123),
                ..Default::default()
            },
            current: LinkMetrics::default(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_radio_writer_has_a_deadline_and_closes_the_queue() {
        let (input, _peer) = tokio::io::duplex(8);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        out.send("x".repeat(32)).await.unwrap();
        let start = Instant::now();
        let error = write_output(input, queued).await.unwrap_err();
        assert!(error.to_string().contains("radio adapter input stalled"));
        assert_eq!(Instant::now() - start, IO_TIMEOUT);
        assert!(out.is_closed());
    }

    #[tokio::test]
    async fn radio_writer_preserves_records_across_partial_writes_and_reports_broken_input() {
        let (input, mut peer) = tokio::io::duplex(4);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        for line in [r#"{"type":"first"}"#, r#"{"type":"second"}"#] {
            out.send(line.into()).await.unwrap();
        }
        drop(out);
        let mut received = String::new();
        let (result, read) = tokio::join!(
            write_output(input, queued),
            peer.read_to_string(&mut received)
        );
        result.unwrap();
        read.unwrap();
        assert_eq!(received, "{\"type\":\"first\"}\n{\"type\":\"second\"}\n");

        let (input, peer) = tokio::io::duplex(4);
        drop(peer);
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        out.send("record".into()).await.unwrap();
        let error = write_output(input, queued).await.unwrap_err();
        assert!(error.to_string().contains("writing to radio adapter"));
        assert!(out.is_closed());
    }

    #[tokio::test(start_paused = true)]
    async fn radio_link_rejects_queue_overflow_and_times_out_queued_requests() {
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let link = RadioLink {
            asks,
            timeout: Duration::from_millis(100),
        };
        let requests: Vec<_> = (0..QUEUE_SIZE)
            .map(|_| link.request(link_request()))
            .collect();
        let full = link.request(link_request()).await;
        assert_eq!(full, LinkResponse::denied().with_text("radio adapter busy"));
        assert_eq!(queued.len(), QUEUE_SIZE);
        drop(requests);
        while let Ok((_, answer)) = queued.try_recv() {
            assert!(answer.is_closed());
        }
        let expired = link.request(link_request()).await;
        assert_eq!(
            expired,
            LinkResponse::denied().with_text("radio adapter timed out")
        );
        assert!(queued.recv().await.unwrap().1.is_closed());
        drop(queued);
        assert_eq!(
            link.request(link_request()).await,
            LinkResponse::denied().with_text("radio adapter unavailable")
        );
    }

    #[tokio::test]
    async fn radio_bridge_bounds_pending_requests_and_recovers_capacity_after_cancellation() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        let mut replies = Vec::new();
        for _ in 0..MAX_PENDING {
            let (answer, response) = oneshot::channel();
            bridge.ask((link_request(), answer)).await.unwrap();
            replies.push(response);
            let message: serde_json::Value =
                serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
            assert_eq!(message["type"], "link_request");
        }
        let (answer, response) = oneshot::channel();
        bridge.ask((link_request(), answer)).await.unwrap();
        assert_eq!(
            response.await.unwrap(),
            LinkResponse::denied().with_text("radio adapter busy")
        );
        assert_eq!(bridge.pending.len(), MAX_PENDING);
        assert!(notices.try_recv().is_err());
        drop(replies.pop());
        let (answer, mut response) = oneshot::channel();
        bridge.ask((link_request(), answer)).await.unwrap();
        assert!(response.try_recv().is_err());
        assert_eq!(bridge.pending.len(), MAX_PENDING);
        assert!(notices.try_recv().is_ok());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_radio_requests_do_not_escape_an_output_backlog() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(1);
        out.send("occupied".into()).await.unwrap();
        bridge.out = out;
        {
            let (answer, response) = oneshot::channel();
            let request = bridge.ask((link_request(), answer));
            tokio::pin!(request);
            tokio::select! {
                biased;
                _ = &mut request => panic!("output queue should apply backpressure"),
                _ = tokio::task::yield_now() => {}
            }
            drop(response);
            request.await.unwrap();
        }
        assert_eq!(notices.recv().await.unwrap(), "occupied");
        let (answer, response) = oneshot::channel();
        drop(response);
        bridge.ask((link_request(), answer)).await.unwrap();
        assert!(bridge.pending.is_empty());
        assert!(notices.try_recv().is_err());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn closed_radio_output_fails_membership_delivery() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        bridge.out = mpsc::channel(1).0;
        let snapshot = daemon.state().borrow().clone();
        let error = bridge.reconcile(&snapshot).await.unwrap_err();
        assert!(error.to_string().contains("radio adapter writer stopped"));
        assert!(!bridge.synced);
        daemon.shutdown().await.unwrap();
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
    async fn retained_sessions_replay_after_event_loss_and_remove_stale_retries() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut lagged = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        bridge.inbound(up(Metrics::default())).await;
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(42),
                    ..Default::default()
                },
            })
            .await;
        let mut peer = session(&daemon, &mut events).await;

        // Lose SessionUp in a real daemon broadcast, without feeding any
        // lifecycle event to the bridge. Each alternating address update emits
        // a public event; its response is a deterministic processing barrier.
        for i in 0..300 {
            let addresses = DestinationAddrs {
                v4: vec!["192.0.2.2".parse().unwrap()],
                ..Default::default()
            };
            let changes = if i % 2 == 0 {
                AddressChanges {
                    added: addresses,
                    removed: Default::default(),
                }
            } else {
                AddressChanges {
                    removed: addresses,
                    added: Default::default(),
                }
            };
            send(
                &mut peer,
                changes.append_to(Message::new(MessageType::SESSION_UPDATE)),
            )
            .await;
            assert_eq!(
                read(&mut peer).await.message_type,
                MessageType::SESSION_UPDATE_RESPONSE
            );
        }
        assert!(matches!(
            lagged.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        let snapshot = daemon.state().borrow().clone();
        let session_id = *snapshot.sessions.keys().next().unwrap();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        let destination = read(&mut peer).await;
        assert_eq!(destination.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&destination).unwrap().latency,
            Duration::from_micros(42)
        );
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        let notice: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(notice["type"], "session_up");
        let sync: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(sync["type"], "session_sync");
        assert_eq!(sync["sessions"][0]["session"], session_id.0);

        // Further snapshots must not re-add a destination the router withdrew.
        send(
            &mut peer,
            dlep_fsm::session_common::build_destination_down(mac(), StatusCode::SUCCESS),
        )
        .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_DOWN_RESPONSE
        );
        flush_peer(&mut peer).await;
        let snapshot = daemon.state().borrow().clone();
        assert_eq!(
            snapshot.sessions[&session_id].destinations[&mac().into()].phase,
            dlep_daemon::DestinationPhase::Withdrawn
        );
        bridge.reconcile(&snapshot).await.unwrap();
        assert!(notices.try_recv().is_err());
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    latency_us: Some(99),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(
            daemon.state().borrow().sessions[&session_id].destinations[&mac().into()]
                .metrics
                .latency,
            Duration::from_micros(99)
        );

        bridge
            .retries
            .insert((session_id, Retry::Add(mac())), Instant::now());
        let (answer, abandoned) = oneshot::channel();
        bridge.pending.insert(
            999,
            Pending {
                session_id,
                answer,
                mac: mac(),
                current: LinkMetrics::default(),
                update_cache: true,
            },
        );
        let mut state = daemon.state();
        drop(peer);
        tokio::time::timeout(WAIT, async {
            while !state.borrow_and_update().sessions.is_empty() {
                state.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let snapshot = state.borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert!(bridge.retries.is_empty());
        assert!(bridge.pending.is_empty());
        assert!(abandoned.await.is_err());
        let sync: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(sync["sessions"], serde_json::json!([]));

        // A new session is replayed, with current adapter state and a new ID.
        let mut fresh_events = daemon.subscribe();
        let mut peer = session(&daemon, &mut fresh_events).await;
        let snapshot = daemon.state().borrow().clone();
        assert!(!snapshot.sessions.contains_key(&session_id));
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        let destination = read(&mut peer).await;
        assert_eq!(destination.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&destination).unwrap().latency,
            Duration::from_micros(99)
        );
        drop(peer);
        drop(bridge);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn session_replay_retries_busy_defaults_without_losing_existing_destination_metrics() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(42),
                    ..Default::default()
                },
            })
            .await;
        let mut peer = session(&daemon, &mut events).await;
        // A destination report reaches the session before the bridge observes
        // its retained membership. Later replay must preserve this override.
        bridge
            .inbound(up(Metrics {
                latency_us: Some(99),
                ..Default::default()
            }))
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_UP
        );
        let snapshot = daemon.state().borrow().clone();
        let session_id = *snapshot.sessions.keys().next().unwrap();
        assert_eq!(
            snapshot.sessions[&session_id].destinations[&mac().into()].phase,
            dlep_daemon::DestinationPhase::PendingUp
        );
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    latency_us: Some(100),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(
            daemon.state().borrow().sessions[&session_id].destinations[&mac().into()]
                .metrics
                .latency,
            Duration::from_micros(100)
        );
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_UPDATE
        );
        flush_peer(&mut peer).await;

        daemon
            .update_session_addresses(
                session_id,
                AddressChanges {
                    added: DestinationAddrs {
                        v4: vec!["192.0.2.5".parse().unwrap()],
                        ..Default::default()
                    },
                    removed: Default::default(),
                },
            )
            .await
            .unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(bridge.retries.len(), 1);
        assert!(
            bridge
                .retries
                .contains_key(&(session_id, Retry::InitializeSession))
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        assert!(bridge.retries.is_empty());
        let defaults = read(&mut peer).await;
        assert_eq!(defaults.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&defaults).unwrap().latency,
            Duration::from_micros(42)
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        let restored = read(&mut peer).await;
        assert_eq!(restored.message_type, MessageType::DESTINATION_UPDATE);
        assert_eq!(
            extract_link_metrics(&restored).unwrap().latency,
            Duration::from_micros(100)
        );
        flush_peer(&mut peer).await;
        let snapshot = daemon.state().borrow().clone();
        assert_eq!(
            snapshot.sessions[&session_id].metrics.latency,
            Duration::from_micros(42)
        );
        assert_eq!(
            snapshot.sessions[&session_id].destinations[&mac().into()]
                .metrics
                .latency,
            Duration::from_micros(100)
        );

        send(&mut peer, Message::new(MessageType::HEARTBEAT)).await;
        flush_peer(&mut peer).await;
        assert_eq!(daemon.state().borrow().generation, snapshot.generation);

        bridge
            .inbound(Inbound::DestinationDown { mac: Mac(mac()) })
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_DOWN
        );
        assert_eq!(
            daemon.state().borrow().sessions[&session_id].destinations[&mac().into()].phase,
            dlep_daemon::DestinationPhase::PendingDown
        );
        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        assert!(
            daemon.state().borrow().sessions[&session_id]
                .destinations
                .is_empty()
        );

        daemon
            .send_command_to(
                session_id,
                SessionCommand::Shutdown {
                    reason: StatusCode::SHUTTING_DOWN,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_TERMINATION
        );
        assert_eq!(
            daemon.state().borrow().sessions[&session_id].phase,
            SessionPhase::Terminating
        );
        let mut state = daemon.state();
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_termination_response(),
        )
        .await;
        tokio::time::timeout(WAIT, async {
            while !state.borrow_and_update().sessions.is_empty() {
                state.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        drop(peer);
        drop(bridge);
        daemon.shutdown().await.unwrap();
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
        assert_eq!(bridge.retries.len(), 1);
        assert!(
            bridge
                .retries
                .keys()
                .any(|(_, retry)| *retry == Retry::Add(mac()))
        );
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    latency_us: Some(1234),
                    ..Default::default()
                },
            })
            .await;
        for deadline in bridge.retries.values_mut() {
            *deadline = Instant::now();
        }
        bridge.retry().await;
        assert_eq!(bridge.retries.len(), 1);

        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        for deadline in bridge.retries.values_mut() {
            *deadline = Instant::now();
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

    // A pending link request makes the withdrawal Busy, and the re-report finds
    // the old entry still present (AlreadyExists). The router must still see
    // the withdrawal followed by the destination's current state.
    #[tokio::test]
    async fn destination_rereported_while_its_drop_awaits_a_link_answer_is_replaced() {
        let (release, released) = oneshot::channel::<()>();
        let released = Arc::new(std::sync::Mutex::new(Some(released)));
        let backend = move |_request: LinkRequest| {
            let released = released.lock().unwrap().take();
            async move {
                if let Some(released) = released {
                    let _ = released.await;
                }
                LinkResponse::denied()
            }
        };
        let daemon = modem_with(Some(Arc::new(backend))).await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut peer = session(&daemon, &mut events).await;

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
        send(
            &mut peer,
            build_link_characteristics_request(
                mac(),
                &dlep_daemon::LinkCharacteristics {
                    latency: Some(Duration::from_micros(1)),
                    ..Default::default()
                },
            ),
        )
        .await;
        wait_for(&mut events, |e| {
            matches!(
                e,
                DaemonEvent::Destination {
                    event: DestinationEvent::LinkCharacteristicsRequested { .. },
                    ..
                }
            )
        })
        .await;

        bridge
            .inbound(Inbound::DestinationDown { mac: Mac(mac()) })
            .await;
        assert_eq!(bridge.retries.len(), 1);
        assert!(
            bridge
                .retries
                .keys()
                .any(|(_, retry)| *retry == Retry::Drop(mac()))
        );
        bridge
            .inbound(up(Metrics {
                latency_us: Some(1234),
                ..Default::default()
            }))
            .await;
        assert_eq!(
            bridge.retries.len(),
            1,
            "re-add was AlreadyExists, not Busy"
        );

        release.send(()).unwrap();
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::LINK_CHARACTERISTICS_RESPONSE
        );
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_DOWN
        );
        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
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
    async fn busy_metric_reports_coalesce_into_one_retry_with_the_latest_values() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut peer = session(&daemon, &mut events).await;
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(100),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        // Keep the first transaction open while reports continue arriving.
        let mut first_deadline = None;
        for latency in 101..=612 {
            bridge
                .inbound(Inbound::SessionMetrics {
                    metrics: Metrics {
                        latency_us: Some(latency),
                        ..Default::default()
                    },
                })
                .await;
            first_deadline.get_or_insert(*bridge.retries.values().next().unwrap());
        }
        assert_eq!(
            bridge.retries.len(),
            1,
            "reports must not accumulate retry work"
        );
        assert_eq!(
            bridge.retries.values().next().copied(),
            first_deadline,
            "new reports must not postpone the first retry"
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        let update = read(&mut peer).await;
        assert_eq!(update.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&update).unwrap().latency,
            Duration::from_micros(612)
        );
        assert!(bridge.retries.is_empty());
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        drop(peer);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn accepted_metric_report_cancels_retries_before_a_later_destination_override() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut peer = session(&daemon, &mut events).await;
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
        for latency in [100, 200] {
            bridge
                .inbound(Inbound::SessionMetrics {
                    metrics: Metrics {
                        latency_us: Some(latency),
                        ..Default::default()
                    },
                })
                .await;
        }
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        assert_eq!(bridge.retries.len(), 1);
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        // A new report succeeds before the deferred retry runs.
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(300),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        bridge
            .inbound(Inbound::DestinationUpdate {
                mac: Mac(mac()),
                metrics: Metrics {
                    latency_us: Some(999),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_UPDATE
        );
        fire_retries(&mut bridge);
        bridge.retry().await;
        let snapshot = daemon.state().borrow().clone();
        assert_eq!(
            snapshot.sessions.values().next().unwrap().destinations[&mac().into()]
                .metrics
                .latency,
            Duration::from_micros(999),
            "a stale retry overwrote a later destination report"
        );
        assert!(bridge.retries.is_empty());
        // Also prove no redundant Session Update was emitted on the wire.
        flush_peer(&mut peer).await;
        drop(peer);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn partial_metric_acceptance_preserves_only_the_busy_sessions_retry() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut a = session(&daemon, &mut events).await;
        let mut b = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        let id_for = |peer: &TcpStream| {
            *snapshot
                .sessions
                .iter()
                .find(|(_, state)| state.peer.addr == peer.local_addr().unwrap())
                .unwrap()
                .0
        };
        let aid = id_for(&a);
        let bid = id_for(&b);
        bridge.inbound(up(Metrics::default())).await;
        for peer in [&mut a, &mut b] {
            assert_eq!(read(peer).await.message_type, MessageType::DESTINATION_UP);
            send(
                peer,
                build_destination_up_response(mac(), StatusCode::SUCCESS),
            )
            .await;
            flush_peer(peer).await;
        }
        for latency in [100, 200] {
            bridge
                .inbound(Inbound::SessionMetrics {
                    metrics: Metrics {
                        latency_us: Some(latency),
                        ..Default::default()
                    },
                })
                .await;
        }
        for peer in [&mut a, &mut b] {
            assert_eq!(read(peer).await.message_type, MessageType::SESSION_UPDATE);
        }
        assert_eq!(bridge.retries.len(), 2);
        send(
            &mut b,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut b).await;
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(300),
                    ..Default::default()
                },
            })
            .await;
        assert_eq!(read(&mut b).await.message_type, MessageType::SESSION_UPDATE);
        send(
            &mut b,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut b).await;
        assert_eq!(
            bridge.retries.keys().copied().collect::<Vec<_>>(),
            [(aid, Retry::SessionMetrics)]
        );
        // Session-specific values on the healthy router must survive retries
        // needed only by the other router.
        let mut metrics = bridge.destinations[&mac()].metrics;
        metrics.latency = Duration::from_micros(999);
        daemon
            .send_command_to(
                bid,
                SessionCommand::UpdateDestination {
                    mac: mac(),
                    metrics,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            read(&mut b).await.message_type,
            MessageType::DESTINATION_UPDATE
        );
        send(
            &mut a,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut a).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        let update = read(&mut a).await;
        assert_eq!(update.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&update).unwrap().latency,
            Duration::from_micros(300)
        );
        send(
            &mut a,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut a).await;
        flush_peer(&mut b).await;
        assert_eq!(
            daemon.state().borrow().sessions[&bid].destinations[&mac().into()].metrics,
            metrics
        );
        assert!(bridge.retries.is_empty());
        drop((a, b));
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn repeated_radio_flaps_during_down_ack_keep_only_the_latest_readd() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut peer = session(&daemon, &mut events).await;
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
        for latency in 100..356 {
            bridge
                .inbound(up(Metrics {
                    latency_us: Some(latency),
                    ..Default::default()
                }))
                .await;
            bridge
                .inbound(Inbound::DestinationDown { mac: Mac(mac()) })
                .await;
        }
        bridge
            .inbound(up(Metrics {
                latency_us: Some(987),
                ..Default::default()
            }))
            .await;
        assert_eq!(
            bridge.retries.len(),
            1,
            "only the latest re-add should remain"
        );
        // An ACK can arrive between a Busy receipt and retry bookkeeping.
        let delayed_receipt = daemon
            .drop_destination(mac().into(), StatusCode::SUCCESS)
            .await;
        assert!(matches!(
            delayed_receipt,
            Err(DaemonError::CommandRejected(_))
        ));
        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        bridge.update_retries(&delayed_receipt, Retry::Drop(mac()), None);
        assert_eq!(
            bridge.retries.len(),
            1,
            "an acknowledged Down must not be retried"
        );
        fire_retries(&mut bridge);
        bridge.retry().await;
        let readded = read(&mut peer).await;
        assert_eq!(readded.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&readded).unwrap().latency,
            Duration::from_micros(987)
        );
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        assert!(bridge.retries.is_empty());
        flush_peer(&mut peer).await;
        assert_eq!(
            daemon
                .state()
                .borrow()
                .sessions
                .values()
                .next()
                .unwrap()
                .destinations[&mac().into()]
                .phase,
            dlep_daemon::DestinationPhase::Up
        );
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
    async fn in_flight_link_grant_keeps_replacement_cache_unchanged() {
        grant_during_replacement(false).await;
    }

    #[tokio::test]
    async fn queued_link_grant_keeps_replacement_cache_unchanged() {
        grant_during_replacement(true).await;
    }

    async fn grant_during_replacement(delayed_ask: bool) {
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let daemon = modem_with(Some(Arc::new(RadioLink {
            asks,
            timeout: Duration::from_secs(30),
        })))
        .await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let mut peer = session(&daemon, &mut events).await;
        bridge
            .inbound(up(Metrics {
                latency_us: Some(100),
                ..Default::default()
            }))
            .await;
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
        send(
            &mut peer,
            build_link_characteristics_request(
                mac(),
                &dlep_daemon::LinkCharacteristics {
                    latency: Some(Duration::from_micros(321)),
                    ..Default::default()
                },
            ),
        )
        .await;
        let ask = tokio::time::timeout(WAIT, queued.recv())
            .await
            .unwrap()
            .unwrap();
        let ask = if delayed_ask {
            Some(ask)
        } else {
            bridge.ask(ask).await.unwrap();
            None
        };
        bridge
            .inbound(Inbound::DestinationDown { mac: Mac(mac()) })
            .await;
        bridge
            .inbound(up(Metrics {
                latency_us: Some(900),
                ..Default::default()
            }))
            .await;
        assert!(
            bridge
                .retries
                .keys()
                .any(|(_, retry)| *retry == Retry::Drop(mac()))
        );
        if let Some(ask) = ask {
            // The backend request was queued before withdrawal, but reaches
            // the bridge only after the replacement has been reported.
            bridge.ask(ask).await.unwrap();
        }
        bridge
            .inbound(Inbound::LinkResponse {
                request: 1,
                status: Status::Success,
                text: "old request".into(),
                metrics: Some(Metrics {
                    latency_us: Some(321),
                    ..Default::default()
                }),
            })
            .await;
        let response = read(&mut peer).await;
        assert_eq!(
            response.message_type,
            MessageType::LINK_CHARACTERISTICS_RESPONSE
        );
        assert_eq!(
            extract_link_metrics(&response).unwrap().latency,
            Duration::from_micros(321)
        );
        assert_eq!(
            bridge.destinations[&mac()].metrics.latency,
            Duration::from_micros(900),
            "the old grant must not overwrite the replacement's cached metrics"
        );
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::DESTINATION_DOWN
        );
        send(
            &mut peer,
            build_destination_down_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        fire_retries(&mut bridge);
        bridge.retry().await;
        let replacement = read(&mut peer).await;
        assert_eq!(replacement.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&replacement).unwrap().latency,
            Duration::from_micros(900)
        );
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        assert!(bridge.retries.is_empty());
        // Requests for the replacement may still update its cache normally.
        send(
            &mut peer,
            build_link_characteristics_request(
                mac(),
                &dlep_daemon::LinkCharacteristics {
                    latency: Some(Duration::from_micros(444)),
                    ..Default::default()
                },
            ),
        )
        .await;
        let ask = tokio::time::timeout(WAIT, queued.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ask.0.current.latency, Duration::from_micros(900));
        bridge.ask(ask).await.unwrap();
        bridge
            .inbound(Inbound::LinkResponse {
                request: 2,
                status: Status::Success,
                text: "replacement request".into(),
                metrics: Some(Metrics {
                    latency_us: Some(444),
                    ..Default::default()
                }),
            })
            .await;
        let response = read(&mut peer).await;
        assert_eq!(
            response.message_type,
            MessageType::LINK_CHARACTERISTICS_RESPONSE
        );
        assert_eq!(
            extract_link_metrics(&response).unwrap().latency,
            Duration::from_micros(444)
        );
        assert_eq!(
            bridge.destinations[&mac()].metrics.latency,
            Duration::from_micros(444)
        );
        drop(peer);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn incompatible_radio_macs_never_enter_the_cache_or_replay() {
        let mac48 = mac();
        let mac64 = MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]);
        for (format, valid, invalid) in [
            (MacAddressFormat::Eui48, mac48, mac64),
            (MacAddressFormat::Eui64, mac64, mac48),
        ] {
            for connected in [false, true] {
                let daemon = modem_with_format(None, format).await;
                let mut events = daemon.subscribe();
                let mut bridge = bridge(&daemon);
                bridge.mac_address_format = format;
                let mut peer = if connected {
                    let peer = session(&daemon, &mut events).await;
                    let snapshot = daemon.state().borrow().clone();
                    bridge.reconcile(&snapshot).await.unwrap();
                    Some(peer)
                } else {
                    None
                };
                let report = |mac| Inbound::DestinationUp {
                    mac: Mac(mac),
                    metrics: Metrics {
                        latency_us: Some(123),
                        ..Default::default()
                    },
                    addresses: Addresses::default(),
                };
                bridge.inbound(report(invalid)).await;
                assert!(
                    bridge.destinations.is_empty(),
                    "incompatible MAC cached for {format:?} (connected: {connected})"
                );
                assert!(bridge.retries.is_empty());
                if let Some(peer) = &mut peer {
                    flush_peer(peer).await;
                }
                bridge.inbound(report(valid)).await;
                let mut peer = match peer {
                    Some(peer) => peer,
                    None => {
                        let peer = session(&daemon, &mut events).await;
                        let snapshot = daemon.state().borrow().clone();
                        bridge.reconcile(&snapshot).await.unwrap();
                        peer
                    }
                };
                let up = read(&mut peer).await;
                assert_eq!(up.message_type, MessageType::DESTINATION_UP);
                assert_eq!(
                    dlep_fsm::session_common::extract_destination_mac(&up),
                    Some(valid)
                );
                assert_eq!(
                    extract_link_metrics(&up).unwrap().latency,
                    Duration::from_micros(123)
                );
                send(
                    &mut peer,
                    build_destination_up_response(valid, StatusCode::SUCCESS),
                )
                .await;
                flush_peer(&mut peer).await;
                bridge
                    .inbound(Inbound::DestinationDown { mac: Mac(valid) })
                    .await;
                assert_eq!(
                    read(&mut peer).await.message_type,
                    MessageType::DESTINATION_DOWN
                );
                send(
                    &mut peer,
                    build_destination_down_response(valid, StatusCode::SUCCESS),
                )
                .await;
                flush_peer(&mut peer).await;
                // Removing the final valid destination must not reset the policy.
                bridge.inbound(report(invalid)).await;
                assert!(bridge.destinations.is_empty());
                assert!(bridge.retries.is_empty());
                flush_peer(&mut peer).await;
                drop(peer);
                daemon.shutdown().await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn oversized_address_updates_leave_a_replayable_cache_and_allow_recovery() {
        for connected in [false, true] {
            let daemon = modem().await;
            let mut events = daemon.subscribe();
            let mut bridge = bridge(&daemon);
            let mut peer = if connected {
                let peer = session(&daemon, &mut events).await;
                let snapshot = daemon.state().borrow().clone();
                bridge.reconcile(&snapshot).await.unwrap();
                Some(peer)
            } else {
                None
            };
            let addresses: Vec<Ipv6Addr> = (1..=3119)
                .map(|suffix| Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, suffix))
                .collect();
            let initial = Addresses {
                ipv4: vec!["192.0.2.1".parse().unwrap()],
                ipv6: addresses[..1600].to_vec(),
                ipv4_subnets: vec!["198.51.100.0/24".into()],
                ipv6_subnets: vec!["2001:db8:1::/64".into()],
            };
            bridge
                .inbound(Inbound::DestinationUp {
                    mac: Mac(mac()),
                    metrics: Metrics::default(),
                    addresses: initial.clone(),
                })
                .await;
            if let Some(peer) = &mut peer {
                assert_eq!(read(peer).await.message_type, MessageType::DESTINATION_UP);
                send(
                    peer,
                    build_destination_up_response(mac(), StatusCode::SUCCESS),
                )
                .await;
                flush_peer(peer).await;
            }
            // Each batch fits on the wire, but their accumulated Up does not.
            // Even the resulting address items fit alone: 3118 * 21 bytes.
            // Adding the MAC and mandatory metrics crosses the message limit.
            // Rejection must also leave the removals in this batch unapplied.
            bridge
                .inbound(Inbound::DestinationAddresses {
                    mac: Mac(mac()),
                    add: Addresses {
                        ipv6: addresses[1600..].to_vec(),
                        ..Default::default()
                    },
                    remove: Addresses {
                        ipv4: initial.ipv4.clone(),
                        ipv6: addresses[..1].to_vec(),
                        ipv4_subnets: initial.ipv4_subnets.clone(),
                        ipv6_subnets: initial.ipv6_subnets.clone(),
                    },
                })
                .await;
            assert_eq!(
                bridge.destinations[&mac()].addresses,
                initial.parse().unwrap(),
                "oversized address update changed the replay cache (connected: {connected})"
            );
            if let Some(peer) = &mut peer {
                // No partial update reached the existing router either.
                flush_peer(peer).await;
                let snapshot = daemon.state().borrow().clone();
                assert_eq!(
                    snapshot.sessions.values().next().unwrap().destinations[&mac().into()]
                        .addresses,
                    initial.parse().unwrap()
                );
            }
            // Making room in the same batch permits the additions again.
            bridge
                .inbound(Inbound::DestinationAddresses {
                    mac: Mac(mac()),
                    add: Addresses {
                        ipv6: addresses[1600..].to_vec(),
                        ..Default::default()
                    },
                    remove: Addresses {
                        ipv6: addresses[..300].to_vec(),
                        ..Default::default()
                    },
                })
                .await;
            let expected = DestinationAddrs {
                v6: addresses[300..].to_vec(),
                ..initial.parse().unwrap()
            };
            assert_eq!(bridge.destinations[&mac()].addresses, expected);
            if let Some(peer) = &mut peer {
                assert_eq!(
                    read(peer).await.message_type,
                    MessageType::DESTINATION_UPDATE
                );
                flush_peer(peer).await;
            }
            let mut late = session(&daemon, &mut events).await;
            let snapshot = daemon.state().borrow().clone();
            bridge.reconcile(&snapshot).await.unwrap();
            let replay = read(&mut late).await;
            assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
            assert_eq!(AddressChanges::from_message(&replay).added, expected);
            drop(late);
            drop(peer);
            daemon.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn partial_link_replies_preserve_reports_received_while_pending() {
        for session_wide in [false, true] {
            let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
            let daemon = modem_with(Some(Arc::new(RadioLink {
                asks,
                timeout: Duration::from_secs(30),
            })))
            .await;
            let mut events = daemon.subscribe();
            let mut bridge = bridge(&daemon);
            let mut peer = session(&daemon, &mut events).await;
            bridge
                .inbound(up(Metrics {
                    max_data_rate_rx_bps: Some(1000),
                    max_data_rate_tx_bps: Some(1000),
                    current_data_rate_rx_bps: Some(100),
                    current_data_rate_tx_bps: Some(700),
                    latency_us: Some(100),
                    ..Default::default()
                }))
                .await;
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
            // Exercise partial, empty, absent, denied, and invalid replies.
            for (index, (status, reply)) in [
                (
                    Status::Success,
                    Some(Metrics {
                        latency_us: Some(321),
                        ..Default::default()
                    }),
                ),
                (Status::Success, Some(Metrics::default())),
                (Status::Success, None),
                (Status::Denied, Some(Metrics::default())),
                (
                    Status::Success,
                    Some(Metrics {
                        mtu: Some(1500),
                        ..Default::default()
                    }),
                ),
            ]
            .into_iter()
            .enumerate()
            {
                send(
                    &mut peer,
                    build_link_characteristics_request(
                        mac(),
                        &dlep_daemon::LinkCharacteristics {
                            latency: Some(Duration::from_micros(321)),
                            ..Default::default()
                        },
                    ),
                )
                .await;
                let ask = tokio::time::timeout(WAIT, queued.recv())
                    .await
                    .unwrap()
                    .unwrap();
                bridge.ask(ask).await.unwrap();
                let invalid = index == 4;
                let report = Metrics {
                    max_data_rate_rx_bps: Some(800),
                    max_data_rate_tx_bps: Some(800),
                    current_data_rate_rx_bps: Some(250),
                    current_data_rate_tx_bps: Some(400),
                    latency_us: Some(900 + index as u64),
                    ..Default::default()
                };
                bridge
                    .inbound(if session_wide {
                        Inbound::SessionMetrics { metrics: report }
                    } else {
                        Inbound::DestinationUpdate {
                            mac: Mac(mac()),
                            metrics: report,
                        }
                    })
                    .await;
                assert_eq!(
                    read(&mut peer).await.message_type,
                    if session_wide {
                        MessageType::SESSION_UPDATE
                    } else {
                        MessageType::DESTINATION_UPDATE
                    }
                );
                if session_wide {
                    send(
                        &mut peer,
                        dlep_fsm::session_common::build_session_update_response(
                            StatusCode::SUCCESS,
                        ),
                    )
                    .await;
                    flush_peer(&mut peer).await;
                }
                let reported = bridge.destinations[&mac()].metrics;
                bridge
                    .inbound(Inbound::LinkResponse {
                        request: index as u64 + 1,
                        status,
                        text: "processed".into(),
                        metrics: reply,
                    })
                    .await;
                let response = read(&mut peer).await;
                assert_eq!(
                    response.message_type,
                    MessageType::LINK_CHARACTERISTICS_RESPONSE
                );
                let expected = if invalid {
                    reported
                } else {
                    reply.map_or(reported, |patch| patch.overlay(reported))
                };
                assert_eq!(extract_link_metrics(&response).unwrap(), expected);
                assert_eq!(bridge.destinations[&mac()].metrics, expected);
                let actual_status = response.data_items.iter().find_map(|item| match item {
                    dlep_core::DataItem::Status { code, text } => Some((*code, text.as_str())),
                    _ => None,
                });
                assert_eq!(
                    actual_status,
                    Some((
                        if invalid || status == Status::Denied {
                            StatusCode::REQUEST_DENIED
                        } else {
                            StatusCode::SUCCESS
                        },
                        if invalid { "" } else { "processed" },
                    ))
                );
            }
            drop(peer);
            daemon.shutdown().await.unwrap();
        }
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
                    session_id: SessionId(1),
                    answer,
                    mac: mac(),
                    current: original,
                    update_cache: true,
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
                session_id: SessionId(1),
                answer,
                mac: mac(),
                current: original,
                update_cache: true,
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
        adapter
            .out
            .as_ref()
            .unwrap()
            .send("x".repeat(1024 * 1024))
            .await
            .unwrap();
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
