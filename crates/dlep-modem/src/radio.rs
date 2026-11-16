//! External radio adapter. The modem runs one configured program and exchanges
//! JSON Lines with it: the adapter reports destinations and session metrics on
//! standard output and answers Link Characteristics Requests (RFC 8175
//! §12.18–12.19) sent to its standard input. See `doc/radio-adapter.md`.
//!
//! The adapter's destination table is kept here and replayed to every router
//! session that comes up, so destinations reported before a router connects
//! are not lost. Adapter exit, failed/stalled input, closed output, or a line
//! that does not match the protocol (see `parse_inbound`) is fatal: the modem
//! terminates its sessions so a supervisor restarts both. A known message with
//! invalid values is logged and ignored.

use std::collections::{BTreeMap, HashMap};
use std::convert::Infallible;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use dlep_core::{MacAddress, MacAddressFormat, StatusCode};
use dlep_daemon::adapter_process::{
    self, AdapterError, AdapterLines, AdapterProcess, QUEUE_SIZE, excerpt,
};
use dlep_daemon::link_control::{LinkControlFuture, LinkControlReplyFuture};
use dlep_daemon::{
    AddressChanges, CommandError, DaemonError, DaemonEvent, DaemonSnapshot, DestinationAddrs,
    DestinationEvent, DestinationId, DestinationPhase, LinkControl, LinkControlReply, LinkMetrics,
    LinkRequest, LinkResponse, ModemDaemon, PeerInfo, RadioConfig, SessionCommand, SessionPhase,
};
use dlep_ext::SessionId;
use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, broadcast, mpsc, oneshot};
use tokio::time::Instant;
use tracing::{debug, warn};

const LABEL: &str = "radio adapter";
const MAX_PENDING: usize = 64;
/// Delay before re-sending a command a session rejected as Busy.
const RETRY_DELAY: Duration = Duration::from_millis(250);

/// Destination MAC as colon-separated hex octets (EUI-48 or EUI-64).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(try_from = "String", into = "String")]
struct Mac(MacAddress);

impl TryFrom<String> for Mac {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .map(Self)
            .map_err(|e| format!("invalid MAC address {:?}: {e}", excerpt(&text)))
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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

impl From<&DestinationAddrs> for Addresses {
    fn from(addresses: &DestinationAddrs) -> Self {
        Self {
            ipv4: addresses.v4.clone(),
            ipv6: addresses.v6.clone(),
            ipv4_subnets: addresses
                .v4_subnets
                .iter()
                .map(ToString::to_string)
                .collect(),
            ipv6_subnets: addresses
                .v6_subnets
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Status {
    Success,
    Denied,
}

/// Adapter → modem. Unknown message types are ignored for forward
/// compatibility; unknown fields in known messages are fatal errors.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Inbound {
    Resync,
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
    SessionAddresses {
        #[serde(default)]
        add: Addresses,
        #[serde(default)]
        remove: Addresses,
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
    ("resync", &[]),
    ("destination_up", &["mac", "metrics", "addresses"]),
    ("destination_update", &["mac", "metrics"]),
    ("destination_addresses", &["mac", "add", "remove"]),
    ("destination_down", &["mac"]),
    ("session_metrics", &["metrics"]),
    ("session_addresses", &["add", "remove"]),
    ("link_response", &["request", "status", "text", "metrics"]),
];

const METRIC_FIELDS: &[&str] = &[
    "max_data_rate_rx_bps",
    "max_data_rate_tx_bps",
    "current_data_rate_rx_bps",
    "current_data_rate_tx_bps",
    "latency_us",
    "resources",
    "rlq_rx",
    "rlq_tx",
    "mtu",
];
const ADDRESS_FIELDS: &[&str] = &["ipv4", "ipv6", "ipv4_subnets", "ipv6_subnets"];

/// Field names allowed in an object nested under `field` in a known message.
fn nested_fields(field: &str) -> Option<&'static [&'static str]> {
    match field {
        "metrics" => Some(METRIC_FIELDS),
        "addresses" | "add" | "remove" => Some(ADDRESS_FIELDS),
        _ => None,
    }
}

impl Inbound {
    /// Check values that deserialize but that the modem cannot use.
    fn validate(&self) -> Result<()> {
        let addresses = match self {
            Inbound::DestinationUp { addresses, .. } => vec![addresses],
            Inbound::DestinationAddresses { add, remove, .. }
            | Inbound::SessionAddresses { add, remove } => vec![add, remove],
            _ => Vec::new(),
        };
        for addresses in addresses {
            addresses.parse()?;
        }
        Ok(())
    }
}

/// A known adapter message with invalid values. The bridge logs and ignores
/// it; the adapter and its other messages are unaffected.
#[derive(Debug)]
struct InvalidMessage {
    kind: String,
    reason: String,
}

impl fmt::Display for InvalidMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {} message: {}", self.kind, self.reason)
    }
}

/// Parse one adapter line.
///
/// The outer error is fatal because the adapter does not speak this
/// protocol: invalid JSON, a value that is not an object, a missing or
/// non-string `type`, or an unknown field in a known message type, including
/// its nested `metrics` and address objects. The inner error is a known
/// message whose fields fail typed deserialization or value validation, such
/// as a malformed address, subnet or MAC, an out-of-range number, a wrong
/// field type, or a missing required field; only that message is ignored.
/// Unknown message types parse as [`Inbound::Unknown`]. Serde cannot deny
/// unknown fields on an internally tagged enum, so they are checked here.
fn parse_inbound(line: &str) -> Result<Result<Inbound, InvalidMessage>> {
    let value: serde_json::Value = serde_json::from_str(line)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("message must be a JSON object"))?;
    let kind = object
        .get("type")
        .and_then(|t| t.as_str())
        .ok_or_else(|| anyhow!("message needs a string \"type\""))?;
    let Some((_, fields)) = INBOUND_FIELDS.iter().find(|(name, _)| *name == kind) else {
        return Ok(Ok(Inbound::Unknown));
    };
    for (key, field) in object {
        if key == "type" {
            continue;
        }
        if !fields.contains(&key.as_str()) {
            bail!("unknown field {:?} in {kind} message", excerpt(key));
        }
        if let (Some(nested), Some(allowed)) = (field.as_object(), nested_fields(key)) {
            if let Some(unknown) = nested.keys().find(|k| !allowed.contains(&k.as_str())) {
                bail!(
                    "unknown field {:?} in {kind} message {key}",
                    excerpt(unknown)
                );
            }
        }
    }
    let kind = kind.to_owned();
    let message = serde_json::from_value::<Inbound>(value)
        .map_err(anyhow::Error::from)
        .and_then(|message| message.validate().map(|()| message));
    Ok(message.map_err(|e| InvalidMessage {
        kind,
        reason: excerpt(&format!("{e:#}")).to_owned(),
    }))
}

/// Modem → adapter.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Outbound {
    EventGap {
        skipped: u64,
    },
    /// Authoritative membership and remote addresses, including after event loss.
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
    SessionUpdateResponse {
        session: u64,
        status: u8,
        text: String,
    },
    DestinationAnnounced {
        session: u64,
        mac: Mac,
        add: Addresses,
        remove: Addresses,
    },
    DestinationWithdrawn {
        session: u64,
        mac: Mac,
    },
    DestinationUpResponse {
        session: u64,
        mac: Mac,
        status: u8,
        text: String,
    },
    DestinationDownResponse {
        session: u64,
        mac: Mac,
        status: u8,
        text: String,
    },
    LinkRequest {
        request: u64,
        session: u64,
        peer: SocketAddr,
        mac: Mac,
        requested: Requested,
        current: Metrics,
    },
    /// The modem no longer waits for this `link_request`'s answer.
    LinkRequestCancelled {
        request: u64,
        reason: CancelReason,
    },
}

/// Why the modem stopped waiting for an adapter answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CancelReason {
    /// `link_request_timeout_ms` expired; the router was answered Request
    /// Denied with `radio adapter timed out`.
    Timeout,
    /// The requesting session ended or is terminating; no answer was sent.
    SessionDown,
    /// The daemon stopped waiting for another reason; no answer was sent.
    Abandoned,
}

#[derive(Debug, Serialize)]
struct SessionPeer {
    session: u64,
    peer: SocketAddr,
    addresses: Addresses,
}

/// A link request on its way to the bridge. The backend stops waiting for
/// the answer at `deadline`.
struct Ask {
    request: LinkRequest,
    answer: oneshot::Sender<LinkControlReply>,
    deadline: Instant,
}

/// Forwards link requests to the bridge task and bounds the adapter's answer.
struct RadioLink {
    asks: mpsc::Sender<Ask>,
    timeout: Duration,
    /// Wakes the bridge whenever a request future ends, so it can cancel a
    /// request whose answer is no longer awaited at the adapter.
    ended: Arc<Notify>,
}

/// The reply channel of a request future. Dropping it, when the future
/// completes, times out or is cancelled, closes the channel and then wakes
/// the bridge.
struct Waiting {
    response: Option<oneshot::Receiver<LinkControlReply>>,
    ended: Arc<Notify>,
}

impl Drop for Waiting {
    fn drop(&mut self) {
        self.response.take();
        self.ended.notify_one();
    }
}

impl LinkControl for RadioLink {
    fn request(&self, request: LinkRequest) -> LinkControlFuture {
        let reply = self.request_with_receipt(request);
        Box::pin(async move { reply.await.response })
    }

    fn request_with_receipt(&self, request: LinkRequest) -> LinkControlReplyFuture {
        let (answer, response) = oneshot::channel();
        let deadline = Instant::now() + self.timeout;
        let sent = self.asks.try_send(Ask {
            request,
            answer,
            deadline,
        });
        let mut waiting = Waiting {
            response: Some(response),
            ended: self.ended.clone(),
        };
        Box::pin(async move {
            if let Err(error) = sent {
                let text = match error {
                    mpsc::error::TrySendError::Full(_) => "radio adapter busy",
                    mpsc::error::TrySendError::Closed(_) => "radio adapter unavailable",
                };
                return LinkResponse::denied().with_text(text).into();
            }
            let response = waiting.response.as_mut().expect("present until dropped");
            match tokio::time::timeout_at(deadline, response).await {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => LinkResponse::denied()
                    .with_text("radio adapter unavailable")
                    .into(),
                Err(_) => {
                    warn!("radio adapter did not answer a link request in time");
                    LinkResponse::denied()
                        .with_text("radio adapter timed out")
                        .into()
                }
            }
        })
    }
}

/// A running adapter process and its I/O tasks.
pub(crate) struct Adapter {
    process: AdapterProcess,
    lines: AdapterLines,
    out: Option<mpsc::Sender<String>>,
    asks: mpsc::Receiver<Ask>,
    link: Arc<RadioLink>,
}

/// The bridge's output queue closed, which happens only when the writer task
/// ends. [`Adapter::run`] reports the writer's own error instead.
#[derive(Debug)]
struct WriterStopped;

impl fmt::Display for WriterStopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("radio adapter writer stopped")
    }
}

impl std::error::Error for WriterStopped {}

impl Adapter {
    /// Start the adapter. Its standard error is inherited for logging.
    pub(crate) fn spawn(config: &RadioConfig) -> Result<Self> {
        config.validate().map_err(|e| anyhow!(e))?;
        let (mut process, lines) = AdapterProcess::spawn(LABEL, &config.command, &config.args)
            .with_context(|| format!("starting radio adapter {}", config.command.display()))?;

        // Brief pauses can drain without growing an unbounded output backlog.
        // A stalled record fails the writer and, in turn, the adapter bridge.
        let (out, queued) = mpsc::channel(QUEUE_SIZE);
        process.start_writer(|stdin| adapter_process::write_queued(stdin, LABEL, queued));

        let (asks_tx, asks) = mpsc::channel(QUEUE_SIZE);
        Ok(Self {
            process,
            lines,
            out: Some(out),
            asks,
            link: Arc::new(RadioLink {
                asks: asks_tx,
                timeout: Duration::from_millis(config.link_request_timeout_ms.into()),
                ended: Arc::default(),
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
            session_addresses: DestinationAddrs::default(),
            pending: HashMap::new(),
            cancelled: Vec::new(),
            next_request: 1,
            retries: BTreeMap::new(),
            sessions: HashMap::new(),
            synced: false,
        };
        let lines = &mut self.lines;
        let asks = &mut self.asks;
        let ended = self.link.ended.clone();
        // Supervise I/O outside the bridge loop so a writer failure or child
        // exit also interrupts replay and command acceptance waits.
        let work = async {
            let mut state = daemon.state();
            loop {
                bridge.cancel_abandoned().await?;
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
                    line = lines.recv() => match line {
                        Some(Ok(line)) => {
                            let parsed = parse_inbound(&line).with_context(|| {
                                format!("invalid radio adapter message: {:?}", excerpt(&line))
                            })?;
                            match parsed {
                                Ok(message) => bridge.inbound(message).await,
                                Err(invalid) => warn!(
                                    "ignoring radio adapter message {:?}: {invalid}",
                                    excerpt(&line)
                                ),
                            }
                        }
                        Some(Err(e)) => return Err(e.into()),
                        None => return Err(AdapterError::OutputClosed { label: LABEL }.into()),
                    },
                    Some(ask) = asks.recv() => bridge.ask(ask).await?,
                    event = events.recv() => match event {
                        Ok(event) => bridge.event(event).await?,
                        Err(broadcast::error::RecvError::Lagged(skipped)) => bridge.event_gap(skipped).await?,
                        Err(broadcast::error::RecvError::Closed) => bail!("modem daemon stopped"),
                    },
                    () = sleep_until(next_retry), if next_retry.is_some() => bridge.retry().await,
                    // A link request future ended; the loop reports abandoned requests.
                    () = ended.notified() => {}
                }
            }
        };
        let result: Result<Infallible> = tokio::select! {
            result = work => result,
            error = self.process.failed() => Err(error.into()),
        };
        match result {
            Ok(never) => match never {},
            Err(error) if error.is::<WriterStopped>() => {
                Err(self.process.writer_error().await.into())
            }
            Err(error) => Err(error),
        }
    }

    /// Close the adapter's input, then kill it if it does not exit promptly.
    pub(crate) async fn stop(mut self) {
        self.out.take();
        self.process.stop().await;
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    tokio::time::sleep_until(deadline.expect("guarded by is_some")).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Retry {
    InitializeSession,
    Add(MacAddress),
    Drop(MacAddress),
}

struct Known {
    metrics: LinkMetrics,
    addresses: DestinationAddrs,
}

struct Pending {
    session_id: SessionId,
    answer: oneshot::Sender<LinkControlReply>,
    mac: MacAddress,
    current: LinkMetrics,
    /// False once this request's physical destination has been withdrawn.
    update_cache: bool,
    /// When the backend stops waiting for the answer.
    deadline: Instant,
}

/// Why the modem stopped waiting for `pending`, judged at `now`.
fn cancel_reason(pending: &Pending, snapshot: &DaemonSnapshot, now: Instant) -> CancelReason {
    if now >= pending.deadline {
        CancelReason::Timeout
    } else if snapshot
        .sessions
        .get(&pending.session_id)
        .is_none_or(|session| session.phase != SessionPhase::Established)
    {
        CancelReason::SessionDown
    } else {
        CancelReason::Abandoned
    }
}

struct Bridge<'a> {
    daemon: &'a ModemDaemon,
    mac_address_format: MacAddressFormat,
    out: mpsc::Sender<String>,
    destinations: BTreeMap<MacAddress, Known>,
    session_metrics: LinkMetrics,
    session_addresses: DestinationAddrs,
    pending: HashMap<u64, Pending>,
    /// Requests the modem stopped waiting for, not yet reported to the adapter.
    cancelled: Vec<(u64, CancelReason)>,
    next_request: u64,
    /// One deadline per operation and session; reports share the latest cache.
    retries: BTreeMap<(SessionId, Retry), Instant>,
    sessions: HashMap<SessionId, (PeerInfo, DestinationAddrs)>,
    synced: bool,
}

impl Bridge<'_> {
    async fn send(&self, message: &Outbound) -> Result<()> {
        let line = serde_json::to_string(message).expect("serializable message");
        self.out.send(line).await.map_err(|_| WriterStopped.into())
    }

    /// Move requests matching `abandoned` from `pending` to `cancelled`.
    fn abandon_where(&mut self, snapshot: &DaemonSnapshot, abandoned: impl Fn(&Pending) -> bool) {
        let now = Instant::now();
        let mut requests: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| abandoned(pending))
            .map(|(&request, _)| request)
            .collect();
        requests.sort_unstable();
        for request in requests {
            let pending = self.pending.remove(&request).expect("listed request");
            self.cancelled
                .push((request, cancel_reason(&pending, snapshot, now)));
        }
    }

    /// Tell the adapter about requests whose answer is no longer awaited:
    /// timed out, or abandoned when their session ended. This releases their
    /// capacity, and a late answer then finds no pending request.
    async fn cancel_abandoned(&mut self) -> Result<()> {
        if self
            .pending
            .values()
            .any(|pending| pending.answer.is_closed())
        {
            let snapshot = self.daemon.state().borrow().clone();
            self.abandon_where(&snapshot, |pending| pending.answer.is_closed());
        }
        for (request, reason) in std::mem::take(&mut self.cancelled) {
            self.send(&Outbound::LinkRequestCancelled { request, reason })
                .await?;
        }
        Ok(())
    }

    async fn inbound(&mut self, message: Inbound) {
        match message {
            // The loop reconciles retained state before reading the next line.
            // Keep known sessions so refreshing membership cannot replay over
            // a withdrawal or session-specific link grant.
            Inbound::Resync => self.synced = false,
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
                let result = self.daemon.queue_session_metrics(metrics).await;
                if self.accepted("session metrics", &result) {
                    self.session_metrics = metrics;
                    // Session Update carries all mandatory metrics and every
                    // supplied optional metric to existing destinations too.
                    let update = Metrics::from_link(&metrics);
                    for known in self.destinations.values_mut() {
                        known.metrics = update.overlay(known.metrics);
                    }
                }
            }
            Inbound::SessionAddresses { add, remove } => {
                let changes = match (add.parse(), remove.parse()) {
                    (Ok(added), Ok(removed)) => AddressChanges { added, removed }.canonical(),
                    (Err(e), _) | (_, Err(e)) => {
                        warn!("radio adapter session addresses rejected: {e:#}");
                        return;
                    }
                };
                // Validate before lenient application can collapse duplicates.
                if let Err(status) = changes.validate() {
                    warn!(?status, "radio adapter session address changes rejected");
                    return;
                }
                let mut addresses = self.session_addresses.clone();
                changes.apply_lenient(&mut addresses);
                // Bound the complete replay set, even without connected routers.
                // The effective replacement may need multiple wire messages.
                if let Err(e) = self.daemon.validate_session_addresses(&addresses) {
                    warn!("radio adapter session addresses rejected: {e}");
                    return;
                }
                self.session_addresses = addresses;
                let snapshot = self.daemon.state().borrow().clone();
                for (&session_id, session) in &snapshot.sessions {
                    if session.phase == SessionPhase::Established {
                        let result = self
                            .daemon
                            .set_session_addresses(session_id, self.session_addresses.clone())
                            .await;
                        self.accepted("session addresses", &result);
                    }
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
                        "radio adapter answered an unknown or cancelled link request"
                    );
                    return;
                };
                if pending.answer.is_closed() {
                    // The cancellation notice follows; the answer is unused.
                    debug!(request, "radio adapter answered an expired link request");
                    let snapshot = self.daemon.state().borrow().clone();
                    let reason = cancel_reason(&pending, &snapshot, Instant::now());
                    self.cancelled.push((request, reason));
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
                        let _ = pending.answer.send(LinkResponse::denied().into());
                        return;
                    }
                }
                let response = LinkResponse {
                    status: match status {
                        Status::Success => StatusCode::SUCCESS,
                        Status::Denied => StatusCode::REQUEST_DENIED,
                    },
                    text,
                    metrics,
                };
                // The status text shares the wire budget with the complete
                // metric set. A valid JSON line can still exceed that budget.
                if let Err(e) =
                    self.daemon
                        .validate_link_response(pending.mac.into(), &response, &current)
                {
                    warn!(request, "radio adapter link response rejected: {e}");
                    let _ = pending.answer.send(LinkResponse::denied().into());
                    return;
                }
                let (receipt, accepted) = oneshot::channel();
                if pending
                    .answer
                    .send(LinkControlReply {
                        response,
                        receipt: Some(receipt),
                    })
                    .is_err()
                {
                    return;
                }
                // Serialize later radio reports after session acceptance, not
                // merely delivery to the backend future. A rejected or lost
                // response must not poison the replay cache.
                match accepted.await {
                    Ok(Ok(())) => {
                        if let (Some(metrics), Some(known)) =
                            (cached, self.destinations.get_mut(&pending.mac))
                        {
                            known.metrics = metrics;
                        }
                    }
                    Ok(Err(error)) => {
                        debug!(request, ?error, "radio link reply rejected by session")
                    }
                    Err(_) => debug!(
                        request,
                        "radio link reply acceptance unknown; cache unchanged"
                    ),
                }
            }
            Inbound::Unknown => debug!("ignoring unknown radio adapter message type"),
        }
    }

    async fn ask(&mut self, ask: Ask) -> Result<()> {
        let Ask {
            request,
            mut answer,
            deadline,
        } = ask;
        // Answers that timed out leave closed senders behind.
        self.cancel_abandoned().await?;
        if answer.is_closed() {
            return Ok(());
        }
        if self.pending.len() >= MAX_PENDING {
            let _ = answer.send(
                LinkResponse::denied()
                    .with_text("radio adapter busy")
                    .into(),
            );
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
                deadline,
            },
        );
        Ok(())
    }

    /// Reconcile membership and peer addresses from retained runtime state,
    /// never transient events that can lag behind this snapshot.
    /// Replay only for a new session; replaying existing sessions would undo a
    /// router's withdrawal or overwrite a session-specific link-control grant.
    async fn reconcile(&mut self, snapshot: &DaemonSnapshot) -> Result<()> {
        let sessions: HashMap<_, _> = snapshot
            .sessions
            .iter()
            .map(|(id, session)| (*id, (session.peer.clone(), session.peer_addresses.clone())))
            .collect();
        self.retries.retain(|(id, _), _| {
            snapshot
                .sessions
                .get(id)
                .is_some_and(|session| session.phase == SessionPhase::Established)
        });
        self.abandon_where(snapshot, |pending| {
            !snapshot.sessions.contains_key(&pending.session_id) || pending.answer.is_closed()
        });
        self.cancel_abandoned().await?;
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
            .map(|(id, (peer, addresses))| SessionPeer {
                session: id.0,
                peer: peer.addr,
                addresses: addresses.into(),
            })
            .collect();
        peers.sort_by_key(|peer| peer.session);
        self.send(&Outbound::SessionSync { sessions: peers })
            .await?;
        self.sessions = sessions;
        self.synced = true;
        Ok(())
    }

    async fn event_gap(&mut self, skipped: u64) -> Result<()> {
        warn!(
            skipped,
            "radio bridge missed transient notices; refreshing adapter membership and addresses"
        );
        self.send(&Outbound::EventGap { skipped }).await?;
        // Force a membership notice even if it has not changed, retaining our
        // known sessions so recovery cannot replay over withdrawals or grants.
        // Read after sending the marker: output pressure can delay this step.
        self.synced = false;
        let snapshot = self.daemon.state().borrow().clone();
        self.reconcile(&snapshot).await
    }

    async fn replay_session(
        &mut self,
        session_id: SessionId,
        session: &dlep_daemon::SessionSnapshot,
    ) {
        if self.session_metrics != session.metrics {
            // Preserve live destination values in the session task; this
            // membership snapshot may predate a completed link-control grant.
            let result = self
                .daemon
                .send_command_to(
                    session_id,
                    SessionCommand::SessionDefaults {
                        metrics: self.session_metrics,
                    },
                )
                .await;
            self.accepted("session metrics replay", &result);
            self.update_retries(&result, Retry::InitializeSession, Some(session_id));
            if result.is_err() {
                return;
            }
        }
        if self.session_addresses != session.local_addresses {
            // The session owns coalescing behind defaults or an earlier update.
            let result = self
                .daemon
                .set_session_addresses(session_id, self.session_addresses.clone())
                .await;
            self.accepted("session addresses replay", &result);
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
            DaemonEvent::Destination {
                session_id,
                event: DestinationEvent::DownResponse { id, status, text },
                ..
            } => {
                // A delayed completion can refer to an earlier incarnation.
                // Its removal is already reflected in retained session state.
                self.send(&Outbound::DestinationDownResponse {
                    session: session_id.0,
                    mac: Mac(id.0),
                    status: status.0,
                    text,
                })
                .await?
            }
            DaemonEvent::SessionUpdateResponse {
                session_id,
                status,
                text,
                ..
            } => {
                self.send(&Outbound::SessionUpdateResponse {
                    session: session_id.0,
                    status: status.0,
                    text,
                })
                .await?
            }
            DaemonEvent::Destination {
                session_id,
                event: DestinationEvent::Down { id, .. },
                ..
            } => {
                // On modems this event reports a router withdrawing interest.
                // Retain the physical destination for other routers and replay.
                self.send(&Outbound::DestinationWithdrawn {
                    session: session_id.0,
                    mac: Mac(id.0),
                })
                .await?
            }
            DaemonEvent::Destination {
                session_id,
                event: DestinationEvent::UpResponse { id, status, text },
                ..
            } => {
                self.send(&Outbound::DestinationUpResponse {
                    session: session_id.0,
                    mac: Mac(id.0),
                    status: status.0,
                    text,
                })
                .await?
            }
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
                event:
                    DestinationEvent::Announced {
                        id,
                        requested_addresses,
                    },
                ..
            } => {
                self.send(&Outbound::DestinationAnnounced {
                    session: session_id.0,
                    mac: Mac(id.0),
                    add: (&requested_addresses.added).into(),
                    remove: (&requested_addresses.removed).into(),
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
    use dlep_daemon::adapter_process::{MAX_LINE, STOP_GRACE};
    use dlep_fsm::session_common::{
        build_destination_down_response, build_destination_up_response,
        build_link_characteristics_request, build_session_update_response, extract_link_metrics,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        session_with_addresses(daemon, events, DestinationAddrs::default()).await
    }

    async fn session_with_addresses(
        daemon: &ModemDaemon,
        events: &mut broadcast::Receiver<DaemonEvent>,
        addresses: DestinationAddrs,
    ) -> TcpStream {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        dlep_net::gtsm::configure_tcp(&socket, false, true).unwrap();
        let mut peer = socket.connect(daemon.local_addr()).await.unwrap();
        let mut router = dlep_fsm::session_router::RouterSessionFsm::new();
        for action in router.step(dlep_fsm::FsmEvent::TcpConnected) {
            if let dlep_fsm::FsmAction::SendMessage(message) = action {
                let changes = AddressChanges {
                    added: addresses.clone(),
                    removed: Default::default(),
                };
                send(&mut peer, changes.append_to(message)).await;
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
            session_addresses: DestinationAddrs::default(),
            pending: HashMap::new(),
            cancelled: Vec::new(),
            next_request: 1,
            retries: BTreeMap::new(),
            sessions: HashMap::new(),
            synced: false,
        }
    }

    fn mac() -> MacAddress {
        MacAddress::new_eui48([2, 0, 0, 0, 0, 1])
    }

    fn ask(answer: oneshot::Sender<LinkControlReply>) -> Ask {
        Ask {
            request: link_request(),
            answer,
            deadline: Instant::now() + WAIT,
        }
    }

    fn parsed(line: &str) -> Inbound {
        parse_inbound(line).unwrap().unwrap()
    }

    fn notice_json(line: Option<String>) -> serde_json::Value {
        serde_json::from_str(&line.expect("notice")).unwrap()
    }

    fn link_request() -> LinkRequest {
        LinkRequest {
            session_id: SessionId(1),
            peer: PeerInfo {
                secured_medium: None,
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
    async fn radio_link_rejects_queue_overflow_and_times_out_queued_requests() {
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let link = RadioLink {
            asks,
            timeout: Duration::from_millis(100),
            ended: Arc::default(),
        };
        let requests: Vec<_> = (0..QUEUE_SIZE)
            .map(|_| link.request(link_request()))
            .collect();
        let full = link.request(link_request()).await;
        assert_eq!(full, LinkResponse::denied().with_text("radio adapter busy"));
        assert_eq!(queued.len(), QUEUE_SIZE);
        drop(requests);
        while let Ok(ask) = queued.try_recv() {
            assert!(ask.answer.is_closed());
        }
        let expired = link.request(link_request()).await;
        assert_eq!(
            expired,
            LinkResponse::denied().with_text("radio adapter timed out")
        );
        assert!(queued.recv().await.unwrap().answer.is_closed());
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
            bridge.ask(ask(answer)).await.unwrap();
            replies.push(response);
            let message: serde_json::Value =
                serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
            assert_eq!(message["type"], "link_request");
        }
        let (answer, response) = oneshot::channel();
        bridge.ask(ask(answer)).await.unwrap();
        assert_eq!(
            response.await.unwrap().response,
            LinkResponse::denied().with_text("radio adapter busy")
        );
        assert_eq!(bridge.pending.len(), MAX_PENDING);
        assert!(notices.try_recv().is_err());
        drop(replies.pop());
        let (answer, mut response) = oneshot::channel();
        bridge.ask(ask(answer)).await.unwrap();
        assert!(response.try_recv().is_err());
        assert_eq!(bridge.pending.len(), MAX_PENDING);
        // The abandoned request is cancelled at the adapter before the next one.
        assert_eq!(
            notice_json(notices.try_recv().ok()),
            serde_json::json!({"type":"link_request_cancelled", "request":MAX_PENDING, "reason":"session_down"})
        );
        assert_eq!(notice_json(notices.try_recv().ok())["type"], "link_request");
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
            let request = bridge.ask(ask(answer));
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
        bridge.ask(ask(answer)).await.unwrap();
        assert!(bridge.pending.is_empty());
        assert!(notices.try_recv().is_err());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn expired_link_requests_are_cancelled_at_the_adapter_and_late_answers_ignored() {
        let daemon = modem().await;
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let link = RadioLink {
            asks,
            timeout: Duration::from_millis(50),
            ended: Arc::default(),
        };
        let late_answer = |request: &serde_json::Value| {
            parsed(&format!(
                r#"{{"type":"link_response","request":{request},"status":"success","metrics":{{"latency_us":1}}}}"#
            ))
        };
        // The answer arrives after the bridge reported the cancellation, or
        // between the timeout and the bridge noticing it.
        for answer_before_sweep in [false, true] {
            let reply = link.request(link_request());
            bridge.ask(queued.recv().await.unwrap()).await.unwrap();
            let request = notice_json(notices.try_recv().ok());
            assert_eq!(request["type"], "link_request");
            assert_eq!(
                reply.await,
                LinkResponse::denied().with_text("radio adapter timed out")
            );
            // The ended request future wakes the bridge loop.
            tokio::time::timeout(WAIT, link.ended.notified())
                .await
                .unwrap();
            if answer_before_sweep {
                bridge.inbound(late_answer(&request["request"])).await;
                assert!(notices.try_recv().is_err());
            }
            bridge.cancel_abandoned().await.unwrap();
            assert_eq!(
                notice_json(notices.try_recv().ok()),
                serde_json::json!({"type":"link_request_cancelled",
                    "request":request["request"], "reason":"timeout"})
            );
            assert!(bridge.pending.is_empty());
            bridge.inbound(late_answer(&request["request"])).await;
            bridge.cancel_abandoned().await.unwrap();
            assert!(notices.try_recv().is_err());
        }
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
    async fn destination_up_outcomes_reach_radio_without_changing_replay() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        bridge
            .inbound(up(Metrics {
                latency_us: Some(321),
                ..Default::default()
            }))
            .await;
        let original_metrics = bridge.destinations[&mac()].metrics;
        let original_addresses = bridge.destinations[&mac()].addresses.clone();
        let mut peers = Vec::new();
        let mut sessions = Vec::new();
        for status in [StatusCode::NOT_INTERESTED, StatusCode::SUCCESS] {
            let mut peer = session(&daemon, &mut events).await;
            let snapshot = daemon.state().borrow().clone();
            bridge.reconcile(&snapshot).await.unwrap();
            let replay = read(&mut peer).await;
            assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
            assert_eq!(extract_link_metrics(&replay), Some(original_metrics));
            let mut text = "router says: dostęp ✓\n\"response\"".to_owned();
            if status == StatusCode::NOT_INTERESTED {
                // A valid wire status can exceed the adapter input limit once
                // escaped for output; preserve the complete peer explanation.
                text.push_str(&"\n".repeat(MAX_LINE / 2));
            }
            send(
                &mut peer,
                Message::new(MessageType::DESTINATION_UP_RESPONSE)
                    .with_item(dlep_core::DataItem::MacAddress(mac()))
                    .with_item(dlep_core::DataItem::Status {
                        code: status,
                        text: text.clone(),
                    }),
            )
            .await;
            let event = tokio::time::timeout(WAIT, async {
                loop {
                    let event = events.recv().await.unwrap();
                    if matches!(
                        event,
                        DaemonEvent::Destination {
                            event: DestinationEvent::UpResponse { .. },
                            ..
                        }
                    ) {
                        break event;
                    }
                }
            })
            .await
            .unwrap();
            let DaemonEvent::Destination { session_id, .. } = &event else {
                unreachable!()
            };
            let session_id = *session_id;
            assert!(!sessions.contains(&session_id));
            sessions.push(session_id);
            bridge.event(event).await.unwrap();
            let reply = tokio::time::timeout(WAIT, async {
                loop {
                    let line = notices.recv().await.unwrap();
                    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if value["type"] == "destination_up_response" {
                        if status == StatusCode::NOT_INTERESTED {
                            assert!(line.len() > MAX_LINE);
                        }
                        break value;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                reply,
                serde_json::json!({
                    "type":"destination_up_response", "session":session_id.0,
                    "mac":mac().to_string(), "status":status.0, "text":text,
                })
            );
            assert_eq!(bridge.destinations[&mac()].metrics, original_metrics);
            assert_eq!(bridge.destinations[&mac()].addresses, original_addresses);
            peers.push(peer);
        }
        drop(peers);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn session_update_outcomes_reach_radio_without_changing_replay() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(321),
                    ..Default::default()
                },
            })
            .await;
        bridge.inbound(up(Metrics::default())).await;
        let expected = bridge.session_metrics;
        let mut peers = Vec::new();
        let mut sessions = Vec::new();
        for status in [
            StatusCode::REQUEST_DENIED,
            StatusCode(42),
            StatusCode::SUCCESS,
        ] {
            let mut peer = session(&daemon, &mut events).await;
            let snapshot = daemon.state().borrow().clone();
            bridge.reconcile(&snapshot).await.unwrap();
            let update = read(&mut peer).await;
            assert_eq!(update.message_type, MessageType::SESSION_UPDATE);
            assert_eq!(extract_link_metrics(&update), Some(expected));
            let replay = read(&mut peer).await;
            assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
            assert_eq!(extract_link_metrics(&replay), Some(expected));
            // Escaping a valid wire response may exceed the adapter input limit.
            let text = format!("router: dostęp ✓\"{}", "\n".repeat(MAX_LINE / 2));
            send(
                &mut peer,
                Message::new(MessageType::SESSION_UPDATE_RESPONSE).with_item(
                    dlep_core::DataItem::Status {
                        code: status,
                        text: text.clone(),
                    },
                ),
            )
            .await;
            let event = tokio::time::timeout(WAIT, events.recv())
                .await
                .unwrap()
                .unwrap();
            let DaemonEvent::SessionUpdateResponse { session_id, .. } = &event else {
                panic!("unexpected event: {event:?}");
            };
            let sid = *session_id;
            assert!(!sessions.contains(&sid));
            sessions.push(sid);
            bridge.event(event).await.unwrap();
            let value = tokio::time::timeout(WAIT, async {
                loop {
                    let line = notices.recv().await.unwrap();
                    let value: serde_json::Value = serde_json::from_str(&line).unwrap();
                    if value["type"] == "session_update_response" {
                        assert!(line.len() > MAX_LINE);
                        break value;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(
                value,
                serde_json::json!({
                    "type":"session_update_response", "session":sid.0, "status":status.0, "text":text,
                })
            );
            assert_eq!(bridge.session_metrics, expected);
            assert_eq!(bridge.destinations[&mac()].metrics, expected);
            peers.push(peer);
        }
        drop(peers);
        daemon.shutdown().await.unwrap();
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
        for i in 0..301 {
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
        flush_peer(&mut peer).await;
        let Err(broadcast::error::RecvError::Lagged(skipped)) = lagged.recv().await else {
            panic!("expected real event loss");
        };
        let snapshot = daemon.state().borrow().clone();
        let session_id = *snapshot.sessions.keys().next().unwrap();
        bridge.event_gap(skipped).await.unwrap();
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
        let gap: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(
            gap,
            serde_json::json!({"type":"event_gap", "skipped":skipped})
        );
        let notice: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(notice["type"], "session_up");
        let sync: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(sync["type"], "session_sync");
        assert_eq!(sync["sessions"][0]["session"], session_id.0);
        assert_eq!(
            sync["sessions"][0]["addresses"],
            serde_json::json!({
                "ipv4":["192.0.2.2"],"ipv6":[],"ipv4_subnets":[],"ipv6_subnets":[]
            })
        );

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
        // A gap forces the same membership to be sent again without replay.
        bridge.event_gap(7).await.unwrap();
        let gap: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(gap, serde_json::json!({"type":"event_gap", "skipped":7}));
        let repeated: serde_json::Value =
            serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(repeated, sync);
        assert!(notices.try_recv().is_err());
        // Any replay sent to the withdrawn destination would precede this ACK.
        flush_peer(&mut peer).await;
        // Explicit refresh uses the same reconciliation without reporting loss.
        bridge.inbound(parsed(r#"{"type":"resync"}"#)).await;
        assert!(!bridge.synced);
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let repeated: serde_json::Value =
            serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(repeated, sync);
        assert!(notices.try_recv().is_err());
        flush_peer(&mut peer).await;
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
                deadline: Instant::now() + WAIT,
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
        assert_eq!(
            notice_json(notices.try_recv().ok()),
            serde_json::json!({"type":"link_request_cancelled", "request":999, "reason":"session_down"})
        );
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
    async fn session_sync_recovers_peer_addresses_without_replaying_stale_events() {
        let addresses = |n| DestinationAddrs {
            v4: vec![format!("192.0.2.{n}").parse().unwrap()],
            v6: vec![format!("2001:db8::{n}").parse().unwrap()],
            v4_subnets: vec![format!("198.51.{n}.7/24").parse().unwrap()],
            v6_subnets: vec![format!("2001:db8:{n}::7/64").parse().unwrap()],
        };
        let expected = |n| {
            serde_json::json!({"ipv4":[format!("192.0.2.{n}")], "ipv6":[format!("2001:db8::{n}")],
            "ipv4_subnets":[format!("198.51.{n}.0/24")], "ipv6_subnets":[format!("2001:db8:{n}::/64")]})
        };
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut peer = session_with_addresses(&daemon, &mut events, addresses(1)).await;
        let mut bridge = bridge(&daemon);
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
        let initial = daemon.state().borrow().clone();
        let sid = *initial.sessions.keys().next().unwrap();
        bridge.reconcile(&initial).await.unwrap();
        let up: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(up["type"], "session_up");
        let sync: serde_json::Value = serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(
            sync,
            serde_json::json!({"type":"session_sync","sessions":[{
            "session":sid.0,"peer":peer.local_addr().unwrap(),"addresses":expected(1)}]})
        );
        bridge.reconcile(&initial).await.unwrap();
        assert!(notices.try_recv().is_err());

        // Coalesce multiple real updates while the bridge does not consume its
        // event stream. The retained state, not older events, determines output.
        let mut stale = daemon.subscribe();
        for (added, removed) in [
            (addresses(2), addresses(1)),
            (DestinationAddrs::default(), addresses(2)),
        ] {
            send(
                &mut peer,
                AddressChanges { added, removed }
                    .append_to(Message::new(MessageType::SESSION_UPDATE)),
            )
            .await;
            assert_eq!(
                read(&mut peer).await.message_type,
                MessageType::SESSION_UPDATE_RESPONSE
            );
        }
        flush_peer(&mut peer).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let cleared: serde_json::Value =
            serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(
            cleared["sessions"][0]["addresses"],
            serde_json::json!({"ipv4":[],"ipv6":[],"ipv4_subnets":[],"ipv6_subnets":[]})
        );
        assert!(notices.try_recv().is_err());
        while let Ok(event) = stale.try_recv() {
            bridge.event(event).await.unwrap();
        }
        assert!(
            notices.try_recv().is_err(),
            "old address events cannot overwrite a newer snapshot"
        );

        // A gap marker blocked on output must refresh addresses after capacity
        // becomes available, even though membership stays unchanged.
        let (out, mut notices) = mpsc::channel(1);
        out.send("occupied".into()).await.unwrap();
        bridge.out = out;
        let (result, refreshed) = tokio::time::timeout(WAIT, async {
            tokio::join!(biased;
                bridge.event_gap(9),
                async {
                    send(&mut peer, AddressChanges { added: addresses(3), removed: Default::default() }.append_to(Message::new(MessageType::SESSION_UPDATE))).await;
                    assert_eq!(read(&mut peer).await.message_type, MessageType::SESSION_UPDATE_RESPONSE);
                    flush_peer(&mut peer).await;
                    assert_eq!(notices.recv().await.unwrap(), "occupied");
                    let gap: serde_json::Value = serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
                    assert_eq!(gap, serde_json::json!({"type":"event_gap","skipped":9}));
                    serde_json::from_str::<serde_json::Value>(&notices.recv().await.unwrap()).unwrap()
                }
            )
        }).await.unwrap();
        result.unwrap();
        assert_eq!(refreshed["sessions"][0]["addresses"], expected(3));
        bridge.inbound(Inbound::Resync).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let repeated: serde_json::Value =
            serde_json::from_str(&notices.try_recv().unwrap()).unwrap();
        assert_eq!(repeated, refreshed);
        assert!(notices.try_recv().is_err());

        // Multiple legal wire updates can accumulate a snapshot larger than
        // the adapter input-line cap. Modem output must preserve it in full.
        let large: Vec<Ipv6Addr> = (1..=3600)
            .map(|n| {
                format!("2001:db8:aaaa:bbbb:cccc:dddd:eeee:{n:x}")
                    .parse()
                    .unwrap()
            })
            .collect();
        for chunk in large.chunks(1800) {
            send(
                &mut peer,
                AddressChanges {
                    added: DestinationAddrs {
                        v6: chunk.to_vec(),
                        ..Default::default()
                    },
                    removed: Default::default(),
                }
                .append_to(Message::new(MessageType::SESSION_UPDATE)),
            )
            .await;
            assert_eq!(
                read(&mut peer).await.message_type,
                MessageType::SESSION_UPDATE_RESPONSE
            );
        }
        flush_peer(&mut peer).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let line = notices.try_recv().unwrap();
        assert!(line.len() > MAX_LINE);
        let sync: serde_json::Value = serde_json::from_str(&line).unwrap();
        let expected: Vec<_> = std::iter::once("2001:db8::3".to_string())
            .chain(large.iter().map(ToString::to_string))
            .collect();
        assert_eq!(
            sync["sessions"][0]["addresses"]["ipv6"],
            serde_json::json!(expected)
        );
        // No replay writes should precede the acknowledgement used as a barrier.
        flush_peer(&mut peer).await;
        drop(peer);
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn event_gap_refreshes_membership_after_output_backpressure() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let peer = session(&daemon, &mut events).await;
        let mut bridge = bridge(&daemon);
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(bridge.sessions.len(), 1);
        let (out, mut notices) = mpsc::channel(1);
        out.send("occupied".into()).await.unwrap();
        bridge.out = out;
        let mut state = daemon.state();
        let (result, refreshed) = tokio::time::timeout(WAIT, async {
            tokio::join!(biased;
                bridge.event_gap(17),
                async {
                    // The gap marker is now blocked behind the occupied slot.
                    // Remove the session before letting the writer proceed.
                    drop(peer);
                    while !state.borrow_and_update().sessions.is_empty() {
                        state.changed().await.unwrap();
                    }
                    assert_eq!(notices.recv().await.unwrap(), "occupied");
                    let gap: serde_json::Value = serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
                    assert_eq!(gap, serde_json::json!({"type":"event_gap", "skipped":17}));
                    serde_json::from_str::<serde_json::Value>(&notices.recv().await.unwrap()).unwrap()
                }
            )
        }).await.unwrap();
        result.unwrap();
        assert_eq!(
            refreshed,
            serde_json::json!({"type":"session_sync", "sessions":[]})
        );
        assert!(bridge.sessions.is_empty());
        assert!(bridge.synced);
        assert!(notices.try_recv().is_err());
        // Consecutive gaps still delimit unknown outcomes with an empty sync.
        let (out, mut notices) = mpsc::channel(2);
        bridge.out = out;
        bridge.event_gap(1).await.unwrap();
        let gap: serde_json::Value = serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
        assert_eq!(gap, serde_json::json!({"type":"event_gap", "skipped":1}));
        let sync: serde_json::Value = serde_json::from_str(&notices.recv().await.unwrap()).unwrap();
        assert_eq!(sync, refreshed);
        drop(notices);
        assert!(bridge.event_gap(2).await.is_err());
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stale_replay_snapshot_cannot_overwrite_a_completed_link_grant() {
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let daemon = modem_with(Some(Arc::new(RadioLink {
            asks,
            timeout: Duration::from_secs(30),
            ended: Arc::default(),
        })))
        .await;
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
        send(
            &mut peer,
            build_destination_up_response(mac(), StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        // The backend can complete while replay still holds an older snapshot.
        let stale = daemon.state().borrow().clone();
        let sid = *stale.sessions.keys().next().unwrap();
        send(
            &mut peer,
            build_link_characteristics_request(
                mac(),
                &dlep_daemon::LinkCharacteristics {
                    latency: Some(Duration::from_micros(999)),
                    ..Default::default()
                },
            ),
        )
        .await;
        let ask = tokio::time::timeout(WAIT, queued.recv())
            .await
            .unwrap()
            .unwrap();
        let request = bridge.next_request;
        bridge.ask(ask).await.unwrap();
        bridge
            .inbound(Inbound::LinkResponse {
                request,
                status: Status::Success,
                text: String::new(),
                metrics: Some(Metrics {
                    latency_us: Some(999),
                    ..Default::default()
                }),
            })
            .await;
        let response = read(&mut peer).await;
        assert_eq!(
            response.message_type,
            MessageType::LINK_CHARACTERISTICS_RESPONSE
        );
        let granted = extract_link_metrics(&response).unwrap();
        assert_eq!(granted.latency, Duration::from_micros(999));
        flush_peer(&mut peer).await;
        bridge.reconcile(&stale).await.unwrap();
        assert_eq!(
            daemon.state().borrow().sessions[&sid].destinations[&mac().into()].metrics,
            granted,
            "replay must preserve the accepted grant, not restore its old snapshot"
        );
        let defaults = read(&mut peer).await;
        assert_eq!(defaults.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&defaults).unwrap().latency,
            Duration::from_micros(42)
        );
        let correction = read(&mut peer).await;
        assert_eq!(correction.message_type, MessageType::DESTINATION_UPDATE);
        assert_eq!(extract_link_metrics(&correction), Some(granted));
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            read(&mut late).await.message_type,
            MessageType::SESSION_UPDATE
        );
        let replay = read(&mut late).await;
        assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
        assert_eq!(extract_link_metrics(&replay), Some(granted));
        drop((peer, late));
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

        bridge
            .inbound(Inbound::SessionAddresses {
                add: Addresses {
                    ipv4: vec!["192.0.2.5".parse().unwrap()],
                    ..Default::default()
                },
                remove: Default::default(),
            })
            .await;
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
        let (out, mut notices) = mpsc::channel(QUEUE_SIZE);
        bridge.out = out;
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

        let text = format!("router: dostęp ✓\"{}", "\n".repeat(MAX_LINE / 2));
        send(
            &mut peer,
            Message::new(MessageType::DESTINATION_DOWN_RESPONSE)
                .with_item(dlep_core::DataItem::MacAddress(mac()))
                .with_item(dlep_core::DataItem::Status {
                    code: StatusCode::REQUEST_DENIED,
                    text: text.clone(),
                }),
        )
        .await;
        flush_peer(&mut peer).await;
        let completion = tokio::time::timeout(WAIT, async {
            loop {
                let event = events.recv().await.unwrap();
                if matches!(
                    event,
                    DaemonEvent::Destination {
                        event: DestinationEvent::DownResponse { .. },
                        ..
                    }
                ) {
                    break event;
                }
            }
        })
        .await
        .unwrap();
        let DaemonEvent::Destination { session_id, .. } = &completion else {
            unreachable!()
        };
        let sid = *session_id;
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
        // Deliver the earlier incarnation's completion after the replacement
        // is already on the wire. It must not erase or change the new cache.
        bridge.event(completion).await.unwrap();
        let line = notices.recv().await.unwrap();
        assert!(line.len() > MAX_LINE);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&line).unwrap(),
            serde_json::json!({
                "type":"destination_down_response", "session":sid.0, "mac":mac().to_string(),
                "status":StatusCode::REQUEST_DENIED.0, "text":text,
            })
        );
        assert_eq!(
            bridge.destinations[&mac()].metrics.latency,
            Duration::from_micros(1234)
        );
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let replay = read(&mut late).await;
        assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&replay).unwrap().latency,
            Duration::from_micros(1234)
        );
        drop((peer, late));
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
    async fn deferred_session_metrics_preserve_a_later_destination_report() {
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
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        assert_eq!(
            read(&mut peer).await.message_type,
            MessageType::SESSION_UPDATE
        );
        let correction = read(&mut peer).await;
        assert_eq!(correction.message_type, MessageType::DESTINATION_UPDATE);
        assert_eq!(
            extract_link_metrics(&correction).unwrap().latency,
            Duration::from_micros(999)
        );
        let snapshot = daemon.state().borrow().clone();
        let state = snapshot.sessions.values().next().unwrap();
        assert_eq!(state.metrics.latency, Duration::from_micros(200));
        assert_eq!(
            state.destinations[&mac().into()].metrics.latency,
            Duration::from_micros(999)
        );
        assert_eq!(
            bridge.destinations[&mac()].metrics,
            state.destinations[&mac().into()].metrics
        );
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            read(&mut late).await.message_type,
            MessageType::SESSION_UPDATE
        );
        let replay = read(&mut late).await;
        assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&replay),
            Some(bridge.destinations[&mac()].metrics)
        );
        drop((peer, late));
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn busy_metric_reports_coalesce_into_one_pending_update_with_the_latest_values() {
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
        for latency in 101..=612 {
            bridge
                .inbound(Inbound::SessionMetrics {
                    metrics: Metrics {
                        latency_us: Some(latency),
                        ..Default::default()
                    },
                })
                .await;
        }
        assert!(bridge.retries.is_empty(), "session owns coalesced metrics");
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
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
    async fn completed_metric_queue_does_not_overwrite_later_destination_reports() {
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
        assert!(bridge.retries.is_empty());
        send(
            &mut peer,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
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
        // Once the queue drains, a new report starts its own transaction.
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
    async fn queued_metric_reports_preserve_each_sessions_later_values() {
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
        assert!(bridge.retries.is_empty());
        send(
            &mut b,
            dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        assert_eq!(read(&mut b).await.message_type, MessageType::SESSION_UPDATE);
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
        assert!(bridge.retries.is_empty());
        // Session-specific values on the healthy router must survive a queued
        // update needed only by the other router.
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
        let update = read(&mut a).await;
        assert_eq!(update.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&update).unwrap().latency,
            Duration::from_micros(300)
        );
        assert_eq!(
            daemon.state().borrow().sessions[&aid].metrics.latency,
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
            ended: Arc::default(),
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
        assert_eq!(ask.request.current.latency, Duration::from_micros(900));
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
    async fn session_addresses_coalesce_behind_defaults_and_replay_after_refusal() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let addresses = |n| Addresses {
            ipv4: vec![Ipv4Addr::new(192, 0, 2, n)],
            ipv6: vec![format!("2001:db8::{n}").parse().unwrap()],
            ipv4_subnets: vec![format!("198.51.{n}.7/24")],
            ipv6_subnets: vec![format!("2001:db8:{n}::7/64")],
        };
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(42),
                    ..Default::default()
                },
            })
            .await;
        bridge
            .inbound(Inbound::SessionAddresses {
                add: addresses(1),
                remove: Default::default(),
            })
            .await;
        let mut peer = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        let sid = *snapshot.sessions.keys().next().unwrap();
        bridge.reconcile(&snapshot).await.unwrap();
        let defaults = read(&mut peer).await;
        assert_eq!(defaults.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            extract_link_metrics(&defaults).unwrap().latency,
            Duration::from_micros(42)
        );
        assert!(AddressChanges::from_message(&defaults).is_empty());
        // Hold the defaults reply: only the last address set may reach the wire.
        for n in 2..=3 {
            bridge
                .inbound(Inbound::SessionAddresses {
                    add: addresses(n),
                    remove: addresses(n - 1),
                })
                .await;
        }
        bridge
            .inbound(Inbound::SessionMetrics {
                metrics: Metrics {
                    latency_us: Some(43),
                    ..Default::default()
                },
            })
            .await;
        let expected = addresses(3).parse().unwrap().canonical();
        assert_eq!(bridge.session_addresses, expected);
        assert_eq!(
            daemon.state().borrow().sessions[&sid].local_addresses,
            expected
        );
        assert!(bridge.retries.is_empty());
        send(
            &mut peer,
            build_session_update_response(StatusCode::REQUEST_DENIED),
        )
        .await;
        let update = read(&mut peer).await;
        assert_eq!(update.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            AddressChanges::from_message(&update),
            AddressChanges {
                added: expected.clone(),
                removed: Default::default(),
            }
        );
        assert_eq!(
            extract_link_metrics(&update).unwrap().latency,
            Duration::from_micros(43)
        );
        send(
            &mut peer,
            build_session_update_response(StatusCode::REQUEST_DENIED),
        )
        .await;
        flush_peer(&mut peer).await;
        // Repeated additions and absent removals are no-ops, even after refusal.
        bridge
            .inbound(Inbound::SessionAddresses {
                add: addresses(3),
                remove: addresses(2),
            })
            .await;
        flush_peer(&mut peer).await;
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let defaults = read(&mut late).await;
        assert_eq!(
            extract_link_metrics(&defaults).unwrap().latency,
            Duration::from_micros(43)
        );
        send(
            &mut late,
            build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        let replay = read(&mut late).await;
        assert_eq!(replay.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(AddressChanges::from_message(&replay).added, expected);
        send(
            &mut late,
            build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut late).await;
        drop((peer, late));
        daemon.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn invalid_session_address_reports_preserve_live_state_and_replay() {
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
            let initial = Addresses {
                ipv4: vec!["192.0.2.1".parse().unwrap()],
                ipv6: vec!["2001:db8::1".parse().unwrap()],
                ipv4_subnets: vec!["198.51.1.7/24".into()],
                ipv6_subnets: vec!["2001:db8:1::7/64".into()],
            };
            bridge
                .inbound(Inbound::SessionAddresses {
                    add: initial.clone(),
                    remove: Default::default(),
                })
                .await;
            let expected = initial.parse().unwrap().canonical();
            if let Some(peer) = &mut peer {
                assert_eq!(
                    AddressChanges::from_message(&read(peer).await).added,
                    expected
                );
                send(peer, build_session_update_response(StatusCode::SUCCESS)).await;
                flush_peer(peer).await;
            }
            for line in [
                r#"{"type":"session_addresses","add":{"ipv4":["192.0.2.2","192.0.2.2"]},"remove":{"ipv6":["2001:db8::1"]}}"#,
                r#"{"type":"session_addresses","add":{"ipv4":["192.0.2.2"]},"remove":{"ipv6":["2001:db8::1","2001:db8::1"]}}"#,
                r#"{"type":"session_addresses","add":{"ipv4_subnets":["198.51.2.1/24","198.51.2.2/24"]},"remove":{"ipv4":["192.0.2.1"]}}"#,
                r#"{"type":"session_addresses","add":{"ipv6_subnets":["2001:db8:1::1/64"]},"remove":{"ipv6_subnets":["2001:db8:1::2/64"]}}"#,
                r#"{"type":"session_addresses","add":{"ipv4":["192.0.2.2"],"ipv6_subnets":["bad"]},"remove":{"ipv4":["192.0.2.1"]}}"#,
            ] {
                // Malformed values are ignored before they reach the bridge.
                if let Ok(message) = parse_inbound(line).unwrap() {
                    bridge.inbound(message).await;
                }
                assert_eq!(bridge.session_addresses, expected, "{line}");
                if let Some(peer) = &mut peer {
                    flush_peer(peer).await;
                }
            }
            // The addition fits by itself, but the accumulated replay set does not.
            bridge
                .inbound(Inbound::SessionAddresses {
                    add: Addresses {
                        ipv6: (1..=3120u128).map(Ipv6Addr::from).collect(),
                        ..Default::default()
                    },
                    remove: Addresses {
                        ipv4: initial.ipv4.clone(),
                        ..Default::default()
                    },
                })
                .await;
            assert_eq!(bridge.session_addresses, expected);
            if let Some(peer) = &mut peer {
                flush_peer(peer).await;
                assert_eq!(
                    daemon
                        .state()
                        .borrow()
                        .sessions
                        .values()
                        .next()
                        .unwrap()
                        .local_addresses,
                    expected
                );
            }
            let mut late = session(&daemon, &mut events).await;
            let snapshot = daemon.state().borrow().clone();
            bridge.reconcile(&snapshot).await.unwrap();
            assert_eq!(
                AddressChanges::from_message(&read(&mut late).await).added,
                expected
            );
            send(
                &mut late,
                build_session_update_response(StatusCode::SUCCESS),
            )
            .await;
            flush_peer(&mut late).await;
            // A valid removal still works after rejected reports.
            bridge
                .inbound(Inbound::SessionAddresses {
                    add: Default::default(),
                    remove: initial,
                })
                .await;
            assert!(bridge.session_addresses.is_empty());
            for peer in peer.iter_mut().chain(std::iter::once(&mut late)) {
                assert_eq!(
                    AddressChanges::from_message(&read(peer).await).removed,
                    expected
                );
                send(peer, build_session_update_response(StatusCode::SUCCESS)).await;
                flush_peer(peer).await;
            }
            drop((peer, late));
            daemon.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn large_session_address_replacements_split_and_replay_the_complete_set() {
        let daemon = modem().await;
        let mut events = daemon.subscribe();
        let mut bridge = bridge(&daemon);
        let initial = Addresses {
            ipv6: (1..=3120u128).map(Ipv6Addr::from).collect(),
            ..Default::default()
        };
        bridge
            .inbound(Inbound::SessionAddresses {
                add: initial.clone(),
                remove: Default::default(),
            })
            .await;
        let mut peer = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            AddressChanges::from_message(&read(&mut peer).await).added,
            initial.parse().unwrap()
        );
        send(
            &mut peer,
            build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        let replacement = Addresses {
            ipv6: (3121..=6240u128).map(Ipv6Addr::from).collect(),
            ..Default::default()
        };
        let line = serde_json::json!({
            "type":"session_addresses", "add":replacement, "remove":initial,
        })
        .to_string();
        assert!(line.len() <= MAX_LINE);
        bridge.inbound(parsed(&line)).await;
        let expected = replacement.parse().unwrap();
        assert_eq!(bridge.session_addresses, expected);
        let removal = read(&mut peer).await;
        assert_eq!(removal.message_type, MessageType::SESSION_UPDATE);
        assert_eq!(
            AddressChanges::from_message(&removal),
            AddressChanges {
                added: Default::default(),
                removed: initial.parse().unwrap(),
            }
        );
        send(
            &mut peer,
            build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        let addition = read(&mut peer).await;
        assert_eq!(
            AddressChanges::from_message(&addition),
            AddressChanges {
                added: expected.clone(),
                removed: Default::default(),
            }
        );
        send(
            &mut peer,
            build_session_update_response(StatusCode::SUCCESS),
        )
        .await;
        flush_peer(&mut peer).await;
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        assert_eq!(
            AddressChanges::from_message(&read(&mut late).await).added,
            expected
        );
        drop((peer, late));
        daemon.shutdown().await.unwrap();
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
                ended: Arc::default(),
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
    async fn link_response_wire_limit_is_checked_before_caching_grants() {
        for format in [MacAddressFormat::Eui48, MacAddressFormat::Eui64] {
            let mac = match format {
                MacAddressFormat::Eui48 => mac(),
                MacAddressFormat::Eui64 => MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 1]),
            };
            let mut config = ModemConfig::default();
            config.shared.network.use_tls = false;
            config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
            config.shared.network.tcp_port = 0;
            config.shared.network.discovery_port = 0;
            config.shared.network.mac_address_format = format;
            config.metrics.resources = Some(80);
            config.metrics.rlq_rx = Some(60);
            config.metrics.rlq_tx = Some(70);
            config.metrics.mtu = Some(1500);
            let initial = config.metrics.link_metrics();
            let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
            let daemon = ModemDaemon::builder()
                .config(config)
                .link_control(Arc::new(RadioLink {
                    asks,
                    timeout: Duration::from_secs(30),
                    ended: Arc::default(),
                }))
                .spawn()
                .await
                .unwrap();
            let mut events = daemon.subscribe();
            let mut bridge = bridge(&daemon);
            bridge.session_metrics = initial;
            bridge.mac_address_format = format;
            let mut peer = session(&daemon, &mut events).await;
            bridge
                .inbound(Inbound::DestinationUp {
                    mac: Mac(mac),
                    metrics: Metrics {
                        latency_us: Some(100),
                        ..Default::default()
                    },
                    addresses: Addresses::default(),
                })
                .await;
            assert_eq!(
                read(&mut peer).await.message_type,
                MessageType::DESTINATION_UP
            );
            send(
                &mut peer,
                build_destination_up_response(mac, StatusCode::SUCCESS),
            )
            .await;
            flush_peer(&mut peer).await;
            let overhead = dlep_fsm::session_common::build_link_characteristics_response(
                mac,
                StatusCode::SUCCESS,
                &initial,
            )
            .encode()
            .unwrap()
            .len()
                - 4;
            let text_limit = usize::from(u16::MAX) - overhead;
            let mut latency = 321;
            for multibyte in [false, true] {
                for oversized in [true, false] {
                    let original = bridge.destinations[&mac].metrics;
                    send(
                        &mut peer,
                        build_link_characteristics_request(
                            mac,
                            &dlep_daemon::LinkCharacteristics {
                                latency: Some(Duration::from_micros(latency)),
                                ..Default::default()
                            },
                        ),
                    )
                    .await;
                    let ask = tokio::time::timeout(WAIT, queued.recv())
                        .await
                        .unwrap()
                        .unwrap();
                    let request = bridge.next_request;
                    bridge.ask(ask).await.unwrap();
                    let length = text_limit + usize::from(oversized);
                    let text = if multibyte {
                        format!("{}{}", "é".repeat(length / 2), "x".repeat(length % 2))
                    } else {
                        "x".repeat(length)
                    };
                    assert_eq!(text.len(), length);
                    let line = serde_json::json!({"type":"link_response", "request":request, "status":"success",
                        "text":text,"metrics":{"latency_us":latency}}).to_string();
                    assert!(
                        line.len() <= MAX_LINE,
                        "valid adapter framing must reach response validation"
                    );
                    bridge.inbound(parsed(&line)).await;
                    let response = read(&mut peer).await;
                    assert_eq!(
                        response.message_type,
                        MessageType::LINK_CHARACTERISTICS_RESPONSE
                    );
                    let expected = if oversized {
                        original
                    } else {
                        LinkMetrics {
                            latency: Duration::from_micros(latency),
                            ..original
                        }
                    };
                    assert_eq!(extract_link_metrics(&response), Some(expected));
                    assert_eq!(
                        bridge.destinations[&mac].metrics, expected,
                        "a response rejected on the wire must not change cached metrics"
                    );
                    let (code, actual_text) = response
                        .data_items
                        .iter()
                        .find_map(|item| match item {
                            dlep_core::DataItem::Status { code, text } => {
                                Some((*code, text.as_str()))
                            }
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(
                        code,
                        if oversized {
                            StatusCode::REQUEST_DENIED
                        } else {
                            StatusCode::SUCCESS
                        }
                    );
                    assert_eq!(actual_text, if oversized { "" } else { &text });
                    if !oversized {
                        assert_eq!(response.encode().unwrap().len(), usize::from(u16::MAX) + 4);
                    }
                    latency += 1;
                }
            }
            drop(peer);
            daemon.shutdown().await.unwrap();
        }
    }

    #[tokio::test]
    async fn link_grant_rejected_during_termination_does_not_change_replay() {
        let (asks, mut queued) = mpsc::channel(QUEUE_SIZE);
        let daemon = modem_with(Some(Arc::new(RadioLink {
            asks,
            timeout: Duration::from_secs(30),
            ended: Arc::default(),
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
        let sid = ask.request.session_id;
        bridge.ask(ask).await.unwrap();
        daemon
            .send_command_to(
                sid,
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
            daemon.state().borrow().sessions[&sid].phase,
            SessionPhase::Terminating
        );
        bridge
            .inbound(Inbound::LinkResponse {
                request: 1,
                status: Status::Success,
                text: String::new(),
                metrics: Some(Metrics {
                    latency_us: Some(321),
                    ..Default::default()
                }),
            })
            .await;
        assert_eq!(
            bridge.destinations[&mac()].metrics.latency,
            Duration::from_micros(100),
            "a reply the terminating session cannot accept must not change replay"
        );
        send(
            &mut peer,
            Message::new(MessageType::SESSION_TERMINATION_RESPONSE),
        )
        .await;
        let mut state = daemon.state();
        tokio::time::timeout(WAIT, async {
            while state.borrow_and_update().sessions.contains_key(&sid) {
                state.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let mut late = session(&daemon, &mut events).await;
        let snapshot = daemon.state().borrow().clone();
        bridge.reconcile(&snapshot).await.unwrap();
        let replay = read(&mut late).await;
        assert_eq!(replay.message_type, MessageType::DESTINATION_UP);
        assert_eq!(
            extract_link_metrics(&replay).unwrap().latency,
            Duration::from_micros(100)
        );
        drop((peer, late));
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
                    session_id: SessionId(1),
                    answer,
                    mac: mac(),
                    current: original,
                    update_cache: true,
                    deadline: Instant::now() + WAIT,
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
                assert_eq!(response.await.unwrap().response, LinkResponse::denied());
            }
            assert!(bridge.pending.is_empty());
            assert_eq!(bridge.destinations[&mac()].metrics, original);
        }
        for outcome in [
            None,
            Some(Err(dlep_fsm::CommandRejection {
                command: dlep_fsm::CommandInfo {
                    kind: dlep_fsm::CommandKind::LinkCharacteristicsResponse,
                    destination: Some(mac()),
                },
                reason: CommandError::NotReady,
            })),
            Some(Ok(())),
        ] {
            let (answer, response) = oneshot::channel();
            bridge.pending.insert(
                2,
                Pending {
                    session_id: SessionId(1),
                    answer,
                    mac: mac(),
                    current: original,
                    update_cache: true,
                    deadline: Instant::now() + WAIT,
                },
            );
            let mut inbound = Box::pin(bridge.inbound(Inbound::LinkResponse {
                request: 2,
                status: Status::Success,
                text: String::new(),
                metrics: Some(Metrics {
                    latency_us: Some(456),
                    ..Default::default()
                }),
            }));
            let reply = tokio::select! {
                biased;
                () = &mut inbound => panic!("reply delivery must wait for acceptance"),
                reply = response => reply.unwrap(),
            };
            assert_eq!(reply.response.status, StatusCode::SUCCESS);
            let receipt = reply.receipt.expect("acceptance requested");
            assert!(
                std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                    inbound.as_mut(),
                    cx
                )))
                .await
                .is_pending()
            );
            if let Some(outcome) = outcome {
                receipt.send(outcome).unwrap();
            } else {
                drop(receipt);
            }
            inbound.await;
            assert_eq!(
                bridge.destinations[&mac()].metrics.latency,
                if outcome == Some(Ok(())) {
                    Duration::from_micros(456)
                } else {
                    original.latency
                }
            );
        }
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
            "+2:+0:+0:+0:+0:+1",
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
        assert!(matches!(parsed(r#"{"type":"resync"}"#), Inbound::Resync));
        let Inbound::SessionAddresses { add, remove } = parsed(r#"{"type":"session_addresses"}"#)
        else {
            panic!("expected session addresses")
        };
        assert!(add.parse().unwrap().is_empty());
        assert!(remove.parse().unwrap().is_empty());
        let up = parsed(
            r#"{"type":"destination_up","mac":"02:00:00:00:00:01","metrics":{"latency_us":5},"addresses":{"ipv4":["192.0.2.1"],"ipv6_subnets":["2001:db8::/32"]}}"#,
        );
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

        let response = parsed(r#"{"type":"link_response","request":3,"status":"denied"}"#);
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
            parsed(r#"{"type":"future_message","anything":[1,2]}"#),
            Inbound::Unknown
        ));
    }

    /// Lines that show the adapter does not speak this protocol stop the modem.
    #[test]
    fn framing_json_and_unknown_fields_are_fatal() {
        for bad in [
            "not json",
            r#"{"type":"resync""#,
            "[1]",
            r#""resync""#,
            r#"{"mac":"02:00:00:00:00:01"}"#,
            r#"{"type":3}"#,
            r#"{"type":"resync","request":1}"#,
            r#"{"type":"resync","sessions":[]}"#,
            r#"{"type":"session_addresses","session":1}"#,
            r#"{"type":"session_addresses","request":1}"#,
            r#"{"type":"session_addresses","mac":"02:00:00:00:00:01"}"#,
            r#"{"type":"session_addresses","add":{"v4":[]}}"#,
            r#"{"type":"destination_down","mac":"02:00:00:00:00:01","reason":1}"#,
            r#"{"type":"destination_update","mac":"02:00:00:00:00:01","metrics":{"latency":5}}"#,
            r#"{"type":"destination_up","mac":"02:00:00:00:00:01","addresses":{"v4":[]}}"#,
            r#"{"type":"link_response","request":1,"status":"success","metrics":{"rate":1}}"#,
        ] {
            assert!(parse_inbound(bad).is_err(), "{bad}");
        }
        let error = parse_inbound(
            r#"{"type":"destination_update","mac":"02:00:00:00:00:01","metrics":{"latency":5}}"#,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            r#"unknown field "latency" in destination_update message metrics"#
        );
    }

    /// Known messages with values the modem cannot use are ignored one by one.
    #[test]
    fn invalid_values_in_known_messages_are_not_fatal() {
        for (bad, reason) in [
            (
                r#"{"type":"destination_update","mac":"02:00:00:00:00:01","metrics":{"rlq_rx":300}}"#,
                "300",
            ),
            (
                r#"{"type":"destination_up","mac":"02:00:00:00:00:02","addresses":{"ipv4":["192.0.2.300"]}}"#,
                "invalid IPv4 address",
            ),
            (
                r#"{"type":"session_addresses","remove":{"ipv4":["bad"]}}"#,
                "invalid IPv4 address",
            ),
            (
                r#"{"type":"session_addresses","add":{"ipv4_subnets":["10.0.0.0/33"]}}"#,
                "10.0.0.0/33",
            ),
            (
                r#"{"type":"destination_addresses","mac":"02:00:00:00:00:01","remove":{"ipv6_subnets":["2001:db8::/129"]}}"#,
                "2001:db8::/129",
            ),
            (
                r#"{"type":"destination_down","mac":"+2:+0:+0:+0:+0:+1"}"#,
                "invalid MAC address",
            ),
            (r#"{"type":"destination_down","mac":"bogus"}"#, "bogus"),
            (r#"{"type":"destination_down","mac":5}"#, "invalid type"),
            (r#"{"type":"destination_down"}"#, "missing field `mac`"),
            (r#"{"type":"session_addresses","add":null}"#, "invalid type"),
            (
                r#"{"type":"session_metrics","metrics":[]}"#,
                "struct Metrics",
            ),
            (
                r#"{"type":"link_response","request":1,"status":"maybe"}"#,
                "maybe",
            ),
            (
                r#"{"type":"link_response","request":-1,"status":"denied"}"#,
                "-1",
            ),
        ] {
            let invalid = parse_inbound(bad)
                .unwrap_or_else(|e| panic!("{bad}: fatal {e:#}"))
                .expect_err(bad);
            let text = invalid.to_string();
            assert!(text.starts_with("invalid "), "{bad}: {text}");
            assert!(text.contains(reason), "{bad}: {text}");
        }
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
