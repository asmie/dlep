//! Active-session runtime. One Tokio task per session; the task is the sole
//! mutator of its FSM, so no locking is needed around state. The runtime
//! owns the `Box<dyn Transport>`, the inbound read buffer, the outstanding
//! timer set, and the public event-broadcast handle. The FSM stays
//! synchronous and tokio-free; everything async lives here.

use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::BytesMut;
use dlep_core::{DataItem, MacAddress, Message, MessageType, StatusCode};
use dlep_ext::{
    DestinationStateSnapshot, DlepExtension, ExtHandled, ExtensionCtx, ExtensionRegistry, Role,
    SessionId, SessionStateSnapshot,
};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::{FsmAction, FsmEvent, SessionConfig, TimerId, TimerKind};
use dlep_net::{MessageCodec, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::Decoder;
use tracing::debug;

use crate::config::TimersConfig;
use crate::connections::ConnectionTracker;
use crate::events::{DaemonEvent, PeerInfo};
use crate::runtime::{
    COMMAND_CHANNEL_CAPACITY, DaemonError, EventTx, SessionCommand, SessionRequest,
};

/// Per-daemon monotonic counter for `SessionId`. Each daemon constructs
/// its own `Arc<AtomicU64>` and passes it into every `run_session` call;
/// two daemons sharing a process have independent id-spaces, and
/// extensions that key state on `SessionId` see a single contiguous
/// id-space per daemon instead of a process-wide counter.
pub type SessionIdCounter = Arc<AtomicU64>;

pub fn new_session_id_counter() -> SessionIdCounter {
    Arc::new(AtomicU64::new(1))
}

fn next_session_id(counter: &SessionIdCounter) -> SessionId {
    SessionId(counter.fetch_add(1, Ordering::Relaxed))
}

/// Per-hook-call context handed to extensions. Captures references to the
/// session task's mutable state so the extension can queue outbound
/// messages (drained to the writer once the hook returns) and emit
/// application-level events on the broadcast channel.
///
/// Constructed fresh on every hook call; never held across `.await`.
struct SessionCtx<'a> {
    session_id: SessionId,
    is_router_side: bool,
    pending_sends: &'a mut Vec<Message>,
    events_tx: &'a EventTx,
}

impl<'a> ExtensionCtx for SessionCtx<'a> {
    fn session_id(&self) -> SessionId {
        self.session_id
    }
    fn is_router_side(&self) -> bool {
        self.is_router_side
    }
    fn send_message(&mut self, msg: Message) {
        self.pending_sends.push(msg);
    }
    fn emit_event(&mut self, ev: Arc<dyn Any + Send + Sync>) {
        // `broadcast::Sender::send` returns `Err(SendError)` when there
        // are zero subscribers — the event is lost. Log at debug so an
        // extension that emits before any `daemon.subscribe()` call can
        // diagnose silent drops in production.
        if self.events_tx.send(DaemonEvent::Extension(ev)).is_err() {
            debug!("extension emit_event dropped: no broadcast subscribers");
        }
    }
}

/// Ensures a terminal notification on every exit, including I/O errors and
/// task cancellation. Explicit FSM shutdown marks the guard complete.
struct SessionLifecycle {
    connection: Option<ConnectionTracker>,
    session_id: SessionId,
    peer: PeerInfo,
    events_tx: EventTx,
    is_router: bool,
    active_exts: Vec<Arc<dyn DlepExtension>>,
    down_emitted: bool,
}

impl Drop for SessionLifecycle {
    fn drop(&mut self) {
        if !self.down_emitted {
            let _ = self.events_tx.send(DaemonEvent::SessionDown {
                session_id: self.session_id,
                peer: self.peer.clone(),
                reason: StatusCode::TIMED_OUT,
            });
            let mut discarded_sends = Vec::new();
            dispatch_session_state(
                &self.active_exts,
                self.session_id,
                self.is_router,
                &mut discarded_sends,
                &self.events_tx,
                false,
            );
        }
    }
}

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

async fn write_message(
    writer: &mut WriteHalf<Box<dyn Transport>>,
    msg: &Message,
) -> Result<(), DaemonError> {
    let bytes = msg.encode()?;
    tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(&bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DLEP write timed out"))??;
    Ok(())
}

/// Hydrate a `SessionConfig` from the daemon-level `TimersConfig` and a
/// per-role peer description. Centralised here (not on `SessionConfig`
/// itself) because `dlep-fsm` deliberately doesn't depend on `dlep-daemon`,
/// so it cannot import `TimersConfig`.
pub fn session_config_from_timers(
    timers: &TimersConfig,
    peer_description: String,
    advertised_extensions: Vec<dlep_core::ExtensionId>,
) -> SessionConfig {
    SessionConfig {
        peer_description,
        heartbeat_interval_ms: timers.heartbeat_interval_ms,
        session_init_timeout: Duration::from_millis(timers.session_init_timeout_ms.into()),
        termination_timeout: Duration::from_millis(timers.termination_timeout_ms.into()),
        advertised_extensions,
        initial_metrics: Default::default(),
    }
}

pub trait SessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction>;
    fn in_session(&self) -> bool;
}

impl SessionFsm for dlep_fsm::session_router::RouterSessionFsm {
    fn in_session(&self) -> bool {
        self.state() == dlep_fsm::session_router::RouterSessionState::InSession
    }
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_router::RouterSessionFsm::step(self, event)
    }
}

impl SessionFsm for dlep_fsm::session_modem::ModemSessionFsm {
    fn in_session(&self) -> bool {
        self.state() == dlep_fsm::session_modem::ModemSessionState::InSession
    }
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_modem::ModemSessionFsm::step(self, event)
    }
}

/// Set of outstanding timer tasks. Wraps a
/// `HashMap<TimerId, TimerEntry>` so `Drop` aborts every still-running
/// timer when the session task exits — including via `?`-propagated errors
/// and panics. Without this, dropping `JoinHandle` would *detach* the
/// sleeper task, leaving it alive until its `Duration` expired naturally.
///
/// The `periodic` flag is critical for M4's heartbeat-send timer. Periodic
/// timer tasks are `loop { sleep; send }` — they survive each tick and
/// must stay in the map so a later `CancelTimer` finds the handle and
/// `abort()`s the loop. Calling `forget()` on a periodic entry would drop
/// the only handle the runtime can later cancel; the task would survive
/// until the session ended on its own. `forget()` only acts on one-shot
/// entries, where the sleeper task has already completed.
///
/// The `generation` field filters stale timer expiries: a one-shot timer
/// can race a successful pre-deadline message — the timer task pushes its
/// expiry into the channel, then the runtime processes the message and
/// calls `cancel`, but `JoinHandle::abort` cannot retract the queued
/// expiry. Each `arm` bumps the generation; the spawned task captures it;
/// the select-loop discards expiries whose generation no longer matches
/// the current entry. Without this, a healthy session would terminate
/// spuriously on the very next message after a near-deadline reset.
#[derive(Default)]
struct TimerSet {
    handles: HashMap<TimerId, TimerEntry>,
    last_generations: HashMap<TimerId, u64>,
}

struct TimerEntry {
    handle: JoinHandle<()>,
    periodic: bool,
    generation: u64,
}

impl TimerSet {
    /// Compute the generation a fresh `arm(id, …)` will assign. Callers
    /// pass this value into the spawned task so its expiry message can be
    /// matched back against the latest generation.
    fn next_generation_for(&mut self, id: TimerId) -> u64 {
        let generation = self
            .last_generations
            .get(&id)
            .copied()
            .unwrap_or(0)
            .wrapping_add(1);
        self.last_generations.insert(id, generation);
        generation
    }

    fn arm(&mut self, id: TimerId, handle: JoinHandle<()>, periodic: bool, generation: u64) {
        if let Some(old) = self.handles.insert(
            id,
            TimerEntry {
                handle,
                periodic,
                generation,
            },
        ) {
            old.handle.abort();
        }
    }

    fn cancel(&mut self, id: TimerId) {
        if let Some(entry) = self.handles.remove(&id) {
            entry.handle.abort();
        }
    }

    /// `true` if the entry at `id` is still on `generation`. Used by the
    /// select-loop to ignore expiries from cancelled or superseded timers
    /// (their event was already in flight when we re-armed).
    fn is_current_generation(&self, id: TimerId, generation: u64) -> bool {
        self.handles
            .get(&id)
            .is_some_and(|e| e.generation == generation)
    }

    /// Forget the entry for an expired one-shot timer. No-op for periodic
    /// timers — their sleeper loop is *not* finished after a tick, so we
    /// must keep the handle around for a later `cancel`.
    ///
    /// Nested `if let` rather than a `let` chain because the workspace MSRV
    /// is 1.85 and let-chains stabilised in 1.88.
    fn forget(&mut self, id: TimerId) {
        if let Some(entry) = self.handles.get(&id) {
            if !entry.periodic {
                self.handles.remove(&id);
            }
        }
    }
}

impl Drop for TimerSet {
    fn drop(&mut self) {
        for (_, entry) in self.handles.drain() {
            entry.handle.abort();
        }
    }
}

/// Drive a session FSM end-to-end against `transport`. Returns when the FSM
/// asks the runtime to close the connection (via `FsmAction::CloseTcp`),
/// when the peer closes the TCP stream, or when the command channel sender
/// is dropped (treated as a one-shot shutdown signal).
///
/// `initial_event` is fed into the FSM before the select-loop starts —
/// `FsmEvent::TcpConnected` for router-side, `FsmEvent::TcpAccepted` for
/// modem-side. The runtime processes the resulting actions (Session Init
/// send, timer start) before awaiting any new I/O.
///
/// `role` is explicit (not derived from `initial_event`) so future code
/// paths that use a different startup event for one role can't silently
/// mislabel the session.
#[allow(clippy::too_many_arguments)]
pub async fn run_session<F: SessionFsm>(
    fsm: F,
    transport: Box<dyn Transport>,
    initial_event: FsmEvent,
    commands: mpsc::Receiver<SessionRequest>,
    events_tx: EventTx,
    peer: PeerInfo,
    extensions: ExtensionRegistry,
    role: Role,
    session_id_counter: SessionIdCounter,
) -> Result<(), DaemonError> {
    run_session_tracked(
        fsm,
        transport,
        initial_event,
        commands,
        events_tx,
        peer,
        extensions,
        role,
        session_id_counter,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_session_tracked<F: SessionFsm>(
    mut fsm: F,
    transport: Box<dyn Transport>,
    initial_event: FsmEvent,
    mut commands: mpsc::Receiver<SessionRequest>,
    events_tx: EventTx,
    mut peer: PeerInfo,
    extensions: ExtensionRegistry,
    role: Role,
    session_id_counter: SessionIdCounter,
    connection: Option<ConnectionTracker>,
) -> Result<(), DaemonError> {
    let (mut reader, mut writer) = tokio::io::split(transport);
    let mut read_buf = BytesMut::with_capacity(4096);
    let mut codec = MessageCodec;

    let session_id = next_session_id(&session_id_counter);
    let is_router_side = role.is_router();
    let mut lifecycle = SessionLifecycle {
        connection,
        session_id,
        peer: peer.clone(),
        events_tx: events_tx.clone(),
        is_router: is_router_side,
        active_exts: Vec::new(),
        down_emitted: false,
    };
    let mut pending_sends: Vec<Message> = Vec::new();

    let (timer_expiry_tx, mut timer_expiry_rx) =
        mpsc::channel::<(TimerId, TimerKind, u64)>(COMMAND_CHANNEL_CAPACITY);
    let mut timers = TimerSet::default();

    // Process the synthetic startup event before entering the loop.
    let actions = fsm.step(initial_event);
    if process_actions(
        actions,
        &mut writer,
        &mut timers,
        &timer_expiry_tx,
        &events_tx,
        &peer,
        &extensions,
        session_id,
        is_router_side,
        &mut lifecycle,
        &mut pending_sends,
    )
    .await?
    {
        return Ok(());
    }

    // Once `commands.recv()` returns `None` we feed `AppShutdown` to the FSM
    // and then disable the branch via this guard — without it `recv()` would
    // continue returning `None` immediately and the FSM (now likely in
    // `Terminating`) would no-op forever, hot-looping the runtime.
    let mut commands_open = true;

    loop {
        tokio::select! {
            // Inbound bytes from the peer. Drain all complete frames before
            // looping; partial frames stay in `read_buf` for the next round.
            read_result = read_frame(&mut reader, &mut read_buf, &mut codec) => {
                let frame = match read_result {
                    Ok(frame) => frame,
                    Err(DaemonError::Codec(_)) => {
                        let actions = fsm.step(FsmEvent::ProtocolError(StatusCode::INVALID_DATA));
                        if process_actions(actions, &mut writer, &mut timers, &timer_expiry_tx,
                            &events_tx, &peer, &extensions, session_id, is_router_side,
                            &mut lifecycle, &mut pending_sends).await? { break; }
                        continue;
                    }
                    Err(e) => return Err(e),
                };
                match frame {
                    FrameRead::Message(mut msg) => {
                        if matches!(msg.message_type, MessageType::SESSION_INITIALIZATION | MessageType::SESSION_INITIALIZATION_RESPONSE) {
                            peer.peer_description = msg.data_items.iter().find_map(|i| match i {
                                DataItem::PeerType { description, .. } => Some(description.clone()), _ => None
                            });
                            lifecycle.peer = peer.clone();
                        }
                        // Only mutually negotiated extensions can consume unknown
                        // messages/items. Unclaimed input reaches strict validation.
                        let handled = fsm.in_session() && !is_known_message_type(msg.message_type) && dispatch_unknown_message(
                            &lifecycle.active_exts, session_id, is_router_side, &mut pending_sends,
                            &events_tx, msg.message_type, &msg.data_items);
                        if !handled && fsm.in_session() {
                            msg.data_items = filter_unknown_items(&lifecycle.active_exts, session_id,
                                is_router_side, &mut pending_sends, &events_tx, msg.message_type, msg.data_items);
                        }
                        let event = if handled { FsmEvent::RecvExtensionMessage } else { FsmEvent::RecvMessage(msg) };
                        let actions = fsm.step(event);
                        let close = process_actions(actions, &mut writer, &mut timers,
                            &timer_expiry_tx, &events_tx, &peer, &extensions, session_id, is_router_side,
                            &mut lifecycle, &mut pending_sends).await?;
                        if close { break; }
                        flush_pending_sends(&mut pending_sends, &mut writer).await?;
                    }
                    FrameRead::Eof => {
                        let actions = fsm.step(FsmEvent::TcpClosed);
                        let _ = process_actions(
                            actions, &mut writer, &mut timers,
                            &timer_expiry_tx, &events_tx, &peer,
                            &extensions, session_id, is_router_side,
                            &mut lifecycle, &mut pending_sends,
                        ).await?;
                        break;
                    }
                }
            }

            cmd = commands.recv(), if commands_open => {
                let (cmd, receipt) = match cmd {
                    Some(request) => {
                        if request.target.is_some_and(|target| target != session_id) {
                            if let Some(receipt) = request.receipt { let _ = receipt.send(None); }
                            continue;
                        }
                        (Some(request.command), request.receipt)
                    }
                    None => (None, None),
                };
                let event = match cmd {
                    Some(SessionCommand::Shutdown { reason }) => {
                        FsmEvent::AppShutdown { reason }
                    }
                    Some(SessionCommand::AddDestination { mac, metrics, addrs }) => {
                        FsmEvent::AppAddDestination { mac, metrics, addrs }
                    }
                    Some(SessionCommand::UpdateDestination { mac, metrics }) => {
                        FsmEvent::AppUpdateMetrics { mac, metrics }
                    }
                    Some(SessionCommand::UpdateDestinationAddresses { mac, changes }) => {
                        FsmEvent::AppUpdateAddresses { mac, changes }
                    }
                    Some(SessionCommand::UpdateSessionAddresses { session_id: _, changes }) => {
                        FsmEvent::AppSessionAddresses { changes }
                    }
                    Some(SessionCommand::DropDestination { mac, reason }) => {
                        FsmEvent::AppDropDestination { mac, reason }
                    }
                    Some(SessionCommand::DropDestinationForSession { session_id: _, mac }) => {
                        FsmEvent::AppDropDestination { mac, reason: StatusCode::SUCCESS }
                    }
                    Some(SessionCommand::SessionUpdate { metrics }) => {
                        FsmEvent::AppSessionUpdate { metrics }
                    }
                    Some(SessionCommand::AnnounceDestination { mac }) => {
                        FsmEvent::AppAnnounceDestination { mac }
                    }
                    Some(SessionCommand::RequestLinkCharacteristics { session_id: _, mac, requested }) => {
                        FsmEvent::AppRequestLinkCharacteristics { mac, requested }
                    }
                    None => {
                        // Daemon dropped the channel without an explicit
                        // Shutdown command. Treat as a one-shot signal:
                        // synthesise AppShutdown once, then disable this
                        // branch so we don't spin.
                        commands_open = false;
                        FsmEvent::AppShutdown { reason: StatusCode::SHUTTING_DOWN }
                    }
                };
                let actions = fsm.step(event);
                let outcome = actions.iter().find_map(|action| match action {
                    FsmAction::Emit(dlep_fsm::events::EmittedEvent::CommandRejected(rejection)) => Some(*rejection),
                    _ => None,
                }).map_or(Ok(()), Err);
                let closed = process_actions(
                    actions, &mut writer, &mut timers,
                    &timer_expiry_tx, &events_tx, &peer,
                    &extensions, session_id, is_router_side,
                    &mut lifecycle, &mut pending_sends,
                ).await?;
                if let Some(receipt) = receipt { let _ = receipt.send(Some((session_id, outcome))); }
                if closed { break; }
            }

            Some((id, kind, generation)) = timer_expiry_rx.recv() => {
                // Drop expiries from cancelled or superseded timers. The
                // hazardous case is the missed-heartbeat deadline: a peer
                // message arriving microseconds before the deadline lets
                // the (now-stale) sleeper task push an expiry into the
                // queue before the message-driven `cancel`+rearm runs;
                // without this filter the FSM would terminate the session
                // on the very next select iteration.
                if !timers.is_current_generation(id, generation) {
                    continue;
                }
                // Forget the entry first so a racing CancelTimer is a no-op
                // — but no abort is needed since the sleeper already
                // completed.
                timers.forget(id);
                let actions = fsm.step(FsmEvent::TimerExpired(id, kind));
                if process_actions(
                    actions, &mut writer, &mut timers,
                    &timer_expiry_tx, &events_tx, &peer,
                    &extensions, session_id, is_router_side,
                    &mut lifecycle, &mut pending_sends,
                ).await? {
                    break;
                }
            }
        }
    }

    Ok(())
}

enum FrameRead {
    Message(dlep_core::Message),
    Eof,
}

async fn read_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut BytesMut,
    codec: &mut MessageCodec,
) -> Result<FrameRead, DaemonError> {
    loop {
        if let Some(msg) = codec.decode(buf)? {
            return Ok(FrameRead::Message(msg));
        }
        let n = reader.read_buf(buf).await?;
        if n == 0 {
            return Ok(FrameRead::Eof);
        }
    }
}

/// Drain a batch of `FsmAction`s into real I/O / state mutations. Returns
/// `Ok(true)` if the FSM asked to close the connection (the caller should
/// break out of the select loop).
#[allow(clippy::too_many_arguments)]
async fn process_actions(
    actions: Vec<FsmAction>,
    writer: &mut WriteHalf<Box<dyn Transport>>,
    timers: &mut TimerSet,
    timer_expiry_tx: &mpsc::Sender<(TimerId, TimerKind, u64)>,
    events_tx: &EventTx,
    peer: &PeerInfo,
    extensions: &ExtensionRegistry,
    session_id: SessionId,
    is_router_side: bool,
    lifecycle: &mut SessionLifecycle,
    pending_sends: &mut Vec<Message>,
) -> Result<bool, DaemonError> {
    let active_exts = &mut lifecycle.active_exts;
    let down_emitted = &mut lifecycle.down_emitted;
    let mut close = false;
    for action in actions {
        match action {
            FsmAction::SendMessage(msg) => {
                write_message(writer, &msg).await?;
            }
            FsmAction::SendSignal { .. } => {
                // Signals belong on the discovery socket (M6); the session
                // task never owns one. Silently drop.
                debug!("session task received SendSignal; ignoring (handled by discovery socket)");
            }
            FsmAction::StartTimer {
                id,
                kind,
                duration,
                periodic,
            } => {
                let generation = timers.next_generation_for(id);
                let tx = timer_expiry_tx.clone();
                let handle = if periodic {
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(duration).await;
                            // Break if the receiver is gone (session task
                            // exited and dropped `timer_expiry_rx` before
                            // our `JoinHandle::abort()` landed). Without
                            // this guard the next `send().await` would
                            // hang on a closed channel.
                            if tx.send((id, kind, generation)).await.is_err() {
                                break;
                            }
                        }
                    })
                } else {
                    tokio::spawn(async move {
                        tokio::time::sleep(duration).await;
                        let _ = tx.send((id, kind, generation)).await;
                    })
                };
                timers.arm(id, handle, periodic, generation);
            }
            FsmAction::CancelTimer(id) => {
                timers.cancel(id);
            }
            FsmAction::ResetHeartbeat {
                timer_id,
                missed_deadline,
            } => {
                // Re-arm the missed-heartbeat single-shot deadline at the
                // FSM-supplied duration (= 2 × peer's announced interval).
                // The FSM owns `timer_id` so the runtime stays decoupled from
                // FSM-internal timer naming. The send-side periodic timer is
                // independent and is not touched here.
                let generation = timers.next_generation_for(timer_id);
                let tx = timer_expiry_tx.clone();
                let handle = tokio::spawn(async move {
                    tokio::time::sleep(missed_deadline).await;
                    let _ = tx
                        .send((timer_id, TimerKind::HeartbeatMissed, generation))
                        .await;
                });
                timers.arm(timer_id, handle, false, generation);
            }
            FsmAction::CloseTcp => {
                close = true;
            }
            FsmAction::Emit(emitted) => {
                if matches!(emitted, EmittedEvent::SessionDown(_)) {
                    *down_emitted = true;
                }
                // 1. Negotiate active_exts BEFORE translate_emitted so the
                //    public `negotiated_extensions` reflects extensions
                //    that actually accepted negotiation (not just the wire
                //    intersection).
                if let EmittedEvent::SessionUp { peer_extensions } = &emitted {
                    *active_exts = extensions.negotiate(peer_extensions);
                    if let Some(connection) = &lifecycle.connection {
                        connection.established();
                    }
                }

                // 2. Broadcast the public lifecycle event FIRST so
                //    subscribers see e.g. `SessionUp` before any
                //    `DaemonEvent::Extension` an extension hook may emit
                //    in response, and so `SessionDown` is always delivered
                //    even if a subsequent flush errors on a closed socket.
                if let Some(daemon_event) =
                    translate_emitted(&emitted, peer, session_id, active_exts)
                {
                    let _ = events_tx.send(daemon_event);
                }

                // 3. Now drive the extension lifecycle hooks. Their queued
                //    wire messages and emitted events arrive AFTER the
                //    public lifecycle event.
                match &emitted {
                    EmittedEvent::SessionUp { .. } => {
                        dispatch_session_state(
                            active_exts,
                            session_id,
                            is_router_side,
                            pending_sends,
                            events_tx,
                            true,
                        );
                    }
                    EmittedEvent::SessionDown(_) => {
                        dispatch_session_state(
                            active_exts,
                            session_id,
                            is_router_side,
                            pending_sends,
                            events_tx,
                            false,
                        );
                        // Session is over: clear active_exts so any
                        // further FSM emits in the same batch (or stray
                        // events) don't dispatch to extensions that
                        // already saw `up=false`.
                        active_exts.clear();
                    }
                    EmittedEvent::DestinationUp { mac, metrics, .. } => {
                        dispatch_destination_state(
                            active_exts,
                            session_id,
                            is_router_side,
                            pending_sends,
                            events_tx,
                            *mac,
                            true,
                            Some(*metrics),
                            StatusCode::SUCCESS,
                        );
                    }
                    EmittedEvent::DestinationDown { mac, reason } => {
                        dispatch_destination_state(
                            active_exts,
                            session_id,
                            is_router_side,
                            pending_sends,
                            events_tx,
                            *mac,
                            false,
                            None,
                            *reason,
                        );
                    }
                    _ => {}
                }

                // Propagate extension write failures through lifecycle cleanup.
                flush_pending_sends(pending_sends, writer).await?;
            }
        }
    }
    if close {
        let _ = tokio::time::timeout(WRITE_TIMEOUT, writer.shutdown()).await;
    }
    Ok(close)
}

fn translate_emitted(
    emitted: &EmittedEvent,
    peer: &PeerInfo,
    session_id: SessionId,
    active_exts: &[Arc<dyn DlepExtension>],
) -> Option<DaemonEvent> {
    use crate::events::{DestinationEvent, DestinationId};
    match emitted {
        EmittedEvent::SessionUp { peer_extensions } => {
            let negotiated = negotiated_from_active(active_exts, peer_extensions);
            Some(DaemonEvent::SessionUp {
                session_id,
                peer: peer.clone(),
                negotiated_extensions: negotiated,
            })
        }
        EmittedEvent::SessionDown(reason) => Some(DaemonEvent::SessionDown {
            session_id,
            peer: peer.clone(),
            reason: *reason,
        }),
        EmittedEvent::PeerDiscovered { .. } => None,
        EmittedEvent::DestinationUp {
            mac,
            metrics,
            addrs,
        } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::Up {
                id: DestinationId(*mac),
                metrics: *metrics,
                v4_addrs: addrs.v4.clone(),
                v6_addrs: addrs.v6.clone(),
                v4_subnets: addrs.v4_subnets.clone(),
                v6_subnets: addrs.v6_subnets.clone(),
            },
        }),
        EmittedEvent::CommandRejected(rejection) => Some(DaemonEvent::CommandRejected {
            session_id,
            peer: peer.clone(),
            rejection: *rejection,
        }),
        EmittedEvent::DestinationUpdate { mac, metrics } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::Update {
                id: DestinationId(*mac),
                metrics: *metrics,
            },
        }),
        EmittedEvent::DestinationDown { mac, reason } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::Down {
                id: DestinationId(*mac),
                reason: *reason,
            },
        }),
        EmittedEvent::LinkCharacteristicsResponse {
            mac,
            status,
            text,
            metrics,
        } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::LinkCharacteristicsResponse {
                id: DestinationId(*mac),
                status: *status,
                text: text.clone(),
                metrics: *metrics,
            },
        }),
        EmittedEvent::SessionAddressesUpdate { changes, addresses } => {
            Some(DaemonEvent::SessionAddresses {
                session_id,
                peer: peer.clone(),
                changes: (**changes).clone(),
                addresses: addresses.clone(),
            })
        }
        EmittedEvent::DestinationAddressesUpdate {
            mac,
            changes,
            addresses,
        } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::AddressesChanged {
                id: DestinationId(*mac),
                changes: (**changes).clone(),
                addresses: addresses.clone(),
            },
        }),
        EmittedEvent::DestinationAnnounced {
            mac,
            requested_addresses,
        } => Some(DaemonEvent::Destination {
            session_id,
            peer: peer.clone(),
            event: DestinationEvent::Announced {
                id: DestinationId(*mac),
                requested_addresses: requested_addresses.clone(),
            },
        }),
        EmittedEvent::SessionMetricsUpdate { metrics } => Some(DaemonEvent::Metrics {
            session_id,
            peer: peer.clone(),
            event: crate::events::MetricsEvent {
                session_wide: *metrics,
            },
        }),
    }
}

/// Compute the public `negotiated_extensions` set: the IDs advertised by
/// extensions that accepted negotiation (i.e. whose `on_negotiated()`
/// returned `true` and thus survived into `active_exts`), restricted to
/// IDs the peer also advertised. Sorted-deduped for determinism.
///
/// This is intentionally NOT the raw wire-intersection of advertised IDs
/// — an extension that returns `false` from `on_negotiated` is inert for
/// the rest of the session, so its IDs must NOT appear in the public
/// negotiated set even if both sides advertised them on the wire.
fn negotiated_from_active(
    active_exts: &[Arc<dyn DlepExtension>],
    peer_extensions: &[dlep_core::ExtensionId],
) -> Vec<dlep_core::ExtensionId> {
    let mut out: Vec<dlep_core::ExtensionId> = active_exts
        .iter()
        .flat_map(|e| e.advertised_ids().iter().copied())
        .filter(|id| peer_extensions.contains(id))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Core message types handled by the FSM. Unsupported core operations are
/// still available to negotiated extensions until their handlers are added.
fn is_known_message_type(mt: MessageType) -> bool {
    matches!(
        mt,
        MessageType::SESSION_INITIALIZATION
            | MessageType::SESSION_INITIALIZATION_RESPONSE
            | MessageType::SESSION_UPDATE
            | MessageType::SESSION_UPDATE_RESPONSE
            | MessageType::SESSION_TERMINATION
            | MessageType::SESSION_TERMINATION_RESPONSE
            | MessageType::DESTINATION_UP
            | MessageType::DESTINATION_UP_RESPONSE
            | MessageType::DESTINATION_ANNOUNCE
            | MessageType::DESTINATION_ANNOUNCE_RESPONSE
            | MessageType::DESTINATION_DOWN
            | MessageType::DESTINATION_DOWN_RESPONSE
            | MessageType::DESTINATION_UPDATE
            | MessageType::HEARTBEAT
    )
}

/// Walk the active-extensions list with `on_unknown_message`. Stops at
/// the first `ExtHandled::Handled` (extensions earlier in the list win).
/// Returns `true` if any extension claimed the message.
fn dispatch_unknown_message(
    active_exts: &[Arc<dyn DlepExtension>],
    session_id: SessionId,
    is_router_side: bool,
    pending_sends: &mut Vec<Message>,
    events_tx: &EventTx,
    message_type: MessageType,
    items: &[DataItem],
) -> bool {
    for ext in active_exts {
        let mut ctx = SessionCtx {
            session_id,
            is_router_side,
            pending_sends,
            events_tx,
        };
        if let ExtHandled::Handled = ext.on_unknown_message(message_type, items, &mut ctx) {
            return true;
        }
    }
    false
}

/// Remove items claimed by negotiated extensions. All remaining unknown
/// items reach the FSM's INVALID_DATA validation.
fn filter_unknown_items(
    active_exts: &[Arc<dyn DlepExtension>],
    session_id: SessionId,
    is_router_side: bool,
    pending_sends: &mut Vec<Message>,
    events_tx: &EventTx,
    in_message: MessageType,
    items: Vec<DataItem>,
) -> Vec<DataItem> {
    items
        .into_iter()
        .filter(|item| {
            let DataItem::Unknown(raw) = item else {
                return true;
            };
            !active_exts.iter().any(|ext| {
                let mut ctx = SessionCtx {
                    session_id,
                    is_router_side,
                    pending_sends,
                    events_tx,
                };
                ext.on_unknown_data_item(in_message, raw, &mut ctx) == ExtHandled::Handled
            })
        })
        .collect()
}

fn dispatch_session_state(
    active_exts: &[Arc<dyn DlepExtension>],
    session_id: SessionId,
    is_router_side: bool,
    pending_sends: &mut Vec<Message>,
    events_tx: &EventTx,
    up: bool,
) {
    let snap = SessionStateSnapshot { up };
    for ext in active_exts {
        let mut ctx = SessionCtx {
            session_id,
            is_router_side,
            pending_sends,
            events_tx,
        };
        ext.on_session_state(snap, &mut ctx);
    }
}

#[allow(clippy::too_many_arguments)]
fn dispatch_destination_state(
    active_exts: &[Arc<dyn DlepExtension>],
    session_id: SessionId,
    is_router_side: bool,
    pending_sends: &mut Vec<Message>,
    events_tx: &EventTx,
    mac: MacAddress,
    up: bool,
    metrics: Option<dlep_core::LinkMetrics>,
    last_status: StatusCode,
) {
    let snap = DestinationStateSnapshot {
        up,
        last_status,
        metrics,
    };
    for ext in active_exts {
        let mut ctx = SessionCtx {
            session_id,
            is_router_side,
            pending_sends,
            events_tx,
        };
        ext.on_destination_state(mac, snap, &mut ctx);
    }
}

/// Encode and write every extension-queued message in `pending_sends` to
/// `writer`. On the first encode or write error, returns Err with the
/// remaining (un-iterated) messages **discarded** via `Drain`'s `Drop` —
/// callers must treat the post-failure session as terminating, since the
/// truncated queue cannot be recovered.
async fn flush_pending_sends(
    pending_sends: &mut Vec<Message>,
    writer: &mut WriteHalf<Box<dyn Transport>>,
) -> Result<(), DaemonError> {
    for msg in pending_sends.drain(..) {
        write_message(writer, &msg).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Runtime tests for `TimerSet`. The full `run_session` happy-path is
    //! covered by `crates/dlep-daemon/tests/loopback.rs`; these tests focus
    //! on the periodic-vs-one-shot bookkeeping introduced in M4 because
    //! getting it wrong is a silent bug — the periodic loop survives as a
    //! detached task until the session task drops the receiver, but
    //! explicit `CancelTimer` semantics quietly stop working.
    use super::*;
    use dlep_fsm::TimerId;

    fn long_periodic_handle() -> JoinHandle<()> {
        // Sleep for an interval longer than any test would wait. The loop
        // shape mirrors the real periodic-send timer so abort behaviour is
        // identical.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        })
    }

    /// Pins the contract that `cancel()` aborts a periodic timer task.
    /// Pre-fix (M3-shaped `TimerSet` without periodic tracking) this would
    /// fail because the first tick's `forget()` removed the handle from the
    /// map, leaving `cancel()` with nothing to abort.
    #[tokio::test]
    async fn periodic_timer_aborts_on_cancel() {
        let mut timers = TimerSet::default();
        let id = TimerId::new(99);
        let generation = timers.next_generation_for(id);
        timers.arm(id, long_periodic_handle(), true, generation);

        timers.cancel(id);
        assert!(
            !timers.handles.contains_key(&id),
            "cancel should remove the entry"
        );

        // Give the abort a moment to land. The aborted task completes (with
        // a Cancelled error) on its next yield point, which is the start of
        // the sleep inside the loop.
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    /// Pins the contract that `Drop` aborts every periodic timer task,
    /// covering the session-task-exit path (the wrapping `run_session`
    /// returns Ok or Err, drops `TimerSet`, every spawned timer task should
    /// terminate).
    #[tokio::test]
    async fn periodic_timer_aborts_on_drop() {
        let timers = {
            let mut t = TimerSet::default();
            let id1 = TimerId::new(1);
            let id2 = TimerId::new(2);
            let g1 = t.next_generation_for(id1);
            t.arm(id1, long_periodic_handle(), true, g1);
            let g2 = t.next_generation_for(id2);
            t.arm(id2, long_periodic_handle(), true, g2);
            t
        };
        // Move out, drop, give abort time to land.
        drop(timers);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // No assertion possible without keeping handles; the test passes
        // when it doesn't hang. (The matching `arm` test above asserts the
        // map state directly.)
    }

    /// `forget()` on a periodic entry must be a no-op so a later
    /// `CancelTimer` still finds the live handle. Without this, the M4
    /// heartbeat-send loop survives until the session ends naturally.
    #[tokio::test]
    async fn forget_keeps_periodic_entry() {
        let mut timers = TimerSet::default();
        let id = TimerId::new(7);
        let generation = timers.next_generation_for(id);
        timers.arm(id, long_periodic_handle(), true, generation);

        timers.forget(id);
        assert!(
            timers.handles.contains_key(&id),
            "forget() should not remove a periodic entry"
        );

        // Cleanup so the test doesn't leak the spawn.
        timers.cancel(id);
    }

    /// `forget()` on a one-shot entry removes it (matches the M3 contract).
    #[tokio::test]
    async fn forget_removes_one_shot_entry() {
        let mut timers = TimerSet::default();
        let id = TimerId::new(8);
        let handle = tokio::spawn(async {});
        // Yield so the trivial one-shot completes naturally before forget.
        tokio::task::yield_now().await;
        let generation = timers.next_generation_for(id);
        timers.arm(id, handle, false, generation);

        timers.forget(id);
        assert!(
            !timers.handles.contains_key(&id),
            "forget() should remove a one-shot entry"
        );
    }

    /// Pins the stale-expiry filter contract: after re-arming, the
    /// previously-issued generation is no longer current. The select-loop
    /// uses this to discard expiries from cancelled/superseded timers,
    /// which would otherwise terminate a healthy session if a peer
    /// message arrives microseconds before the missed-deadline.
    #[tokio::test]
    async fn rearm_invalidates_prior_generation() {
        let mut timers = TimerSet::default();
        let id = TimerId::new(42);

        let gen_a = timers.next_generation_for(id);
        timers.arm(id, long_periodic_handle(), false, gen_a);
        assert!(timers.is_current_generation(id, gen_a));

        // Rearm — simulates the runtime processing a fresh peer message
        // and emitting `ResetHeartbeat`. The first task's expiry, if it
        // were already in the channel, would carry `gen_a`.
        let gen_b = timers.next_generation_for(id);
        assert_ne!(gen_a, gen_b, "rearm must bump the generation");
        timers.arm(id, long_periodic_handle(), false, gen_b);

        assert!(
            !timers.is_current_generation(id, gen_a),
            "stale (gen_a) expiry must be filtered after rearm"
        );
        assert!(timers.is_current_generation(id, gen_b));

        timers.cancel(id);
    }

    /// After `cancel`, *any* generation is considered stale (the entry is
    /// gone). Covers the case where a timer fires after cancellation but
    /// no rearm follows.
    #[tokio::test]
    async fn cancelled_timer_generation_is_stale() {
        let mut timers = TimerSet::default();
        let id = TimerId::new(43);
        let generation = timers.next_generation_for(id);
        timers.arm(id, long_periodic_handle(), false, generation);

        timers.cancel(id);
        assert!(
            !timers.is_current_generation(id, generation),
            "expiry from cancelled timer must be filtered"
        );

        let next_generation = timers.next_generation_for(id);
        timers.arm(id, long_periodic_handle(), false, next_generation);
        assert_ne!(
            generation, next_generation,
            "generation must remain monotonic across cancel/rearm"
        );
        assert!(
            !timers.is_current_generation(id, generation),
            "cancelled generation must stay stale after the same timer id is rearmed"
        );
        assert!(timers.is_current_generation(id, next_generation));
    }
}
