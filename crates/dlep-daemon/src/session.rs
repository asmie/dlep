//! Active-session runtime. One Tokio task per session; the task is the sole
//! mutator of its FSM, so no locking is needed around state. The runtime
//! owns the `Box<dyn Transport>`, the inbound read buffer, the outstanding
//! timer set, and the public event-broadcast handle. The FSM stays
//! synchronous and tokio-free; everything async lives here.

use std::collections::HashMap;
use std::time::Duration;

use bytes::BytesMut;
use dlep_core::StatusCode;
use dlep_fsm::SessionConfig;
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::{FsmAction, FsmEvent, TimerId, TimerKind};
use dlep_net::{MessageCodec, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::codec::Decoder;
use tracing::{debug, warn};

use crate::config::TimersConfig;
use crate::events::{DaemonEvent, PeerInfo};
use crate::runtime::{COMMAND_CHANNEL_CAPACITY, DaemonError, EventTx, SessionCommand};

/// Hydrate a `SessionConfig` from the daemon-level `TimersConfig` and a
/// per-role peer description. Centralised here (not on `SessionConfig`
/// itself) because `dlep-fsm` deliberately doesn't depend on `dlep-daemon`,
/// so it cannot import `TimersConfig`.
pub fn session_config_from_timers(
    timers: &TimersConfig,
    peer_description: String,
) -> SessionConfig {
    SessionConfig {
        peer_description,
        heartbeat_interval_ms: timers.heartbeat_interval_ms,
        session_init_timeout: Duration::from_millis(timers.session_init_timeout_ms.into()),
        termination_timeout: Duration::from_millis(timers.termination_timeout_ms.into()),
    }
}

pub trait SessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction>;
}

impl SessionFsm for dlep_fsm::session_router::RouterSessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_router::RouterSessionFsm::step(self, event)
    }
}

impl SessionFsm for dlep_fsm::session_modem::ModemSessionFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        dlep_fsm::session_modem::ModemSessionFsm::step(self, event)
    }
}

/// Set of outstanding timer tasks. Wraps a `HashMap<TimerId, JoinHandle>`
/// so `Drop` aborts every still-running timer when the session task exits —
/// including via `?`-propagated errors and panics. Without this, dropping
/// `JoinHandle` would *detach* the sleeper task, leaving it alive until its
/// `Duration` expired naturally (a malformed-frame error in `read_frame`
/// could otherwise leak a 5-second `SessionInit` timer per affected
/// session).
#[derive(Default)]
struct TimerSet {
    handles: HashMap<TimerId, JoinHandle<()>>,
}

impl TimerSet {
    fn arm(&mut self, id: TimerId, handle: JoinHandle<()>) {
        if let Some(old) = self.handles.insert(id, handle) {
            old.abort();
        }
    }

    fn cancel(&mut self, id: TimerId) {
        if let Some(h) = self.handles.remove(&id) {
            h.abort();
        }
    }

    /// Forget the entry for an expired timer. The sleeper task already
    /// completed and sent on the expiry channel; no abort is needed.
    fn forget(&mut self, id: TimerId) {
        self.handles.remove(&id);
    }
}

impl Drop for TimerSet {
    fn drop(&mut self) {
        for (_, h) in self.handles.drain() {
            h.abort();
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
pub async fn run_session<F: SessionFsm>(
    mut fsm: F,
    transport: Box<dyn Transport>,
    initial_event: FsmEvent,
    mut commands: mpsc::Receiver<SessionCommand>,
    events_tx: EventTx,
    peer: PeerInfo,
) -> Result<(), DaemonError> {
    let (mut reader, mut writer) = tokio::io::split(transport);
    let mut read_buf = BytesMut::with_capacity(4096);
    let mut codec = MessageCodec;

    let (timer_expiry_tx, mut timer_expiry_rx) =
        mpsc::channel::<(TimerId, TimerKind)>(COMMAND_CHANNEL_CAPACITY);
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
                match read_result? {
                    FrameRead::Message(msg) => {
                        let actions = fsm.step(FsmEvent::RecvMessage(msg));
                        if process_actions(
                            actions, &mut writer, &mut timers,
                            &timer_expiry_tx, &events_tx, &peer,
                        ).await? {
                            break;
                        }
                    }
                    FrameRead::Eof => {
                        let actions = fsm.step(FsmEvent::TcpClosed);
                        let _ = process_actions(
                            actions, &mut writer, &mut timers,
                            &timer_expiry_tx, &events_tx, &peer,
                        ).await?;
                        break;
                    }
                }
            }

            cmd = commands.recv(), if commands_open => {
                let reason = match cmd {
                    Some(SessionCommand::Shutdown { reason }) => reason,
                    None => {
                        // Daemon dropped the channel without an explicit
                        // Shutdown command. Treat as a one-shot signal:
                        // synthesise AppShutdown once, then disable this
                        // branch so we don't spin.
                        commands_open = false;
                        StatusCode::SHUTTING_DOWN
                    }
                };
                let actions = fsm.step(FsmEvent::AppShutdown { reason });
                if process_actions(
                    actions, &mut writer, &mut timers,
                    &timer_expiry_tx, &events_tx, &peer,
                ).await? {
                    break;
                }
            }

            Some((id, kind)) = timer_expiry_rx.recv() => {
                // Forget the entry first so a racing CancelTimer is a no-op
                // — but no abort is needed since the sleeper already
                // completed.
                timers.forget(id);
                let actions = fsm.step(FsmEvent::TimerExpired(id, kind));
                if process_actions(
                    actions, &mut writer, &mut timers,
                    &timer_expiry_tx, &events_tx, &peer,
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
async fn process_actions(
    actions: Vec<FsmAction>,
    writer: &mut WriteHalf<Box<dyn Transport>>,
    timers: &mut TimerSet,
    timer_expiry_tx: &mpsc::Sender<(TimerId, TimerKind)>,
    events_tx: &EventTx,
    peer: &PeerInfo,
) -> Result<bool, DaemonError> {
    let mut close = false;
    for action in actions {
        match action {
            FsmAction::SendMessage(msg) => {
                let bytes = msg.encode()?;
                writer.write_all(&bytes).await?;
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
                if periodic {
                    // M3 has no periodic timers; M4 introduces the heartbeat
                    // pair. Until then, log and treat as one-shot.
                    warn!("periodic timer requested in M3; treating as one-shot");
                }
                let tx = timer_expiry_tx.clone();
                let handle = tokio::spawn(async move {
                    tokio::time::sleep(duration).await;
                    let _ = tx.send((id, kind)).await;
                });
                timers.arm(id, handle);
            }
            FsmAction::CancelTimer(id) => {
                timers.cancel(id);
            }
            FsmAction::ResetHeartbeat => {
                // M4 will install the periodic-send and missed-deadline
                // timer pair here; M3 leaves it as a no-op so the FSM can
                // still emit the action without runtime support.
            }
            FsmAction::CloseTcp => {
                close = true;
            }
            FsmAction::Emit(emitted) => {
                if let Some(daemon_event) = translate_emitted(emitted, peer) {
                    let _ = events_tx.send(daemon_event);
                }
            }
        }
    }
    if close {
        let _ = writer.shutdown().await;
    }
    Ok(close)
}

fn translate_emitted(emitted: EmittedEvent, peer: &PeerInfo) -> Option<DaemonEvent> {
    match emitted {
        EmittedEvent::SessionUp => Some(DaemonEvent::SessionUp {
            peer: peer.clone(),
            negotiated_extensions: Vec::new(),
        }),
        EmittedEvent::SessionDown(reason) => Some(DaemonEvent::SessionDown { reason }),
        // M5 wires destination events through to DaemonEvent::Destination.
        EmittedEvent::DestinationUp(_)
        | EmittedEvent::DestinationDown(_, _)
        | EmittedEvent::DestinationUpdate(_) => None,
    }
}
