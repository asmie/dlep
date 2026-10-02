//! Background task that owns a `DiscoverySocket` and a discovery FSM.
//!
//! Used by both `RouterDaemon::start_discovery` (router-side, drives
//! Peer_Discovery sends and listens for Peer_Offers) and `ModemDaemon::spawn`
//! (modem-side, listens for Peer_Discovery and replies with Peer_Offer).
//!
//! Discovery has a single timer kind (`TimerKind::Discovery`) and one
//! `TimerId` (`TIMER_DISCOVERY = 10`). The periodic-resend semantics
//! tolerate one stale firing — if we cancel and the timer's already
//! pushed an expiry into the channel, the FSM observes
//! `TimerExpired` in a state where it ignores the event (the catch-all
//! `_ => Vec::new()` branch). So unlike `session::TimerSet`, no
//! generation tracking is needed here.

use std::collections::HashMap;
use std::time::Duration;

use dlep_fsm::events::{EmittedEvent, FsmAction, FsmEvent, SendTarget};
use dlep_fsm::{TimerId, TimerKind};
use dlep_net::discovery::{DiscoverySocket, ReceivedSignal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::connections::ConnectedRouters;
use crate::events::{DaemonEvent, PeerOffer};
use crate::runtime::{DaemonError, EventTx};

/// Trait shared by the two discovery FSMs so the runtime can drive either
/// one without taking a concrete type.
pub trait DiscoveryFsm: Send + 'static {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction>;
}

impl DiscoveryFsm for dlep_fsm::discovery_router::RouterDiscoveryFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        Self::step(self, event)
    }
}

impl DiscoveryFsm for dlep_fsm::discovery_modem::ModemDiscoveryFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        Self::step(self, event)
    }
}

/// Tracks in-flight timer tasks for the discovery runtime. Mirrors the
/// shape of `session::TimerSet` but drops the generation-counter machinery
/// because discovery only ever has one timer in flight at a time, and the
/// FSM tolerates one stale firing (see module comment).
#[derive(Default)]
struct DiscoveryTimers {
    handles: HashMap<TimerId, JoinHandle<()>>,
}

impl DiscoveryTimers {
    /// Arm a timer at `id`. If a previous handle was registered under the
    /// same id, it is aborted before being replaced — this avoids leaking
    /// a task when the FSM re-arms the same logical timer.
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
}

impl Drop for DiscoveryTimers {
    fn drop(&mut self) {
        for (_, h) in self.handles.drain() {
            h.abort();
        }
    }
}

/// Run a discovery task until shutdown. Owns the FSM and the socket; bridges
/// socket I/O to FSM events. Emits `DaemonEvent::PeerDiscovered` when the
/// FSM signals one.
///
/// `initial_event` lets the caller kick the router-side FSM into Probing
/// (`Some(FsmEvent::AppStartDiscovery)`) or leave the modem-side FSM in its
/// default Listening state (`None`).
pub async fn run_discovery<F: DiscoveryFsm>(
    fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
) -> Result<(), DaemonError> {
    run_discovery_with_peers(fsm, socket, initial_event, shutdown_rx, events_tx, None).await
}

pub(crate) async fn run_discovery_with_peers<F: DiscoveryFsm>(
    mut fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    connected_routers: Option<ConnectedRouters>,
) -> Result<(), DaemonError> {
    let mut timers = DiscoveryTimers::default();
    // Capacity 8 is comfortably above the expected steady-state queue
    // depth: discovery fires at most one timer per period, and the select
    // loop drains expiries promptly.
    let (timer_tx, mut timer_rx) = mpsc::channel::<(TimerId, TimerKind)>(8);
    let mut receive_after = tokio::time::Instant::now();

    if let Some(event) = initial_event {
        let actions = fsm.step(event);
        process_actions(
            actions,
            &socket,
            &events_tx,
            &mut timers,
            &timer_tx,
            None,
            None,
        )
        .await?;
    }

    loop {
        tokio::select! {
            res = async {
                // Back off only socket failures, without blocking timers or
                // shutdown while waiting to retry the receive operation.
                tokio::time::sleep_until(receive_after).await;
                socket.recv_with_metadata().await
            } => {
                match res {
                    Ok(ReceivedSignal { signal, from, local_addr, interface_index, .. }) => {
                        // RFC 8175 §7.1: an existing TCP connection suppresses
                        // discovery even before TLS/DLEP initialization finishes.
                        if signal.signal_type == dlep_core::SignalType::PEER_DISCOVERY
                            && connected_routers.as_ref().is_some_and(|peers| peers.contains(from)) {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        let actions = fsm.step(FsmEvent::RecvSignal { signal, from });
                        process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, Some(local_addr), Some(interface_index)).await?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        // A peer controls its datagram contents. Malformed
                        // packets must not impose a retry delay or warning log
                        // on other peers sharing discovery.
                        debug!("dropping malformed discovery datagram: {e}");
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        warn!("discovery recv error: {e}");
                        receive_after = tokio::time::Instant::now() + Duration::from_millis(100);
                    }
                }
            }
            Some((id, kind)) = timer_rx.recv() => {
                let actions = fsm.step(FsmEvent::TimerExpired(id, kind));
                process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, None, None).await?;
            }
            Some(()) = shutdown_rx.recv() => {
                let actions = fsm.step(FsmEvent::AppShutdown {
                    reason: dlep_core::StatusCode::SHUTTING_DOWN,
                });
                process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, None, None).await?;
                return Ok(());
            }
        }
    }
}

async fn process_actions(
    actions: Vec<FsmAction>,
    socket: &DiscoverySocket,
    events_tx: &EventTx,
    timers: &mut DiscoveryTimers,
    timer_tx: &mpsc::Sender<(TimerId, TimerKind)>,
    local: Option<std::net::IpAddr>,
    interface_index: Option<u32>,
) -> Result<(), DaemonError> {
    for action in actions {
        match action {
            FsmAction::SendSignal { mut signal, target } => match target {
                SendTarget::DiscoveryGroup => {
                    if let Err(e) = socket.send_to_group(&signal).await {
                        warn!("discovery send_to_group failed: {e}");
                    }
                }
                SendTarget::Unicast(addr) => {
                    // Replace wildcard listeners with the selected ingress
                    // interface's usable unicast address, never a multicast IP.
                    if let Some(local) = local {
                        for item in &mut signal.data_items {
                            match (item, local) {
                                (
                                    dlep_core::DataItem::Ipv4ConnectionPoint { addr, .. },
                                    std::net::IpAddr::V4(local),
                                ) if addr.is_unspecified() => *addr = local,
                                (
                                    dlep_core::DataItem::Ipv6ConnectionPoint { addr, .. },
                                    std::net::IpAddr::V6(local),
                                ) if addr.is_unspecified() => *addr = local,
                                _ => {}
                            }
                        }
                    }
                    if let Err(e) = socket.send_unicast(&signal, addr).await {
                        warn!(?addr, "discovery send_unicast failed: {e}");
                    }
                }
            },
            FsmAction::StartTimer {
                id,
                kind,
                duration,
                periodic,
            } => {
                let tx = timer_tx.clone();
                let handle = if periodic {
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(duration).await;
                            // `send` only fails if the receiver dropped,
                            // which happens when `run_discovery` returns
                            // (timer_rx goes out of scope). At that point
                            // the timer task should exit, not retry.
                            if tx.send((id, kind)).await.is_err() {
                                break;
                            }
                        }
                    })
                } else {
                    tokio::spawn(async move {
                        tokio::time::sleep(duration).await;
                        // Single-shot: ignore send error — same reasoning
                        // as the periodic break above.
                        let _ = tx.send((id, kind)).await;
                    })
                };
                timers.arm(id, handle);
            }
            FsmAction::CancelTimer(id) => timers.cancel(id),
            FsmAction::ResetHeartbeat { .. } | FsmAction::SendMessage(_) | FsmAction::CloseTcp => {
                debug!("discovery task received session-domain action; ignoring");
            }
            FsmAction::Emit(emitted) => {
                if let Some(mut evt) = translate(emitted) {
                    if let (DaemonEvent::PeerDiscovered(offer), Some(index)) =
                        (&mut evt, interface_index)
                    {
                        for endpoint in &mut offer.endpoints {
                            if let std::net::SocketAddr::V6(addr) = &mut endpoint.addr {
                                if addr.ip().is_unicast_link_local() {
                                    addr.set_scope_id(index);
                                }
                            }
                        }
                    }
                    let _ = events_tx.send(evt);
                }
            }
        }
    }
    Ok(())
}

fn translate(emitted: EmittedEvent) -> Option<DaemonEvent> {
    match emitted {
        EmittedEvent::PeerDiscovered {
            endpoints,
            peer_description,
        } => Some(DaemonEvent::PeerDiscovered(PeerOffer {
            endpoints,
            peer_description,
        })),
        _ => None,
    }
}
