//! Background task that owns a `DiscoverySocket` and a discovery FSM.
//!
//! Used by both `RouterDaemon::start_discovery` (router-side, drives
//! Peer_Discovery sends and listens for Peer_Offers) and `ModemDaemon::spawn`
//! (modem-side, listens for Peer_Discovery and replies with Peer_Offer).
//!
//! M6 Task 7 lands the FSM-↔-socket bridge end-to-end **without** periodic
//! timers and **without** a dedicated unicast sendto path — both arrive in
//! Task 8. The integration test in Task 11 works on a single
//! Peer_Discovery → Peer_Offer exchange, which this runtime can drive
//! today.

use std::time::Duration;

use dlep_fsm::events::{EmittedEvent, FsmAction, FsmEvent, SendTarget};
use dlep_net::discovery::DiscoverySocket;
use dlep_net::gtsm;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::events::{DaemonEvent, PeerInfo};
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

/// Run a discovery task until shutdown. Owns the FSM and the socket; bridges
/// socket I/O to FSM events. Emits `DaemonEvent::PeerDiscovered` when the
/// FSM signals one.
///
/// `initial_event` lets the caller kick the router-side FSM into Probing
/// (`Some(FsmEvent::AppStartDiscovery)`) or leave the modem-side FSM in its
/// default Listening state (`None`).
pub async fn run_discovery<F: DiscoveryFsm>(
    mut fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
) -> Result<(), DaemonError> {
    if let Some(event) = initial_event {
        let actions = fsm.step(event);
        process_actions(actions, &socket, &events_tx).await?;
    }

    loop {
        tokio::select! {
            res = socket.recv() => {
                match res {
                    Ok((signal, from, ttl)) => {
                        if !gtsm::is_gtsm_valid(ttl) {
                            debug!(?from, ttl, "dropping non-GTSM discovery datagram");
                            continue;
                        }
                        let actions = fsm.step(FsmEvent::RecvSignal { signal, from });
                        process_actions(actions, &socket, &events_tx).await?;
                    }
                    Err(e) => {
                        warn!("discovery recv error: {e}");
                        // Brief backoff so a persistent failure doesn't hot-loop.
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            Some(()) = shutdown_rx.recv() => {
                let actions = fsm.step(FsmEvent::AppShutdown {
                    reason: dlep_core::StatusCode::SHUTTING_DOWN,
                });
                process_actions(actions, &socket, &events_tx).await?;
                return Ok(());
            }
        }
    }
}

async fn process_actions(
    actions: Vec<FsmAction>,
    socket: &DiscoverySocket,
    events_tx: &EventTx,
) -> Result<(), DaemonError> {
    for action in actions {
        match action {
            FsmAction::SendSignal { signal, target } => match target {
                SendTarget::DiscoveryGroup => {
                    if let Err(e) = socket.send_to_group(&signal).await {
                        warn!("discovery send_to_group failed: {e}");
                    }
                }
                SendTarget::Unicast(_addr) => {
                    // Task 8 wires a real `DiscoverySocket::send_unicast`.
                    // Until then, fall back to the group: every joined
                    // router receives it anyway since they share the
                    // multicast membership. This is fine for the M6
                    // integration test on loopback.
                    if let Err(e) = socket.send_to_group(&signal).await {
                        warn!("unicast Peer_Offer fallback to group send failed: {e}");
                    }
                }
            },
            FsmAction::StartTimer { .. } | FsmAction::CancelTimer(_) => {
                debug!("discovery timer action ignored — wired in Task 8");
            }
            FsmAction::ResetHeartbeat { .. } | FsmAction::SendMessage(_) | FsmAction::CloseTcp => {
                debug!("discovery task received session-domain action; ignoring");
            }
            FsmAction::Emit(emitted) => {
                if let Some(evt) = translate(emitted) {
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
            addr,
            peer_description,
            use_tls,
        } => Some(DaemonEvent::PeerDiscovered(PeerInfo {
            addr,
            is_tls: use_tls,
            peer_description,
        })),
        _ => None,
    }
}
