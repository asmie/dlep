//! Shared runtime plumbing used by both router and modem daemons.
//!
//! The daemon owns a single-consumer mpsc for internal FSM events and a
//! broadcast channel for public `DaemonEvent`s. A single Tokio task per
//! session (owning the FSM) serializes all state mutation; cross-task
//! concurrency happens only via channels.

use dlep_core::{MacAddress, StatusCode};
use dlep_fsm::{DestinationAddrs, LinkMetrics};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::events::DaemonEvent;

/// Per-session control message. The session task receives one of these on its
/// mpsc command channel and translates into the appropriate `FsmEvent`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SessionCommand {
    /// Start the local-initiated termination handshake.
    Shutdown { reason: StatusCode },
    /// Modem-side: announce a new destination to the peer router.
    AddDestination {
        mac: MacAddress,
        metrics: LinkMetrics,
        addrs: DestinationAddrs,
    },
    /// Modem-side: push fresh metrics for an existing destination.
    UpdateDestination {
        mac: MacAddress,
        metrics: LinkMetrics,
    },
    UpdateDestinationAddresses {
        mac: MacAddress,
        changes: dlep_fsm::AddressChanges,
    },
    UpdateSessionAddresses {
        session_id: dlep_ext::SessionId,
        changes: dlep_fsm::AddressChanges,
    },
    /// Modem-side: retain the latest desired local address set and reconcile
    /// it after the current session transaction, splitting large replacements.
    SetSessionAddresses {
        session_id: dlep_ext::SessionId,
        addresses: DestinationAddrs,
    },
    /// Modem-side: drop a destination at the peer router.
    DropDestination { mac: MacAddress, reason: StatusCode },
    /// Router-side: withdraw interest in a destination on one session only.
    DropDestinationForSession {
        session_id: dlep_ext::SessionId,
        mac: MacAddress,
    },
    /// Modem side: push session-wide metric changes via a Session Update
    /// Message (RFC 8175 §12.7).
    SessionUpdate { metrics: LinkMetrics },
    /// Modem side: change session defaults while preserving each destination's
    /// current metrics in the same session command. Sends Session Update and
    /// any necessary Destination Updates; returns Busy if the session is busy.
    SessionDefaults { metrics: LinkMetrics },
    /// Modem side: retain/coalesce session metrics when a session transaction
    /// is busy, preserving subsequent destination changes when sent.
    QueueSessionUpdate { metrics: LinkMetrics },
    /// Router-side: declare interest in a destination the modem has not
    /// reported, via Destination Announce (RFC 8175 §12.13).
    AnnounceDestination { mac: MacAddress },
    /// Router-side Announce with address hints; does not change retained
    /// local addresses or the modem's authoritative destination addresses.
    AnnounceDestinationWithAddresses {
        mac: MacAddress,
        changes: dlep_fsm::AddressChanges,
    },
    /// Router-side request, addressed to one session because a MAC can be
    /// present at several modems with different link characteristics.
    RequestLinkCharacteristics {
        session_id: dlep_ext::SessionId,
        mac: MacAddress,
        requested: dlep_core::LinkCharacteristics,
    },
}

/// Result for a selected session, or None if the request targets another session.
pub type CommandReceipt = Option<(dlep_ext::SessionId, Result<(), dlep_fsm::CommandRejection>)>;

/// A command with an optional acceptance receipt. The runtime resolves it only
/// after checking FSM state and executing the resulting local actions. This is
/// not the peer's protocol response. Dropped receipts indicate an unknown
/// outcome (e.g. transport failure after a partial write), not safe retry.
#[derive(Debug)]
pub struct SessionRequest {
    pub target: Option<dlep_ext::SessionId>,
    pub command: SessionCommand,
    pub receipt: Option<oneshot::Sender<CommandReceipt>>,
}

impl From<SessionCommand> for SessionRequest {
    fn from(command: SessionCommand) -> Self {
        Self {
            target: command.target(),
            command,
            receipt: None,
        }
    }
}

impl SessionCommand {
    pub fn target(&self) -> Option<dlep_ext::SessionId> {
        match self {
            Self::DropDestinationForSession { session_id, .. }
            | Self::UpdateSessionAddresses { session_id, .. }
            | Self::SetSessionAddresses { session_id, .. }
            | Self::RequestLinkCharacteristics { session_id, .. } => Some(*session_id),
            _ => None,
        }
    }
}

/// Broadcasts are not atomic: a healthy session may accept a command while
/// another rejects it. Inspect this report before deciding which peers to retry.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CommandReport {
    pub accepted: Vec<dlep_ext::SessionId>,
    pub rejected: Vec<(dlep_ext::SessionId, dlep_fsm::CommandRejection)>,
    /// Channels closed before enqueue; these commands were not delivered.
    pub undelivered: usize,
    /// Session ended without a receipt. The command may have taken effect.
    pub unknown: usize,
}

/// Command channel of one session task. The session ID is allocated before
/// the task starts so targeted commands are delivered only to their session.
#[derive(Clone, Debug)]
pub(crate) struct SessionHandle {
    pub(crate) id: dlep_ext::SessionId,
    pub(crate) tx: mpsc::Sender<SessionRequest>,
}

impl SessionHandle {
    pub(crate) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Deliver `command` and wait for local acceptance. A targeted command goes
/// only to the selected session, so a stalled or busy unrelated session
/// cannot delay it; an untargeted command waits for every session's receipt.
pub(crate) async fn dispatch_command(
    sessions: Vec<SessionHandle>,
    command: SessionCommand,
    target: Option<dlep_ext::SessionId>,
) -> Result<(), DaemonError> {
    if target.is_some() && command.target().is_some() && target != command.target() {
        return Err(DaemonError::Config(
            "conflicting command session IDs".into(),
        ));
    }
    let target = target.or(command.target());
    let mut report = CommandReport::default();
    let mut receipts = Vec::new();
    let senders = sessions
        .into_iter()
        .filter(|session| target.is_none_or(|target| target == session.id))
        .map(|session| session.tx);
    for sender in senders {
        let (receipt, receiver) = oneshot::channel();
        if sender
            .send(SessionRequest {
                target,
                command: command.clone(),
                receipt: Some(receipt),
            })
            .await
            .is_err()
        {
            report.undelivered += 1;
        } else {
            receipts.push(receiver);
        }
    }
    for receipt in receipts {
        match receipt.await {
            Ok(Some((id, Ok(())))) => report.accepted.push(id),
            Ok(Some((id, Err(reason)))) => report.rejected.push((id, reason)),
            Ok(None) => {} // A targeted command belongs to a different session.
            Err(_) => report.unknown += 1,
        }
    }
    if !report.rejected.is_empty() || report.undelivered != 0 || report.unknown != 0 {
        Err(DaemonError::CommandRejected(report))
    } else if report.accepted.is_empty() {
        Err(DaemonError::NoMatchingSession)
    } else {
        Ok(())
    }
}

/// Broadcast buffer size for public `DaemonEvent`s. When a subscriber lags
/// past this many events, the oldest events are dropped for that subscriber
/// (standard `tokio::sync::broadcast` semantics). Use the daemon's retained
/// `state()` feed to reconcile current protocol state after lag; forwarding
/// this broadcast through mpsc cannot make missed events recoverable.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the internal commands mpsc feeding the session task.
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;

/// Errors returned from the public daemon API.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DaemonError {
    #[error("router connection/session limit reached")]
    SessionLimitReached,
    #[error("router discovered-peer history is full of active peers")]
    PeerHistoryFull,
    #[error("no matching live session")]
    NoMatchingSession,
    #[error("command was not accepted by every session: {0:?}")]
    CommandRejected(CommandReport),
    #[error("daemon is shutting down")]
    ShuttingDown,
    #[error("configuration error: {0}")]
    Config(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec error: {0}")]
    Codec(#[from] dlep_core::CodecError),
}

pub type EventTx = broadcast::Sender<DaemonEvent>;
pub type EventRx = broadcast::Receiver<DaemonEvent>;
pub type CommandTx<C> = mpsc::Sender<C>;
pub type CommandRx<C> = mpsc::Receiver<C>;

pub fn new_event_channel() -> (EventTx, EventRx) {
    broadcast::channel(EVENT_CHANNEL_CAPACITY)
}

pub fn new_command_channel<C>() -> (CommandTx<C>, CommandRx<C>) {
    mpsc::channel(COMMAND_CHANNEL_CAPACITY)
}

/// Validate public address batches before queueing work for a session.
pub(crate) fn validate_address_changes(
    changes: &dlep_fsm::AddressChanges,
) -> Result<(), DaemonError> {
    changes
        .validate()
        .map_err(|_| DaemonError::Config("duplicate or conflicting address changes".into()))?;
    changes
        .append_to(dlep_core::Message::new(
            dlep_core::MessageType::SESSION_UPDATE,
        ))
        .encode()?;
    Ok(())
}

#[cfg(test)]
mod command_tests {
    use super::*;
    use dlep_ext::SessionId;

    fn handle(id: u64, tx: mpsc::Sender<SessionRequest>) -> SessionHandle {
        SessionHandle {
            id: SessionId(id),
            tx,
        }
    }

    #[tokio::test]
    async fn closed_channels_and_lost_receipts_never_report_success() {
        let (closed, receiver) = mpsc::channel(1);
        drop(receiver);
        let (accepted, mut receiver) = mpsc::channel::<SessionRequest>(1);
        let task = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            request
                .receipt
                .unwrap()
                .send(Some((SessionId(1), Ok(()))))
                .unwrap();
        });
        let (lost, mut receiver) = mpsc::channel::<SessionRequest>(1);
        let lost_task = tokio::spawn(async move {
            drop(receiver.recv().await.unwrap());
        });
        let error = dispatch_command(
            vec![handle(1, accepted), handle(2, closed), handle(3, lost)],
            SessionCommand::SessionUpdate {
                metrics: Default::default(),
            },
            None,
        )
        .await
        .unwrap_err();
        let DaemonError::CommandRejected(report) = error else {
            panic!("{error:?}")
        };
        assert_eq!(report.accepted, [SessionId(1)]);
        assert_eq!(report.undelivered, 1);
        assert_eq!(report.unknown, 1);
        task.await.unwrap();
        lost_task.await.unwrap();
    }

    #[tokio::test]
    async fn targeted_receipt_is_not_overridden_by_unrelated_closed_channel() {
        let (closed, receiver) = mpsc::channel(1);
        drop(receiver);
        let (accepted, mut receiver) = mpsc::channel::<SessionRequest>(1);
        let task = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            assert_eq!(request.target, Some(SessionId(1)));
            request
                .receipt
                .unwrap()
                .send(Some((SessionId(1), Ok(()))))
                .unwrap();
        });
        dispatch_command(
            vec![handle(2, closed), handle(1, accepted)],
            SessionCommand::SessionUpdate {
                metrics: Default::default(),
            },
            Some(SessionId(1)),
        )
        .await
        .unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn targeted_command_skips_a_stalled_unrelated_session() {
        // The unrelated session's queue is full and never drained.
        let (stalled, _stalled_receiver) = mpsc::channel::<SessionRequest>(1);
        stalled
            .try_send(
                SessionCommand::SessionUpdate {
                    metrics: Default::default(),
                }
                .into(),
            )
            .unwrap();
        let (accepted, mut receiver) = mpsc::channel::<SessionRequest>(1);
        let task = tokio::spawn(async move {
            let request = receiver.recv().await.unwrap();
            request
                .receipt
                .unwrap()
                .send(Some((SessionId(2), Ok(()))))
                .unwrap();
        });
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            dispatch_command(
                vec![handle(1, stalled.clone()), handle(2, accepted)],
                SessionCommand::SessionUpdate {
                    metrics: Default::default(),
                },
                Some(SessionId(2)),
            ),
        )
        .await
        .expect("targeted command waited for an unrelated session")
        .unwrap();
        task.await.unwrap();
        assert_eq!(stalled.capacity(), 0, "unrelated session received nothing");
    }

    #[tokio::test]
    async fn targeted_command_without_a_matching_session_is_reported() {
        let (other, _receiver) = mpsc::channel::<SessionRequest>(1);
        let error = dispatch_command(
            vec![handle(1, other)],
            SessionCommand::SessionUpdate {
                metrics: Default::default(),
            },
            Some(SessionId(9)),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, DaemonError::NoMatchingSession), "{error:?}");
    }
}
