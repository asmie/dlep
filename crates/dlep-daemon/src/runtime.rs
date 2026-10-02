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
    /// Router-side: declare interest in a destination the modem has not
    /// reported, via Destination Announce (RFC 8175 §12.13).
    AnnounceDestination { mac: MacAddress },
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
            | Self::RequestLinkCharacteristics { session_id, .. } => Some(*session_id),
            _ => None,
        }
    }
}

/// Broadcasts are not atomic: a healthy session may accept a command while
/// another rejects it. Inspect this report before deciding which peers to retry.
#[derive(Clone, Debug, Default)]
pub struct CommandReport {
    pub accepted: Vec<dlep_ext::SessionId>,
    pub rejected: Vec<(dlep_ext::SessionId, dlep_fsm::CommandRejection)>,
    /// Channels closed before enqueue; these commands were not delivered.
    pub undelivered: usize,
    /// Session ended without a receipt. The command may have taken effect.
    pub unknown: usize,
}

pub(crate) async fn dispatch_command(
    senders: Vec<mpsc::Sender<SessionRequest>>,
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
    // Session IDs are unique. Once the selected session replied, failures of
    // unrelated sessions cannot change the outcome of a targeted command.
    if target.is_some() && (!report.accepted.is_empty() || !report.rejected.is_empty()) {
        report.undelivered = 0;
        report.unknown = 0;
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
/// (standard `tokio::sync::broadcast` semantics) — consumers that need
/// lossless delivery should build their own mpsc bridge on top.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the internal commands mpsc feeding the session task.
pub const COMMAND_CHANNEL_CAPACITY: usize = 64;

/// Errors returned from the public daemon API.
#[derive(Debug, Error)]
pub enum DaemonError {
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
            vec![closed, accepted, lost],
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
            vec![closed, accepted],
            SessionCommand::SessionUpdate {
                metrics: Default::default(),
            },
            Some(SessionId(1)),
        )
        .await
        .unwrap();
        task.await.unwrap();
    }
}
