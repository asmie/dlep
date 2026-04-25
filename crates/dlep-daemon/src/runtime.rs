//! Shared runtime plumbing used by both router and modem daemons.
//!
//! The daemon owns a single-consumer mpsc for internal FSM events and a
//! broadcast channel for public `DaemonEvent`s. A single Tokio task per
//! session (owning the FSM) serializes all state mutation; cross-task
//! concurrency happens only via channels.

use thiserror::Error;
use tokio::sync::{broadcast, mpsc};

use crate::events::DaemonEvent;

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
