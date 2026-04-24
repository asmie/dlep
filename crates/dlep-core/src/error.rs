use thiserror::Error;

use crate::ids::{DataItemType, MessageType, SignalType};

#[derive(Debug, Error)]
pub enum CodecError {
    #[error("buffer too short: need at least {needed} bytes, have {have}")]
    Truncated { needed: usize, have: usize },

    #[error("missing DLEP signal prefix")]
    MissingSignalPrefix,

    #[error("declared length {declared} does not match remaining buffer {remaining}")]
    LengthMismatch { declared: usize, remaining: usize },

    #[error("unknown signal type {0:?} in strict mode")]
    UnknownSignalType(SignalType),

    #[error("unknown message type {0:?} in strict mode")]
    UnknownMessageType(MessageType),

    #[error("unknown data item type {0:?} in strict mode")]
    UnknownDataItemType(DataItemType),

    #[error("invalid data item length for {kind:?}: expected {expected}, got {got}")]
    InvalidDataItemLength {
        kind: DataItemType,
        expected: usize,
        got: usize,
    },

    #[error("invalid UTF-8 in text field")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("value out of range for {field}: {value}")]
    OutOfRange { field: &'static str, value: u64 },
}
