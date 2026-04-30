use std::fmt;

use thiserror::Error;

use crate::ids::{DataItemType, MessageType, SignalType};

/// What length(s) a Data Item is permitted to take on the wire, used for
/// `CodecError::InvalidDataItemLength` reporting. Several DLEP Data Items are
/// not fixed-width — Connection Points are 5 *or* 7, Status / Peer Type are
/// "at least 1", Extensions Supported is a multiple of 2 — so a single
/// `expected: usize` would be misleading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedLen {
    /// Length must be exactly this value.
    Exact(usize),
    /// Length must be at least this value.
    AtLeast(usize),
    /// Length must be one of the listed values.
    OneOf(&'static [usize]),
    /// Length must be a non-negative multiple of this value.
    Multiple(usize),
}

impl fmt::Display for ExpectedLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpectedLen::Exact(n) => write!(f, "{n}"),
            ExpectedLen::AtLeast(n) => write!(f, "at least {n}"),
            ExpectedLen::OneOf(ns) => {
                write!(f, "one of [")?;
                for (i, n) in ns.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{n}")?;
                }
                write!(f, "]")
            }
            ExpectedLen::Multiple(n) => write!(f, "a multiple of {n}"),
        }
    }
}

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
        expected: ExpectedLen,
        got: usize,
    },

    #[error("invalid UTF-8 in text field")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("value out of range for {field}: {value}")]
    OutOfRange { field: &'static str, value: u64 },
}
