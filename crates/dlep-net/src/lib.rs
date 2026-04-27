//! Transport layer for DLEP.
//!
//! Responsibilities:
//! - UDP multicast discovery socket setup (IPv4 + IPv6).
//! - TCP session transport and TLS via `tokio-rustls`.
//! - GTSM enforcement (TTL = 255 on send; verify on receive).
//! - `tokio_util::codec` wrappers for `Signal` and `Message`.

#![allow(dead_code)]

pub mod addr;
pub mod discovery;
pub mod framed;
pub mod gtsm;
pub mod tls;
pub mod transport;

pub use framed::{MessageCodec, SignalCodec};
pub use transport::{Acceptor, Connector, Transport, TransportKind};

// Re-exported so daemon/binary consumers have a single import site for TLS
// configuration, and so the underlying TLS library can be swapped without
// churning every call site.
pub use rustls::{ClientConfig, ServerConfig};
