//! Wire types, data items and byte-level codec for DLEP (RFC 8175).
//!
//! This crate is the foundation of the workspace. It has no dependencies on
//! tokio, rustls or socket2 — only `bytes`, `thiserror` and `ipnet`. Anything
//! that touches I/O or state machines lives in sibling crates.

#![allow(dead_code)]

pub mod codec;
pub mod data_item;
pub mod error;
pub mod ids;
pub mod mac;
pub mod message;
pub mod signal;
pub mod status;

pub use data_item::{DataItem, RawDataItem};
pub use error::{CodecError, ExpectedLen};
pub use ids::{DataItemType, ExtensionId, MessageType, SignalType};
pub use mac::MacAddress;
pub use message::Message;
pub use signal::Signal;
pub use status::StatusCode;

/// ASCII prefix used on every DLEP UDP discovery signal (RFC 8175 §11.1).
pub const SIGNAL_PREFIX: &[u8; 4] = b"DLEP";

/// Default IANA-assigned TCP/UDP port for DLEP.
pub const DEFAULT_PORT: u16 = 854;

/// RFC 8175 §7.3.1 requires the heartbeat interval to be at least one second.
pub const MIN_HEARTBEAT_INTERVAL_MS: u32 = 1_000;

/// IANA-assigned IPv4 link-local multicast group for discovery.
pub const DISCOVERY_IPV4_GROUP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(224, 0, 0, 117);

/// IANA-assigned IPv6 link-local multicast group for discovery.
pub const DISCOVERY_IPV6_GROUP: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x7);
