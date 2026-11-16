//! Explicitly enabled, pre-session UDP discovery hooks.

use crate::Role;
use dlep_core::RawDataItem;
use std::{
    any::Any,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Most extension data items all plugins together may add to one signal.
pub const MAX_DISCOVERY_EXTENSION_ITEMS: usize = 32;
/// Most extension bytes, including TLV headers, all plugins together may add
/// to one signal. Additions must also keep the whole signal within
/// [`MAX_DISCOVERY_SIGNAL_BYTES`].
pub const MAX_DISCOVERY_EXTENSION_BYTES: usize = 1024;
/// Largest encoded discovery signal a hook may produce: the UDP payload of an
/// IPv6 datagram on a 1500-byte MTU link (1500 − 40 − 8). Receivers read at
/// most one 1500-byte datagram and drop truncated ones, so larger signals
/// would be fragmented or silently discarded by every peer.
pub const MAX_DISCOVERY_SIGNAL_BYTES: usize = 1452;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryDirection {
    Incoming,
    Outgoing,
}

/// Datagram metadata, without a session identity or authentication guarantee.
/// Outgoing multicast has no peer; local/interface metadata is available for
/// received datagrams and their unicast replies, not periodic multicast sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryInfo {
    pub role: Role,
    pub direction: DiscoveryDirection,
    pub peer: Option<SocketAddr>,
    pub local_addr: Option<IpAddr>,
    pub interface_index: Option<u32>,
}

pub trait DiscoveryCtx {
    fn info(&self) -> DiscoveryInfo;
    fn emit_event(&mut self, event: Arc<dyn Any + Send + Sync>);

    /// Append an extension TLV to an outgoing standard discovery signal.
    /// Core/reserved types are rejected. Budgets include TLV headers and are
    /// shared by all plugins on this signal. Incoming contexts are read-only.
    fn add_data_item(&mut self, item: RawDataItem) -> Result<(), DiscoveryItemError> {
        let _ = item;
        Err(DiscoveryItemError::ReadOnly)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscoveryItemError {
    ReadOnly,
    InvalidType,
    TooManyItems,
    TooLarge,
}
impl std::fmt::Display for DiscoveryItemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "discovery context is read-only",
            Self::InvalidType => {
                "discovery extension cannot append a core or reserved data-item type"
            }
            Self::TooManyItems => "discovery extension item count exceeds the signal budget",
            Self::TooLarge => "discovery extension data exceeds the signal byte budget",
        })
    }
}
impl std::error::Error for DiscoveryItemError {}
