use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::Bytes;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::ids::{DataItemType, ExtensionId};
use crate::mac::MacAddress;
use crate::status::StatusCode;

/// Low-level, untyped TLV data item. Useful for forward-compat and for
/// extensions that carry their own value encoding.
#[derive(Clone, Debug)]
pub struct RawDataItem {
    pub type_id: DataItemType,
    pub value: Bytes,
}

/// Peer Type flags (RFC 8175 §13.4.4).
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerFlags {
    pub smi: bool,
}

/// IPv4/IPv6 Connection Point sub-flags (RFC 8175 §13.4.2 / §13.4.3).
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionPointFlags {
    pub use_tls: bool,
}

/// Typed DLEP Data Item. `Unknown` preserves forward compatibility: the
/// decoder never fails on an unrecognized type_id and extension code paths
/// can introspect the raw bytes.
#[derive(Clone, Debug)]
pub enum DataItem {
    Status {
        code: StatusCode,
        text: String,
    },
    Ipv4ConnectionPoint {
        flags: ConnectionPointFlags,
        addr: Ipv4Addr,
        port: Option<u16>,
    },
    Ipv6ConnectionPoint {
        flags: ConnectionPointFlags,
        addr: Ipv6Addr,
        port: Option<u16>,
    },
    PeerType {
        flags: PeerFlags,
        description: String,
    },
    HeartbeatInterval(Duration),
    ExtensionsSupported(Vec<ExtensionId>),
    MacAddress(MacAddress),
    Ipv4Address {
        add: bool,
        addr: Ipv4Addr,
    },
    Ipv6Address {
        add: bool,
        addr: Ipv6Addr,
    },
    Ipv4AttachedSubnet {
        add: bool,
        subnet: Ipv4Net,
    },
    Ipv6AttachedSubnet {
        add: bool,
        subnet: Ipv6Net,
    },
    MaxDataRateReceive(u64),
    MaxDataRateTransmit(u64),
    CurrentDataRateReceive(u64),
    CurrentDataRateTransmit(u64),
    Latency(Duration),
    Resources(u8),
    RelativeLinkQualityReceive(u8),
    RelativeLinkQualityTransmit(u8),
    Mtu(u16),
    Unknown(RawDataItem),
}

impl DataItem {
    pub fn type_id(&self) -> DataItemType {
        match self {
            DataItem::Status { .. } => DataItemType::STATUS,
            DataItem::Ipv4ConnectionPoint { .. } => DataItemType::IPV4_CONNECTION_POINT,
            DataItem::Ipv6ConnectionPoint { .. } => DataItemType::IPV6_CONNECTION_POINT,
            DataItem::PeerType { .. } => DataItemType::PEER_TYPE,
            DataItem::HeartbeatInterval(_) => DataItemType::HEARTBEAT_INTERVAL,
            DataItem::ExtensionsSupported(_) => DataItemType::EXTENSIONS_SUPPORTED,
            DataItem::MacAddress(_) => DataItemType::MAC_ADDRESS,
            DataItem::Ipv4Address { .. } => DataItemType::IPV4_ADDRESS,
            DataItem::Ipv6Address { .. } => DataItemType::IPV6_ADDRESS,
            DataItem::Ipv4AttachedSubnet { .. } => DataItemType::IPV4_ATTACHED_SUBNET,
            DataItem::Ipv6AttachedSubnet { .. } => DataItemType::IPV6_ATTACHED_SUBNET,
            DataItem::MaxDataRateReceive(_) => DataItemType::MAXIMUM_DATA_RATE_RECEIVE,
            DataItem::MaxDataRateTransmit(_) => DataItemType::MAXIMUM_DATA_RATE_TRANSMIT,
            DataItem::CurrentDataRateReceive(_) => DataItemType::CURRENT_DATA_RATE_RECEIVE,
            DataItem::CurrentDataRateTransmit(_) => DataItemType::CURRENT_DATA_RATE_TRANSMIT,
            DataItem::Latency(_) => DataItemType::LATENCY,
            DataItem::Resources(_) => DataItemType::RESOURCES,
            DataItem::RelativeLinkQualityReceive(_) => DataItemType::RELATIVE_LINK_QUALITY_RECEIVE,
            DataItem::RelativeLinkQualityTransmit(_) => {
                DataItemType::RELATIVE_LINK_QUALITY_TRANSMIT
            }
            DataItem::Mtu(_) => DataItemType::MTU,
            DataItem::Unknown(r) => r.type_id,
        }
    }
}
