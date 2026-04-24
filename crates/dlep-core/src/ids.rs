//! Type-id newtypes for signals, messages, data items and extensions.
//!
//! All on-the-wire identifiers are 16-bit, network byte order. Using newtypes
//! (instead of bare `u16`) prevents accidental mixing between e.g. a
//! `MessageType` and a `DataItemType`.

macro_rules! id_newtype {
    ($(#[$m:meta])* $vis:vis $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
        $vis struct $name(pub u16);

        impl From<u16> for $name {
            fn from(v: u16) -> Self { Self(v) }
        }
        impl From<$name> for u16 {
            fn from(v: $name) -> u16 { v.0 }
        }
    };
}

id_newtype!(
    /// Signal type on the UDP discovery channel (RFC 8175 §13.1).
    pub SignalType
);
id_newtype!(
    /// Message type on the TCP session channel (RFC 8175 §13.2).
    pub MessageType
);
id_newtype!(
    /// Data item type inside a message or signal (RFC 8175 §13.4).
    pub DataItemType
);
id_newtype!(
    /// Extension identifier advertised in `Extensions Supported` (RFC 8175 §13.6).
    pub ExtensionId
);

impl SignalType {
    pub const PEER_DISCOVERY: Self = Self(1);
    pub const PEER_OFFER: Self = Self(2);
}

impl MessageType {
    pub const SESSION_INITIALIZATION: Self = Self(1);
    pub const SESSION_INITIALIZATION_RESPONSE: Self = Self(2);
    pub const SESSION_UPDATE: Self = Self(3);
    pub const SESSION_UPDATE_RESPONSE: Self = Self(4);
    pub const SESSION_TERMINATION: Self = Self(5);
    pub const SESSION_TERMINATION_RESPONSE: Self = Self(6);
    pub const DESTINATION_UP: Self = Self(7);
    pub const DESTINATION_UP_RESPONSE: Self = Self(8);
    pub const DESTINATION_ANNOUNCE: Self = Self(9);
    pub const DESTINATION_ANNOUNCE_RESPONSE: Self = Self(10);
    pub const DESTINATION_DOWN: Self = Self(11);
    pub const DESTINATION_DOWN_RESPONSE: Self = Self(12);
    pub const DESTINATION_UPDATE: Self = Self(13);
    pub const LINK_CHARACTERISTICS_REQUEST: Self = Self(14);
    pub const LINK_CHARACTERISTICS_RESPONSE: Self = Self(15);
    pub const HEARTBEAT: Self = Self(16);
}

impl DataItemType {
    pub const STATUS: Self = Self(1);
    pub const IPV4_CONNECTION_POINT: Self = Self(2);
    pub const IPV6_CONNECTION_POINT: Self = Self(3);
    pub const PEER_TYPE: Self = Self(4);
    pub const HEARTBEAT_INTERVAL: Self = Self(5);
    pub const EXTENSIONS_SUPPORTED: Self = Self(6);
    pub const MAC_ADDRESS: Self = Self(7);
    pub const IPV4_ADDRESS: Self = Self(8);
    pub const IPV6_ADDRESS: Self = Self(9);
    pub const IPV4_ATTACHED_SUBNET: Self = Self(10);
    pub const IPV6_ATTACHED_SUBNET: Self = Self(11);
    pub const MAXIMUM_DATA_RATE_RECEIVE: Self = Self(12);
    pub const MAXIMUM_DATA_RATE_TRANSMIT: Self = Self(13);
    pub const CURRENT_DATA_RATE_RECEIVE: Self = Self(14);
    pub const CURRENT_DATA_RATE_TRANSMIT: Self = Self(15);
    pub const LATENCY: Self = Self(16);
    pub const RESOURCES: Self = Self(17);
    pub const RELATIVE_LINK_QUALITY_RECEIVE: Self = Self(18);
    pub const RELATIVE_LINK_QUALITY_TRANSMIT: Self = Self(19);
    pub const MTU: Self = Self(20);
}
