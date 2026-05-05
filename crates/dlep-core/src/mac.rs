use std::fmt;

/// MAC address used to identify a DLEP destination. RFC 8175 §13.7 permits
/// either EUI-48 (6 octets) or EUI-64 (8 octets) on the wire and requires
/// all destination MACs in a single session to share one format
/// (consistent with the modem's link-layer format).
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum MacAddress {
    Eui48([u8; 6]),
    Eui64([u8; 8]),
}

impl MacAddress {
    /// 6-octet broadcast (FF:FF:FF:FF:FF:FF). Use this in EUI-48 sessions.
    pub const BROADCAST_EUI48: Self = Self::Eui48([0xff; 6]);
    /// 8-octet broadcast. Use this in EUI-64 sessions.
    pub const BROADCAST_EUI64: Self = Self::Eui64([0xff; 8]);
    /// Alias for [`Self::BROADCAST_EUI48`]; preserves the M3-era name.
    pub const BROADCAST: Self = Self::BROADCAST_EUI48;

    pub const fn new_eui48(octets: [u8; 6]) -> Self {
        Self::Eui48(octets)
    }

    pub const fn new_eui64(octets: [u8; 8]) -> Self {
        Self::Eui64(octets)
    }

    /// Octets in network byte order. Length is 6 for EUI-48, 8 for EUI-64.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            MacAddress::Eui48(o) => o,
            MacAddress::Eui64(o) => o,
        }
    }

    /// Wire length in octets (RFC 8175 §13.7: 6 or 8).
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        match self {
            MacAddress::Eui48(_) => 6,
            MacAddress::Eui64(_) => 8,
        }
    }

    /// `true` if this is an EUI-48 (6-octet) address.
    pub const fn is_eui48(&self) -> bool {
        matches!(self, MacAddress::Eui48(_))
    }

    /// `true` if this is an EUI-64 (8-octet) address.
    pub const fn is_eui64(&self) -> bool {
        matches!(self, MacAddress::Eui64(_))
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for byte in self.as_bytes() {
            if first {
                first = false;
            } else {
                write!(f, ":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<[u8; 6]> for MacAddress {
    fn from(v: [u8; 6]) -> Self {
        Self::Eui48(v)
    }
}

impl From<[u8; 8]> for MacAddress {
    fn from(v: [u8; 8]) -> Self {
        Self::Eui64(v)
    }
}
