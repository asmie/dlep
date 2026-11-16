use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// Destination address format of the modem's router-facing link (§13.7).
/// This is a local session policy, not a negotiated wire parameter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MacAddressFormat {
    #[default]
    Eui48,
    Eui64,
}

impl MacAddressFormat {
    pub fn accepts(self, mac: MacAddress) -> bool {
        matches!(
            (self, mac),
            (Self::Eui48, MacAddress::Eui48(_)) | (Self::Eui64, MacAddress::Eui64(_))
        )
    }
}

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

/// Error from parsing a [`MacAddress`] from text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum MacParseError {
    /// A part between colons is empty, longer than two characters, or not
    /// made of ASCII hexadecimal digits (signs and other separators included).
    #[error("MAC address octets must be one or two hexadecimal digits separated by colons")]
    InvalidOctet,
    /// The text has a number of octets other than six (EUI-48) or eight (EUI-64).
    #[error("MAC address needs six or eight octets, found {0}")]
    OctetCount(usize),
}

/// Parses colon-separated octets of one or two ASCII hexadecimal digits
/// (either case), six for EUI-48 or eight for EUI-64, such as
/// `02:00:00:0a:0b:1`. The [`Display`](fmt::Display) form always parses back.
impl FromStr for MacAddress {
    type Err = MacParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut octets = [0u8; 8];
        let mut count = 0usize;
        for part in text.split(':') {
            // `u8::from_str_radix` alone would also accept a leading `+`.
            if !(1..=2).contains(&part.len()) || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(MacParseError::InvalidOctet);
            }
            if let Some(octet) = octets.get_mut(count) {
                *octet = u8::from_str_radix(part, 16).expect("validated hexadecimal digits");
            }
            count += 1;
        }
        match count {
            6 => {
                let mut eui48 = [0u8; 6];
                eui48.copy_from_slice(&octets[..6]);
                Ok(Self::Eui48(eui48))
            }
            8 => Ok(Self::Eui64(octets)),
            count => Err(MacParseError::OctetCount(count)),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_eui48_and_eui64_with_one_or_two_digit_octets() {
        assert_eq!(
            "02:00:00:0a:0B:1".parse::<MacAddress>(),
            Ok(MacAddress::new_eui48([2, 0, 0, 10, 11, 1]))
        );
        assert_eq!(
            "2:0:0:0:0:0:0:ff".parse::<MacAddress>(),
            Ok(MacAddress::new_eui64([2, 0, 0, 0, 0, 0, 0, 0xff]))
        );
        for mac in [
            MacAddress::new_eui48([0x02, 0xab, 0, 0, 0, 0x01]),
            MacAddress::BROADCAST_EUI64,
        ] {
            assert_eq!(mac.to_string().parse::<MacAddress>(), Ok(mac));
        }
    }

    #[test]
    fn rejects_signs_separators_empty_parts_and_wrong_counts() {
        for bad in [
            "",
            "+2:+0:+0:+0:+0:+1",
            "02:00:00:00:00:+f",
            "-2:00:00:00:00:01",
            "02-00-00-00-00-01",
            "02.00.00.00.00.01",
            "002:00:00:00:00:01",
            "02:00::00:00:01",
            "02:00:00:00:00:01:",
            " 02:00:00:00:00:01",
            "zz:00:00:00:00:01",
            "0x:00:00:00:00:01",
        ] {
            assert_eq!(
                bad.parse::<MacAddress>(),
                Err(MacParseError::InvalidOctet),
                "{bad:?}"
            );
        }
        for (bad, count) in [
            ("02", 1),
            ("02:00:00:00:00", 5),
            ("02:00:00:00:00:00:00", 7),
            ("02:00:00:00:00:00:00:00:00", 9),
        ] {
            assert_eq!(
                bad.parse::<MacAddress>(),
                Err(MacParseError::OctetCount(count)),
                "{bad:?}"
            );
        }
        assert_eq!(
            MacParseError::OctetCount(5).to_string(),
            "MAC address needs six or eight octets, found 5"
        );
    }
}
