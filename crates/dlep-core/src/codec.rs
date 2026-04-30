//! Byte-level encoding and decoding primitives.
//!
//! These helpers live in `dlep-core` so that any crate can serialize or parse
//! DLEP wire bytes without dragging in tokio. The async-friendly
//! `tokio_util::codec::{Decoder, Encoder}` wrappers live in `dlep-net`.
//!
//! All multi-byte integers are big-endian (network byte order). UTF-8 strings
//! inside Data Items have no length prefix and no NUL terminator; their length
//! is governed by the surrounding TLV header. Insertion order of Data Items is
//! preserved on encode and is decode-stable.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use ipnet::{Ipv4Net, Ipv6Net};

use crate::SIGNAL_PREFIX;
use crate::data_item::{ConnectionPointFlags, DataItem, PeerFlags, RawDataItem};
use crate::error::{CodecError, ExpectedLen};
use crate::ids::{DataItemType, ExtensionId, MessageType, SignalType};
use crate::mac::MacAddress;
use crate::message::Message;
use crate::signal::Signal;
use crate::status::StatusCode;

/// Length of the fixed-size signal header: `"DLEP" (4) || type (2) || length (2)`.
pub const SIGNAL_HEADER_LEN: usize = 8;

/// Length of the fixed-size message header: `type (2) || length (2)`.
pub const MESSAGE_HEADER_LEN: usize = 4;

/// Field-name labels used in `CodecError::OutOfRange`. Keeps the literals in
/// one place so a rename touches one site, not ten, and a typo at a call site
/// becomes a compile error rather than a silent diagnostic regression.
mod field {
    pub const HEARTBEAT_INTERVAL_MS: &str = "heartbeat_interval_ms";
    pub const LATENCY_US: &str = "latency_us";
    pub const RESOURCES: &str = "resources";
    pub const RLQ_RECEIVE: &str = "relative_link_quality_receive";
    pub const RLQ_TRANSMIT: &str = "relative_link_quality_transmit";
    pub const IPV4_ATTACHED_SUBNET_PREFIX: &str = "ipv4_attached_subnet_prefix";
    pub const IPV6_ATTACHED_SUBNET_PREFIX: &str = "ipv6_attached_subnet_prefix";
    pub const DATA_ITEM_VALUE_LENGTH: &str = "data_item_value_length";
    pub const SIGNAL_BODY_LENGTH: &str = "signal_body_length";
    pub const MESSAGE_BODY_LENGTH: &str = "message_body_length";
}

impl RawDataItem {
    /// Encode this raw TLV onto `out`. Validates the value length upfront —
    /// extension/forward-compat callers using `DataItem::Unknown(raw)` must
    /// not silently truncate when `value.len() > u16::MAX`.
    pub fn encode(&self, out: &mut BytesMut) -> Result<(), CodecError> {
        let len = u16_length(field::DATA_ITEM_VALUE_LENGTH, self.value.len())?;
        out.put_u16(self.type_id.0);
        out.put_u16(len);
        out.put_slice(&self.value);
        Ok(())
    }

    pub fn decode(src: &mut Bytes) -> Result<Self, CodecError> {
        ensure_len(src.remaining(), 4)?;
        let type_id = DataItemType(src.get_u16());
        let len = src.get_u16() as usize;
        ensure_len(src.remaining(), len)?;
        let value = src.split_to(len);
        Ok(RawDataItem { type_id, value })
    }
}

impl DataItem {
    /// Encode this typed Data Item — including its 4-byte TLV header —
    /// onto `out`. Writes directly into the caller's buffer; on error `out`
    /// is restored to its starting length so the caller can recover.
    ///
    /// Returns an error for values that cannot be expressed on the wire:
    ///
    /// * `Resources` / `RelativeLinkQuality{Receive,Transmit}` outside `0..=100`
    ///   (per RFC 8175 §13.17–§13.19)
    /// * `HeartbeatInterval` whose milliseconds exceed `u32::MAX`
    /// * `Latency` whose microseconds exceed `u64::MAX`
    ///
    /// `Ipv4AttachedSubnet` / `Ipv6AttachedSubnet` always emit the **network
    /// address** (host bits truncated to the prefix), per RFC 8175 §13.10–§13.11.
    /// `decode` symmetrically truncates non-canonical input, so a peer that
    /// puts host bits on the wire is normalized in memory rather than silently
    /// re-canonicalized on the next encode.
    pub fn encode(&self, out: &mut BytesMut) -> Result<(), CodecError> {
        let restore_to = out.len();
        match self.encode_into(out) {
            Ok(()) => Ok(()),
            Err(e) => {
                out.truncate(restore_to);
                Err(e)
            }
        }
    }

    fn encode_into(&self, out: &mut BytesMut) -> Result<(), CodecError> {
        if let DataItem::Unknown(raw) = self {
            return raw.encode(out);
        }

        // For variable-length variants, project the wire length up-front so
        // an oversized payload errors immediately instead of allocating
        // multi-MB into `out` only to roll back via `truncate` on the
        // post-write `u16_length` check.
        if let Some(projected) = self.projected_value_len() {
            u16_length(field::DATA_ITEM_VALUE_LENGTH, projected)?;
        }

        // Avoids a temp `BytesMut` per item: write the type, leave the length
        // as a placeholder, append the value bytes, then patch the placeholder.
        out.put_u16(self.type_id().0);
        let len_pos = out.len();
        out.put_u16(0);
        let value_start = out.len();

        match self {
            DataItem::Status { code, text } => {
                out.put_u8(code.0);
                out.put_slice(text.as_bytes());
            }
            DataItem::Ipv4ConnectionPoint { flags, addr, port } => {
                out.put_u8(encode_cp_flags(*flags));
                out.put_slice(&addr.octets());
                if let Some(p) = port {
                    out.put_u16(*p);
                }
            }
            DataItem::Ipv6ConnectionPoint { flags, addr, port } => {
                out.put_u8(encode_cp_flags(*flags));
                out.put_slice(&addr.octets());
                if let Some(p) = port {
                    out.put_u16(*p);
                }
            }
            DataItem::PeerType { flags, description } => {
                out.put_u8(encode_peer_flags(*flags));
                out.put_slice(description.as_bytes());
            }
            DataItem::HeartbeatInterval(d) => {
                let ms = d.as_millis();
                if ms > u32::MAX as u128 {
                    return Err(CodecError::OutOfRange {
                        field: field::HEARTBEAT_INTERVAL_MS,
                        value: u64::try_from(ms).unwrap_or(u64::MAX),
                    });
                }
                out.put_u32(ms as u32);
            }
            DataItem::ExtensionsSupported(ids) => {
                for id in ids {
                    out.put_u16(id.0);
                }
            }
            DataItem::MacAddress(mac) => {
                out.put_slice(&mac.0);
            }
            DataItem::Ipv4Address { add, addr } => {
                out.put_u8(u8::from(*add));
                out.put_slice(&addr.octets());
            }
            DataItem::Ipv6Address { add, addr } => {
                out.put_u8(u8::from(*add));
                out.put_slice(&addr.octets());
            }
            DataItem::Ipv4AttachedSubnet { add, subnet } => {
                out.put_u8(u8::from(*add));
                out.put_slice(&subnet.network().octets());
                out.put_u8(subnet.prefix_len());
            }
            DataItem::Ipv6AttachedSubnet { add, subnet } => {
                out.put_u8(u8::from(*add));
                out.put_slice(&subnet.network().octets());
                out.put_u8(subnet.prefix_len());
            }
            DataItem::MaxDataRateReceive(bps)
            | DataItem::MaxDataRateTransmit(bps)
            | DataItem::CurrentDataRateReceive(bps)
            | DataItem::CurrentDataRateTransmit(bps) => {
                out.put_u64(*bps);
            }
            DataItem::Latency(d) => {
                let us = d.as_micros();
                if us > u64::MAX as u128 {
                    // Threshold equals u64::MAX, so any overflow is by
                    // definition unrepresentable as u64 — there is no
                    // informative actual value to surface (unlike
                    // `HeartbeatInterval`, whose threshold is u32::MAX so
                    // the actual ms can still fit in the report).
                    return Err(CodecError::OutOfRange {
                        field: field::LATENCY_US,
                        value: u64::MAX,
                    });
                }
                out.put_u64(us as u64);
            }
            DataItem::Resources(pct) => {
                check_percent(field::RESOURCES, *pct)?;
                out.put_u8(*pct);
            }
            DataItem::RelativeLinkQualityReceive(pct) => {
                check_percent(field::RLQ_RECEIVE, *pct)?;
                out.put_u8(*pct);
            }
            DataItem::RelativeLinkQualityTransmit(pct) => {
                check_percent(field::RLQ_TRANSMIT, *pct)?;
                out.put_u8(*pct);
            }
            DataItem::Mtu(mtu) => {
                out.put_u16(*mtu);
            }
            DataItem::Unknown(_) => unreachable!("Unknown handled by early return"),
        }

        let value_len = out.len() - value_start;
        let len_u16 = u16_length(field::DATA_ITEM_VALUE_LENGTH, value_len)?;
        out[len_pos..len_pos + 2].copy_from_slice(&len_u16.to_be_bytes());
        Ok(())
    }

    /// Projected wire length for variants whose value bytes are dominated by
    /// caller-controlled data: text strings or `Vec`s. Returns `None` for
    /// fixed- or small-bounded-length variants where the post-write
    /// `u16_length` check is already O(1) cheap. `saturating_mul` guards
    /// against pathological `usize` overflow on 32-bit targets — the
    /// `u16_length` check then catches the saturated value as out-of-range.
    fn projected_value_len(&self) -> Option<usize> {
        match self {
            DataItem::Status { text, .. } => Some(1usize.saturating_add(text.len())),
            DataItem::PeerType { description, .. } => {
                Some(1usize.saturating_add(description.len()))
            }
            DataItem::ExtensionsSupported(ids) => Some(ids.len().saturating_mul(2)),
            _ => None,
        }
    }

    /// Lift a parsed `RawDataItem` into a typed `DataItem`. Unknown type ids
    /// fall through to `DataItem::Unknown`, preserving forward compatibility
    /// (RFC 8175 §13: "implementations MUST silently discard any Data Item
    /// they do not recognise"). Length errors and value-range errors are
    /// reported.
    ///
    /// `Ipv4AttachedSubnet` / `Ipv6AttachedSubnet` are normalized to network
    /// form here — host bits in non-canonical wire input are zeroed so the
    /// in-memory representation matches what `encode` would produce, and
    /// equality comparisons across peer-sent subnets are stable.
    pub fn decode(raw: RawDataItem) -> Result<Self, CodecError> {
        let kind = raw.type_id;
        let len = raw.value.len();
        let v = &raw.value[..];

        match kind {
            DataItemType::STATUS => {
                if len < 1 {
                    return Err(CodecError::InvalidDataItemLength {
                        kind,
                        expected: ExpectedLen::AtLeast(1),
                        got: len,
                    });
                }
                let code = StatusCode(v[0]);
                let text = String::from_utf8(v[1..].to_vec())?;
                Ok(DataItem::Status { code, text })
            }
            DataItemType::IPV4_CONNECTION_POINT => {
                if len != 5 && len != 7 {
                    return Err(CodecError::InvalidDataItemLength {
                        kind,
                        expected: ExpectedLen::OneOf(&[5, 7]),
                        got: len,
                    });
                }
                let flags = decode_cp_flags(v[0]);
                let addr = Ipv4Addr::new(v[1], v[2], v[3], v[4]);
                let port = (len == 7).then(|| u16::from_be_bytes([v[5], v[6]]));
                Ok(DataItem::Ipv4ConnectionPoint { flags, addr, port })
            }
            DataItemType::IPV6_CONNECTION_POINT => {
                if len != 17 && len != 19 {
                    return Err(CodecError::InvalidDataItemLength {
                        kind,
                        expected: ExpectedLen::OneOf(&[17, 19]),
                        got: len,
                    });
                }
                let flags = decode_cp_flags(v[0]);
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&v[1..17]);
                let addr = Ipv6Addr::from(octets);
                let port = (len == 19).then(|| u16::from_be_bytes([v[17], v[18]]));
                Ok(DataItem::Ipv6ConnectionPoint { flags, addr, port })
            }
            DataItemType::PEER_TYPE => {
                if len < 1 {
                    return Err(CodecError::InvalidDataItemLength {
                        kind,
                        expected: ExpectedLen::AtLeast(1),
                        got: len,
                    });
                }
                let flags = decode_peer_flags(v[0]);
                let description = String::from_utf8(v[1..].to_vec())?;
                Ok(DataItem::PeerType { flags, description })
            }
            DataItemType::HEARTBEAT_INTERVAL => {
                expect_exact(kind, len, 4)?;
                let ms = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                Ok(DataItem::HeartbeatInterval(Duration::from_millis(
                    ms.into(),
                )))
            }
            DataItemType::EXTENSIONS_SUPPORTED => {
                if len % 2 != 0 {
                    return Err(CodecError::InvalidDataItemLength {
                        kind,
                        expected: ExpectedLen::Multiple(2),
                        got: len,
                    });
                }
                let mut ids = Vec::with_capacity(len / 2);
                let mut i = 0;
                while i < len {
                    ids.push(ExtensionId(u16::from_be_bytes([v[i], v[i + 1]])));
                    i += 2;
                }
                Ok(DataItem::ExtensionsSupported(ids))
            }
            DataItemType::MAC_ADDRESS => {
                // RFC 8175 §13.7 fixes MAC Address at exactly 6 octets (EUI-48).
                // RFC 8703 introduces a separate Link Identifier Data Item to
                // carry destination IDs of arbitrary length; that lives in the
                // dlep-ext-lid extension crate, not as a length variant here.
                expect_exact(kind, len, 6)?;
                let mut octets = [0u8; 6];
                octets.copy_from_slice(&v[..6]);
                Ok(DataItem::MacAddress(MacAddress(octets)))
            }
            DataItemType::IPV4_ADDRESS => {
                expect_exact(kind, len, 5)?;
                let add = (v[0] & 0x01) != 0;
                let addr = Ipv4Addr::new(v[1], v[2], v[3], v[4]);
                Ok(DataItem::Ipv4Address { add, addr })
            }
            DataItemType::IPV6_ADDRESS => {
                expect_exact(kind, len, 17)?;
                let add = (v[0] & 0x01) != 0;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&v[1..17]);
                Ok(DataItem::Ipv6Address {
                    add,
                    addr: Ipv6Addr::from(octets),
                })
            }
            DataItemType::IPV4_ATTACHED_SUBNET => {
                expect_exact(kind, len, 6)?;
                let add = (v[0] & 0x01) != 0;
                let addr = Ipv4Addr::new(v[1], v[2], v[3], v[4]);
                let prefix = v[5];
                // Normalize host bits to zero so encode/decode are symmetric:
                // a peer that sends `10.0.0.5/24` and one that sends
                // `10.0.0.0/24` produce identical in-memory subnets, and
                // re-encoding never silently changes the value.
                let subnet = Ipv4Net::new(addr, prefix)
                    .map_err(|_| CodecError::OutOfRange {
                        field: field::IPV4_ATTACHED_SUBNET_PREFIX,
                        value: prefix as u64,
                    })?
                    .trunc();
                Ok(DataItem::Ipv4AttachedSubnet { add, subnet })
            }
            DataItemType::IPV6_ATTACHED_SUBNET => {
                expect_exact(kind, len, 18)?;
                let add = (v[0] & 0x01) != 0;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&v[1..17]);
                let prefix = v[17];
                let subnet = Ipv6Net::new(Ipv6Addr::from(octets), prefix)
                    .map_err(|_| CodecError::OutOfRange {
                        field: field::IPV6_ATTACHED_SUBNET_PREFIX,
                        value: prefix as u64,
                    })?
                    .trunc();
                Ok(DataItem::Ipv6AttachedSubnet { add, subnet })
            }
            DataItemType::MAXIMUM_DATA_RATE_RECEIVE => {
                expect_exact(kind, len, 8)?;
                Ok(DataItem::MaxDataRateReceive(read_u64_be(v)))
            }
            DataItemType::MAXIMUM_DATA_RATE_TRANSMIT => {
                expect_exact(kind, len, 8)?;
                Ok(DataItem::MaxDataRateTransmit(read_u64_be(v)))
            }
            DataItemType::CURRENT_DATA_RATE_RECEIVE => {
                expect_exact(kind, len, 8)?;
                Ok(DataItem::CurrentDataRateReceive(read_u64_be(v)))
            }
            DataItemType::CURRENT_DATA_RATE_TRANSMIT => {
                expect_exact(kind, len, 8)?;
                Ok(DataItem::CurrentDataRateTransmit(read_u64_be(v)))
            }
            DataItemType::LATENCY => {
                expect_exact(kind, len, 8)?;
                Ok(DataItem::Latency(Duration::from_micros(read_u64_be(v))))
            }
            DataItemType::RESOURCES => Ok(DataItem::Resources(decode_percent(
                kind,
                v,
                field::RESOURCES,
            )?)),
            DataItemType::RELATIVE_LINK_QUALITY_RECEIVE => Ok(
                DataItem::RelativeLinkQualityReceive(decode_percent(kind, v, field::RLQ_RECEIVE)?),
            ),
            DataItemType::RELATIVE_LINK_QUALITY_TRANSMIT => {
                Ok(DataItem::RelativeLinkQualityTransmit(decode_percent(
                    kind,
                    v,
                    field::RLQ_TRANSMIT,
                )?))
            }
            DataItemType::MTU => {
                expect_exact(kind, len, 2)?;
                Ok(DataItem::Mtu(u16::from_be_bytes([v[0], v[1]])))
            }
            _ => Ok(DataItem::Unknown(raw)),
        }
    }
}

impl Signal {
    /// Encode this signal into a fresh `BytesMut`. Returns an error if any
    /// contained `DataItem` cannot be expressed on the wire (see
    /// [`DataItem::encode`] for which values can fail).
    pub fn encode(&self) -> Result<BytesMut, CodecError> {
        let mut body = BytesMut::new();
        for item in &self.data_items {
            item.encode(&mut body)?;
        }
        let body_len = u16_length(field::SIGNAL_BODY_LENGTH, body.len())?;
        let mut out = BytesMut::with_capacity(SIGNAL_HEADER_LEN + body.len());
        out.put_slice(SIGNAL_PREFIX);
        out.put_u16(self.signal_type.0);
        out.put_u16(body_len);
        out.put(body);
        Ok(out)
    }

    pub fn decode(mut src: Bytes) -> Result<Self, CodecError> {
        ensure_len(src.remaining(), SIGNAL_HEADER_LEN)?;
        let mut prefix = [0u8; 4];
        src.copy_to_slice(&mut prefix);
        if &prefix != SIGNAL_PREFIX {
            return Err(CodecError::MissingSignalPrefix);
        }
        let signal_type = SignalType(src.get_u16());
        let declared = src.get_u16() as usize;
        if src.remaining() < declared {
            return Err(CodecError::LengthMismatch {
                declared,
                remaining: src.remaining(),
            });
        }
        let mut body = src.split_to(declared);
        let mut data_items = Vec::new();
        while body.has_remaining() {
            let raw = RawDataItem::decode(&mut body)?;
            data_items.push(DataItem::decode(raw)?);
        }
        Ok(Signal {
            signal_type,
            data_items,
        })
    }
}

impl Message {
    /// Encode this message into a fresh `BytesMut`. Returns an error if any
    /// contained `DataItem` cannot be expressed on the wire (see
    /// [`DataItem::encode`] for which values can fail).
    pub fn encode(&self) -> Result<BytesMut, CodecError> {
        let mut body = BytesMut::new();
        for item in &self.data_items {
            item.encode(&mut body)?;
        }
        let body_len = u16_length(field::MESSAGE_BODY_LENGTH, body.len())?;
        let mut out = BytesMut::with_capacity(MESSAGE_HEADER_LEN + body.len());
        out.put_u16(self.message_type.0);
        out.put_u16(body_len);
        out.put(body);
        Ok(out)
    }

    pub fn decode(mut src: Bytes) -> Result<Self, CodecError> {
        ensure_len(src.remaining(), MESSAGE_HEADER_LEN)?;
        let message_type = MessageType(src.get_u16());
        let declared = src.get_u16() as usize;
        if src.remaining() < declared {
            return Err(CodecError::LengthMismatch {
                declared,
                remaining: src.remaining(),
            });
        }
        let mut body = src.split_to(declared);
        let mut data_items = Vec::new();
        while body.has_remaining() {
            let raw = RawDataItem::decode(&mut body)?;
            data_items.push(DataItem::decode(raw)?);
        }
        Ok(Message {
            message_type,
            data_items,
        })
    }
}

fn ensure_len(have: usize, needed: usize) -> Result<(), CodecError> {
    if have < needed {
        Err(CodecError::Truncated { needed, have })
    } else {
        Ok(())
    }
}

fn expect_exact(kind: DataItemType, got: usize, expected: usize) -> Result<(), CodecError> {
    if got == expected {
        Ok(())
    } else {
        Err(CodecError::InvalidDataItemLength {
            kind,
            expected: ExpectedLen::Exact(expected),
            got,
        })
    }
}

fn read_u64_be(value: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&value[..8]);
    u64::from_be_bytes(buf)
}

// All single-bit flag fields in RFC 8175 §13 (T in §13.2/§13.3, S in §13.4,
// A in §13.8/§13.9/§13.10/§13.11) sit at the **rightmost** column of the
// 8-bit IETF wire diagram — i.e. bit 7 in IETF numbering, the LSB of the
// octet, mask `0x01`. The leftmost seven bits are Reserved (MUST be zero).
// Encoding the named flag at any other position would set a Reserved bit and
// place the flag where peers expect zero.

fn encode_cp_flags(flags: ConnectionPointFlags) -> u8 {
    u8::from(flags.use_tls)
}

fn decode_cp_flags(byte: u8) -> ConnectionPointFlags {
    ConnectionPointFlags {
        use_tls: (byte & 0x01) != 0,
    }
}

fn encode_peer_flags(flags: PeerFlags) -> u8 {
    u8::from(flags.smi)
}

fn decode_peer_flags(byte: u8) -> PeerFlags {
    PeerFlags {
        smi: (byte & 0x01) != 0,
    }
}

fn check_percent(field: &'static str, pct: u8) -> Result<(), CodecError> {
    if pct > 100 {
        Err(CodecError::OutOfRange {
            field,
            value: pct as u64,
        })
    } else {
        Ok(())
    }
}

/// Decode the body of a percentage Data Item — Resources, Relative Link
/// Quality Receive/Transmit. All three share the same wire shape (single
/// `u8` in `0..=100`) and only differ in the field name surfaced on error.
fn decode_percent(kind: DataItemType, value: &[u8], field: &'static str) -> Result<u8, CodecError> {
    expect_exact(kind, value.len(), 1)?;
    let pct = value[0];
    check_percent(field, pct)?;
    Ok(pct)
}

/// Convert a buffer length to the `u16` width used by every DLEP TLV
/// length field. Returns `OutOfRange` rather than silently truncating, which
/// would produce a corrupt frame.
fn u16_length(field: &'static str, len: usize) -> Result<u16, CodecError> {
    u16::try_from(len).map_err(|_| CodecError::OutOfRange {
        field,
        value: len as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_one(item: DataItem) -> Vec<u8> {
        let mut buf = BytesMut::new();
        item.encode(&mut buf).expect("encode should not fail");
        buf.to_vec()
    }

    fn decode_one(bytes: &[u8]) -> DataItem {
        let mut b = Bytes::copy_from_slice(bytes);
        let raw = RawDataItem::decode(&mut b).unwrap();
        DataItem::decode(raw).unwrap()
    }

    #[test]
    fn empty_message_roundtrips() {
        let m = Message::new(MessageType::HEARTBEAT);
        let bytes = m.encode().unwrap().freeze();
        let decoded = Message::decode(bytes).unwrap();
        assert_eq!(decoded.message_type, MessageType::HEARTBEAT);
        assert!(decoded.data_items.is_empty());
    }

    #[test]
    fn empty_signal_roundtrips() {
        let s = Signal::new(SignalType::PEER_DISCOVERY);
        let bytes = s.encode().unwrap().freeze();
        let decoded = Signal::decode(bytes).unwrap();
        assert_eq!(decoded.signal_type, SignalType::PEER_DISCOVERY);
    }

    #[test]
    fn signal_rejects_bad_prefix() {
        let mut bad = BytesMut::from(&b"XLEP"[..]);
        bad.put_u16(1);
        bad.put_u16(0);
        let err = Signal::decode(bad.freeze()).unwrap_err();
        assert!(matches!(err, CodecError::MissingSignalPrefix));
    }

    // --- Per-variant byte-vector tests ---

    #[test]
    fn status_encodes_with_text() {
        let item = DataItem::Status {
            code: StatusCode::SUCCESS,
            text: "ok".into(),
        };
        // type=1, length=3, value=00 'o' 'k'
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x01, 0x00, 0x03, 0x00, b'o', b'k']
        );
    }

    #[test]
    fn status_roundtrips_terminate_code() {
        let item = DataItem::Status {
            code: StatusCode::TIMED_OUT,
            text: "deadline".into(),
        };
        let bytes = encode_one(item);
        let DataItem::Status { code, text } = decode_one(&bytes) else {
            panic!("wrong variant")
        };
        assert_eq!(code, StatusCode::TIMED_OUT);
        assert_eq!(text, "deadline");
    }

    #[test]
    fn status_with_empty_text_roundtrips() {
        let item = DataItem::Status {
            code: StatusCode::SUCCESS,
            text: String::new(),
        };
        let bytes = encode_one(item);
        // type=1, length=1, value=00
        assert_eq!(bytes, vec![0x00, 0x01, 0x00, 0x01, 0x00]);
        let DataItem::Status { code, text } = decode_one(&bytes) else {
            panic!()
        };
        assert_eq!(code, StatusCode::SUCCESS);
        assert!(text.is_empty());
    }

    #[test]
    fn status_with_zero_length_value_rejected() {
        let raw = RawDataItem {
            type_id: DataItemType::STATUS,
            value: Bytes::new(),
        };
        let err = DataItem::decode(raw).unwrap_err();
        assert!(matches!(
            err,
            CodecError::InvalidDataItemLength {
                kind: DataItemType::STATUS,
                ..
            }
        ));
    }

    #[test]
    fn ipv4_connection_point_with_port_encodes() {
        let item = DataItem::Ipv4ConnectionPoint {
            flags: ConnectionPointFlags { use_tls: true },
            addr: Ipv4Addr::new(10, 0, 0, 1),
            port: Some(854),
        };
        // type=2, length=7, flags=01, addr=10.0.0.1, port=854 (0x0356)
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x02, 0x00, 0x07, 0x01, 10, 0, 0, 1, 0x03, 0x56]
        );
    }

    #[test]
    fn ipv4_connection_point_length_between_valid_forms_rejected() {
        // Valid lengths are 5 (no port) or 7 (with port). Length 6 is illegal
        // — but a strict "expected: 5" message would be misleading. Confirm
        // we report `OneOf([5, 7])`.
        let raw = RawDataItem {
            type_id: DataItemType::IPV4_CONNECTION_POINT,
            value: Bytes::from_static(&[0, 1, 2, 3, 4, 5]),
        };
        match DataItem::decode(raw).unwrap_err() {
            CodecError::InvalidDataItemLength {
                kind: DataItemType::IPV4_CONNECTION_POINT,
                expected: ExpectedLen::OneOf(&[5, 7]),
                got: 6,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ipv6_connection_point_length_between_valid_forms_rejected() {
        let raw = RawDataItem {
            type_id: DataItemType::IPV6_CONNECTION_POINT,
            value: Bytes::from_static(&[0u8; 18]),
        };
        match DataItem::decode(raw).unwrap_err() {
            CodecError::InvalidDataItemLength {
                kind: DataItemType::IPV6_CONNECTION_POINT,
                expected: ExpectedLen::OneOf(&[17, 19]),
                got: 18,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn status_at_least_one_byte_error_carries_atleast() {
        let raw = RawDataItem {
            type_id: DataItemType::STATUS,
            value: Bytes::new(),
        };
        match DataItem::decode(raw).unwrap_err() {
            CodecError::InvalidDataItemLength {
                kind: DataItemType::STATUS,
                expected: ExpectedLen::AtLeast(1),
                got: 0,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn extensions_supported_odd_length_error_carries_multiple() {
        let raw = RawDataItem {
            type_id: DataItemType::EXTENSIONS_SUPPORTED,
            value: Bytes::from_static(&[0x00, 0x01, 0x00]),
        };
        match DataItem::decode(raw).unwrap_err() {
            CodecError::InvalidDataItemLength {
                kind: DataItemType::EXTENSIONS_SUPPORTED,
                expected: ExpectedLen::Multiple(2),
                got: 3,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ipv4_connection_point_without_port_roundtrips() {
        let item = DataItem::Ipv4ConnectionPoint {
            flags: ConnectionPointFlags::default(),
            addr: Ipv4Addr::new(192, 168, 1, 1),
            port: None,
        };
        let bytes = encode_one(item);
        assert_eq!(bytes.len(), 4 + 5);
        let DataItem::Ipv4ConnectionPoint { flags, addr, port } = decode_one(&bytes) else {
            panic!()
        };
        assert!(!flags.use_tls);
        assert_eq!(addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(port, None);
    }

    #[test]
    fn ipv6_connection_point_with_port_roundtrips() {
        let item = DataItem::Ipv6ConnectionPoint {
            flags: ConnectionPointFlags { use_tls: true },
            addr: "fe80::1".parse().unwrap(),
            port: Some(854),
        };
        let bytes = encode_one(item);
        assert_eq!(bytes.len(), 4 + 19);
        let DataItem::Ipv6ConnectionPoint { flags, addr, port } = decode_one(&bytes) else {
            panic!()
        };
        assert!(flags.use_tls);
        assert_eq!(addr, "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(port, Some(854));
    }

    #[test]
    fn ipv6_connection_point_without_port_roundtrips() {
        let item = DataItem::Ipv6ConnectionPoint {
            flags: ConnectionPointFlags::default(),
            addr: Ipv6Addr::LOCALHOST,
            port: None,
        };
        let bytes = encode_one(item);
        assert_eq!(bytes.len(), 4 + 17);
        let DataItem::Ipv6ConnectionPoint { port, .. } = decode_one(&bytes) else {
            panic!()
        };
        assert_eq!(port, None);
    }

    #[test]
    fn peer_type_encodes() {
        let item = DataItem::PeerType {
            flags: PeerFlags { smi: true },
            description: "modem".into(),
        };
        // type=4, length=6, flags=01, "modem"
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x04, 0x00, 0x06, 0x01, b'm', b'o', b'd', b'e', b'm']
        );
    }

    #[test]
    fn peer_type_with_empty_description_roundtrips() {
        let item = DataItem::PeerType {
            flags: PeerFlags::default(),
            description: String::new(),
        };
        let bytes = encode_one(item);
        let DataItem::PeerType { flags, description } = decode_one(&bytes) else {
            panic!()
        };
        assert!(!flags.smi);
        assert!(description.is_empty());
    }

    #[test]
    fn heartbeat_interval_encodes() {
        let item = DataItem::HeartbeatInterval(Duration::from_millis(60_000));
        // type=5, length=4, value=60000_u32_be (0x0000EA60)
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0xEA, 0x60]
        );
    }

    #[test]
    fn heartbeat_interval_overflow_rejected_on_encode() {
        let item = DataItem::HeartbeatInterval(Duration::from_secs(u64::MAX / 1000));
        let mut buf = BytesMut::new();
        let err = item.encode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
        // On encode failure the buffer is restored to its starting length.
        assert!(buf.is_empty());
    }

    #[test]
    fn heartbeat_interval_at_u32_max_encodes() {
        // u32::MAX milliseconds is the largest value the wire format can carry.
        let item = DataItem::HeartbeatInterval(Duration::from_millis(u32::MAX.into()));
        let bytes = encode_one(item);
        let DataItem::HeartbeatInterval(d) = decode_one(&bytes) else {
            panic!()
        };
        assert_eq!(d, Duration::from_millis(u32::MAX.into()));
    }

    #[test]
    fn extensions_supported_encodes_three_ids() {
        let item = DataItem::ExtensionsSupported(vec![
            ExtensionId(1),
            ExtensionId(2),
            ExtensionId(0xFFFF),
        ]);
        // type=6, length=6, value=0001 0002 FFFF
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x06, 0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFF]
        );
    }

    #[test]
    fn extensions_supported_empty_roundtrips() {
        let item = DataItem::ExtensionsSupported(Vec::new());
        let bytes = encode_one(item);
        // type=6, length=0
        assert_eq!(bytes, vec![0x00, 0x06, 0x00, 0x00]);
        let DataItem::ExtensionsSupported(ids) = decode_one(&bytes) else {
            panic!()
        };
        assert!(ids.is_empty());
    }

    #[test]
    fn extensions_supported_odd_length_rejected() {
        let raw = RawDataItem {
            type_id: DataItemType::EXTENSIONS_SUPPORTED,
            value: Bytes::from_static(&[0x00, 0x01, 0x00]),
        };
        let err = DataItem::decode(raw).unwrap_err();
        assert!(matches!(
            err,
            CodecError::InvalidDataItemLength {
                kind: DataItemType::EXTENSIONS_SUPPORTED,
                ..
            }
        ));
    }

    #[test]
    fn mac_address_encodes() {
        let item = DataItem::MacAddress(MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]));
        // type=7, length=6
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x07, 0x00, 0x06, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]
        );
    }

    #[test]
    fn mac_address_wrong_length_rejected() {
        // RFC 8703 will allow longer link IDs; until then, EUI-48 only.
        let raw = RawDataItem {
            type_id: DataItemType::MAC_ADDRESS,
            value: Bytes::from_static(&[0u8; 8]),
        };
        assert!(matches!(
            DataItem::decode(raw).unwrap_err(),
            CodecError::InvalidDataItemLength { .. }
        ));
    }

    #[test]
    fn ipv4_address_add_drop_flag_roundtrips() {
        let add = DataItem::Ipv4Address {
            add: true,
            addr: Ipv4Addr::new(1, 2, 3, 4),
        };
        let bytes = encode_one(add);
        assert_eq!(bytes, vec![0x00, 0x08, 0x00, 0x05, 0x01, 1, 2, 3, 4]);
        let DataItem::Ipv4Address { add, addr } = decode_one(&bytes) else {
            panic!()
        };
        assert!(add);
        assert_eq!(addr, Ipv4Addr::new(1, 2, 3, 4));

        let drop = DataItem::Ipv4Address {
            add: false,
            addr: Ipv4Addr::new(1, 2, 3, 4),
        };
        let bytes = encode_one(drop);
        assert_eq!(bytes[4], 0x00);
        let DataItem::Ipv4Address { add, .. } = decode_one(&bytes) else {
            panic!()
        };
        assert!(!add);
    }

    #[test]
    fn ipv6_address_roundtrips() {
        let item = DataItem::Ipv6Address {
            add: true,
            addr: "2001:db8::1".parse().unwrap(),
        };
        let bytes = encode_one(item);
        assert_eq!(bytes.len(), 4 + 17);
        let DataItem::Ipv6Address { add, addr } = decode_one(&bytes) else {
            panic!()
        };
        assert!(add);
        assert_eq!(addr, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn ipv4_attached_subnet_encodes() {
        let item = DataItem::Ipv4AttachedSubnet {
            add: true,
            subnet: "10.0.0.0/24".parse().unwrap(),
        };
        // type=10, length=6, flags=01, addr=10.0.0.0, prefix=24
        assert_eq!(
            encode_one(item),
            vec![0x00, 0x0A, 0x00, 0x06, 0x01, 10, 0, 0, 0, 24]
        );
    }

    #[test]
    fn ipv4_attached_subnet_bad_prefix_rejected() {
        let raw = RawDataItem {
            type_id: DataItemType::IPV4_ATTACHED_SUBNET,
            // 33 is out of range for IPv4
            value: Bytes::from_static(&[0x01, 10, 0, 0, 0, 33]),
        };
        let err = DataItem::decode(raw).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
    }

    #[test]
    fn ipv6_attached_subnet_roundtrips() {
        let item = DataItem::Ipv6AttachedSubnet {
            add: true,
            subnet: "2001:db8::/32".parse().unwrap(),
        };
        let bytes = encode_one(item);
        assert_eq!(bytes.len(), 4 + 18);
        let DataItem::Ipv6AttachedSubnet { add, subnet } = decode_one(&bytes) else {
            panic!()
        };
        assert!(add);
        assert_eq!(subnet, "2001:db8::/32".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn data_rate_variants_encode_as_u64() {
        let pairs = [
            (
                DataItem::MaxDataRateReceive(1_000_000_000),
                DataItemType::MAXIMUM_DATA_RATE_RECEIVE,
            ),
            (
                DataItem::MaxDataRateTransmit(1_000_000_000),
                DataItemType::MAXIMUM_DATA_RATE_TRANSMIT,
            ),
            (
                DataItem::CurrentDataRateReceive(500_000_000),
                DataItemType::CURRENT_DATA_RATE_RECEIVE,
            ),
            (
                DataItem::CurrentDataRateTransmit(500_000_000),
                DataItemType::CURRENT_DATA_RATE_TRANSMIT,
            ),
        ];
        for (item, ty) in pairs {
            let bytes = encode_one(item);
            assert_eq!(bytes.len(), 4 + 8);
            assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), ty.0);
            assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 8);
        }
    }

    #[test]
    fn latency_encodes_microseconds() {
        let item = DataItem::Latency(Duration::from_micros(0xDEAD_BEEF));
        let bytes = encode_one(item);
        // type=16, length=8
        assert_eq!(&bytes[..4], &[0x00, 0x10, 0x00, 0x08]);
        let DataItem::Latency(d) = decode_one(&bytes) else {
            panic!()
        };
        assert_eq!(d, Duration::from_micros(0xDEAD_BEEF));
    }

    #[test]
    fn resources_encodes_single_byte() {
        let item = DataItem::Resources(75);
        // type=17, length=1, value=0x4B
        assert_eq!(encode_one(item), vec![0x00, 0x11, 0x00, 0x01, 0x4B]);
    }

    #[test]
    fn resources_above_100_rejected_on_decode() {
        let raw = RawDataItem {
            type_id: DataItemType::RESOURCES,
            value: Bytes::from_static(&[150]),
        };
        let err = DataItem::decode(raw).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
    }

    #[test]
    fn resources_above_100_rejected_on_encode() {
        let mut buf = BytesMut::new();
        let err = DataItem::Resources(150).encode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
        // Buffer restored on error.
        assert!(buf.is_empty());
    }

    #[test]
    fn rlq_above_100_rejected_on_encode() {
        for item in [
            DataItem::RelativeLinkQualityReceive(101),
            DataItem::RelativeLinkQualityTransmit(255),
        ] {
            let mut buf = BytesMut::new();
            let err = item.encode(&mut buf).unwrap_err();
            assert!(matches!(err, CodecError::OutOfRange { .. }));
            assert!(buf.is_empty());
        }
    }

    #[test]
    fn latency_overflow_rejected_on_encode() {
        // Duration::MAX has more microseconds than fit in u64 — encode must
        // refuse rather than silently truncate. Buffer is restored on error,
        // including any pre-existing prefix.
        let mut buf = BytesMut::from(&b"prefix"[..]);
        let snapshot = buf.clone();
        let err = DataItem::Latency(Duration::MAX)
            .encode(&mut buf)
            .unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
        assert_eq!(buf, snapshot);
    }

    #[test]
    fn heartbeat_interval_overflow_restores_nonempty_buffer() {
        // The HeartbeatInterval validation runs *after* the 4-byte TLV header
        // is written into `out` — confirm the wrapping `encode` undoes that
        // partial write even when `out` was non-empty going in.
        let mut buf = BytesMut::from(&b"existing"[..]);
        let snapshot = buf.clone();
        let item = DataItem::HeartbeatInterval(Duration::from_secs(u64::MAX / 1000));
        let err = item.encode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
        assert_eq!(buf, snapshot);
    }

    #[test]
    fn oversized_data_item_value_rejected() {
        // A Status with > 64 KiB of text overflows the 16-bit TLV length
        // field. Must surface as OutOfRange, not as a silently-truncated frame.
        let item = DataItem::Status {
            code: StatusCode::SUCCESS,
            text: "x".repeat(70_000),
        };
        let mut buf = BytesMut::new();
        let err = item.encode(&mut buf).unwrap_err();
        match err {
            CodecError::OutOfRange { field, value } => {
                assert_eq!(field, "data_item_value_length");
                assert!(value > u16::MAX as u64);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn oversized_signal_body_rejected() {
        // Two large items together push the signal body past u16::MAX even
        // though each individual item fits. The frame-level length check must
        // catch this.
        let s = Signal::new(SignalType::PEER_OFFER)
            .with_item(DataItem::Status {
                code: StatusCode::SUCCESS,
                text: "x".repeat(40_000),
            })
            .with_item(DataItem::Status {
                code: StatusCode::SUCCESS,
                text: "y".repeat(40_000),
            });
        match s.encode().unwrap_err() {
            CodecError::OutOfRange { field, .. } => {
                assert_eq!(field, "signal_body_length");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn oversized_message_body_rejected() {
        let m = Message::new(MessageType::SESSION_UPDATE)
            .with_item(DataItem::Status {
                code: StatusCode::SUCCESS,
                text: "x".repeat(40_000),
            })
            .with_item(DataItem::Status {
                code: StatusCode::SUCCESS,
                text: "y".repeat(40_000),
            });
        match m.encode().unwrap_err() {
            CodecError::OutOfRange { field, .. } => {
                assert_eq!(field, "message_body_length");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn mtu_wrong_length_carries_exact() {
        // Round out the ExpectedLen variants: the three non-Exact forms have
        // direct assertions; this test pins the Exact(N) form too.
        let raw = RawDataItem {
            type_id: DataItemType::MTU,
            value: Bytes::from_static(&[0x05]),
        };
        match DataItem::decode(raw).unwrap_err() {
            CodecError::InvalidDataItemLength {
                kind: DataItemType::MTU,
                expected: ExpectedLen::Exact(2),
                got: 1,
            } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ipv4_attached_subnet_decode_normalizes_host_bits() {
        // Wire form carries `10.0.0.5/24` (host bits set). After decode, the
        // in-memory subnet must match the canonical `10.0.0.0/24`, so encode
        // and decode are symmetric. The `add` flag must survive truncation.
        let raw = RawDataItem {
            type_id: DataItemType::IPV4_ATTACHED_SUBNET,
            value: Bytes::from_static(&[0x01, 10, 0, 0, 5, 24]),
        };
        let DataItem::Ipv4AttachedSubnet { add, subnet } = DataItem::decode(raw).unwrap() else {
            panic!()
        };
        assert!(add);
        assert_eq!(subnet, "10.0.0.0/24".parse::<Ipv4Net>().unwrap());
    }

    #[test]
    fn ipv6_attached_subnet_decode_normalizes_host_bits() {
        // 2001:db8::1234/32 → 2001:db8::/32 after decode.
        let mut wire = vec![0x01u8];
        wire.extend_from_slice(&"2001:db8::1234".parse::<Ipv6Addr>().unwrap().octets());
        wire.push(32);
        let raw = RawDataItem {
            type_id: DataItemType::IPV6_ATTACHED_SUBNET,
            value: Bytes::from(wire),
        };
        let DataItem::Ipv6AttachedSubnet { add, subnet } = DataItem::decode(raw).unwrap() else {
            panic!()
        };
        assert!(add);
        assert_eq!(subnet, "2001:db8::/32".parse::<Ipv6Net>().unwrap());
    }

    #[test]
    fn non_canonical_subnet_wire_bytes_round_trip_to_canonical() {
        // End-to-end contract: peer sends non-canonical subnet wire bytes,
        // we decode → re-encode, and the second wire form is canonical
        // (host bits zeroed). Locks in the symmetry property at the
        // boundary, not just inside decode and encode in isolation.
        let non_canonical = [0x01u8, 10, 0, 0, 5, 24];
        let canonical = [0x01u8, 10, 0, 0, 0, 24];

        let raw = RawDataItem {
            type_id: DataItemType::IPV4_ATTACHED_SUBNET,
            value: Bytes::copy_from_slice(&non_canonical),
        };
        let item = DataItem::decode(raw).unwrap();

        let mut out = BytesMut::new();
        item.encode(&mut out).unwrap();
        // Skip the 4-byte TLV header; compare just the value bytes.
        assert_eq!(&out[4..], &canonical[..]);
    }

    #[test]
    fn oversized_peer_type_value_rejected() {
        let item = DataItem::PeerType {
            flags: PeerFlags::default(),
            description: "x".repeat(70_000),
        };
        let mut buf = BytesMut::new();
        let err = item.encode(&mut buf).unwrap_err();
        match err {
            CodecError::OutOfRange { field, value } => {
                assert_eq!(field, "data_item_value_length");
                assert!(value > u16::MAX as u64);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Up-front check fires before any header is written.
        assert!(buf.is_empty());
    }

    #[test]
    fn oversized_unknown_data_item_value_rejected() {
        // The Unknown path delegates to RawDataItem::encode, which historically
        // cast `len() as u16` and silently truncated. Confirm it now refuses
        // values that don't fit the 16-bit TLV length field.
        let item = DataItem::Unknown(RawDataItem {
            type_id: DataItemType(4242),
            value: Bytes::from(vec![0u8; 70_000]),
        });
        let mut buf = BytesMut::new();
        let err = item.encode(&mut buf).unwrap_err();
        match err {
            CodecError::OutOfRange { field, value } => {
                assert_eq!(field, "data_item_value_length");
                assert_eq!(value, 70_000);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Buffer untouched on rejection.
        assert!(buf.is_empty());
    }

    #[test]
    fn oversized_extensions_supported_value_rejected() {
        // > 32_768 ids overflows the 16-bit length field (each id is 2 bytes).
        let item = DataItem::ExtensionsSupported(vec![ExtensionId(0); 33_000]);
        let mut buf = BytesMut::new();
        let err = item.encode(&mut buf).unwrap_err();
        match err {
            CodecError::OutOfRange { field, value } => {
                assert_eq!(field, "data_item_value_length");
                assert!(value > u16::MAX as u64);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(buf.is_empty());
    }

    #[test]
    fn encode_failure_does_not_corrupt_existing_buffer() {
        // Pre-populate the buffer; encode failure must restore it byte-for-byte.
        let mut buf = BytesMut::from(&b"prefix"[..]);
        let snapshot = buf.clone();
        let err = DataItem::Resources(200).encode(&mut buf).unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
        assert_eq!(buf, snapshot);
    }

    #[test]
    fn signal_encode_propagates_data_item_error() {
        let s = Signal::new(SignalType::PEER_OFFER).with_item(DataItem::Resources(200));
        let err = s.encode().unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
    }

    #[test]
    fn message_encode_propagates_data_item_error() {
        let m = Message::new(MessageType::SESSION_UPDATE)
            .with_item(DataItem::HeartbeatInterval(Duration::from_millis(1000)))
            .with_item(DataItem::RelativeLinkQualityReceive(120));
        let err = m.encode().unwrap_err();
        assert!(matches!(err, CodecError::OutOfRange { .. }));
    }

    #[test]
    fn relative_link_quality_variants_roundtrip() {
        for v in [0u8, 50, 100] {
            let rx = DataItem::RelativeLinkQualityReceive(v);
            let DataItem::RelativeLinkQualityReceive(out) = decode_one(&encode_one(rx)) else {
                panic!()
            };
            assert_eq!(out, v);

            let tx = DataItem::RelativeLinkQualityTransmit(v);
            let DataItem::RelativeLinkQualityTransmit(out) = decode_one(&encode_one(tx)) else {
                panic!()
            };
            assert_eq!(out, v);
        }
    }

    #[test]
    fn mtu_encodes() {
        let item = DataItem::Mtu(1500);
        // type=20, length=2, value=0x05DC
        assert_eq!(encode_one(item), vec![0x00, 0x14, 0x00, 0x02, 0x05, 0xDC]);
    }

    #[test]
    fn unknown_data_item_passes_through() {
        // Unknown type id (4242) should round-trip verbatim through Unknown.
        let raw_in = RawDataItem {
            type_id: DataItemType(4242),
            value: Bytes::from_static(&[0xAA, 0xBB, 0xCC]),
        };
        let item = DataItem::decode(raw_in.clone()).unwrap();
        match &item {
            DataItem::Unknown(r) => {
                assert_eq!(r.type_id, DataItemType(4242));
                assert_eq!(&r.value[..], &[0xAA, 0xBB, 0xCC]);
            }
            _ => panic!("expected Unknown"),
        }
        // Encoded form preserves bytes exactly.
        let mut buf = BytesMut::new();
        item.encode(&mut buf).unwrap();
        assert_eq!(&buf[..], &[0x10, 0x92, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn decoder_skips_unknown_data_items_inside_message() {
        // A message with one known (HeartbeatInterval) and one unknown item.
        let m = Message::new(MessageType::SESSION_INITIALIZATION)
            .with_item(DataItem::HeartbeatInterval(Duration::from_millis(1000)))
            .with_item(DataItem::Unknown(RawDataItem {
                type_id: DataItemType(9999),
                value: Bytes::from_static(&[0x42]),
            }));
        let decoded = Message::decode(m.encode().unwrap().freeze()).unwrap();
        assert_eq!(decoded.message_type, MessageType::SESSION_INITIALIZATION);
        assert_eq!(decoded.data_items.len(), 2);
        assert!(matches!(
            decoded.data_items[0],
            DataItem::HeartbeatInterval(_)
        ));
        assert!(matches!(decoded.data_items[1], DataItem::Unknown(_)));
    }

    #[test]
    fn signal_with_multiple_unknown_items_round_trips() {
        // Mirrors the Message-side test: forward-compat must work on Signals
        // (Peer Offer / Peer Discovery) too.
        let s = Signal::new(SignalType::PEER_OFFER)
            .with_item(DataItem::PeerType {
                flags: PeerFlags::default(),
                description: "router".into(),
            })
            .with_item(DataItem::Unknown(RawDataItem {
                type_id: DataItemType(7777),
                value: Bytes::from_static(&[1, 2, 3]),
            }))
            .with_item(DataItem::Unknown(RawDataItem {
                type_id: DataItemType(8888),
                value: Bytes::new(),
            }));
        let decoded = Signal::decode(s.encode().unwrap().freeze()).unwrap();
        assert_eq!(decoded.data_items.len(), 3);
        assert!(matches!(decoded.data_items[0], DataItem::PeerType { .. }));
        match &decoded.data_items[1] {
            DataItem::Unknown(r) => {
                assert_eq!(r.type_id, DataItemType(7777));
                assert_eq!(&r.value[..], &[1, 2, 3]);
            }
            _ => panic!(),
        }
        match &decoded.data_items[2] {
            DataItem::Unknown(r) => {
                assert_eq!(r.type_id, DataItemType(8888));
                assert!(r.value.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn signal_with_multiple_items_preserves_order() {
        let s = Signal::new(SignalType::PEER_OFFER)
            .with_item(DataItem::PeerType {
                flags: PeerFlags::default(),
                description: "router".into(),
            })
            .with_item(DataItem::Ipv4ConnectionPoint {
                flags: ConnectionPointFlags { use_tls: false },
                addr: Ipv4Addr::new(127, 0, 0, 1),
                port: Some(854),
            });
        let decoded = Signal::decode(s.encode().unwrap().freeze()).unwrap();
        assert_eq!(decoded.signal_type, SignalType::PEER_OFFER);
        assert_eq!(decoded.data_items.len(), 2);
        assert!(matches!(decoded.data_items[0], DataItem::PeerType { .. }));
        assert!(matches!(
            decoded.data_items[1],
            DataItem::Ipv4ConnectionPoint { .. }
        ));
    }

    #[test]
    fn truncated_message_buffer_rejected() {
        // declared length 4 but only 2 bytes follow
        let mut buf = BytesMut::new();
        buf.put_u16(MessageType::HEARTBEAT.0);
        buf.put_u16(4);
        buf.put_u8(0xAB);
        buf.put_u8(0xCD);
        let err = Message::decode(buf.freeze()).unwrap_err();
        assert!(matches!(err, CodecError::LengthMismatch { .. }));
    }

    #[test]
    fn truncated_signal_header_rejected() {
        let buf = Bytes::from_static(b"DLE");
        let err = Signal::decode(buf).unwrap_err();
        assert!(matches!(err, CodecError::Truncated { .. }));
    }

    #[test]
    fn invalid_utf8_in_status_text_rejected() {
        // Status code 0 followed by an invalid UTF-8 sequence (0xFF is never valid).
        let raw = RawDataItem {
            type_id: DataItemType::STATUS,
            value: Bytes::from_static(&[0x00, 0xFF, 0xFE]),
        };
        let err = DataItem::decode(raw).unwrap_err();
        assert!(matches!(err, CodecError::InvalidUtf8(_)));
    }
}
