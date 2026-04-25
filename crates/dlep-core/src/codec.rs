//! Byte-level encoding and decoding primitives.
//!
//! These helpers live in `dlep-core` so that any crate can serialize or parse
//! DLEP wire bytes without dragging in tokio. The async-friendly
//! `tokio_util::codec::{Decoder, Encoder}` wrappers live in `dlep-net`.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::data_item::RawDataItem;
use crate::error::CodecError;
use crate::ids::{DataItemType, MessageType, SignalType};
use crate::message::Message;
use crate::signal::Signal;
use crate::SIGNAL_PREFIX;

/// Length of the fixed-size signal header: `"DLEP" (4) || type (2) || length (2)`.
pub const SIGNAL_HEADER_LEN: usize = 8;

/// Length of the fixed-size message header: `type (2) || length (2)`.
pub const MESSAGE_HEADER_LEN: usize = 4;

impl RawDataItem {
    pub fn encode(&self, out: &mut BytesMut) {
        out.put_u16(self.type_id.0);
        out.put_u16(self.value.len() as u16);
        out.put_slice(&self.value);
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

impl Signal {
    pub fn encode(&self) -> BytesMut {
        let body = BytesMut::new();
        for item in &self.data_items {
            let _ = item; // TODO: item.encode(&mut body);
        }
        let mut out = BytesMut::with_capacity(SIGNAL_HEADER_LEN + body.len());
        out.put_slice(SIGNAL_PREFIX);
        out.put_u16(self.signal_type.0);
        out.put_u16(body.len() as u16);
        out.put(body);
        out
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
        while body.has_remaining() {
            let _raw = RawDataItem::decode(&mut body)?;
            // TODO: lift RawDataItem into typed DataItem; for now drop unknown.
        }
        Ok(Signal {
            signal_type,
            data_items: Vec::new(),
        })
    }
}

impl Message {
    pub fn encode(&self) -> BytesMut {
        let body = BytesMut::new();
        for item in &self.data_items {
            let _ = item; // TODO: item.encode(&mut body);
        }
        let mut out = BytesMut::with_capacity(MESSAGE_HEADER_LEN + body.len());
        out.put_u16(self.message_type.0);
        out.put_u16(body.len() as u16);
        out.put(body);
        out
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
        while body.has_remaining() {
            let _raw = RawDataItem::decode(&mut body)?;
            // TODO: lift RawDataItem into typed DataItem.
        }
        Ok(Message {
            message_type,
            data_items: Vec::new(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_message_roundtrips() {
        let m = Message::new(MessageType::HEARTBEAT);
        let bytes = m.encode().freeze();
        let decoded = Message::decode(bytes).unwrap();
        assert_eq!(decoded.message_type, MessageType::HEARTBEAT);
        assert!(decoded.data_items.is_empty());
    }

    #[test]
    fn empty_signal_roundtrips() {
        let s = Signal::new(SignalType::PEER_DISCOVERY);
        let bytes = s.encode().freeze();
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
}
