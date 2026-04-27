//! tokio-util `Decoder`/`Encoder` wrappers over the byte-level codec in
//! `dlep-core`.

use bytes::BytesMut;
use dlep_core::codec::MESSAGE_HEADER_LEN;
use dlep_core::{CodecError, Message, Signal};
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Default)]
pub struct MessageCodec;

#[derive(Debug, Default)]
pub struct SignalCodec;

impl Decoder for MessageCodec {
    type Item = Message;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Message>, Self::Error> {
        if src.len() < MESSAGE_HEADER_LEN {
            return Ok(None);
        }
        // Peek length without consuming.
        let declared = u16::from_be_bytes([src[2], src[3]]) as usize;
        let total = MESSAGE_HEADER_LEN + declared;
        if src.len() < total {
            src.reserve(total - src.len());
            return Ok(None);
        }
        let frame = src.split_to(total).freeze();
        Message::decode(frame).map(Some)
    }
}

impl Encoder<Message> for MessageCodec {
    type Error = CodecError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let bytes = item.encode();
        dst.reserve(bytes.len());
        dst.extend_from_slice(&bytes);
        Ok(())
    }
}

impl SignalCodec {
    /// Decode a complete UDP datagram body (received via `recvmsg`) into a
    /// `Signal`. The datagram boundary is authoritative, so no framing
    /// bookkeeping is needed.
    pub fn decode_datagram(&self, buf: BytesMut) -> Result<Signal, CodecError> {
        Signal::decode(buf.freeze())
    }

    pub fn encode_datagram(&self, signal: &Signal) -> BytesMut {
        signal.encode()
    }
}
