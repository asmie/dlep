#![no_main]

use bytes::{Bytes, BytesMut};
use dlep_core::Message;
use dlep_net::MessageCodec;
use libfuzzer_sys::fuzz_target;
use tokio_util::codec::Decoder;

// The reference walks complete frames in the original byte slice, independent
// of MessageCodec's buffering, reserve, split_to, and EOF implementation.
fn reference(mut wire: &[u8]) -> (Vec<Bytes>, bool) {
    let mut messages = Vec::new();
    while !wire.is_empty() {
        if wire.len() < 4 {
            return (messages, true);
        }
        let length = 4 + usize::from(u16::from_be_bytes([wire[2], wire[3]]));
        if length > wire.len() {
            return (messages, true);
        }
        match Message::decode(Bytes::copy_from_slice(&wire[..length])) {
            Ok(message) => messages.push(message.encode().unwrap().freeze()),
            Err(_) => return (messages, true),
        }
        wire = &wire[length..];
    }
    (messages, false)
}

fn framed(wire: &[u8], first: usize, later: usize) -> (Vec<Bytes>, bool) {
    let mut codec = MessageCodec;
    let mut buffer = BytesMut::new();
    let mut messages = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let size = if offset == 0 { first } else { later };
        let end = (offset + size).min(wire.len());
        buffer.extend_from_slice(&wire[offset..end]);
        offset = end;
        loop {
            let before = buffer.len();
            match codec.decode(&mut buffer) {
                Ok(Some(message)) => {
                    assert!(buffer.len() < before, "decoder did not consume a frame");
                    messages.push(message.encode().unwrap().freeze());
                }
                Ok(None) => {
                    assert_eq!(buffer.len(), before, "incomplete frame consumed bytes");
                    break;
                }
                Err(_) => return (messages, true),
            }
        }
    }
    loop {
        let before = buffer.len();
        match codec.decode_eof(&mut buffer) {
            Ok(Some(message)) => {
                assert!(buffer.len() < before, "EOF decoder did not consume a frame");
                messages.push(message.encode().unwrap().freeze());
            }
            Ok(None) => {
                assert!(buffer.is_empty(), "truncated EOF accepted");
                return (messages, false);
            }
            Err(_) => return (messages, true),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let wire = &data[2..];
    // Zero selects a coalesced read; other selectors split across every header
    // and body boundary at sizes 1..255. Two selectors vary the initial split.
    let width = |value: u8| {
        if value == 0 {
            wire.len().max(1)
        } else {
            usize::from(value)
        }
    };
    let expected = reference(wire);
    assert_eq!(framed(wire, width(data[0]), width(data[1])), expected);
    assert_eq!(framed(wire, wire.len().max(1), wire.len().max(1)), expected);
});
