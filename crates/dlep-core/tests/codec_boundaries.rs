//! Independent wire fixtures for RFC 8175 section 13 boundary conditions.
use bytes::{Bytes, BytesMut};
use dlep_core::error::ExpectedLen;
use dlep_core::{CodecError, DataItem, DataItemType, Message, RawDataItem, Signal};

fn raw(kind: u16, value: Vec<u8>) -> RawDataItem {
    RawDataItem {
        type_id: DataItemType(kind),
        value: value.into(),
    }
}

#[test]
fn every_core_item_rejects_invalid_lengths_before_reading_fields() {
    // RFC wire lengths, independently enumerated for all twenty core types.
    let lengths = [
        ExpectedLen::AtLeast(1),
        ExpectedLen::OneOf(&[5, 7]),
        ExpectedLen::OneOf(&[17, 19]),
        ExpectedLen::AtLeast(1),
        ExpectedLen::Exact(4),
        ExpectedLen::Multiple(2),
        ExpectedLen::OneOf(&[6, 8]),
        ExpectedLen::Exact(5),
        ExpectedLen::Exact(17),
        ExpectedLen::Exact(6),
        ExpectedLen::Exact(18),
        ExpectedLen::Exact(8),
        ExpectedLen::Exact(8),
        ExpectedLen::Exact(8),
        ExpectedLen::Exact(8),
        ExpectedLen::Exact(8),
        ExpectedLen::Exact(1),
        ExpectedLen::Exact(1),
        ExpectedLen::Exact(1),
        ExpectedLen::Exact(2),
    ];
    for (index, expected) in lengths.into_iter().enumerate() {
        let kind = (index + 1) as u16;
        for len in 0..=22 {
            let valid = match expected {
                ExpectedLen::Exact(n) => len == n,
                ExpectedLen::AtLeast(n) => len >= n,
                ExpectedLen::OneOf(ns) => ns.contains(&len),
                ExpectedLen::Multiple(n) => len % n == 0,
            };
            if valid {
                continue;
            }
            assert!(
                matches!(DataItem::decode(raw(kind, vec![0; len])),
                Err(CodecError::InvalidDataItemLength { kind: got_kind, expected: got_expected, got })
                if got_kind == DataItemType(kind) && got_expected == expected && got == len),
                "type {kind}, length {len}"
            );
        }
    }
}

#[test]
fn reserved_flag_bits_are_rejected_in_every_flagged_item() {
    for (kind, len) in [
        (2, 5),
        (2, 7),
        (3, 17),
        (3, 19),
        (4, 1),
        (8, 5),
        (9, 17),
        (10, 6),
        (11, 18),
    ] {
        for flags in 0..=u8::MAX {
            let mut value = vec![0; len];
            value[0] = flags;
            let decoded = DataItem::decode(raw(kind, value));
            if flags <= 1 {
                let mut encoded = BytesMut::new();
                decoded.unwrap().encode(&mut encoded).unwrap();
                assert_eq!(encoded[4], flags, "type {kind}: preserve the defined flag");
            } else {
                assert!(
                    matches!(decoded, Err(CodecError::OutOfRange { field: "data_item_flags", value }) if value == flags as u64),
                    "type {kind}, flags {flags:#04x}: {decoded:?}"
                );
            }
        }
    }
}

#[test]
fn text_lengths_count_utf8_octets_and_preserve_embedded_nuls() {
    for kind in [1, 4] {
        let text = "Łącze 日本 🛰\0";
        let mut value = vec![0];
        value.extend_from_slice(text.as_bytes());
        let item = DataItem::decode(raw(kind, value.clone())).unwrap();
        match &item {
            DataItem::Status { text: decoded, .. } => assert_eq!(decoded, text),
            DataItem::PeerType { description, .. } => assert_eq!(description, text),
            _ => unreachable!(),
        }
        let mut encoded = BytesMut::new();
        item.encode(&mut encoded).unwrap();
        assert_eq!(
            u16::from_be_bytes([encoded[2], encoded[3]]) as usize,
            1 + text.len()
        );
        assert_eq!(&encoded[4..], value);
    }
}

#[test]
fn both_text_fields_reject_invalid_utf8_sequences() {
    for kind in [1, 4] {
        // Truncated, overlong, surrogate, continuation-only, and out-of-range.
        for invalid in [
            &[0xc3][..],
            &[0xc0, 0xaf],
            &[0xed, 0xa0, 0x80],
            &[0x80],
            &[0xf4, 0x90, 0x80, 0x80],
        ] {
            let mut value = vec![0];
            value.extend_from_slice(invalid);
            assert!(matches!(
                DataItem::decode(raw(kind, value)),
                Err(CodecError::InvalidUtf8(_))
            ));
        }
    }
}

#[test]
fn datagram_length_and_nested_tlv_boundaries_are_enforced() {
    // A datagram cannot contain bytes beyond its declared body.
    assert!(matches!(
        Signal::decode(Bytes::from_static(b"DLEP\x00\x01\x00\x00\xff")),
        Err(CodecError::LengthMismatch {
            declared: 0,
            remaining: 1
        })
    ));
    // Outer lengths are valid, but the nested TLV header or value is truncated.
    for body in [&[0, 1, 0][..], &[0, 1, 0, 2, 0]] {
        let mut message = vec![0, 16, 0, body.len() as u8];
        message.extend_from_slice(body);
        assert!(matches!(
            Message::decode(message.into()),
            Err(CodecError::Truncated { .. })
        ));
        let mut signal = b"DLEP\x00\x01\x00".to_vec();
        signal.push(body.len() as u8);
        signal.extend_from_slice(body);
        assert!(matches!(
            Signal::decode(signal.into()),
            Err(CodecError::Truncated { .. })
        ));
    }
}

#[test]
fn percentage_and_prefix_limits_are_checked_on_receive() {
    for kind in [17, 18, 19] {
        for value in [0, 100, 101, 255] {
            assert_eq!(
                DataItem::decode(raw(kind, vec![value])).is_ok(),
                value <= 100
            );
        }
    }
    for (kind, len, max) in [(10, 6, 32), (11, 18, 128)] {
        for prefix in [0, max, max + 1, 255] {
            let mut value = vec![0; len];
            value[len - 1] = prefix;
            assert_eq!(DataItem::decode(raw(kind, value)).is_ok(), prefix <= max);
        }
    }
}
