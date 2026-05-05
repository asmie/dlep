//! Property-based codec coverage:
//!   1. Every typed `DataItem` round-trips through encode/decode.
//!   2. `Signal::decode` and `Message::decode` never panic on arbitrary bytes.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dlep_core::codec::{MESSAGE_HEADER_LEN, SIGNAL_HEADER_LEN};
use dlep_core::data_item::{ConnectionPointFlags, PeerFlags};
use dlep_core::{
    DataItem, ExtensionId, MIN_HEARTBEAT_INTERVAL_MS, MacAddress, Message, MessageType,
    RawDataItem, Signal, SignalType, StatusCode,
};
use ipnet::{Ipv4Net, Ipv6Net};
use proptest::prelude::*;

// --- Strategies ---------------------------------------------------------

fn arb_status() -> impl Strategy<Value = DataItem> {
    (any::<u8>(), "[\\x20-\\x7e]{0,32}").prop_map(|(c, t)| DataItem::Status {
        code: StatusCode(c),
        text: t,
    })
}

fn arb_ipv4_cp() -> impl Strategy<Value = DataItem> {
    (
        any::<bool>(),
        any::<[u8; 4]>(),
        proptest::option::of(any::<u16>()),
    )
        .prop_map(|(t, octets, port)| DataItem::Ipv4ConnectionPoint {
            flags: ConnectionPointFlags { use_tls: t },
            addr: Ipv4Addr::from(octets),
            port,
        })
}

fn arb_ipv6_cp() -> impl Strategy<Value = DataItem> {
    (
        any::<bool>(),
        any::<[u8; 16]>(),
        proptest::option::of(any::<u16>()),
    )
        .prop_map(|(t, octets, port)| DataItem::Ipv6ConnectionPoint {
            flags: ConnectionPointFlags { use_tls: t },
            addr: Ipv6Addr::from(octets),
            port,
        })
}

fn arb_peer_type() -> impl Strategy<Value = DataItem> {
    (any::<bool>(), "[\\x20-\\x7e]{0,32}").prop_map(|(s, d)| DataItem::PeerType {
        flags: PeerFlags { smi: s },
        description: d,
    })
}

fn arb_heartbeat() -> impl Strategy<Value = DataItem> {
    (MIN_HEARTBEAT_INTERVAL_MS..=u32::MAX)
        .prop_map(|ms| DataItem::HeartbeatInterval(Duration::from_millis(ms.into())))
}

fn arb_extensions_supported() -> impl Strategy<Value = DataItem> {
    proptest::collection::vec(any::<u16>(), 0..16)
        .prop_map(|v| DataItem::ExtensionsSupported(v.into_iter().map(ExtensionId).collect()))
}

fn arb_mac() -> impl Strategy<Value = DataItem> {
    // RFC 8175 §13.7 allows EUI-48 (6 octets) or EUI-64 (8 octets).
    prop_oneof![
        any::<[u8; 6]>().prop_map(|o| DataItem::MacAddress(MacAddress::Eui48(o))),
        any::<[u8; 8]>().prop_map(|o| DataItem::MacAddress(MacAddress::Eui64(o))),
    ]
}

fn arb_ipv4_addr_item() -> impl Strategy<Value = DataItem> {
    (any::<bool>(), any::<[u8; 4]>()).prop_map(|(add, o)| DataItem::Ipv4Address {
        add,
        addr: Ipv4Addr::from(o),
    })
}

fn arb_ipv6_addr_item() -> impl Strategy<Value = DataItem> {
    (any::<bool>(), any::<[u8; 16]>()).prop_map(|(add, o)| DataItem::Ipv6Address {
        add,
        addr: Ipv6Addr::from(o),
    })
}

fn arb_ipv4_subnet() -> impl Strategy<Value = DataItem> {
    (any::<bool>(), any::<[u8; 4]>(), 0u8..=32).prop_map(|(add, o, p)| {
        DataItem::Ipv4AttachedSubnet {
            add,
            // truncate the address to the prefix so Ipv4Net round-trips bit-for-bit
            subnet: Ipv4Net::new(Ipv4Addr::from(o), p).unwrap().trunc(),
        }
    })
}

fn arb_ipv6_subnet() -> impl Strategy<Value = DataItem> {
    (any::<bool>(), any::<[u8; 16]>(), 0u8..=128).prop_map(|(add, o, p)| {
        DataItem::Ipv6AttachedSubnet {
            add,
            subnet: Ipv6Net::new(Ipv6Addr::from(o), p).unwrap().trunc(),
        }
    })
}

fn arb_data_rate() -> impl Strategy<Value = DataItem> {
    (0u8..4, any::<u64>()).prop_map(|(which, bps)| match which {
        0 => DataItem::MaxDataRateReceive(bps),
        1 => DataItem::MaxDataRateTransmit(bps),
        2 => DataItem::CurrentDataRateReceive(bps),
        _ => DataItem::CurrentDataRateTransmit(bps),
    })
}

fn arb_latency() -> impl Strategy<Value = DataItem> {
    any::<u64>().prop_map(|us| DataItem::Latency(Duration::from_micros(us)))
}

fn arb_percent() -> impl Strategy<Value = DataItem> {
    (0u8..3, 0u8..=100).prop_map(|(which, pct)| match which {
        0 => DataItem::Resources(pct),
        1 => DataItem::RelativeLinkQualityReceive(pct),
        _ => DataItem::RelativeLinkQualityTransmit(pct),
    })
}

fn arb_mtu() -> impl Strategy<Value = DataItem> {
    any::<u16>().prop_map(DataItem::Mtu)
}

fn arb_unknown() -> impl Strategy<Value = DataItem> {
    // Use a type id that is guaranteed to be outside the known range (1..=20).
    (
        proptest::sample::select(vec![0u16, 21, 100, 1000, 0xFFFF]),
        proptest::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(ty, v)| {
            DataItem::Unknown(RawDataItem {
                type_id: dlep_core::DataItemType(ty),
                value: Bytes::from(v),
            })
        })
}

fn arb_data_item() -> impl Strategy<Value = DataItem> {
    prop_oneof![
        arb_status(),
        arb_ipv4_cp(),
        arb_ipv6_cp(),
        arb_peer_type(),
        arb_heartbeat(),
        arb_extensions_supported(),
        arb_mac(),
        arb_ipv4_addr_item(),
        arb_ipv6_addr_item(),
        arb_ipv4_subnet(),
        arb_ipv6_subnet(),
        arb_data_rate(),
        arb_latency(),
        arb_percent(),
        arb_mtu(),
        arb_unknown(),
    ]
}

// --- Properties ---------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Every typed `DataItem` round-trips: encode → decode → semantically equal.
    /// We compare via `Debug` formatting because `DataItem` does not derive
    /// `PartialEq` (some fields use third-party types whose `PartialEq` would
    /// add API surface area without value).
    #[test]
    fn data_item_roundtrips(item in arb_data_item()) {
        let mut buf = BytesMut::new();
        item.encode(&mut buf).expect("encode");

        let mut bytes = buf.freeze();
        let raw = RawDataItem::decode(&mut bytes).expect("raw decode");
        prop_assert!(bytes.is_empty(), "extra bytes after one item");

        let back = DataItem::decode(raw).expect("typed decode");
        prop_assert_eq!(format!("{item:?}"), format!("{back:?}"));
    }

    /// A sequence of items inside a Message round-trips with the same order.
    #[test]
    fn message_roundtrips(items in proptest::collection::vec(arb_data_item(), 0..6),
                          ty in any::<u16>()) {
        let mut m = Message::new(MessageType(ty));
        for it in items.iter().cloned() {
            m = m.with_item(it);
        }
        let bytes = m.encode().unwrap().freeze();
        let decoded = Message::decode(bytes).expect("message decode");
        prop_assert_eq!(decoded.message_type, MessageType(ty));
        prop_assert_eq!(decoded.data_items.len(), items.len());
        for (a, b) in items.iter().zip(decoded.data_items.iter()) {
            prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
        }
    }

    /// A sequence of items inside a Signal round-trips with the same order.
    #[test]
    fn signal_roundtrips(items in proptest::collection::vec(arb_data_item(), 0..6),
                         ty in any::<u16>()) {
        let mut s = Signal::new(SignalType(ty));
        for it in items.iter().cloned() {
            s = s.with_item(it);
        }
        let bytes = s.encode().unwrap().freeze();
        let decoded = Signal::decode(bytes).expect("signal decode");
        prop_assert_eq!(decoded.signal_type, SignalType(ty));
        prop_assert_eq!(decoded.data_items.len(), items.len());
    }

    /// `Signal::decode` must never panic on arbitrary bytes.
    #[test]
    fn signal_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Signal::decode(Bytes::from(bytes));
    }

    /// `Message::decode` must never panic on arbitrary bytes.
    #[test]
    fn message_decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Message::decode(Bytes::from(bytes));
    }

    /// Even when the discriminator/length fields are well-formed, decoding
    /// random bodies must never panic.
    #[test]
    fn signal_with_valid_header_never_panics(
        ty in any::<u16>(),
        body in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut buf = BytesMut::with_capacity(SIGNAL_HEADER_LEN + body.len());
        buf.extend_from_slice(b"DLEP");
        buf.extend_from_slice(&ty.to_be_bytes());
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);
        let _ = Signal::decode(buf.freeze());
    }

    #[test]
    fn message_with_valid_header_never_panics(
        ty in any::<u16>(),
        body in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let mut buf = BytesMut::with_capacity(MESSAGE_HEADER_LEN + body.len());
        buf.extend_from_slice(&ty.to_be_bytes());
        buf.extend_from_slice(&(body.len() as u16).to_be_bytes());
        buf.extend_from_slice(&body);
        let _ = Message::decode(buf.freeze());
    }
}
