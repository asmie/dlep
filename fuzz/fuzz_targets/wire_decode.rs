#![no_main]

use bytes::{Bytes, BytesMut};
use dlep_core::{DataItem, Message, RawDataItem, Signal};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    if let Ok(message) = Message::decode(bytes.clone()) {
        let encoded = message
            .encode()
            .expect("decoded message must encode")
            .freeze();
        let decoded = Message::decode(encoded.clone()).expect("encoded message must decode");
        assert_eq!(encoded, decoded.encode().unwrap().freeze());
    }
    if let Ok(signal) = Signal::decode(bytes.clone()) {
        let encoded = signal
            .encode()
            .expect("decoded signal must encode")
            .freeze();
        let decoded = Signal::decode(encoded.clone()).expect("encoded signal must decode");
        assert_eq!(encoded, decoded.encode().unwrap().freeze());
    }
    let mut remaining = bytes;
    if let Ok(raw) = RawDataItem::decode(&mut remaining)
        && let Ok(item) = DataItem::decode(raw)
    {
        let mut encoded = BytesMut::new();
        item.encode(&mut encoded).expect("decoded item must encode");
        let mut canonical = encoded.clone().freeze();
        let item = DataItem::decode(RawDataItem::decode(&mut canonical).unwrap()).unwrap();
        assert!(canonical.is_empty());
        let mut again = BytesMut::new();
        item.encode(&mut again).unwrap();
        assert_eq!(encoded, again);
    }
});
