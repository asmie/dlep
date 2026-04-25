use crate::data_item::DataItem;
use crate::ids::SignalType;

/// A DLEP UDP discovery signal (Peer Discovery / Peer Offer).
///
/// Wire format (RFC 8175 §11.1):
/// `"DLEP" (4 bytes) || signal_type: u16 || length: u16 || <data items>`
#[derive(Clone, Debug)]
pub struct Signal {
    pub signal_type: SignalType,
    pub data_items: Vec<DataItem>,
}

impl Signal {
    pub fn new(signal_type: SignalType) -> Self {
        Self {
            signal_type,
            data_items: Vec::new(),
        }
    }

    pub fn with_item(mut self, item: DataItem) -> Self {
        self.data_items.push(item);
        self
    }
}
