use crate::data_item::DataItem;
use crate::ids::MessageType;

/// A DLEP TCP session message.
///
/// Wire format (RFC 8175 §11.2):
/// `message_type: u16 || length: u16 || <data items>`
///
/// Unlike signals, messages do NOT carry the ASCII `"DLEP"` prefix.
#[derive(Clone, Debug)]
pub struct Message {
    pub message_type: MessageType,
    pub data_items: Vec<DataItem>,
}

impl Message {
    pub fn new(message_type: MessageType) -> Self {
        Self {
            message_type,
            data_items: Vec::new(),
        }
    }

    pub fn with_item(mut self, item: DataItem) -> Self {
        self.data_items.push(item);
        self
    }
}
