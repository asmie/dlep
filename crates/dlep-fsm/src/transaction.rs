//! Transaction tracking — enforces RFC 8175 serialization rules.
//!
//! At any time there may be at most ONE outstanding session-level request
//! and at most ONE outstanding per-destination request per destination.
//! Violating this → terminate with `StatusCode::UNEXPECTED_MESSAGE` (129).

use std::collections::HashMap;

use dlep_core::MacAddress;

#[derive(Debug, Default)]
pub struct TransactionTracker {
    pub session_pending: Option<PendingRequest>,
    pub per_destination: HashMap<MacAddress, PendingRequest>,
}

#[derive(Clone, Copy, Debug)]
pub struct PendingRequest {
    pub kind: RequestKind,
}

#[derive(Clone, Copy, Debug)]
pub enum RequestKind {
    SessionUpdate,
    SessionTermination,
    DestinationUp,
    DestinationAnnounce,
    DestinationDown,
    LinkCharacteristics,
}

impl TransactionTracker {
    pub fn session_busy(&self) -> bool {
        self.session_pending.is_some()
    }

    pub fn destination_busy(&self, mac: &MacAddress) -> bool {
        self.per_destination.contains_key(mac)
    }

    pub fn open_session(&mut self, kind: RequestKind) -> Result<(), PendingRequest> {
        if let Some(existing) = self.session_pending {
            return Err(existing);
        }
        self.session_pending = Some(PendingRequest { kind });
        Ok(())
    }

    pub fn close_session(&mut self) -> Option<PendingRequest> {
        self.session_pending.take()
    }

    pub fn open_destination(
        &mut self,
        mac: MacAddress,
        kind: RequestKind,
    ) -> Result<(), PendingRequest> {
        if let Some(existing) = self.per_destination.get(&mac) {
            return Err(*existing);
        }
        self.per_destination.insert(mac, PendingRequest { kind });
        Ok(())
    }

    pub fn close_destination(&mut self, mac: &MacAddress) -> Option<PendingRequest> {
        self.per_destination.remove(mac)
    }
}
