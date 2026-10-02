//! DLEP extension plug-in API.
//!
//! Extensions declare the `ExtensionId`s they advertise in Session
//! Initialization, and provide hooks to handle unknown data items and
//! messages, or to observe session/destination state transitions.
//!
//! The trait lives in its own crate (depending only on `dlep-core`) so
//! third-party extensions do not pull the daemon runtime.

#![allow(dead_code)]

use std::any::Any;
use std::sync::Arc;

use dlep_core::{
    DataItem, ExtensionId, LinkMetrics, MacAddress, Message, MessageType, RawDataItem, StatusCode,
};

/// Opaque session identifier produced by the runtime. `Copy`-cheap for
/// passing into hooks. The runtime mints these per-daemon (not
/// process-wide), so two daemons sharing one process have independent
/// id-spaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SessionId(pub u64);

/// Which side of the DLEP protocol a session is on. Set explicitly by the
/// daemon when spawning a session task so extensions can reason about
/// directionality without deriving it from the initial FSM event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Role {
    Router,
    Modem,
}

impl Role {
    pub fn is_router(self) -> bool {
        matches!(self, Role::Router)
    }
    pub fn is_modem(self) -> bool {
        matches!(self, Role::Modem)
    }
}

/// Context handed to every hook. Extensions may queue outbound messages and
/// emit opaque application-level events, but cannot mutate FSM state.
pub trait ExtensionCtx {
    fn session_id(&self) -> SessionId;
    fn is_router_side(&self) -> bool;
    fn send_message(&mut self, msg: Message);
    fn emit_event(&mut self, ev: Arc<dyn Any + Send + Sync>);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtHandled {
    Handled,
    Passthrough,
}

/// A snapshot of session-level state exposed to extensions. Real fields
/// arrive once the FSM grows its transitions; for now this is a placeholder.
#[derive(Clone, Copy, Debug)]
pub struct SessionStateSnapshot {
    pub up: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationStateSnapshot {
    pub up: bool,
    /// Last status the FSM saw for this destination. `SUCCESS` on `Up`;
    /// the inbound reason on `Down`.
    pub last_status: StatusCode,
    /// Wire-reported link metrics. `Some(_)` on `Up`; `None` on `Down`
    /// (RFC 8175's `Destination_Down` carries no metric Data Items).
    /// Extensions that want richer per-destination context (addresses,
    /// subnets) should subscribe to `DaemonEvent::Destination` directly.
    pub metrics: Option<LinkMetrics>,
}

/// Extension plug-in trait. All hooks have default empty implementations so a
/// real extension only overrides what it cares about.
pub trait DlepExtension: Send + Sync + 'static {
    /// Extension IDs this plug-in advertises in Session Initialization.
    fn advertised_ids(&self) -> &[ExtensionId];

    /// Invoked after parsing the peer's Session Init / Session Init Response.
    /// Return `false` to opt out of this session (extension stays inert).
    fn on_negotiated(&self, remote_ids: &[ExtensionId]) -> bool {
        !self.advertised_ids().is_empty()
            && self
                .advertised_ids()
                .iter()
                .all(|id| remote_ids.contains(id))
    }

    /// Called when the core codec could not map a data item to a typed
    /// variant. Consuming the item (`ExtHandled::Handled`) hides it from the
    /// core FSM; returning `Passthrough` leaves it in the message's
    /// `unknown_items` list.
    fn on_unknown_data_item(
        &self,
        in_message: MessageType,
        item: &RawDataItem,
        ctx: &mut dyn ExtensionCtx,
    ) -> ExtHandled {
        let _ = (in_message, item, ctx);
        ExtHandled::Passthrough
    }

    /// Called for unknown `MessageType` values arriving on the session
    /// channel (after typed data items have been parsed).
    fn on_unknown_message(
        &self,
        message_type: MessageType,
        items: &[DataItem],
        ctx: &mut dyn ExtensionCtx,
    ) -> ExtHandled {
        let _ = (message_type, items, ctx);
        ExtHandled::Passthrough
    }

    fn on_session_state(&self, state: SessionStateSnapshot, ctx: &mut dyn ExtensionCtx) {
        let _ = (state, ctx);
    }

    fn on_destination_state(
        &self,
        mac: MacAddress,
        state: DestinationStateSnapshot,
        ctx: &mut dyn ExtensionCtx,
    ) {
        let _ = (mac, state, ctx);
    }
}

/// Registry of configured extensions. Cheap to clone (holds `Arc`s).
#[derive(Clone, Default)]
pub struct ExtensionRegistry {
    extensions: Vec<Arc<dyn DlepExtension>>,
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, ext: Arc<dyn DlepExtension>) {
        self.extensions.push(ext);
    }

    /// Union of all advertised IDs, for Session Initialization.
    pub fn advertised(&self) -> Vec<ExtensionId> {
        let mut out = Vec::new();
        for e in &self.extensions {
            out.extend_from_slice(e.advertised_ids());
        }
        out.sort();
        out.dedup();
        out
    }

    /// Given the peer's advertised IDs, return extensions that accepted
    /// negotiation. Only these receive subsequent hook calls.
    pub fn negotiate(&self, remote: &[ExtensionId]) -> Vec<Arc<dyn DlepExtension>> {
        self.extensions
            .iter()
            .filter(|e| {
                !e.advertised_ids().is_empty()
                    && e.advertised_ids().iter().all(|id| remote.contains(id))
                    && e.on_negotiated(remote)
            })
            .cloned()
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Arc<dyn DlepExtension>> {
        self.extensions.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct DefaultExtension;
    impl DlepExtension for DefaultExtension {
        fn advertised_ids(&self) -> &[ExtensionId] {
            &[ExtensionId(65000)]
        }
    }
    struct PermissiveExtension;
    impl DlepExtension for PermissiveExtension {
        fn advertised_ids(&self) -> &[ExtensionId] {
            &[ExtensionId(65000), ExtensionId(65001)]
        }
        fn on_negotiated(&self, _: &[ExtensionId]) -> bool {
            true
        }
    }
    #[test]
    fn negotiation_requires_mutual_support_even_for_permissive_plugins() {
        let mut r = ExtensionRegistry::new();
        r.register(Arc::new(DefaultExtension));
        r.register(Arc::new(PermissiveExtension));
        assert!(r.negotiate(&[]).is_empty());
        assert_eq!(r.negotiate(&[ExtensionId(65000)]).len(), 1);
        assert_eq!(
            r.negotiate(&[ExtensionId(65000), ExtensionId(65001)]).len(),
            2
        );
    }
    struct SelectiveExtension {
        ids: Vec<ExtensionId>,
        accept: bool,
    }
    impl DlepExtension for SelectiveExtension {
        fn advertised_ids(&self) -> &[ExtensionId] {
            &self.ids
        }
        fn on_negotiated(&self, _: &[ExtensionId]) -> bool {
            assert!(!self.ids.is_empty(), "unadvertised plugins must stay inert");
            self.accept
        }
    }

    #[test]
    fn advertisement_is_sorted_unique_and_negotiation_preserves_plugin_order() {
        let mut registry = ExtensionRegistry::new();
        for ids in [vec![65002, 65000, 65002], vec![65001], vec![65000]] {
            registry.register(Arc::new(SelectiveExtension {
                ids: ids.into_iter().map(ExtensionId).collect(),
                accept: true,
            }));
        }
        let advertised = vec![ExtensionId(65000), ExtensionId(65001), ExtensionId(65002)];
        assert_eq!(registry.advertised(), advertised);
        let negotiated = registry.negotiate(&advertised);
        assert_eq!(negotiated.len(), 3);
        for (actual, registered) in negotiated.iter().zip(registry.iter()) {
            assert!(Arc::ptr_eq(actual, registered));
        }
    }

    #[test]
    fn plugins_can_opt_out_and_plugins_without_ids_never_negotiate() {
        let mut registry = ExtensionRegistry::new();
        registry.register(Arc::new(SelectiveExtension {
            ids: vec![],
            accept: true,
        }));
        registry.register(Arc::new(SelectiveExtension {
            ids: vec![ExtensionId(65000)],
            accept: false,
        }));
        assert!(registry.negotiate(&[ExtensionId(65000)]).is_empty());
    }
}
