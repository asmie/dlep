//! DLEP extension plug-in API.
//!
//! Extensions declare the `ExtensionId`s they advertise in Session
//! Initialization, and provide hooks to handle unknown data items and
//! messages, or to observe session/destination state transitions.
//!
//! The trait lives in its own crate (depending only on `dlep-core`) so
//! third-party extensions do not pull the daemon runtime.

#![allow(dead_code)]

pub mod discovery;
pub use discovery::{
    DiscoveryCtx, DiscoveryDirection, DiscoveryInfo, DiscoveryItemError,
    MAX_DISCOVERY_EXTENSION_BYTES, MAX_DISCOVERY_EXTENSION_ITEMS, MAX_DISCOVERY_SIGNAL_BYTES,
};

use std::any::Any;
use std::sync::Arc;

use dlep_core::{
    DataItem, ExtensionId, LinkMetrics, MacAddress, Message, MessageType, RawDataItem, Signal,
    SignalType, StatusCode,
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
/// emit opaque application-level events, or request FSM-managed termination.
pub trait ExtensionCtx {
    fn session_id(&self) -> SessionId;
    fn is_router_side(&self) -> bool;
    fn send_message(&mut self, msg: Message);
    fn emit_event(&mut self, ev: Arc<dyn Any + Send + Sync>);

    /// Queue FSM-managed termination of this session with the supplied Status
    /// Code. The runtime finishes the current action batch first; existing
    /// protocol-error/closing transitions take precedence. The first accepted
    /// request wins and suppresses queued extension messages. An unknown-message
    /// or data-item handler should also return `Handled` for input it consumes.
    ///
    /// Requests from session-down hooks are rejected. Success means queued,
    /// not acknowledged by the peer. Custom contexts default to `Unsupported`.
    fn terminate_session(&mut self, reason: StatusCode) -> Result<(), TerminationRequestError> {
        let _ = reason;
        Err(TerminationRequestError::Unsupported)
    }
}

/// Why an extension's session-termination request was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TerminationRequestError {
    Unsupported,
    SessionClosing,
    AlreadyRequested,
}

impl std::fmt::Display for TerminationRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "extension context does not support session termination",
            Self::SessionClosing => "session is closing or closed",
            Self::AlreadyRequested => "session termination was already requested",
        })
    }
}

impl std::error::Error for TerminationRequestError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtHandled {
    Handled,
    Passthrough,
}

/// Session lifecycle state exposed to negotiated extensions.
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

    /// Opt in to discovery callbacks before session negotiation. At least one
    /// advertised ID is also required. This does not activate session hooks;
    /// their existing mutual-negotiation requirements still apply.
    fn supports_discovery(&self) -> bool {
        false
    }

    /// Add extension TLVs to an outgoing Peer Discovery or Peer Offer. Core
    /// fields and the destination remain owned by the discovery FSM/runtime.
    fn on_discovery_send(&self, kind: SignalType, ctx: &mut dyn DiscoveryCtx) {
        let _ = (kind, ctx);
    }

    /// Consume an unknown TLV in a role-compatible signal whose core grammar
    /// and extension budgets have passed validation. First handler wins. Every
    /// unknown item must be claimed for the signal to reach the core FSM.
    /// Other unclaimed items can still cause the datagram to be discarded.
    fn on_discovery_data_item(
        &self,
        signal: &Signal,
        item: &RawDataItem,
        ctx: &mut dyn DiscoveryCtx,
    ) -> ExtHandled {
        let _ = (signal, item, ctx);
        ExtHandled::Passthrough
    }

    /// Observe a complete valid signal after all unknown items were claimed.
    /// It includes the original extension TLVs; the core FSM receives only its
    /// core items. Discovery input is unauthenticated and has no SessionId.
    fn on_discovery_signal(&self, signal: &Signal, ctx: &mut dyn DiscoveryCtx) {
        let _ = (signal, ctx);
    }

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

    #[test]
    fn existing_contexts_can_report_termination_as_unsupported() {
        struct Context;
        impl ExtensionCtx for Context {
            fn session_id(&self) -> SessionId {
                SessionId(1)
            }
            fn is_router_side(&self) -> bool {
                true
            }
            fn send_message(&mut self, _: Message) {}
            fn emit_event(&mut self, _: Arc<dyn Any + Send + Sync>) {}
        }
        assert_eq!(
            Context.terminate_session(StatusCode::SHUTTING_DOWN),
            Err(TerminationRequestError::Unsupported)
        );
    }

    struct DefaultExtension;
    #[test]
    fn session_plugins_do_not_implicitly_enable_discovery_hooks() {
        assert!(!DefaultExtension.supports_discovery());
    }
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
