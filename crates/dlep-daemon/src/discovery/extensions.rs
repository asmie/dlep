//! Guarded discovery callbacks, separate from negotiated session dispatch.
use crate::runtime::EventTx;
use dlep_core::{DataItem, RawDataItem, Signal, SignalType};
use dlep_ext::{
    DiscoveryCtx, DiscoveryDirection, DiscoveryInfo, DiscoveryItemError, DlepExtension, ExtHandled,
    ExtensionRegistry, MAX_DISCOVERY_EXTENSION_BYTES, MAX_DISCOVERY_EXTENSION_ITEMS, Role,
};
use std::{
    any::Any,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

const MAX_SIGNAL_BYTES: usize = 65_507;

pub(crate) struct DiscoveryHooks {
    role: Role,
    extensions: Vec<Arc<dyn DlepExtension>>,
}

impl Default for DiscoveryHooks {
    fn default() -> Self {
        Self {
            role: Role::Router,
            extensions: Vec::new(),
        }
    }
}

fn extension_type(item: &RawDataItem) -> bool {
    (21..u16::MAX).contains(&item.type_id.0)
}

impl DiscoveryHooks {
    pub(crate) fn new(registry: &ExtensionRegistry, role: Role) -> Self {
        Self {
            role,
            extensions: registry
                .iter()
                .filter(|extension| {
                    !extension.advertised_ids().is_empty() && extension.supports_discovery()
                })
                .cloned()
                .collect(),
        }
    }

    pub(super) fn receive(
        &self,
        signal: Signal,
        from: SocketAddr,
        local: IpAddr,
        index: u32,
        events: &EventTx,
    ) -> Option<Signal> {
        if self.extensions.is_empty() {
            return Some(signal);
        }
        let expected = if self.role.is_router() {
            SignalType::PEER_OFFER
        } else {
            SignalType::PEER_DISCOVERY
        };
        if signal.signal_type != expected {
            return None;
        }
        let mut count = 0;
        let mut bytes = 0;
        let mut core = Signal::new(signal.signal_type);
        for item in &signal.data_items {
            if let DataItem::Unknown(raw) = item {
                count += 1;
                bytes += raw.value.len() + 4;
                if !extension_type(raw)
                    || count > MAX_DISCOVERY_EXTENSION_ITEMS
                    || bytes > MAX_DISCOVERY_EXTENSION_BYTES
                {
                    return None;
                }
            } else {
                core.data_items.push(item.clone());
            }
        }
        if !dlep_fsm::discovery_common::valid_signal(&core) {
            return None;
        }
        if core.signal_type == SignalType::PEER_OFFER
            && dlep_fsm::discovery_common::offer_endpoints(&core, from).is_empty()
        {
            return None;
        }
        let mut ctx = Context {
            info: DiscoveryInfo {
                role: self.role,
                direction: DiscoveryDirection::Incoming,
                peer: Some(from),
                local_addr: Some(local),
                interface_index: Some(index),
            },
            events,
            signal: None,
            count: 0,
            bytes: 0,
            wire_bytes: 0,
        };
        for item in &signal.data_items {
            if let DataItem::Unknown(raw) = item {
                if !self.extensions.iter().any(|extension| {
                    extension.on_discovery_data_item(&signal, raw, &mut ctx) == ExtHandled::Handled
                }) {
                    return None;
                }
            }
        }
        for extension in &self.extensions {
            extension.on_discovery_signal(&signal, &mut ctx);
        }
        Some(core)
    }

    pub(super) fn send(
        &self,
        signal: &mut Signal,
        peer: Option<SocketAddr>,
        local: Option<IpAddr>,
        index: Option<u32>,
        events: &EventTx,
    ) {
        if self.extensions.is_empty() {
            return;
        }
        let expected = if self.role.is_router() {
            SignalType::PEER_DISCOVERY
        } else {
            SignalType::PEER_OFFER
        };
        if signal.signal_type != expected || !dlep_fsm::discovery_common::valid_signal(signal) {
            return;
        }
        let Ok(encoded) = signal.encode() else {
            return;
        };
        let mut ctx = Context {
            info: DiscoveryInfo {
                role: self.role,
                direction: DiscoveryDirection::Outgoing,
                peer,
                local_addr: local,
                interface_index: index,
            },
            events,
            wire_bytes: encoded.len(),
            signal: Some(signal),
            count: 0,
            bytes: 0,
        };
        for extension in &self.extensions {
            extension.on_discovery_send(expected, &mut ctx);
        }
    }
}

struct Context<'a> {
    info: DiscoveryInfo,
    events: &'a EventTx,
    signal: Option<&'a mut Signal>,
    count: usize,
    bytes: usize,
    wire_bytes: usize,
}
impl DiscoveryCtx for Context<'_> {
    fn info(&self) -> DiscoveryInfo {
        self.info
    }
    fn emit_event(&mut self, payload: Arc<dyn Any + Send + Sync>) {
        let _ = self.events.send(crate::DaemonEvent::Extension(payload));
    }
    fn add_data_item(&mut self, item: RawDataItem) -> Result<(), DiscoveryItemError> {
        let signal = self.signal.as_mut().ok_or(DiscoveryItemError::ReadOnly)?;
        if !extension_type(&item) {
            return Err(DiscoveryItemError::InvalidType);
        }
        if self.count >= MAX_DISCOVERY_EXTENSION_ITEMS {
            return Err(DiscoveryItemError::TooManyItems);
        }
        let size = item.value.len().saturating_add(4);
        if size > MAX_DISCOVERY_EXTENSION_BYTES.saturating_sub(self.bytes)
            || size > MAX_SIGNAL_BYTES.saturating_sub(self.wire_bytes)
        {
            return Err(DiscoveryItemError::TooLarge);
        }
        self.count += 1;
        self.bytes += size;
        self.wire_bytes += size;
        signal.data_items.push(DataItem::Unknown(item));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlep_core::{DataItemType, ExtensionId};
    use dlep_fsm::discovery_common::build_peer_discovery;
    use std::sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    struct Plugin {
        enabled: bool,
        ids: Vec<ExtensionId>,
        additions: Vec<RawDataItem>,
        results: Mutex<Vec<Result<(), DiscoveryItemError>>>,
        claimed: Option<DataItemType>,
        inspected: AtomicUsize,
        observed: AtomicUsize,
    }
    impl Plugin {
        fn new(additions: Vec<RawDataItem>, claimed: Option<DataItemType>) -> Arc<Self> {
            Arc::new(Self {
                enabled: true,
                ids: vec![ExtensionId(0xF020)],
                additions,
                results: Mutex::new(Vec::new()),
                claimed,
                inspected: AtomicUsize::new(0),
                observed: AtomicUsize::new(0),
            })
        }
    }
    impl DlepExtension for Plugin {
        fn advertised_ids(&self) -> &[dlep_core::ExtensionId] {
            &self.ids
        }
        fn supports_discovery(&self) -> bool {
            self.enabled
        }
        fn on_discovery_send(&self, _: SignalType, ctx: &mut dyn DiscoveryCtx) {
            for item in &self.additions {
                self.results
                    .lock()
                    .unwrap()
                    .push(ctx.add_data_item(item.clone()));
            }
        }
        fn on_discovery_data_item(
            &self,
            _: &Signal,
            item: &RawDataItem,
            ctx: &mut dyn DiscoveryCtx,
        ) -> ExtHandled {
            self.inspected.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                ctx.add_data_item(item.clone()),
                Err(DiscoveryItemError::ReadOnly)
            );
            if self.claimed == Some(item.type_id) {
                ExtHandled::Handled
            } else {
                ExtHandled::Passthrough
            }
        }
        fn on_discovery_signal(&self, _: &Signal, _: &mut dyn DiscoveryCtx) {
            self.observed.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn raw(kind: u16, size: usize) -> RawDataItem {
        RawDataItem {
            type_id: DataItemType(kind),
            value: vec![0; size].into(),
        }
    }
    fn make_hooks(role: Role, plugins: &[Arc<Plugin>]) -> DiscoveryHooks {
        let mut registry = ExtensionRegistry::new();
        for plugin in plugins {
            registry.register(plugin.clone());
        }
        DiscoveryHooks::new(&registry, role)
    }
    fn receive(hooks: &DiscoveryHooks, signal: Signal) -> Option<Signal> {
        let (events, _) = crate::runtime::new_event_channel();
        hooks.receive(
            signal,
            "192.0.2.1:12345".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            7,
            &events,
        )
    }

    #[test]
    fn outgoing_budgets_are_shared_and_rejected_additions_preserve_core_fields() {
        let mut additions: Vec<_> = [0, 1, 6, 20, u16::MAX]
            .into_iter()
            .map(|id| raw(id, 0))
            .collect();
        additions.extend([raw(21, MAX_DISCOVERY_EXTENSION_BYTES), raw(21, 0)]);
        let plugin = Plugin::new(additions, None);
        let (events, _) = crate::runtime::new_event_channel();
        let mut signal = build_peer_discovery("unchanged");
        make_hooks(Role::Router, std::slice::from_ref(&plugin)).send(
            &mut signal,
            None,
            None,
            None,
            &events,
        );
        assert_eq!(
            *plugin.results.lock().unwrap(),
            vec![Err(DiscoveryItemError::InvalidType); 5]
                .into_iter()
                .chain([Err(DiscoveryItemError::TooLarge), Ok(())])
                .collect::<Vec<_>>()
        );
        assert!(
            matches!(&signal.data_items[0], DataItem::PeerType { description, .. } if description == "unchanged")
        );
        assert_eq!(signal.data_items.len(), 2);
        let full = Plugin::new(vec![raw(21, 0)], None);
        let mut signal = build_peer_discovery(&"x".repeat(MAX_SIGNAL_BYTES - 13));
        make_hooks(Role::Router, std::slice::from_ref(&full)).send(
            &mut signal,
            None,
            None,
            None,
            &events,
        );
        assert_eq!(
            *full.results.lock().unwrap(),
            vec![Err(DiscoveryItemError::TooLarge)]
        );
        assert_eq!(signal.encode().unwrap().len(), MAX_SIGNAL_BYTES);
        for by_count in [true, false] {
            let first = Plugin::new(
                if by_count {
                    vec![raw(21, 0); MAX_DISCOVERY_EXTENSION_ITEMS]
                } else {
                    vec![raw(21, MAX_DISCOVERY_EXTENSION_BYTES - 4)]
                },
                None,
            );
            let second = Plugin::new(vec![raw(22, 0)], None);
            let mut signal = build_peer_discovery("router");
            make_hooks(Role::Router, &[first, second.clone()]).send(
                &mut signal,
                None,
                None,
                None,
                &events,
            );
            assert_eq!(
                *second.results.lock().unwrap(),
                vec![Err(if by_count {
                    DiscoveryItemError::TooManyItems
                } else {
                    DiscoveryItemError::TooLarge
                })]
            );
            assert!(signal.encode().is_ok());
        }
    }

    #[test]
    fn incoming_core_validation_and_budgets_precede_item_hooks() {
        let plugin = Plugin::new(Vec::new(), Some(DataItemType(21)));
        let hooks = make_hooks(Role::Modem, std::slice::from_ref(&plugin));
        for signal in [
            build_peer_discovery("router")
                .with_item(DataItem::Status {
                    code: dlep_core::StatusCode::SUCCESS,
                    text: String::new(),
                })
                .with_item(DataItem::Unknown(raw(21, 0))),
            build_peer_discovery("router").with_item(DataItem::Unknown(raw(4, 0))),
            build_peer_discovery("router")
                .with_item(DataItem::Unknown(raw(21, MAX_DISCOVERY_EXTENSION_BYTES))),
            Signal {
                signal_type: SignalType::PEER_DISCOVERY,
                data_items: vec![DataItem::Unknown(raw(21, 0)); MAX_DISCOVERY_EXTENSION_ITEMS + 1],
            },
            Signal::new(SignalType::PEER_OFFER).with_item(DataItem::Unknown(raw(21, 0))),
        ] {
            assert!(receive(&hooks, signal).is_none());
        }
        assert_eq!(plugin.inspected.load(Ordering::SeqCst), 0);
        assert_eq!(plugin.observed.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn explicit_opt_in_and_first_claimant_control_discovery_dispatch() {
        let first = Plugin::new(Vec::new(), Some(DataItemType(21)));
        let later = Plugin::new(Vec::new(), None);
        let hooks = make_hooks(Role::Modem, &[first.clone(), later.clone()]);
        let core = receive(
            &hooks,
            build_peer_discovery("router").with_item(DataItem::Unknown(raw(21, 0))),
        )
        .unwrap();
        assert!(dlep_fsm::discovery_common::valid_signal(&core));
        assert_eq!(first.inspected.load(Ordering::SeqCst), 1);
        assert_eq!(later.inspected.load(Ordering::SeqCst), 0);
        assert_eq!(later.observed.load(Ordering::SeqCst), 1);
        assert!(
            receive(
                &hooks,
                build_peer_discovery("router").with_item(DataItem::Unknown(raw(22, 0)))
            )
            .is_none()
        );
        assert_eq!(
            later.observed.load(Ordering::SeqCst),
            1,
            "unclaimed items prevent whole-signal callbacks"
        );
        for no_ids in [true, false] {
            let mut plugin = Plugin::new(Vec::new(), Some(DataItemType(21)));
            if no_ids {
                Arc::get_mut(&mut plugin).unwrap().ids.clear();
            } else {
                Arc::get_mut(&mut plugin).unwrap().enabled = false;
            }
            let hooks = make_hooks(Role::Modem, std::slice::from_ref(&plugin));
            let signal = receive(
                &hooks,
                build_peer_discovery("router").with_item(DataItem::Unknown(raw(21, 0))),
            )
            .unwrap();
            assert!(!dlep_fsm::discovery_common::valid_signal(&signal));
            assert_eq!(plugin.inspected.load(Ordering::SeqCst), 0);
        }
    }
}
