//! Configured plugin startup, validation, and negotiated wire behavior.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use dlep_core::{DataItem, DataItemType, ExtensionId, Message, MessageType, RawDataItem};
use dlep_daemon::{
    ConfigCheckError, DaemonError, DaemonEvent, ExtensionCatalog, ExtensionConfig,
    ExtensionSetupError, ExtensionsConfig, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon,
    check_modem_config, check_modem_config_with_extensions, check_router_config,
    check_router_config_with_extensions,
};
use dlep_ext::{DlepExtension, ExtHandled, ExtensionCtx, SessionStateSnapshot};
use serde::Deserialize;
use tokio::sync::broadcast::Receiver;

const ID: ExtensionId = ExtensionId(0xF010);
const MESSAGE: MessageType = MessageType(0xF010);

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    label: String,
    id: u16,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            label: "default".into(),
            id: ID.0,
        }
    }
}

#[derive(Debug)]
struct Observation {
    local: String,
    remote: String,
    instance: usize,
}
struct Plugin {
    label: String,
    ids: [ExtensionId; 1],
    instance: usize,
}
impl DlepExtension for Plugin {
    fn advertised_ids(&self) -> &[ExtensionId] {
        &self.ids
    }
    fn on_session_state(&self, state: SessionStateSnapshot, ctx: &mut dyn ExtensionCtx) {
        if state.up {
            ctx.send_message(
                Message::new(MESSAGE).with_item(DataItem::Unknown(RawDataItem {
                    type_id: DataItemType(0xFF80),
                    value: self.label.clone().into_bytes().into(),
                })),
            );
        }
    }
    fn on_unknown_message(
        &self,
        kind: MessageType,
        items: &[DataItem],
        ctx: &mut dyn ExtensionCtx,
    ) -> ExtHandled {
        if kind != MESSAGE {
            return ExtHandled::Passthrough;
        }
        let [DataItem::Unknown(item)] = items else {
            panic!("configured payload");
        };
        ctx.emit_event(Arc::new(Observation {
            local: self.label.clone(),
            remote: String::from_utf8(item.value.to_vec()).unwrap(),
            instance: self.instance,
        }));
        ExtHandled::Handled
    }
}

fn catalog(calls: Arc<AtomicUsize>) -> ExtensionCatalog {
    let mut catalog = ExtensionCatalog::new();
    catalog.register_factory("echo", move |table: &ExtensionConfig| {
        let settings: Settings = toml::Value::Table(table.clone())
            .try_into()
            .map_err(|error| error.to_string())?;
        if settings.label.is_empty() {
            return Err("label must not be empty".into());
        }
        Ok(Arc::new(Plugin {
            label: settings.label,
            ids: [ExtensionId(settings.id)],
            instance: calls.fetch_add(1, Ordering::SeqCst),
        }))
    });
    catalog
}

#[test]
fn catalog_preserves_registration_order_and_supplies_default_settings() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut catalog = catalog(calls.clone());
    catalog.register(Arc::new(Plugin {
        label: "prebuilt".into(),
        ids: [ExtensionId(65001)],
        instance: 99,
    }));
    catalog.register_factory("last", |_| {
        Ok(Arc::new(Plugin {
            label: "last".into(),
            ids: [ExtensionId(65002)],
            instance: 100,
        }))
    });
    let registry = catalog.build(&ExtensionsConfig::new()).unwrap();
    assert_eq!(
        registry
            .iter()
            .map(|ext| ext.advertised_ids()[0])
            .collect::<Vec<_>>(),
        vec![ID, ExtensionId(65001), ExtensionId(65002)]
    );
    let configured = toml::from_str("[echo]\nid=65003\nlabel='configured'").unwrap();
    assert_eq!(
        catalog
            .build(&configured)
            .unwrap()
            .iter()
            .next()
            .unwrap()
            .advertised_ids(),
        &[ExtensionId(65003)]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        registry.iter().next().unwrap().advertised_ids(),
        &[ID],
        "a later build must not reconfigure an existing instance"
    );
}

#[test]
fn names_and_unused_settings_are_rejected_before_any_factory_runs() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registered = catalog(calls.clone());
    let unknown = toml::from_str("[typo]\nlabel='ignored'").unwrap();
    assert!(
        matches!(registered.build(&unknown), Err(ExtensionSetupError::UnknownFactory { name }) if name == "typo")
    );
    registered.register_factory("echo", |_| unreachable!("duplicate factory must not run"));
    assert!(
        matches!(registered.build(&ExtensionsConfig::new()), Err(ExtensionSetupError::DuplicateFactory { name }) if name == "echo")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let mut empty = ExtensionCatalog::new();
    empty.register_factory("", |_| unreachable!("empty name must not run"));
    assert!(matches!(
        empty.build(&ExtensionsConfig::new()),
        Err(ExtensionSetupError::EmptyName)
    ));
}

#[tokio::test]
async fn settings_round_trip_and_fail_consistently_in_checks_and_builders() {
    let valid = "[network]\nuse_tls=false\n[extensions.echo]\nlabel='radio'\nid=61456";
    let router: RouterConfig = toml::from_str(valid).unwrap();
    let modem: ModemConfig = toml::from_str(valid).unwrap();
    let router_copy: RouterConfig = toml::from_str(&toml::to_string(&router).unwrap()).unwrap();
    let modem_copy: ModemConfig = toml::from_str(&toml::to_string(&modem).unwrap()).unwrap();
    assert_eq!(router_copy.shared.extensions, router.shared.extensions);
    assert_eq!(modem_copy.shared.extensions, modem.shared.extensions);
    assert!(matches!(
        check_router_config(&router),
        Err(ConfigCheckError::Extension(
            ExtensionSetupError::UnknownFactory { .. }
        ))
    ));
    assert!(matches!(
        check_modem_config(&modem),
        Err(ConfigCheckError::Extension(
            ExtensionSetupError::UnknownFactory { .. }
        ))
    ));
    let recipes = catalog(Arc::new(AtomicUsize::new(0)));
    check_router_config_with_extensions(&router, &recipes).unwrap();
    check_modem_config_with_extensions(&modem, &recipes).unwrap();
    for settings in ["label=3", "unknown=true", "label=''", "id=65536"] {
        let text = format!(
            "[network]\nuse_tls=false\nbind_addr='192.0.2.123'\ntcp_port=0\n[extensions.echo]\n{settings}"
        );
        let router: RouterConfig = toml::from_str(&text).unwrap();
        let modem: ModemConfig = toml::from_str(&text).unwrap();
        assert!(matches!(
            check_router_config_with_extensions(&router, &recipes),
            Err(ConfigCheckError::Extension(
                ExtensionSetupError::Factory { .. }
            ))
        ));
        assert!(matches!(
            check_modem_config_with_extensions(&modem, &recipes),
            Err(ConfigCheckError::Extension(
                ExtensionSetupError::Factory { .. }
            ))
        ));
        assert!(
            matches!(RouterDaemon::builder().config(router).extension_catalog(recipes.clone()).spawn().await, Err(DaemonError::Config(message)) if message.contains("extension \"echo\" configuration failed"))
        );
        assert!(
            matches!(ModemDaemon::builder().config(modem).extension_catalog(recipes.clone()).spawn().await, Err(DaemonError::Config(message)) if message.contains("extension \"echo\" configuration failed"))
        );
    }
    assert!(toml::from_str::<RouterConfig>("[extensions]\necho=false").is_err());
    assert!(toml::from_str::<ModemConfig>("[extensions]\necho='wrong shape'").is_err());
}

async fn up(events: &mut Receiver<DaemonEvent>) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let DaemonEvent::SessionUp {
                negotiated_extensions,
                ..
            } = events.recv().await.unwrap()
            {
                assert_eq!(negotiated_extensions, vec![ID]);
                break;
            }
        }
    })
    .await
    .unwrap();
}
async fn observation(events: &mut Receiver<DaemonEvent>) -> Observation {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let DaemonEvent::Extension(payload) = events.recv().await.unwrap() {
                let payload = payload.downcast_ref::<Observation>().unwrap();
                return Observation {
                    local: payload.local.clone(),
                    remote: payload.remote.clone(),
                    instance: payload.instance,
                };
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn configured_factories_negotiate_and_keep_daemon_instances_independent() {
    for ip in ["127.0.0.1", "::1"] {
        let calls = Arc::new(AtomicUsize::new(0));
        let recipes = catalog(calls.clone());
        let mut config: ModemConfig = toml::from_str("[network]\nuse_tls=false\ntcp_port=0\ndiscovery_port=0\n[extensions.echo]\nlabel='modem'").unwrap();
        config.shared.network.bind_addr = ip.parse().unwrap();
        let modem = ModemDaemon::builder()
            .config(config)
            .extension_catalog(recipes.clone())
            .spawn()
            .await
            .unwrap();
        let mut me = modem.subscribe();
        let mut local_instances = Vec::new();
        let mut remote_instances = Vec::new();
        let mut routers = Vec::new();
        for label in ["router-a", "router-b"] {
            let config: RouterConfig = toml::from_str(&format!(
                "[network]\nuse_tls=false\n[extensions.echo]\nlabel='{label}'"
            ))
            .unwrap();
            let router = RouterDaemon::builder()
                .config(config)
                .extension_catalog(recipes.clone())
                .spawn()
                .await
                .unwrap();
            let mut re = router.subscribe();
            router.connect_static(modem.local_addr()).await.unwrap();
            up(&mut re).await;
            up(&mut me).await;
            let local = observation(&mut re).await;
            let remote = observation(&mut me).await;
            assert_eq!(
                (local.local.as_str(), local.remote.as_str()),
                (label, "modem")
            );
            assert_eq!(
                (remote.local.as_str(), remote.remote.as_str()),
                ("modem", label)
            );
            local_instances.push(local.instance);
            remote_instances.push(remote.instance);
            routers.push(router);
        }
        assert_ne!(local_instances[0], local_instances[1]);
        assert_eq!(remote_instances[0], remote_instances[1]);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        for router in routers {
            router.shutdown().await.unwrap();
        }
        modem.shutdown().await.unwrap();
    }
}
