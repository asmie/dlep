//! Explicit pre-session discovery hooks and unchanged session negotiation.
use dlep_core::{DataItem, DataItemType, ExtensionId, RawDataItem, Signal, SignalType};
use dlep_daemon::{DaemonEvent, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon};
use dlep_ext::{
    DiscoveryCtx, DiscoveryDirection, DiscoveryInfo, DlepExtension, ExtHandled,
    SessionStateSnapshot,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::broadcast::Receiver;

const ITEM: DataItemType = DataItemType(0xFF80);
#[derive(Clone, Debug)]
struct Notice {
    info: DiscoveryInfo,
    kind: SignalType,
    payload: String,
}
struct Plugin {
    ids: [ExtensionId; 1],
    label: &'static str,
    sent: AtomicUsize,
    received: AtomicUsize,
    sessions: AtomicUsize,
}
impl Plugin {
    fn new(label: &'static str, id: u16) -> Arc<Self> {
        Arc::new(Self {
            ids: [ExtensionId(id)],
            label,
            sent: AtomicUsize::new(0),
            received: AtomicUsize::new(0),
            sessions: AtomicUsize::new(0),
        })
    }
}
impl DlepExtension for Plugin {
    fn advertised_ids(&self) -> &[ExtensionId] {
        &self.ids
    }
    fn supports_discovery(&self) -> bool {
        true
    }
    fn on_discovery_send(&self, _: SignalType, ctx: &mut dyn DiscoveryCtx) {
        assert_eq!(ctx.info().direction, DiscoveryDirection::Outgoing);
        ctx.add_data_item(RawDataItem {
            type_id: ITEM,
            value: self.label.as_bytes().into(),
        })
        .unwrap();
        self.sent.fetch_add(1, Ordering::SeqCst);
    }
    fn on_discovery_data_item(
        &self,
        _: &Signal,
        item: &RawDataItem,
        _: &mut dyn DiscoveryCtx,
    ) -> ExtHandled {
        if item.type_id == ITEM {
            ExtHandled::Handled
        } else {
            ExtHandled::Passthrough
        }
    }
    fn on_discovery_signal(&self, signal: &Signal, ctx: &mut dyn DiscoveryCtx) {
        let payload = signal
            .data_items
            .iter()
            .find_map(|item| match item {
                DataItem::Unknown(item) if item.type_id == ITEM => {
                    Some(String::from_utf8(item.value.to_vec()).unwrap())
                }
                _ => None,
            })
            .unwrap();
        self.received.fetch_add(1, Ordering::SeqCst);
        ctx.emit_event(Arc::new(Notice {
            info: ctx.info(),
            kind: signal.signal_type,
            payload,
        }));
    }
    fn on_session_state(&self, state: SessionStateSnapshot, _: &mut dyn dlep_ext::ExtensionCtx) {
        if state.up {
            self.sessions.fetch_add(1, Ordering::SeqCst);
        }
    }
}
async fn notice(events: &mut Receiver<DaemonEvent>) -> Notice {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let DaemonEvent::Extension(payload) = events.recv().await.unwrap() {
                return payload.downcast_ref::<Notice>().unwrap().clone();
            }
        }
    })
    .await
    .unwrap()
}
async fn up(events: &mut Receiver<DaemonEvent>, matched: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let DaemonEvent::SessionUp {
                negotiated_extensions,
                ..
            } = events.recv().await.unwrap()
            {
                assert_eq!(
                    negotiated_extensions,
                    if matched {
                        vec![ExtensionId(0xF020)]
                    } else {
                        vec![]
                    }
                );
                break;
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn extended_discovery_preserves_metadata_core_fields_and_session_negotiation() {
    for (family, bind) in ["192.0.2.1", "fe80::1"].into_iter().enumerate() {
        for matched in [true, false] {
            let port = 50077 + family as u16 * 2 + u16::from(matched);
            let modem_plugin = Plugin::new("modem-private", 0xF020);
            let router_plugin =
                Plugin::new("router-private", if matched { 0xF020 } else { 0xF021 });
            let mut config = ModemConfig {
                secured_medium: true,
                ..Default::default()
            };
            config.shared.network.bind_addr = bind.parse().unwrap();
            config.shared.network.interface = Some("dlep-test".into());
            config.shared.network.tcp_port = 0;
            config.shared.network.discovery_port = port;
            config.shared.network.use_tls = false;
            let modem = ModemDaemon::builder()
                .config(config)
                .register_extension(modem_plugin.clone())
                .spawn()
                .await
                .unwrap();
            let mut config = RouterConfig::default();
            config.shared.network.bind_addr = bind.parse().unwrap();
            config.shared.network.interface = Some("dlep-test".into());
            config.shared.network.discovery_port = port;
            config.shared.network.use_tls = false;
            config.shared.timers.discovery_interval_ms = 1000;
            let router = RouterDaemon::builder()
                .config(config)
                .register_extension(router_plugin.clone())
                .spawn()
                .await
                .unwrap();
            let mut re = router.subscribe();
            let mut me = modem.subscribe();
            router.start_discovery().await.unwrap();
            let probe = notice(&mut me).await;
            let offer_notice = notice(&mut re).await;
            assert_eq!(
                (probe.kind, probe.payload.as_str()),
                (SignalType::PEER_DISCOVERY, "router-private")
            );
            assert_eq!(
                (offer_notice.kind, offer_notice.payload.as_str()),
                (SignalType::PEER_OFFER, "modem-private")
            );
            for info in [probe.info, offer_notice.info] {
                assert_eq!(info.direction, DiscoveryDirection::Incoming);
                assert!(info.peer.is_some());
                assert!(info.local_addr.is_some());
                assert!(info.interface_index.is_some_and(|index| index > 0));
            }
            assert_eq!(probe.info.role, dlep_ext::Role::Modem);
            assert_eq!(offer_notice.info.role, dlep_ext::Role::Router);
            let offer = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if let DaemonEvent::PeerDiscovered(offer) = re.recv().await.unwrap() {
                        return offer;
                    }
                }
            })
            .await
            .unwrap();
            assert_eq!(offer.secured_medium, Some(true));
            assert_eq!(offer.endpoints[0].addr, modem.local_addr());
            assert!(!offer.endpoints[0].use_tls);
            assert_eq!(router_plugin.sessions.load(Ordering::SeqCst), 0);
            assert_eq!(modem_plugin.sessions.load(Ordering::SeqCst), 0);
            router.connect_discovered(&offer).await.unwrap();
            up(&mut re, matched).await;
            up(&mut me, matched).await;
            assert_eq!(
                router_plugin.sessions.load(Ordering::SeqCst),
                usize::from(matched)
            );
            assert_eq!(
                modem_plugin.sessions.load(Ordering::SeqCst),
                usize::from(matched)
            );
            let before = modem_plugin.received.load(Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(1200)).await;
            assert!(router_plugin.sent.load(Ordering::SeqCst) >= 2);
            assert_eq!(
                modem_plugin.received.load(Ordering::SeqCst),
                before,
                "connected routers must be suppressed before callbacks"
            );
            router.shutdown().await.unwrap();
            modem.shutdown().await.unwrap();
        }
    }
}

#[tokio::test]
async fn bad_ttl_and_wrong_interface_traffic_do_not_reach_extension_hooks() {
    let plugin = Plugin::new("modem", 0xF020);
    let mut config = ModemConfig::default();
    config.shared.network.bind_addr = "192.0.2.1".parse().unwrap();
    config.shared.network.interface = Some("dlep-test".into());
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 50081;
    config.shared.network.use_tls = false;
    let modem = ModemDaemon::builder()
        .config(config)
        .register_extension(plugin.clone())
        .spawn()
        .await
        .unwrap();
    let mut events = modem.subscribe();
    let probe = dlep_fsm::discovery_common::build_peer_discovery("probe").with_item(
        DataItem::Unknown(RawDataItem {
            type_id: ITEM,
            value: bytes::Bytes::from_static(b"probe-private"),
        }),
    );
    let signal = probe.encode().unwrap();
    let socket = tokio::net::UdpSocket::bind("192.0.2.1:0").await.unwrap();
    socket.set_multicast_loop_v4(true).unwrap();
    socket.set_multicast_ttl_v4(64).unwrap();
    socket.send_to(&signal, "224.0.0.117:50081").await.unwrap();
    let wrong = dlep_net::discovery::DiscoverySocket::bind_on_interface(
        &dlep_net::discovery::DiscoveryParams {
            group_v4: dlep_core::DISCOVERY_IPV4_GROUP,
            interface_v4: std::net::Ipv4Addr::LOCALHOST,
            port: 0,
            group_port: Some(50081),
            multicast_loop: true,
            join_group: false,
        },
        &dlep_net::addr::InterfaceSpec::ByName("lo".into()),
    )
    .unwrap();
    wrong.send_to_group(&probe).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), events.recv())
            .await
            .is_err()
    );
    assert_eq!(plugin.received.load(Ordering::SeqCst), 0);
    socket.set_multicast_ttl_v4(255).unwrap();
    socket.send_to(&signal, "224.0.0.117:50081").await.unwrap();
    assert_eq!(notice(&mut events).await.payload, "probe-private");
    assert_eq!(plugin.received.load(Ordering::SeqCst), 1);
    modem.shutdown().await.unwrap();
}
