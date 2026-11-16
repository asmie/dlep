//! Optional offer retransmission keeps each probe's transport metadata.
use dlep_core::{DataItem, DataItemType, ExtensionId, RawDataItem, Signal, SignalType};
use dlep_daemon::{DaemonEvent, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon};
use dlep_ext::{DiscoveryCtx, DiscoveryInfo, DlepExtension};
use dlep_net::{
    addr::InterfaceSpec,
    discovery::{DiscoveryParams, DiscoveryParamsV6, DiscoverySocket},
    tls::test_helpers::{client_config_for, self_signed_for_ip, server_config_for},
};
use std::{
    net::{IpAddr, SocketAddr, SocketAddrV6},
    sync::{Arc, Mutex},
    time::Duration,
};

struct Observer(Mutex<Vec<DiscoveryInfo>>);
impl DlepExtension for Observer {
    fn advertised_ids(&self) -> &[ExtensionId] {
        &[ExtensionId(0xF080)]
    }
    fn supports_discovery(&self) -> bool {
        true
    }
    fn on_discovery_send(&self, kind: SignalType, ctx: &mut dyn DiscoveryCtx) {
        assert_eq!(kind, SignalType::PEER_OFFER);
        self.0.lock().unwrap().push(ctx.info());
        ctx.add_data_item(RawDataItem {
            type_id: DataItemType(0xFF80),
            value: b"offer-retry".as_slice().into(),
        })
        .unwrap();
    }
}
fn router_socket(ip: IpAddr) -> DiscoverySocket {
    let interface = InterfaceSpec::ByName("dlep-test".into());
    match ip {
        IpAddr::V4(ip) => DiscoverySocket::bind_on_interface(
            &DiscoveryParams {
                group_v4: dlep_core::DISCOVERY_IPV4_GROUP,
                interface_v4: ip,
                port: 0,
                group_port: None,
                multicast_loop: true,
                join_group: false,
            },
            &interface,
        ),
        IpAddr::V6(ip) => DiscoverySocket::bind_v6(
            &DiscoveryParamsV6 {
                group: dlep_core::DISCOVERY_IPV6_GROUP,
                local_address: ip,
                port: 0,
                group_port: None,
                multicast_loop: true,
                join_group: false,
            },
            &interface,
        ),
    }
    .unwrap()
}
fn scoped(ip: IpAddr, port: u16, index: u32) -> SocketAddr {
    match ip {
        IpAddr::V4(ip) => (ip, port).into(),
        IpAddr::V6(ip) => SocketAddrV6::new(ip, port, 0, index).into(),
    }
}

#[tokio::test]
async fn retried_offers_keep_scope_core_fields_and_hooks_and_establish_tls() {
    for (ip, bind, port) in [("192.0.2.1", "0.0.0.0", 50092), ("fe80::1", "::", 50093)] {
        let ip: IpAddr = ip.parse().unwrap();
        let mut config = ModemConfig {
            secured_medium: true,
            ..Default::default()
        };
        config.shared.network.interface = Some("dlep-test".into());
        config.shared.network.bind_addr = bind.parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = port;
        config.discovery.offer_retries = 2;
        let pki = self_signed_for_ip(ip);
        let client = client_config_for(pki.roots);
        let observer = Arc::new(Observer(Mutex::new(Vec::new())));
        let modem = ModemDaemon::builder()
            .config(config)
            .register_extension(observer.clone())
            .with_rustls_server(server_config_for(pki.cert_der, pki.key_der))
            .spawn()
            .await
            .unwrap();
        let sockets = [router_socket(ip), router_socket(ip)];
        let index = sockets[0].interface_index().unwrap();
        for socket in &sockets {
            socket
                .send_unicast(
                    &Signal::new(SignalType::PEER_DISCOVERY),
                    scoped(ip, port, index),
                )
                .await
                .unwrap();
        }
        let mut retained = None;
        for socket in &sockets {
            // Model losing the immediate offer. No second probe is sent.
            tokio::time::timeout(Duration::from_secs(3), socket.recv_with_metadata())
                .await
                .unwrap()
                .unwrap();
            for _ in 0..2 {
                let received =
                    tokio::time::timeout(Duration::from_secs(3), socket.recv_with_metadata())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(received.local_addr, ip);
                assert_eq!(received.interface_index, index);
                assert_eq!(received.ttl, 255);
                assert_eq!(received.signal.signal_type, SignalType::PEER_OFFER);
                assert!(
                    received
                        .signal
                        .data_items
                        .iter()
                        .any(|item| matches!(item, DataItem::PeerType { flags, .. } if flags.smi))
                );
                assert!(received.signal.data_items.iter().any(|item| matches!(item, DataItem::Unknown(raw) if raw.type_id == DataItemType(0xFF80) && raw.value.as_ref() == b"offer-retry")));
                let endpoint = received
                    .signal
                    .data_items
                    .iter()
                    .find_map(|item| match item {
                        DataItem::Ipv4ConnectionPoint {
                            flags,
                            addr,
                            port: Some(port),
                        } => {
                            assert!(flags.use_tls);
                            Some(SocketAddr::from((*addr, *port)))
                        }
                        DataItem::Ipv6ConnectionPoint {
                            flags,
                            addr,
                            port: Some(port),
                        } => {
                            assert!(flags.use_tls);
                            Some(scoped((*addr).into(), *port, index))
                        }
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(endpoint.ip(), ip);
                assert_eq!(endpoint.port(), modem.local_addr().port());
                retained = Some(endpoint);
            }
        }
        {
            let metadata = observer.0.lock().unwrap();
            assert_eq!(metadata.len(), 6);
            for socket in &sockets {
                let replies: Vec<_> = metadata
                    .iter()
                    .filter(|info| info.peer.unwrap().port() == socket.local_port())
                    .collect();
                assert_eq!(replies.len(), 3);
                assert!(
                    replies
                        .iter()
                        .all(|info| info.local_addr == Some(ip)
                            && info.interface_index == Some(index))
                );
            }
        }
        let mut config = RouterConfig::default();
        config.shared.network.bind_addr = ip;
        config.shared.network.interface = Some("dlep-test".into());
        let router = RouterDaemon::builder()
            .config(config)
            .with_rustls_client(client)
            .spawn()
            .await
            .unwrap();
        let mut events = router.subscribe();
        router.connect_static(retained.unwrap()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let DaemonEvent::SessionUp { peer, .. } = events.recv().await.unwrap() {
                    assert!(peer.is_tls);
                    break;
                }
            }
        })
        .await
        .unwrap();
        router.shutdown().await.unwrap();
        modem.shutdown().await.unwrap();
    }
}
