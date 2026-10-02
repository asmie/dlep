//! Loopback integration test for M6 discovery.
//!
//! End-to-end gate for the discovery pipeline: spawn a `ModemDaemon` (which
//! auto-starts its discovery listener), spawn a `RouterDaemon`, kick off
//! `start_discovery()`, observe `DaemonEvent::PeerDiscovered`, then
//! `connect_discovered` using the offered endpoints and assert `SessionUp` on
//! both sides.
//!
//! This test leaves interface selection to the default route and verifies that
//! a wildcard listener advertises the ingress interface's real unicast address.
//! A separate named-loopback test verifies explicit interface selection even
//! when the default route points to another interface.
//!
//! The router-side discovery socket binds an ephemeral port (port `0`) and
//! does not join the multicast group; only the modem joins. This avoids
//! Linux's `SO_REUSEPORT` 4-tuple hash on inbound unicast (the modem's
//! reply) routing back to the modem's own socket — the failure mode you
//! see if both sockets share the well-known discovery port on the same
//! host. See `crates/dlep-net/src/discovery.rs` `DiscoveryParams` for the
//! knobs.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dlep_daemon::{
    DaemonEvent, ModemConfig, ModemDaemon, NetworkConfig, PeerOffer, RouterConfig, RouterDaemon,
    SharedConfig, TimersConfig,
};
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// High, unprivileged UDP port for the discovery group rendezvous. 49854
/// is used by `dlep-net/src/discovery.rs::tests::loopback_send_recv_with_ttl_255`
/// so we offset to avoid colliding when both test binaries run concurrently.
fn discovery_test_port() -> u16 {
    49_855
}

fn loopback_modem_config() -> ModemConfig {
    ModemConfig {
        metrics: Default::default(),
        shared: SharedConfig {
            network: NetworkConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                tcp_port: 0,
                discovery_port: discovery_test_port(),
                use_tls: false,
                ..NetworkConfig::default()
            },
            timers: TimersConfig {
                // Fast resend so the test closes quickly even if the first
                // multicast probe is dropped (UDP).
                discovery_interval_ms: 200,
                ..TimersConfig::default()
            },
            ..SharedConfig::default()
        },
        peer_description: "discovery-modem".into(),
    }
}

fn loopback_router_config() -> RouterConfig {
    RouterConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                discovery_port: discovery_test_port(),
                use_tls: false,
                ..NetworkConfig::default()
            },
            timers: TimersConfig {
                discovery_interval_ms: 200,
                ..TimersConfig::default()
            },
            ..SharedConfig::default()
        },
        ..RouterConfig::default()
    }
}

async fn await_peer_discovered(rx: &mut Receiver<DaemonEvent>) -> PeerOffer {
    loop {
        let evt = timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for PeerDiscovered")
            .expect("event channel closed");
        if let DaemonEvent::PeerDiscovered(p) = evt {
            return p;
        }
    }
}

async fn await_session_up(rx: &mut Receiver<DaemonEvent>) {
    loop {
        let evt = timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for SessionUp")
            .expect("event channel closed");
        if matches!(evt, DaemonEvent::SessionUp { .. }) {
            return;
        }
    }
}

#[tokio::test]
async fn discovery_loopback_finds_modem_and_establishes_session() {
    // 1) Modem comes up first so the discovery listener is ready.
    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .spawn()
        .await
        .expect("modem spawn");
    let mut modem_events = modem.subscribe();

    // 2) Router subscribes before start_discovery (broadcast capture rule).
    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    // 3) Kick off discovery on the router.
    router.start_discovery().await.expect("start_discovery");

    // 4) Router observes the modem's offer.
    let peer = await_peer_discovered(&mut router_events).await;
    // A wildcard bind must produce a usable unicast connection point.
    assert_eq!(peer.peer_description.as_deref(), Some("discovery-modem"));
    assert!(
        !peer.endpoints[0].addr.ip().is_unspecified(),
        "must advertise a reachable unicast address"
    );
    assert_ne!(
        peer.endpoints[0].addr.port(),
        0,
        "modem TCP port must be resolved"
    );

    // 5) Router connects to the discovered modem (embedder-driven path).
    router
        .connect_discovered(&peer)
        .await
        .expect("connect_static after discovery");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // 6) Clean shutdown.
    router.shutdown().await.expect("router shutdown");
    modem.shutdown().await.expect("modem shutdown");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn named_loopback_discovery_uses_selected_address_and_connects() {
    let mut mc = loopback_modem_config();
    mc.shared.network.interface = Some("lo".into());
    // Wildcard TCP bind tests that the offer uses the selected ingress address.
    mc.shared.network.discovery_port = 49_857;
    let modem = ModemDaemon::builder().config(mc).spawn().await.unwrap();
    let mut me = modem.subscribe();
    let mut rc = loopback_router_config();
    rc.shared.network.interface = Some("lo".into());
    rc.shared.network.discovery_port = 49_857;
    let router = RouterDaemon::builder().config(rc).spawn().await.unwrap();
    let mut re = router.subscribe();
    router.start_discovery().await.unwrap();
    let offer = await_peer_discovered(&mut re).await;
    assert_eq!(offer.endpoints[0].addr.ip(), Ipv4Addr::LOCALHOST);
    assert_eq!(offer.endpoints[0].addr.port(), modem.local_addr().port());
    router.connect_discovered(&offer).await.unwrap();
    await_session_up(&mut me).await;
    await_session_up(&mut re).await;
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_named_interface_fails_validation_and_spawn() {
    let mut mc = loopback_modem_config();
    mc.shared.network.interface = Some("dlep-no-such-if".into());
    assert!(matches!(
        dlep_daemon::check_modem_config(&mc),
        Err(dlep_daemon::ConfigCheckError::Interface(_))
    ));
    assert!(matches!(
        ModemDaemon::builder().config(mc).spawn().await,
        Err(dlep_daemon::DaemonError::Config(_))
    ));
    let mut rc = loopback_router_config();
    rc.shared.network.interface = Some("dlep-no-such-if".into());
    assert!(matches!(
        dlep_daemon::check_router_config(&rc),
        Err(dlep_daemon::ConfigCheckError::Interface(_))
    ));
    assert!(matches!(
        RouterDaemon::builder().config(rc).spawn().await,
        Err(dlep_daemon::DaemonError::Config(_))
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn named_interface_validates_address_ownership_and_toml() {
    let mc: ModemConfig = toml::from_str("[network]\nuse_tls=false\ninterface='lo'").unwrap();
    dlep_daemon::check_modem_config(&mc).unwrap();
    let mut rc: RouterConfig = toml::from_str("[network]\nuse_tls=false\ninterface='lo'").unwrap();
    dlep_daemon::check_router_config(&rc).unwrap();
    rc.shared.network.bind_addr = "255.255.255.255".parse().unwrap();
    assert!(matches!(
        dlep_daemon::check_router_config(&rc),
        Err(dlep_daemon::ConfigCheckError::Interface(_))
    ));
}

#[cfg(target_os = "linux")]
async fn ipv6_discovery_connects(bind: &str, port: u16) {
    let mut mc = loopback_modem_config();
    mc.shared.network.bind_addr = bind.parse().unwrap();
    mc.shared.network.interface = Some("dlep-test".into());
    mc.shared.network.discovery_port = port;
    // A non-default group proves discovery_v6_group is actually used.
    mc.shared.network.discovery_v6_group = "ff02::117".parse().unwrap();
    let iface = dlep_net::addr::InterfaceSpec::ByName("dlep-test".into())
        .resolve_v6(bind.parse().unwrap())
        .unwrap();
    dlep_daemon::check_modem_config(&mc).unwrap();
    let modem = ModemDaemon::builder()
        .config(mc.clone())
        .spawn()
        .await
        .unwrap();
    let mut me = modem.subscribe();
    let mut rc = loopback_router_config();
    rc.shared.network = mc.shared.network;
    let router = RouterDaemon::builder().config(rc).spawn().await.unwrap();
    let mut re = router.subscribe();
    router.start_discovery().await.unwrap();
    let offer = await_peer_discovered(&mut re).await;
    let std::net::SocketAddr::V6(endpoint) = offer.endpoints[0].addr else {
        panic!("expected IPv6 offer")
    };
    assert_eq!(*endpoint.ip(), iface.address);
    assert!(!endpoint.ip().is_unspecified());
    assert!(!endpoint.ip().is_multicast());
    assert_eq!(endpoint.port(), modem.local_addr().port());
    if endpoint.ip().is_unicast_link_local() {
        assert_eq!(endpoint.scope_id(), iface.index);
    }
    router.connect_discovered(&offer).await.unwrap();
    await_session_up(&mut me).await;
    await_session_up(&mut re).await;
    router.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv6_wildcard_discovery_advertises_scoped_unicast_and_connects() {
    ipv6_discovery_connects("::", 49_858).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv6_link_local_listener_uses_selected_interface_scope() {
    ipv6_discovery_connects("fe80::1", 49_859).await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv6_concrete_unicast_discovery_connects() {
    ipv6_discovery_connects("fd00::1", 49_860).await;
}

#[test]
fn ipv6_wildcard_configuration_requires_scope() {
    let mut mc = loopback_modem_config();
    mc.shared.network.bind_addr = "::".parse().unwrap();
    assert!(matches!(
        dlep_daemon::check_modem_config(&mc),
        Err(dlep_daemon::ConfigCheckError::Interface(_))
    ));
    let mut rc = loopback_router_config();
    rc.shared.network.bind_addr = "::".parse().unwrap();
    assert!(matches!(
        dlep_daemon::check_router_config(&rc),
        Err(dlep_daemon::ConfigCheckError::Interface(_))
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ipv6_offers_from_global_source_scope_link_local_connection_points() {
    use dlep_net::{
        addr::InterfaceSpec,
        discovery::{DiscoveryParamsV6, DiscoverySocket},
    };
    let spec = InterfaceSpec::ByName("dlep-test".into());
    let iface = spec.resolve_v6("fe80::1".parse().unwrap()).unwrap();
    let socket = DiscoverySocket::bind_v6(
        &DiscoveryParamsV6 {
            group: "ff02::1:7".parse().unwrap(),
            local_address: "fd00::1".parse().unwrap(),
            port: 0,
            group_port: None,
            multicast_loop: true,
            join_group: true,
        },
        &spec,
    )
    .unwrap();
    let mut config = loopback_router_config();
    config.shared.network.bind_addr = "::".parse().unwrap();
    config.shared.network.interface = Some("dlep-test".into());
    config.shared.network.discovery_port = socket.local_port();
    let router = RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    router.start_discovery().await.unwrap();
    let (_, from, _) = timeout(STEP_TIMEOUT, socket.recv()).await.unwrap().unwrap();
    let signal = dlep_fsm::discovery_common::build_peer_offer(
        "test",
        "[fe80::1]:12345".parse().unwrap(),
        false,
    );
    socket.send_unicast(&signal, from).await.unwrap();
    let offer = await_peer_discovered(&mut events).await;
    assert_eq!(
        offer.endpoints[0].addr,
        std::net::SocketAddrV6::new(iface.address, 12345, 0, iface.index).into()
    );
    // Without a Connection Point, retain the source address and default port.
    socket
        .send_unicast(
            &dlep_core::Signal::new(dlep_core::SignalType::PEER_OFFER),
            from,
        )
        .await
        .unwrap();
    let fallback = await_peer_discovered(&mut events).await;
    assert_eq!(fallback.endpoints[0].addr, "[fd00::1]:854".parse().unwrap());
    router.shutdown().await.unwrap();
}
