//! Loopback integration test for M6 discovery.
//!
//! End-to-end gate for the discovery pipeline: spawn a `ModemDaemon` (which
//! auto-starts its discovery listener), spawn a `RouterDaemon`, kick off
//! `start_discovery()`, observe `DaemonEvent::PeerDiscovered`, then
//! `connect_discovered` using the offered endpoints and assert `SessionUp` on
//! both sides.
//!
//! ## WSL2 environment caveat
//!
//! On WSL2 the `lo` interface does not carry the `MULTICAST` link flag
//! (`ip link show lo`), so binding the discovery socket's multicast join to
//! `127.0.0.1` would never receive datagrams. This test uses
//! `Ipv4Addr::UNSPECIFIED` for `bind_addr` to let the kernel pick the
//! default-route interface for multicast. The offer must resolve the wildcard
//! listener to the ingress interface's real unicast address via IP_PKTINFO.
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
