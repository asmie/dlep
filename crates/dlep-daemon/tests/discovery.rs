//! Loopback integration test for M6 discovery.
//!
//! End-to-end gate for the discovery pipeline: spawn a `ModemDaemon` (which
//! auto-starts its discovery listener), spawn a `RouterDaemon`, kick off
//! `start_discovery()`, observe `DaemonEvent::PeerDiscovered`, then
//! `connect_static` to the discovered endpoint and assert `SessionUp` on
//! both sides.
//!
//! ## WSL2 environment caveat
//!
//! On WSL2 the `lo` interface does not carry the `MULTICAST` link flag
//! (`ip link show lo`), so binding the discovery socket's multicast join to
//! `127.0.0.1` would never receive datagrams. This test uses
//! `Ipv4Addr::UNSPECIFIED` for `bind_addr` to let the kernel pick the
//! default-route interface (typically `eth0`) for multicast. On Linux,
//! `TcpStream::connect("0.0.0.0:<port>")` still routes to loopback, so the
//! TCP-session leg works fine — the modem's `Peer_Offer` carries
//! `0.0.0.0:<resolved-tcp-port>`, which the router dials successfully.
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
    DaemonEvent, ModemConfig, ModemDaemon, NetworkConfig, PeerInfo, RouterConfig, RouterDaemon,
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

async fn await_peer_discovered(rx: &mut Receiver<DaemonEvent>) -> PeerInfo {
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
    // `peer.addr.ip()` is whatever the modem's TCP listener bound to —
    // `0.0.0.0` here (see file-level WSL2 note). The load-bearing
    // assertions are the description echo (proves the offer's data items
    // round-trip end-to-end) and that the port is a resolved, non-zero
    // value (proves the OS-assigned listen port was captured).
    assert_eq!(peer.peer_description.as_deref(), Some("discovery-modem"));
    assert_ne!(peer.addr.port(), 0, "modem TCP port must be resolved");

    // 5) Router connects to the discovered modem (embedder-driven path).
    router
        .connect_static(peer.addr)
        .await
        .expect("connect_static after discovery");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // 6) Clean shutdown.
    router.shutdown().await.expect("router shutdown");
    modem.shutdown().await.expect("modem shutdown");
}
