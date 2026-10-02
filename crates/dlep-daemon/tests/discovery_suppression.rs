//! A TCP-connected router must not receive more Peer Offers (RFC 8175 §7.1).
#![cfg(target_os = "linux")]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dlep_core::{Signal, SignalType};
use dlep_daemon::{DaemonEvent, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon};
use dlep_net::{
    Connector,
    addr::InterfaceSpec,
    discovery::{DiscoveryParamsV6, DiscoverySocket},
    tls::test_helpers::{client_config_for, self_signed_for_ip, server_config_for},
};
use tokio::{io::AsyncWriteExt, net::UdpSocket, time::timeout};

const WAIT: Duration = Duration::from_secs(3);
const QUIET: Duration = Duration::from_millis(100);

enum Probe {
    V4(UdpSocket),
    V6(DiscoverySocket),
}

impl Probe {
    async fn new(source: &str) -> Self {
        match source.parse::<IpAddr>().unwrap() {
            IpAddr::V4(ip) => {
                let socket = UdpSocket::bind((ip, 0)).await.unwrap();
                socket.set_ttl(255).unwrap();
                Self::V4(socket)
            }
            IpAddr::V6(ip) => Self::V6(
                DiscoverySocket::bind_v6(
                    &DiscoveryParamsV6 {
                        group: "ff02::1:7".parse().unwrap(),
                        local_address: ip,
                        port: 0,
                        group_port: None,
                        multicast_loop: true,
                        join_group: false,
                    },
                    &InterfaceSpec::ByName("dlep-test".into()),
                )
                .unwrap(),
            ),
        }
    }

    async fn send(&self, modem: SocketAddr) {
        let signal = dlep_fsm::discovery_common::build_peer_discovery("probe");
        match self {
            Self::V4(socket) => {
                socket
                    .send_to(&signal.encode().unwrap(), modem)
                    .await
                    .unwrap();
            }
            Self::V6(socket) => {
                socket.send_unicast(&signal, modem).await.unwrap();
            }
        }
    }

    async fn receive(&self) {
        let signal = match self {
            Self::V4(socket) => {
                let mut bytes = [0; 1500];
                let (len, _) = socket.recv_from(&mut bytes).await.unwrap();
                Signal::decode(bytes[..len].to_vec().into()).unwrap()
            }
            Self::V6(socket) => socket.recv().await.unwrap().0,
        };
        assert_eq!(signal.signal_type, SignalType::PEER_OFFER);
    }

    async fn offered(&self, modem: SocketAddr) {
        // Retry while TCP closure propagates through the session/handshake task.
        timeout(WAIT, async {
            loop {
                self.send(modem).await;
                if timeout(QUIET, self.receive()).await.is_ok() {
                    break;
                }
            }
        })
        .await
        .expect("discovery did not resume after connection closure");
    }

    async fn suppressed(&self, modem: SocketAddr) {
        // A connect can return before the accept task registers the connection.
        timeout(WAIT, async {
            loop {
                self.send(modem).await;
                if timeout(QUIET, self.receive()).await.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("connected router kept receiving offers");
        for _ in 0..2 {
            self.send(modem).await;
            assert!(
                timeout(QUIET, self.receive()).await.is_err(),
                "connected router received an offer"
            );
        }
    }
}

async fn exercise(ip: &str, other: &str, port: u16, tls: bool) {
    let mut config = ModemConfig::default();
    config.shared.network.bind_addr = ip.parse().unwrap();
    config.shared.network.interface =
        Some(if ip.contains(':') { "dlep-test" } else { "lo" }.into());
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = port;
    config.shared.network.use_tls = tls;
    let mut builder = ModemDaemon::builder().config(config.clone());
    let client = if tls {
        let pki = self_signed_for_ip(ip.parse().unwrap());
        builder = builder.with_rustls_server(server_config_for(pki.cert_der, pki.key_der));
        Some(client_config_for(pki.roots))
    } else {
        None
    };
    let modem = builder.spawn().await.unwrap();
    let mut discovery_addr = modem.local_addr();
    discovery_addr.set_port(port);
    let probe = Probe::new(ip).await;
    let other = Probe::new(other).await;
    probe.offered(discovery_addr).await;

    // Plain TCP deliberately sends neither TLS nor DLEP initialization.
    let mut first = Connector::plain()
        .connect(modem.local_addr())
        .await
        .unwrap();
    probe.suppressed(discovery_addr).await;
    // A new UDP source port from the same router remains suppressed.
    Probe::new(ip).await.suppressed(discovery_addr).await;
    other.offered(discovery_addr).await;

    let second = Connector::plain()
        .connect(modem.local_addr())
        .await
        .unwrap();
    if tls {
        // A failed handshake must release only its own registration.
        first.write_all(b"invalid TLS hello").await.unwrap();
    }
    drop(first);
    probe.suppressed(discovery_addr).await;
    other.offered(discovery_addr).await;
    drop(second);
    probe.offered(discovery_addr).await;

    // The same rule continues through an established DLEP session, and clean
    // shutdown allows the router to discover the modem again.
    let mut rc = RouterConfig::default();
    rc.shared.network = config.shared.network;
    let mut builder = RouterDaemon::builder().config(rc);
    if let Some(client) = client {
        builder = builder.with_rustls_client(client);
    }
    let router = builder.spawn().await.unwrap();
    let mut events = router.subscribe();
    router.connect_static(modem.local_addr()).await.unwrap();
    timeout(WAIT, async {
        loop {
            if matches!(events.recv().await.unwrap(), DaemonEvent::SessionUp { .. }) {
                break;
            }
        }
    })
    .await
    .unwrap();
    probe.suppressed(discovery_addr).await;
    other.offered(discovery_addr).await;
    router.shutdown().await.unwrap();
    probe.offered(discovery_addr).await;
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn ipv4_discovery_suppression_tracks_tcp_lifetime() {
    exercise("127.0.0.1", "127.0.0.2", 49_903, false).await;
}

#[tokio::test]
async fn ipv6_discovery_suppression_tracks_scoped_tcp_peer() {
    exercise("fe80::1", "fd00::1", 49_904, false).await;
}

#[tokio::test]
async fn tls_discovery_suppression_includes_pending_and_failed_handshakes() {
    exercise("127.0.0.1", "127.0.0.2", 49_905, true).await;
}

#[tokio::test]
async fn initialization_timeout_releases_discovery_suppression() {
    let mut config = ModemConfig::default();
    config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    config.shared.network.interface = Some("lo".into());
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 49_906;
    config.shared.network.use_tls = false;
    config.shared.timers.session_init_timeout_ms = 500;
    config.shared.timers.termination_timeout_ms = 100;
    let modem = ModemDaemon::builder().config(config).spawn().await.unwrap();
    let mut addr = modem.local_addr();
    addr.set_port(49_906);
    let probe = Probe::new("127.0.0.1").await;
    probe.offered(addr).await;
    let peer = Connector::plain()
        .connect(modem.local_addr())
        .await
        .unwrap();
    probe.suppressed(addr).await;
    // Keep our side alive: only the modem's initialization/termination timeout
    // can close this connection and make discovery eligible again.
    probe.offered(addr).await;
    drop(peer);
    modem.shutdown().await.unwrap();
}
