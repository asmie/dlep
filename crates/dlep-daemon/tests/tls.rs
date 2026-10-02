//! TLS and mTLS loopback integration tests (M7, M9).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon,
    NetworkConfig, RouterConfig, RouterDaemon, SharedConfig,
};
use dlep_net::tls::test_helpers::{
    client_config_for, client_config_with_identity, self_signed_for_ip, server_config_for,
    server_config_requiring_client_certs,
};
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(3);

fn loopback_modem_config() -> ModemConfig {
    ModemConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tcp_port: 0,
                discovery_port: 0,
                use_tls: true,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        },
        peer_description: "tls-modem".into(),
    }
}

fn loopback_router_config() -> RouterConfig {
    RouterConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                use_tls: true,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        },
        ..RouterConfig::default()
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

async fn await_session_down(rx: &mut Receiver<DaemonEvent>) {
    loop {
        let evt = timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for SessionDown")
            .expect("event channel closed");
        if matches!(evt, DaemonEvent::SessionDown { .. }) {
            return;
        }
    }
}

async fn await_destination_event<F>(rx: &mut Receiver<DaemonEvent>, mut pred: F) -> DestinationEvent
where
    F: FnMut(&DestinationEvent) -> bool,
{
    loop {
        let evt = timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for destination event")
            .expect("event channel closed");
        if let DaemonEvent::Destination { event: d, .. } = evt {
            if pred(&d) {
                return d;
            }
        }
    }
}

#[tokio::test]
async fn tls_session_establishes_and_carries_destination_lifecycle() {
    // PKI: self-signed cert for 127.0.0.1, trusted by the router.
    let pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let server_cfg = server_config_for(pki.cert_der, pki.key_der);
    let client_cfg = client_config_for(pki.roots);

    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .with_rustls_server(server_cfg)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .with_rustls_client(client_cfg)
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static (TLS)");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // Destination round-trip across the TLS session.
    let mac = MacAddress::new_eui48([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let id = DestinationId(mac);
    let metrics = LinkMetrics {
        max_data_rate_rx_bps: 1_000_000_000,
        max_data_rate_tx_bps: 1_000_000_000,
        current_data_rate_rx_bps: 500_000_000,
        current_data_rate_tx_bps: 500_000_000,
        latency: Duration::from_micros(2_500),
        resources: 90,
        rlq_rx: 100,
        rlq_tx: 100,
        mtu: 1500,
    };

    modem
        .add_destination(id, metrics)
        .await
        .expect("add_destination over TLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Up { id: got, .. } if *got == id),
    )
    .await;

    // The router emits DestinationEvent::Up _before_ its Destination_Up_Response
    // round-trips back to the modem; the modem keeps the per-destination
    // transaction open until that response arrives. If we fire
    // `drop_destination` while the prior Up transaction is still pending the
    // modem-side FSM silently swallows the request (see
    // `ModemSessionFsm`'s `AppDropDestination` arm). Plain-TCP localhost
    // delivery is fast enough that the response is almost always in by the
    // time the test gets here; the extra record-framing overhead of TLS makes
    // the race observable. Yield the runtime briefly to let the response drain.
    tokio::time::sleep(Duration::from_millis(50)).await;

    modem
        .drop_destination(id, StatusCode::SHUTTING_DOWN)
        .await
        .expect("drop_destination over TLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Down { id: got, .. } if *got == id),
    )
    .await;

    router.shutdown().await.expect("router shutdown");
    await_session_down(&mut router_events).await;
    await_session_down(&mut modem_events).await;
    modem.shutdown().await.expect("modem shutdown");
}

#[tokio::test]
async fn mtls_session_requires_and_accepts_client_certificate() {
    // Two identities: the modem's server cert (trusted by the router) and
    // the router's client cert (trusted by the modem's client verifier).
    let server_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let server_cfg = server_config_requiring_client_certs(
        server_pki.cert_der,
        server_pki.key_der,
        client_pki.roots,
    );
    let client_cfg =
        client_config_with_identity(server_pki.roots, client_pki.cert_der, client_pki.key_der);

    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .with_rustls_server(server_cfg)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .with_rustls_client(client_cfg)
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static (mTLS)");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // Destination round-trip across the mTLS session.
    let mac = MacAddress::new_eui48([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let id = DestinationId(mac);
    let metrics = LinkMetrics {
        max_data_rate_rx_bps: 1_000_000_000,
        max_data_rate_tx_bps: 1_000_000_000,
        current_data_rate_rx_bps: 500_000_000,
        current_data_rate_tx_bps: 500_000_000,
        latency: Duration::from_micros(2_500),
        resources: 90,
        rlq_rx: 100,
        rlq_tx: 100,
        mtu: 1500,
    };

    modem
        .add_destination(id, metrics)
        .await
        .expect("add_destination over mTLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Up { id: got, .. } if *got == id),
    )
    .await;

    // Same AppDropDestination race mitigation as the M7 test above.
    tokio::time::sleep(Duration::from_millis(50)).await;

    modem
        .drop_destination(id, StatusCode::SHUTTING_DOWN)
        .await
        .expect("drop_destination over mTLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Down { id: got, .. } if *got == id),
    )
    .await;

    router.shutdown().await.expect("router shutdown");
    await_session_down(&mut router_events).await;
    await_session_down(&mut modem_events).await;
    modem.shutdown().await.expect("modem shutdown");
}

#[tokio::test]
async fn mtls_modem_rejects_client_without_certificate() {
    let server_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Modem requires client certs; router presents none.
    let server_cfg = server_config_requiring_client_certs(
        server_pki.cert_der,
        server_pki.key_der,
        client_pki.roots,
    );
    let client_cfg = client_config_for(server_pki.roots);

    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .with_rustls_server(server_cfg)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .with_rustls_client(client_cfg)
        .spawn()
        .await
        .expect("router spawn");

    // Under TLS 1.3 the client side may believe the handshake succeeded
    // before the server rejects the missing certificate, so connect_static
    // is allowed to return Ok here; the session must still never come up.
    let _ = router.connect_static(modem_addr).await;

    let no_session_up = async {
        loop {
            match modem_events.recv().await {
                Ok(DaemonEvent::SessionUp { .. }) => return false,
                Ok(_) => continue,
                Err(_) => return true,
            }
        }
    };
    let result = timeout(STEP_TIMEOUT, no_session_up).await;
    match result {
        // Timed out without seeing SessionUp: the modem held the line.
        Err(_) => {}
        Ok(true) => {} // channel closed without SessionUp — also a pass
        Ok(false) => panic!("modem accepted a session from a client without a certificate"),
    }

    router.shutdown().await.expect("router shutdown");
    modem.shutdown().await.expect("modem shutdown");
}
