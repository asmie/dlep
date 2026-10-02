//! TLS and mTLS loopback integration tests (M7, M9).

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon,
    NetworkConfig, RouterConfig, RouterDaemon, SharedConfig,
};
use dlep_net::tls::test_helpers::{
    client_config_for, client_config_with_identity, expired_self_signed_for_ip, self_signed_for_ip,
    server_config_for, server_config_requiring_client_certs,
};
use tokio::sync::broadcast::Receiver;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(3);

fn loopback_modem_config() -> ModemConfig {
    ModemConfig {
        metrics: dlep_daemon::MetricsConfig {
            resources: Some(100),
            rlq_rx: Some(100),
            rlq_tx: Some(100),
            mtu: Some(1500),
            ..Default::default()
        },
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
        resources: Some(90),
        rlq_rx: Some(100),
        rlq_tx: Some(100),
        mtu: Some(1500),
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

    drop_after_ack(&modem, id).await;
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
        resources: Some(90),
        rlq_rx: Some(100),
        rlq_tx: Some(100),
        mtu: Some(1500),
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

    drop_after_ack(&modem, id).await;
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
    rejects_client(ClientFailure::Missing).await;
}

// Explicit Busy permits a safe retry; no guessed delay for the Up response.
async fn drop_after_ack(modem: &ModemDaemon, id: DestinationId) {
    timeout(STEP_TIMEOUT, async {
        loop {
            match modem.drop_destination(id, StatusCode::SHUTTING_DOWN).await {
                Ok(()) => break,
                Err(dlep_daemon::DaemonError::CommandRejected(report))
                    if report.accepted.is_empty()
                        && report.undelivered == 0
                        && report.unknown == 0
                        && !report.rejected.is_empty()
                        && report
                            .rejected
                            .iter()
                            .all(|(_, r)| r.reason == dlep_daemon::CommandError::Busy) =>
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => panic!("drop over TLS failed: {error}"),
            }
        }
    })
    .await
    .expect("Up acknowledgement before drop");
}

#[derive(Clone, Copy, Debug)]
enum ServerFailure {
    WrongIp,
    Untrusted,
    Expired,
}

async fn rejects_server(failure: ServerFailure, ip: IpAddr) {
    let healthy = self_signed_for_ip(ip);
    let invalid = match failure {
        ServerFailure::WrongIp => self_signed_for_ip(if ip.is_ipv4() {
            "127.0.0.2".parse().unwrap()
        } else {
            "::2".parse().unwrap()
        }),
        ServerFailure::Untrusted => self_signed_for_ip(ip),
        ServerFailure::Expired => expired_self_signed_for_ip(ip),
    };
    let mut roots = healthy.roots.clone();
    if !matches!(failure, ServerFailure::Untrusted) {
        // Trust the invalid identity: rejection must be about its name/date,
        // not an accidentally missing trust anchor.
        roots.add(invalid.cert_der.clone()).unwrap();
    }
    let mut mc = loopback_modem_config();
    mc.shared.network.bind_addr = ip;
    let bad = ModemDaemon::builder()
        .config(mc.clone())
        .with_rustls_server(server_config_for(invalid.cert_der, invalid.key_der))
        .spawn()
        .await
        .unwrap();
    let mut bad_events = bad.subscribe();
    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .with_rustls_client(client_config_for(roots))
        .spawn()
        .await
        .unwrap();
    let mut events = router.subscribe();
    let error = timeout(STEP_TIMEOUT, router.connect_static(bad.local_addr()))
        .await
        .expect("certificate rejection stalled")
        .expect_err("invalid server was accepted");
    let dlep_daemon::DaemonError::Io(io_error) = error else {
        panic!("unexpected error: {error}");
    };
    let Some(rustls::Error::InvalidCertificate(reason)) = io_error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    else {
        panic!("expected certificate verification failure, got {io_error:?}");
    };
    use rustls::CertificateError as C;
    assert!(
        match failure {
            ServerFailure::WrongIp => matches!(
                reason,
                C::NotValidForName | C::NotValidForNameContext { .. }
            ),
            ServerFailure::Untrusted => matches!(reason, C::UnknownIssuer),
            ServerFailure::Expired => matches!(reason, C::Expired | C::ExpiredContext { .. }),
        },
        "{failure:?}: wrong rejection reason {reason:?}"
    );
    assert!(
        router.connection_states().borrow().is_empty(),
        "failed handshake registered a DLEP session"
    );
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));

    // The same router and trust configuration must still establish a valid
    // session, proving rejection rather than a generally broken TLS setup.
    let good = ModemDaemon::builder()
        .config(mc)
        .with_rustls_server(server_config_for(healthy.cert_der, healthy.key_der))
        .spawn()
        .await
        .unwrap();
    let mut good_events = good.subscribe();
    timeout(STEP_TIMEOUT, router.connect_static(good.local_addr()))
        .await
        .unwrap()
        .unwrap();
    await_session_up(&mut events).await;
    await_session_up(&mut good_events).await;
    assert!(matches!(
        bad_events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    router.shutdown().await.unwrap();
    good.shutdown().await.unwrap();
    bad.shutdown().await.unwrap();
}

#[tokio::test]
async fn tls_rejects_wrong_server_ip_for_ipv4_and_ipv6() {
    for ip in ["127.0.0.1", "::1"] {
        rejects_server(ServerFailure::WrongIp, ip.parse().unwrap()).await;
    }
}

#[tokio::test]
async fn tls_rejects_untrusted_server_for_ipv4_and_ipv6() {
    for ip in ["127.0.0.1", "::1"] {
        rejects_server(ServerFailure::Untrusted, ip.parse().unwrap()).await;
    }
}

#[tokio::test]
async fn tls_rejects_expired_server_for_ipv4_and_ipv6() {
    for ip in ["127.0.0.1", "::1"] {
        rejects_server(ServerFailure::Expired, ip.parse().unwrap()).await;
    }
}

#[derive(Clone, Copy)]
enum ClientFailure {
    Missing,
    Untrusted,
    Expired,
    Plaintext,
}

async fn rejects_client(failure: ClientFailure) {
    let ip = "127.0.0.1".parse().unwrap();
    let server = self_signed_for_ip(ip);
    let healthy = self_signed_for_ip(ip);
    let invalid = if matches!(failure, ClientFailure::Expired) {
        expired_self_signed_for_ip(ip)
    } else {
        self_signed_for_ip(ip)
    };
    let mut client_roots = healthy.roots.clone();
    if matches!(failure, ClientFailure::Expired) {
        client_roots.add(invalid.cert_der.clone()).unwrap();
    }
    let server_cfg = if matches!(failure, ClientFailure::Plaintext) {
        server_config_for(server.cert_der, server.key_der)
    } else {
        server_config_requiring_client_certs(server.cert_der, server.key_der, client_roots)
    };
    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .with_rustls_server(server_cfg)
        .spawn()
        .await
        .unwrap();
    let mut modem_events = modem.subscribe();
    let mut cfg = loopback_router_config();
    cfg.peer_description = "rejected-router".into();
    cfg.shared.network.use_tls = !matches!(failure, ClientFailure::Plaintext);
    let mut builder = RouterDaemon::builder().config(cfg);
    if !matches!(failure, ClientFailure::Plaintext) {
        let tls = if matches!(failure, ClientFailure::Missing) {
            client_config_for(server.roots.clone())
        } else {
            client_config_with_identity(server.roots.clone(), invalid.cert_der, invalid.key_der)
        };
        builder = builder.with_rustls_client(tls);
    }
    let bad = builder.spawn().await.unwrap();
    let mut bad_events = bad.subscribe();
    // TLS 1.3 may return client-side handshake success before server-side
    // client-certificate rejection. Require either an immediate I/O error or
    // a terminal session event, never a DLEP SessionUp.
    match timeout(STEP_TIMEOUT, bad.connect_static(modem.local_addr()))
        .await
        .unwrap()
    {
        Ok(()) => timeout(STEP_TIMEOUT, async {
            loop {
                match bad_events.recv().await.unwrap() {
                    DaemonEvent::SessionUp { .. } => panic!("invalid client established DLEP"),
                    DaemonEvent::SessionDown { .. } => break,
                    _ => {}
                }
            }
        })
        .await
        .expect("rejected client was left pending"),
        Err(error) => assert!(matches!(error, dlep_daemon::DaemonError::Io(_)), "{error}"),
    }
    bad.shutdown().await.unwrap();
    assert!(
        matches!(
            modem_events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "modem emitted a session event for a rejected handshake"
    );

    // Reuse the same modem after rejection. A failed handshake must not stop
    // the accept loop or be mistaken for an established DLEP session.
    let mut cfg = loopback_router_config();
    cfg.peer_description = "healthy-router".into();
    let good = RouterDaemon::builder()
        .config(cfg)
        .with_rustls_client(client_config_with_identity(
            server.roots,
            healthy.cert_der,
            healthy.key_der,
        ))
        .spawn()
        .await
        .unwrap();
    let mut good_events = good.subscribe();
    timeout(STEP_TIMEOUT, good.connect_static(modem.local_addr()))
        .await
        .unwrap()
        .unwrap();
    await_session_up(&mut good_events).await;
    let event = timeout(STEP_TIMEOUT, modem_events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(event, DaemonEvent::SessionUp { peer, .. } if peer.peer_description.as_deref() == Some("healthy-router"))
    );
    good.shutdown().await.unwrap();
    modem.shutdown().await.unwrap();
}

#[tokio::test]
async fn mtls_rejects_untrusted_client_and_accepts_next_healthy_client() {
    rejects_client(ClientFailure::Untrusted).await;
}

#[tokio::test]
async fn mtls_rejects_expired_client_and_accepts_next_healthy_client() {
    rejects_client(ClientFailure::Expired).await;
}

#[tokio::test]
async fn tls_modem_rejects_plaintext_dlep_and_accepts_next_tls_client() {
    rejects_client(ClientFailure::Plaintext).await;
}
