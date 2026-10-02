use std::time::Duration;

use dlep_core::MacAddress;
use dlep_daemon::{
    DaemonEvent, DestinationEvent, DestinationId, LinkMetrics, MetricsConfig, MetricsEvent,
    ModemConfig, ModemDaemon, RouterConfig, RouterDaemon, check_modem_config,
};
use tokio::sync::broadcast;
use tokio::time::timeout;

fn config() -> ModemConfig {
    let mut c = ModemConfig::default();
    c.shared.network.use_tls = false;
    c.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
    c.shared.network.tcp_port = 0;
    c.shared.network.discovery_port = 0;
    c.metrics = MetricsConfig {
        max_data_rate_rx_bps: 50_000,
        max_data_rate_tx_bps: 60_000,
        current_data_rate_rx_bps: 10_000,
        current_data_rate_tx_bps: 20_000,
        latency_us: 1234,
        resources: Some(0),
        mtu: Some(1300),
        ..Default::default()
    };
    c
}
async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.unwrap();
            assert!(
                !matches!(event, DaemonEvent::SessionDown { .. }),
                "unexpected termination: {event:?}"
            );
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

#[test]
fn toml_metrics_parse_units_and_validate_ranges() {
    let example: ModemConfig =
        toml::from_str(include_str!("../../../examples/modem.toml")).unwrap();
    example.metrics.validate().unwrap();
    let c: ModemConfig = toml::from_str(
        r#"
        [network]
        use_tls = false
        [metrics]
        max_data_rate_rx_bps = 50000
        max_data_rate_tx_bps = 60000
        current_data_rate_rx_bps = 10000
        current_data_rate_tx_bps = 20000
        latency_us = 1234
        resources = 0
        mtu = 1300
    "#,
    )
    .unwrap();
    check_modem_config(&c).unwrap();
    assert_eq!(c.metrics.link_metrics(), config().metrics.link_metrics());
    let defaults: ModemConfig = toml::from_str("").unwrap();
    assert_eq!(defaults.metrics.link_metrics(), LinkMetrics::default());
    for field in ["resources", "rlq_rx", "rlq_tx"] {
        let c: ModemConfig =
            toml::from_str(&format!("[network]\nuse_tls=false\n[metrics]\n{field}=101")).unwrap();
        assert!(check_modem_config(&c).is_err());
    }
    assert!(toml::from_str::<ModemConfig>("[metrics]\nlatncy_us=1").is_err());
    let mut c = config();
    c.metrics.current_data_rate_rx_bps = 50_001;
    assert!(check_modem_config(&c).is_err());
    c = config();
    c.metrics.current_data_rate_tx_bps = 60_001;
    assert!(check_modem_config(&c).is_err());
}

#[tokio::test]
async fn invalid_metrics_fail_spawn_before_network_setup() {
    let mut c = config();
    c.metrics.rlq_tx = Some(101);
    assert!(matches!(
        ModemDaemon::builder().config(c).spawn().await,
        Err(dlep_daemon::runtime::DaemonError::Config(_))
    ));
}

#[tokio::test]
async fn configured_metrics_and_partial_updates_reach_router_without_optional_placeholders() {
    let c = config();
    let initial = c.metrics.link_metrics();
    let m = ModemDaemon::builder().config(c).spawn().await.unwrap();
    let mut c = RouterConfig::default();
    c.shared.network.use_tls = false;
    let r = RouterDaemon::builder().config(c).spawn().await.unwrap();
    let mut me = m.subscribe();
    let mut re = r.subscribe();
    r.connect_static(m.local_addr()).await.unwrap();
    event(&mut me, |e| matches!(e, DaemonEvent::SessionUp { .. })).await;
    let session_id = match event(&mut re, |e| matches!(e, DaemonEvent::SessionUp { .. })).await {
        DaemonEvent::SessionUp { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    let got = event(&mut re, |e| matches!(e, DaemonEvent::Metrics { .. })).await;
    assert!(
        matches!(got, DaemonEvent::Metrics { session_id: sid, event: MetricsEvent { session_wide: metrics }, .. } if sid == session_id && metrics == initial)
    );
    let id = DestinationId(MacAddress::new_eui48([2, 0, 0, 0, 0, 1]));
    for bad in [
        LinkMetrics {
            rlq_rx: Some(0),
            ..Default::default()
        },
        LinkMetrics {
            resources: Some(101),
            ..Default::default()
        },
        LinkMetrics {
            latency: Duration::MAX,
            ..Default::default()
        },
    ] {
        assert!(m.add_destination(id, bad).await.is_err());
        assert!(m.update_destination(id, bad).await.is_err());
        assert!(m.update_session_metrics(bad).await.is_err());
    }
    m.add_destination(id, LinkMetrics::default()).await.unwrap();
    let up = event(&mut re, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::Up { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(up, DaemonEvent::Destination { event: DestinationEvent::Up { metrics, .. }, .. } if metrics.resources == Some(0) && metrics.mtu == Some(1300) && metrics.rlq_rx.is_none() && metrics.rlq_tx.is_none())
    );
    m.update_session_metrics(LinkMetrics {
        resources: Some(30),
        ..Default::default()
    })
    .await
    .unwrap();
    let updated = event(&mut re, |e| matches!(e, DaemonEvent::Metrics { .. })).await;
    assert!(
        matches!(updated, DaemonEvent::Metrics { event: MetricsEvent { session_wide: metrics }, .. } if metrics.resources == Some(30) && metrics.mtu == Some(1300) && metrics.rlq_rx.is_none())
    );
    // Request follows the router's Up acknowledgment and Session Update response
    // on the same stream, so the modem has completed both transactions first.
    r.request_link_characteristics(
        session_id,
        id,
        dlep_core::LinkCharacteristics {
            latency: Some(Duration::ZERO),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let reply = event(&mut re, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::LinkCharacteristicsResponse { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        matches!(reply, DaemonEvent::Destination { event: DestinationEvent::LinkCharacteristicsResponse { metrics, .. }, .. } if metrics.resources == Some(30) && metrics.mtu == Some(1300) && metrics.rlq_rx.is_none())
    );
    r.shutdown().await.unwrap();
    m.shutdown().await.unwrap();
}
