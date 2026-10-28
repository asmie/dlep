use std::sync::{Arc, Mutex};
use std::time::Duration;

use dlep_core::{MacAddress, StatusCode as S};
use dlep_daemon::{
    DaemonError, DaemonEvent, DestinationEvent, DestinationId, LinkCharacteristics, LinkControl,
    LinkMetrics, LinkRequest, LinkResponse, ModemConfig, ModemDaemon, RouterConfig, RouterDaemon,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(3);

fn destination() -> DestinationId {
    MacAddress::new_eui48([2, 0, 0, 0, 0, 1]).into()
}
fn requested() -> LinkCharacteristics {
    LinkCharacteristics {
        current_data_rate_tx_bps: Some(123_000),
        ..Default::default()
    }
}
fn current() -> LinkMetrics {
    LinkMetrics {
        current_data_rate_tx_bps: 70_000,
        ..Default::default()
    }
}

struct Pair {
    router: RouterDaemon,
    modem: ModemDaemon,
    router_events: broadcast::Receiver<DaemonEvent>,
    modem_events: broadcast::Receiver<DaemonEvent>,
    session_id: dlep_ext::SessionId,
}

impl Pair {
    async fn new(backend: Arc<dyn LinkControl>) -> Self {
        let mut config = ModemConfig::default();
        config.shared.network.use_tls = false;
        config.shared.network.bind_addr = "127.0.0.1".parse().unwrap();
        config.shared.network.tcp_port = 0;
        config.shared.network.discovery_port = 0;
        let modem = ModemDaemon::builder()
            .config(config)
            .link_control(backend)
            .spawn()
            .await
            .unwrap();
        let mut router_config = RouterConfig::default();
        router_config.shared.network.use_tls = false;
        let router = RouterDaemon::builder()
            .config(router_config)
            .spawn()
            .await
            .unwrap();
        let mut router_events = router.subscribe();
        let modem_events = modem.subscribe();
        router.connect_static(modem.local_addr()).await.unwrap();
        let session_id = match event(&mut router_events, |e| {
            matches!(e, DaemonEvent::SessionUp { .. })
        })
        .await
        {
            DaemonEvent::SessionUp { session_id, .. } => session_id,
            _ => unreachable!(),
        };
        modem
            .add_destination(destination(), current())
            .await
            .unwrap();
        event(&mut router_events, |e| {
            matches!(
                e,
                DaemonEvent::Destination {
                    event: DestinationEvent::Up { .. },
                    ..
                }
            )
        })
        .await;
        Self {
            router,
            modem,
            router_events,
            modem_events,
            session_id,
        }
    }

    async fn request(&self) -> Result<(), DaemonError> {
        self.router
            .request_link_characteristics(self.session_id, destination(), requested())
            .await
    }

    async fn response(&mut self) -> (S, String, LinkMetrics) {
        match event(&mut self.router_events, |e| {
            matches!(
                e,
                DaemonEvent::Destination {
                    event: DestinationEvent::LinkCharacteristicsResponse { .. },
                    ..
                }
            )
        })
        .await
        {
            DaemonEvent::Destination {
                event:
                    DestinationEvent::LinkCharacteristicsResponse {
                        status,
                        text,
                        metrics,
                        ..
                    },
                ..
            } => (status, text, metrics),
            _ => unreachable!(),
        }
    }

    async fn shutdown(self) {
        self.router.shutdown().await.unwrap();
        self.modem.shutdown().await.unwrap();
    }
}

async fn event(
    rx: &mut broadcast::Receiver<DaemonEvent>,
    predicate: impl Fn(&DaemonEvent) -> bool,
) -> DaemonEvent {
    timeout(WAIT, async {
        loop {
            let event = rx.recv().await.unwrap();
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn backend_grant_reaches_router_with_applied_metrics() {
    let (seen_tx, mut seen) = mpsc::unbounded_channel();
    let backend = move |request: LinkRequest| {
        let seen_tx = seen_tx.clone();
        async move {
            let mut metrics = request.current;
            metrics.current_data_rate_tx_bps = request.requested.current_data_rate_tx_bps.unwrap();
            seen_tx.send(request).unwrap();
            LinkResponse::granted(metrics).with_text("applied")
        }
    };
    let mut pair = Pair::new(Arc::new(backend)).await;
    pair.request().await.unwrap();
    let (status, text, metrics) = pair.response().await;
    assert_eq!(status, S::SUCCESS);
    assert_eq!(text, "applied");
    assert_eq!(metrics.current_data_rate_tx_bps, 123_000);

    let request = seen.recv().await.unwrap();
    assert_eq!(request.id, destination());
    assert_eq!(request.requested, requested());
    assert_eq!(request.current, current());
    let notice = event(&mut pair.modem_events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::LinkCharacteristicsRequested { .. },
                ..
            }
        )
    })
    .await;
    assert!(matches!(
        notice,
        DaemonEvent::Destination { session_id, event: DestinationEvent::LinkCharacteristicsRequested { id, requested: got }, .. }
            if session_id == request.session_id && id == destination() && got == requested()
    ));

    // The granted rate is now the modem's stored metric for this session.
    pair.request().await.unwrap();
    let (_, _, metrics) = pair.response().await;
    assert_eq!(metrics.current_data_rate_tx_bps, 123_000);
    pair.shutdown().await;
}

#[tokio::test]
async fn slow_backend_holds_the_transaction_until_it_answers() {
    let (release_tx, release) = oneshot::channel::<()>();
    let release = Arc::new(Mutex::new(Some(release)));
    let backend = move |_request: LinkRequest| {
        let release = release.lock().unwrap().take();
        async move {
            if let Some(release) = release {
                release.await.unwrap();
            }
            LinkResponse::denied().with_text("radio busy")
        }
    };
    let mut pair = Pair::new(Arc::new(backend)).await;
    pair.request().await.unwrap();
    event(&mut pair.modem_events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::LinkCharacteristicsRequested { .. },
                ..
            }
        )
    })
    .await;
    assert!(
        timeout(Duration::from_millis(300), pair.response())
            .await
            .is_err(),
        "no response before the backend answers"
    );
    // Both sides keep the destination's single transaction slot occupied.
    for result in [
        pair.request().await,
        pair.modem.drop_destination(destination(), S::SUCCESS).await,
    ] {
        let Err(DaemonError::CommandRejected(report)) = result else {
            panic!("{result:?}")
        };
        assert_eq!(report.rejected[0].1.reason, dlep_daemon::CommandError::Busy);
    }
    // Destination Update is not a transaction and remains available.
    pair.modem
        .update_destination(
            destination(),
            LinkMetrics {
                current_data_rate_tx_bps: 80_000,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    release_tx.send(()).unwrap();
    let (status, text, metrics) = pair.response().await;
    assert_eq!(status, S::REQUEST_DENIED);
    assert_eq!(text, "radio busy");
    assert_eq!(metrics.current_data_rate_tx_bps, 80_000);
    pair.request().await.unwrap();
    assert_eq!(pair.response().await.0, S::REQUEST_DENIED);
    pair.shutdown().await;
}

#[tokio::test]
async fn invalid_or_panicking_backend_answers_become_denials() {
    let calls = Arc::new(Mutex::new(0));
    let backend = move |_request: LinkRequest| {
        let call = {
            let mut calls = calls.lock().unwrap();
            *calls += 1;
            *calls
        };
        if call == 3 {
            panic!("link-control backend failure before returning a future");
        }
        async move {
            match call {
                // MTU was not declared in ModemConfig.metrics.
                1 => LinkResponse::granted(LinkMetrics {
                    mtu: Some(1400),
                    ..Default::default()
                }),
                2 => LinkResponse {
                    status: S::INVALID_DATA,
                    text: String::new(),
                    metrics: None,
                },
                _ => panic!("link-control backend failure"),
            }
        }
    };
    let mut pair = Pair::new(Arc::new(backend)).await;
    // Each fallback completes the transaction and keeps the session usable.
    for _ in 0..4 {
        pair.request().await.unwrap();
        let (status, _, metrics) = pair.response().await;
        assert_eq!(status, S::REQUEST_DENIED);
        assert_eq!(metrics, current());
    }
    pair.shutdown().await;
}

#[tokio::test]
async fn session_end_cancels_an_outstanding_backend_call() {
    struct Dropped(Option<oneshot::Sender<()>>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }
    let (dropped_tx, dropped) = oneshot::channel();
    let dropped_tx = Arc::new(Mutex::new(Some(dropped_tx)));
    let backend = move |_request: LinkRequest| {
        let guard = Dropped(dropped_tx.lock().unwrap().take());
        async move {
            let _guard = guard;
            std::future::pending::<LinkResponse>().await
        }
    };
    let mut pair = Pair::new(Arc::new(backend)).await;
    pair.request().await.unwrap();
    event(&mut pair.modem_events, |e| {
        matches!(
            e,
            DaemonEvent::Destination {
                event: DestinationEvent::LinkCharacteristicsRequested { .. },
                ..
            }
        )
    })
    .await;
    pair.router.shutdown().await.unwrap();
    timeout(WAIT, dropped).await.unwrap().unwrap();
    pair.modem.shutdown().await.unwrap();
}
