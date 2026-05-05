//! Plain-TCP loopback integration test (M3).
//!
//! Spins up a `ModemDaemon` listening on `127.0.0.1` with an OS-assigned
//! port, then a `RouterDaemon` that dials it. Asserts both sides emit
//! `DaemonEvent::SessionUp`, then drives `shutdown()` and asserts both sides
//! see `DaemonEvent::SessionDown`. All `recv` calls are wrapped in a
//! `tokio::time::timeout` so a hang fails loud rather than waiting forever.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use dlep_daemon::{
    DaemonEvent, ModemConfig, ModemDaemon, NetworkConfig, RouterConfig, RouterDaemon, SharedConfig,
    TimersConfig,
};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(2);

/// Aggressive timer overrides for the heartbeat keepalive test. RFC 8175
/// requires heartbeat intervals to be at least one second, so keep this at
/// the protocol minimum.
const FAST_HEARTBEAT_MS: u32 = 1_000;
const FAST_SESSION_INIT_MS: u32 = 500;
const FAST_TERMINATION_MS: u32 = 200;

fn fast_timers() -> TimersConfig {
    TimersConfig {
        heartbeat_interval_ms: FAST_HEARTBEAT_MS,
        discovery_interval_ms: 5_000,
        session_init_timeout_ms: FAST_SESSION_INIT_MS,
        termination_timeout_ms: FAST_TERMINATION_MS,
    }
}

fn loopback_modem_config() -> ModemConfig {
    ModemConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                // Pin to loopback so the test doesn't depend on the
                // OS-specific behaviour of `connect("0.0.0.0:N")`.
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tcp_port: 0, // OS-assigned
                use_tls: false,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        },
        peer_description: "loopback-modem".into(),
    }
}

fn loopback_router_config() -> RouterConfig {
    RouterConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                use_tls: false,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        },
        ..RouterConfig::default()
    }
}

async fn await_session_up(rx: &mut Receiver<DaemonEvent>) {
    let evt = timeout(STEP_TIMEOUT, rx.recv())
        .await
        .expect("timed out waiting for SessionUp")
        .expect("event channel closed");
    match evt {
        DaemonEvent::SessionUp { .. } => {}
        other => panic!("expected SessionUp, got {other:?}"),
    }
}

async fn await_session_down(rx: &mut Receiver<DaemonEvent>) {
    loop {
        let evt = timeout(STEP_TIMEOUT, rx.recv())
            .await
            .expect("timed out waiting for SessionDown")
            .expect("event channel closed");
        match evt {
            DaemonEvent::SessionDown { .. } => return,
            // Skip any non-terminal events that may sneak through.
            _ => continue,
        }
    }
}

#[tokio::test]
async fn router_modem_loopback_session() {
    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .spawn()
        .await
        .expect("router spawn");
    // Subscribe BEFORE connect_static so we don't miss SessionUp on the
    // router side (broadcast::Receiver only sees events sent after
    // subscription).
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    router.shutdown().await.expect("router shutdown");
    await_session_down(&mut router_events).await;
    await_session_down(&mut modem_events).await;

    modem.shutdown().await.expect("modem shutdown");
}

/// Regression: dropping the router handle without calling `shutdown()` must
/// terminate the session in bounded time. Before P2 #1 fix, the session
/// task would hot-loop on `commands.recv() == None` after the FSM entered
/// `Terminating`, only exiting when the `termination_timeout` elapsed.
/// With the `commands_open` guard, the FSM transitions through Terminating
/// once and then yields to timer/I/O handling — the modem sees `SessionDown`
/// well within the test's 2-second step bound.
#[tokio::test]
async fn router_dropped_without_shutdown_terminates_session() {
    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .spawn()
        .await
        .expect("router spawn");

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static");

    await_session_up(&mut modem_events).await;

    // Drop without calling shutdown() — this drops the per-session command
    // channel sender, which the session task observes as recv() == None.
    drop(router);

    // Modem must still see a clean SessionDown, not hang or hot-spin.
    await_session_down(&mut modem_events).await;

    modem.shutdown().await.expect("modem shutdown");
}

/// M4: with a 1s heartbeat interval and a 2s missed-deadline (2×),
/// run the session for ~2.5s (2+ heartbeat round-trips) and assert the
/// session stays up — no `SessionDown` is emitted on either side. Pins the
/// runtime's periodic-timer loop and the FSM's `RecvMessage(_)` keepalive
/// catch-all working together end-to-end.
#[tokio::test]
async fn heartbeat_keepalive_over_loopback() {
    let mut modem_cfg = loopback_modem_config();
    modem_cfg.shared.timers = fast_timers();
    let modem = ModemDaemon::builder()
        .config(modem_cfg)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let mut router_cfg = loopback_router_config();
    router_cfg.shared.timers = fast_timers();
    let router = RouterDaemon::builder()
        .config(router_cfg)
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // Run for several heartbeat cycles. With FAST_HEARTBEAT_MS=1000 and
    // missed-deadline=2000ms, surviving 2500ms means ≥2 heartbeats round-tripped
    // on each side and at least one missed-deadline reset has fired without
    // tearing down.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    // Neither side should have emitted SessionDown.
    assert_no_session_down(&mut router_events);
    assert_no_session_down(&mut modem_events);

    // Clean shutdown still works.
    router.shutdown().await.expect("router shutdown");
    await_session_down(&mut router_events).await;
    await_session_down(&mut modem_events).await;

    modem.shutdown().await.expect("modem shutdown");
}

fn assert_no_session_down(rx: &mut Receiver<DaemonEvent>) {
    loop {
        match rx.try_recv() {
            Ok(DaemonEvent::SessionDown { reason }) => {
                panic!("unexpected SessionDown({reason:?}) during keepalive window");
            }
            Ok(_) => continue, // ignore other events
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Closed) => panic!("event channel closed unexpectedly"),
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }
}

#[tokio::test]
async fn modem_tls_config_fails_instead_of_plaintext_downgrade() {
    let mut config = loopback_modem_config();
    config.shared.network.use_tls = true;

    let err = match ModemDaemon::builder().config(config).spawn().await {
        Ok(_) => panic!("TLS modem spawn should fail until TLS transport is implemented"),
        Err(err) => err,
    };

    assert!(
        err.to_string()
            .contains("TLS transport is not yet implemented")
    );
}

#[tokio::test]
async fn router_tls_config_fails_instead_of_plaintext_downgrade() {
    let mut config = loopback_router_config();
    config.shared.network.use_tls = true;
    let router = RouterDaemon::builder()
        .config(config)
        .spawn()
        .await
        .expect("router spawn");

    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 9));
    let err = router
        .connect_static(peer)
        .await
        .expect_err("TLS router connect should fail until TLS transport is implemented");

    assert!(
        err.to_string()
            .contains("TLS transport is not yet implemented")
    );
}
