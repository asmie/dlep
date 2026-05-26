//! M8 — Extension plug-in API loopback test.
//!
//! Round-trips a Private-Use `ExtensionId` through a `TestExt` on both
//! sides: each side advertises the ID, observes the peer's advertisement,
//! sends a Private-Use `MessageType` on `on_session_state(up=true)`, and
//! emits a downcastable payload on the other side's `on_unknown_message`.

use std::any::Any;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dlep_core::{DataItem, ExtensionId, Message, MessageType};
use dlep_daemon::{
    DaemonEvent, ModemConfig, ModemDaemon, NetworkConfig, RouterConfig, RouterDaemon, SharedConfig,
};
use dlep_ext::{DlepExtension, ExtHandled, ExtensionCtx, SessionStateSnapshot};
use tokio::sync::broadcast::Receiver;
use tokio::sync::broadcast::error::RecvError;
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(3);

/// Private-Use ID per RFC 8175 §13.6 (the Private Use range starts at
/// 0x8000 / 32768). 0xF000 is well inside the range and stable for tests.
const TEST_EXT_ID: ExtensionId = ExtensionId(0xF000);

/// Private-Use MessageType for the in-session round-trip. RFC 8175
/// reserves 1..=16; anything above is fair game for extensions.
const TEST_MSG_TYPE: MessageType = MessageType(0xF000);

/// Payload that `TestExt::on_unknown_message` emits on the broadcast
/// channel. Downcastable from `DaemonEvent::Extension`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestExtPayload {
    from: String,
}

struct TestExt {
    label: String,
    advertised: Vec<ExtensionId>,
    /// Records what `on_negotiated` saw the peer advertise. Tests inspect
    /// after `SessionUp` to confirm the negotiation hook ran.
    saw_peer: Arc<Mutex<Option<Vec<ExtensionId>>>>,
}

impl TestExt {
    fn new(label: &str) -> Arc<Self> {
        Arc::new(Self {
            label: label.into(),
            advertised: vec![TEST_EXT_ID],
            saw_peer: Arc::new(Mutex::new(None)),
        })
    }
}

impl DlepExtension for TestExt {
    fn advertised_ids(&self) -> &[ExtensionId] {
        &self.advertised
    }

    fn on_negotiated(&self, remote_ids: &[ExtensionId]) -> bool {
        *self.saw_peer.lock().unwrap() = Some(remote_ids.to_vec());
        remote_ids.contains(&TEST_EXT_ID)
    }

    fn on_session_state(&self, state: SessionStateSnapshot, ctx: &mut dyn ExtensionCtx) {
        if state.up {
            // Send a Private-Use Message. The body has no payload —
            // exercising the unknown-message path is enough.
            let msg = Message::new(TEST_MSG_TYPE);
            ctx.send_message(msg);
        }
    }

    fn on_unknown_message(
        &self,
        message_type: MessageType,
        _items: &[DataItem],
        ctx: &mut dyn ExtensionCtx,
    ) -> ExtHandled {
        if message_type != TEST_MSG_TYPE {
            return ExtHandled::Passthrough;
        }
        let payload = TestExtPayload {
            from: self.label.clone(),
        };
        ctx.emit_event(Arc::new(payload) as Arc<dyn Any + Send + Sync>);
        ExtHandled::Handled
    }
}

fn loopback_modem_config() -> ModemConfig {
    ModemConfig {
        shared: SharedConfig {
            network: NetworkConfig {
                bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                tcp_port: 0,
                discovery_port: 0,
                // Plain TCP is enough; TLS path is covered by M7's test.
                use_tls: false,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        },
        peer_description: "ext-modem".into(),
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

/// Pull events off the broadcast `rx` until a `SessionUp` is observed.
/// `RecvError::Lagged` is logged-and-continued (broadcast lost some
/// events but the channel is still live); `RecvError::Closed` is treated
/// as a fatal "event channel closed" condition.
async fn await_session_up(rx: &mut Receiver<DaemonEvent>) -> Vec<ExtensionId> {
    loop {
        match timeout(STEP_TIMEOUT, rx.recv()).await {
            Err(_) => panic!("timed out waiting for SessionUp"),
            Ok(Err(RecvError::Closed)) => panic!("event channel closed before SessionUp"),
            Ok(Err(RecvError::Lagged(n))) => {
                eprintln!("await_session_up: receiver lagged {n}; continuing");
                continue;
            }
            Ok(Ok(DaemonEvent::SessionUp {
                negotiated_extensions,
                ..
            })) => return negotiated_extensions,
            Ok(Ok(_)) => continue,
        }
    }
}

async fn await_extension_payload(rx: &mut Receiver<DaemonEvent>) -> TestExtPayload {
    loop {
        match timeout(STEP_TIMEOUT, rx.recv()).await {
            Err(_) => panic!("timed out waiting for DaemonEvent::Extension"),
            Ok(Err(RecvError::Closed)) => {
                panic!("event channel closed before Extension event")
            }
            Ok(Err(RecvError::Lagged(n))) => {
                eprintln!("await_extension_payload: receiver lagged {n}; continuing");
                continue;
            }
            Ok(Ok(DaemonEvent::Extension(any))) => {
                return any
                    .downcast_ref::<TestExtPayload>()
                    .expect("payload type is TestExtPayload")
                    .clone();
            }
            Ok(Ok(_)) => continue,
        }
    }
}

#[tokio::test]
async fn private_use_extension_round_trips_session_init_and_unknown_message() {
    let modem_ext = TestExt::new("modem");
    let router_ext = TestExt::new("router");

    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .register_extension(modem_ext.clone() as Arc<dyn DlepExtension>)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .register_extension(router_ext.clone() as Arc<dyn DlepExtension>)
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static");

    let router_neg = await_session_up(&mut router_events).await;
    let modem_neg = await_session_up(&mut modem_events).await;

    assert_eq!(
        router_neg,
        vec![TEST_EXT_ID],
        "router-side negotiated set should contain the Private-Use ID"
    );
    assert_eq!(
        modem_neg,
        vec![TEST_EXT_ID],
        "modem-side negotiated set should contain the Private-Use ID"
    );

    // Each TestExt's on_negotiated must have run.
    assert_eq!(
        router_ext.saw_peer.lock().unwrap().clone(),
        Some(vec![TEST_EXT_ID]),
        "router-side on_negotiated did not run"
    );
    assert_eq!(
        modem_ext.saw_peer.lock().unwrap().clone(),
        Some(vec![TEST_EXT_ID]),
        "modem-side on_negotiated did not run"
    );

    // Each side sent the Private-Use message on `on_session_state(up=true)`,
    // and the *peer* side surfaces the unknown message via its
    // `on_unknown_message` hook, which calls `ctx.emit_event(...)`.
    let on_modem = await_extension_payload(&mut modem_events).await;
    let on_router = await_extension_payload(&mut router_events).await;
    assert_eq!(on_modem.from, "modem");
    assert_eq!(on_router.from, "router");

    router.shutdown().await.expect("router shutdown");
    modem.shutdown().await.expect("modem shutdown");
}
