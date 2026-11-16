//! Background task that owns a `DiscoverySocket` and a discovery FSM.
//!
//! Used by both `RouterDaemon::start_discovery` (router-side, drives
//! Peer_Discovery sends and listens for Peer_Offers) and `ModemDaemon::spawn`
//! (modem-side, listens for Peer_Discovery and replies with Peer_Offer).
//!
//! Routers use one periodic probe timer. Optional modem offer bursts use bounded
//! per-peer single-shot timers with non-reused ids, retaining the probe's packet
//! metadata for each retry. Cancelled/stale expiries cannot revive a burst.

mod extensions;
pub(crate) use extensions::DiscoveryHooks;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use dlep_fsm::events::{EmittedEvent, FsmAction, FsmEvent, SendTarget};
use dlep_fsm::{TimerId, TimerKind};
use dlep_net::discovery::{DiscoverySocket, ReceivedSignal};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::connections::ConnectedRouters;
use crate::events::{DaemonEvent, PeerOffer};
use crate::runtime::{DaemonError, EventTx};

// Keep failure injection private; public callers still supply DiscoverySocket.
trait DiscoveryIo: Send + Sync {
    fn recv_with_metadata(&self) -> impl Future<Output = io::Result<ReceivedSignal>> + Send;
    fn send_to_group(
        &self,
        signal: &dlep_core::Signal,
    ) -> impl Future<Output = io::Result<()>> + Send;
    fn send_unicast(
        &self,
        signal: &dlep_core::Signal,
        dest: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

impl DiscoveryIo for DiscoverySocket {
    async fn recv_with_metadata(&self) -> io::Result<ReceivedSignal> {
        DiscoverySocket::recv_with_metadata(self).await
    }

    async fn send_to_group(&self, signal: &dlep_core::Signal) -> io::Result<()> {
        DiscoverySocket::send_to_group(self, signal).await
    }

    async fn send_unicast(&self, signal: &dlep_core::Signal, dest: SocketAddr) -> io::Result<()> {
        DiscoverySocket::send_unicast(self, signal, dest).await
    }
}

/// Trait shared by the two discovery FSMs so the runtime can drive either
/// one without taking a concrete type.
pub trait DiscoveryFsm: Send + 'static {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction>;
}

impl DiscoveryFsm for dlep_fsm::discovery_router::RouterDiscoveryFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        Self::step(self, event)
    }
}

impl DiscoveryFsm for dlep_fsm::discovery_modem::ModemDiscoveryFsm {
    fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
        Self::step(self, event)
    }
}

#[derive(Clone, Copy, Default)]
struct PacketContext {
    local: Option<std::net::IpAddr>,
    interface_index: Option<u32>,
    peer: Option<SocketAddr>,
}

/// Router probe or bounded per-peer modem retry timers. The context belongs to
/// the originating datagram, so a later peer cannot change a retry's scope.
#[derive(Default)]
struct DiscoveryTimers {
    handles: HashMap<TimerId, (JoinHandle<()>, PacketContext)>,
}

impl DiscoveryTimers {
    /// Arm a timer at `id`. If a previous handle was registered under the
    /// same id, it is aborted before being replaced — this avoids leaking
    /// a task when the FSM re-arms the same logical timer.
    fn arm(&mut self, id: TimerId, handle: JoinHandle<()>, packet: PacketContext) {
        if let Some((old, _)) = self.handles.insert(id, (handle, packet)) {
            old.abort();
        }
    }

    fn cancel(&mut self, id: TimerId) {
        if let Some((h, _)) = self.handles.remove(&id) {
            h.abort();
        }
    }

    fn context(&self, id: TimerId) -> PacketContext {
        self.handles
            .get(&id)
            .map_or(PacketContext::default(), |(_, packet)| *packet)
    }
}

impl Drop for DiscoveryTimers {
    fn drop(&mut self) {
        for (_, (h, _)) in self.handles.drain() {
            h.abort();
        }
    }
}

/// Run a discovery task until shutdown. Owns the FSM and the socket; bridges
/// socket I/O to FSM events. Emits `DaemonEvent::PeerDiscovered` when the
/// FSM signals one.
///
/// `initial_event` lets the caller kick the router-side FSM into Probing
/// (`Some(FsmEvent::AppStartDiscovery)`) or leave the modem-side FSM in its
/// default Listening state (`None`).
/// A shutdown message or closure of the shutdown channel stops discovery.
/// Timers started while processing a datagram retain that packet's reply
/// metadata. Native modem runners additionally cancel offers to connected peers.
pub async fn run_discovery<F: DiscoveryFsm>(
    fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
) -> Result<(), DaemonError> {
    run_discovery_with_peers(
        fsm,
        socket,
        initial_event,
        shutdown_rx,
        events_tx,
        None,
        DiscoveryHooks::default(),
    )
    .await
}

/// Run discovery with explicitly enabled pre-session extension hooks. Session
/// negotiation remains independent. `role` determines compatible signal types.
pub async fn run_discovery_with_extensions<F: DiscoveryFsm>(
    fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    registry: dlep_ext::ExtensionRegistry,
    role: dlep_ext::Role,
) -> Result<(), DaemonError> {
    run_discovery_with_peers(
        fsm,
        socket,
        initial_event,
        shutdown_rx,
        events_tx,
        None,
        DiscoveryHooks::new(&registry, role),
    )
    .await
}

pub(crate) async fn run_discovery_with_peers<F: DiscoveryFsm>(
    fsm: F,
    socket: DiscoverySocket,
    initial_event: Option<FsmEvent>,
    shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    connected_routers: Option<ConnectedRouters>,
    hooks: DiscoveryHooks,
) -> Result<(), DaemonError> {
    run_discovery_io(
        fsm,
        socket,
        initial_event,
        shutdown_rx,
        events_tx,
        connected_routers,
        hooks,
    )
    .await
}

/// Run a discovery group and report an unexpected stop. Shutdown returns
/// `Ok`; any error is logged and published as `DaemonEvent::DiscoveryStopped`
/// so applications learn that discovery ended while sessions continue.
pub(crate) async fn run_supervised_discovery_group<F: DiscoveryFsm>(
    members: Vec<(F, DiscoverySocket)>,
    start: bool,
    shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    connected_routers: Option<ConnectedRouters>,
    registry: dlep_ext::ExtensionRegistry,
    role: dlep_ext::Role,
) -> Result<(), DaemonError> {
    /// Aborts the group when the supervisor is cancelled.
    struct AbortOnDrop(tokio::task::JoinHandle<Result<(), DaemonError>>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let events = events_tx.clone();
    // A separate task turns a panic into an error reported here instead of
    // only when shutdown joins the daemon's discovery handle.
    let mut group = AbortOnDrop(tokio::spawn(run_discovery_group(
        members,
        start,
        shutdown_rx,
        events_tx,
        connected_routers,
        registry,
        role,
    )));
    let result = (&mut group.0).await.unwrap_or_else(|error| {
        Err(DaemonError::Config(format!(
            "discovery task failed: {error}"
        )))
    });
    if let Err(error) = &result {
        tracing::error!(%error, "discovery stopped; established sessions continue");
        let _ = events.send(crate::DaemonEvent::DiscoveryStopped {
            error: error.to_string(),
        });
    }
    result
}

/// Own both family tasks as one lifecycle. Dropping the supervisor aborts all
/// children; ordinary shutdown closes their stop channels and joins them.
/// Any unexpected child exit stops the complete group.
pub(crate) async fn run_discovery_group<F: DiscoveryFsm>(
    mut members: Vec<(F, DiscoverySocket)>,
    start: bool,
    mut shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    connected_routers: Option<ConnectedRouters>,
    registry: dlep_ext::ExtensionRegistry,
    role: dlep_ext::Role,
) -> Result<(), DaemonError> {
    if members.len() == 1 {
        let (fsm, socket) = members.pop().expect("one discovery member");
        return run_discovery_with_peers(
            fsm,
            socket,
            start.then_some(FsmEvent::AppStartDiscovery),
            shutdown_rx,
            events_tx,
            connected_routers,
            DiscoveryHooks::new(&registry, role),
        )
        .await;
    }
    if members.is_empty() {
        return Err(DaemonError::Config("discovery group has no sockets".into()));
    }
    let mut children = tokio::task::JoinSet::new();
    let mut stops = Vec::new();
    for (fsm, socket) in members {
        let (stop, rx) = mpsc::channel(1);
        stops.push(stop);
        children.spawn(run_discovery_with_peers(
            fsm,
            socket,
            start.then_some(FsmEvent::AppStartDiscovery),
            rx,
            events_tx.clone(),
            connected_routers.clone(),
            DiscoveryHooks::new(&registry, role),
        ));
    }
    let mut failure = tokio::select! {
        _ = shutdown_rx.recv() => None,
        result = children.join_next() => Some(match result {
            Some(Ok(Err(error))) => error,
            Some(Err(error)) => DaemonError::Config(format!("discovery task failed: {error}")),
            _ => DaemonError::Config("discovery task stopped unexpectedly".into()),
        }),
    };
    drop(stops);
    while let Some(result) = children.join_next().await {
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(error)) => Some(error),
            Err(error) => Some(DaemonError::Config(format!(
                "discovery task failed: {error}"
            ))),
        };
        if failure.is_none() {
            failure = error;
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn run_discovery_io<F: DiscoveryFsm>(
    mut fsm: F,
    socket: impl DiscoveryIo,
    initial_event: Option<FsmEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
    events_tx: EventTx,
    connected_routers: Option<ConnectedRouters>,
    hooks: DiscoveryHooks,
) -> Result<(), DaemonError> {
    let mut timers = DiscoveryTimers::default();
    // Capacity 8 is comfortably above the expected steady-state queue
    // depth: discovery fires at most one timer per period, and the select
    // loop drains expiries promptly.
    let (timer_tx, mut timer_rx) = mpsc::channel::<(TimerId, TimerKind)>(8);
    let mut receive_after = tokio::time::Instant::now();

    if let Some(event) = initial_event {
        let actions = fsm.step(event);
        process_actions(
            actions,
            &socket,
            &events_tx,
            &mut timers,
            &timer_tx,
            PacketContext::default(),
            connected_routers.as_ref(),
            &hooks,
        )
        .await?;
    }

    loop {
        tokio::select! {
            res = async {
                // Back off only socket failures, without blocking timers or
                // shutdown while waiting to retry the receive operation.
                tokio::time::sleep_until(receive_after).await;
                socket.recv_with_metadata().await
            } => {
                match res {
                    Ok(ReceivedSignal { signal, from, local_addr, interface_index, .. }) => {
                        // RFC 8175 §7.1: an existing TCP connection suppresses
                        // discovery even before TLS/DLEP initialization finishes.
                        if signal.signal_type == dlep_core::SignalType::PEER_DISCOVERY
                            && connected_routers.as_ref().is_some_and(|peers| peers.contains(from)) {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        let Some(signal) = hooks.receive(signal, from, local_addr, interface_index, &events_tx) else {
                            tokio::task::yield_now().await;
                            continue;
                        };
                        let actions = fsm.step(FsmEvent::RecvSignal { signal, from });
                        let packet = PacketContext { local: Some(local_addr), interface_index: Some(interface_index), peer: Some(from) };
                        process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, packet, connected_routers.as_ref(), &hooks).await?;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                        // A peer controls its datagram contents. Malformed
                        // packets must not impose a retry delay or warning log
                        // on other peers sharing discovery.
                        debug!("dropping malformed discovery datagram: {e}");
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        warn!("discovery recv error: {e}");
                        receive_after = tokio::time::Instant::now() + Duration::from_millis(100);
                    }
                }
            }
            Some((id, kind)) = timer_rx.recv() => {
                let packet = timers.context(id);
                let event = match packet.peer {
                    Some(peer) if connected_routers.as_ref().is_some_and(|peers| peers.contains(peer)) => {
                        FsmEvent::AppStopDiscoveryOffers { peer }
                    }
                    _ => FsmEvent::TimerExpired(id, kind),
                };
                let actions = fsm.step(event);
                process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, packet, connected_routers.as_ref(), &hooks).await?;
            }
            // Losing the owner is also shutdown; otherwise the receive loop
            // and periodic probe task outlive the last shutdown sender.
            _ = shutdown_rx.recv() => {
                let actions = fsm.step(FsmEvent::AppShutdown {
                    reason: dlep_core::StatusCode::SHUTTING_DOWN,
                });
                process_actions(actions, &socket, &events_tx, &mut timers, &timer_tx, PacketContext::default(), connected_routers.as_ref(), &hooks).await?;
                return Ok(());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_actions(
    actions: Vec<FsmAction>,
    socket: &impl DiscoveryIo,
    events_tx: &EventTx,
    timers: &mut DiscoveryTimers,
    timer_tx: &mpsc::Sender<(TimerId, TimerKind)>,
    packet: PacketContext,
    connected_routers: Option<&ConnectedRouters>,
    hooks: &DiscoveryHooks,
) -> Result<(), DaemonError> {
    let PacketContext {
        local,
        interface_index,
        ..
    } = packet;
    for action in actions {
        match action {
            FsmAction::SendSignal { mut signal, target } => {
                let peer = match &target {
                    SendTarget::DiscoveryGroup => None,
                    SendTarget::Unicast(addr) => Some(*addr),
                };
                if signal.signal_type == dlep_core::SignalType::PEER_OFFER
                    && peer.is_some_and(|addr| {
                        connected_routers.is_some_and(|peers| peers.contains(addr))
                    })
                {
                    continue;
                }
                hooks.send(&mut signal, peer, local, interface_index, events_tx);
                match target {
                    SendTarget::DiscoveryGroup => {
                        if let Err(e) = socket.send_to_group(&signal).await {
                            warn!("discovery send_to_group failed: {e}");
                        }
                    }
                    SendTarget::Unicast(addr) => {
                        // Replace wildcard listeners with the selected ingress
                        // interface's usable unicast address, never a multicast IP.
                        if let Some(local) = local {
                            for item in &mut signal.data_items {
                                match (item, local) {
                                    (
                                        dlep_core::DataItem::Ipv4ConnectionPoint { addr, .. },
                                        std::net::IpAddr::V4(local),
                                    ) if addr.is_unspecified() => *addr = local,
                                    (
                                        dlep_core::DataItem::Ipv6ConnectionPoint { addr, .. },
                                        std::net::IpAddr::V6(local),
                                    ) if addr.is_unspecified() => *addr = local,
                                    _ => {}
                                }
                            }
                        }
                        if let Err(e) = socket.send_unicast(&signal, addr).await {
                            warn!(?addr, "discovery send_unicast failed: {e}");
                        }
                    }
                }
            }
            FsmAction::StartTimer {
                id,
                kind,
                duration,
                periodic,
            } => {
                let tx = timer_tx.clone();
                let handle = if periodic {
                    tokio::spawn(async move {
                        loop {
                            tokio::time::sleep(duration).await;
                            // `send` only fails if the receiver dropped,
                            // which happens when `run_discovery` returns
                            // (timer_rx goes out of scope). At that point
                            // the timer task should exit, not retry.
                            if tx.send((id, kind)).await.is_err() {
                                break;
                            }
                        }
                    })
                } else {
                    tokio::spawn(async move {
                        tokio::time::sleep(duration).await;
                        // Single-shot: ignore send error — same reasoning
                        // as the periodic break above.
                        let _ = tx.send((id, kind)).await;
                    })
                };
                timers.arm(id, handle, packet);
            }
            FsmAction::CancelTimer(id) => timers.cancel(id),
            FsmAction::Emit(emitted) => {
                if let Some(mut evt) = translate(emitted) {
                    if let (DaemonEvent::PeerDiscovered(offer), Some(index)) =
                        (&mut evt, interface_index)
                    {
                        for endpoint in &mut offer.endpoints {
                            if let std::net::SocketAddr::V6(addr) = &mut endpoint.addr {
                                if addr.ip().is_unicast_link_local() {
                                    addr.set_scope_id(index);
                                }
                            }
                        }
                    }
                    let _ = events_tx.send(evt);
                }
            }
            // Session-domain actions (messages, heartbeats, TCP close) and
            // any future action kinds have no meaning on a discovery socket.
            _ => debug!("discovery task received a non-discovery action; ignoring"),
        }
    }
    Ok(())
}

fn translate(emitted: EmittedEvent) -> Option<DaemonEvent> {
    match emitted {
        EmittedEvent::PeerDiscovered {
            endpoints,
            peer_description,
            secured_medium,
        } => Some(DaemonEvent::PeerDiscovered(PeerOffer {
            endpoints,
            peer_description,
            secured_medium,
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlep_core::{DataItem, Signal, SignalType};
    use dlep_fsm::{
        discovery_modem::ModemDiscoveryFsm,
        discovery_router::{RouterDiscoveryConfig, RouterDiscoveryFsm},
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::{Instant, advance, timeout};

    struct GroupObserver {
        sends: Arc<AtomicUsize>,
    }

    /// Router discovery FSM whose start event can fail its whole task.
    struct FailingStart(RouterDiscoveryFsm, bool);
    impl DiscoveryFsm for FailingStart {
        fn step(&mut self, event: FsmEvent) -> Vec<FsmAction> {
            assert!(!self.1, "injected discovery task failure");
            self.0.step(event)
        }
    }
    impl dlep_ext::DlepExtension for GroupObserver {
        fn advertised_ids(&self) -> &[dlep_core::ExtensionId] {
            &[dlep_core::ExtensionId(0xF051)]
        }
        fn supports_discovery(&self) -> bool {
            true
        }
        fn on_discovery_send(&self, _: SignalType, _: &mut dyn dlep_ext::DiscoveryCtx) {
            self.sends.fetch_add(1, Ordering::SeqCst);
        }
    }

    async fn group_lifecycle(panic_once: bool) {
        let config = crate::NetworkConfig {
            interface: Some("dlep-test".into()),
            discovery_dual_stack: true,
            discovery_port: 50091,
            ..Default::default()
        };
        let members: Vec<_> = config
            .bind_discoveries(false)
            .unwrap()
            .into_iter()
            .enumerate()
            .map(|(index, socket)| (FailingStart(router(), panic_once && index == 0), socket))
            .collect();
        let ports: Vec<_> = members
            .iter()
            .map(|(_, socket)| socket.local_port())
            .collect();
        let count = Arc::new(AtomicUsize::new(0));
        let mut registry = dlep_ext::ExtensionRegistry::new();
        registry.register(Arc::new(GroupObserver {
            sends: count.clone(),
        }));
        let (_stop, rx) = mpsc::channel(1);
        let (events, mut received) = crate::runtime::new_event_channel();
        let task = tokio::spawn(run_supervised_discovery_group(
            members,
            true,
            rx,
            events,
            None,
            registry,
            dlep_ext::Role::Router,
        ));
        if panic_once {
            assert!(
                timeout(Duration::from_secs(2), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert!(matches!(
                received.try_recv(),
                Ok(crate::DaemonEvent::DiscoveryStopped { error })
                    if error.contains("discovery task failed")
            ));
        } else {
            timeout(Duration::from_secs(2), async {
                while count.load(Ordering::SeqCst) < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        }
        settle().await;
        let _v4 = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, ports[0]))
            .expect("IPv4 discovery socket leaked");
        let _v6 = std::net::UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, ports[1]))
            .expect("IPv6 discovery socket leaked");
        let stopped = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            stopped,
            "discovery child or timer outlived the group"
        );
    }

    #[tokio::test]
    async fn cancelling_dual_discovery_releases_both_sockets_and_timers() {
        group_lifecycle(false).await;
    }
    #[tokio::test]
    async fn failing_discovery_child_stops_the_complete_group() {
        group_lifecycle(true).await;
    }

    struct ScriptedIo {
        input: tokio::sync::Mutex<mpsc::UnboundedReceiver<io::Result<ReceivedSignal>>>,
        observed: Arc<Observed>,
    }

    #[derive(Default)]
    struct Observed {
        sends: Mutex<Vec<(Instant, SendTarget, Signal)>>,
        failures: Mutex<usize>,
        receives: AtomicUsize,
    }

    impl ScriptedIo {
        fn new(
            failures: usize,
        ) -> (
            Self,
            mpsc::UnboundedSender<io::Result<ReceivedSignal>>,
            Arc<Observed>,
        ) {
            let (input, rx) = mpsc::unbounded_channel();
            let observed = Arc::new(Observed::default());
            *observed.failures.lock().unwrap() = failures;
            (
                Self {
                    input: tokio::sync::Mutex::new(rx),
                    observed: observed.clone(),
                },
                input,
                observed,
            )
        }

        fn send(&self, signal: &Signal, target: SendTarget) -> io::Result<()> {
            self.observed
                .sends
                .lock()
                .unwrap()
                .push((Instant::now(), target, signal.clone()));
            let mut failures = self.observed.failures.lock().unwrap();
            if *failures > 0 {
                *failures -= 1;
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
    }

    impl DiscoveryIo for ScriptedIo {
        async fn recv_with_metadata(&self) -> io::Result<ReceivedSignal> {
            let result = self
                .input
                .lock()
                .await
                .recv()
                .await
                .expect("input stays open until shutdown");
            self.observed.receives.fetch_add(1, Ordering::SeqCst);
            result
        }

        async fn send_to_group(&self, signal: &Signal) -> io::Result<()> {
            self.send(signal, SendTarget::DiscoveryGroup)
        }

        async fn send_unicast(&self, signal: &Signal, dest: SocketAddr) -> io::Result<()> {
            self.send(signal, SendTarget::Unicast(dest))
        }
    }

    fn router() -> RouterDiscoveryFsm {
        RouterDiscoveryFsm::with_config(RouterDiscoveryConfig {
            discovery_interval: Duration::from_secs(1),
            ..Default::default()
        })
    }

    fn incoming(kind: SignalType, from: &str) -> io::Result<ReceivedSignal> {
        Ok(ReceivedSignal {
            signal: Signal::new(kind),
            from: from.parse().unwrap(),
            ttl: 255,
            local_addr: "192.0.2.10".parse().unwrap(),
            interface_index: 7,
        })
    }

    async fn settle() {
        // Keep virtual time under test control while runtime/timer tasks poll.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    async fn tick(ms: u64) {
        advance(Duration::from_millis(ms)).await;
        settle().await;
    }

    #[tokio::test(start_paused = true)]
    async fn connected_router_cancels_offer_retries_before_hooks_and_requires_a_fresh_probe() {
        // The first send fails at the socket, but still consumes one attempt.
        let (socket, input, observed) = ScriptedIo::new(1);
        let (stop, rx) = mpsc::channel(1);
        let (events, _) = crate::runtime::new_event_channel();
        let peers = ConnectedRouters::default();
        let count = Arc::new(AtomicUsize::new(0));
        let mut registry = dlep_ext::ExtensionRegistry::new();
        registry.register(Arc::new(GroupObserver {
            sends: count.clone(),
        }));
        let fsm = ModemDiscoveryFsm::new("0.0.0.0:854".parse().unwrap(), "modem".into(), true)
            .with_offer_retries(2, Duration::from_secs(1))
            .unwrap();
        let task = tokio::spawn(run_discovery_io(
            fsm,
            socket,
            None,
            rx,
            events,
            Some(peers.clone()),
            DiscoveryHooks::new(&registry, dlep_ext::Role::Modem),
        ));
        input
            .send(incoming(SignalType::PEER_DISCOVERY, "192.0.2.1:1000"))
            .unwrap();
        settle().await;
        assert_eq!(observed.sends.lock().unwrap().len(), 1);
        // Retry once after the initial OS send failure.
        tick(1000).await;
        assert_eq!(observed.sends.lock().unwrap().len(), 2);
        let accepted = peers.register("192.0.2.1:9999".parse().unwrap());
        tick(1000).await;
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert_eq!(observed.sends.lock().unwrap().len(), 2);
        drop(accepted);
        tick(2000).await;
        assert_eq!(observed.sends.lock().unwrap().len(), 2);
        input
            .send(incoming(SignalType::PEER_DISCOVERY, "192.0.2.1:1000"))
            .unwrap();
        settle().await;
        assert_eq!(observed.sends.lock().unwrap().len(), 3);
        stop.send(()).await.unwrap();
        task.await.unwrap().unwrap();
        tick(3000).await;
        assert_eq!(count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn multicast_send_failures_preserve_periodic_retry_and_offer_delivery() {
        let (socket, input, observed) = ScriptedIo::new(2);
        let (stop, rx) = mpsc::channel(1);
        let (events, mut received) = crate::runtime::new_event_channel();
        let start = Instant::now();
        let task = tokio::spawn(run_discovery_io(
            router(),
            socket,
            Some(FsmEvent::AppStartDiscovery),
            rx,
            events,
            None,
            DiscoveryHooks::default(),
        ));
        settle().await;
        assert_eq!(observed.sends.lock().unwrap().len(), 1);
        for _ in 0..2 {
            // Receiving offers remains possible even when probes fail to send.
            input
                .send(incoming(SignalType::PEER_OFFER, "192.0.2.1:12345"))
                .unwrap();
            settle().await;
            let DaemonEvent::PeerDiscovered(offer) = received.try_recv().unwrap() else {
                panic!("expected offer")
            };
            assert_eq!(offer.endpoints[0].addr, "192.0.2.1:854".parse().unwrap());
            tick(1000).await;
        }
        assert_eq!(*observed.failures.lock().unwrap(), 0);
        {
            let sends = observed.sends.lock().unwrap();
            assert_eq!(sends.len(), 3);
            for (i, (at, target, signal)) in sends.iter().enumerate() {
                assert_eq!(*at - start, Duration::from_secs(i as u64));
                assert!(matches!(target, SendTarget::DiscoveryGroup));
                assert_eq!(signal.signal_type, SignalType::PEER_DISCOVERY);
            }
        }
        stop.send(()).await.unwrap();
        timeout(Duration::from_millis(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(input.is_closed());
        tick(2000).await;
        assert_eq!(observed.sends.lock().unwrap().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn failed_unicast_offer_does_not_block_other_peers_or_retries() {
        let (socket, input, observed) = ScriptedIo::new(1);
        let (stop, rx) = mpsc::channel(1);
        let (events, _) = crate::runtime::new_event_channel();
        let modem = ModemDiscoveryFsm::new("0.0.0.0:854".parse().unwrap(), "test".into(), false);
        let task = tokio::spawn(run_discovery_io(
            modem,
            socket,
            None,
            rx,
            events,
            None,
            DiscoveryHooks::default(),
        ));
        for peer in ["192.0.2.1:10001", "192.0.2.2:10002", "192.0.2.1:10001"] {
            input
                .send(incoming(SignalType::PEER_DISCOVERY, peer))
                .unwrap();
            settle().await;
        }
        {
            let sends = observed.sends.lock().unwrap();
            assert_eq!(sends.len(), 3);
            for ((_, target, signal), peer) in
                sends
                    .iter()
                    .zip(["192.0.2.1:10001", "192.0.2.2:10002", "192.0.2.1:10001"])
            {
                assert!(
                    matches!(target, SendTarget::Unicast(addr) if *addr == peer.parse::<SocketAddr>().unwrap())
                );
                assert_eq!(signal.signal_type, SignalType::PEER_OFFER);
                assert!(signal.data_items.iter().any(|item| matches!(item,
                    DataItem::Ipv4ConnectionPoint { addr, .. } if *addr == "192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap())));
            }
        }
        stop.send(()).await.unwrap();
        timeout(Duration::from_millis(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn receive_errors_back_off_without_delaying_probes_or_recovery() {
        let (socket, input, observed) = ScriptedIo::new(0);
        for _ in 0..11 {
            input
                .send(Err(io::Error::from(io::ErrorKind::ConnectionRefused)))
                .unwrap();
        }
        input
            .send(incoming(SignalType::PEER_OFFER, "192.0.2.1:854"))
            .unwrap();
        let (stop, rx) = mpsc::channel(1);
        let (events, mut received) = crate::runtime::new_event_channel();
        let task = tokio::spawn(run_discovery_io(
            router(),
            socket,
            Some(FsmEvent::AppStartDiscovery),
            rx,
            events,
            None,
            DiscoveryHooks::default(),
        ));
        settle().await;
        assert_eq!(observed.receives.load(Ordering::SeqCst), 1);
        for retries in 1..=11 {
            tick(99).await;
            assert_eq!(observed.receives.load(Ordering::SeqCst), retries);
            assert!(received.try_recv().is_err());
            tick(1).await;
            assert_eq!(observed.receives.load(Ordering::SeqCst), retries + 1);
        }
        assert!(matches!(
            received.try_recv().unwrap(),
            DaemonEvent::PeerDiscovered(_)
        ));
        {
            let sends = observed.sends.lock().unwrap();
            assert_eq!(sends.len(), 2);
            assert_eq!(sends[1].0 - sends[0].0, Duration::from_secs(1));
        }
        input
            .send(incoming(SignalType::PEER_OFFER, "192.0.2.2:854"))
            .unwrap();
        settle().await;
        assert!(matches!(
            received.try_recv().unwrap(),
            DaemonEvent::PeerDiscovered(_)
        ));
        stop.send(()).await.unwrap();
        timeout(Duration::from_millis(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_receive_backoff_handles_message_and_sender_drop() {
        for drop_sender in [false, true] {
            let (socket, input, observed) = ScriptedIo::new(0);
            input
                .send(Err(io::Error::from(io::ErrorKind::ConnectionRefused)))
                .unwrap();
            let (stop, rx) = mpsc::channel(1);
            let (events, _) = crate::runtime::new_event_channel();
            let task = tokio::spawn(run_discovery_io(
                router(),
                socket,
                Some(FsmEvent::AppStartDiscovery),
                rx,
                events,
                None,
                DiscoveryHooks::default(),
            ));
            settle().await;
            assert_eq!(observed.receives.load(Ordering::SeqCst), 1);
            let now = Instant::now();
            if !drop_sender {
                stop.send(()).await.unwrap();
            }
            drop(stop);
            timeout(Duration::from_millis(1), task)
                .await
                .expect("shutdown must interrupt receive backoff")
                .unwrap()
                .unwrap();
            assert_eq!(Instant::now(), now);
            assert!(input.is_closed());
            tick(2000).await;
            assert_eq!(observed.sends.lock().unwrap().len(), 1);
        }
    }
}
