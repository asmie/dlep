//! Table-driven tests for the router and modem session FSMs (RFC 8175 §7.1, §7.2).
//!
//! Each test pins one row of the state-transition tables in
//! `~/.claude/plans/what-s-the-plan-to-polished-unicorn.md` (M3 section).
//! Tests are pure — no I/O, no Tokio — and assert (a) the post-`step` state
//! and (b) the `Vec<FsmAction>` pattern. `FsmAction` does not derive
//! `PartialEq` (its `Message` payload carries heap-backed fields), so matches
//! use `matches!` and explicit destructuring.

use std::time::Duration;

use dlep_core::{DataItem, MacAddress, MessageType, StatusCode};
use dlep_fsm::events::{DestinationAddrs, EmittedEvent, FsmAction, FsmEvent, LinkMetrics};
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{
    RouterSessionFsm, RouterSessionState, TIMER_HEARTBEAT, TIMER_HEARTBEAT_MISSED,
    TIMER_SESSION_INIT, TIMER_TERMINATION,
};
use dlep_fsm::timers::TimerKind;

// --- Small helpers ---------------------------------------------------------

/// Default peer heartbeat interval used when a test puts the FSM into a
/// post-InSession state via the state setter (bypassing the natural
/// `SessionInitPending → InSession` transition that would have populated
/// `peer_heartbeat_interval` from the inbound Session Init Response).
const DEFAULT_PEER_HEARTBEAT: Duration = Duration::from_millis(60_000);

fn router_at(state: RouterSessionState) -> RouterSessionFsm {
    let mut fsm = RouterSessionFsm::new();
    fsm.state = state;
    if matches!(
        state,
        RouterSessionState::InSession | RouterSessionState::Terminating
    ) {
        fsm.peer_heartbeat_interval = Some(DEFAULT_PEER_HEARTBEAT);
    }
    fsm
}

fn modem_at(state: ModemSessionState) -> ModemSessionFsm {
    let mut fsm = ModemSessionFsm::new();
    fsm.state = state;
    if matches!(
        state,
        ModemSessionState::InSession | ModemSessionState::Terminating
    ) {
        fsm.peer_heartbeat_interval = Some(DEFAULT_PEER_HEARTBEAT);
    }
    fsm
}

fn make_init_response(status: StatusCode) -> dlep_core::Message {
    use std::time::Duration;
    dlep_core::Message::new(MessageType::SESSION_INITIALIZATION_RESPONSE)
        .with_item(DataItem::Status {
            code: status,
            text: String::new(),
        })
        .with_item(DataItem::HeartbeatInterval(Duration::from_millis(60_000)))
        .with_item(DataItem::PeerType {
            flags: dlep_core::data_item::PeerFlags::default(),
            description: "test-peer".into(),
        })
        .with_item(DataItem::ExtensionsSupported(Vec::new()))
        .with_item(DataItem::Mtu(1500))
        .with_item(DataItem::MaxDataRateReceive(1_000_000))
        .with_item(DataItem::MaxDataRateTransmit(1_000_000))
        .with_item(DataItem::CurrentDataRateReceive(1_000_000))
        .with_item(DataItem::CurrentDataRateTransmit(1_000_000))
        .with_item(DataItem::Latency(Duration::from_micros(0)))
}

fn make_session_init() -> dlep_core::Message {
    use std::time::Duration;
    dlep_core::Message::new(MessageType::SESSION_INITIALIZATION)
        .with_item(DataItem::HeartbeatInterval(Duration::from_millis(60_000)))
        .with_item(DataItem::PeerType {
            flags: dlep_core::data_item::PeerFlags::default(),
            description: "test-router".into(),
        })
        .with_item(DataItem::ExtensionsSupported(Vec::new()))
}

fn make_simple(ty: MessageType) -> dlep_core::Message {
    dlep_core::Message::new(ty)
}

fn make_termination(reason: StatusCode) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::SESSION_TERMINATION).with_item(DataItem::Status {
        code: reason,
        text: String::new(),
    })
}

fn sample_metrics_dest() -> LinkMetrics {
    LinkMetrics {
        max_data_rate_rx_bps: 1_000_000,
        max_data_rate_tx_bps: 1_000_000,
        current_data_rate_rx_bps: 500_000,
        current_data_rate_tx_bps: 500_000,
        latency: std::time::Duration::from_micros(1_000),
        resources: 90,
        rlq_rx: 100,
        rlq_tx: 100,
        mtu: 1500,
    }
}

fn dest_mac() -> MacAddress {
    MacAddress::new_eui48([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01])
}

/// Find the first action matching the given predicate. Used because the
/// action vector typically contains a fixed-size handful and order is
/// important for some assertions but not all.
fn action_count_send_message(actions: &[FsmAction]) -> usize {
    actions
        .iter()
        .filter(|a| matches!(a, FsmAction::SendMessage(_)))
        .count()
}

// --- Router transitions ----------------------------------------------------

#[test]
fn router_closed_to_session_init_pending_on_tcp_connected() {
    let mut fsm = RouterSessionFsm::new();
    let actions = fsm.step(FsmEvent::TcpConnected);
    assert_eq!(fsm.state(), RouterSessionState::SessionInitPending);
    // Expect: SendMessage(Session Init), StartTimer(SessionInit).
    assert_eq!(actions.len(), 2);
    match &actions[0] {
        FsmAction::SendMessage(msg) => {
            assert_eq!(msg.message_type, MessageType::SESSION_INITIALIZATION);
        }
        other => panic!("expected SendMessage, got {other:?}"),
    }
    match &actions[1] {
        FsmAction::StartTimer { kind, id, .. } => {
            assert_eq!(*kind, TimerKind::SessionInit);
            assert_eq!(*id, TIMER_SESSION_INIT);
        }
        other => panic!("expected StartTimer, got {other:?}"),
    }
}

#[test]
fn router_closed_to_terminated_on_app_shutdown() {
    let mut fsm = RouterSessionFsm::new();
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(actions.is_empty());
}

#[test]
fn router_closed_to_terminated_on_tcp_closed() {
    let mut fsm = RouterSessionFsm::new();
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(actions.is_empty());
}

#[test]
fn router_session_init_pending_to_in_session_on_success_response() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::RecvMessage(make_init_response(
        StatusCode::SUCCESS,
    )));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    // Predicate-based so M5 additions to InSession entry don't break the test.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_SESSION_INIT)))
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Heartbeat,
            periodic: true,
            ..
        }
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::SessionUp { .. })))
    );
    assert_eq!(
        fsm.peer_heartbeat_interval,
        Some(Duration::from_millis(60_000))
    );
}

#[test]
fn router_session_init_pending_to_terminated_on_terminate_status() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::RecvMessage(make_init_response(
        StatusCode::REQUEST_DENIED, // 2 — continue category... we want a terminate
    )));
    // REQUEST_DENIED is a Continue code; FSM stays InSession. Re-test with a Terminate code.
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    assert!(matches!(
        actions.last().unwrap(),
        FsmAction::Emit(EmittedEvent::SessionUp { .. })
    ));

    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::RecvMessage(make_init_response(
        StatusCode::INVALID_DATA, // 130 — terminate category
    )));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
    assert!(matches!(actions[1], FsmAction::CloseTcp));
    match &actions[2] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::INVALID_DATA);
        }
        other => panic!("expected SessionDown(InvalidData), got {other:?}"),
    }
}

#[test]
fn router_session_init_pending_to_terminated_on_session_init_timer() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_SESSION_INIT,
        TimerKind::SessionInit,
    ));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(actions[0], FsmAction::CloseTcp));
    match &actions[1] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::TIMED_OUT);
        }
        other => panic!("expected SessionDown(TimedOut), got {other:?}"),
    }
}

#[test]
fn router_session_init_pending_to_terminated_on_tcp_closed() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::Emit(EmittedEvent::SessionDown(_))
    ));
}

#[test]
fn router_session_init_pending_to_terminated_on_app_shutdown() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
    assert!(matches!(actions[1], FsmAction::CloseTcp));
    match &actions[2] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::SHUTTING_DOWN);
        }
        other => panic!("expected SessionDown(SHUTTING_DOWN), got {other:?}"),
    }
}

/// Symmetric to the modem-side rule (RFC 8175 §7.2): a router awaiting
/// Session Initialization Response that receives any other message type
/// drops the connection rather than waiting for its session-init timer.
#[test]
fn router_session_init_pending_to_terminated_on_unexpected_message() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_SESSION_INIT)))
    );
    assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
    )));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_))),
        "router MUST NOT send any Message before completing init"
    );
}

#[test]
fn router_in_session_destination_up_responds_and_emits() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let metrics = sample_metrics_dest();
    let up_msg = dlep_fsm::session_common::build_destination_up(
        dest_mac(),
        &metrics,
        &DestinationAddrs::default(),
    );
    let actions = fsm.step(FsmEvent::RecvMessage(up_msg));
    assert_eq!(fsm.state(), RouterSessionState::InSession);

    let resp = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .expect("expected SendMessage(Destination_Up_Response)");
    assert_eq!(resp.message_type, MessageType::DESTINATION_UP_RESPONSE);

    let emitted = actions.iter().find_map(|a| match a {
        FsmAction::Emit(EmittedEvent::DestinationUp { mac, metrics, .. }) => Some((*mac, *metrics)),
        _ => None,
    });
    let (mac, metrics) = emitted.expect("expected Emit(DestinationUp)");
    assert_eq!(mac, dest_mac());
    assert_eq!(metrics.current_data_rate_rx_bps, 500_000);

    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );

    assert!(fsm.destinations.contains_key(&dest_mac()));
    assert!(fsm.destinations[&dest_mac()].up);
}

#[test]
fn router_in_session_heartbeat_resets_heartbeat() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    // Per RFC 8175 §11.2 the missed-deadline is rearmed at 2 × peer interval.
    let expected = DEFAULT_PEER_HEARTBEAT * 2;
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::ResetHeartbeat { missed_deadline, timer_id: _ } if *missed_deadline == expected
    )));
}

#[test]
fn router_in_session_to_terminated_on_peer_termination() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_termination(
        StatusCode::INVALID_DATA,
    )));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    // SendMessage(termination_response), CloseTcp, Emit(SessionDown).
    assert_eq!(action_count_send_message(&actions), 1);
    assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
    )));
}

#[test]
fn router_in_session_to_terminating_on_app_shutdown() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), RouterSessionState::Terminating);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendMessage(msg) if msg.message_type == MessageType::SESSION_TERMINATION
    )));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Termination,
            id: TIMER_TERMINATION,
            ..
        }
    )));
    // M4: heartbeat timers must be cancelled before the Termination handshake.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT)))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED)))
    );
}

#[test]
fn router_in_session_to_terminated_on_tcp_closed() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::SessionDown(_))))
    );
    // M4: heartbeat timers cancelled on transport drop.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT)))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED)))
    );
}

#[test]
fn router_terminating_to_terminated_on_termination_response() {
    let mut fsm = router_at(RouterSessionState::Terminating);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(
        MessageType::SESSION_TERMINATION_RESPONSE,
    )));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_TERMINATION)
    ));
    assert!(matches!(actions[1], FsmAction::CloseTcp));
    match &actions[2] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::SUCCESS);
        }
        other => panic!("expected SessionDown(SUCCESS), got {other:?}"),
    }
}

#[test]
fn router_terminating_to_terminated_on_termination_timer() {
    let mut fsm = router_at(RouterSessionState::Terminating);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_TERMINATION,
        TimerKind::Termination,
    ));
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(actions[0], FsmAction::CloseTcp));
    match &actions[1] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::TIMED_OUT);
        }
        other => panic!("expected SessionDown(TimedOut), got {other:?}"),
    }
}

#[test]
fn router_terminating_to_terminated_on_tcp_closed_treats_as_success() {
    // Plan §"Risks": shutdown ordering — treat transport drop during
    // Terminating as success rather than spurious timeout.
    let mut fsm = router_at(RouterSessionState::Terminating);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_TERMINATION)
    ));
    match &actions[1] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::SUCCESS);
        }
        other => panic!("expected SessionDown(SUCCESS), got {other:?}"),
    }
}

// --- Modem transitions -----------------------------------------------------

#[test]
fn modem_listening_to_awaiting_session_init_on_tcp_accepted() {
    let mut fsm = ModemSessionFsm::new();
    let actions = fsm.step(FsmEvent::TcpAccepted);
    assert_eq!(fsm.state(), ModemSessionState::AwaitingSessionInit);
    match &actions[0] {
        FsmAction::StartTimer { kind, .. } => assert_eq!(*kind, TimerKind::SessionInit),
        other => panic!("expected StartTimer, got {other:?}"),
    }
}

#[test]
fn modem_awaiting_session_init_to_in_session_on_session_init_message() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    let actions = fsm.step(FsmEvent::RecvMessage(make_session_init()));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    // Predicate-based so M5 additions don't break the test.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_SESSION_INIT)))
    );
    let init_response = actions.iter().find_map(|a| match a {
        FsmAction::SendMessage(msg)
            if msg.message_type == MessageType::SESSION_INITIALIZATION_RESPONSE =>
        {
            Some(msg)
        }
        _ => None,
    });
    let init_response = init_response.expect("expected SendMessage(InitResponse)");
    // RFC 8175 §11.2: response carries Status, Heartbeat, PeerType,
    // ExtensionsSupported, MTU, MaxDR Rx/Tx, CurDR Rx/Tx, Latency,
    // Resources, RLQ Rx/Tx — at least 13 items.
    assert!(init_response.data_items.len() >= 13);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Heartbeat,
            periodic: true,
            ..
        }
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::Emit(EmittedEvent::SessionUp { .. })))
    );
    assert_eq!(
        fsm.peer_heartbeat_interval,
        Some(Duration::from_millis(60_000))
    );
}

#[test]
fn modem_awaiting_session_init_to_terminated_on_session_init_timer() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_SESSION_INIT,
        TimerKind::SessionInit,
    ));
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(matches!(actions[0], FsmAction::CloseTcp));
}

#[test]
fn modem_awaiting_session_init_to_terminated_on_tcp_closed() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
}

#[test]
fn modem_awaiting_session_init_to_terminated_on_app_shutdown() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
    assert!(matches!(actions[1], FsmAction::CloseTcp));
    match &actions[2] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::SHUTTING_DOWN);
        }
        other => panic!("expected SessionDown(SHUTTING_DOWN), got {other:?}"),
    }
}

/// RFC 8175 §7.2: a modem in AwaitingSessionInit that receives anything
/// other than Session Initialization MUST close the TCP connection without
/// sending a reply.
#[test]
fn modem_awaiting_session_init_to_terminated_on_unexpected_message() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    // A Heartbeat is one example of an unexpected message in this state.
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_SESSION_INIT)))
    );
    assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
    )));
    // Critical: per RFC, the modem MUST NOT send any Message in this case.
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_))),
        "modem MUST NOT send any Message on non-Init in AwaitingSessionInit"
    );
}

#[test]
fn modem_in_session_to_terminating_on_app_shutdown() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), ModemSessionState::Terminating);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendMessage(msg) if msg.message_type == MessageType::SESSION_TERMINATION
    )));
    // M4: heartbeat timers cancelled.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT)))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT_MISSED)))
    );
}

#[test]
fn modem_in_session_to_terminated_on_peer_termination() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_termination(
        StatusCode::INVALID_DATA,
    )));
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert_eq!(action_count_send_message(&actions), 1);
    assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::INVALID_DATA))
    )));
}

#[test]
fn modem_terminating_to_terminated_on_termination_response() {
    let mut fsm = modem_at(ModemSessionState::Terminating);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(
        MessageType::SESSION_TERMINATION_RESPONSE,
    )));
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_TERMINATION)
    ));
}

#[test]
fn modem_terminating_to_terminated_on_tcp_closed_treats_as_success() {
    let mut fsm = modem_at(ModemSessionState::Terminating);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_TERMINATION)
    ));
    match &actions[1] {
        FsmAction::Emit(EmittedEvent::SessionDown(s)) => {
            assert_eq!(*s, StatusCode::SUCCESS);
        }
        other => panic!("expected SessionDown(SUCCESS), got {other:?}"),
    }
}

// --- M4 transitions (heartbeat send + missed-deadline) ---------------------

#[test]
fn router_in_session_periodic_heartbeat_send() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_HEARTBEAT,
        TimerKind::Heartbeat,
    ));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    let send = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(msg) => Some(msg),
            _ => None,
        })
        .expect("expected SendMessage(Heartbeat)");
    assert_eq!(send.message_type, MessageType::HEARTBEAT);
    assert!(send.data_items.is_empty());
}

#[test]
fn modem_in_session_periodic_heartbeat_send() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_HEARTBEAT,
        TimerKind::Heartbeat,
    ));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    let send = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(msg) => Some(msg),
            _ => None,
        })
        .expect("expected SendMessage(Heartbeat)");
    assert_eq!(send.message_type, MessageType::HEARTBEAT);
}

#[test]
fn router_in_session_to_terminating_on_missed_deadline() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_HEARTBEAT_MISSED,
        TimerKind::HeartbeatMissed,
    ));
    assert_eq!(fsm.state(), RouterSessionState::Terminating);
    // Cancels the periodic send, sends Termination(TIMED_OUT), starts the
    // termination timer.
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT)))
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendMessage(msg) if msg.message_type == MessageType::SESSION_TERMINATION
    )));
    let term = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(msg) if msg.message_type == MessageType::SESSION_TERMINATION => {
                Some(msg)
            }
            _ => None,
        })
        .unwrap();
    let status = term
        .data_items
        .iter()
        .find_map(|d| match d {
            DataItem::Status { code, .. } => Some(*code),
            _ => None,
        })
        .expect("Status mandatory in Session Termination");
    assert_eq!(status, StatusCode::TIMED_OUT);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Termination,
            id: TIMER_TERMINATION,
            ..
        }
    )));
}

#[test]
fn modem_in_session_to_terminating_on_missed_deadline() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_HEARTBEAT_MISSED,
        TimerKind::HeartbeatMissed,
    ));
    assert_eq!(fsm.state(), ModemSessionState::Terminating);
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::CancelTimer(TIMER_HEARTBEAT)))
    );
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::SendMessage(msg) if msg.message_type == MessageType::SESSION_TERMINATION
    )));
}

#[test]
fn router_in_session_missing_peer_interval_skips_reset() {
    // Build the FSM directly into InSession with peer_heartbeat_interval = None
    // (= the field was missing). RecvMessage(Heartbeat) must not emit
    // ResetHeartbeat because there is no peer interval to double.
    let mut fsm = RouterSessionFsm::new();
    fsm.state = RouterSessionState::InSession;
    fsm.peer_heartbeat_interval = None;
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. })),
        "expected no ResetHeartbeat when peer_heartbeat_interval is None"
    );
}

#[test]
fn modem_in_session_missing_peer_interval_skips_reset() {
    let mut fsm = ModemSessionFsm::new();
    fsm.state = ModemSessionState::InSession;
    fsm.peer_heartbeat_interval = None;
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
}

#[test]
fn router_session_init_pending_to_in_session_clamps_local_interval_to_rfc_minimum() {
    use dlep_fsm::SessionConfig;
    let mut fsm = RouterSessionFsm::with_config(SessionConfig {
        heartbeat_interval_ms: 0,
        ..SessionConfig::default()
    });
    fsm.state = RouterSessionState::SessionInitPending;
    let actions = fsm.step(FsmEvent::RecvMessage(make_init_response(
        StatusCode::SUCCESS,
    )));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    // RFC 8175 requires a minimum 1s interval and forbids zero, so local
    // misconfiguration is clamped before advertising/arming.
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Heartbeat,
            duration,
            ..
        } if *duration == Duration::from_millis(1_000)
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
}

#[test]
fn modem_awaiting_session_init_to_in_session_clamps_local_interval_to_rfc_minimum() {
    use dlep_fsm::SessionConfig;
    let mut fsm = ModemSessionFsm::with_config(SessionConfig {
        heartbeat_interval_ms: 0,
        peer_description: "dlep-modem".into(),
        ..SessionConfig::default()
    });
    fsm.state = ModemSessionState::AwaitingSessionInit;
    let actions = fsm.step(FsmEvent::RecvMessage(make_session_init()));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::StartTimer {
            kind: TimerKind::Heartbeat,
            duration,
            ..
        } if *duration == Duration::from_millis(1_000)
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
}

/// Stray Heartbeat tick that lands during `Terminated` (after `CancelTimer`
/// abort but before the in-flight expiry event was drained from the channel)
/// must be silently absorbed by the catch-all rather than panicking on an
/// unmatched arm.
#[test]
fn router_terminated_ignores_stray_heartbeat_timer_expiry() {
    let mut fsm = router_at(RouterSessionState::Terminated);
    let actions = fsm.step(FsmEvent::TimerExpired(
        TIMER_HEARTBEAT,
        TimerKind::Heartbeat,
    ));
    assert!(actions.is_empty());
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
}

#[test]
fn modem_in_session_app_add_destination_sends_up() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    let send = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .expect("expected SendMessage(Destination_Up)");
    assert_eq!(send.message_type, MessageType::DESTINATION_UP);
    assert!(fsm.destinations.contains_key(&dest_mac()));
    assert!(!fsm.destinations[&dest_mac()].announced);
    assert!(fsm.tx.destination_busy(&dest_mac()));
}

#[test]
fn modem_in_session_app_add_destination_dedupes_on_repeat() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });
    let actions = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_))),
        "duplicate add must not emit a second Destination_Up"
    );
}

fn make_destination_up_response(status: StatusCode) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::DESTINATION_UP_RESPONSE)
        .with_item(DataItem::MacAddress(dest_mac()))
        .with_item(DataItem::Status {
            code: status,
            text: String::new(),
        })
}

#[test]
fn modem_in_session_destination_up_response_success_marks_announced() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });
    assert!(fsm.tx.destination_busy(&dest_mac()));

    let actions = fsm.step(FsmEvent::RecvMessage(make_destination_up_response(
        StatusCode::SUCCESS,
    )));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    assert!(!fsm.tx.destination_busy(&dest_mac()), "tx should be closed");
    assert!(
        fsm.destinations[&dest_mac()].announced,
        "announced should flip to true on Success"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
}

#[test]
fn modem_in_session_destination_up_response_failure_drops_local() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });

    let _ = fsm.step(FsmEvent::RecvMessage(make_destination_up_response(
        StatusCode::REQUEST_DENIED,
    )));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    assert!(!fsm.tx.destination_busy(&dest_mac()));
    assert!(
        !fsm.destinations.contains_key(&dest_mac()),
        "non-Success response should drop the local destination"
    );
}

#[test]
fn modem_in_session_app_update_metrics_sends_update() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppAddDestination {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
        addrs: DestinationAddrs::default(),
    });

    let mut new_metrics = sample_metrics_dest();
    new_metrics.current_data_rate_rx_bps = 1_234_567;
    let actions = fsm.step(FsmEvent::AppUpdateMetrics {
        mac: dest_mac(),
        metrics: new_metrics,
    });
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    let send = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .expect("expected SendMessage(Destination_Update)");
    assert_eq!(send.message_type, MessageType::DESTINATION_UPDATE);
}

#[test]
fn modem_in_session_app_update_metrics_ignored_for_unknown_destination() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppUpdateMetrics {
        mac: dest_mac(),
        metrics: sample_metrics_dest(),
    });
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_))),
        "update for unknown MAC must not send a message"
    );
}

#[test]
fn router_in_session_destination_update_emits() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let metrics = sample_metrics_dest();
    let update_msg = dlep_fsm::session_common::build_destination_update(dest_mac(), &metrics);
    let actions = fsm.step(FsmEvent::RecvMessage(update_msg));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::DestinationUpdate { mac, .. }) if *mac == dest_mac()
    )));
    assert!(
        !actions
            .iter()
            .any(|a| matches!(a, FsmAction::SendMessage(_)))
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. }))
    );
}

fn make_destination_down_response(status: StatusCode) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::DESTINATION_DOWN_RESPONSE)
        .with_item(DataItem::MacAddress(dest_mac()))
        .with_item(DataItem::Status {
            code: status,
            text: String::new(),
        })
}

fn make_destination_down(reason: StatusCode) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::DESTINATION_DOWN)
        .with_item(DataItem::MacAddress(dest_mac()))
        .with_item(DataItem::Status {
            code: reason,
            text: String::new(),
        })
}

#[test]
fn modem_in_session_app_drop_destination_sends_down() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    fsm.destinations.insert(
        dest_mac(),
        dlep_fsm::session_modem::DestinationState { announced: true },
    );
    let actions = fsm.step(FsmEvent::AppDropDestination {
        mac: dest_mac(),
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    let send = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .expect("expected SendMessage(Destination_Down)");
    assert_eq!(send.message_type, MessageType::DESTINATION_DOWN);
    assert!(fsm.tx.destination_busy(&dest_mac()));
    // Local entry stays until the response arrives.
    assert!(fsm.destinations.contains_key(&dest_mac()));
}

#[test]
fn modem_in_session_destination_down_response_removes_local() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    fsm.destinations.insert(
        dest_mac(),
        dlep_fsm::session_modem::DestinationState { announced: true },
    );
    let _ = fsm.step(FsmEvent::AppDropDestination {
        mac: dest_mac(),
        reason: StatusCode::SHUTTING_DOWN,
    });

    let _ = fsm.step(FsmEvent::RecvMessage(make_destination_down_response(
        StatusCode::SUCCESS,
    )));
    assert!(!fsm.tx.destination_busy(&dest_mac()));
    assert!(!fsm.destinations.contains_key(&dest_mac()));
}

#[test]
fn router_in_session_destination_down_responds_and_emits() {
    let mut fsm = router_at(RouterSessionState::InSession);
    fsm.destinations.insert(
        dest_mac(),
        dlep_fsm::session_router::DestinationState { up: true },
    );
    let actions = fsm.step(FsmEvent::RecvMessage(make_destination_down(
        StatusCode::SHUTTING_DOWN,
    )));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    let resp = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) => Some(m),
            _ => None,
        })
        .expect("expected SendMessage(Destination_Down_Response)");
    assert_eq!(resp.message_type, MessageType::DESTINATION_DOWN_RESPONSE);
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::DestinationDown { mac, reason })
            if *mac == dest_mac() && *reason == StatusCode::SHUTTING_DOWN
    )));
    assert!(!fsm.destinations.contains_key(&dest_mac()));
}
