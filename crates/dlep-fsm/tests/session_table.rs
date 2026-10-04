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
    if matches!(
        state,
        RouterSessionState::InSession | RouterSessionState::Terminating
    ) {
        fsm.step(FsmEvent::TcpConnected);
        fsm.step(FsmEvent::RecvMessage(make_init_response(
            StatusCode::SUCCESS,
        )));
    }
    fsm.state = state;
    fsm
}

fn modem_at(state: ModemSessionState) -> ModemSessionFsm {
    let mut fsm = ModemSessionFsm::with_config(dlep_fsm::SessionConfig {
        initial_metrics: sample_metrics_dest(),
        ..Default::default()
    });
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
        .with_item(DataItem::Resources(100))
        .with_item(DataItem::RelativeLinkQualityReceive(100))
        .with_item(DataItem::RelativeLinkQualityTransmit(100))
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
        resources: Some(90),
        rlq_rx: Some(100),
        rlq_tx: Some(100),
        mtu: Some(1500),
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
    for status in [StatusCode::REQUEST_DENIED, StatusCode::INVALID_DATA] {
        let mut fsm = router_at(RouterSessionState::SessionInitPending);
        let actions = fsm.step(FsmEvent::RecvMessage(make_init_response(status)));
        assert_eq!(fsm.state(), RouterSessionState::Terminating);
        let msg = find_sent(&actions, MessageType::SESSION_TERMINATION);
        assert!(has_status(
            msg,
            if status == StatusCode::REQUEST_DENIED {
                StatusCode::UNEXPECTED_MESSAGE
            } else {
                status
            }
        ));
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
    assert_eq!(fsm.state(), RouterSessionState::Terminating);
    assert!(has_status(
        find_sent(&actions, MessageType::SESSION_TERMINATION),
        StatusCode::UNEXPECTED_MESSAGE
    ));
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
    // Per RFC 8175 §7.3.1 the missed-deadline is rearmed at 2 × peer interval.
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
    // RFC 8175 §12.6: response carries Status, Heartbeat, PeerType,
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
        FsmAction::Emit(EmittedEvent::SessionDown(StatusCode::UNEXPECTED_MESSAGE))
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
fn router_rejects_initialization_without_heartbeat() {
    let mut fsm = router_at(RouterSessionState::SessionInitPending);
    let mut msg = make_init_response(StatusCode::SUCCESS);
    msg.data_items
        .retain(|i| !matches!(i, DataItem::HeartbeatInterval(_)));
    let actions = fsm.step(FsmEvent::RecvMessage(msg));
    assert_eq!(fsm.state(), RouterSessionState::Terminating);
    assert!(has_status(
        find_sent(&actions, MessageType::SESSION_TERMINATION),
        StatusCode::INVALID_DATA
    ));
}

#[test]
fn modem_rejects_initialization_without_heartbeat() {
    let mut fsm = modem_at(ModemSessionState::AwaitingSessionInit);
    let mut msg = make_session_init();
    msg.data_items
        .retain(|i| !matches!(i, DataItem::HeartbeatInterval(_)));
    let actions = fsm.step(FsmEvent::RecvMessage(msg));
    assert_eq!(fsm.state(), ModemSessionState::Terminated);
    assert!(actions.iter().any(|a| matches!(a, FsmAction::CloseTcp)));
    assert_eq!(action_count_send_message(&actions), 0);
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
fn modem_in_session_destination_up_response_failure_stops_updates() {
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
        !fsm.destinations[&dest_mac()].announced,
        "non-Success response should stop announcements but retain modem knowledge"
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
    fsm.step(FsmEvent::RecvMessage(make_destination_up_response(
        StatusCode::SUCCESS,
    )));
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
    fsm.step(FsmEvent::RecvMessage(
        dlep_fsm::session_common::build_destination_up(
            dest_mac(),
            &sample_metrics_dest(),
            &DestinationAddrs::default(),
        ),
    ));
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

fn make_destination_down(_reason: StatusCode) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::DESTINATION_DOWN)
        .with_item(DataItem::MacAddress(dest_mac()))
}

#[test]
fn modem_in_session_app_drop_destination_sends_down() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    fsm.destinations.insert(
        dest_mac(),
        dlep_fsm::session_modem::DestinationState {
            announced: true,
            pending_metrics: false,
            metrics: sample_metrics_dest(),
            addrs: DestinationAddrs::default(),
            advertised_addrs: DestinationAddrs::default(),
        },
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
        dlep_fsm::session_modem::DestinationState {
            announced: true,
            pending_metrics: false,
            metrics: sample_metrics_dest(),
            addrs: DestinationAddrs::default(),
            advertised_addrs: DestinationAddrs::default(),
        },
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
        dlep_fsm::session_router::DestinationState {
            addrs: DestinationAddrs::default(),
            up: true,
            metrics: sample_metrics_dest(),
        },
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
            if *mac == dest_mac() && *reason == StatusCode::SUCCESS
    )));
    assert!(!fsm.destinations.contains_key(&dest_mac()));
}

// --- Session Update / Session Update Response (RFC 8175 §12.7-12.8) -------
//
// §12.7: "A Session Update Message MAY be sent by a DLEP participant, on a
// session-wide basis, to indicate local Layer 3 address changes and/or
// metric changes." — so both roles both send and receive it.
// §12.8: "A Session Update Response Message MUST be sent by a DLEP
// participant when a Session Update Message is received."

fn make_session_update(metrics: &LinkMetrics) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::SESSION_UPDATE)
        .with_item(DataItem::MaxDataRateReceive(metrics.max_data_rate_rx_bps))
        .with_item(DataItem::MaxDataRateTransmit(metrics.max_data_rate_tx_bps))
        .with_item(DataItem::CurrentDataRateReceive(
            metrics.current_data_rate_rx_bps,
        ))
        .with_item(DataItem::CurrentDataRateTransmit(
            metrics.current_data_rate_tx_bps,
        ))
        .with_item(DataItem::Latency(metrics.latency))
        .with_item(DataItem::Resources(metrics.resources.unwrap()))
        .with_item(DataItem::RelativeLinkQualityReceive(
            metrics.rlq_rx.unwrap(),
        ))
        .with_item(DataItem::RelativeLinkQualityTransmit(
            metrics.rlq_tx.unwrap(),
        ))
        .with_item(DataItem::Mtu(metrics.mtu.unwrap()))
}

/// Pull the first `SendMessage` of the given type out of an action batch.
fn find_sent(actions: &[FsmAction], ty: MessageType) -> &dlep_core::Message {
    actions
        .iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(m) if m.message_type == ty => Some(m),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected a SendMessage({ty:?}) in {actions:?}"))
}

fn has_status(msg: &dlep_core::Message, want: StatusCode) -> bool {
    msg.data_items
        .iter()
        .any(|i| matches!(i, DataItem::Status { code, .. } if *code == want))
}

#[test]
fn router_in_session_session_update_must_send_response() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_session_update(
        &sample_metrics_dest(),
    )));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    let resp = find_sent(&actions, MessageType::SESSION_UPDATE_RESPONSE);
    assert!(has_status(resp, StatusCode::SUCCESS));
}

#[test]
fn modem_in_session_session_update_must_send_response() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let msg =
        dlep_core::Message::new(MessageType::SESSION_UPDATE).with_item(DataItem::Ipv4Address {
            add: true,
            addr: "192.0.2.1".parse().unwrap(),
        });
    let actions = fsm.step(FsmEvent::RecvMessage(msg));
    assert!(has_status(
        find_sent(&actions, MessageType::SESSION_UPDATE_RESPONSE),
        StatusCode::SUCCESS
    ));
}

#[test]
fn router_in_session_session_update_emits_session_wide_metrics() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_session_update(
        &sample_metrics_dest(),
    )));
    let emitted = actions
        .iter()
        .find_map(|a| match a {
            FsmAction::Emit(EmittedEvent::SessionMetricsUpdate { metrics }) => Some(metrics),
            _ => None,
        })
        .expect("expected Emit(SessionMetricsUpdate)");
    assert_eq!(emitted.current_data_rate_rx_bps, 500_000);
    assert_eq!(emitted.mtu, Some(1500));
}

#[test]
fn router_in_session_session_update_resets_missed_heartbeat_deadline() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_session_update(
        &sample_metrics_dest(),
    )));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, FsmAction::ResetHeartbeat { .. })),
        "RFC 8175 §7.3.1: any received message resets the deadline"
    );
}

#[test]
fn modem_in_session_app_session_update_sends_session_update() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppSessionUpdate {
        metrics: sample_metrics_dest(),
    });
    let sent = find_sent(&actions, MessageType::SESSION_UPDATE);
    let parsed = dlep_fsm::session_common::extract_link_metrics(sent).expect("metrics present");
    assert_eq!(parsed.current_data_rate_tx_bps, 500_000);
}

#[test]
fn router_cannot_originate_session_metrics() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppSessionUpdate {
        metrics: sample_metrics_dest(),
    });
    assert_eq!(action_count_send_message(&actions), 0);
    assert!(!fsm.tx.session_busy());
}

#[test]
fn modem_in_session_session_update_opens_then_closes_session_transaction() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppSessionUpdate {
        metrics: sample_metrics_dest(),
    });
    assert!(
        fsm.tx.session_busy(),
        "outbound Session Update must occupy the session-level transaction slot"
    );
    let _ = fsm.step(FsmEvent::RecvMessage(
        dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
    ));
    assert!(
        !fsm.tx.session_busy(),
        "Session Update Response must free the slot"
    );
}

#[test]
fn modem_in_session_second_app_session_update_is_rejected_while_pending() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let first = fsm.step(FsmEvent::AppSessionUpdate {
        metrics: sample_metrics_dest(),
    });
    assert_eq!(action_count_send_message(&first), 1);
    let second = fsm.step(FsmEvent::AppSessionUpdate {
        metrics: sample_metrics_dest(),
    });
    assert!(
        matches!(second.as_slice(), [FsmAction::Emit(EmittedEvent::CommandRejected(rejection))]
        if rejection.reason == dlep_fsm::CommandError::Busy)
    );
    assert_eq!(
        action_count_send_message(&second),
        0,
        "RFC 8175 allows only one in-flight session-level request"
    );
}

// --- Destination Announce (RFC 8175 §12.13-12.14) -------------------------
//
// §12.13: "Destination Announce Messages MAY be sent by a router" —
// router → modem, never the reverse.
// §12.14: "A modem MUST send a Destination Announce Response Message when a
// Destination Announce Message is received."

fn make_destination_announce(mac: MacAddress) -> dlep_core::Message {
    dlep_core::Message::new(MessageType::DESTINATION_ANNOUNCE).with_item(DataItem::MacAddress(mac))
}

#[test]
fn router_in_session_app_announce_destination_sends_announce() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppAnnounceDestination { mac: dest_mac() });
    let sent = find_sent(&actions, MessageType::DESTINATION_ANNOUNCE);
    assert_eq!(
        dlep_fsm::session_common::extract_destination_mac(sent),
        Some(dest_mac())
    );
}

#[test]
fn modem_in_session_destination_announce_must_send_response() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_destination_announce(dest_mac())));
    assert_eq!(fsm.state(), ModemSessionState::InSession);
    let resp = find_sent(&actions, MessageType::DESTINATION_ANNOUNCE_RESPONSE);
    assert_eq!(
        dlep_fsm::session_common::extract_destination_mac(resp),
        Some(dest_mac())
    );
    assert!(has_status(resp, StatusCode::REQUEST_DENIED));
}

#[test]
fn modem_in_session_destination_announce_emits_announced() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_destination_announce(dest_mac())));
    assert!(actions.iter().any(|a| matches!(
        a,
        FsmAction::Emit(EmittedEvent::DestinationAnnounced { mac, .. }) if *mac == dest_mac()
    )));
}

#[test]
fn router_in_session_announce_opens_then_closes_destination_transaction() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let _ = fsm.step(FsmEvent::AppAnnounceDestination { mac: dest_mac() });
    assert!(fsm.tx.destination_busy(&dest_mac()));
    let resp = dlep_core::Message::new(MessageType::DESTINATION_ANNOUNCE_RESPONSE)
        .with_item(DataItem::MacAddress(dest_mac()))
        .with_item(DataItem::Status {
            code: StatusCode::SUCCESS,
            text: String::new(),
        });
    let _ = fsm.step(FsmEvent::RecvMessage(resp));
    assert!(
        !fsm.tx.destination_busy(&dest_mac()),
        "Destination Announce Response must free the per-destination slot"
    );
}

#[test]
fn modem_rejects_destination_announce_without_mac() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(
        MessageType::DESTINATION_ANNOUNCE,
    )));
    assert_eq!(fsm.state(), ModemSessionState::Terminating);
    assert!(has_status(
        find_sent(&actions, MessageType::SESSION_TERMINATION),
        StatusCode::INVALID_DATA
    ));
}

#[test]
fn every_termination_path_uses_four_local_heartbeats_or_explicit_override() {
    use dlep_fsm::SessionConfig;
    for (heartbeat, explicit, expected_ms) in [
        (60_000, None, 240_000_u64),
        (2_500, None, 10_000),
        (0, None, 4_000), // Direct FSM callers get the advertised minimum.
        (u32::MAX, None, u64::from(u32::MAX) * 4),
        (60_000, Some(Duration::from_millis(500)), 500),
    ] {
        let events: [fn() -> FsmEvent; 3] = [
            || FsmEvent::AppShutdown {
                reason: StatusCode::SHUTTING_DOWN,
            },
            || FsmEvent::TimerExpired(TIMER_HEARTBEAT_MISSED, TimerKind::HeartbeatMissed),
            || FsmEvent::ProtocolError(StatusCode::INVALID_DATA),
        ];
        for event in events {
            let config = SessionConfig {
                heartbeat_interval_ms: heartbeat,
                termination_timeout: explicit,
                ..Default::default()
            };
            let mut router = RouterSessionFsm::with_config(config.clone());
            router.state = RouterSessionState::InSession;
            let mut modem = ModemSessionFsm::with_config(config);
            modem.state = ModemSessionState::InSession;
            for actions in [router.step(event()), modem.step(event())] {
                assert!(actions.iter().any(|action| matches!(action,
                    FsmAction::StartTimer { kind: TimerKind::Termination, duration, periodic: false, .. }
                    if *duration == Duration::from_millis(expected_ms)
                )), "missing expected termination deadline: {actions:?}");
            }
        }
    }
}

// --- Extensions Supported in Session Initialization (RFC 8175 §12.5) -------

fn router_session_init(config: dlep_fsm::SessionConfig) -> dlep_core::Message {
    let mut fsm = RouterSessionFsm::with_config(config);
    fsm.step(FsmEvent::TcpConnected)
        .into_iter()
        .find_map(|a| match a {
            FsmAction::SendMessage(msg)
                if msg.message_type == MessageType::SESSION_INITIALIZATION =>
            {
                Some(msg)
            }
            _ => None,
        })
        .expect("expected SendMessage(Session Initialization)")
}

fn extensions_supported(msg: &dlep_core::Message) -> Option<&Vec<dlep_core::ExtensionId>> {
    msg.data_items.iter().find_map(|item| match item {
        DataItem::ExtensionsSupported(ids) => Some(ids),
        _ => None,
    })
}

/// An absent item is how §12.5 says "no extensions"; an empty one is refused
/// by stricter peers (OONF's dlep_radio resets the session over it).
#[test]
fn router_session_init_omits_extensions_supported_when_none_are_advertised() {
    let msg = router_session_init(dlep_fsm::SessionConfig::default());
    assert_eq!(extensions_supported(&msg), None);
}

#[test]
fn router_session_init_lists_the_extensions_it_advertises() {
    let ids = vec![dlep_core::ExtensionId(1)];
    let msg = router_session_init(dlep_fsm::SessionConfig {
        advertised_extensions: ids.clone(),
        ..Default::default()
    });
    assert_eq!(extensions_supported(&msg), Some(&ids));
}
