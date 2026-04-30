//! Table-driven tests for the router and modem session FSMs (RFC 8175 §7.1, §7.2).
//!
//! Each test pins one row of the state-transition tables in
//! `~/.claude/plans/what-s-the-plan-to-polished-unicorn.md` (M3 section).
//! Tests are pure — no I/O, no Tokio — and assert (a) the post-`step` state
//! and (b) the `Vec<FsmAction>` pattern. `FsmAction` does not derive
//! `PartialEq` (its `Message` payload carries heap-backed fields), so matches
//! use `matches!` and explicit destructuring.

use dlep_core::{DataItem, MessageType, StatusCode};
use dlep_fsm::events::{EmittedEvent, FsmAction, FsmEvent};
use dlep_fsm::session_modem::{ModemSessionFsm, ModemSessionState};
use dlep_fsm::session_router::{
    RouterSessionFsm, RouterSessionState, TIMER_SESSION_INIT, TIMER_TERMINATION,
};
use dlep_fsm::timers::TimerKind;

// --- Small helpers ---------------------------------------------------------

fn router_at(state: RouterSessionState) -> RouterSessionFsm {
    let mut fsm = RouterSessionFsm::new();
    fsm.state = state;
    fsm
}

fn modem_at(state: ModemSessionState) -> ModemSessionFsm {
    let mut fsm = ModemSessionFsm::new();
    fsm.state = state;
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
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
    assert!(matches!(actions[1], FsmAction::ResetHeartbeat));
    assert!(matches!(
        actions[2],
        FsmAction::Emit(EmittedEvent::SessionUp)
    ));
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
        FsmAction::Emit(EmittedEvent::SessionUp)
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

#[test]
fn router_in_session_heartbeat_resets_heartbeat() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::RecvMessage(make_simple(MessageType::HEARTBEAT)));
    assert_eq!(fsm.state(), RouterSessionState::InSession);
    assert!(matches!(actions[0], FsmAction::ResetHeartbeat));
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
    match &actions[0] {
        FsmAction::SendMessage(msg) => {
            assert_eq!(msg.message_type, MessageType::SESSION_TERMINATION);
        }
        other => panic!("expected SendMessage(SessionTermination), got {other:?}"),
    }
    match &actions[1] {
        FsmAction::StartTimer { kind, id, .. } => {
            assert_eq!(*kind, TimerKind::Termination);
            assert_eq!(*id, TIMER_TERMINATION);
        }
        other => panic!("expected StartTimer(Termination), got {other:?}"),
    }
}

#[test]
fn router_in_session_to_terminated_on_tcp_closed() {
    let mut fsm = router_at(RouterSessionState::InSession);
    let actions = fsm.step(FsmEvent::TcpClosed);
    assert_eq!(fsm.state(), RouterSessionState::Terminated);
    assert!(matches!(
        actions[0],
        FsmAction::Emit(EmittedEvent::SessionDown(_))
    ));
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
    // Expect: CancelTimer(SessionInit), SendMessage(InitResponse), ResetHeartbeat, Emit(SessionUp).
    assert!(matches!(
        actions[0],
        FsmAction::CancelTimer(TIMER_SESSION_INIT)
    ));
    match &actions[1] {
        FsmAction::SendMessage(msg) => {
            assert_eq!(
                msg.message_type,
                MessageType::SESSION_INITIALIZATION_RESPONSE
            );
            // RFC 8175 §11.2: response carries Status, Heartbeat, PeerType,
            // ExtensionsSupported, MTU, MaxDR Rx/Tx, CurDR Rx/Tx, Latency,
            // Resources, RLQ Rx/Tx — at least 13 items.
            assert!(msg.data_items.len() >= 13);
        }
        other => panic!("expected SendMessage(InitResponse), got {other:?}"),
    }
    assert!(matches!(actions[2], FsmAction::ResetHeartbeat));
    assert!(matches!(
        actions[3],
        FsmAction::Emit(EmittedEvent::SessionUp)
    ));
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

#[test]
fn modem_in_session_to_terminating_on_app_shutdown() {
    let mut fsm = modem_at(ModemSessionState::InSession);
    let actions = fsm.step(FsmEvent::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    assert_eq!(fsm.state(), ModemSessionState::Terminating);
    match &actions[0] {
        FsmAction::SendMessage(msg) => {
            assert_eq!(msg.message_type, MessageType::SESSION_TERMINATION);
        }
        other => panic!("expected SendMessage(SessionTermination), got {other:?}"),
    }
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
