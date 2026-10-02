mod common;

use dlep_core::{LinkMetrics, MacAddress, Message, MessageType as M, StatusCode as S};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::RouterSessionFsm;
use dlep_fsm::{CommandError as C, FsmAction as A, FsmEvent as E};

fn mac(n: u8) -> MacAddress {
    MacAddress::new_eui48([2, 0, 0, 0, 0, n])
}
fn sent(actions: &[A], kind: M) -> Message {
    actions
        .iter()
        .find_map(|a| match a {
            A::SendMessage(m) if m.message_type == kind => Some(m.clone()),
            _ => None,
        })
        .expect("wire message")
}
fn sessions() -> (RouterSessionFsm, ModemSessionFsm) {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::new();
    m.step(E::TcpAccepted);
    let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let reply = sent(
        &m.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    r.step(E::RecvMessage(reply));
    (r, m)
}
fn add(n: u8) -> E {
    E::AppAddDestination {
        mac: mac(n),
        metrics: LinkMetrics::default(),
        addrs: Default::default(),
    }
}
fn drop(n: u8) -> E {
    E::AppDropDestination {
        mac: mac(n),
        reason: S::SUCCESS,
    }
}

#[test]
fn busy_drop_is_explicit_retry_succeeds_and_down_updates_cannot_be_lost() {
    let (mut r, mut m) = sessions();
    let up = sent(&m.step(add(1)), M::DESTINATION_UP);
    common::assert_rejected(m.step(drop(1)), C::Busy);
    common::assert_rejected(m.step(add(1)), C::Busy);
    // Different destinations remain independent.
    sent(&m.step(add(2)), M::DESTINATION_UP);
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
    common::assert_rejected(m.step(add(1)), C::AlreadyExists);
    let down = sent(&m.step(drop(1)), M::DESTINATION_DOWN);
    let before = m.destinations[&mac(1)].metrics;
    common::assert_rejected(
        m.step(E::AppUpdateMetrics {
            mac: mac(1),
            metrics: LinkMetrics {
                latency: std::time::Duration::from_secs(1),
                ..Default::default()
            },
        }),
        C::Busy,
    );
    common::assert_rejected(
        m.step(E::AppUpdateAddresses {
            mac: mac(1),
            changes: Default::default(),
        }),
        C::Busy,
    );
    assert_eq!(m.destinations[&mac(1)].metrics, before);
    let ack = sent(&r.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
    m.step(E::RecvMessage(ack));
    common::assert_rejected(m.step(drop(1)), C::UnknownDestination);
    sent(&m.step(add(1)), M::DESTINATION_UP);
}

#[test]
fn announce_and_link_requests_report_busy_without_changing_pending_transaction() {
    let (mut r, mut m) = sessions();
    let up = sent(&m.step(add(1)), M::DESTINATION_UP);
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
    common::assert_rejected(
        r.step(E::AppAnnounceDestination { mac: mac(1) }),
        C::AlreadyExists,
    );
    let request = || E::AppRequestLinkCharacteristics {
        mac: mac(1),
        requested: dlep_core::LinkCharacteristics {
            latency: Some(std::time::Duration::ZERO),
            ..Default::default()
        },
    };
    let wire = sent(&r.step(request()), M::LINK_CHARACTERISTICS_REQUEST);
    common::assert_rejected(r.step(drop(1)), C::Busy);
    common::assert_rejected(r.step(E::AppAnnounceDestination { mac: mac(1) }), C::Busy);
    let reply = sent(
        &m.step(E::RecvMessage(wire)),
        M::LINK_CHARACTERISTICS_RESPONSE,
    );
    r.step(E::RecvMessage(reply));
    sent(&r.step(drop(1)), M::DESTINATION_DOWN);
    let announce = sent(
        &r.step(E::AppAnnounceDestination { mac: mac(2) }),
        M::DESTINATION_ANNOUNCE,
    );
    common::assert_rejected(r.step(E::AppAnnounceDestination { mac: mac(2) }), C::Busy);
    let denied = sent(
        &m.step(E::RecvMessage(announce)),
        M::DESTINATION_ANNOUNCE_RESPONSE,
    );
    r.step(E::RecvMessage(denied));
    sent(
        &r.step(E::AppAnnounceDestination { mac: mac(2) }),
        M::DESTINATION_ANNOUNCE,
    );
}

#[test]
fn session_commands_share_busy_error_shutdown_still_preempts() {
    let (_, mut m) = sessions();
    sent(
        &m.step(E::AppSessionUpdate {
            metrics: LinkMetrics::default(),
        }),
        M::SESSION_UPDATE,
    );
    common::assert_rejected(
        m.step(E::AppSessionAddresses {
            changes: Default::default(),
        }),
        C::Busy,
    );
    common::assert_rejected(
        m.step(E::AppSessionUpdate {
            metrics: LinkMetrics::default(),
        }),
        C::Busy,
    );
    sent(
        &m.step(E::AppShutdown {
            reason: S::SHUTTING_DOWN,
        }),
        M::SESSION_TERMINATION,
    );
    common::assert_rejected(m.step(add(1)), C::NotReady);
}

#[test]
fn commands_before_initialization_and_wrong_role_are_explicitly_rejected() {
    let mut m = ModemSessionFsm::new();
    common::assert_rejected(m.step(add(1)), C::NotReady);
    m.step(E::TcpAccepted);
    common::assert_rejected(m.step(add(1)), C::NotReady);
    let (mut r, mut m) = sessions();
    common::assert_rejected(r.step(add(1)), C::Unsupported);
    common::assert_rejected(
        m.step(E::AppAnnounceDestination { mac: mac(1) }),
        C::Unsupported,
    );
    common::assert_rejected(
        m.step(E::AppUpdateMetrics {
            mac: mac(1),
            metrics: LinkMetrics::default(),
        }),
        C::UnknownDestination,
    );
}
