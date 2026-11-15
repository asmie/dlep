mod common;
use std::time::Duration;

use dlep_core::{DataItem, LinkMetrics, MacAddress, Message, MessageType as M, StatusCode};
use dlep_fsm::events::EmittedEvent;
use dlep_fsm::session_common::{build_session_update, extract_link_metrics};
use dlep_fsm::session_modem::ModemSessionFsm;
use dlep_fsm::session_router::{RouterSessionFsm, RouterSessionState};
use dlep_fsm::{FsmAction as A, FsmEvent as E, SessionConfig};

fn configured() -> LinkMetrics {
    LinkMetrics {
        max_data_rate_rx_bps: 9_000,
        max_data_rate_tx_bps: 8_000,
        current_data_rate_rx_bps: 7_000,
        current_data_rate_tx_bps: 6_000,
        latency: Duration::from_micros(123),
        resources: Some(0),
        rlq_rx: None,
        rlq_tx: Some(75),
        mtu: Some(1400),
    }
}
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
        .expect("expected message")
}
fn sessions(initial: LinkMetrics) -> (RouterSessionFsm, ModemSessionFsm, Message) {
    let mut r = RouterSessionFsm::new();
    let mut m = ModemSessionFsm::with_config(SessionConfig {
        initial_metrics: initial,
        ..Default::default()
    });
    m.step(E::TcpAccepted);
    let init = sent(&r.step(E::TcpConnected), M::SESSION_INITIALIZATION);
    let reply = sent(
        &m.step(E::RecvMessage(init)),
        M::SESSION_INITIALIZATION_RESPONSE,
    );
    let actions = r.step(E::RecvMessage(reply.clone()));
    assert!(actions.iter().any(|a| matches!(a, A::Emit(EmittedEvent::SessionMetricsUpdate { metrics }) if *metrics == initial)));
    assert_eq!(r.state(), RouterSessionState::InSession);
    (r, m, reply)
}
fn add(r: &mut RouterSessionFsm, m: &mut ModemSessionFsm, n: u8, metrics: LinkMetrics) {
    let up = sent(
        &m.step(E::AppAddDestination {
            mac: mac(n),
            metrics,
            addrs: Default::default(),
        }),
        M::DESTINATION_UP,
    );
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    m.step(E::RecvMessage(ack));
}
fn characteristics(r: &mut RouterSessionFsm, m: &mut ModemSessionFsm, n: u8) {
    let request = sent(
        &r.step(E::AppRequestLinkCharacteristics {
            mac: mac(n),
            requested: dlep_core::LinkCharacteristics {
                latency: Some(Duration::ZERO),
                ..Default::default()
            },
        }),
        M::LINK_CHARACTERISTICS_REQUEST,
    );
    let reply = sent(
        &m.step(E::RecvMessage(request)),
        M::LINK_CHARACTERISTICS_RESPONSE,
    );
    let expected = m.destinations[&mac(n)].metrics;
    assert_eq!(extract_link_metrics(&reply), Some(expected));
    assert!(
        !reply
            .data_items
            .iter()
            .any(|i| matches!(i, DataItem::RelativeLinkQualityReceive(_)))
    );
    r.step(E::RecvMessage(reply));
    assert_eq!(r.state(), RouterSessionState::InSession);
    assert_eq!(r.destinations[&mac(n)].metrics, expected);
}

#[test]
fn initialization_uses_configured_values_and_distinguishes_zero_from_unsupported() {
    for metrics in [LinkMetrics::default(), configured()] {
        let (mut r, _, reply) = sessions(metrics);
        let decoded = Message::decode(reply.encode().unwrap().freeze()).unwrap();
        assert_eq!(extract_link_metrics(&decoded), Some(metrics));
        r.step(E::RecvMessage(
            Message::new(M::DESTINATION_UP).with_item(DataItem::MacAddress(mac(1))),
        ));
        assert_eq!(
            r.destinations[&mac(1)].metrics,
            metrics,
            "a peer may omit all destination metrics to inherit session defaults"
        );
        assert_eq!(
            decoded
                .data_items
                .iter()
                .filter(|i| (12..=20).contains(&i.type_id().0))
                .count(),
            if metrics == LinkMetrics::default() {
                5
            } else {
                8
            }
        );
    }
}

#[test]
fn destinations_inherit_optional_defaults_and_updates_preserve_omissions() {
    let (mut r, mut m, _) = sessions(configured());
    add(&mut r, &mut m, 1, LinkMetrics::default());
    assert_eq!(r.destinations[&mac(1)].metrics.resources, Some(0));
    assert_eq!(r.destinations[&mac(1)].metrics.mtu, Some(1400));
    assert_eq!(r.destinations[&mac(1)].metrics.rlq_rx, None);
    let update = sent(
        &m.step(E::AppUpdateMetrics {
            mac: mac(1),
            metrics: LinkMetrics {
                mtu: Some(1200),
                ..Default::default()
            },
        }),
        M::DESTINATION_UPDATE,
    );
    r.step(E::RecvMessage(update));
    characteristics(&mut r, &mut m, 1);
    assert_eq!(r.destinations[&mac(1)].metrics.mtu, Some(1200));
    // A session-wide omission must preserve a destination-specific MTU.
    let update = sent(
        &m.step(E::AppSessionUpdate {
            metrics: LinkMetrics {
                resources: Some(40),
                ..Default::default()
            },
        }),
        M::SESSION_UPDATE,
    );
    let ack = sent(&r.step(E::RecvMessage(update)), M::SESSION_UPDATE_RESPONSE);
    m.step(E::RecvMessage(ack));
    characteristics(&mut r, &mut m, 1);
    assert_eq!(r.destinations[&mac(1)].metrics.mtu, Some(1200));
    assert_eq!(r.destinations[&mac(1)].metrics.resources, Some(40));
    // Future destinations inherit the updated session default, not destination 1's override.
    add(&mut r, &mut m, 2, LinkMetrics::default());
    assert_eq!(r.destinations[&mac(2)].metrics.resources, Some(40));
    assert_eq!(r.destinations[&mac(2)].metrics.mtu, Some(1400));
    characteristics(&mut r, &mut m, 2);
}

#[test]
fn pending_destination_update_preserves_declared_values_for_response() {
    let (mut r, mut m, _) = sessions(configured());
    let up = sent(
        &m.step(E::AppAddDestination {
            mac: mac(1),
            metrics: LinkMetrics::default(),
            addrs: Default::default(),
        }),
        M::DESTINATION_UP,
    );
    assert!(
        m.step(E::AppUpdateMetrics {
            mac: mac(1),
            metrics: LinkMetrics {
                mtu: Some(1250),
                ..Default::default()
            }
        })
        .is_empty()
    );
    let ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    let update = sent(&m.step(E::RecvMessage(ack)), M::DESTINATION_UPDATE);
    r.step(E::RecvMessage(update));
    characteristics(&mut r, &mut m, 1);
    assert_eq!(r.destinations[&mac(1)].metrics.mtu, Some(1250));
}

#[test]
fn undeclared_metrics_terminate_for_each_metric_bearing_message() {
    for kind in [
        M::SESSION_UPDATE,
        M::DESTINATION_UP,
        M::DESTINATION_UPDATE,
        M::DESTINATION_ANNOUNCE_RESPONSE,
        M::LINK_CHARACTERISTICS_RESPONSE,
    ] {
        let (mut r, mut m, _) = sessions(LinkMetrics::default());
        if kind == M::DESTINATION_UPDATE || kind == M::LINK_CHARACTERISTICS_RESPONSE {
            add(&mut r, &mut m, 1, LinkMetrics::default());
        }
        if kind == M::DESTINATION_ANNOUNCE_RESPONSE {
            r.step(E::AppAnnounceDestination { mac: mac(1) });
        }
        if kind == M::LINK_CHARACTERISTICS_RESPONSE {
            r.step(E::AppRequestLinkCharacteristics {
                mac: mac(1),
                requested: dlep_core::LinkCharacteristics {
                    latency: Some(Duration::ZERO),
                    ..Default::default()
                },
            });
        }
        let mut message = Message::new(kind).with_item(DataItem::Resources(0));
        if kind != M::SESSION_UPDATE {
            message.data_items.push(DataItem::MacAddress(mac(1)));
        }
        if kind == M::DESTINATION_ANNOUNCE_RESPONSE || kind == M::LINK_CHARACTERISTICS_RESPONSE {
            message.data_items.push(DataItem::Status {
                code: StatusCode::SUCCESS,
                text: String::new(),
            });
        }
        let termination = sent(&r.step(E::RecvMessage(message)), M::SESSION_TERMINATION);
        assert!(termination.data_items.iter().any(|i| matches!(
            i,
            DataItem::Status {
                code: StatusCode::INVALID_DATA,
                ..
            }
        )));
    }
}

#[test]
fn invalid_app_metrics_do_not_mutate_state_or_open_transactions() {
    let (mut r, mut m, _) = sessions(configured());
    add(&mut r, &mut m, 1, LinkMetrics::default());
    let before = m.destinations[&mac(1)].metrics;
    for invalid in [
        LinkMetrics {
            rlq_rx: Some(80),
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
        common::assert_rejected(
            m.step(E::AppAddDestination {
                mac: mac(2),
                metrics: invalid,
                addrs: Default::default(),
            }),
            dlep_fsm::CommandError::InvalidInput,
        );
        common::assert_rejected(
            m.step(E::AppUpdateMetrics {
                mac: mac(1),
                metrics: invalid,
            }),
            dlep_fsm::CommandError::InvalidInput,
        );
        common::assert_rejected(
            m.step(E::AppSessionUpdate { metrics: invalid }),
            dlep_fsm::CommandError::InvalidInput,
        );
        assert!(!m.tx.session_busy());
        assert!(!m.tx.destination_busy(&mac(2)));
        assert!(!m.destinations.contains_key(&mac(2)));
        assert_eq!(m.destinations[&mac(1)].metrics, before);
    }
    // Explicit zero still encodes an optional metric.
    assert!(
        build_session_update(&configured())
            .data_items
            .iter()
            .any(|i| matches!(i, DataItem::Resources(0)))
    );
}

#[test]
fn queued_session_metrics_coalesce_behind_addresses_and_preserve_later_overrides() {
    let (mut r, mut m, _) = sessions(configured());
    add(&mut r, &mut m, 1, configured());
    add(&mut r, &mut m, 2, configured());
    let addresses = sent(
        &m.step(E::AppSessionAddresses {
            changes: dlep_fsm::AddressChanges {
                added: dlep_fsm::DestinationAddrs {
                    v4: vec!["192.0.2.1".parse().unwrap()],
                    ..Default::default()
                },
                ..Default::default()
            },
        }),
        M::SESSION_UPDATE,
    );
    let ack = sent(
        &r.step(E::RecvMessage(addresses)),
        M::SESSION_UPDATE_RESPONSE,
    );
    for latency in 200..=700 {
        assert!(
            m.step(E::AppQueueSessionUpdate {
                metrics: LinkMetrics {
                    latency: Duration::from_micros(latency),
                    resources: (latency == 200).then_some(45),
                    ..Default::default()
                },
            })
            .is_empty()
        );
    }
    let mut defaults = m.session_metrics();
    assert_eq!(defaults.resources, Some(45));
    assert_eq!(defaults.mtu, Some(1400));
    common::assert_rejected(
        m.step(E::AppSessionUpdate {
            metrics: configured(),
        }),
        dlep_fsm::CommandError::Busy,
    );
    common::assert_rejected(
        m.step(E::AppQueueSessionUpdate {
            metrics: LinkMetrics {
                resources: Some(101),
                ..configured()
            },
        }),
        dlep_fsm::CommandError::InvalidInput,
    );
    assert_eq!(m.session_metrics(), defaults);
    let override_metrics = LinkMetrics {
        latency: Duration::from_micros(999),
        resources: Some(0),
        mtu: Some(1200),
        ..defaults
    };
    let update = sent(
        &m.step(E::AppUpdateMetrics {
            mac: mac(1),
            metrics: override_metrics,
        }),
        M::DESTINATION_UPDATE,
    );
    r.step(E::RecvMessage(update));
    // A further queued report keeps omitted optional destination overrides,
    // even when an earlier queued report supplied a different optional value.
    defaults.latency = override_metrics.latency;
    assert!(
        m.step(E::AppQueueSessionUpdate {
            metrics: LinkMetrics {
                latency: defaults.latency,
                ..Default::default()
            },
        })
        .is_empty()
    );
    assert_eq!(m.destinations[&mac(1)].metrics, override_metrics);
    let messages: Vec<_> = m
        .step(E::RecvMessage(ack))
        .into_iter()
        .filter_map(|a| match a {
            A::SendMessage(message) => Some(message),
            _ => None,
        })
        .collect();
    assert_eq!(messages.len(), 2, "one coalesced update and one correction");
    assert_eq!(messages[0].message_type, M::SESSION_UPDATE);
    assert_eq!(messages[1].message_type, M::DESTINATION_UPDATE);
    assert!(
        !messages[0]
            .data_items
            .iter()
            .any(|item| matches!(item, DataItem::Mtu(_)))
    );
    let mut responses = Vec::new();
    for message in messages {
        let decoded = Message::decode(message.encode().unwrap().freeze()).unwrap();
        responses.extend(r.step(E::RecvMessage(decoded)));
    }
    assert_eq!(r.session_metrics, defaults);
    assert_eq!(r.destinations[&mac(1)].metrics, override_metrics);
    assert_eq!(r.destinations[&mac(2)].metrics, defaults);
    assert_eq!(m.destinations[&mac(1)].metrics, override_metrics);
    let actions = m.step(E::RecvMessage(sent(&responses, M::SESSION_UPDATE_RESPONSE)));
    assert!(!actions.iter().any(|a| matches!(a, A::SendMessage(_))));
    assert!(!m.tx.session_busy());
    // A later session report intentionally supersedes the destination override.
    let newer = LinkMetrics {
        latency: Duration::from_micros(1000),
        ..defaults
    };
    let update = sent(
        &m.step(E::AppQueueSessionUpdate { metrics: newer }),
        M::SESSION_UPDATE,
    );
    r.step(E::RecvMessage(update));
    assert_eq!(m.destinations[&mac(1)].metrics, newer);
    assert_eq!(r.destinations[&mac(1)].metrics, newer);
}

#[test]
fn queued_metrics_respect_pending_up_down_and_withdrawn_destinations() {
    let (mut r, mut m, _) = sessions(configured());
    for n in [1, 2] {
        add(&mut r, &mut m, n, configured());
    }
    let down = sent(
        &r.step(E::AppDropDestination {
            mac: mac(2),
            reason: StatusCode::SUCCESS,
        }),
        M::DESTINATION_DOWN,
    );
    let response = sent(&m.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
    r.step(E::RecvMessage(response));
    let up = sent(
        &m.step(E::AppAddDestination {
            mac: mac(3),
            metrics: configured(),
            addrs: Default::default(),
        }),
        M::DESTINATION_UP,
    );
    let up_ack = sent(&r.step(E::RecvMessage(up)), M::DESTINATION_UP_RESPONSE);
    let initial = sent(
        &m.step(E::AppSessionUpdate {
            metrics: configured(),
        }),
        M::SESSION_UPDATE,
    );
    let ack = sent(&r.step(E::RecvMessage(initial)), M::SESSION_UPDATE_RESPONSE);
    assert!(
        m.step(E::AppQueueSessionUpdate {
            metrics: LinkMetrics {
                latency: Duration::from_micros(200),
                ..configured()
            }
        })
        .is_empty()
    );
    let expected = LinkMetrics {
        latency: Duration::from_micros(999),
        ..configured()
    };
    for n in [1, 2, 3] {
        for action in m.step(E::AppUpdateMetrics {
            mac: mac(n),
            metrics: expected,
        }) {
            if let A::SendMessage(message) = action {
                r.step(E::RecvMessage(message));
            }
        }
    }
    let down = sent(
        &m.step(E::AppDropDestination {
            mac: mac(1),
            reason: StatusCode::SUCCESS,
        }),
        M::DESTINATION_DOWN,
    );
    let down_ack = sent(&r.step(E::RecvMessage(down)), M::DESTINATION_DOWN_RESPONSE);
    let actions = m.step(E::RecvMessage(ack));
    assert_eq!(
        actions
            .iter()
            .filter(|a| matches!(a, A::SendMessage(_)))
            .count(),
        1
    );
    r.step(E::RecvMessage(sent(&actions, M::SESSION_UPDATE)));
    assert!(!m.destinations[&mac(2)].announced);
    assert!(m.destinations[&mac(3)].pending_metrics);
    let correction = sent(&m.step(E::RecvMessage(up_ack)), M::DESTINATION_UPDATE);
    r.step(E::RecvMessage(correction));
    assert_eq!(r.destinations[&mac(3)].metrics, expected);
    m.step(E::RecvMessage(down_ack));
    assert!(!m.destinations.contains_key(&mac(1)));
    let announce = sent(
        &r.step(E::AppAnnounceDestination { mac: mac(2) }),
        M::DESTINATION_ANNOUNCE,
    );
    let response = sent(
        &m.step(E::RecvMessage(announce)),
        M::DESTINATION_ANNOUNCE_RESPONSE,
    );
    r.step(E::RecvMessage(response));
    assert_eq!(r.destinations[&mac(2)].metrics, expected);
    assert_eq!(r.state(), RouterSessionState::InSession);
}

#[test]
fn queued_metrics_are_modem_only_and_cannot_escape_shutdown() {
    let (mut r, mut m, _) = sessions(configured());
    common::assert_rejected(
        r.step(E::AppQueueSessionUpdate {
            metrics: configured(),
        }),
        dlep_fsm::CommandError::Unsupported,
    );
    m.step(E::AppQueueSessionUpdate {
        metrics: configured(),
    });
    assert!(
        m.step(E::AppQueueSessionUpdate {
            metrics: LinkMetrics::default()
        })
        .is_empty()
    );
    m.step(E::AppShutdown {
        reason: StatusCode::SHUTTING_DOWN,
    });
    let actions = m.step(E::RecvMessage(
        dlep_fsm::session_common::build_session_update_response(StatusCode::SUCCESS),
    ));
    assert!(!actions.iter().any(
        |a| matches!(a, A::SendMessage(message) if message.message_type == M::SESSION_UPDATE)
    ));
    common::assert_rejected(
        m.step(E::AppQueueSessionUpdate {
            metrics: configured(),
        }),
        dlep_fsm::CommandError::NotReady,
    );
}
