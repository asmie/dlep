//! RFC 8175 message grammar. Transport framing and extension dispatch happen
//! before this check; neither a well-framed message nor a known type implies
//! that the message is valid in the current session.
use std::collections::HashSet;

use dlep_core::{DataItem, DataItemType as D, Message, MessageType as M, StatusCode};

use crate::session_common::extract_destination_mac;
use crate::transaction::{RequestKind, TransactionTracker};

/// Check every core MAC item, including ones carried by extension messages.
pub fn validate_mac_format(
    msg: &Message,
    format: dlep_core::MacAddressFormat,
) -> Result<(), StatusCode> {
    if msg
        .data_items
        .iter()
        .any(|item| matches!(item, DataItem::MacAddress(mac) if !format.accepts(*mac)))
    {
        Err(StatusCode::INVALID_DATA)
    } else {
        Ok(())
    }
}

pub fn validate_message(
    msg: &Message,
    router: bool,
    initializing: bool,
    local_extensions: &[dlep_core::ExtensionId],
) -> Result<(), StatusCode> {
    let mt = msg.message_type;
    if !(1..=16).contains(&mt.0) {
        return Err(StatusCode::UNKNOWN_MESSAGE);
    }
    let expected = if initializing {
        mt == if router {
            M::SESSION_INITIALIZATION_RESPONSE
        } else {
            M::SESSION_INITIALIZATION
        }
    } else {
        matches!(
            mt,
            M::SESSION_UPDATE | M::SESSION_UPDATE_RESPONSE | M::SESSION_TERMINATION | M::HEARTBEAT
        ) || if router {
            matches!(
                mt,
                M::DESTINATION_UP
                    | M::DESTINATION_ANNOUNCE_RESPONSE
                    | M::DESTINATION_DOWN
                    | M::DESTINATION_DOWN_RESPONSE
                    | M::DESTINATION_UPDATE
                    | M::LINK_CHARACTERISTICS_RESPONSE
            )
        } else {
            matches!(
                mt,
                M::DESTINATION_UP_RESPONSE
                    | M::DESTINATION_ANNOUNCE
                    | M::DESTINATION_DOWN
                    | M::DESTINATION_DOWN_RESPONSE
                    | M::LINK_CHARACTERISTICS_REQUEST
            )
        }
    };
    if !expected {
        return Err(StatusCode::UNEXPECTED_MESSAGE);
    }

    let mut types = HashSet::new();
    let mut addresses = HashSet::new();
    for item in &msg.data_items {
        let t = item.type_id();
        if let DataItem::Unknown(_) = item {
            // Initialization explicitly permits ignoring extension items when
            // the peer announces extensions we do not implement (§12.5).
            let unrecognized_extension = msg.data_items.iter().any(|i| {
                matches!(i, DataItem::ExtensionsSupported(ids)
                    if ids.iter().any(|id| !local_extensions.contains(id)))
            });
            if initializing && unrecognized_extension {
                continue;
            }
            return Err(StatusCode::INVALID_DATA);
        }
        let address = (8..=11).contains(&t.0);
        let metric = (12..=20).contains(&t.0);
        let allowed = match mt {
            M::SESSION_INITIALIZATION => {
                matches!(
                    t,
                    D::PEER_TYPE | D::HEARTBEAT_INTERVAL | D::EXTENSIONS_SUPPORTED
                ) || address
            }
            M::SESSION_INITIALIZATION_RESPONSE => {
                matches!(
                    t,
                    D::STATUS | D::PEER_TYPE | D::HEARTBEAT_INTERVAL | D::EXTENSIONS_SUPPORTED
                ) || address
                    || metric
            }
            M::SESSION_UPDATE => address || (router && metric),
            M::SESSION_UPDATE_RESPONSE | M::SESSION_TERMINATION => t == D::STATUS,
            M::DESTINATION_UP | M::DESTINATION_UPDATE => t == D::MAC_ADDRESS || address || metric,
            M::DESTINATION_UP_RESPONSE | M::DESTINATION_DOWN_RESPONSE => {
                matches!(t, D::MAC_ADDRESS | D::STATUS)
            }
            M::DESTINATION_ANNOUNCE => {
                matches!(t, D::MAC_ADDRESS | D::IPV4_ADDRESS | D::IPV6_ADDRESS)
            }
            M::DESTINATION_ANNOUNCE_RESPONSE => {
                matches!(t, D::MAC_ADDRESS | D::STATUS) || address || metric
            }
            M::LINK_CHARACTERISTICS_RESPONSE => matches!(t, D::MAC_ADDRESS | D::STATUS) || metric,
            M::DESTINATION_DOWN => t == D::MAC_ADDRESS,
            M::LINK_CHARACTERISTICS_REQUEST => matches!(
                t,
                D::MAC_ADDRESS
                    | D::CURRENT_DATA_RATE_RECEIVE
                    | D::CURRENT_DATA_RATE_TRANSMIT
                    | D::LATENCY
            ),
            _ => false,
        };
        if !allowed {
            return Err(StatusCode::INVALID_DATA);
        }
        // Round-trip validation also covers typed callers bypassing the codec.
        let mut bytes = bytes::BytesMut::new();
        item.encode(&mut bytes)
            .map_err(|_| StatusCode::INVALID_DATA)?;
        if address {
            if !addresses.insert(bytes.to_vec()) {
                return Err(StatusCode::INVALID_DATA);
            }
            if initializing
                && matches!(
                    item,
                    DataItem::Ipv4Address { add: false, .. }
                        | DataItem::Ipv6Address { add: false, .. }
                        | DataItem::Ipv4AttachedSubnet { add: false, .. }
                        | DataItem::Ipv6AttachedSubnet { add: false, .. }
                )
            {
                return Err(StatusCode::INVALID_DATA);
            }
        } else if !types.insert(t) {
            return Err(StatusCode::INVALID_DATA);
        }
    }
    let required: &[D] = match mt {
        M::SESSION_INITIALIZATION => &[D::PEER_TYPE, D::HEARTBEAT_INTERVAL],
        M::SESSION_INITIALIZATION_RESPONSE => &[
            D::STATUS,
            D::PEER_TYPE,
            D::HEARTBEAT_INTERVAL,
            D::MAXIMUM_DATA_RATE_RECEIVE,
            D::MAXIMUM_DATA_RATE_TRANSMIT,
            D::CURRENT_DATA_RATE_RECEIVE,
            D::CURRENT_DATA_RATE_TRANSMIT,
            D::LATENCY,
        ],
        M::SESSION_UPDATE_RESPONSE | M::SESSION_TERMINATION => &[D::STATUS],
        M::DESTINATION_UP_RESPONSE
        | M::DESTINATION_ANNOUNCE_RESPONSE
        | M::DESTINATION_DOWN_RESPONSE
        | M::LINK_CHARACTERISTICS_RESPONSE => &[D::MAC_ADDRESS, D::STATUS],
        M::DESTINATION_UP
        | M::DESTINATION_ANNOUNCE
        | M::DESTINATION_DOWN
        | M::DESTINATION_UPDATE
        | M::LINK_CHARACTERISTICS_REQUEST => &[D::MAC_ADDRESS],
        _ => &[],
    };
    if required.iter().any(|t| !types.contains(t)) {
        return Err(StatusCode::INVALID_DATA);
    }
    if mt == M::LINK_CHARACTERISTICS_REQUEST
        && !types.iter().any(|t| {
            matches!(
                *t,
                D::CURRENT_DATA_RATE_RECEIVE | D::CURRENT_DATA_RATE_TRANSMIT | D::LATENCY
            )
        })
    {
        return Err(StatusCode::INVALID_DATA);
    }
    Ok(())
}

pub fn validate_transaction(
    msg: &Message,
    tx: &TransactionTracker,
    destination_up: bool,
) -> Result<(), StatusCode> {
    let mt = msg.message_type;
    if mt == M::SESSION_UPDATE && tx.session_busy() {
        return Err(StatusCode::UNEXPECTED_MESSAGE);
    }
    if mt == M::SESSION_UPDATE_RESPONSE
        && !tx
            .session_pending
            .is_some_and(|p| p.kind == RequestKind::SessionUpdate)
    {
        return Err(StatusCode::UNEXPECTED_MESSAGE);
    }
    if let Some(mac) = extract_destination_mac(msg) {
        let response_kind = match mt {
            M::DESTINATION_UP_RESPONSE => Some(RequestKind::DestinationUp),
            M::DESTINATION_DOWN_RESPONSE => Some(RequestKind::DestinationDown),
            M::DESTINATION_ANNOUNCE_RESPONSE => Some(RequestKind::DestinationAnnounce),
            M::LINK_CHARACTERISTICS_RESPONSE => Some(RequestKind::LinkCharacteristics),
            _ => None,
        };
        if let Some(kind) = response_kind {
            if !tx.per_destination.get(&mac).is_some_and(|p| p.kind == kind) {
                return Err(StatusCode::UNEXPECTED_MESSAGE);
            }
        } else {
            if matches!(
                mt,
                M::DESTINATION_UP
                    | M::DESTINATION_ANNOUNCE
                    | M::DESTINATION_DOWN
                    | M::LINK_CHARACTERISTICS_REQUEST
            ) && tx.destination_busy(&mac)
            {
                return Err(StatusCode::UNEXPECTED_MESSAGE);
            }
            if matches!(
                mt,
                M::DESTINATION_UPDATE | M::DESTINATION_DOWN | M::LINK_CHARACTERISTICS_REQUEST
            ) && !destination_up
            {
                return Err(StatusCode::INVALID_DESTINATION);
            }
            if matches!(mt, M::DESTINATION_UP | M::DESTINATION_ANNOUNCE) && destination_up {
                return Err(StatusCode::UNEXPECTED_MESSAGE);
            }
        }
    }
    Ok(())
}
