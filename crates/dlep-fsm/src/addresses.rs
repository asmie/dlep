//! IPv4/IPv6 address and attached-subnet state (RFC 8175 §13.8–13.11).
use std::net::{Ipv4Addr, Ipv6Addr};

use dlep_core::{DataItem, Message, StatusCode};
use ipnet::{Ipv4Net, Ipv6Net};

/// Complete address/subnet set for a destination or session peer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DestinationAddrs {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
    pub v4_subnets: Vec<Ipv4Net>,
    pub v6_subnets: Vec<Ipv6Net>,
}

impl DestinationAddrs {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty()
            && self.v6.is_empty()
            && self.v4_subnets.is_empty()
            && self.v6_subnets.is_empty()
    }

    /// Subnets identify networks, independent of host bits in an IP prefix.
    pub fn canonical(&self) -> Self {
        Self {
            v4: self.v4.clone(),
            v6: self.v6.clone(),
            v4_subnets: self.v4_subnets.iter().map(Ipv4Net::trunc).collect(),
            v6_subnets: self.v6_subnets.iter().map(Ipv6Net::trunc).collect(),
        }
    }
}

/// Explicit additions and removals. Event payloads also include the resulting
/// complete set, so applications can consume deltas or replace their snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressChanges {
    pub added: DestinationAddrs,
    pub removed: DestinationAddrs,
}

impl AddressChanges {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }

    pub fn canonical(&self) -> Self {
        Self {
            added: self.added.canonical(),
            removed: self.removed.canonical(),
        }
    }

    pub fn from_message(message: &Message) -> Self {
        let mut changes = Self::default();
        for item in &message.data_items {
            match item {
                DataItem::Ipv4Address { add, addr } => {
                    let set = if *add {
                        &mut changes.added
                    } else {
                        &mut changes.removed
                    };
                    set.v4.push(*addr);
                }
                DataItem::Ipv6Address { add, addr } => {
                    let set = if *add {
                        &mut changes.added
                    } else {
                        &mut changes.removed
                    };
                    set.v6.push(*addr);
                }
                DataItem::Ipv4AttachedSubnet { add, subnet } => {
                    let set = if *add {
                        &mut changes.added
                    } else {
                        &mut changes.removed
                    };
                    set.v4_subnets.push(subnet.trunc());
                }
                DataItem::Ipv6AttachedSubnet { add, subnet } => {
                    let set = if *add {
                        &mut changes.added
                    } else {
                        &mut changes.removed
                    };
                    set.v6_subnets.push(subnet.trunc());
                }
                _ => {}
            }
        }
        changes
    }

    pub fn append_to(&self, mut message: Message) -> Message {
        for (add, addresses) in [(false, &self.removed), (true, &self.added)] {
            for addr in &addresses.v4 {
                message
                    .data_items
                    .push(DataItem::Ipv4Address { add, addr: *addr });
            }
            for addr in &addresses.v6 {
                message
                    .data_items
                    .push(DataItem::Ipv6Address { add, addr: *addr });
            }
            for subnet in &addresses.v4_subnets {
                message.data_items.push(DataItem::Ipv4AttachedSubnet {
                    add,
                    subnet: subnet.trunc(),
                });
            }
            for subnet in &addresses.v6_subnets {
                message.data_items.push(DataItem::Ipv6AttachedSubnet {
                    add,
                    subnet: subnet.trunc(),
                });
            }
        }
        message
    }

    /// Reject ambiguous commands and duplicates before encoding a wire message.
    pub fn validate(&self) -> Result<(), StatusCode> {
        let changes = self.canonical();
        fn valid<T: Eq>(add: &[T], remove: &[T]) -> bool {
            add.iter()
                .enumerate()
                .all(|(n, value)| !add[..n].contains(value) && !remove.contains(value))
                && remove
                    .iter()
                    .enumerate()
                    .all(|(n, value)| !remove[..n].contains(value))
        }
        if valid(&changes.added.v4, &changes.removed.v4)
            && valid(&changes.added.v6, &changes.removed.v6)
            && valid(&changes.added.v4_subnets, &changes.removed.v4_subnets)
            && valid(&changes.added.v6_subnets, &changes.removed.v6_subnets)
        {
            Ok(())
        } else {
            Err(StatusCode::INVALID_DATA)
        }
    }

    /// Session messages must reject existing adds and unknown removes. Validate
    /// all four families before mutating, so a failing batch is atomic.
    pub fn apply_strict(&self, current: &mut DestinationAddrs) -> Result<(), StatusCode> {
        self.validate()?;
        let changes = self.canonical();
        fn valid<T: Eq>(current: &[T], add: &[T], remove: &[T]) -> bool {
            add.iter().all(|a| !current.contains(a)) && remove.iter().all(|a| current.contains(a))
        }
        if !valid(&current.v4, &changes.added.v4, &changes.removed.v4)
            || !valid(&current.v6, &changes.added.v6, &changes.removed.v6)
            || !valid(
                &current.v4_subnets,
                &changes.added.v4_subnets,
                &changes.removed.v4_subnets,
            )
            || !valid(
                &current.v6_subnets,
                &changes.added.v6_subnets,
                &changes.removed.v6_subnets,
            )
        {
            return Err(StatusCode::INVALID_DATA);
        }
        changes.apply_lenient(current);
        Ok(())
    }

    /// Destination inconsistencies never terminate a session. Ignore duplicate
    /// adds, unknown removes, and values both added and removed in one message.
    pub fn apply_lenient(&self, current: &mut DestinationAddrs) {
        let changes = self.canonical();
        fn apply<T: Copy + Eq>(current: &mut Vec<T>, add: &[T], remove: &[T]) {
            current.retain(|a| !remove.contains(a) || add.contains(a));
            for a in add {
                if !remove.contains(a) && !current.contains(a) {
                    current.push(*a);
                }
            }
        }
        apply(&mut current.v4, &changes.added.v4, &changes.removed.v4);
        apply(&mut current.v6, &changes.added.v6, &changes.removed.v6);
        apply(
            &mut current.v4_subnets,
            &changes.added.v4_subnets,
            &changes.removed.v4_subnets,
        );
        apply(
            &mut current.v6_subnets,
            &changes.added.v6_subnets,
            &changes.removed.v6_subnets,
        );
    }

    /// Effective changes between two complete sets (omitted values survive).
    pub fn between(old: &DestinationAddrs, new: &DestinationAddrs) -> Self {
        fn difference(a: &DestinationAddrs, b: &DestinationAddrs) -> DestinationAddrs {
            DestinationAddrs {
                v4: a.v4.iter().filter(|v| !b.v4.contains(v)).copied().collect(),
                v6: a.v6.iter().filter(|v| !b.v6.contains(v)).copied().collect(),
                v4_subnets: a
                    .v4_subnets
                    .iter()
                    .filter(|v| !b.v4_subnets.contains(v))
                    .copied()
                    .collect(),
                v6_subnets: a
                    .v6_subnets
                    .iter()
                    .filter(|v| !b.v6_subnets.contains(v))
                    .copied()
                    .collect(),
            }
        }
        Self {
            added: difference(new, old),
            removed: difference(old, new),
        }
    }
}
