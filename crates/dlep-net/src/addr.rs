use std::net::{IpAddr, SocketAddr};

/// Identifies a network interface for multicast socket binding.
#[derive(Clone, Debug)]
pub enum InterfaceSpec {
    ByName(String),
    ByIndex(u32),
    Any,
}

/// Convenience wrapper for a discovered DLEP peer endpoint.
#[derive(Clone, Copy, Debug)]
pub struct PeerAddr {
    pub addr: IpAddr,
    pub port: u16,
    pub tls: bool,
}

impl PeerAddr {
    pub fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }
}

/// One usable IPv4 address and its owning interface, resolved at socket setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv4Interface {
    pub index: u32,
    pub address: std::net::Ipv4Addr,
}

impl InterfaceSpec {
    /// Resolve an interface and optional preferred local address. `Any` with
    /// an unspecified address leaves interface selection to the routing table.
    /// A supplied address must belong to the selected interface. Multiple
    /// addresses are sorted so the choice is deterministic without a preference.
    pub fn resolve_v4(
        &self,
        preferred: std::net::Ipv4Addr,
    ) -> std::io::Result<Option<Ipv4Interface>> {
        use nix::{
            ifaddrs::getifaddrs,
            net::if_::{InterfaceFlags, if_nametoindex},
        };
        use std::io::{Error, ErrorKind};
        if matches!(self, Self::Any) && preferred.is_unspecified() {
            return Ok(None);
        }
        let requested_index = match self {
            Self::ByName(name) => Some(if_nametoindex(name.as_str()).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid discovery interface {name:?}: {e}"),
                )
            })?),
            Self::ByIndex(0) => {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "interface index must not be zero",
                ));
            }
            Self::ByIndex(index) => Some(*index),
            Self::Any => None,
        };
        let mut candidates = Vec::new();
        for entry in getifaddrs()? {
            let Some(address) = entry
                .address
                .and_then(|a| a.as_sockaddr_in().map(|a| a.ip()))
            else {
                continue;
            };
            let index = if_nametoindex(entry.interface_name.as_str())?;
            if requested_index.is_some_and(|wanted| wanted != index)
                || (!preferred.is_unspecified() && address != preferred)
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_broadcast()
                || !entry.flags.contains(InterfaceFlags::IFF_UP)
                || !entry
                    .flags
                    .intersects(InterfaceFlags::IFF_MULTICAST | InterfaceFlags::IFF_LOOPBACK)
            {
                continue;
            }
            candidates.push(Ipv4Interface { index, address });
        }
        candidates.sort_by_key(|i| (i.index, i.address));
        candidates.first().copied().map(Some).ok_or_else(|| Error::new(
            ErrorKind::AddrNotAvailable,
            format!("discovery interface {self:?} has no usable IPv4 address matching {preferred}; it must be up and support multicast (or be loopback)"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn unspecified_interface_preserves_route_selection() {
        assert_eq!(
            InterfaceSpec::Any
                .resolve_v4(Ipv4Addr::UNSPECIFIED)
                .unwrap(),
            None
        );
    }

    #[test]
    fn interface_name_and_index_resolve_same_loopback_address() {
        let resolved = InterfaceSpec::Any
            .resolve_v4(Ipv4Addr::LOCALHOST)
            .unwrap()
            .unwrap();
        assert_eq!(
            InterfaceSpec::ByIndex(resolved.index)
                .resolve_v4(Ipv4Addr::LOCALHOST)
                .unwrap(),
            Some(resolved)
        );
        let name = nix::net::if_::if_indextoname(resolved.index).unwrap();
        assert_eq!(
            InterfaceSpec::ByName(name.to_string_lossy().into_owned())
                .resolve_v4(Ipv4Addr::UNSPECIFIED)
                .unwrap(),
            Some(resolved)
        );
    }

    #[test]
    fn invalid_interface_and_nonlocal_address_are_rejected() {
        for spec in [
            InterfaceSpec::ByName("".into()),
            InterfaceSpec::ByName("dlep-no-such-if".into()),
            InterfaceSpec::ByName("bad\0name".into()),
            InterfaceSpec::ByIndex(0),
            InterfaceSpec::ByIndex(u32::MAX),
        ] {
            assert!(spec.resolve_v4(Ipv4Addr::UNSPECIFIED).is_err());
        }
        assert!(InterfaceSpec::Any.resolve_v4(Ipv4Addr::BROADCAST).is_err());
    }
}
