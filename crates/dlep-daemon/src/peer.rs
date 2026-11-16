//! Configured peer identities, kept separate from resolved TCP endpoints.

use std::{
    fmt,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

/// A validated ASCII DNS name and port. Resolution is deferred until connecting.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamedPeer {
    host: String,
    port: u16,
}

impl NamedPeer {
    pub fn new(host: &str, port: u16) -> Result<Self, String> {
        if !matches!(
            dlep_net::ServerName::try_from(host),
            Ok(dlep_net::ServerName::DnsName(_))
        ) {
            return Err("expected an ASCII DNS host name".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }

    pub fn host(&self) -> &str {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for NamedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// An IPv6 link-local peer whose local interface is resolved at connection time.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopedPeer {
    address: Ipv6Addr,
    interface: String,
    port: u16,
}

impl ScopedPeer {
    pub fn new(address: Ipv6Addr, interface: &str, port: u16) -> Result<Self, String> {
        if !address.is_unicast_link_local() {
            return Err("named IPv6 zones require a unicast link-local address".into());
        }
        if interface.is_empty()
            || interface.len() > dlep_net::addr::MAX_INTERFACE_NAME_BYTES
            || interface.bytes().all(|b| b.is_ascii_digit())
            || interface
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace() || b"%[]/\\".contains(&b))
        {
            return Err(
                "invalid IPv6 interface name; use a nonempty name or a numeric scope index".into(),
            );
        }
        Ok(Self {
            address,
            interface: interface.into(),
            port,
        })
    }

    pub fn address(&self) -> Ipv6Addr {
        self.address
    }
    pub fn interface(&self) -> &str {
        &self.interface
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Look up the interface afresh without DNS. The zone is routing metadata;
    /// TLS verifies the bare IPv6 address, never the interface name.
    pub fn resolve(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddrV6::new(
            self.address,
            self.port,
            0,
            dlep_net::addr::interface_index(&self.interface)?,
        )
        .into())
    }
}

impl fmt::Display for ScopedPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}%{}]:{}", self.address, self.interface, self.port)
    }
}

/// A numeric address, DNS name, or named-zone IPv6 address with an explicit port.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum PeerEndpoint {
    Address(SocketAddr),
    Named(NamedPeer),
    Scoped(ScopedPeer),
}

impl FromStr for PeerEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = value.parse() {
            return Ok(Self::Address(addr));
        }
        if let Some(bracketed) = value.strip_prefix('[') {
            let (host, port) = bracketed
                .rsplit_once("]:")
                .ok_or("expected [IPv6%INTERFACE]:PORT")?;
            let (address, interface) = host
                .rsplit_once('%')
                .ok_or("expected [IPv6%INTERFACE]:PORT")?;
            let address = address
                .parse::<Ipv6Addr>()
                .map_err(|_| "invalid IPv6 peer address")?;
            let port = parse_port(port)?;
            if !interface.is_empty() && interface.bytes().all(|b| b.is_ascii_digit()) {
                return Err("IPv6 scope index must be a number from 0 to 4294967295".into());
            }
            return Ok(Self::Scoped(ScopedPeer::new(address, interface, port)?));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or("expected IP:PORT, [IPv6]:PORT, or HOST:PORT")?;
        let port = parse_port(port)?;
        Ok(Self::Named(NamedPeer::new(host, port)?))
    }
}

impl TryFrom<String> for PeerEndpoint {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<SocketAddr> for PeerEndpoint {
    fn from(value: SocketAddr) -> Self {
        Self::Address(value)
    }
}

impl From<PeerEndpoint> for String {
    fn from(value: PeerEndpoint) -> Self {
        value.to_string()
    }
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(addr) => addr.fmt(f),
            Self::Named(peer) => peer.fmt(f),
            Self::Scoped(peer) => peer.fmt(f),
        }
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("peer port must be a number from 0 to 65535".into());
    }
    value
        .parse()
        .map_err(|_| "peer port must be a number from 0 to 65535".into())
}
