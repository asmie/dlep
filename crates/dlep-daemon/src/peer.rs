//! Configured peer identities, kept separate from resolved TCP endpoints.

use std::{fmt, net::SocketAddr, str::FromStr};

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

/// A numeric socket address or DNS name with an explicit port.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum PeerEndpoint {
    Address(SocketAddr),
    Named(NamedPeer),
}

impl FromStr for PeerEndpoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = value.parse() {
            return Ok(Self::Address(addr));
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or("expected IP:PORT, [IPv6]:PORT, or HOST:PORT")?;
        if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err("peer port must be a number from 0 to 65535".into());
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| "peer port must be a number from 0 to 65535")?;
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
        }
    }
}
