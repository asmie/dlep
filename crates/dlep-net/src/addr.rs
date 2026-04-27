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
