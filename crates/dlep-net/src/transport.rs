use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// Error message surfaced when a daemon is configured with `use_tls = true`
/// before the TLS path is wired (M7). Centralised so the three call sites
/// (transport, router, modem) cannot drift in wording.
pub const TLS_NOT_IMPLEMENTED_MSG: &str = "TLS transport is not yet implemented";

/// Erased stream type for a session transport. A single trait object carries
/// either a plain TCP stream or a TLS-wrapped one; the rest of the runtime
/// does not care which.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn is_tls(&self) -> bool;
}

impl Transport for TcpStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::peer_addr(self)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        TcpStream::local_addr(self)
    }
    fn is_tls(&self) -> bool {
        false
    }
}

impl Transport for tokio_rustls::client::TlsStream<TcpStream> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

impl Transport for tokio_rustls::server::TlsStream<TcpStream> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().0.local_addr()
    }
    fn is_tls(&self) -> bool {
        true
    }
}

/// Selects between plain TCP and TLS for outbound/inbound connections.
pub enum TransportKind {
    Plain,
    Tls {
        client: Arc<rustls::ClientConfig>,
        server: Arc<rustls::ServerConfig>,
    },
}

pub struct Connector {
    pub kind: TransportKind,
}

impl Connector {
    pub fn plain() -> Self {
        Self {
            kind: TransportKind::Plain,
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Transport>> {
        match &self.kind {
            TransportKind::Plain => {
                let stream = TcpStream::connect(addr).await?;
                Ok(Box::new(stream))
            }
            TransportKind::Tls { .. } => {
                // TODO (M7): wire tokio-rustls TlsConnector + ServerName.
                Err(io::Error::other(TLS_NOT_IMPLEMENTED_MSG))
            }
        }
    }
}

pub struct Acceptor {
    pub kind: TransportKind,
    pub listener: TcpListener,
}

impl Acceptor {
    pub async fn accept(&self) -> io::Result<Box<dyn Transport>> {
        let (stream, _peer) = self.listener.accept().await?;
        match &self.kind {
            TransportKind::Plain => Ok(Box::new(stream)),
            TransportKind::Tls { .. } => {
                // TODO (M7): wire tokio-rustls TlsAcceptor.
                Err(io::Error::other(TLS_NOT_IMPLEMENTED_MSG))
            }
        }
    }
}
