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

pub struct Connector {
    kind: ConnectorKind,
}

enum ConnectorKind {
    Plain,
    Tls(Arc<rustls::ClientConfig>),
}

impl Connector {
    pub fn plain() -> Self {
        Self {
            kind: ConnectorKind::Plain,
        }
    }

    pub fn tls(client: Arc<rustls::ClientConfig>) -> Self {
        Self {
            kind: ConnectorKind::Tls(client),
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Transport>> {
        let stream = TcpStream::connect(addr).await?;
        match &self.kind {
            ConnectorKind::Plain => Ok(Box::new(stream)),
            ConnectorKind::Tls(client) => {
                let connector = tokio_rustls::TlsConnector::from(client.clone());
                let server_name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
                let tls = connector
                    .connect(server_name, stream)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Box::new(tls))
            }
        }
    }
}

pub struct Acceptor {
    listener: TcpListener,
    kind: AcceptorKind,
}

enum AcceptorKind {
    Plain,
    Tls(Arc<rustls::ServerConfig>),
}

impl Acceptor {
    pub fn plain(listener: TcpListener) -> Self {
        Self {
            listener,
            kind: AcceptorKind::Plain,
        }
    }

    pub fn tls(listener: TcpListener, server: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            kind: AcceptorKind::Tls(server),
        }
    }

    pub async fn accept(&self) -> io::Result<Box<dyn Transport>> {
        let (stream, _peer) = self.listener.accept().await?;
        match &self.kind {
            AcceptorKind::Plain => Ok(Box::new(stream)),
            AcceptorKind::Tls(server) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(server.clone());
                let tls = acceptor
                    .accept(stream)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                Ok(Box::new(tls))
            }
        }
    }
}
