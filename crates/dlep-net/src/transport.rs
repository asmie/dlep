use crate::tcp_monitor::{Monitor, Registration};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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

// Keep monitoring alive through both the TLS handshake and session lifetime.
struct MonitoredTransport {
    inner: Box<dyn Transport>,
    _registration: Option<Registration>,
}

impl AsyncRead for MonitoredTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for MonitoredTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl Transport for MonitoredTransport {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn is_tls(&self) -> bool {
        self.inner.is_tls()
    }
}

pub struct Connector {
    kind: ConnectorKind,
    enforce_gtsm: bool,
}

enum ConnectorKind {
    Plain,
    Tls(Arc<rustls::ClientConfig>),
}

impl Connector {
    pub fn plain() -> Self {
        Self {
            kind: ConnectorKind::Plain,
            enforce_gtsm: true,
        }
    }

    pub fn tls(client: Arc<rustls::ClientConfig>) -> Self {
        Self {
            kind: ConnectorKind::Tls(client),
            enforce_gtsm: true,
        }
    }

    pub fn with_gtsm(mut self, enforce: bool) -> Self {
        self.enforce_gtsm = enforce;
        self
    }

    pub async fn connect(&self, addr: SocketAddr) -> io::Result<Box<dyn Transport>> {
        let monitor = self.enforce_gtsm.then(Monitor::new).transpose()?;
        let socket = if addr.is_ipv6() {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };
        crate::gtsm::configure_tcp(&socket, addr.is_ipv6(), self.enforce_gtsm)?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(addr))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;
        let registration = monitor.as_ref().map(|m| m.register(&stream)).transpose()?;
        let inner: Box<dyn Transport> = match &self.kind {
            ConnectorKind::Plain => Box::new(stream),
            ConnectorKind::Tls(client) => {
                let connector = tokio_rustls::TlsConnector::from(client.clone());
                let server_name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
                let tls = tokio::time::timeout(
                    TLS_HANDSHAKE_TIMEOUT,
                    connector.connect(server_name, stream),
                )
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS connect timed out"))??;
                Box::new(tls)
            }
        };
        Ok(Box::new(MonitoredTransport {
            inner,
            _registration: registration,
        }))
    }
}

pub struct Acceptor {
    listener: TcpListener,
    kind: AcceptorKind,
    monitor: Option<Arc<Monitor>>,
}

#[derive(Clone)]
enum AcceptorKind {
    Plain,
    Tls(Arc<rustls::ServerConfig>),
}

impl Acceptor {
    pub fn plain(listener: TcpListener) -> io::Result<Self> {
        Self::new(listener, AcceptorKind::Plain, true)
    }

    pub fn plain_with_gtsm(listener: TcpListener, enforce: bool) -> io::Result<Self> {
        Self::new(listener, AcceptorKind::Plain, enforce)
    }

    pub fn tls(listener: TcpListener, server: Arc<rustls::ServerConfig>) -> io::Result<Self> {
        Self::new(listener, AcceptorKind::Tls(server), true)
    }

    pub fn tls_with_gtsm(
        listener: TcpListener,
        server: Arc<rustls::ServerConfig>,
        enforce: bool,
    ) -> io::Result<Self> {
        Self::new(listener, AcceptorKind::Tls(server), enforce)
    }

    fn new(listener: TcpListener, kind: AcceptorKind, enforce: bool) -> io::Result<Self> {
        crate::gtsm::configure_tcp(&listener, listener.local_addr()?.is_ipv6(), enforce)?;
        let monitor = enforce.then(Monitor::new).transpose()?;
        Ok(Self {
            listener,
            kind,
            monitor,
        })
    }

    /// Accept TCP only. The caller runs each TLS handshake independently.
    pub async fn accept_pending(&self) -> io::Result<PendingTransport> {
        let (stream, _) = self.listener.accept().await?;
        let registration = self
            .monitor
            .as_ref()
            .map(|m| m.register(&stream))
            .transpose()?;
        Ok(PendingTransport {
            registration,
            stream,
            kind: self.kind.clone(),
        })
    }

    pub async fn accept(&self) -> io::Result<Box<dyn Transport>> {
        self.accept_pending().await?.handshake().await
    }
}

pub struct PendingTransport {
    registration: Option<Registration>,
    stream: TcpStream,
    kind: AcceptorKind,
}

impl PendingTransport {
    /// TCP peer identity, available before a potentially slow TLS handshake.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    pub async fn handshake(self) -> io::Result<Box<dyn Transport>> {
        let inner: Box<dyn Transport> = match self.kind {
            AcceptorKind::Plain => Box::new(self.stream),
            AcceptorKind::Tls(server) => {
                let acceptor = tokio_rustls::TlsAcceptor::from(server);
                let tls = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(self.stream))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "TLS accept timed out")
                    })??;
                Box::new(tls)
            }
        };
        Ok(Box::new(MonitoredTransport {
            inner,
            _registration: self.registration,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    async fn gtsm_exchange(bind: &str) {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = Acceptor::plain(listener).unwrap();
        let server = tokio::spawn(async move {
            let pending = acceptor.accept_pending().await.unwrap();
            let sock = socket2::SockRef::from(&pending.stream);
            let ttl = if addr.is_ipv6() {
                sock.unicast_hops_v6().unwrap()
            } else {
                sock.ttl().unwrap()
            };
            assert_eq!(ttl, 255);
            let mut stream = pending.handshake().await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let connector = Connector::plain();
        let mut client = timeout(Duration::from_secs(2), connector.connect(addr))
            .await
            .unwrap()
            .unwrap();
        let mut bytes = [0; 2];
        timeout(Duration::from_secs(2), client.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_gtsm_ipv4_including_handshake() {
        gtsm_exchange("127.0.0.1:0").await;
    }
    #[tokio::test]
    async fn tcp_gtsm_ipv6_including_handshake() {
        gtsm_exchange("[::1]:0").await;
    }

    async fn stalled_tls_accept_times_out_without_disrupting_another_peer(bind: &str) {
        use crate::tls::test_helpers::{client_config_for, self_signed_for_ip, server_config_for};

        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pki = self_signed_for_ip(addr.ip());
        let acceptor =
            Acceptor::tls(listener, server_config_for(pki.cert_der, pki.key_der)).unwrap();
        let monitor = acceptor.monitor.as_ref().unwrap();
        assert_eq!(Arc::strong_count(monitor), 1);

        // Establish conforming TCP but never send a TLS ClientHello. Retain
        // the peer so EOF cannot accidentally stand in for the timeout.
        let mut stalled_peer = timeout(Duration::from_secs(2), Connector::plain().connect(addr))
            .await
            .unwrap()
            .unwrap();
        let pending = timeout(Duration::from_secs(2), acceptor.accept_pending())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.peer_addr().unwrap(),
            stalled_peer.local_addr().unwrap()
        );
        assert_eq!(Arc::strong_count(monitor), 2);
        let started = tokio::time::Instant::now();
        let stalled = tokio::spawn(pending.handshake());

        // A separate handshake on the same listener must finish while the
        // first is stalled. Drive both sides under one outer safety deadline.
        let connector = Connector::tls(client_config_for(pki.roots));
        let (client, server) = timeout(Duration::from_secs(3), async {
            tokio::join!(connector.connect(addr), acceptor.accept())
        })
        .await
        .expect("stalled handshake blocked a healthy peer");
        let mut client = client.unwrap();
        let mut server = server.unwrap();
        assert!(client.is_tls() && server.is_tls());
        assert!(!stalled.is_finished());
        assert_eq!(Arc::strong_count(monitor), 3);

        let error = timeout(TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(2), stalled)
            .await
            .expect("TLS handshake exceeded its built-in deadline")
            .unwrap()
            .err()
            .expect("silent TCP peer cannot complete TLS");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() >= TLS_HANDSHAKE_TIMEOUT);
        // The failed handshake must release its registration and duplicate fd,
        // leaving only the acceptor and the healthy session on this monitor.
        assert_eq!(Arc::strong_count(monitor), 2);
        let mut buf = [0; 2];
        assert_eq!(
            timeout(Duration::from_secs(2), stalled_peer.read(&mut buf))
                .await
                .expect("timed-out handshake retained its TCP socket")
                .unwrap(),
            0
        );

        server.write_all(b"ok").await.unwrap();
        timeout(Duration::from_secs(2), client.read_exact(&mut buf))
            .await
            .expect("timeout disrupted the healthy connection")
            .unwrap();
        assert_eq!(&buf, b"ok");
        drop(server);
        assert_eq!(Arc::strong_count(monitor), 1);
    }

    #[tokio::test]
    async fn stalled_tls_accept_ipv4_times_out_and_releases_registration() {
        stalled_tls_accept_times_out_without_disrupting_another_peer("127.0.0.1:0").await;
    }

    #[tokio::test]
    async fn stalled_tls_accept_ipv6_times_out_and_releases_registration() {
        stalled_tls_accept_times_out_without_disrupting_another_peer("[::1]:0").await;
    }

    async fn low_ttl_resets_only_matching_session(bind: &str, connect_addr: Option<&str>) {
        let listener = TcpListener::bind(bind).await.unwrap();
        let mut addr = listener.local_addr().unwrap();
        if let Some(ip) = connect_addr {
            addr.set_ip(ip.parse().unwrap());
        }
        let acceptor = Acceptor::plain(listener).unwrap();
        let socket = if addr.is_ipv6() {
            TcpSocket::new_v6().unwrap()
        } else {
            TcpSocket::new_v4().unwrap()
        };
        crate::gtsm::configure_tcp(&socket, addr.is_ipv6(), true).unwrap();
        let mut peer = timeout(Duration::from_secs(2), socket.connect(addr))
            .await
            .unwrap()
            .unwrap();
        let mut server = acceptor.accept().await.unwrap();
        // A second session on the same listener must remain usable.
        let mut healthy_peer = Connector::plain().connect(addr).await.unwrap();
        let mut healthy_server = acceptor.accept().await.unwrap();
        let sock = socket2::SockRef::from(&peer);
        if addr.is_ipv6() {
            sock.set_unicast_hops_v6(254).unwrap();
        } else {
            sock.set_ttl(254).unwrap();
        }
        peer.write_all(b"invalid TTL").await.unwrap();
        let mut buf = [0; 1];
        let result = timeout(Duration::from_secs(1), server.read(&mut buf))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "invalid packet reached the session"
        );
        let error = timeout(Duration::from_secs(1), peer.read(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
        healthy_peer.write_all(b"x").await.unwrap();
        timeout(Duration::from_secs(1), healthy_server.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"x");
    }

    #[tokio::test]
    async fn invalid_ttl_resets_ipv4_session() {
        low_ttl_resets_only_matching_session("127.0.0.1:0", None).await;
    }

    #[tokio::test]
    async fn invalid_hop_limit_resets_ipv6_session() {
        low_ttl_resets_only_matching_session("[::1]:0", None).await;
    }

    #[tokio::test]
    async fn invalid_ttl_resets_ipv4_mapped_session() {
        low_ttl_resets_only_matching_session("[::]:0", Some("127.0.0.1")).await;
    }

    #[tokio::test]
    async fn connector_monitors_incoming_packets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        crate::gtsm::configure_tcp(&listener, false, true).unwrap();
        let mut client = Connector::plain()
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        server.set_ttl(254).unwrap();
        server.write_all(b"bad TTL").await.unwrap();
        let mut buf = [0; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
        let error = timeout(Duration::from_secs(1), server.read(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn tcp_rejects_low_ttl_syn() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = Acceptor::plain(listener).unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        socket2::SockRef::from(&socket).set_ttl(254).unwrap();
        assert!(
            timeout(Duration::from_millis(100), socket.connect(addr))
                .await
                .is_err()
        );
        assert!(
            timeout(Duration::from_millis(100), acceptor.accept_pending())
                .await
                .is_err()
        );
        // A bad attempt must not prevent a conforming peer from connecting.
        timeout(Duration::from_secs(2), Connector::plain().connect(addr))
            .await
            .unwrap()
            .unwrap();
        timeout(Duration::from_secs(2), acceptor.accept_pending())
            .await
            .unwrap()
            .unwrap();
    }
}
