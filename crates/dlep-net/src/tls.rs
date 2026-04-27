//! rustls helpers: build client and server configs from PEM material.
//!
//! Actual TlsConnector/TlsAcceptor wiring lives in `transport.rs`; this
//! module exists so the binaries can build a config from filesystem paths
//! without pulling rustls at the CLI layer.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(path: impl AsRef<Path>) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path.as_ref())?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()
}

pub fn load_private_key(path: impl AsRef<Path>) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path.as_ref())?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
}

/// Placeholder for a real client-config builder. Returns a minimal,
/// root-less config that must be populated with a trust store by callers.
pub fn client_config_placeholder() -> Arc<rustls::ClientConfig> {
    // TODO: real trust-store wiring in M7.
    let roots = rustls::RootCertStore::empty();
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
