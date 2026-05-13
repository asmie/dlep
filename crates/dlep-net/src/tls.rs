//! rustls helpers: build client and server configs from PEM material.
//!
//! Actual TlsConnector/TlsAcceptor wiring lives in `transport.rs`; this
//! module exists so the binaries can build a config from filesystem paths
//! without pulling rustls at the CLI layer.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::Path;

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

/// Cert/key generation helpers for integration tests. Gated behind the
/// `test-helpers` feature so production builds don't pull `rcgen` and its
/// transitive deps. Downstream test crates enable the feature in their
/// `[dev-dependencies]`.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use std::net::IpAddr;
    use std::sync::Arc;

    use rcgen::{CertificateParams, KeyPair, SanType};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};

    /// A self-signed cert + key + root store the client side can trust.
    pub struct TestPki {
        pub cert_der: CertificateDer<'static>,
        pub key_der: PrivateKeyDer<'static>,
        pub roots: RootCertStore,
    }

    /// Generate a self-signed cert for the given IP. The cert's SAN
    /// contains the IP, and the returned `RootCertStore` is seeded with
    /// the cert itself (the simplest trust setup for a single-host test).
    pub fn self_signed_for_ip(ip: IpAddr) -> TestPki {
        let key = KeyPair::generate().expect("rcgen key generation");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("rcgen params");
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
        let cert = params.self_signed(&key).expect("rcgen self-sign");

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_pkcs8 = PrivatePkcs8KeyDer::from(key.serialize_der());
        let key_der = PrivateKeyDer::Pkcs8(key_pkcs8);

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add self-signed root");

        TestPki {
            cert_der,
            key_der,
            roots,
        }
    }

    /// Build a `ClientConfig` that trusts the given roots.
    pub fn client_config_for(roots: RootCertStore) -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// Build a `ServerConfig` that presents the given cert + key.
    pub fn server_config_for(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Arc<ServerConfig> {
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("ServerConfig build"),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::test_helpers::*;

    #[test]
    fn self_signed_for_ip_round_trips_through_client_and_server_configs() {
        let pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Sanity: the helpers produce non-panicking configs.
        let _server = server_config_for(pki.cert_der.clone(), pki.key_der.clone_key());
        let _client = client_config_for(pki.roots);
    }
}
