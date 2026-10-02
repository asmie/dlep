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
        /// PEM renderings of `cert_der` / `key_der`, for tests that exercise
        /// the file-loading path (`load_certs` / `load_private_key`).
        pub cert_pem: String,
        pub key_pem: String,
    }

    /// Generate a self-signed cert for the given IP. The cert's SAN
    /// contains the IP, and the returned `RootCertStore` is seeded with
    /// the cert itself (the simplest trust setup for a single-host test).
    pub fn self_signed_for_ip(ip: IpAddr) -> TestPki {
        self_signed_with_params(
            ip,
            CertificateParams::new(Vec::<String>::new()).expect("rcgen params"),
        )
    }

    /// Expired in 2001, avoiding a fixture that becomes invalid only after
    /// a future wall-clock date. Otherwise identical to the valid IP fixture.
    pub fn expired_self_signed_for_ip(ip: IpAddr) -> TestPki {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("rcgen params");
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
        self_signed_with_params(ip, params)
    }

    fn self_signed_with_params(ip: IpAddr, mut params: CertificateParams) -> TestPki {
        let key = KeyPair::generate().expect("rcgen key generation");
        // Independent fixtures need distinct issuer names. Reusing rcgen's
        // default name makes an unrelated root look like the right issuer
        // with a bad signature instead of an unknown issuer.
        let subject: String = key
            .public_key_raw()
            .iter()
            .take(16)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("DLEP test {subject}"));
        params.subject_alt_names = vec![SanType::IpAddress(ip)];
        let cert = params.self_signed(&key).expect("rcgen self-sign");

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_pkcs8 = PrivatePkcs8KeyDer::from(key.serialize_der());
        let key_der = PrivateKeyDer::Pkcs8(key_pkcs8);

        let mut roots = RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add self-signed root");

        TestPki {
            cert_der,
            key_der,
            roots,
            cert_pem,
            key_pem,
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

    /// Build a `ServerConfig` that presents `cert`+`key` and REQUIRES the
    /// client to present a certificate chaining to `client_roots`.
    pub fn server_config_requiring_client_certs(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
        client_roots: RootCertStore,
    ) -> Arc<ServerConfig> {
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(client_roots))
            .build()
            .expect("client cert verifier");
        Arc::new(
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert], key)
                .expect("ServerConfig build"),
        )
    }

    /// Build a `ClientConfig` that trusts `roots` and presents `cert`+`key`
    /// as its client identity (mutual TLS).
    pub fn client_config_with_identity(
        roots: RootCertStore,
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![cert], key)
                .expect("ClientConfig with identity"),
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

    #[test]
    fn test_pki_exposes_loadable_pem() {
        let pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let mut reader = std::io::BufReader::new(pki.cert_pem.as_bytes());
        let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
            .collect::<Result<_, _>>()
            .expect("cert_pem parses");
        assert_eq!(certs.len(), 1);
        let mut reader = std::io::BufReader::new(pki.key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader).expect("key_pem parses");
        assert!(key.is_some());
    }

    #[test]
    fn mtls_helper_configs_build() {
        let server = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let client = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let _server_cfg = server_config_requiring_client_certs(
            server.cert_der.clone(),
            server.key_der.clone_key(),
            client.roots.clone(),
        );
        let _client_cfg =
            client_config_with_identity(server.roots, client.cert_der, client.key_der);
    }
}
