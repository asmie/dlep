//! Build rustls client/server configs from the TOML `[tls]` section.
//!
//! Lives in `dlep-daemon` (not the binaries) so TOML-driven embedders get
//! the same path→config logic, and stays out of `spawn()` so the explicit
//! `with_rustls_client` / `with_rustls_server` builder contract from M7
//! (fail fast when TLS is on and no rustls config was supplied) is
//! unchanged.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use dlep_net::tls::{load_certs, load_private_key};
use dlep_net::{ClientConfig, ServerConfig};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use thiserror::Error;

use crate::config::TlsConfig;

#[derive(Debug, Error)]
pub enum TlsSetupError {
    /// Router side: peer verification needs a trust root. DLEP deployments
    /// run private PKI, so there is deliberately no system-roots fallback.
    #[error("tls.ca_bundle is required when use_tls = true")]
    MissingCaBundle,
    #[error("tls.cert is required on the modem (server) side when use_tls = true")]
    MissingCert,
    #[error("tls.key is required on the modem (server) side when use_tls = true")]
    MissingKey,
    #[error("tls.cert and tls.key must be set together; only {present} is set")]
    IncompleteClientIdentity { present: &'static str },
    #[error("tls.require_client_cert = true requires tls.ca_bundle")]
    MissingClientCaBundle,
    #[error("failed to read TLS material from {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path} contains no PEM certificates")]
    EmptyPem { path: PathBuf },
    #[error("rustls rejected the TLS material from {field} ({path}): {source}")]
    Rustls {
        field: &'static str,
        path: PathBuf,
        #[source]
        source: rustls::Error,
    },
    #[error("failed to build the client-certificate verifier: {0}")]
    Verifier(#[from] VerifierBuilderError),
}

fn certs_from(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsSetupError> {
    let certs = load_certs(path).map_err(|source| TlsSetupError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if certs.is_empty() {
        return Err(TlsSetupError::EmptyPem {
            path: path.to_path_buf(),
        });
    }
    Ok(certs)
}

fn key_from(path: &Path) -> Result<PrivateKeyDer<'static>, TlsSetupError> {
    load_private_key(path).map_err(|source| TlsSetupError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn root_store_from(path: &Path) -> Result<RootCertStore, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    for cert in certs_from(path)? {
        roots.add(cert).map_err(|source| TlsSetupError::Rustls {
            field: "tls.ca_bundle",
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(roots)
}

/// Build the router-side `ClientConfig` from `[tls]` paths.
///
/// `ca_bundle` is required (private PKI; no system-roots fallback). When
/// `cert` + `key` are both set they are presented as the client identity
/// for mutual TLS; setting only one of them is an error.
pub fn client_config(tls: &TlsConfig) -> Result<Arc<ClientConfig>, TlsSetupError> {
    let ca = tls
        .ca_bundle
        .as_deref()
        .ok_or(TlsSetupError::MissingCaBundle)?;
    let roots = root_store_from(ca)?;
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match (tls.cert.as_deref(), tls.key.as_deref()) {
        (Some(cert_path), Some(key_path)) => {
            let certs = certs_from(cert_path)?;
            let key = key_from(key_path)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|source| TlsSetupError::Rustls {
                    field: "tls.cert/tls.key",
                    path: cert_path.to_path_buf(),
                    source,
                })?
        }
        (None, None) => builder.with_no_client_auth(),
        (Some(_), None) => {
            return Err(TlsSetupError::IncompleteClientIdentity {
                present: "tls.cert",
            });
        }
        (None, Some(_)) => {
            return Err(TlsSetupError::IncompleteClientIdentity { present: "tls.key" });
        }
    };
    Ok(Arc::new(config))
}

/// Build the modem-side `ServerConfig` from `[tls]` paths.
///
/// `cert` + `key` are required. With `require_client_cert = true` the
/// peer must present a certificate chaining to `ca_bundle` (mutual TLS).
pub fn server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, TlsSetupError> {
    let cert_path = tls.cert.as_deref().ok_or(TlsSetupError::MissingCert)?;
    let key_path = tls.key.as_deref().ok_or(TlsSetupError::MissingKey)?;
    let certs = certs_from(cert_path)?;
    let key = key_from(key_path)?;

    let builder = if tls.require_client_cert {
        let ca = tls
            .ca_bundle
            .as_deref()
            .ok_or(TlsSetupError::MissingClientCaBundle)?;
        let verifier = WebPkiClientVerifier::builder(Arc::new(root_store_from(ca)?)).build()?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        if tls.ca_bundle.is_some() {
            tracing::warn!(
                "tls.ca_bundle is set but tls.require_client_cert = false; \
                 client certificates will NOT be required"
            );
        }
        ServerConfig::builder().with_no_client_auth()
    };
    Ok(Arc::new(builder.with_single_cert(certs, key).map_err(
        |source| TlsSetupError::Rustls {
            field: "tls.cert/tls.key",
            path: cert_path.to_path_buf(),
            source,
        },
    )?))
}

// `pub(crate)` so cli.rs's tests can reuse `write_pki` (a private `mod
// tests` would not be reachable from sibling modules).
#[cfg(test)]
pub(crate) mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use dlep_net::tls::test_helpers::self_signed_for_ip;
    use tempfile::TempDir;

    use super::*;

    pub(crate) struct PemFiles {
        pub _dir: TempDir,
        pub cert: PathBuf,
        pub key: PathBuf,
    }

    pub(crate) fn write_pki() -> PemFiles {
        let pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let dir = TempDir::new().expect("tempdir");
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, &pki.cert_pem).expect("write cert.pem");
        std::fs::write(&key, &pki.key_pem).expect("write key.pem");
        PemFiles {
            _dir: dir,
            cert,
            key,
        }
    }

    #[test]
    fn server_config_builds_from_cert_and_key() {
        let pki = write_pki();
        let tls = TlsConfig {
            cert: Some(pki.cert.clone()),
            key: Some(pki.key.clone()),
            ..TlsConfig::default()
        };
        server_config(&tls).expect("server config");
    }

    #[test]
    fn server_config_requires_cert_and_key() {
        let pki = write_pki();
        let missing_cert = TlsConfig {
            key: Some(pki.key.clone()),
            ..TlsConfig::default()
        };
        assert!(matches!(
            server_config(&missing_cert).unwrap_err(),
            TlsSetupError::MissingCert
        ));
        let missing_key = TlsConfig {
            cert: Some(pki.cert.clone()),
            ..TlsConfig::default()
        };
        assert!(matches!(
            server_config(&missing_key).unwrap_err(),
            TlsSetupError::MissingKey
        ));
    }

    #[test]
    fn server_config_with_client_certs_requires_ca_bundle() {
        let pki = write_pki();
        let tls = TlsConfig {
            cert: Some(pki.cert.clone()),
            key: Some(pki.key.clone()),
            require_client_cert: true,
            ..TlsConfig::default()
        };
        assert!(matches!(
            server_config(&tls).unwrap_err(),
            TlsSetupError::MissingClientCaBundle
        ));
    }

    #[test]
    fn server_config_enforcing_client_certs_builds() {
        let server = write_pki();
        let client = write_pki();
        let tls = TlsConfig {
            cert: Some(server.cert.clone()),
            key: Some(server.key.clone()),
            ca_bundle: Some(client.cert.clone()),
            require_client_cert: true,
        };
        server_config(&tls).expect("mTLS server config");
    }

    #[test]
    fn missing_file_reports_io_error_with_path() {
        let pki = write_pki();
        let gone = pki._dir.path().join("nope.pem");
        let tls = TlsConfig {
            cert: Some(gone.clone()),
            key: Some(pki.key.clone()),
            ..TlsConfig::default()
        };
        match server_config(&tls).unwrap_err() {
            TlsSetupError::Io { path, .. } => assert_eq!(path, gone),
            other => panic!("expected Io error, got: {other}"),
        }
    }

    #[test]
    fn empty_pem_is_rejected() {
        let pki = write_pki();
        let empty = pki._dir.path().join("empty.pem");
        std::fs::write(&empty, "").expect("write empty file");
        let tls = TlsConfig {
            cert: Some(empty.clone()),
            key: Some(pki.key.clone()),
            ..TlsConfig::default()
        };
        assert!(matches!(
            server_config(&tls).unwrap_err(),
            TlsSetupError::EmptyPem { .. }
        ));
    }

    #[test]
    fn client_config_requires_ca_bundle() {
        let tls = TlsConfig::default();
        assert!(matches!(
            client_config(&tls).unwrap_err(),
            TlsSetupError::MissingCaBundle
        ));
    }

    #[test]
    fn client_config_builds_with_trust_roots_only() {
        let pki = write_pki();
        let tls = TlsConfig {
            ca_bundle: Some(pki.cert.clone()),
            ..TlsConfig::default()
        };
        client_config(&tls).expect("client config");
    }

    #[test]
    fn client_config_with_identity_builds() {
        let server = write_pki();
        let client = write_pki();
        let tls = TlsConfig {
            ca_bundle: Some(server.cert.clone()),
            cert: Some(client.cert.clone()),
            key: Some(client.key.clone()),
            ..TlsConfig::default()
        };
        client_config(&tls).expect("mTLS client config");
    }

    #[test]
    fn client_config_with_partial_identity_is_rejected() {
        let pki = write_pki();
        let cert_only = TlsConfig {
            ca_bundle: Some(pki.cert.clone()),
            cert: Some(pki.cert.clone()),
            ..TlsConfig::default()
        };
        assert!(matches!(
            client_config(&cert_only).unwrap_err(),
            TlsSetupError::IncompleteClientIdentity {
                present: "tls.cert"
            }
        ));
        let key_only = TlsConfig {
            ca_bundle: Some(pki.cert.clone()),
            key: Some(pki.key.clone()),
            ..TlsConfig::default()
        };
        assert!(matches!(
            client_config(&key_only).unwrap_err(),
            TlsSetupError::IncompleteClientIdentity { present: "tls.key" }
        ));
    }

    #[test]
    fn garbage_certificate_reports_rustls_error() {
        // Valid PEM framing around base64 of non-DER bytes: parses at the
        // pemfile layer, rejected by rustls when added to the root store.
        let pki = write_pki();
        let bogus = pki._dir.path().join("bogus.pem");
        std::fs::write(
            &bogus,
            "-----BEGIN CERTIFICATE-----\naGVsbG8gd29ybGQ=\n-----END CERTIFICATE-----\n",
        )
        .expect("write bogus pem");
        let tls = TlsConfig {
            ca_bundle: Some(bogus.clone()),
            ..TlsConfig::default()
        };
        match client_config(&tls).unwrap_err() {
            TlsSetupError::Rustls { field, path, .. } => {
                assert_eq!(field, "tls.ca_bundle");
                assert_eq!(path, bogus);
            }
            other => panic!("expected Rustls error, got: {other}"),
        }
    }

    #[test]
    fn server_config_with_unused_ca_bundle_still_builds() {
        // ca_bundle without require_client_cert is warned about (see
        // server_config) but must not fail the build.
        let server = write_pki();
        let client = write_pki();
        let tls = TlsConfig {
            cert: Some(server.cert.clone()),
            key: Some(server.key.clone()),
            ca_bundle: Some(client.cert.clone()),
            require_client_cert: false,
        };
        server_config(&tls).expect("server config with ignored ca_bundle");
    }
}
