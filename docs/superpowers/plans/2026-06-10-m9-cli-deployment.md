# M9: CLI Polish + Deployment Documentation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `dlep-router`/`dlep-modem` deployable under the default `use_tls = true` posture (TOML `[tls]` → rustls, full mTLS) and document deployment.

**Architecture:** The `TlsConfig` → rustls conversion lives in a new `dlep-daemon/src/tls.rs` module built on `dlep_net::tls::{load_certs, load_private_key}`, preserving the explicit `with_rustls_client/server` builder contract. Binaries gain `--cert/--key/--ca-bundle/--check-config` (router also `--peer`) and the router binary gains the missing run loop (connect static peers / auto-connect on `PeerDiscovered`). Docs: `doc/deployment.md` + working `examples/`.

**Tech Stack:** rustls 0.23 (`WebPkiClientVerifier`), rustls-pemfile 2, rcgen 0.13 (test PKI), clap derive, tempfile (tests), TOML configs, systemd.

**Spec:** `docs/superpowers/specs/2026-06-10-m9-cli-deployment-design.md` (approved).

**Two discoveries beyond the spec text, both in-scope for "polish the CLI binaries":**

1. The router binary never calls `start_discovery()` or `connect_static()` — it spawns the daemon and idles. Task 7 adds the run loop (the M6 design requires the app to call `connect_static` when `DaemonEvent::PeerDiscovered` arrives).
2. `NetworkConfig` has no struct-level `#[serde(default)]`, so a TOML file with a *partial* `[network]` section (e.g. just `use_tls = false`) fails to parse with "missing field `discovery_v4_group`". Example configs are unusable without this. Task 2 fixes it.

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `Cargo.toml` (workspace) | Modify | add `tempfile` to `[workspace.dependencies]` |
| `crates/dlep-daemon/Cargo.toml` | Modify | add `rustls` dep; `tempfile` dev-dep |
| `crates/dlep-daemon/src/config.rs` | Modify | `#[serde(default)]` on `NetworkConfig`; parse tests |
| `crates/dlep-net/src/tls.rs` | Modify | `TestPki` gains PEM strings; mTLS config helpers |
| `crates/dlep-daemon/src/tls.rs` | Create | `client_config`/`server_config` from `TlsConfig`; `TlsSetupError` |
| `crates/dlep-daemon/src/cli.rs` | Modify | `check_router_config`/`check_modem_config`; `ConfigCheckError` |
| `crates/dlep-daemon/src/lib.rs` | Modify | export new module + names |
| `crates/dlep-router/src/main.rs` | Rewrite | new flags, TLS wiring, run loop |
| `crates/dlep-modem/src/main.rs` | Rewrite | new flags, TLS wiring |
| `crates/dlep-daemon/tests/tls.rs` | Modify | mTLS integration test |
| `examples/router.toml`, `examples/modem.toml` | Create | commented working configs |
| `examples/dlep-router.service`, `examples/dlep-modem.service` | Create | hardened systemd units |
| `doc/deployment.md` | Create | deployment guide |
| `README.md`, `doc/architecture.md` | Modify | status updates, §4.6, §9, §10 |

---

### Task 1: Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/dlep-daemon/Cargo.toml`

- [ ] **Step 1: Add `tempfile` to workspace dependencies**

In the root `Cargo.toml`, in `[workspace.dependencies]`, next to the existing rustls entries (around line 35), add:

```toml
tempfile = "3"
```

- [ ] **Step 2: Add `rustls` dependency and `tempfile` dev-dependency to dlep-daemon**

In `crates/dlep-daemon/Cargo.toml` append to `[dependencies]` (dlep-daemon already passes `Arc<ClientConfig>` around via dlep-net's re-export; the new tls module needs `RootCertStore`, `WebPkiClientVerifier` and error types directly):

```toml
rustls.workspace = true
```

and extend `[dev-dependencies]`:

```toml
[dev-dependencies]
dlep-net = { workspace = true, features = ["test-helpers"] }
tempfile.workspace = true
```

- [ ] **Step 3: Verify it builds**

Run: `cargo check -p dlep-daemon`
Expected: clean check, no errors.

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock crates/dlep-daemon/Cargo.toml
git commit -m "chore(daemon): add rustls dep + tempfile dev-dep for M9 TLS wiring"
```

---

### Task 2: `#[serde(default)]` on `NetworkConfig`

Partial `[network]` sections must parse (example configs say only `use_tls`/ports). `NetworkConfig` implements `Default`, so a struct-level `#[serde(default)]` is enough.

**Files:**
- Modify: `crates/dlep-daemon/src/config.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/dlep-daemon/src/config.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_network_section_uses_defaults() {
        let cfg: RouterConfig = toml::from_str(
            r#"
            [network]
            use_tls = false
            "#,
        )
        .expect("partial [network] section must parse");
        assert!(!cfg.shared.network.use_tls);
        assert_eq!(cfg.shared.network.tcp_port, dlep_core::DEFAULT_PORT);
        assert_eq!(cfg.shared.network.discovery_v4_group, DISCOVERY_IPV4_GROUP);
    }

    #[test]
    fn empty_config_parses_to_defaults() {
        let router: RouterConfig = toml::from_str("").expect("empty router config");
        assert!(router.shared.network.use_tls);
        assert!(matches!(router.mode, DiscoveryMode::Discovery));
        let modem: ModemConfig = toml::from_str("").expect("empty modem config");
        assert_eq!(modem.peer_description, "dlep-modem");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p dlep-daemon --lib config::tests -- --nocapture`
Expected: `partial_network_section_uses_defaults` FAILS with `missing field \`discovery_v4_group\`` (the `empty_config_parses_to_defaults` test passes — `SharedConfig` fields already carry `#[serde(default)]`).

- [ ] **Step 3: Add the attribute**

Change the `NetworkConfig` derive block (config.rs line 7) to:

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct NetworkConfig {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p dlep-daemon --lib config::tests`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/dlep-daemon/src/config.rs
git commit -m "feat(daemon): NetworkConfig accepts partial [network] TOML sections"
```

---

### Task 3: Test PKI exposes PEM + mTLS config helpers (`dlep-net`)

**Files:**
- Modify: `crates/dlep-net/src/tls.rs`

- [ ] **Step 1: Write the failing tests**

In `crates/dlep-net/src/tls.rs`, extend the bottom `mod tests`:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dlep-net --lib tls::`
Expected: COMPILE ERROR — no field `cert_pem` on `TestPki`, unresolved `server_config_requiring_client_certs` / `client_config_with_identity`.

- [ ] **Step 3: Implement**

In `test_helpers`, extend the struct and constructor (PEM strings captured before the DER conversions move things):

```rust
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
```

In `self_signed_for_ip`, after `let cert = params.self_signed(&key).expect("rcgen self-sign");` insert:

```rust
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
```

and add both fields to the returned struct literal.

Append the two config builders to `test_helpers` (next to `server_config_for`):

```rust
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p dlep-net --lib tls::`
Expected: 3 passed (the existing roundtrip test + the 2 new ones).

- [ ] **Step 5: Commit**

```bash
git add crates/dlep-net/src/tls.rs
git commit -m "feat(net): test PKI exposes PEM strings + mTLS config helpers"
```

---

### Task 4: `dlep-daemon::tls` — error enum + `server_config`

**Files:**
- Create: `crates/dlep-daemon/src/tls.rs`
- Modify: `crates/dlep-daemon/src/lib.rs` (module declaration only, exports come in Task 6)

- [ ] **Step 1: Create the module skeleton with tests**

Create `crates/dlep-daemon/src/tls.rs`:

```rust
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
    #[error("rustls rejected the TLS material: {0}")]
    Rustls(#[from] rustls::Error),
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
        roots.add(cert)?;
    }
    Ok(roots)
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
        ServerConfig::builder().with_no_client_auth()
    };
    Ok(Arc::new(builder.with_single_cert(certs, key)?))
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
}
```

- [ ] **Step 2: Declare the module**

In `crates/dlep-daemon/src/lib.rs`, after `pub mod session;` add:

```rust
pub mod tls;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test -p dlep-daemon --lib tls::tests`
Expected: 6 passed. (If `WebPkiClientVerifier::builder` complains about the crypto provider, the builder variant `WebPkiClientVerifier::builder_with_provider(roots, rustls::crypto::ring::default_provider().into())` is NOT needed — the workspace uses rustls 0.23 default features, the same process-default provider the existing `ClientConfig::builder()` calls already rely on.)

- [ ] **Step 4: Commit**

```bash
git add crates/dlep-daemon/src/tls.rs crates/dlep-daemon/src/lib.rs
git commit -m "feat(daemon): build rustls ServerConfig from the TOML [tls] section"
```

---

### Task 5: `dlep-daemon::tls::client_config`

**Files:**
- Modify: `crates/dlep-daemon/src/tls.rs`

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `crates/dlep-daemon/src/tls.rs`:

```rust
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
            TlsSetupError::IncompleteClientIdentity { present: "tls.cert" }
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
            ca_bundle: Some(bogus),
            ..TlsConfig::default()
        };
        assert!(matches!(
            client_config(&tls).unwrap_err(),
            TlsSetupError::Rustls(_)
        ));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dlep-daemon --lib tls::tests`
Expected: COMPILE ERROR — `client_config` not found.

- [ ] **Step 3: Implement**

Insert above `server_config` in `crates/dlep-daemon/src/tls.rs`:

```rust
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
        (Some(cert), Some(key)) => builder.with_client_auth_cert(certs_from(cert)?, key_from(key)?)?,
        (None, None) => builder.with_no_client_auth(),
        (Some(_), None) => {
            return Err(TlsSetupError::IncompleteClientIdentity {
                present: "tls.cert",
            });
        }
        (None, Some(_)) => {
            return Err(TlsSetupError::IncompleteClientIdentity {
                present: "tls.key",
            });
        }
    };
    Ok(Arc::new(config))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p dlep-daemon --lib tls::tests`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/dlep-daemon/src/tls.rs
git commit -m "feat(daemon): build rustls ClientConfig (incl. mTLS identity) from [tls]"
```

---

### Task 6: Config check helpers + public exports

**Files:**
- Modify: `crates/dlep-daemon/src/cli.rs`
- Modify: `crates/dlep-daemon/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/dlep-daemon/src/cli.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        DiscoveryMode, ModemConfig, NetworkConfig, RouterConfig, SharedConfig, TlsConfig,
    };
    use crate::tls::TlsSetupError;

    fn no_tls_shared() -> SharedConfig {
        SharedConfig {
            network: NetworkConfig {
                use_tls: false,
                ..NetworkConfig::default()
            },
            ..SharedConfig::default()
        }
    }

    #[test]
    fn static_mode_without_peers_fails_check() {
        let cfg = RouterConfig {
            shared: no_tls_shared(),
            mode: DiscoveryMode::Static,
            ..RouterConfig::default()
        };
        assert!(matches!(
            check_router_config(&cfg).unwrap_err(),
            ConfigCheckError::StaticModeWithoutPeers
        ));
    }

    #[test]
    fn no_tls_configs_pass_check() {
        let router = RouterConfig {
            shared: no_tls_shared(),
            ..RouterConfig::default()
        };
        check_router_config(&router).expect("router check");
        let modem = ModemConfig {
            shared: no_tls_shared(),
            ..ModemConfig::default()
        };
        check_modem_config(&modem).expect("modem check");
    }

    #[test]
    fn default_tls_configs_fail_without_material() {
        assert!(matches!(
            check_router_config(&RouterConfig::default()).unwrap_err(),
            ConfigCheckError::Tls(TlsSetupError::MissingCaBundle)
        ));
        assert!(matches!(
            check_modem_config(&ModemConfig::default()).unwrap_err(),
            ConfigCheckError::Tls(TlsSetupError::MissingCert)
        ));
    }

    #[test]
    fn tls_router_config_with_ca_bundle_passes_check() {
        let pki = crate::tls::tests::write_pki();
        let cfg = RouterConfig {
            shared: SharedConfig {
                tls: TlsConfig {
                    ca_bundle: Some(pki.cert.clone()),
                    ..TlsConfig::default()
                },
                ..SharedConfig::default()
            },
            ..RouterConfig::default()
        };
        check_router_config(&cfg).expect("router TLS check");
    }
}
```

Note: this reuses `write_pki()` from `crate::tls::tests` — it is already declared `pub(crate)` in Task 4.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p dlep-daemon --lib cli::tests`
Expected: COMPILE ERROR — `check_router_config`, `check_modem_config`, `ConfigCheckError`, `DiscoveryMode` unresolved in cli.rs.

- [ ] **Step 3: Implement**

In `crates/dlep-daemon/src/cli.rs`, extend the imports and add below `load_toml_config`:

```rust
use crate::config::{DiscoveryMode, ModemConfig, RouterConfig};
use crate::tls::{TlsSetupError, client_config, server_config};

/// Errors surfaced by `--check-config` style validation.
#[derive(Debug, Error)]
pub enum ConfigCheckError {
    #[error(transparent)]
    Tls(#[from] TlsSetupError),
    #[error("mode = \"static\" requires at least one entry in static_peers")]
    StaticModeWithoutPeers,
}

/// Validate a router configuration without starting the daemon: TLS
/// material must load when `use_tls` is on, and static mode needs peers.
pub fn check_router_config(cfg: &RouterConfig) -> Result<(), ConfigCheckError> {
    if matches!(cfg.mode, DiscoveryMode::Static) && cfg.static_peers.is_empty() {
        return Err(ConfigCheckError::StaticModeWithoutPeers);
    }
    if cfg.shared.network.use_tls {
        client_config(&cfg.shared.tls)?;
    }
    Ok(())
}

/// Validate a modem configuration without starting the daemon.
pub fn check_modem_config(cfg: &ModemConfig) -> Result<(), ConfigCheckError> {
    if cfg.shared.network.use_tls {
        server_config(&cfg.shared.tls)?;
    }
    Ok(())
}
```

- [ ] **Step 4: Update the public exports**

In `crates/dlep-daemon/src/lib.rs` replace the two `pub use cli::…`/`pub use config::…` lines with:

```rust
pub use cli::{
    ConfigCheckError, ConfigLoadError, check_modem_config, check_router_config, load_toml_config,
};
pub use config::{
    DiscoveryMode, ModemConfig, NetworkConfig, RouterConfig, SharedConfig, TimersConfig, TlsConfig,
};
```

and add at the end of the `pub use` block:

```rust
pub use tls::TlsSetupError;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p dlep-daemon --lib`
Expected: all lib tests pass (config + tls + cli modules).

- [ ] **Step 6: Commit**

```bash
git add crates/dlep-daemon/src/cli.rs crates/dlep-daemon/src/lib.rs
git commit -m "feat(daemon): --check-config validation helpers + exports"
```

---

### Task 7: Router binary — flags, TLS wiring, run loop

The binary previously spawned the daemon and idled: it never started discovery, never connected to static peers, and could not run with TLS (the default). This task makes it a functioning router.

**Files:**
- Rewrite: `crates/dlep-router/src/main.rs`

- [ ] **Step 1: Replace `crates/dlep-router/src/main.rs` with:**

```rust
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{
    DaemonEvent, DiscoveryMode, RouterConfig, RouterDaemon, check_router_config, load_toml_config,
};
use tokio::sync::broadcast::{Receiver, error::RecvError};
use tracing_subscriber::EnvFilter;

/// DLEP (RFC 8175) router-side daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long, short = 'c', env = "DLEP_ROUTER_CONFIG")]
    config: Option<PathBuf>,

    /// Override the network interface used for discovery.
    #[arg(long)]
    interface: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, env = "DLEP_LOG", default_value = "info")]
    log_level: String,

    /// Disable TLS — development only.
    #[arg(long)]
    no_tls: bool,

    /// PEM bundle of CA certificates used to verify the modem
    /// (overrides [tls] ca_bundle).
    #[arg(long, value_name = "PATH")]
    ca_bundle: Option<PathBuf>,

    /// PEM client certificate presented to the modem for mutual TLS
    /// (overrides [tls] cert).
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key for --cert (overrides [tls] key).
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// Modem address to connect to directly instead of multicast
    /// discovery. Repeatable; implies mode = "static".
    #[arg(long, value_name = "ADDR")]
    peer: Vec<SocketAddr>,

    /// Validate the configuration (including TLS material) and exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let mut config: RouterConfig =
        load_toml_config(cli.config.as_deref()).context("loading router configuration")?;
    apply_overrides(&mut config, &cli);

    if cli.check_config {
        check_router_config(&config).context("configuration check failed")?;
        println!("configuration OK");
        return Ok(());
    }

    tracing::info!(
        interface = ?config.shared.network.interface,
        tls = config.shared.network.use_tls,
        mode = ?config.mode,
        "starting dlep-router"
    );

    let tls = if config.shared.network.use_tls {
        Some(
            dlep_daemon::tls::client_config(&config.shared.tls)
                .context("building TLS client configuration")?,
        )
    } else {
        None
    };

    let mode = config.mode.clone();
    let static_peers = config.static_peers.clone();

    let mut builder = RouterDaemon::builder().config(config);
    if let Some(tls) = tls {
        builder = builder.with_rustls_client(tls);
    }
    let daemon = builder
        .spawn()
        .await
        .context("failed to start router daemon")?;
    let mut events = daemon.subscribe();

    match mode {
        DiscoveryMode::Static => {
            for peer in &static_peers {
                daemon
                    .connect_static(*peer)
                    .await
                    .with_context(|| format!("connecting to static peer {peer}"))?;
            }
        }
        DiscoveryMode::Discovery => {
            daemon
                .start_discovery()
                .await
                .context("starting discovery")?;
        }
    }

    run_event_loop(&daemon, &mut events).await;

    tracing::info!("shutdown requested");
    daemon.shutdown().await?;
    Ok(())
}

/// Drive the daemon until Ctrl-C: connect to modems as discovery finds
/// them (deduplicated by address) and log session lifecycle.
async fn run_event_loop(daemon: &RouterDaemon, events: &mut Receiver<DaemonEvent>) {
    let mut connected: HashSet<SocketAddr> = HashSet::new();
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return,
            evt = events.recv() => match evt {
                Ok(DaemonEvent::PeerDiscovered(peer)) => {
                    if !connected.insert(peer.addr) {
                        continue;
                    }
                    tracing::info!(addr = %peer.addr, "modem discovered; connecting");
                    if let Err(e) = daemon.connect_static(peer.addr).await {
                        tracing::warn!(addr = %peer.addr, "connect failed: {e}");
                        connected.remove(&peer.addr);
                    }
                }
                Ok(DaemonEvent::SessionUp { peer, .. }) => {
                    tracing::info!(addr = %peer.addr, tls = peer.is_tls, "session up");
                }
                Ok(DaemonEvent::SessionDown { reason }) => {
                    tracing::info!(?reason, "session down");
                }
                Ok(_) => {}
                Err(RecvError::Lagged(skipped)) => {
                    tracing::warn!(skipped, "event stream lagged");
                }
                Err(RecvError::Closed) => return,
            },
        }
    }
}

fn init_tracing(requested: &str) {
    let filter = match EnvFilter::try_new(requested) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("warning: invalid log level {requested:?} ({err}); falling back to 'info'");
            EnvFilter::new("info")
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn apply_overrides(cfg: &mut RouterConfig, cli: &Cli) {
    if let Some(iface) = &cli.interface {
        cfg.shared.network.interface = Some(iface.clone());
    }
    if cli.no_tls {
        cfg.shared.network.use_tls = false;
    }
    if let Some(path) = &cli.ca_bundle {
        cfg.shared.tls.ca_bundle = Some(path.clone());
    }
    if let Some(path) = &cli.cert {
        cfg.shared.tls.cert = Some(path.clone());
    }
    if let Some(path) = &cli.key {
        cfg.shared.tls.key = Some(path.clone());
    }
    if !cli.peer.is_empty() {
        cfg.mode = DiscoveryMode::Static;
        cfg.static_peers.extend(cli.peer.iter().copied());
    }
}
```

Note: there is deliberately no clap-level `requires` pairing between `--cert`/`--key` — the other half may come from the TOML file; `client_config` reports `IncompleteClientIdentity` after the merge.

- [ ] **Step 2: Verify check-config behavior**

```bash
cargo run -q -p dlep-router -- --check-config
```
Expected: exit 1, stderr contains `configuration check failed` and `tls.ca_bundle is required when use_tls = true`.

```bash
cargo run -q -p dlep-router -- --check-config --no-tls
```
Expected: exit 0, stdout `configuration OK`.

```bash
cargo run -q -p dlep-router -- --check-config --no-tls --peer 192.0.2.1:854
```
Expected: exit 0, stdout `configuration OK` (peer flag forces static mode and supplies the peer).

- [ ] **Step 3: Commit**

```bash
git add crates/dlep-router/src/main.rs
git commit -m "feat(router-bin): TLS wiring, --check-config, --peer, discovery run loop"
```

---

### Task 8: Modem binary — flags + TLS wiring

The modem needs no run loop (the daemon's accept loop and discovery listener start on `spawn`); it gains the TLS flags and `--check-config`.

**Files:**
- Rewrite: `crates/dlep-modem/src/main.rs`

- [ ] **Step 1: Replace `crates/dlep-modem/src/main.rs` with:**

```rust
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use dlep_daemon::{ModemConfig, ModemDaemon, check_modem_config, load_toml_config};
use tracing_subscriber::EnvFilter;

/// DLEP (RFC 8175) modem-side daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Path to a TOML configuration file.
    #[arg(long, short = 'c', env = "DLEP_MODEM_CONFIG")]
    config: Option<PathBuf>,

    /// Override the network interface used for discovery.
    #[arg(long)]
    interface: Option<String>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long, env = "DLEP_LOG", default_value = "info")]
    log_level: String,

    /// Disable TLS — development only.
    #[arg(long)]
    no_tls: bool,

    /// PEM server certificate presented to routers (overrides [tls] cert).
    #[arg(long, value_name = "PATH")]
    cert: Option<PathBuf>,

    /// PEM private key for --cert (overrides [tls] key).
    #[arg(long, value_name = "PATH")]
    key: Option<PathBuf>,

    /// PEM bundle of CA certificates used to verify router client
    /// certificates when require_client_cert is set
    /// (overrides [tls] ca_bundle).
    #[arg(long, value_name = "PATH")]
    ca_bundle: Option<PathBuf>,

    /// Validate the configuration (including TLS material) and exit.
    #[arg(long)]
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log_level);

    let mut config: ModemConfig =
        load_toml_config(cli.config.as_deref()).context("loading modem configuration")?;
    apply_overrides(&mut config, &cli);

    if cli.check_config {
        check_modem_config(&config).context("configuration check failed")?;
        println!("configuration OK");
        return Ok(());
    }

    tracing::info!(
        peer = %config.peer_description,
        tls = config.shared.network.use_tls,
        "starting dlep-modem"
    );

    let tls = if config.shared.network.use_tls {
        Some(
            dlep_daemon::tls::server_config(&config.shared.tls)
                .context("building TLS server configuration")?,
        )
    } else {
        None
    };

    let mut builder = ModemDaemon::builder().config(config);
    if let Some(tls) = tls {
        builder = builder.with_rustls_server(tls);
    }
    let daemon = builder
        .spawn()
        .await
        .context("failed to start modem daemon")?;

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown requested");
    daemon.shutdown().await?;
    Ok(())
}

fn init_tracing(requested: &str) {
    let filter = match EnvFilter::try_new(requested) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("warning: invalid log level {requested:?} ({err}); falling back to 'info'");
            EnvFilter::new("info")
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn apply_overrides(cfg: &mut ModemConfig, cli: &Cli) {
    if let Some(iface) = &cli.interface {
        cfg.shared.network.interface = Some(iface.clone());
    }
    if cli.no_tls {
        cfg.shared.network.use_tls = false;
    }
    if let Some(path) = &cli.cert {
        cfg.shared.tls.cert = Some(path.clone());
    }
    if let Some(path) = &cli.key {
        cfg.shared.tls.key = Some(path.clone());
    }
    if let Some(path) = &cli.ca_bundle {
        cfg.shared.tls.ca_bundle = Some(path.clone());
    }
}
```

- [ ] **Step 2: Verify check-config behavior**

```bash
cargo run -q -p dlep-modem -- --check-config
```
Expected: exit 1, stderr contains `tls.cert is required on the modem (server) side when use_tls = true`.

```bash
cargo run -q -p dlep-modem -- --check-config --no-tls
```
Expected: exit 0, stdout `configuration OK`.

- [ ] **Step 3: Commit**

```bash
git add crates/dlep-modem/src/main.rs
git commit -m "feat(modem-bin): TLS wiring + --check-config"
```

---

### Task 9: mTLS loopback integration test

**Files:**
- Modify: `crates/dlep-daemon/tests/tls.rs`

- [ ] **Step 1: Write the test**

In `crates/dlep-daemon/tests/tls.rs`, extend the helper import (line 11) to:

```rust
use dlep_net::tls::test_helpers::{
    client_config_for, client_config_with_identity, self_signed_for_ip,
    server_config_for, server_config_requiring_client_certs,
};
```

Append the test (mirrors the M7 test, including the documented 50 ms `AppDropDestination` mitigation — see the comment in the existing test, lines 144–153):

```rust
#[tokio::test]
async fn mtls_session_requires_and_accepts_client_certificate() {
    // Two identities: the modem's server cert (trusted by the router) and
    // the router's client cert (trusted by the modem's client verifier).
    let server_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let client_pki = self_signed_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));

    let server_cfg = server_config_requiring_client_certs(
        server_pki.cert_der,
        server_pki.key_der,
        client_pki.roots,
    );
    let client_cfg = client_config_with_identity(
        server_pki.roots,
        client_pki.cert_der,
        client_pki.key_der,
    );

    let modem = ModemDaemon::builder()
        .config(loopback_modem_config())
        .with_rustls_server(server_cfg)
        .spawn()
        .await
        .expect("modem spawn");
    let modem_addr = modem.local_addr();
    let mut modem_events = modem.subscribe();

    let router = RouterDaemon::builder()
        .config(loopback_router_config())
        .with_rustls_client(client_cfg)
        .spawn()
        .await
        .expect("router spawn");
    let mut router_events = router.subscribe();

    router
        .connect_static(modem_addr)
        .await
        .expect("router connect_static (mTLS)");

    await_session_up(&mut router_events).await;
    await_session_up(&mut modem_events).await;

    // Destination round-trip across the mTLS session.
    let mac = MacAddress::new_eui48([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let id = DestinationId(mac);
    let metrics = LinkMetrics {
        max_data_rate_rx_bps: 1_000_000_000,
        max_data_rate_tx_bps: 1_000_000_000,
        current_data_rate_rx_bps: 500_000_000,
        current_data_rate_tx_bps: 500_000_000,
        latency: Duration::from_micros(2_500),
        resources: 90,
        rlq_rx: 100,
        rlq_tx: 100,
        mtu: 1500,
    };

    modem
        .add_destination(id, metrics)
        .await
        .expect("add_destination over mTLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Up { id: got, .. } if *got == id),
    )
    .await;

    // Same AppDropDestination race mitigation as the M7 test above.
    tokio::time::sleep(Duration::from_millis(50)).await;

    modem
        .drop_destination(id, StatusCode::SHUTTING_DOWN)
        .await
        .expect("drop_destination over mTLS");
    let _ = await_destination_event(
        &mut router_events,
        |d| matches!(d, DestinationEvent::Down { id: got, .. } if *got == id),
    )
    .await;

    router.shutdown().await.expect("router shutdown");
    await_session_down(&mut router_events).await;
    await_session_down(&mut modem_events).await;
    modem.shutdown().await.expect("modem shutdown");
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test -p dlep-daemon --test tls`
Expected: 2 passed (`tls_session_establishes_and_carries_destination_lifecycle`, `mtls_session_requires_and_accepts_client_certificate`).

If the mTLS handshake fails with a certificate verification error: webpki must accept the self-signed client cert as its own trust anchor (the server-side equivalent already passes in M7). Should it not, regenerate the client identity as a CA-signed pair instead — add a CA + `signed_by` variant to `test_helpers` — but try the simple form first.

- [ ] **Step 3: Commit**

```bash
git add crates/dlep-daemon/tests/tls.rs
git commit -m "test(daemon): mTLS loopback session with required client certificate"
```

---

### Task 10: Example configs + systemd units

**Files:**
- Create: `examples/router.toml`
- Create: `examples/modem.toml`
- Create: `examples/dlep-router.service`
- Create: `examples/dlep-modem.service`

- [ ] **Step 1: Create `examples/router.toml`**

```toml
# dlep-router example configuration.
# Copy to /etc/dlep/router.toml and adjust paths and addresses.
# See doc/deployment.md for the full walkthrough.

# How the router finds its modem:
#   "discovery" — RFC 8175 UDP multicast Peer Discovery (default)
#   "static"    — connect directly to the addresses in static_peers
mode = "discovery"
# static_peers = ["192.0.2.10:854"]

# Free-text description sent in the Peer Type data item.
peer_description = "dlep-router"

[network]
# Interface used for multicast discovery. Omit to use bind_addr's default.
# interface = "eth0"
# DLEP well-known port is 854 (UDP for discovery, TCP for the session).
# Ports below 1024 need CAP_NET_BIND_SERVICE — see doc/deployment.md.
discovery_port = 854
tcp_port = 854
# TLS is on by default per the RFC's security guidance. With use_tls = true
# the [tls] section below is required.
use_tls = true

[tls]
# CA bundle used to verify the modem's certificate (required with TLS).
ca_bundle = "/etc/dlep/pki/ca.pem"
# Client certificate + key presented to the modem. Required if the modem
# sets require_client_cert = true; omit both for server-only TLS.
cert = "/etc/dlep/pki/router.pem"
key = "/etc/dlep/pki/router.key"

[timers]
heartbeat_interval_ms = 60000
discovery_interval_ms = 5000
```

- [ ] **Step 2: Create `examples/modem.toml`**

```toml
# dlep-modem example configuration.
# Copy to /etc/dlep/modem.toml and adjust paths and addresses.
# See doc/deployment.md for the full walkthrough.

# Free-text description sent in the Peer Type data item.
peer_description = "dlep-modem"

[network]
# Address the TCP listener binds to; 0.0.0.0 means all interfaces.
bind_addr = "0.0.0.0"
# DLEP well-known port is 854 (UDP for discovery, TCP for the session).
# Ports below 1024 need CAP_NET_BIND_SERVICE — see doc/deployment.md.
discovery_port = 854
tcp_port = 854
# TLS is on by default per the RFC's security guidance. With use_tls = true
# the [tls] section below is required.
use_tls = true

[tls]
# Server certificate + key presented to routers (required with TLS).
# The certificate's SAN must contain the IP routers connect to.
cert = "/etc/dlep/pki/modem.pem"
key = "/etc/dlep/pki/modem.key"
# Require routers to present a client certificate signed by this CA
# (mutual TLS — recommended).
require_client_cert = true
ca_bundle = "/etc/dlep/pki/ca.pem"

[timers]
heartbeat_interval_ms = 60000
```

- [ ] **Step 3: Create `examples/dlep-router.service`**

```ini
[Unit]
Description=DLEP router-side daemon (RFC 8175)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/dlep-router --config /etc/dlep/router.toml
Restart=on-failure
RestartSec=2

# Port 854 is privileged; grant only the bind capability.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/dlep

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 4: Create `examples/dlep-modem.service`**

Identical to the router unit except `Description=DLEP modem-side daemon (RFC 8175)` and `ExecStart=/usr/local/bin/dlep-modem --config /etc/dlep/modem.toml`:

```ini
[Unit]
Description=DLEP modem-side daemon (RFC 8175)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
ExecStart=/usr/local/bin/dlep-modem --config /etc/dlep/modem.toml
Restart=on-failure
RestartSec=2

# Port 854 is privileged; grant only the bind capability.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Hardening
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/dlep

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 5: Verify the example configs parse**

```bash
cargo run -q -p dlep-router -- -c examples/router.toml --check-config --no-tls
cargo run -q -p dlep-modem  -- -c examples/modem.toml  --check-config --no-tls
```
Expected: both print `configuration OK` (with `--no-tls` the `/etc/dlep/pki` paths are not opened; TOML shape and static-peers checks still run).

- [ ] **Step 6: Commit**

```bash
git add examples/
git commit -m "feat: example TOML configs + hardened systemd units"
```

---

### Task 11: `doc/deployment.md` + end-to-end PKI verification

**Files:**
- Create: `doc/deployment.md`

- [ ] **Step 1: Create `doc/deployment.md`**

````markdown
# Deploying dlep-router and dlep-modem

This guide covers building, certificate provisioning, configuration, the
privileged-port question, firewalls, and systemd. Working example configs
and unit files live in [`examples/`](../examples/).

## 1. Build and install

Requires Rust 1.85+ (edition 2024).

```bash
cargo install --path crates/dlep-router
cargo install --path crates/dlep-modem
# or: cargo build --release && cp target/release/dlep-{router,modem} /usr/local/bin/
```

## 2. Certificates

TLS is **on by default** (RFC 8175 security guidance). DLEP runs on
closed router↔modem links, so the expected setup is a small private CA —
there is deliberately no fallback to the system trust store.

Create a CA, a modem (server) certificate, and a router (client)
certificate. The modem certificate's subjectAltName **must** contain the
IP address routers connect to (hostname verification uses the IP; DNS
names are not yet supported):

```bash
MODEM_IP=192.0.2.10   # the address routers will connect to

# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 3650 -subj "/CN=dlep-ca"

# Modem (server) certificate with IP SAN
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout modem.key -out modem.csr -subj "/CN=dlep-modem"
openssl x509 -req -in modem.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out modem.pem -days 825 -extfile <(printf "subjectAltName=IP:%s" "$MODEM_IP")

# Router (client) certificate for mutual TLS
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout router.key -out router.csr -subj "/CN=dlep-router"
openssl x509 -req -in router.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out router.pem -days 825 -extfile <(printf "extendedKeyUsage=clientAuth")
```

Install to `/etc/dlep/pki/` (readable by the service user; keys 0600).

The router needs: `ca.pem` (to verify the modem), `router.pem` + `router.key`
(its identity, when the modem sets `require_client_cert = true`).
The modem needs: `modem.pem` + `modem.key`, plus `ca.pem` when requiring
client certificates (recommended).

## 3. Configuration

Both binaries read a TOML file via `--config/-c` (env:
`DLEP_ROUTER_CONFIG` / `DLEP_MODEM_CONFIG`). Start from
[`examples/router.toml`](../examples/router.toml) and
[`examples/modem.toml`](../examples/modem.toml). All sections and fields
are optional; defaults follow the RFC (port 854, TLS on, discovery on).

| Section | Field | Default | Meaning |
|---|---|---|---|
| top level (router) | `mode` | `"discovery"` | `"discovery"` or `"static"` |
| top level (router) | `static_peers` | `[]` | modem `addr:port` list for static mode |
| top level | `peer_description` | binary name | Peer Type data item text |
| `[network]` | `interface` | none | discovery interface override |
| `[network]` | `discovery_port` | `854` | UDP discovery port |
| `[network]` | `tcp_port` | `854` | TCP/TLS session port |
| `[network]` | `bind_addr` | `0.0.0.0` | modem listener bind address |
| `[network]` | `use_tls` | `true` | TLS for the session transport |
| `[network]` | `gtsm_enforce` | `true` | require TTL 255 on discovery |
| `[tls]` | `cert` / `key` | none | identity (modem: required; router: mTLS) |
| `[tls]` | `ca_bundle` | none | trust roots (router: required; modem: for mTLS) |
| `[tls]` | `require_client_cert` | `false` | modem requires router client certs |
| `[timers]` | `heartbeat_interval_ms` | `60000` | RFC 8175 heartbeat interval |
| `[timers]` | `discovery_interval_ms` | `5000` | Peer Discovery resend interval |

CLI flags override the file: `--interface`, `--no-tls`, `--cert`, `--key`,
`--ca-bundle`, and (router) `--peer ADDR` (repeatable; implies static mode).

Validate without starting the daemon:

```bash
dlep-router --config /etc/dlep/router.toml --check-config
dlep-modem  --config /etc/dlep/modem.toml  --check-config
```

`configuration OK` on stdout and exit code 0 mean the TOML parses, static
mode has peers, and all TLS material loads.

## 4. Port 854 privileges

The DLEP well-known port (854, UDP and TCP) is below 1024 and requires
`CAP_NET_BIND_SERVICE` on Linux. Pick one:

1. **systemd (recommended)** — the shipped units grant
   `AmbientCapabilities=CAP_NET_BIND_SERVICE` to an unprivileged
   `DynamicUser`.
2. **setcap** — `sudo setcap cap_net_bind_service=+ep /usr/local/bin/dlep-modem`
   (repeat after each binary update).
3. **Unprivileged ports** — set `discovery_port`/`tcp_port` ≥ 1024 on both
   sides (non-standard; both peers must agree).

Do **not** run the daemons as root.

## 5. Firewall

| Direction | Proto | Port | Purpose |
|---|---|---|---|
| router → 224.0.0.117 | UDP | 854 | Peer Discovery multicast |
| modem → router | UDP | ephemeral | unicast Peer Offer reply |
| router → modem | TCP | 854 | DLEP session (TLS) |

Discovery sends with TTL 255 and, with `gtsm_enforce = true` (default),
the modem drops discovery packets whose TTL is not 255 (GTSM, RFC 5082) —
discovery only works between directly-connected (one-hop) peers.

## 6. systemd

```bash
sudo cp examples/dlep-modem.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dlep-modem
journalctl -u dlep-modem -f
```

Same for `dlep-router.service`. Log verbosity: `--log-level
trace|debug|info|warn|error` or the `DLEP_LOG` env var (add
`Environment=DLEP_LOG=debug` to the unit).

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `tls.ca_bundle is required when use_tls = true` | Router with TLS on but no trust roots. Set `[tls] ca_bundle` or pass `--ca-bundle`. |
| `tls.cert is required on the modem (server) side…` | Modem with TLS on but no identity. Set `[tls] cert` + `key`. |
| `tls.require_client_cert = true requires tls.ca_bundle` | The modem can't verify client certs without roots. |
| `tls.cert and tls.key must be set together; only … is set` | One half of the identity is missing (check both TOML and CLI overrides). |
| `failed to read TLS material from <path>` | Path wrong, or the service user can't read it (systemd: is it under `ReadOnlyPaths`? keys must be readable by the `DynamicUser`). |
| `<path> contains no PEM certificates` | File exists but isn't PEM (`openssl x509 -in <path> -noout` to check). |
| `use_tls = true requires RouterBuilder::with_rustls_client(...)` | Library embedder didn't supply a rustls config — binaries never hit this. |
| TLS handshake fails with certificate errors | Modem cert SAN doesn't contain the IP the router dialed, or peers disagree about the CA. |
| Discovery finds nothing | Peers more than one hop apart (GTSM), multicast blocked, or wrong `interface`. Try static mode (`--peer`) to isolate. |
| `permission denied` binding port 854 | See §4. |
````


- [ ] **Step 2: Verify the guide's PKI commands end-to-end**

Run the §2 openssl block in a temp dir with `MODEM_IP=127.0.0.1`, then
validate both binaries against the generated material:

```bash
set -e
PKI=$(mktemp -d)
cd "$PKI"
MODEM_IP=127.0.0.1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 3650 -subj "/CN=dlep-ca"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout modem.key -out modem.csr -subj "/CN=dlep-modem"
openssl x509 -req -in modem.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out modem.pem -days 825 -extfile <(printf "subjectAltName=IP:%s" "$MODEM_IP")
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout router.key -out router.csr -subj "/CN=dlep-router"
openssl x509 -req -in router.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out router.pem -days 825 -extfile <(printf "extendedKeyUsage=clientAuth")
cd - >/dev/null

cargo run -q -p dlep-modem -- --check-config \
  --cert "$PKI/modem.pem" --key "$PKI/modem.key" --ca-bundle "$PKI/ca.pem"
cargo run -q -p dlep-router -- --check-config \
  --ca-bundle "$PKI/ca.pem" --cert "$PKI/router.pem" --key "$PKI/router.key"
```
Expected: `configuration OK` twice.

- [ ] **Step 3 (live smoke test): run a real mTLS session with openssl-issued certs**

```bash
cat > "$PKI/modem.toml" <<EOF
[network]
bind_addr = "127.0.0.1"
tcp_port = 8542
discovery_port = 8542
use_tls = true
[tls]
cert = "$PKI/modem.pem"
key = "$PKI/modem.key"
require_client_cert = true
ca_bundle = "$PKI/ca.pem"
EOF
cat > "$PKI/router.toml" <<EOF
mode = "static"
static_peers = ["127.0.0.1:8542"]
[network]
use_tls = true
[tls]
ca_bundle = "$PKI/ca.pem"
cert = "$PKI/router.pem"
key = "$PKI/router.key"
EOF
cargo build -p dlep-router -p dlep-modem
target/debug/dlep-modem -c "$PKI/modem.toml" &
MODEM_PID=$!
sleep 1
timeout 5 target/debug/dlep-router -c "$PKI/router.toml" &
ROUTER_PID=$!
sleep 3
kill $MODEM_PID $ROUTER_PID 2>/dev/null || true
```
Expected: router log contains `session up` (the run-loop log line added in
Task 7) and no TLS errors. This proves the deployment guide's openssl PKI
actually interoperates with the rustls stack.

- [ ] **Step 4: Commit**

```bash
git add doc/deployment.md
git commit -m "doc: deployment guide (PKI, port 854 privileges, firewall, systemd)"
```

---

### Task 12: README + architecture.md + final verification

**Files:**
- Modify: `README.md`
- Modify: `doc/architecture.md`

- [ ] **Step 1: Update the README status note**

Replace the status blockquote (README.md lines 15–19) with:

```markdown
> **Status: all nine milestones complete.** Wire codec, both state
> machines, TCP + TLS (mutual TLS supported) transport, UDP multicast
> discovery with GTSM, destinations & metrics, the extension plug-in API,
> and deployable CLI binaries. See
> [§9 of `doc/architecture.md`](doc/architecture.md#9-implementation-status-high-level)
> for the milestone log and remaining follow-ups, and
> [`doc/deployment.md`](doc/deployment.md) for deployment.
```

- [ ] **Step 2: Update architecture.md §4.6**

Replace the §4.6 body (the "Thin binaries (~70 lines each)" paragraph and numbered list, lines 142–151) with:

```markdown
Thin binaries. Each one:

1. Parses CLI flags via `clap` (`--config`, `--interface`, `--log-level`,
   `--no-tls`, `--cert`, `--key`, `--ca-bundle`, `--check-config`; the
   router also takes repeatable `--peer ADDR`, which implies static mode).
2. Initialises `tracing-subscriber` (with a stderr warning if the requested
   log level is invalid).
3. Loads configuration via `dlep_daemon::load_toml_config` and applies CLI
   overrides (`apply_overrides`).
4. With `--check-config`: runs `check_router_config` / `check_modem_config`
   (TOML shape, static peers, TLS material) and exits.
5. When `use_tls` is on, builds the rustls config from the `[tls]` section
   via `dlep_daemon::tls::{client_config, server_config}` and hands it to
   the builder.
6. Builds and spawns the daemon. The router then starts discovery (or
   connects to its static peers) and runs an event loop that connects to
   modems as `PeerDiscovered` arrives (deduplicated by address) and logs
   session lifecycle; the modem's accept loop starts on `spawn`.
7. Awaits SIGINT, then calls `daemon.shutdown().await`.
```

- [ ] **Step 3: Mark M9 done in architecture.md §9**

Replace line 325 (`9. Polish the CLI binaries and document deployment.`) with:

```markdown
9. Polish the CLI binaries and document deployment. **Done (M9)** — the binaries build rustls configs from the TOML `[tls]` section via `dlep_daemon::tls::{client_config, server_config}`: the router requires `ca_bundle` (private PKI; no system-roots fallback) and presents `cert`+`key` as its mTLS identity when set; the modem requires `cert`+`key` and, with `require_client_cert = true`, enforces client certificates through `WebPkiClientVerifier` — closing the mutual-TLS follow-up from M7. New flags: `--cert` / `--key` / `--ca-bundle` overrides, `--check-config` (validates TOML shape, static peers and TLS material via `check_router_config` / `check_modem_config`, then exits), and the router's repeatable `--peer` (implies static mode). The router binary gained its missing run loop: static peers connect at startup, discovery mode auto-connects on `PeerDiscovered` (deduplicated by address). `NetworkConfig` is now `#[serde(default)]` so partial `[network]` sections parse. Deployment guide at `doc/deployment.md` (private-CA openssl walkthrough, port-854 privileges, firewall/GTSM, systemd) plus working artifacts in `examples/` (TOML configs, hardened systemd units). Verified by the `mtls_session_requires_and_accepts_client_certificate` integration test and an end-to-end smoke run with openssl-issued certificates. Follow-ups: `--tcp-port`/`--bind-addr` overrides, shell completions, packaging.
```

- [ ] **Step 4: Update the §10 port-854 open question**

In architecture.md line 334, replace the sentence `Document this in the deployment guide once it exists.` with `Documented in `doc/deployment.md` §4 (M9).`

- [ ] **Step 5: Full verification gate**

```bash
cargo fmt --all
git diff --stat   # fmt should produce no changes; if it does, inspect them
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
Expected: build clean, all tests pass, clippy silent.

- [ ] **Step 6: Commit**

```bash
git add README.md doc/architecture.md
git commit -m "doc: mark M9 complete; update binary docs and port-854 note"
```
