# M9 design — CLI polish + deployment documentation

Date: 2026-06-10
Status: approved

## Goal

Close out milestone 9 (architecture.md §9, item 9): make the `dlep-router` and
`dlep-modem` binaries deployable under the default `use_tls = true` posture,
and document how to deploy them. Today the binaries cannot start without
`--no-tls` because nothing converts the TOML `[tls]` section into rustls
configs, and `with_rustls_client` / `with_rustls_server` are never called.

## Scope decisions (made with the user)

- **Full mTLS now**: `require_client_cert` is wired for real (it currently
  does nothing), closing that M7 follow-up.
- **Guide + shipped examples**: `doc/deployment.md` plus working example
  configs and systemd units in `examples/`.
- **CLI**: TLS path overrides + `--check-config` + router `--peer`. No
  `--print-config`, no shell completions, no packaging.

## Design

### 1. TLS plumbing — new module `dlep-daemon/src/tls.rs`

The `TlsConfig` → rustls conversion lives in `dlep-daemon` (not in the
binaries, not auto-wired into `spawn()`). Rationale: binaries stay thin,
TOML-driven embedders get the same logic for free, and the explicit
`with_rustls_client/server` builder contract from M7 — fail fast at spawn
when TLS is on but no rustls config was provided — is preserved, leaving
room for the deferred custom-verifier hooks.

```rust
pub fn client_config(tls: &TlsConfig) -> Result<Arc<ClientConfig>, TlsSetupError>;
pub fn server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, TlsSetupError>;
```

Built on the existing `dlep_net::tls::{load_certs, load_private_key}` PEM
loaders.

`client_config` (router side):

- `ca_bundle` is **required**. DLEP deployments run private PKI; there is no
  fallback to system roots. A missing bundle is `TlsSetupError::MissingCaBundle`.
- `cert` + `key` both set → presented as client identity via
  `with_client_auth_cert` (mTLS).
- Neither set → `with_no_client_auth`.
- Exactly one set → `TlsSetupError::IncompleteClientIdentity`.

`server_config` (modem side):

- `cert` + `key` are **required** (`TlsSetupError::MissingCert` / `MissingKey`).
- `require_client_cert = true` → build `WebPkiClientVerifier` from
  `ca_bundle` (required in that case) and enforce client certs.
- `require_client_cert = false` → `with_no_client_auth`; `ca_bundle` unused.

`TlsSetupError` is a `thiserror` enum whose variants name the offending
field and path, matching the style of `ConfigLoadError` in `cli.rs`. I/O and
parse failures from the PEM loaders are wrapped with the path included.

### 2. Binary wiring (`dlep-router/src/main.rs`, `dlep-modem/src/main.rs`)

New flags on both binaries:

- `--cert <path>`, `--key <path>`, `--ca-bundle <path>` — override the TOML
  `[tls]` section (same precedence as the existing `--interface` override).
- `--check-config` — load TOML, apply CLI overrides, run validation, print
  the outcome, exit 0 on success / 1 on failure. Does not start the daemon.

Router only:

- `--peer <addr>` (repeatable) — appends to `static_peers` and forces
  `mode = "static"`.

Startup path: when `use_tls` is on, build the rustls config from
`config.shared.tls` via the new module and pass it to
`with_rustls_client` / `with_rustls_server`. `--no-tls` keeps its current
meaning and skips all of this.

Validation behind `--check-config` lives in `dlep-daemon` so it is
unit-testable; the binaries only call it:

- TLS material loads and parses (calls `client_config` / `server_config`
  when `use_tls` is on).
- Router: `mode = "static"` with an empty `static_peers` is an error.

### 3. Test coverage

- Extend `dlep_net::tls::test_helpers::TestPki` to also expose PEM strings
  (rcgen `Certificate::pem()` / `KeyPair::serialize_pem()`), so tests can
  write real PEM files to a tempdir and exercise the path-loading code.
- Unit tests for `client_config` / `server_config`: happy paths + every
  error variant.
- Unit tests for the `--check-config` validation helpers and the router
  `--peer` override behaviour.
- One integration test in `dlep-daemon/tests`: full mTLS loopback session —
  modem with `require_client_cert = true`, router presenting a client cert,
  session establishes and carries a destination Up/Down round-trip.
  Mirrors `tls_session_establishes_and_carries_destination_lifecycle` (M7).

### 4. Deployment docs + examples

`doc/deployment.md` covering:

- Building and installing the binaries (`cargo install --path`, MSRV 1.85).
- Certificate provisioning with a private CA: openssl one-liners for CA,
  modem (server) cert with IP SAN, router (client) cert.
- Configuration reference for the TOML sections (`[network]`, `[tls]`,
  `[timers]`, router `mode`/`static_peers`).
- Port 854 privileges: `setcap cap_net_bind_service=+ep`, systemd
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`, or choosing an unprivileged
  port. (Closes the documentation debt noted in architecture.md §10.)
- Firewall requirements: UDP 854 multicast discovery (group 224.0.0.117) +
  TCP 854 session; GTSM note (TTL 255 expected on discovery).
- Logging (`--log-level`, `DLEP_LOG`).
- Troubleshooting keyed to actual error messages (`TlsSetupError` variants,
  the spawn-time "use_tls = true requires …" errors).

`examples/` at the repo root:

- `router.toml`, `modem.toml` — commented, working configs that match the
  deployment guide's PKI layout.
- `dlep-router.service`, `dlep-modem.service` — systemd units with
  `AmbientCapabilities=CAP_NET_BIND_SERVICE`, `DynamicUser=yes`, and config
  paths matching the guide.

Doc updates: README status note, architecture.md §4.6 (new flags) and §9
(mark M9 done with a summary in the established style).

## Out of scope

Unchanged deferrals: DNS-based `ServerName` resolution, custom certificate
verifier hooks, extension follow-ups, IPv6 discovery, packaging (deb/rpm/
nix), and the `AppDropDestination` race (tracked separately; not a CLI/docs
concern).

## Error handling summary

Every failure path is an early, named error before the daemon starts: config
read/parse (`ConfigLoadError`), TLS material (`TlsSetupError`), spawn
preconditions (existing daemon errors). `--check-config` surfaces the same
errors without side effects. No silent fallbacks anywhere in the TLS path.
