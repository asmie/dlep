# Changelog

## 0.2.0

The first functional release of this repository's DLEP implementation. The
published `dlep` 0.1.0 binary was a placeholder that printed `Hello, world!`.

- `cargo install dlep --version 0.2.0 --locked` installs the `dlep` launcher.
  Run `dlep router --help` or `dlep modem --help`. The roles run in-process and
  accept the same options as the standalone `dlep-router` and `dlep-modem`
  packages, which can also be installed separately.
- Eight packages share version 0.2.0: the launcher, core codec, state machines,
  extension API, network transport, daemon runtime, and two role-specific CLIs.
- IPv4/IPv6 discovery, TCP, TLS/mutual TLS, strict Linux GTSM, session lifecycle,
  destination/metric/address updates, and Link Characteristics replies.
- Router reconnection, bounded connection handling, graceful SIGINT/SIGTERM,
  configuration validation, and explicit application-command rejection.
- Crate archives include their license, README, test support, and configuration
  fixtures. Release checks exercise CLI flags and local sessions from installed
  archive sources as well as the workspace build.

### Requirements and migration

- Rust 1.85+; the daemons and transport require Linux. The core codec, FSM, and
  extension API are portable. Strict TCP GTSM requires `CAP_NET_RAW`; binding
  port 854 normally also requires `CAP_NET_BIND_SERVICE` for the modem.
- TLS is on by default and needs explicit certificates/trust roots. Use
  `--no-tls` only for plaintext development. `--check-config` validates inputs
  without opening sockets; it does not verify runtime capabilities.
- Relative to earlier development snapshots, optional metrics use `Option`,
  events include peer/session identity, address changes have explicit removals,
  and command APIs return acceptance/rejection results. Invalid/unknown config
  fields are rejected. See the README and deployment guide for migration details.
- The modem CLI has no physical-radio backend and does not originate real
  radio destinations by itself. Applying requested link changes, independent
  implementation interoperability, and non-Linux daemon support remain outside
  this release's validation scope.

## 0.1.0

Initial placeholder binary.
