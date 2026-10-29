# Changelog

## Unreleased

- Radio adapter for the `dlep-modem` binary: a `[radio]` section runs an
  external program that reports destinations, metrics, and addresses and
  answers Link Characteristics Requests over JSON Lines (see
  `doc/radio-adapter.md`). Destinations are replayed to routers that connect
  later. `link_request_timeout_ms` (default 30000) denies requests a stalled
  adapter does not answer. If the adapter fails, the modem terminates its
  sessions and exits with an error. The adapter does not inherit the modem's
  ambient capabilities; adapters needing devices require a systemd drop-in.
- New dependency: `serde_json` (adapter protocol). `ModemConfig` gains
  `radio: Option<RadioConfig>`, which breaks exhaustive struct literals.
- Modem link-control backend: `ModemBuilder::link_control` registers a
  `LinkControl` implementation (or closure) that answers router Link
  Characteristics Requests, taking as long as the radio needs. Invalid answers
  and backend panics fall back to Request Denied. Without a backend, requests
  are still denied immediately; the `dlep-modem` binary uses its radio adapter
  when one is configured.
- The modem application receives `DestinationEvent::LinkCharacteristicsRequested`
  for every request. Applications that match `DestinationEvent` exhaustively
  must handle the new variant.
- FSM: `SessionConfig.defer_link_characteristics`,
  `FsmEvent::AppLinkCharacteristicsResponse`,
  `EmittedEvent::LinkCharacteristicsRequested`,
  `CommandKind::LinkCharacteristicsResponse`, and
  `CommandError::NoPendingRequest`. A deferred request occupies its
  destination's transaction scope, so the modem's `drop_destination` returns
  Busy until it is answered. The new field and variants break `SessionConfig`
  literals without `..Default::default()` and exhaustive matches.

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
