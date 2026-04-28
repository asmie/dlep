# dlep

A Rust implementation of the **Dynamic Link Exchange Protocol** (DLEP, [RFC 8175]),
covering both the router and modem sides from a single workspace.

DLEP is an event-driven protocol that lets a router obtain timely link-state and
link-quality information from a co-located modem (typically a wireless or radio
modem) over a single Layer-2 segment. Discovery happens over UDP multicast; the
session itself is a long-lived TCP (or TLS) connection over which the modem
reports destinations, advertises and updates per-destination metrics (data rate,
latency, link quality, MTU, …) and exchanges heartbeats.

[RFC 8175]: https://www.rfc-editor.org/rfc/rfc8175

> **Status: early.** The crate layout, public API surface, FSM enums, codec
> skeleton, configuration, CI and CLI are in place. Most function bodies are
> stubs marked with `TODO (Mn)` referencing the milestone they belong to. See
> [§9 of `doc/architecture.md`](doc/architecture.md#9-implementation-status-high-level)
> for the current milestone breakdown.

## Goals

- Implement both sides of the protocol from a single tree, so end-to-end tests
  can run on loopback.
- Expose the daemon as a library (`dlep-daemon`) so a third party can embed
  DLEP into their own networking stack without taking the bundled binaries.
- Keep wire format and state machines fully tested in isolation (no I/O), so
  logic bugs are caught without spinning up sockets.
- Provide a stable plug-in API for DLEP extensions (RFC 8175 §13.6 reserves a
  Private Use range for them).
- Support TLS as a first-class transport, per the RFC's security guidance.

## Workspace layout

```
crates/
├── dlep-core      wire types, data items, byte-level codec
├── dlep-fsm       state machines (no I/O, no tokio)
├── dlep-net       transport: UDP multicast, TCP, TLS, framing
├── dlep-ext       extension plug-in trait + registry
├── dlep-daemon    integration layer + public library API
├── dlep-router    router-side daemon binary
└── dlep-modem     modem-side daemon binary
```

The dependency DAG is acyclic; `dlep-core` is the leaf and has no internal
dependencies. See [`doc/architecture.md`](doc/architecture.md) for per-crate
responsibilities and the design rationale.

## Build

Requires Rust **1.85** or newer (edition 2024).

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

CI (`.github/workflows/ci.yml`) runs `fmt`, `clippy -D warnings`, and `build` +
`test` across the workspace.

## Run

Both binaries take a TOML configuration file:

```bash
cargo run -p dlep-router -- --config examples/router.toml
cargo run -p dlep-modem  -- --config examples/modem.toml
```

CLI flags shared by both binaries:

| Flag           | Purpose                                                  |
|----------------|----------------------------------------------------------|
| `--config`     | Path to the TOML config file.                            |
| `--interface`  | Override the network interface from config.              |
| `--log-level`  | Override `RUST_LOG`-style level (`info`, `debug`, …).    |
| `--no-tls`     | Force plain TCP regardless of config.                    |

A minimal configuration:

```toml
[network]
interface           = "eth0"
discovery_v4_group  = "224.0.0.117"
discovery_v6_group  = "ff02::1:7"
discovery_port      = 854
tcp_port            = 854
use_tls             = false
gtsm_enforce        = true

[timers]
heartbeat_interval_ms = 60000
discovery_interval_ms = 5000
```

The full schema (network, TLS, timers, plus router/modem-specific keys) is
documented in [§6 of `doc/architecture.md`](doc/architecture.md#6-configuration).

> Port **854** is below 1024 and requires `CAP_NET_BIND_SERVICE` on Linux
> (`setcap cap_net_bind_service=+ep` on the binary, or
> `AmbientCapabilities=CAP_NET_BIND_SERVICE` in a systemd unit).

## Library use

```rust
use std::sync::Arc;
use dlep_daemon::{RouterDaemon, RouterConfig};
use dlep_ext::DlepExtension;

let daemon = RouterDaemon::builder()
    .config(RouterConfig::default())
    .register_extension(my_extension as Arc<dyn DlepExtension>)
    .with_rustls_client(my_client_tls_config)
    .spawn()
    .await?;

let mut events = daemon.subscribe();          // broadcast::Receiver<DaemonEvent>
daemon.start_discovery().await?;

while let Ok(event) = events.recv().await {
    // react to PeerDiscovered, SessionUp, Destination(...), Metrics(...) …
}

daemon.shutdown().await?;
```

The modem-side API is symmetric, with
`add_destination` / `update_destination` / `drop_destination` /
`announce_destination` in place of `start_discovery` / `connect_static`.

## Documentation

- [`doc/architecture.md`](doc/architecture.md) — full architecture document:
  per-crate responsibilities, design decisions, configuration schema, public
  API shape, testing strategy, milestone status and open questions. Read this
  before contributing.
- [RFC 8175] — the protocol specification.

## License

MIT — see [`LICENSE`](LICENSE).
