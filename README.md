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

> **Status: core implementation with remaining conformance gaps.** Wire codec, both state machines,
> TCP + TLS (mutual TLS supported) transport, UDP multicast discovery with
> GTSM, destinations & metrics, `Session Update`, `Destination Announce`,
> and `Link Characteristics Request`/`Response`,
> the extension plug-in API, and deployable CLI binaries with
> reconnect-on-drop. See
> [§9 of `doc/architecture.md`](doc/architecture.md#9-implementation-status-high-level)
> for the milestone log and remaining follow-ups, and
> [`doc/deployment.md`](doc/deployment.md) for deployment.
>
> Not yet implemented: IPv6 discovery transport, a modem backend that applies
> requested link changes, and configurable session-wide metrics (the modem
> still advertises placeholders in `Session Initialization Response`).

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
    // react to PeerDiscovered, SessionUp, Destination { .. }, Metrics { .. } …
}

daemon.shutdown().await?;
```

The modem-side API is symmetric, with
`add_destination` / `update_destination` / `drop_destination` in place of
`start_discovery` / `connect_static`.

`ModemDaemon::update_session_metrics` sends session-wide metric changes via
`Session Update` (RFC 8175 §12.7). The router compatibility method returns an
error: routers may report Layer 3 changes but cannot originate metric items.
`announce_destination` is router-side only. The modem denies destinations it
does not know; successful responses create destinations at the router.

`RouterDaemon::drop_destination(session_id, destination)` withdraws interest
from one modem. The modem acknowledges with Destination Down Response, stops
reporting that destination on this session, and emits a `DestinationEvent::Down`.
The router emits its own Down event when the response arrives. The session stays
active; a later Destination Announce can restore reports using the modem's
latest local metrics and addresses. Busy/unknown destinations and stale session
IDs follow the existing command-delivery limitation described below.

`RouterDaemon::request_link_characteristics(session_id, destination, requested)`
requests rate or latency changes from one modem. `LinkCharacteristics` has
optional receive rate, transmit rate, and latency fields; supply at least one.
Listen for `DestinationEvent::LinkCharacteristicsResponse` to obtain the status,
status text, and current metrics. A response must include every core metric the
peer declared during initialization. The request deadline defaults to 60 seconds
and is configurable with `[timers].link_characteristics_timeout_ms`; expiry
terminates the session even if the peer is still sending heartbeats.

The bundled modem cannot change physical link parameters. It returns
`Request Denied` with current destination metrics, keeping the session alive.
Applying requested changes requires a modem control backend, which remains
unimplemented. As with other destination commands, a busy transaction, an
unknown destination, or a stale session ID prevents the request from being sent;
command acknowledgement and queueing remain a separate gap.

Discovery events carry a `PeerOffer` containing ordered connection points.
Use `RouterDaemon::connect_discovered(&offer)` to try compatible endpoints;
TLS-required configurations never fall back to plaintext. Discovery continues
while sessions are active, allowing additional modems to be found.

`SessionUp`, `SessionDown`, `Destination`, and `Metrics` events carry a
`session_id`; destination and metric events also carry `peer` and `event`
fields. Consumers of the earlier tuple variants must update their matches:
`DaemonEvent::Destination { session_id, peer, event }`. Metric event values are
effective merged values, including defaults received during initialization.

On Linux, TCP sends use TTL/hop limit 255, including the connection handshake.
With `gtsm_enforce = true`, the kernel filters lower-TTL traffic and a packet
monitor immediately resets the affected connection. This requires `CAP_NET_RAW`;
missing privileges fail explicitly. The supplied systemd units grant it.
Setting `gtsm_enforce = false` disables TCP receive enforcement for development;
outbound TTL remains 255 and discovery still checks inbound TTL.

The network tests exercise strict enforcement. On Linux, run them in an isolated
network namespace (requires unprivileged user namespaces and `iproute2`):

```sh
unshare --user --map-root-user --net sh -c '
  set -e
  ip link set lo up
  ip link add dlep-test type dummy
  ip addr add 192.0.2.1/24 dev dlep-test
  ip link set dlep-test up multicast on
  ip route add default dev dlep-test
  cargo test --workspace --locked
'
```

This grants capabilities only inside the temporary namespace, without changing
binary capabilities or the host network. See the CI workflow for the privileged
namespace alternative on systems that restrict user namespaces.

## Documentation

- [`doc/architecture.md`](doc/architecture.md) — full architecture document:
  per-crate responsibilities, design decisions, configuration schema, public
  API shape, testing strategy, milestone status and open questions. Read this
  before contributing.
- [RFC 8175] — the protocol specification.

## License

MIT — see [`LICENSE`](LICENSE).
