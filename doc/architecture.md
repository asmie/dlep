# DLEP Daemon — Architecture

This document describes the architecture of the Rust DLEP (RFC 8175) implementation hosted in this repository: how the codebase is organised, what each module is responsible for, and the design decisions behind those choices.

It is meant to be read end-to-end by a new contributor before touching the code. Implementation details that are obvious from reading the source are deliberately omitted.

---

## 1. What DLEP is, in one paragraph

DLEP (Dynamic Link Exchange Protocol, RFC 8175) is an event-driven protocol that lets a **router** obtain timely link-state and link-quality information from a co-located **modem** (typically a wireless or radio modem). The protocol consists of a UDP-multicast peer discovery phase followed by a long-lived TCP session, over which the modem reports destinations (neighbouring nodes), advertises and updates per-destination metrics (data rate, latency, link quality, MTU, …), and sends heartbeats. DLEP runs over a single Layer-2 segment between exactly one router and one modem; multiple modems attach to a router as separate sessions.

---

## 2. Goals

The implementation aims to:

- Implement both the router side and the modem side from a single code base, so end-to-end testing on a loopback interface is trivial.
- Expose the protocol as a library (`dlep-daemon`) so a third party can embed DLEP into their own networking stack without taking the bundled binaries.
- Keep the wire format and state machines fully tested in isolation (no I/O), so logic bugs are caught without spinning up sockets.
- Provide a stable plug-in API for DLEP extensions (RFC 8175 §13.6 reserves a Private Use range for them).
- Support TLS as a first-class transport, per the RFC's security recommendation.

The implementation deliberately does **not** aim to:

- Implement specific extensions in-tree on day one (the plug-in API is enough).
- Provide its own async runtime — Tokio is a hard dependency of the network layer.
- Run on `no_std` targets — `dlep-core` is conservative about deps but a fully-`no_std` build is not a goal.

---

## 3. Workspace layout

The repository is a Cargo workspace with seven crates under `crates/`:

```
dlep/
├── Cargo.toml                   workspace manifest
├── crates/
│   ├── dlep-core/               wire types, data items, byte-level codec
│   ├── dlep-fsm/                state machines (no I/O, no tokio)
│   ├── dlep-net/                transport: UDP multicast, TCP, TLS, framing
│   ├── dlep-ext/                extension plug-in trait + registry
│   ├── dlep-daemon/             integration layer + public API
│   ├── dlep-router/             router-side daemon binary
│   └── dlep-modem/              modem-side daemon binary
├── doc/                         this document and any future docs
└── .github/workflows/ci.yml     fmt + clippy + build & test
```

The dependency DAG is strictly acyclic; arrows point in the "depends on" direction:

```
dlep-router ─┐
             ├─→ dlep-daemon ─┬─→ dlep-fsm ─┐
dlep-modem  ─┘                ├─→ dlep-net ─┼─→ dlep-core
                              ├─→ dlep-ext ─┘
                              └─→ dlep-core
```

`dlep-core` is the leaf; it has no internal dependencies and is intentionally minimal so it stays cheap to compile and to publish.

---

## 4. Per-crate responsibilities

### 4.1 `dlep-core`

The wire-format crate. Pure data and parsing; depends only on `bytes`, `thiserror` and `ipnet`.

| Module | Responsibility |
|---|---|
| `ids.rs` | Newtypes `SignalType`, `MessageType`, `DataItemType`, `ExtensionId` plus all RFC-assigned constants. |
| `mac.rs` | `MacAddress([u8; 6])` newtype with `Display`. |
| `status.rs` | `StatusCode(u8)` plus the standard Continue (<128) / Terminate (≥128) constants and a `terminates_session()` helper. |
| `data_item.rs` | Typed `DataItem` enum with one variant per RFC data item, plus an `Unknown(RawDataItem)` variant for forward compatibility. |
| `signal.rs`, `message.rs` | The two top-level wire structures (`Signal` for UDP discovery, `Message` for TCP session). |
| `codec.rs` | Byte-level `encode`/`decode` for `RawDataItem`, `Signal` and `Message`. Uses `bytes::Bytes` slicing for zero-copy parsing. Roundtrip unit tests live here. |
| `error.rs` | `CodecError`, the single error type emitted by the codec; implements `From<io::Error>` so the codec plugs into `tokio_util::codec::{Decoder, Encoder}` upstream. |
| `lib.rs` | Re-exports the canonical types and exposes RFC-level constants (`SIGNAL_PREFIX = b"DLEP"`, `DEFAULT_PORT = 854`, IPv4/IPv6 discovery groups). |

### 4.2 `dlep-fsm`

State machines for both the discovery phase and the session phase, on both the router and modem sides. **Pure synchronous logic; no Tokio, no sockets.** Each FSM exposes a single `step(&mut self, FsmEvent) -> Vec<FsmAction>` method.

| Module | Responsibility |
|---|---|
| `addresses.rs` | IPv4/IPv6 peer and destination address/subnet sets, additions/removals, canonical subnet identity, and strict versus tolerant consistency checks. |
| `events.rs` | `FsmEvent` (inbound: parsed messages, transport lifecycle, timer expiry, app commands), `FsmAction` (outbound: send message, start/cancel timer, reset heartbeat, close TCP, emit public-API event). |
| `timers.rs` | `TimerId` (opaque handle) and `TimerKind` (`Heartbeat`, `HeartbeatMissed`, `SessionInit`, `Termination`, `Discovery`). |
| `transaction.rs` | `TransactionTracker` — enforces the RFC rule that at most one session-level request and one per-destination request may be in flight at a time. Violation → `StatusCode::UNEXPECTED_MESSAGE` (129). |
| `session_router.rs` | `RouterSessionFsm` (`Closed → TcpConnecting → SessionInitPending → InSession → Terminating → Terminated`). |
| `session_modem.rs` | `ModemSessionFsm` (`Listening → AwaitingSessionInit → InSession → Terminating → Terminated`). |
| `discovery_router.rs` | `RouterDiscoveryFsm` (`Idle → Probing → OfferReceived`). |
| `discovery_modem.rs` | `ModemDiscoveryFsm` (`Listening → OfferBurst`). |

### 4.3 `dlep-net`

Everything that touches the operating system. Built on Tokio.

| Module | Responsibility |
|---|---|
| `transport.rs` | `Transport` trait (`AsyncRead + AsyncWrite + Unpin + Send + 'static` plus `peer_addr`/`local_addr`/`is_tls`). `Connector` and `Acceptor` produce `Box<dyn Transport>` for either plain TCP or TLS. |
| `tls.rs` | rustls helpers: `load_certs`, `load_private_key`, placeholder `client_config_placeholder`. |
| `framed.rs` | `MessageCodec` and `SignalCodec` — `tokio_util::codec::{Decoder, Encoder}` adapters over the byte-level codec from `dlep-core`. |
| `discovery.rs` | `DiscoverySocket`: builds a UDP/v4 socket via `socket2` with SO_REUSEADDR/REUSEPORT, optional multicast group join, sets IP_TTL=255 and IP_RECVTTL (GTSM), wraps the fd in `AsyncFd`. Sends via `nix::sendto` (both group and unicast); receives via `nix::recvmsg` extracting the inbound TTL from `IP_TTL` cmsg ancillary data so the daemon can drop non-GTSM packets. |
| `gtsm.rs` | RFC 5082 helpers: `REQUIRED_TTL = 255`, `set_send_ttl` (configures IP_TTL/IP_MULTICAST_TTL on `socket2::Socket`), `enable_recv_ttl` (enables IP_RECVTTL via `nix::setsockopt`), `is_gtsm_valid` for inbound checks. |
| `addr.rs` | `InterfaceSpec` (by name / index / any) and `PeerAddr` convenience wrappers. |
| `lib.rs` | Re-exports `MessageCodec`, `SignalCodec`, `Transport`, `Connector`, `Acceptor`, `TransportKind`, plus `rustls::{ClientConfig, ServerConfig}` so consumers have a single import site for TLS configuration. |

### 4.4 `dlep-ext`

The extension plug-in surface. A separate crate so a third-party extension can depend on it (and on `dlep-core`) without dragging in the runtime.

`DlepExtension` is a trait with default-empty hooks for:

- `advertised_ids()` — which `ExtensionId`s the plug-in announces in Session Initialization.
- `on_negotiated(remote_ids)` — accept or opt out of this session based on what the peer advertised.
- `on_unknown_data_item(...)` — receive Data Items the core codec did not recognise.
- `on_unknown_message(...)` — receive Messages with unknown `MessageType`.
- `on_session_state(...)` / `on_destination_state(...)` — observe FSM transitions.

The `ExtensionRegistry` holds `Arc<dyn DlepExtension>` instances and supports advertised-ID union and runtime negotiation.

### 4.5 `dlep-daemon`

The integration layer. Wires `dlep-fsm` + `dlep-net` + `dlep-ext` together and exposes the public `RouterDaemon` / `ModemDaemon` handles. This is what library embedders depend on.

| Module | Responsibility |
|---|---|
| `config.rs` | `RouterConfig`, `ModemConfig`, plus shared `NetworkConfig`, `TlsConfig`, `TimersConfig`. All `serde::Deserialize` for TOML. |
| `events.rs` | Public `DaemonEvent` enum (`PeerDiscovered`, `SessionUp`, `SessionDown`, `Destination`, `Metrics`, `Extension`), plus `DestinationId`, `LinkMetrics`, `PeerInfo`. `SessionUp`, `SessionDown`, `Destination`, and `Metrics` carry both `PeerInfo` and a `SessionId` so a multi-session embedder can attribute events across reconnects. `DaemonEvent: Clone` (required by `tokio::sync::broadcast`); `Debug` is hand-written because `Arc<dyn Any + Send + Sync>` does not derive `Debug`. |
| `runtime.rs` | Channel plumbing: `EventTx = broadcast::Sender<DaemonEvent>` for the public event bus, `mpsc` for internal commands. `DaemonError` lives here too. |
| `discovery.rs` | `run_discovery` background task: owns a `DiscoverySocket` + a discovery FSM (router or modem), bridges socket I/O to FSM events, applies GTSM filtering on inbound packets, drives periodic Peer_Discovery resends via `DiscoveryTimers`, and translates `EmittedEvent::PeerDiscovered` into `DaemonEvent::PeerDiscovered`. |
| `session.rs` | The `SessionFsm` trait that the runtime drives, with blanket impls for the router and modem session FSMs. |
| `router.rs`, `modem.rs` | `RouterDaemon` / `ModemDaemon` handles plus their builders. Builders take a `Config`, optional rustls config, and any number of extensions. |
| `cli.rs` | Shared CLI helpers used by both binaries: `load_toml_config<T>(Option<&Path>)` and `ConfigLoadError`. |
| `lib.rs` | The public re-export surface. |

### 4.6 `dlep-router` and `dlep-modem`

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

---

## 5. Key design decisions

### 5.1 Why a workspace, not a single crate

Splitting into seven crates is more upfront work, but each split serves a purpose:

- **`dlep-core` is a leaf** with minimal dependencies. It is the only place that knows the wire format, and it can be tested without any runtime.
- **`dlep-fsm` cannot accidentally do I/O**, because Tokio is not on its dependency list. This is a structural guarantee: a future contributor cannot, by accident, make a state handler `.await` something. Anything that needs to wait must come back through an `FsmEvent`.
- **`dlep-net` is the only place that uses `tokio`, `rustls`, `socket2` and `nix`**. If we ever swap Tokio for another runtime (unlikely, but conceivable), only one crate changes.
- **`dlep-ext` is tiny on purpose.** A third-party extension only needs to depend on `dlep-core` and `dlep-ext` — it does not pull in the runtime, the network layer, or the binaries.
- **`dlep-daemon` is the integration crate**, used by library embedders. The two binaries depend on it.
- **`dlep-router` and `dlep-modem` are separate binaries** rather than one binary with a `--mode` flag. This keeps each binary's CLI focused and makes deployment (e.g. systemd units, capability scoping) cleaner.

### 5.2 Typed `DataItem` enum + opaque `Unknown` fallback

The decoder produces a fully typed `DataItem` enum, with an `Unknown(RawDataItem)` variant that preserves any item the core codec does not recognise. Downstream code matches exhaustively on the typed variants and gets compile-time errors when a new variant is added; extensions can introspect the `Unknown` items.

The codec preserves unknown Data Items for extension dispatch and validates framing, lengths, and value ranges. The session layer rejects unclaimed unknown items with `INVALID_DATA` under RFC 8175 §12.1, except for the initialization exception for unrecognized advertised extensions. Unknown items are not silently accepted in an established session.

### 5.3 Bytes-based parsing, no `nom`, no full zero-copy

`dlep-core` uses `bytes::Bytes` and `bytes::BytesMut` directly; `Bytes::split_to` keeps Data Item payloads as zero-copy slices of the original network buffer. We deliberately did not adopt `nom` (its expressive power is overkill for a strictly linear `type/length/value` format) and we did not push borrowed slices into the `DataItem` API (the lifetime would propagate through the FSM and hurt ergonomics). Strings inside Data Items pay one UTF-8-validation copy; everything else is a refcount bump on the underlying `Bytes` allocation.

### 5.4 Hand-rolled FSMs

Each FSM is a plain `enum` state plus a `match`-based `step()` function. We considered the `statig`, `rust-fsm` and `sm` crates and rejected them. DLEP FSMs have nested concerns (heartbeat timers, in-flight transactions) that span multiple "simple" states, so any framework that forces a strict hierarchy ends up bifurcating the logic. A direct `match` is clearer, debuggable, and shorter than the same thing expressed in a DSL.

The four FSMs share `FsmEvent`, `FsmAction`, `TimerId`/`TimerKind`, and `TransactionTracker`.

### 5.5 `Transport` trait, not async-fn-in-trait

`Transport` is `AsyncRead + AsyncWrite + Unpin + Send + 'static` plus three sync inspection methods (`peer_addr`, `local_addr`, `is_tls`). It deliberately has no `async fn` of its own — that means `Box<dyn Transport>` is trivial and the same trait object carries either a `TcpStream` or a `TlsStream<TcpStream>`. The session task only sees `Box<dyn Transport>`; the choice between plain and TLS is made once, at connect/accept time.

### 5.6 Heartbeat reset is centralised

A valid in-session core message or a message consumed by a negotiated extension causes the FSM to emit `FsmAction::ResetHeartbeat { missed_deadline }`, which the runtime uses to cancel and re-arm the **missed-heartbeat deadline** (the single-shot timer set to `2 × peer_interval` per RFC 8175 §11.2). The send-side periodic heartbeat timer is **independent**: it is armed once at `InSession` entry from our locally-configured `heartbeat_interval_ms` and reschedules itself on each tick — receives don't touch it. The advertised local interval is clamped to RFC 8175's minimum of 1 second, and the codec rejects Heartbeat Interval Data Items below that minimum (`0` is explicitly forbidden by RFC §13.5). The FSM owns `peer_heartbeat_interval: Option<Duration>` extracted from the Heartbeat Interval Data Item in the Session Init / Init Response handshake; `None` is valid only before initialization; a missing mandatory heartbeat interval rejects initialization. Two consecutive missed intervals — equivalently, one fire of a `2 × interval` deadline — trigger a Session Termination with status code 132.

### 5.7 Transaction serialisation is enforced in one place

`TransactionTracker` (in `dlep-fsm/src/transaction.rs`) is the single source of truth for the rule "at most one session-level request and one per-destination request in flight at a time." Each FSM consults it before sending or before acting on an inbound request; violations always produce a Session Termination with status code 129.

### 5.8 `DaemonEvent::Extension(Arc<dyn Any + Send + Sync>)`

The public event channel is a `tokio::sync::broadcast` — fan-out, lossy on slow consumers. Broadcast requires `T: Clone`, so the extension payload is wrapped in `Arc` (cheap clone, atomic refcount bump) rather than `Box` (would require a deep clone). `Send + Sync` is required because broadcast subscribers can be on different threads. Extensions that need non-`Sync` payloads can wrap in `Mutex`.

### 5.9 TLS is on by default

`use_tls` defaults to `true` in `NetworkConfig::default()` (M7). Embedders that need plain TCP must explicitly set `use_tls = false` in their config — the default is RFC 8175 §10's recommended posture. Daemons configured with `use_tls = true` MUST also call `RouterBuilder::with_rustls_client(...)` / `ModemBuilder::with_rustls_server(...)` before `spawn`; otherwise the modem fails during spawn and the router fails when connecting with a `DaemonError::Config` error. `ServerName::IpAddress` is derived from the connect target's IP; cert SANs must include that IP. Client/server `rustls::ClientConfig` and `rustls::ServerConfig` re-exported from `dlep-net` for one-stop import. A `dlep_net::tls::test_helpers` module (gated by the `test-helpers` feature) generates rcgen-based self-signed certs for integration tests.

### 5.10 GTSM (RFC 5082)

IPv4 UDP discovery sends with TTL 255 and checks received TTL through ancillary
data. TCP sockets set TTL/hop limit 255 before connecting or listening. On Linux,
`gtsm_enforce` additionally configures `IP_MINTTL` / `IPV6_MINHOPCOUNT` so the
kernel rejects lower-TTL TCP segments, including handshake traffic. Other
platforms fail explicitly when TCP enforcement is requested.

Linux does not surface minimum-TTL drops through the stream API. The transport
therefore opens an `AF_PACKET` monitor before accepting/connecting, requiring
`CAP_NET_RAW`. It matches incoming TCP tuples (including IPv6 scope and mapped
IPv4 addresses) and aborts an affected connection using Linux's `AF_UNSPEC`
disconnect. This sends RST, wakes the session task, and triggers its normal
`SessionDown` cleanup. The monitor remains active during TLS negotiation and is
released with the connection/listener. Setup failures are explicit; a monitor
read failure resets all its registered connections. The systemd examples grant
the capability; network tests run in an isolated network namespace.

### 5.11 Channels: broadcast for events, mpsc for commands

The public event bus is `tokio::sync::broadcast::Sender<DaemonEvent>` with a fixed capacity (256). Slow subscribers lose old events; consumers that require lossless delivery can mpsc-bridge it themselves. Internal command flow (CLI → daemon → session task) is `mpsc`, single-consumer. Because the session task is the **sole owner and mutator of its FSM**, no locks are needed around the state — concurrency happens only at channel boundaries.

### 5.12 Extension dispatch ordering

Extensions are dispatched per session by the session task. Their lifecycle:

1. At `spawn` time, the registry's union of `advertised_ids()` is stamped into `SessionConfig.advertised_extensions` and goes onto the wire in `ExtensionsSupported`.
2. On the inbound `Session Initialization` (modem) or `Session Initialization Response` (router), the FSM extracts the peer's `ExtensionsSupported` into `peer_extensions` and emits `EmittedEvent::SessionUp { peer_extensions }`.
3. The registry activates only plugins whose nonempty advertised ID set is supported by the peer and whose negotiation callback accepts the session. A plugin implementing independent extensions can register separate instances if it needs partial negotiation.
4. The public `SessionUp` event is emitted before `on_session_state(up=true)` runs.
5. In-session unknown messages and items are first offered to negotiated extensions. Unclaimed input reaches the FSM's strict validation; handled messages reset the peer-silence deadline. Extension callbacks do not process terminating-session traffic.
6. Destination lifecycle events notify `on_destination_state`; the router also surfaces successful Announce responses as destination arrivals.
7. A lifecycle guard emits exactly one `SessionDown` and extension teardown callback on ordinary termination, I/O failure, or task cancellation. Codec failures initiate protocol termination; writes have a bounded deadline.


---

## 6. Configuration

Configuration is a TOML file passed via `--config`. Both binaries share a `SharedConfig` (network, TLS, timers) and add their own role-specific bits:

```toml
[network]
interface           = "eth0"
discovery_v4_group  = "224.0.0.117"
discovery_v6_group  = "ff02::1:7"
discovery_port      = 854
tcp_port            = 854
use_tls             = true
gtsm_enforce        = true

[tls]
cert                 = "/etc/dlep/server.pem"
key                  = "/etc/dlep/server.key"
ca_bundle            = "/etc/dlep/ca.pem"
require_client_cert  = true

[timers]
heartbeat_interval_ms = 60000
discovery_interval_ms = 5000

# router only
mode         = "discovery"          # or "static"
static_peers = ["10.0.0.1:854"]

# modem only
peer_description = "example-modem"
```

The configuration types live in `dlep-daemon/src/config.rs`. The IANA-assigned multicast groups (`224.0.0.117`, `ff02::1:7`) and default port (`854`) are hard-coded constants in `dlep-core/src/lib.rs` and used as the `Default` for `NetworkConfig`.

---

## 7. Public API shape

A library embedder uses `dlep-daemon` like this (router side):

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

The modem-side API is symmetric, with `add_destination`, `update_destination` and `drop_destination` taking the place of `start_discovery` / `connect_static`.

Only the modem can originate metric changes via `update_session_metrics`. The router compatibility method returns an error; router Session Update payloads are restricted to Layer 3 information. `announce_destination` is **router-side only**, because RFC 8175 §12.13 makes `Destination Announce` router-originated — the modem receives it, answers per §12.14, and surfaces it to its application as `DestinationEvent::Announced`.

---

## 8. Testing strategy

The suite is **209 tests**, all passing, with `clippy -D warnings` clean.

| Layer | Where | What |
|---|---|---|
| Codec roundtrip | `dlep-core/src/codec.rs` (`#[cfg(test)]`) | `encode → decode → ==` for every typed `DataItem`. Hand-rolled byte-vector tests for the dozen most common items. |
| Codec robustness | `dlep-core/tests/codec_proptest.rs` | `proptest` strategies for `DataItem` and `Message`; the decoder must never panic on random bytes. |
| FSM transitions | `dlep-fsm/tests/session_table.rs`, `discovery_table.rs` | Table-driven, in-memory: feed events, assert states and emitted actions. No sockets. Owns the transaction-slot lifecycle assertions, which are racy to observe from an integration test. |
| Integration | `dlep-daemon/tests/loopback.rs`, `tls.rs`, `discovery.rs`, `extensions.rs` | Two daemons on `127.0.0.1`, plain TCP and `rcgen`-generated TLS (incl. mTLS). Assert session-up, destination churn, Session Update, Destination Announce, clean shutdown. |
| FSM end-to-end | (partly covered by the loopback integration tests) | A dedicated in-memory router↔modem FSM bus was never needed; the loopback tests cover the same ground over real sockets. A fake-peer harness is still wanted for selective-silence timeout scenarios — see §10. |
| Conformance | `testdata/pcaps/` (nice-to-have) | Captures from reference implementations parsed read-only. |
| Fuzzing | `cargo-fuzz` (later) | Targets for `Signal::decode` and `Message::decode`. Not yet present; the codec proptests cover much of the same ground. |

CI (`.github/workflows/ci.yml`) runs three parallel jobs: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo build --workspace --all-targets --locked` + `cargo test --workspace --locked`.

---

## 9. Implementation status (high level)

The implementation is **not yet complete for RFC 8175**. The initial 209-test suite validated many happy paths but missed interoperability and failure-path defects. The current review adds strict message/transaction validation, fatal-status echoing, metric merging, destination Announce state, continuous discovery with usable unicast endpoints, bounded concurrent TLS handshakes, session error cleanup, and peer/session attribution for application events. Remaining feature gaps are tracked separately below. Strict TCP GTSM now uses a privileged Linux packet monitor.

The order of work was:

1. Codec — fill in per-variant encode/decode and proptest the roundtrip. **Done.**
2. FSMs — happy-path transitions for both session sides. **Done.**
3. Plain-TCP session over a static peer (loopback integration test). **Done.**
4. Heartbeat timers + missed-deadline termination. **Done.**
5. Destinations and metrics end-to-end. **Done (M5)** — modem→router `Destination_Up`/`Update`/`Down` round-trip, including FSM transitions, daemon command/event plumbing, and the `destination_round_trip_over_loopback` integration test. Out-of-scope follow-ups: `Destination_Announce` (router-initiated query) and `Link_Characteristics_Request`/`Response`.
6. UDP multicast discovery, including GTSM cmsg handling. **Done (M6)** — IPv4 multicast group join, `socket2`-built UDP sockets with TTL=255 outbound (GTSM), cmsg-based inbound TTL extraction via `nix::recvmsg`, router + modem discovery FSMs, and the `discovery_loopback_finds_modem_and_establishes_session` integration test. The router is an *active probe* (sends `Peer_Discovery` to the well-known group from an ephemeral source port; does **not** join the group) — the modem is the only group member and replies with unicast `Peer_Offer` to the discovery's source. Modem-side discovery socket bind is best-effort: a bind failure logs a warning and the modem still spawns (the daemon stays usable for direct `connect_static` callers). Follow-ups: IPv6 discovery, `OfferBurst` retries, decoupling `discovery_v4_group` membership from `bind_addr` so production deployments can pick the interface independently of the TCP bind.
7. TLS via tokio-rustls, then flip the `use_tls` default. **Done (M7)** — `tokio_rustls::TlsConnector` / `TlsAcceptor` wired through `Connector::tls(client_cfg)` / `Acceptor::tls(listener, server_cfg)` factory constructors with private fields; `Transport` implemented for both `tokio_rustls::{client,server}::TlsStream<TcpStream>`; `NetworkConfig::default().use_tls` flipped to `true`; `with_rustls_client(...)` / `with_rustls_server(...)` becomes the required setup step when TLS is on (spawn fails fast otherwise). Cert verification uses `ServerName::IpAddress` derived from the connect target's IP. Verified by the `tls_session_establishes_and_carries_destination_lifecycle` integration test covering handshake plus a destination Up/Down round-trip. The Drop/Up race now returns an explicit Busy error; TLS tests retry on that result rather than waiting a guessed 50 ms. Follow-ups: DNS-based `ServerName` resolution and custom certificate verifier hooks.
8. Wire the extension plug-in API and round-trip a private-use ID through a test-only extension. **Done (M8)** — `ExtensionRegistry` is now plumbed from `RouterBuilder`/`ModemBuilder` into each session task; `SessionConfig.advertised_extensions` is populated from `registry.advertised()` and shows up in the `ExtensionsSupported` data item of `Session Initialization` / `Session Initialization Response`; both FSMs capture the peer's advertised IDs into `peer_extensions` and surface them via `EmittedEvent::SessionUp { peer_extensions }`; the daemon computes `negotiated_extensions = advertised_local ∩ peer_extensions` for `DaemonEvent::SessionUp`. The session task routes inbound messages with an unknown `MessageType` through `on_unknown_message`, dispatches `DataItem::Unknown` items inside known messages through `on_unknown_data_item`, and drives `on_session_state` / `on_destination_state` on lifecycle transitions. Verified by the `private_use_extension_round_trips_session_init_and_unknown_message` integration test (Private-Use `ExtensionId(0xF000)` + `MessageType(0xF000)`). Follow-ups: extension-driven Session Termination, per-extension config plumbing, extensions over the UDP discovery socket, and an "ask FSM to terminate" hook.
9. Polish the CLI binaries and document deployment. **Done (M9)** — the binaries build rustls configs from the TOML `[tls]` section via `dlep_daemon::tls::{client_config, server_config}`: the router requires `ca_bundle` (private PKI; no system-roots fallback) and presents `cert`+`key` as its mTLS identity when set; the modem requires `cert`+`key` and, with `require_client_cert = true`, enforces client certificates through `WebPkiClientVerifier` — closing the mutual-TLS follow-up from M7. New flags: `--cert` / `--key` / `--ca-bundle` overrides, `--check-config` (validates TOML shape, static peers and TLS material via `check_router_config` / `check_modem_config`, then exits), and the router's repeatable `--peer` (implies static mode). The router binary gained its missing run loop: static peers connect at startup, discovery mode auto-connects on `PeerDiscovered` (deduplicated by address). `NetworkConfig` is now `#[serde(default)]` so partial `[network]` sections parse, and the `[network]`/`[tls]`/`[timers]` sections reject unknown keys. Deployment guide at `doc/deployment.md` (private-CA openssl walkthrough, port-854 privileges, firewall/GTSM, systemd) plus working artifacts in `examples/` (TOML configs, hardened systemd units with a static `dlep` user). Verified by the `mtls_session_requires_and_accepts_client_certificate` / `mtls_modem_rejects_client_without_certificate` integration tests and an end-to-end smoke run with openssl-issued certificates. Follow-ups: `--tcp-port`/`--bind-addr` overrides, shell completions, packaging, reconnect-on-drop for the router's run loop.
10. Close the RFC-conformance gaps a post-M9 audit turned up. **Done (M10)** — three defects, all of which had survived because nothing in the tree exercised them:
    - **`Session Update` / `Session Update Response` (RFC 8175 §12.7-12.8) were entirely absent.** Neither FSM had an arm, so an inbound `Session Update` fell through the `InSession` catch-all: the missed-heartbeat deadline was reset and the message was then dropped **without the mandatory Response** ("A Session Update Response Message MUST be sent … when a Session Update Message is received"). Both FSMs acknowledge valid Session Updates and close matching transactions. The subsequent review corrected the original interpretation of §12.7: only modem-originated updates may contain metrics. Inbound session-wide metrics now surface as `DaemonEvent::Metrics`, which had been a defined-but-never-constructed variant.
    - **`Destination Announce` was on the wrong role.** `ModemDaemon::announce_destination` existed, took a MAC, discarded it and returned `Ok(())` — a public method that silently did nothing, advertised in both the README and §7. But §12.13 makes Destination Announce *router*-originated ("MAY be sent by a router to announce such an interest"), and §12.14 obliges the *modem* to answer it. The no-op is gone; `RouterDaemon::announce_destination` sends the message under a per-destination transaction, and the modem answers and emits `DestinationEvent::Announced` (another previously-dead variant) so its application can decide whether to follow up with a `Destination_Up`. A malformed announce with no MAC now terminates the session with Invalid Data.
    - **The router binary could never reconnect.** `run_event_loop` inserted each peer into a `connected` dedup set and never removed it, and the `SessionDown` arm only logged, so a modem restart orphaned the router until the process was restarted — re-discovery hit the dedup `continue` and was skipped forever. The root cause was an API gap: `DaemonEvent::SessionDown` carried only a `StatusCode`, so the loop could not tell *which* peer had dropped. `SessionDown` now carries `PeerInfo`, and the loop evicts the dead peer and re-dials it via a `ReconnectQueue` (1 s base, doubling, 30 s cap; `forget` on `SessionUp` so each drop starts a fresh sequence). The queue takes its clock as a parameter, so the backoff is unit-tested without sleeping.

    Follow-ups: IPv6 discovery; a modem backend capable of applying requested link changes. Session-wide metric configuration and support declarations are implemented below. Commands rejected by busy transactions now return explicit errors, as described below.

11. **Link Characteristics Request/Response (RFC 8175 §12.18–12.19).**
    The router API targets one session and accepts optional receive rate,
    transmit rate, and latency changes (at least one is required). Requests
    occupy a per-destination transaction slot until a response or session reset,
    without an independent deadline (RFC §8). Responses update stored metrics
    and emit a session-attributed `DestinationEvent::LinkCharacteristicsResponse`
    containing status, text, and metrics. The router requires the complete set
    of core metrics declared by that peer during initialization. The modem
    currently has no link-control backend, so it immediately replies Request
    Denied with the current destination metrics. It does not fabricate a
    successful physical link change. Tests cover denial and success replies,
    missing/undeclared metrics, serialization across destinations, responses
    delayed for minutes while the peer remains active, heartbeat-based failure
    detection, and targeting modems sharing a MAC.

12. **Router-originated Destination Down (RFC 8175 §12.15–12.16).**
    `RouterDaemon::drop_destination(session_id, destination)` withdraws interest
    from a single modem. The router keeps the destination through the pending
    exchange to accept updates already in transit, then removes it and emits
    Down when the matching response arrives. The modem sends Success, stops
    reporting the destination on that session, and emits its own Down event.
    It retains physical-link knowledge so a later Announce can restore reports
    with current metrics and addresses. No independent Down transaction timeout
    is used; peer failure is detected through the session heartbeat. Tests cover
    both Up- and Announce-originated destinations, resubscription, in-flight
    updates, conflicting transactions, invalid input, and session isolation.

13. **Layer 3 address and attached-subnet changes (RFC 8175 §13.8–13.11).**
    `AddressChanges` separates additions and removals for all four item types.
    Both FSMs retain addresses learned during initialization and apply peer
    Session Updates atomically. Duplicate peer additions and unknown peer
    removals terminate with Invalid Data. Destination inconsistencies are
    nonfatal: duplicate additions, unknown removals, contradictory operations,
    and attempts to claim another destination's or the peer's addresses are
    ignored while valid changes and metrics continue. Subnet identity uses its
    network prefix, independent of host bits in the encoded address.

    The modem API can advertise initial destination addresses and subsequent
    changes; both daemons can originate session address changes. Address-only
    updates preserve metrics. Pending Up address changes coalesce until its
    acknowledgement; withdrawn destinations retain their latest local snapshot
    for Announce. Applications receive explicit deltas plus full snapshots via
    `DestinationEvent::AddressesChanged` and `DaemonEvent::SessionAddresses`.
    Announce request address hints, including removals, are available in
    `DestinationEvent::Announced.requested_addresses`. Every event carries its
    peer/session context. Tests cover all four families, initialization,
    consistency errors, delayed acknowledgement, resubscription, both session
    directions, and identical address sets on different modem sessions.

14. Configurable session metrics and optional metric support. **Done** —
    `ModemConfig.metrics` / TOML `[metrics]` supplies initialization values;
    `SessionConfig.initial_metrics` is the equivalent FSM API. Mandatory rates
    and latency default to zero; optional Resources, both Relative Link Quality
    fields, and MTU default to unsupported. `LinkMetrics` represents optional
    values with `Option`, distinguishing omission from explicit zero.

    The modem validates configuration before opening sockets and validates
    metric commands before enqueueing. Optional metric support stays fixed for
    each session. The router checks all subsequent metric-bearing messages
    against that declaration and terminates on undeclared items. Destination
    and session updates merge supplied fields, retaining omitted optional
    values; newly added destinations inherit current session defaults.
    Link Characteristics replies use the complete effective metric set.
    Tests cover mixed support, explicit zero, default inheritance, partial
    updates, pending Up updates, invalid input without state mutation, and
    configured values reaching the application through real sessions.

15. Explicit command acceptance. **Done** — both session FSMs preflight local
    commands before mutating state and emit structured `CommandRejected` events
    for busy transactions, non-established sessions, unknown/duplicate
    destinations, wrong-role commands, and invalid values. Shutdown bypasses
    serialization. Metric/address updates during Up remain retained; updates
    during Down return Busy because that destination is about to be removed.

    Daemon command channels carry `SessionRequest` envelopes with optional
    oneshot receipts. Public calls await local acceptance and action processing,
    without waiting for a wire response or imposing a transaction timeout.
    Broadcast errors report accepted/rejected session IDs plus undelivered and
    unknown-outcome counts. `send_command_to` permits retrying one rejected
    session without replaying a partial broadcast. Stale session IDs and empty
    session lists return `NoMatchingSession`. Cancellation after enqueue can
    leave an unknown outcome; it does not cancel a protocol transaction.

    Tests hold real peer acknowledgements to prove Busy, retry, and shutdown
    behavior, check multi-session partial results and targeted retries, and
    distinguish closed channels from lost receipts. TLS lifecycle tests use
    explicit Busy retries. No unbounded command queue is introduced.

---

## 10. Open questions / risks

- **Extension negotiation.** Plugins now require mutual support for their advertised IDs; callbacks cannot override that requirement.
- **Order of Data Items inside a message.** The RFC says order is not significant, but some implementations are sensitive. We will be lenient on receive and pick a canonical order on send.
- **Privileged binding to port 854.** Port 854 is below 1024 and requires `CAP_NET_BIND_SERVICE` on Linux, or running behind an unprivileged user with `setcap cap_net_bind_service=+ep` on the binary, or a systemd unit with `AmbientCapabilities=CAP_NET_BIND_SERVICE`. Documented in `doc/deployment.md` §4 (M9).
- **IPv4 vs IPv6.** Wire encoding handles both from day one (`Ipv4ConnectionPoint` / `Ipv6ConnectionPoint` etc.), and the GTSM helpers in `dlep-net/src/gtsm.rs` already have `IPV6_UNICAST_HOPS` / `IPV6_MULTICAST_HOPS` paths. **The discovery transport is still IPv4-only**: `dlep-net/src/discovery.rs` contains no IPv6 code, so `NetworkConfig::discovery_v6_group` is currently a dead config key — it parses and is then read by nothing. Setting it silently does nothing, which is worse than rejecting it; wiring v6 discovery (or rejecting the key until then) is outstanding work.

- **Heartbeat failure coverage.** `silent_peer_is_detected_by_heartbeat_while_request_is_pending` uses an independent TCP peer that completes initialization, starts a destination transaction, and then goes silent. It verifies termination and `SessionDown(TIMED_OUT)`. A virtual-time transport test verifies that a response delayed for three minutes is accepted while the peer continues communicating.
