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
| `events.rs` | `FsmEvent` (inbound: parsed messages, transport lifecycle, timer expiry, app commands), `FsmAction` (outbound: send message, start/cancel timer, reset heartbeat, close TCP, emit public-API event). |
| `timers.rs` | `TimerId` (opaque handle) and `TimerKind` (`Heartbeat`, `HeartbeatMissed`, `SessionInit`, `Termination`, `Transaction(MacAddress)`, `Discovery`). |
| `transaction.rs` | `TransactionTracker` — enforces the RFC rule that at most one session-level request and one per-destination request may be in flight at a time. Violation → `StatusCode::UNEXPECTED_MESSAGE` (129). |
| `session_router.rs` | `RouterSessionFsm` (`Closed → TcpConnecting → SessionInitPending → InSession → Terminating → Terminated`). |
| `session_modem.rs` | `ModemSessionFsm` (`Listening → AwaitingSessionInit → InSession → Terminating → Terminated`). |
| `discovery_router.rs` | `RouterDiscoveryFsm` (`Idle → Probing → OfferReceived`). |
| `discovery_modem.rs` | `ModemDiscoveryFsm` (`Listening → OfferBurst`). |

### 4.3 `dlep-net`

Everything that touches the operating system. Built on Tokio.

| Module | Responsibility |
|---|---|
| `transport.rs` | `Transport` trait (`AsyncRead + AsyncWrite + Unpin + Send + 'static` plus `peer_addr`/`local_addr`/`is_tls`). `Connector` and `Acceptor` produce `Box<dyn Transport>` for either plain TCP or (TODO M7) TLS. |
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
| `events.rs` | Public `DaemonEvent` enum (`PeerDiscovered`, `SessionUp`, `SessionDown`, `Destination`, `Metrics`, `Extension`), plus `DestinationId`, `LinkMetrics`, `PeerInfo`. `DaemonEvent: Clone` (required by `tokio::sync::broadcast`); `Debug` is hand-written because `Arc<dyn Any + Send + Sync>` does not derive `Debug`. |
| `runtime.rs` | Channel plumbing: `EventTx = broadcast::Sender<DaemonEvent>` for the public event bus, `mpsc` for internal commands. `DaemonError` lives here too. |
| `discovery.rs` | `run_discovery` background task: owns a `DiscoverySocket` + a discovery FSM (router or modem), bridges socket I/O to FSM events, applies GTSM filtering on inbound packets, drives periodic Peer_Discovery resends via `DiscoveryTimers`, and translates `EmittedEvent::PeerDiscovered` into `DaemonEvent::PeerDiscovered`. |
| `session.rs` | The `SessionFsm` trait that the runtime drives, with blanket impls for the router and modem session FSMs. |
| `router.rs`, `modem.rs` | `RouterDaemon` / `ModemDaemon` handles plus their builders. Builders take a `Config`, optional rustls config, and any number of extensions. |
| `cli.rs` | Shared CLI helpers used by both binaries: `load_toml_config<T>(Option<&Path>)` and `ConfigLoadError`. |
| `lib.rs` | The public re-export surface. |

### 4.6 `dlep-router` and `dlep-modem`

Thin binaries (~70 lines each). Each one:

1. Parses CLI flags via `clap` (`--config`, `--interface`, `--log-level`, `--no-tls`).
2. Initialises `tracing-subscriber` (with a stderr warning if the requested log level is invalid).
3. Loads configuration via `dlep_daemon::load_toml_config`.
4. Applies CLI overrides (`apply_overrides`).
5. Builds and spawns the daemon.
6. Awaits SIGINT, then calls `daemon.shutdown().await`.

The two binaries differ only in their `Daemon` / `Config` types and in CLI doc strings.

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

The codec **never fails on an unknown Data Item type id**. It only fails on malformed framing (truncated buffer, wrong length, missing `"DLEP"` prefix on a signal). This is the forward-compatibility behaviour required by the RFC.

### 5.3 Bytes-based parsing, no `nom`, no full zero-copy

`dlep-core` uses `bytes::Bytes` and `bytes::BytesMut` directly; `Bytes::split_to` keeps Data Item payloads as zero-copy slices of the original network buffer. We deliberately did not adopt `nom` (its expressive power is overkill for a strictly linear `type/length/value` format) and we did not push borrowed slices into the `DataItem` API (the lifetime would propagate through the FSM and hurt ergonomics). Strings inside Data Items pay one UTF-8-validation copy; everything else is a refcount bump on the underlying `Bytes` allocation.

### 5.4 Hand-rolled FSMs

Each FSM is a plain `enum` state plus a `match`-based `step()` function. We considered the `statig`, `rust-fsm` and `sm` crates and rejected them. DLEP FSMs have nested concerns (heartbeat timers, in-flight transactions) that span multiple "simple" states, so any framework that forces a strict hierarchy ends up bifurcating the logic. A direct `match` is clearer, debuggable, and shorter than the same thing expressed in a DSL.

The four FSMs share `FsmEvent`, `FsmAction`, `TimerId`/`TimerKind`, and `TransactionTracker`.

### 5.5 `Transport` trait, not async-fn-in-trait

`Transport` is `AsyncRead + AsyncWrite + Unpin + Send + 'static` plus three sync inspection methods (`peer_addr`, `local_addr`, `is_tls`). It deliberately has no `async fn` of its own — that means `Box<dyn Transport>` is trivial and the same trait object carries either a `TcpStream` or a `TlsStream<TcpStream>`. The session task only sees `Box<dyn Transport>`; the choice between plain and TLS is made once, at connect/accept time.

### 5.6 Heartbeat reset is centralised

Any successfully decoded `FsmEvent::RecvMessage` causes the FSM to emit `FsmAction::ResetHeartbeat { missed_deadline }`, which the runtime uses to cancel and re-arm the **missed-heartbeat deadline** (the single-shot timer set to `2 × peer_interval` per RFC 8175 §11.2). The send-side periodic heartbeat timer is **independent**: it is armed once at `InSession` entry from our locally-configured `heartbeat_interval_ms` and reschedules itself on each tick — receives don't touch it. The advertised local interval is clamped to RFC 8175's minimum of 1 second, and the codec rejects Heartbeat Interval Data Items below that minimum (`0` is explicitly forbidden by RFC §13.5). The FSM owns `peer_heartbeat_interval: Option<Duration>` extracted from the Heartbeat Interval Data Item in the Session Init / Init Response handshake; `None` means the field was absent. Two consecutive missed intervals — equivalently, one fire of a `2 × interval` deadline — trigger a Session Termination with status code 132.

### 5.7 Transaction serialisation is enforced in one place

`TransactionTracker` (in `dlep-fsm/src/transaction.rs`) is the single source of truth for the rule "at most one session-level request and one per-destination request in flight at a time." Each FSM consults it before sending or before acting on an inbound request; violations always produce a Session Termination with status code 129.

### 5.8 `DaemonEvent::Extension(Arc<dyn Any + Send + Sync>)`

The public event channel is a `tokio::sync::broadcast` — fan-out, lossy on slow consumers. Broadcast requires `T: Clone`, so the extension payload is wrapped in `Arc` (cheap clone, atomic refcount bump) rather than `Box` (would require a deep clone). `Send + Sync` is required because broadcast subscribers can be on different threads. Extensions that need non-`Sync` payloads can wrap in `Mutex`.

### 5.9 TLS is on by default

`use_tls` defaults to `true` in `NetworkConfig::default()` (M7). Embedders that need plain TCP must explicitly set `use_tls = false` in their config — the default is RFC 8175 §10's recommended posture. Daemons configured with `use_tls = true` MUST also call `RouterBuilder::with_rustls_client(...)` / `ModemBuilder::with_rustls_server(...)` before `spawn`; otherwise spawn fails fast with a `DaemonError::Config` error rather than silently downgrading to plaintext. `ServerName::IpAddress` is derived from the connect target's IP; cert SANs must include that IP. Client/server `rustls::ClientConfig` and `rustls::ServerConfig` re-exported from `dlep-net` for one-stop import. A `dlep_net::tls::test_helpers` module (gated by the `test-helpers` feature) generates rcgen-based self-signed certs for integration tests.

### 5.10 GTSM (RFC 5082) primarily on UDP

DLEP requires inbound packets to have TTL/HopLimit = 255 (any lower means the packet was forwarded across an L3 hop). The full enforcement happens on the UDP discovery socket via `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` and `recvmsg`-based cmsg parsing. For TCP, we set TTL = 255 on send and check it once at connection setup; per-segment TTL inspection on TCP would require XDP/eBPF, which is out of scope. This is consistent with the RFC's intent — GTSM is primarily about discovery.

### 5.11 Channels: broadcast for events, mpsc for commands

The public event bus is `tokio::sync::broadcast::Sender<DaemonEvent>` with a fixed capacity (256). Slow subscribers lose old events; consumers that require lossless delivery can mpsc-bridge it themselves. Internal command flow (CLI → daemon → session task) is `mpsc`, single-consumer. Because the session task is the **sole owner and mutator of its FSM**, no locks are needed around the state — concurrency happens only at channel boundaries.

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
    // react to PeerDiscovered, SessionUp, Destination(...), Metrics(...) …
}

daemon.shutdown().await?;
```

The modem-side API is symmetric, with `add_destination`, `update_destination`, `drop_destination`, `announce_destination` taking the place of `start_discovery` / `connect_static`.

---

## 8. Testing strategy

| Layer | Where | What |
|---|---|---|
| Codec roundtrip | `dlep-core/src/codec.rs` (`#[cfg(test)]`) | `encode → decode → ==` for every typed `DataItem`. Hand-rolled byte-vector tests for the dozen most common items. |
| Codec robustness | (planned) | `proptest` strategies for `DataItem` and `Message`; the decoder must never panic on random bytes. |
| FSM transitions | (planned) | Table-driven, in-memory: feed events, assert states and emitted actions. No sockets. |
| FSM end-to-end | (planned) | Pair a router-side FSM with a modem-side FSM through an in-memory bus; replay the canonical happy-path session and several failure modes (heartbeat starvation, two-in-flight). |
| Integration | `dlep-daemon/tests/` (planned) | Two daemons on `127.0.0.1`, plain TCP first, then with `rcgen`-generated TLS. Assert session-up, destination churn, clean shutdown. |
| Conformance | `testdata/pcaps/` (nice-to-have) | Captures from reference implementations parsed read-only. |
| Fuzzing | `cargo-fuzz` (later) | Targets for `Signal::decode` and `Message::decode`. |

CI (`.github/workflows/ci.yml`) runs three parallel jobs: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo build --workspace --all-targets --locked` + `cargo test --workspace --locked`.

---

## 9. Implementation status (high level)

The current state of the tree is the **scaffolding** — types, traits, module layout, FSM enums, codec headers, channels and CLI all in place; `cargo clippy -D warnings` clean; codec roundtrip tests pass. Most function bodies inside the FSM `step()` methods, the `DataItem`-level encode/decode, the discovery socket, and the TLS path are stubs guarded by `TODO (Mn)` markers referencing the milestone they belong to.

The intended order of further work is:

1. Codec — fill in per-variant encode/decode and proptest the roundtrip. **Done.**
2. FSMs — happy-path transitions for both session sides. **Done.**
3. Plain-TCP session over a static peer (loopback integration test). **Done.**
4. Heartbeat timers + missed-deadline termination. **Done.**
5. Destinations and metrics end-to-end. **Done (M5)** — modem→router `Destination_Up`/`Update`/`Down` round-trip, including FSM transitions, daemon command/event plumbing, and the `destination_round_trip_over_loopback` integration test. Out-of-scope follow-ups: `Destination_Announce` (router-initiated query) and `Link_Characteristics_Request`/`Response`.
6. UDP multicast discovery, including GTSM cmsg handling. **Done (M6)** — IPv4 multicast group join, `socket2`-built UDP sockets with TTL=255 outbound (GTSM), cmsg-based inbound TTL extraction via `nix::recvmsg`, router + modem discovery FSMs, and the `discovery_loopback_finds_modem_and_establishes_session` integration test. The router is an *active probe* (sends `Peer_Discovery` to the well-known group from an ephemeral source port; does **not** join the group) — the modem is the only group member and replies with unicast `Peer_Offer` to the discovery's source. Modem-side discovery socket bind is best-effort: a bind failure logs a warning and the modem still spawns (the daemon stays usable for direct `connect_static` callers). Follow-ups: IPv6 discovery, `OfferBurst` retries, decoupling `discovery_v4_group` membership from `bind_addr` so production deployments can pick the interface independently of the TCP bind.
7. TLS via tokio-rustls, then flip the `use_tls` default. **Done (M7)** — `tokio_rustls::TlsConnector` / `TlsAcceptor` wired through `Connector::tls(client_cfg)` / `Acceptor::tls(listener, server_cfg)` factory constructors with private fields; `Transport` implemented for both `tokio_rustls::{client,server}::TlsStream<TcpStream>`; `NetworkConfig::default().use_tls` flipped to `true`; `with_rustls_client(...)` / `with_rustls_server(...)` becomes the required setup step when TLS is on (spawn fails fast otherwise). Cert verification uses `ServerName::IpAddress` derived from the connect target's IP. Verified by the `tls_session_establishes_and_carries_destination_lifecycle` integration test covering handshake plus a destination Up/Down round-trip. **Known follow-up**: `ModemSessionFsm::AppDropDestination` silently no-ops if the preceding `Destination_Up` transaction is still pending; the M7 TLS test mitigates with a 50 ms sleep but a real fix (queue the drop, or surface a busy error) is needed before production. Follow-ups: mutual TLS (client certs), DNS-based `ServerName` resolution, custom certificate verifier hooks, fixing the `AppDropDestination` race.
8. Wire the extension plug-in API and round-trip a private-use ID through a test-only extension.
9. Polish the CLI binaries and document deployment.

---

## 10. Open questions / risks

- **Extension-set negotiation semantics.** RFC 8175 §11.6 phrases the negotiated set ambiguously; cross-reference with the LL-DLEP reference implementation when wiring this.
- **Order of Data Items inside a message.** The RFC says order is not significant, but some implementations are sensitive. We will be lenient on receive and pick a canonical order on send.
- **Per-segment TTL on TCP.** Out of scope; we accept the GTSM-on-UDP-only stance documented above. If a deployment needs it, that is an XDP/eBPF concern.
- **Privileged binding to port 854.** Port 854 is below 1024 and requires `CAP_NET_BIND_SERVICE` on Linux, or running behind an unprivileged user with `setcap cap_net_bind_service=+ep` on the binary, or a systemd unit with `AmbientCapabilities=CAP_NET_BIND_SERVICE`. Document this in the deployment guide once it exists.
- **IPv4 vs IPv6.** Wire encoding handles both from day one (`Ipv4ConnectionPoint` / `Ipv6ConnectionPoint` etc.). Transport-layer dual-stack support arrives in milestone 6 alongside multicast discovery.
- **M4 follow-up: missed-deadline integration test.** The negative-path scenario "peer completes Session Init, then goes silent ⇒ session terminates with `TIMED_OUT` after `2 × interval`" is covered at the FSM-table level (`router_in_session_to_terminating_on_missed_deadline` and the modem analogue) and indirectly by the loopback heartbeat keepalive test, but no integration test drives a real TCP peer that selectively goes silent. Building one requires a partial-DLEP fake-peer harness (~80–120 LOC: hand-encode Init / Init Response, manage a `tokio::net::TcpListener`, race a `tokio::time::sleep` against the missed-deadline). Tracked here so it doesn't get lost.
