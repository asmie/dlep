# Changelog

## Unreleased

- Extensions can opt in to pre-session discovery hooks on both daemon roles.
  Plugins can append bounded TLVs to Peer Discovery/Peer Offer signals and
  inspect validated incoming items/signals with datagram metadata. Core fields,
  GTSM/interface filtering, connected-router suppression, and TCP negotiation
  remain intact. Unclaimed unknown items discard the datagram. Existing plugins
  and the original low-level discovery runner retain their default behavior.
- Embedders can register configured extension factories on both daemon builders,
  or supply an ordered `ExtensionCatalog`. Factories consume `[extensions.NAME]`
  tables before networking, with plugin-owned validation and defaults. Matching
  config-check helpers validate against the application's catalog. Unused
  settings and invalid/duplicate factory names fail early; bundled commands
  reject settings without registered factories before adapters or networking.
  Prebuilt extension registration is unchanged. `SharedConfig` gains an
  `extensions` map; full Rust struct initializers need that field or a default.
- Negotiated extensions can call `ExtensionCtx::terminate_session(reason)` from
  in-session hooks. The runtime drives the existing FSM termination exchange
  and deadline, discards queued extension messages, and preserves session-scoped
  cleanup. The first accepted request wins; protocol-error/closing transitions
  retain precedence. Session-down hooks reject requests, and the default method
  reports `Unsupported` so existing custom contexts continue to compile.
- Router `--peer` and TOML `static_peers` accept DNS names with explicit ports.
  Retries resolve names afresh while preserving hostname-based TLS verification
  and SNI, bounded fallback, connection limits, and exponential backoff. Duplicate
  entries and overlapping aliases cannot open duplicate endpoint sessions.
  `--check-config` validates names without DNS queries. Numeric Rust peers stay
  in `RouterConfig.static_peers`; DNS peers use the new `named_peers` field, and
  serialization combines both lists. Manual full Rust struct initializers need
  to supply that field or use `..RouterConfig::default()`.
- Library routers can connect to DNS peers with `connect_named(host, port)` or
  verify an explicit TLS identity at a numeric address with
  `connect_static_with_server_name(addr, name)`. Named connections preserve the
  requested hostname across address fallback, with 16-address/15-second bounds
  and one shared connection slot. Numeric connections retain IP verification.
  CLI/configuration support includes name-aware retries as described above.
- All commands can print Bash, Elvish, Fish, PowerShell, and Zsh completion
  scripts with `--generate-completions SHELL`. Scripts use the actual CLI
  definitions, including both roles in the combined launcher. Generation exits
  before configuration, logging, or networking setup.
- Modems can set top-level `secured_medium` (default false) to advertise RF-medium
  access control in Peer Offers and initialization responses. Routers expose the
  received flag in discovery/session metadata, snapshots, and adapter `session`
  records, independently of TLS. `PeerInfo` and `PeerOffer` gain an optional
  `secured_medium` field; manual Rust struct initializers must supply it.
- Routers support a startup `[destinations]` admission policy with default
  acceptance and MAC allow/deny lists. Declined Destination Up announcements
  receive Not Interested and do not enter router state. Explicit Announce
  requests can still express interest in a previously declined destination.
  Configuration checks reject invalid, conflicting, or wrong-format entries.
- Both CLIs now accept `--bind-addr` and `--discovery-port` overrides; the modem
  also accepts `--tcp-port`, including zero for an allocated listen port. These
  override TOML for startup and `--check-config`, including through `dlep router`
  and `dlep modem`. Router TCP endpoints retain their configured/offered ports.
- Session fuzzing can now hold encoded peer messages and deliver them later in
  each direction's original order. New seeds and harness checks exercise metric
  coalescing, desired-address corrections, pending destination changes, and link
  replies while acknowledgements remain queued.
- Session fuzzing now generates structured metrics, IPv4/IPv6 address changes,
  Announce hints, and link-characteristic requests/replies, including deferred
  replies and invalid command recovery. A harness test verifies that generated
  commands reach address updates and successful link completion for both MAC
  formats before CI fuzzes them.
- Added a TCP message-framing fuzz target that compares fragmented/coalesced
  reads with whole-buffer decoding, including malformed frames, incomplete EOF,
  and maximum message lengths. CI now fuzzes the network codec alongside core
  decoding and the session/discovery FSMs.
- Fuzz CI explicitly selects the runner's GNU target, fixing startup failures
  when the installed cargo-fuzz binary defaults to its musl build platform.
- Discovery offers now remove equivalent endpoints even when another candidate
  separates them, preserving TLS/IPv6 preference and within-class order.
  Omitted port 854 and explicit port 854 no longer cause duplicate connection
  attempts. Different TLS requirements remain distinct. A new discovery FSM fuzz
  target checks endpoint uniqueness, filtering, scope, and request/offer behavior.
- Added separate cargo-fuzz targets for message/signal/Data Item decoding and
  bounded router/modem session event sequences. Deterministic seeds, nightly
  AddressSanitizer CI smoke runs, and corpus/failure artifacts support longer
  local campaigns without changing the release workspace or its Rust minimum.
- Independent dlepard checks now discover our modem over IPv4 multicast and
  complete both termination directions without a configured TCP endpoint.
  The harness configures multicast TTL 255 and local loopback on the upstream
  socket. UDP captures verify reply ports and the advertised connection point.
  Separate IPv4/IPv6 probes document the pinned LL-DLEP modem's incompatible
  discovery reply ports; those probes are not successful session scenarios.
- Independent LL-DLEP modem checks now run over IPv4 and scoped link-local IPv6
  TCP, including both termination directions, address changes, and Announce
  success/denial. The capture parser verifies both IP families, TTL/hop limits,
  and matching peer addresses; twelve regression tests cover malformed and
  incomplete evidence. Discovery and TLS interoperability remain unverified.
- The lockfile updates the test-only `rustix` dependency to 1.1.6 for
  [RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html).
  Rust 1.85 remains supported; the existing guarded `time` exception is unchanged.
- Release archive checks compare every packaged library, binary, example, and
  test target with the source workspace before compiling and installing. Missing
  or changed targets fail validation. CI invokes its capture-parser and archive
  inventory tests explicitly, so an omitted test file cannot silently pass as
  an empty test suite.
- Independent-peer checks now cover address data and Destination Announce.
  The pinned LL-DLEP modem exercises IPv4/IPv6 address and subnet replacements
  and removals, bidirectional session updates, withdrawal/re-announcement with
  address hints, and denied requests. The pinned dlepard router checks supported
  IPv4 initialization and Destination Up fields; its unsupported address-update
  and Announce behaviors are explicitly documented. Shared capture checks verify
  exact address flags/values and reject incomplete evidence. Both peers remain
  unmodified, with static IPv4 plaintext transport and strict GTSM.
- Destination Announce can carry IPv4/IPv6 address hints through optional
  `add`/`remove` objects on router adapter commands. Radio `destination_announced`
  notices expose both objects, including empty sets and denied requests. Hints
  preserve physical destination and session addresses; invalid, duplicate,
  conflicting, oversized, or attached-subnet hints are rejected before sending.
  `RouterDaemon::announce_destination_with_addresses` exposes the targeted
  library API. Existing MAC-only commands still work; exhaustive matches must
  handle the new `SessionCommand::AnnounceDestinationWithAddresses` and
  `FsmEvent::AppAnnounceDestinationWithAddresses` variants.
- Radio adapters can report modem `session_addresses` using optional `add` and
  `remove` objects. The bridge retains a validated complete set without routers,
  updates every connected router, coalesces busy updates, and replays addresses
  on new sessions. Invalid or oversized reports preserve cached and live state;
  large replacements use multiple acknowledged updates. Address reports preserve
  destination withdrawals and link grants. Existing `session_update_response`
  notices report wire completion, and `session_sync` still describes remote
  router addresses.
- `ModemDaemon::set_session_addresses` retains a complete desired address set
  per session, coalesces replacements while busy, and sends fitting changes
  after each response. Large replacements remove addresses before adding new
  ones across acknowledged Session Updates; queued metrics share the next
  update while preserving later destination values. Invalid or oversized sets
  leave accepted state intact. `validate_session_addresses` validates replay
  state without requiring a connected peer.
- Library `SessionSnapshot` adds `local_addresses`, including queued desired
  modem addresses; existing adapter address fields still describe remote peers.
  Exhaustive snapshot literals and matches on the new
  `SessionCommand::SetSessionAddresses` / `FsmEvent::AppSetSessionAddresses`
  variants need updating. Existing delta-based address methods still return
  Busy; nonfatal refusals do not roll back local addresses.
- Radio `session_sync` entries include each router's complete IPv4/IPv6 address
  and subnet sets. Address changes refresh the snapshot even when membership
  is unchanged. Retained state restores addresses after event loss and on
  `resync`, without replaying destinations or applying stale address events.
- Router adapters can advertise local IPv4/IPv6 addresses and attached subnets
  through targeted `session_addresses` commands with `add`/`remove` deltas.
  Commands validate and canonicalize addresses, share request-ID deduplication,
  and report local acceptance separately from `session_update_response` peer
  completion. Unchanged deltas send no update; busy sessions reject commands.
  Existing snapshots continue to expose remote peer addresses.
- Radio adapters can send `{"type":"resync"}` to request fresh `session_sync`
  membership, even when unchanged or empty. Refresh preserves established
  sessions, router withdrawals, link grants, and pending requests without
  producing a synthetic event-gap notice or replaying existing destinations.
- Radio adapters receive `event_gap` with the number of lost daemon events,
  followed by `session_sync` even when membership is unchanged. Recovery reads
  retained membership after output backpressure and preserves existing router
  withdrawals, cached destinations, and link requests. Lost command outcomes
  remain unknown; the membership notice does not reconstruct their history.
- Both daemon roles expose validated, nonfatal Destination Down replies through
  `DestinationEvent::DownResponse`, including peer status text. Routers retain
  their preceding `Down` event and forward `down_response` adapter notices;
  modems emit completion without a withdrawal event and forward
  `destination_down_response` to radio adapters. Delayed notices preserve a
  replacement destination and its replay cache. Exhaustive matches must handle
  the new daemon event and FSM `EmittedEvent::DestinationDownResponse` variant.
- Both daemon roles expose validated, nonfatal Session Update replies through
  `DaemonEvent::SessionUpdateResponse`, preserving peer status and text. Both
  adapters forward `session_update_response` notices. Completion precedes any
  queued next update and does not roll back local state on refusal. Events
  correspond to wire replies; coalesced calls and address no-ops have no separate
  outcomes. Exhaustive matches must handle the new daemon and FSM
  `EmittedEvent::SessionUpdateResponse` variants.
- Radio adapters receive `destination_withdrawn` notices with the session and
  MAC when a router withdraws interest. The physical destination stays cached
  for other routers, later replay, and re-announcement on the original session.
- Modems expose validated Destination Up replies through
  `DestinationEvent::UpResponse`, including refusals and peer status text.
  Radio adapters receive `destination_up_response` notices scoped by session
  and MAC. Declines preserve destination knowledge and later replay. Exhaustive
  matches must handle the new daemon event and FSM
  `EmittedEvent::DestinationUpResponse` variant. Modem notices may exceed
  64 KiB after escaping peer text; that limit applies to messages sent by the adapter.
- Routers expose successful and denied Destination Announce replies through
  `DestinationEvent::AnnounceResponse`, preserving peer status and text. The
  router adapter forwards them as `announce_response` notices scoped by session
  and MAC. Successful replies still publish destination state and emit `Up`
  first. Exhaustive matches must handle the new daemon event and FSM
  `EmittedEvent::DestinationAnnounceResponse` variant.
- The TCP monitor cleanup test uses an owned abstract Unix socket name to verify
  failed setup releases its socket, avoiding ephemeral-port races with parallel
  network tests.
- Radio link grants enter the replay cache only after the session accepts and
  writes the response. Replies rejected during termination or cancelled before
  acceptance leave the cache unchanged, and later radio reports wait for the
  reply to be handled. Backends can opt into the same local acceptance receipt
  through `LinkControl::request_with_receipt` and `LinkControlReply`; existing
  implementations and closures keep working unchanged.
- Initial radio replay preserves live destination metrics in a single session
  command. A stale membership snapshot can no longer restore old values over a
  completed link grant. `SessionCommand::SessionDefaults` changes defaults while
  preserving existing destinations, including pending and withdrawn entries;
  it returns Busy if a session transaction is pending. This and the new
  `FsmEvent::AppSessionDefaults` variant require exhaustive matches to be updated.
- Radio session metrics coalesce inside each session while its transaction is
  busy. Later destination reports and link answers survive delivery of the queued
  defaults, preventing deferred updates from restoring stale values. Retained
  modem state includes accepted queued metrics before wire delivery.
  `ModemDaemon::queue_session_metrics` exposes this behavior; the immediate
  `update_session_metrics` API still returns Busy. New `QueueSessionUpdate` and
  `AppQueueSessionUpdate` enum variants require exhaustive matches to be updated.
- Radio link replies validate their complete wire size, including status text
  and inherited metrics, before changing the replay cache. Oversized replies
  become Request Denied with unchanged metrics, so later routers cannot receive
  a rejected grant. Embedders can use `ModemDaemon::validate_link_response`
  for the same content checks before retaining an answer.
- Near-limit destinations can be re-announced without closing the session when
  the required Status item makes the response larger than Destination Up.
  Successful responses carry metrics and fitting addresses; remaining addresses
  follow in Destination Updates on the same session.
- Destination address updates split across wire-sized messages when accumulated
  changes exceed one message, including updates coalesced before Up is acknowledged.
  MAC and metric overhead count toward the limit. This prevents session closure
  on encoding failure while preserving all removals, additions, and deferred metrics.
- Radio destination reports with a MAC format incompatible with
  `[network].mac_address_format` are logged and ignored before entering the
  replay cache, including before any router connects.
- Radio address updates validate the complete resulting destination before
  sending or caching changes. A batch that would exceed the Destination Up wire
  limit is rejected atomically, preserving replay for later routers; a subsequent
  batch can remove addresses to make room for new ones.
- Partial radio link replies preserve newer destination and session metric
  reports. Grants merge only supplied fields into each session and the replay
  cache, so overlapping requests on different routers retain each other's cached
  changes without leaking session-specific values between routers.
- Link grants for a physically withdrawn destination no longer overwrite the
  cached metrics of a replacement using the same MAC. Old transactions still
  complete, while replacement replay and subsequent grants retain their own state.
- Radio command retries coalesce by session and operation. Successful updates
  cancel superseded retries, preventing stale Session Updates from overwriting
  later destination metrics. Repeated destination flaps retain the latest re-add
  without queuing redundant withdrawals against its replacement.
- Radio adapter queues and pending requests are bounded. Overload denies excess
  link requests with `radio adapter busy`; cancelled requests waiting for output
  capacity are discarded. A broken input pipe or a write stalled for five seconds
  now triggers modem shutdown and failure exit for supervisor restart. Adapter
  I/O tasks are also cancelled on drop.
- End-to-end adapter regression tests run both daemon roles and both external
  adapter processes, covering IPv4/IPv6 commands, exact state, multi-modem
  isolation, restart recovery, and snapshot recovery after consumer backpressure.
- The modem TCP listener enables address reuse so a supervisor can restart it
  on the same port while old connections remain in TIME_WAIT. A live listener
  still prevents another modem from binding its port.
- Router integration adapter: `[adapter]` starts an external JSON Lines process
  that receives complete, replaceable snapshots and can submit targeted announce,
  withdrawal, and link-characteristic commands. Explicit resync, bounded queues,
  write/acceptance deadlines, local command results, and event-gap notices support
  slow consumers and recovery. Adapter failure terminates router sessions; shutdown
  closes adapter input and bounds its exit. Ambient capabilities are cleared.
- `RouterConfig` gains `adapter: Option<RouterAdapterConfig>`; exhaustive struct
  literals need updating. `--check-config` validates the section without execution.

- Both daemon handles expose retained `state()` snapshots with a generation,
  session/peer identity, negotiated extensions, effective metrics, addresses,
  and destination phases. Late or lagged consumers can reconcile current state
  without relying on public broadcast delivery. Session cleanup removes retained
  entries on termination, I/O failure, and cancellation.
- Radio bridge replay now follows retained session state, including after a lost
  SessionUp. The adapter receives `session_sync` membership snapshots. Replay
  retries busy session initialization and preserves existing destination metrics
  and router withdrawals; ended sessions release pending requests and retries.

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
