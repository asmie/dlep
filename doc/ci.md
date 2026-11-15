# Continuous integration

`.github/workflows/ci.yml` runs formatting and workflow validation, clippy, a
Linux workspace build/test, a Rust 1.85.0 check of all targets and features,
macOS tests of the portable crates, and instrumented Linux tests. Cargo commands
use the committed lockfile. Jobs have read-only repository permissions and
deadlines; new pushes cancel obsolete runs for the same branch or pull request.

The release job verifies all crates.io archives, fetches the complete locked
dependency set (including test-only dependencies), compares archived Cargo
targets with the source workspace, compiles their test targets in an isolated
extracted workspace, installs `dlep`, `dlep-router`, and `dlep-modem`
under `target/release-install`, then checks every CLI flag and four local
plaintext/mutual-TLS session scenarios in a disposable network namespace.
It does not publish packages. See [release validation](#release-validation).
Package verification alone does not populate every development dependency;
the explicit fetch makes subsequent offline checks independent of cache hits.
The inventory comparison requires matching target names, kinds, relative source
paths, and required features. A missing test or example fails before compilation.
Its two regression tests cover relocated archives and missing, extra, or changed
targets:

```sh
python3 -B .github/scripts/test_release_packages.py
```

The formatting job installs actionlint 1.7.12 from the official Linux x86-64
release with a pinned SHA-256 checksum; `taiki-e/install-action` does not support
this Go tool. Update the version and checksum together. The job also checks
that `.cargo/audit.toml` is tracked, even on pushes that do not trigger the
path-filtered dependency audit.
It invokes both Python regression files explicitly, so a missing file fails
instead of passing through test discovery with zero tests.

The macOS job covers `dlep-core`, `dlep-fsm`, and `dlep-ext`. It does **not**
validate the daemons or advertise macOS transport support. Discovery ancillary
socket handling and strict TCP GTSM reset monitoring currently require Linux.

## Release validation

Use current stable Cargo for workspace packaging (validated with Cargo 1.100),
Python 3.12+, OpenSSL, and Linux with `iproute2`/`unshare`. Run these checks from
the repository root; consumers still need only Rust 1.85+. The commands build
local archives and install under `target/release-install` without publishing:

```sh
cargo build --release --workspace --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  python3 -B .github/scripts/release-smoke.py

# --allow-dirty permits pre-commit review; omit it for committed artifacts.
cargo package --workspace --allow-dirty --locked
cargo fetch --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  python3 -B .github/scripts/check-release-packages.py --run-tests
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  python3 -B .github/scripts/release-smoke.py --bin-dir target/release-install/bin
```

Packaging needs network access for Cargo's temporary registry checksum lookup.
After the explicit fetch, archive tests and installs run offline with the locked
third-party dependencies. Only the DLEP crates are patched to extracted local
sources. The checker validates required package files, flattened symlinks, and
matching Cargo targets before running tests and installing the three commands.
CI compiles the archived tests; `--run-tests` above also executes them.

Smoke checks cover CLI flags and configuration precedence, certificate errors,
two static plaintext IPv4 peers, mutual TLS over IPv6, mutual TLS with IPv4
discovery, and plaintext discovery through the combined launcher. Sessions cross
heartbeat intervals and must shut down cleanly on SIGINT/SIGTERM. All network
changes occur in disposable namespaces. Use the sudo alternative in the network
test instructions when user namespaces are unavailable.

Checkpoint 60 (2026-11-15) passed all eight archives, 591 archived Rust tests
across 60 suites, three command installations, and 113 CLI/certificate checks
plus four session scenarios for each build. Formatting, clippy, Rust 1.85,
actionlint, the six Python checks, and the guarded dependency audit also passed.
These are local results; clean-commit packaging and pushed CI must be checked
before a maintainer publishes. The independent-peer scenarios below are separate
evidence, and coverage percentages were not recollected for that checkpoint.

## Independent router interoperability

The interoperability job runs our modem against the unmodified session and
codec from [Rohde & Schwarz dlepard](https://github.com/Rohde-Schwarz/dlepard),
pinned to commit `9300773a566290897839b845c4ec9f2feba3e93b`. It imports those
modules directly; the upstream REST application and its aiohttp dependency
are not used. No external Python packages are needed.

```sh
git clone --no-checkout https://github.com/Rohde-Schwarz/dlepard.git /tmp/dlepard
git -C /tmp/dlepard checkout --detach 9300773a566290897839b845c4ec9f2feba3e93b
cargo build -p dlep-daemon --example interop_modem --locked
unshare --user --map-root-user bash .github/scripts/interop-dlepard.sh \
  --peer-source /tmp/dlepard
```

The wrapper creates a disposable network namespace and sets its IPv4 default
TTL to 255 because dlepard's TCP proxy does not set a socket TTL. The host's
setting is unaffected, and our modem retains strict GTSM enforcement. The Python
runner checks the namespace, TTL setting, source revision, and tracked-file
cleanliness before starting either peer.
For discovery cases, the harness also sets multicast TTL 255 and enables
multicast loopback on dlepard's UDP socket. Its upstream defaults are TTL 1 and
loopback disabled. These are socket settings for this isolated local fixture;
the upstream session, codec, and UDP proxy source files are unchanged.

Four scenarios verify initialization and exact session metrics, Destination
Up/Update/Down and their metrics, bidirectional heartbeats, and termination
initiated by each participant: two use static endpoints and two use multicast
discovery. Discovery cases provide no TCP address or port to dlepard. It must
learn the modem's dynamically allocated TCP port from the Peer Offer and then
complete the same session checks. UDP PCAPs verify the multicast group, ephemeral
request source, offer source/destination ports, TTL 255, and exact advertised
connection point. Discovery artifacts use the `discovery-` prefix, with a
separate `-discovery.pcap` for UDP. Address checks cover a router-advertised IPv4
subnet during initialization and a modem-advertised IPv4 address and subnet in
Destination Up. Assertions inspect dlepard's information base, our modem's
address/lifecycle events, and the address items in the reassembled capture.
The Rust fixture uses the public
daemon API for all traffic; it has no independent wire codec. Bounded waits
make failures fail the job. Logs, loopback Ethernet PCAP files, and a successful
run's `summary.json` are saved in `target/interop-dlepard/` and uploaded even if
the scenario fails (a failed run has no success summary).

This is evidence for static and multicast-discovered IPv4 TCP sessions with TLS
and extensions disabled. It does not establish IPv6 transport, TLS, our router's compatibility
with an independent modem, or arbitrary implementations. The namespace TTL
setting and explicit multicast socket options are necessary for this peer;
this is not an out-of-box deployment test. Each scenario uses a separate asyncio
event loop because the upstream UDP proxy stops its loop when closed.
The pinned dlepard session has no Session Update or Destination Announce
handler. Its information base stores only IPv4 address data, ignores removal
flags, and replaces the entire destination entry on Destination Update. The
harness therefore makes no claim about address retention across updates,
removal semantics, IPv6 address data, or Announce with this peer. These limits
are recorded in `summary.json`; the upstream source is not patched to fill
them. Session Update and link-characteristics exchanges remain outside these
dlepard scenarios.

## Independent modem interoperability

The MIT LL-DLEP job runs our router against
[LL-DLEP](https://github.com/mit-ll/LL-DLEP) revision
`184e148ae4747dee11263a7ccedf952e36861ec0`. A digest-pinned Ubuntu 24.04 container
builds the upstream executable with its dependencies. No host packages are
installed. Compiler warnings are allowed, and `-include map` supplies a standard
header missing from the upstream example client; protocol source is unchanged.

```sh
cargo build -p dlep-daemon --example interop_router --locked
docker build -t dlep-interop-ll:184e148 .github/interop/ll-dlep
bash .github/scripts/interop-ll-dlep.sh
```

Docker is required. The Rust fixture must run on Ubuntu 24.04's libc; CI builds
it on an Ubuntu 24.04 runner. The local tested binary requires GLIBC 2.38 and
runs on the container's GLIBC 2.39. A binary built on a newer host may need
rebuilding in a compatible environment.

The runtime container has no external network, a read-only repository mount,
and a writable `target/interop-ll-dlep/` artifact mount. It drops capabilities
except NET_RAW (strict GTSM and capture), NET_ADMIN (isolated interface setup), and
DAC_OVERRIDE (writing the mounted artifact directory). It adds `fe80::1/64` to
the container's loopback interface and uses its numeric scope ID in the router
endpoint. The pinned peer requires a link-local address for IPv6 sessions.
It sets IPv4 TTL and the IPv6 loopback hop limit to 255 only in the container:
LL-DLEP configures TCP hops after acceptance, so its SYN-ACK otherwise uses the
system default. Rebuild an older image to include `iproute2` for address setup.
Discovery diagnostics additionally create a multicast-capable `dlep-interop`
dummy interface with `192.0.2.1` and scoped `fe80::2`. All interfaces and routes
remain inside the networkless container.
The host's network settings are unaffected. Artifacts can be root-owned locally;
CI returns their ownership before upload.

Four scenarios check initialization, destination Up/Update/Down, session-wide
metric updates, complete Link Characteristics Request/Response, bidirectional
periodic heartbeats, and termination initiated by each peer over both IPv4 and
scoped link-local IPv6 TCP. They also verify
IPv4/IPv6 addresses and attached subnets in modem initialization, bidirectional
session address additions/replacements/removals, and destination address
additions/replacements/removals. After router withdrawal, an Announce with IPv4
and IPv6 add/remove hints must restore the modem's actual destination metrics
and addresses, independently of those hints. A second Announce requests an
unknown destination and receives Request Denied through the upstream CLI's
configured response. Assertions check
the router's public events and exact metrics, as well as independent modem
retained peer addresses using `show peer`. Cleared sets must be empty on both
sides. Each session emits one SessionDown. PCAPs, the generated core profile,
both peer logs, and `summary.json` are uploaded as `ll-dlep-interoperability`.
Scenario filenames begin with `ipv4-` or `ipv6-`, followed by the termination
initiator. Each summary entry identifies its IP version; `wrong_ttl` counts
incorrect TTL for IPv4 or hop limit for IPv6 and must be zero.
The Cargo test count excludes these external scenarios.

These are qualified static IPv4 and link-local IPv6 plaintext results. Three upstream example
behaviors required explicit configuration, without relaxing our validation:

- The default XML profile includes experimental extensions and emits a Latency
  Range item without advertising it. Our router rejected initialization with
  status 130. The harness copies the core profile and removes its two XInclude
  extension entries through the supported protocol-configuration mechanism.
- The example's automatic link reply echoes only the requested metrics. Our
  router rejected that incomplete response with status 130. The harness disables
  `linkchar-autoreply` and supplies every supported metric via the upstream
  `linkchar reply` CLI, as required by
  [RFC 8175 §12.19](https://www.rfc-editor.org/rfc/rfc8175.html#section-12.19).
- The XML profile omits the RFC's Shutting Down status 255. Without it, LL-DLEP
  rejects our termination and our router can time out waiting for a response.
  The generated profile adds that standard status with failure mode `terminate`.
  Capture assertions require the actual termination request and response in
  all four scenarios, so a TCP disconnect alone cannot pass the test.

Successful discovery, TLS, extension negotiation, and interoperability with
arbitrary peers remain outside these four session scenarios. This is not a stock-configuration
deployment test; the TTL/hop-limit settings, corrected core profile, and explicit link
reply matter. The PCAP checks reconstruct each direction's TCP payload, reject
gaps/conflicting retransmissions and truncated messages/data items, and require
at least two Heartbeats in each direction. Exact address values, subnet prefixes,
add/remove flags, Announce hints, and success/denial responses are checked
independently of either peer's codec. Each capture must contain exactly one
connection with matching peer IP addresses and ports, using the expected IP
family and TTL/hop limit 255. The parser handles the unfragmented TCP traffic
these fixtures generate and rejects IPv4 fragments and IPv6 extension headers.
The IPv6 scenarios use loopback link-local addresses; global IPv6 addresses and
operation across physical interfaces remain outside this check.

Two additional discovery diagnostics run our real router's discovery API against
the same pinned modem over IPv4 and IPv6. Both reproduce an upstream limitation:
LL-DLEP sends the Peer Offer **to the configured discovery port**, from an
ephemeral source port, instead of returning it to the requesting socket from
the discovery port. See the
[pinned send implementation](https://github.com/mit-ll/LL-DLEP/blob/184e148ae4747dee11263a7ccedf952e36861ec0/PeerDiscovery.cpp#L591)
and [verified RFC erratum 6472](https://www.rfc-editor.org/errata/eid6472).

The diagnostics require captured requests and replies with those exact port
properties, a valid connection point, TTL/hop limit 255, `NO_OFFER` from our
router, and no TCP packets. A silent or broken fixture cannot satisfy them.
`summary.json` records them under `discovery_probes` with `result: incompatible`,
separately from successful sessions. Artifacts use `ipv4-discovery` and
`ipv6-discovery` prefixes. UDP captures include outgoing multicast and may
contain loopback copies, so request/offer counts are capture records rather than
unique transmissions. No relay, peer source patch, or alternate router bind port
is used to turn these failures into a compatibility claim.

The shared capture parser has twenty network-free regression tests for segmented
and retransmitted TCP data, missing peers/SYNs, gaps, conflicting retransmissions,
truncation, malformed IP/TCP headers, low TTL/hop limits, mismatched IP endpoints,
and invalid address items across both IP families. UDP cases cover malformed
signal/UDP lengths and TLVs, missing requests/offers, wrong multicast/reply
endpoints, incorrect connection points, and legacy-port diagnostics that must
fail the successful-exchange validator. CI runs them in the formatting/workflow
job. Run them locally with:

```sh
python3 -B .github/scripts/test_interop_common.py
```

## Network tests and coverage

Both Linux test jobs use `.github/scripts/test-network.sh`. It creates a
disposable network namespace, configures loopback and a multicast-capable dummy
interface with IPv4/IPv6 addresses, and preserves the child command's exit
status. The script always enters a new network namespace before making network
changes. GitHub runners use `sudo` to provide the capabilities needed by strict
GTSM.

The modem and router adapter tests run Python 3 adapter scripts and use
`setpriv` (util-linux) to check that adapters do not inherit ambient
capabilities; the capability checks are skipped when `setpriv` is unavailable.

For local Linux runs where unprivileged user namespaces are enabled:

```sh
cargo build --workspace --all-targets --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  cargo test --workspace --locked --offline
```

The root `tests/adapter_pipeline.rs` suite launches both roles through the
combined `dlep` binary, each with an external Python 3 adapter. Its consumer
reconstructs state independently from the public JSON Lines records, rejects
interleaved or incomplete snapshots, and checks exact metrics and addresses.
It covers link grants/denials, command rejection, withdrawal and re-announcement,
two modems sharing a MAC, radio failure and automatic reconnection after modem
restart, explicit resync, and empty state before shutdown EOF. A paused consumer
fills its real input pipe and causes broadcast lag; the test requires both an
explicit event-gap notice and recovery of the complete latest state. Control
sockets operate the adapters without bypassing the daemons' public protocols.

The same suite pauses radio input long enough to block writes and closes it
while keeping the adapter alive. Both cases must terminate the modem sessions
with Shutting Down and fail the modem process. A shorter pause must recover
all queued notices and complete a pending link request on the original session.
An IPv4/IPv6 case overflows the radio broadcast during a pause and requires an
`event_gap` followed by unchanged session membership. A pending link request
must still complete, withdrawn destinations must stay withdrawn, and later
routers must receive the cached physical destinations and granted metrics.
Radio bridge unit tests separately exercise bounded requests, cancellation,
partial writes, and the output deadline using virtual time.
Gap recovery tests also remove a session while the marker waits for output
capacity, check exact skipped counts, and require fresh and repeated empty
membership notices without replaying existing sessions.
Explicit radio `resync` cases reject extra fields and require a fresh membership
notice for each request without inventing event loss. The IPv4/IPv6 adapter
pipeline checks repeated unchanged and empty membership, a pending link answer,
preserved withdrawals and grants, and physical replay to a later router.
Radio session snapshots also include remote router addresses. Unit tests cover
initialization addresses, canonical subnets, coalesced changes, delayed events,
real broadcast loss, updates while a gap marker waits for output capacity, and
complete address snapshots larger than the adapter's input-line limit.
An IPv4/IPv6 pipeline sends session address commands through both real adapters
and checks per-router isolation, additions/removals, explicit refresh, session
removal, reconnect state, and preservation of a withdrawn destination.
Radio-originated `session_addresses` cases cover reports before any routers,
replay behind busy defaults, coalescing with metrics, nonfatal refusal, no-ops,
invalid/duplicate/conflicting entries, accumulated replay limits, and large
replacements across multiple acknowledged updates. An IPv4/IPv6 adapter pipeline
checks broadcast to multiple routers, local/remote address separation, complete
removal, reconnect replay, and preserved destination withdrawals and link grants.
Bridge tests also hold protocol acknowledgements while sending hundreds of
radio reports to check session metric coalescing and latest-value convergence. Queued metrics
must preserve later destination reports, optional values, and link answers;
pending Up, pending Down, withdrawal, and shutdown have dedicated FSM cases.
Runtime tests check effective retained values before delivery and ordered wire
corrections over IPv4/IPv6 with both MAC formats. Further bridge cases cover
independent progress across routers, replay to a later router, and repeated
destination flaps during withdrawal acknowledgement.
Initial-replay regressions retain an old membership snapshot, complete a link
grant, then replay the defaults. The current session and later routers must keep
the granted values. FSM cases check default inheritance and command validation;
IPv4/IPv6 runtime cases cover both MAC formats, pending Up/Down, withdrawn
destinations, a single retained-state update, and isolation from other sessions.
Replacement regressions hold a link request across physical Down/Up and then
grant it: the old transaction must complete without changing the replacement's
cache. Bridge tests cover requests already delivered and requests still queued;
the IPv4/IPv6 subprocess case also checks replay to a later router and new grants.
Partial-reply regressions report new destination/session metrics while a request
is pending, then check omitted fields and invalid optional metrics. Overlapping
requests from two real routers must preserve each session's values and accumulate
their explicit grants in the cache replayed to a third router over IPv4/IPv6.
Link-reply size regressions include status text and inherited optional metrics,
checking exact wire limits and one-byte overflow with ASCII and multibyte text
under both MAC formats. The real adapter pipeline sends compact JSON that fits
the line limit but exceeds the response limit; IPv4/IPv6 cases require unchanged
replay to a later router and a subsequent valid grant on the original session.
Link-reply acceptance tests reject a grant during session termination and require
unchanged replay. Runtime tests check receipt delivery after state publication,
original rejection despite fallback denial, cancellation, and abandoned receipt
receivers. Bridge tests require successful acceptance before caching and hold
the receipt to check ordering. The IPv4/IPv6 adapter pipeline sends a grant and
a newer report on adjacent lines; live state and later replay must retain the
newer report.
Address-cache regressions accumulate individually valid batches beyond the
Destination Up wire limit, with and without a connected router. Rejected batches
must preserve all addresses, later replay must work, and a batch that frees space
must recover. The real adapter pipeline covers this over both IPv4 and IPv6.
Radio MAC-format cases check EUI-48 and EUI-64 admission before and after a router
connects and after the last destination is removed. Real adapter pipelines verify
valid reports, targeted link grants, and later replay under both format settings
over IPv4 and IPv6 while incompatible reports are ignored.

FSM address tests replace large snapshots while Up is pending, encode/decode
each resulting chunk, and apply them to a router to check exact addresses and
metrics. Runtime command tests cover accumulated changes and live batches whose
MAC overhead crosses the message limit. Both MAC formats and transport families
must deliver every chunk and keep the original session usable.
Near-limit Announce tests include the required Status item, restore all four
address families and current metrics after withdrawal, and check subsequent
updates. The real adapter regression requires the same session ID throughout
for both MAC formats over IPv4/IPv6, so reconnection cannot mask an encoding failure.
It also requires an `announce_response` success notice. Denied-announcement
cases require a separate peer-response notice after local acceptance and allow
a subsequent request on the same session. FSM tests reject duplicate, unsolicited,
malformed, and fatal replies without emitting completion; runtime tests preserve
status text and session/peer attribution, verify state publication before success,
and isolate two peers sharing a MAC over both IP families and MAC formats.
Destination Up completion tests cover accepted and declined reports, queued
metric/address corrections, preserved state after refusal, later Announce, and
peer/session attribution. Bridge tests preserve replay for a later router and
round-trip escaped status text beyond the adapter input-line limit. The real
adapter pipeline requires the acceptance notice, and churn checks each peer
response without discarding unexpected modem events.
Radio withdrawal notices are checked per session over both IP families and MAC
formats. The real adapter regression verifies continued reports to other routers,
cached replay to a later router, and re-announcement with current metrics and
addresses. Subsequent physical Down/Up cycles must not echo router withdrawals.
Session Update completion tests cover both roles, status text, refused and
unknown nonfatal statuses, transaction release, address no-ops, and completion
before coalesced next metrics. Malformed, unsolicited, duplicate, and fatal
replies must not emit completion. IPv4/IPv6 runtime tests check peer attribution
and independent sessions; adapter tests preserve replay after refusal, escape
long text, and keep notices outside complete snapshots. The real subprocess
pipeline requires a radio notice after a session metric update.
Router adapter session address tests with controlled IPv4/IPv6 peers verify
targeting, concurrent sessions, busy rejection, strict JSON fields, invalid and
conflicting addresses, oversized wire updates, shared request-ID deduplication,
stale sessions, and nonfatal refusal without rollback. The real router binary
and Python adapter add, replace, and remove IPv4/IPv6 addresses and attached
subnets, checking canonical subnets, peer state, completion notices, no-op
acceptance, and unchanged remote snapshots.
Desired modem address tests exercise complete-set replacements while busy,
coalescing and cancellation, canonical subnets, duplicate/oversized rejection,
and near-limit replacements split across acknowledged Session Updates. Combined
metric/address updates must preserve later destination changes and publish
completion before the next send. IPv4/IPv6 runtime tests check immediate desired
state in snapshots, independent router sessions, stale IDs, raw-command
validation, no-op delivery, large-set convergence, and cleanup on reconnect.
Destination Announce hint tests check duplicate/conflicting addresses, forbidden
attached subnets, the MAC-inclusive wire budget, role/phase/MAC validation, and
transaction release after refusal. Controlled runtime peers verify address
payloads, busy rejection, session isolation, and unchanged retained addresses.
Router adapter checks include strict fields, semantic rejection without peers,
and shared request-ID handling. IPv4/IPv6 adapter pipelines with both MAC formats
verify targeted radio notices, denied requests, empty hints from older commands,
rejection before transmission, and preservation of physical destination data.
Destination Down completion tests require removal before completion and preserve
status text on both roles. Router `Down` events precede completion; modem replies
must not masquerade as router withdrawals. Invalid replies emit no completion.
Runtime and real adapter cases cover both MAC formats and IP families with
multiple peers. The radio regression delays notice delivery until after a
replacement is sent and requires unchanged replay, including escaped peer text
beyond the input-line limit. Churn verifies every modem Down response.

These tests run automatically in the workspace and coverage jobs. To run them
alone:

```sh
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  cargo test -p dlep --test adapter_pipeline --locked --offline
```

The command and restart scenarios cover IPv4 and IPv6 static plaintext sessions
with strict GTSM. The fixture uses Linux pipe controls and process groups for
bounded backpressure and subprocess cleanup. It does not use radio hardware or
an independent DLEP implementation; the interoperability jobs above cover
independent peers.

The daemon's `review_regressions` suite also forces modem-initiated TCP closure
over IPv4 and IPv6 before restarting on the same port. This deterministically
checks reuse with an old connection in TIME_WAIT and verifies that a second
live modem still cannot bind the listening endpoint.

The TCP monitor's filter-setup failure test binds a process-specific abstract
Unix socket name, verifies it cannot be rebound while owned, then locks its BPF
filter to force setup failure. Rebinding after the error proves the socket was
released without competing with parallel tests for an ephemeral TCP port. The
test also checks that a new packet monitor can still start afterward.

The normal workspace and coverage runs include `dlep-daemon/tests/churn.rs`.
It keeps the same daemons alive for 100 successive sessions per address family
(200 total), alternates termination initiators, and reuses destination MACs
within and across sessions. It checks exact metrics and event attribution,
stale session-ID rejection, retained connection state, capacity recovery, and
file descriptors returning to baseline after every session and daemon shutdown.
Strict TCP GTSM remains enabled. Its transaction barriers wait for protocol
responses rather than assuming a delay is sufficient. Each cycle has a deadline.

For a longer local run, increase the positive per-family cycle count:

```sh
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  env DLEP_CHURN_CYCLES=1000 \
  cargo test -p dlep-daemon --test churn --locked --offline -- --nocapture
```

This is bounded sequential plaintext churn, not a multi-day soak, simultaneous
client load test, TLS churn check, or heap-leak measurement. Descriptor accounting
uses Linux `/proc/self/fd`; keep this as the only test in its integration-test
binary so concurrent cases cannot invalidate its baseline.

Coverage uses cargo-llvm-cov 0.9.1 and the matching toolchain's
`llvm-tools-preview` component. To reproduce the CI run:

```sh
cargo fetch --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  bash .github/scripts/coverage.sh
```

The coverage script cleans old instrumented workspace artifacts before testing.
Collection and reporting run with the same privileges so CI does not encounter
root-owned profile write failures. Before upload, CI returns ownership of
`target/coverage/` to the runner user: LLVM's HTML directories can otherwise be
unreadable to the unprivileged upload action. Successful runs upload
`linux-workspace-coverage`, retained for 14 days, containing LCOV, HTML, and a
JSON summary. There is no coverage-percentage gate yet; reports provide a
baseline for the final coverage review. Reports are under `target/coverage/`,
which is already ignored by Git.

## Fuzzing

`.github/workflows/fuzz.yml` runs three cargo-fuzz 0.13.2 targets on changes to the
codec, FSM, fuzz workspace, or workspace manifests, and on manual dispatch.
Each nightly AddressSanitizer job fuzzes for 30 seconds, with a five-second input
deadline, 2 GiB RSS limit, and a 15-minute job deadline. Generated corpora and
failure artifacts are uploaded for 14 days. CI verifies `fuzz/Cargo.lock` did
not change during execution.

`wire_decode` checks panic freedom and stable re-encoding of accepted messages,
signals, and Data Items, including maximum-length bodies. `session_sequence`
drives both session FSMs with real initialization, injected messages, application
commands, timers, and teardown under both MAC formats. Every emitted message
must encode/decode before delivery to the other FSM; operation and response
budgets bound each input. The independent unpublished workspace keeps fuzzing
dependencies and nightly requirements outside release packages.
`discovery_sequence` adds raw-signal injection and real request/offer exchanges
through both discovery FSMs, including timers and restarts. It checks emitted
signal serialization, reply targets, usable and unique endpoints, TLS/IPv6
preference, and IPv6 link-local scope propagation.

See [fuzzing instructions](../fuzz/README.md) for seed generation, longer runs,
input formats, failure replay/minimization, and the local LeakSanitizer sandbox
limitation. Short runs are smoke evidence; network transports, TLS, extensions,
and adapters are outside these targets.

## Dependency audit

`.github/workflows/audit.yml` runs cargo-audit 0.22.2 for dependency,
audit-policy, or workflow changes, every Monday, and on manual dispatch. It
fetches the current RustSec database and fails on vulnerabilities and warnings.
Run locally with:

```sh
cargo metadata --locked --all-features --format-version 1 | \
  python3 .github/scripts/check-audit-exception.py
cargo audit --deny warnings
```

There is one documented exception in `.cargo/audit.toml`:
[RUSTSEC-2026-0009](https://rustsec.org/advisories/RUSTSEC-2026-0009) affects
`time`'s RFC 2822 parser. Version 0.3.45 is needed by certificate test helpers
while maintaining Rust 1.85 support; the patched release requires Rust 1.88.
The `parsing` feature is disabled, including when all workspace features are
enabled. CI checks that the resolved version stays 0.3.45, only `alloc`/`std`
features are active, and the only consumers remain `rcgen`/`yasna`. Any change
fails the guard and requires reviewing or removing the exception. The normal
daemon build does not use the certificate generation helpers.

The guard rejects a missing/malformed policy or an expanded advisory ignore
list. Include `.cargo/audit.toml` in the commit; having it only in a local
working tree does not configure a clean CI checkout.

The initial audit also prompted upgrades to rustls 0.23.45 and anyhow 1.0.103,
and replacement of the archived `rustls-pemfile` wrapper with the maintained
`rustls-pki-types::pem::PemObject` API.

The November 2026 release checkpoint updates the test-only `rustix` dependency
from 1.1.4 to 1.1.6 to resolve
[RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html).
It is reached through `tempfile` and property-test dependencies. No new audit
exception is added, and the all-target Rust 1.85 check remains required.
