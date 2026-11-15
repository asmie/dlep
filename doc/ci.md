# Continuous integration

`.github/workflows/ci.yml` runs formatting and workflow validation, clippy, a
Linux workspace build/test, a Rust 1.85.0 check of all targets and features,
macOS tests of the portable crates, and instrumented Linux tests. Cargo commands
use the committed lockfile. Jobs have read-only repository permissions and
deadlines; new pushes cancel obsolete runs for the same branch or pull request.

The release job verifies all crates.io archives, fetches the complete locked
dependency set (including test-only dependencies), compiles their test targets in
an isolated extracted workspace, installs `dlep`, `dlep-router`, and `dlep-modem`
under `target/release-install`, then checks every CLI flag and four local
plaintext/mutual-TLS session scenarios in a disposable network namespace.
It does not publish packages. See [release checks](releasing.md).
Package verification alone does not populate every development dependency;
the explicit fetch makes subsequent offline checks independent of cache hits.

The formatting job installs actionlint 1.7.12 from the official Linux x86-64
release with a pinned SHA-256 checksum; `taiki-e/install-action` does not support
this Go tool. Update the version and checksum together. The job also checks
that `.cargo/audit.toml` is tracked, even on pushes that do not trigger the
path-filtered dependency audit.

The macOS job covers `dlep-core`, `dlep-fsm`, and `dlep-ext`. It does **not**
validate the daemons or advertise macOS transport support. Discovery ancillary
socket handling and strict TCP GTSM reset monitoring currently require Linux.

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

Two scenarios verify initialization and exact session metrics, Destination
Up/Update/Down and their metrics, bidirectional heartbeats, and termination
initiated by each participant. Assertions inspect dlepard's information base
and our modem's lifecycle notifications. The Rust fixture uses the public
daemon API for all traffic; it has no independent wire codec. Bounded waits
make failures fail the job. Logs, loopback Ethernet PCAP files, and a successful
run's `summary.json` are saved in `target/interop-dlepard/` and uploaded even if
the scenario fails (a failed run has no success summary).

This is evidence for static IPv4 TCP sessions with TLS disabled and extensions
disabled. It does not establish discovery, IPv6, TLS, our router's compatibility
with an independent modem, or arbitrary implementations. The namespace TTL
setting is necessary for this peer; this is not an out-of-box deployment test.
Session Update and link-characteristics exchanges are outside these scenarios.

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
except NET_RAW (strict GTSM and capture) and DAC_OVERRIDE (writing the mounted
artifact directory). It sets TTL 255 only in the container: LL-DLEP configures
TCP TTL after acceptance, so its SYN-ACK otherwise uses the system default.
The host's network settings are unaffected. Artifacts can be root-owned locally;
CI returns their ownership before upload.

Two scenarios check initialization, destination Up/Update/Down, session-wide
metric updates, complete Link Characteristics Request/Response, bidirectional
periodic heartbeats, and termination initiated by each peer. Assertions check
the router's public events and exact metrics, as well as independent modem
logs. Each session emits one SessionDown. PCAPs, the generated core profile,
both peer logs, and `summary.json` are uploaded as `ll-dlep-interoperability`.
The Cargo test count excludes these external scenarios.

These are qualified static IPv4 plaintext results. Three upstream example
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
  both scenarios, so a TCP disconnect alone cannot pass the test.

Discovery, IPv6, TLS, extension negotiation, and interoperability with arbitrary
peers remain outside these scenarios. This is not a stock-configuration
deployment test; the TTL setting, corrected core profile, and explicit link
reply matter. The PCAP checks also reconstruct each direction's TCP payload,
reject capture gaps, and require at least two Heartbeats in each direction.

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
Radio bridge unit tests separately exercise bounded requests, cancellation,
partial writes, and the output deadline using virtual time.
They also hold protocol acknowledgements while sending hundreds of radio reports
to check session metric coalescing and latest-value convergence. Queued metrics
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
