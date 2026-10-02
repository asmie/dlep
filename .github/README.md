# Continuous integration

`workflows/ci.yml` runs formatting and workflow validation, clippy, a Linux
workspace build/test, a Rust 1.85.0 check of all targets and features, macOS tests
of the portable crates, and instrumented Linux tests. Cargo commands use the
committed lockfile. Jobs have read-only repository permissions and deadlines;
new pushes cancel obsolete runs for the same branch or pull request.

The macOS job covers `dlep-core`, `dlep-fsm`, and `dlep-ext`. It does **not**
validate the daemons or advertise macOS transport support. Discovery ancillary
socket handling and strict TCP GTSM reset monitoring currently require Linux.

## Network tests and coverage

Both Linux test jobs use `scripts/test-network.sh`. It creates a disposable
network namespace, configures loopback and a multicast-capable dummy interface
with IPv4/IPv6 addresses, and preserves the child command's exit status. The
script always enters a new network namespace before making network changes.
GitHub runners use `sudo` to provide the capabilities needed by strict GTSM.

For local Linux runs where unprivileged user namespaces are enabled:

```sh
cargo build --workspace --all-targets --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  cargo test --workspace --locked --offline
```

Coverage uses cargo-llvm-cov 0.9.1 and the matching toolchain's
`llvm-tools-preview` component. To reproduce the CI run:

```sh
cargo fetch --locked
unshare --user --map-root-user bash .github/scripts/test-network.sh \
  bash .github/scripts/coverage.sh
```

The coverage script cleans old instrumented workspace artifacts before testing.
Collection and reporting run with the same privileges so CI does not encounter
root-owned profile write failures. Successful runs upload
`linux-workspace-coverage`, retained for 14 days, containing LCOV, HTML, and a
JSON summary. There is no coverage-percentage gate yet; reports provide a
baseline for the final coverage review. Reports are under `target/coverage/`,
which is already ignored by Git.

## Dependency audit

`workflows/audit.yml` runs cargo-audit 0.22.2 for dependency, audit-policy, or
workflow changes, every Monday, and on manual dispatch. It fetches the current
RustSec database and fails on vulnerabilities and warnings. Run locally with:

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

The initial audit also prompted upgrades to rustls 0.23.45 and anyhow 1.0.103,
and replacement of the archived `rustls-pemfile` wrapper with the maintained
`rustls-pki-types::pem::PemObject` API.
