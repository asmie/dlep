# Fuzzing DLEP

These targets use [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html),
libFuzzer, nightly Rust, and AddressSanitizer. They run without sockets or
capabilities. This independent, unpublished workspace has its own lockfile;
fuzz tooling does not enter the eight release packages or change their Rust 1.85
minimum. Run commands from the repository root:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --version 0.13.2 --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
python3 -B .github/scripts/seed-fuzz.py
cargo +nightly fuzz run wire_decode -- -max_total_time=30 -max_len=65543 -timeout=5 -rss_limit_mb=2048
cargo +nightly fuzz run session_sequence -- -max_total_time=30 -max_len=65543 -timeout=5 -rss_limit_mb=2048
```

`wire_decode` tries message, signal, and individual Data Item decoding on every
input. Accepted values must encode, decode again, and reach stable encoded bytes.
This allows documented normalization such as subnet canonicalization. The size
limit includes an eight-byte signal header plus the largest 16-bit body.

`session_sequence` runs the synchronous router and modem FSMs together. Its
first byte selects EUI-48/EUI-64 (bit 1) and either real initialization (bit 0)
or incomplete initialization. Up to 64 following operations select a recipient
(bit 7), a destination number (bits 4–5), and an operation (bits 0–3):

| Code | Event |
| --- | --- |
| 0 | Inject message: two-byte big-endian length followed by wire bytes; decode failures become protocol errors |
| 1–4 | Add, drop, update metrics, or Announce a destination |
| 5–7 | Queue session metrics, set defaults, or clear desired session addresses |
| 8–11 | Heartbeat, missed-heartbeat, initialization, or termination timer |
| 12–15 | Shutdown, TCP close, protocol error, or consumed extension message |

Each action batch checks that emitted messages encode and decode, then delivers
them to the other FSM. A 128-batch budget detects response loops. Inputs stop at
64 operations, including after closure; application metrics/addresses currently
use defaults. This checks panic freedom, message serialization, and bounded
responses. It does not assert complete protocol semantics or fuzz transports,
TLS, discovery FSMs, plug-ins, or adapter processes.

The seed generator writes 19 codec and 100 session starting inputs, covering
initialization, destination lifecycle, unknown items, duplicates, truncation,
invalid prefixes/UTF-8, maximum body lengths, both MAC formats, and teardown.
Generated corpora, artifacts, and builds are ignored. Rerunning the generator
restores starting seeds and preserves newly discovered corpus entries.

CI runs each target for 30 seconds with a five-second per-input deadline and a
2 GiB RSS limit, then uploads corpora and failure artifacts for 14 days. Its
15-minute job deadline also bounds compilation. Increase `-max_total_time` for
longer local campaigns. A successful short run is smoke evidence, not exhaustive
coverage or certification.

If LeakSanitizer reports that process inspection/ptrace is blocked in a local
sandbox, prefix commands with `ASAN_OPTIONS=detect_leaks=0`. AddressSanitizer
remains enabled, but that run cannot measure leaks. CI retains default leak
detection. No host ptrace setting needs to change.

Reproduce and minimize a failure before fixing it:

```sh
cargo +nightly fuzz run wire_decode fuzz/artifacts/wire_decode/crash-HASH
cargo +nightly fuzz tmin wire_decode fuzz/artifacts/wire_decode/crash-HASH
```

Use the corresponding target name for session failures. Preserve the minimized
input as a normal regression test in the affected crate. Review `fuzz/Cargo.lock`
after dependency updates; cargo-fuzz does not pass `--locked` to its build, so CI
explicitly checks that running it did not alter the lockfile.
