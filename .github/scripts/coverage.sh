#!/usr/bin/env bash
# Run inside test-network.sh so every transport test has strict GTSM support.
set -euo pipefail

cargo llvm-cov clean --workspace
cargo llvm-cov --workspace --all-features --locked --offline --no-report
mkdir -p target/coverage
cargo llvm-cov report --locked --offline --lcov --output-path target/coverage/lcov.info
cargo llvm-cov report --locked --offline --html --output-dir target/coverage
cargo llvm-cov report --locked --offline --json --summary-only --output-path target/coverage/summary.json
