#!/usr/bin/env bash
# Run a command in a disposable Linux network namespace. The caller needs
# CAP_SYS_ADMIN and CAP_NET_RAW (sudo in CI, or a root-mapped user namespace).
set -euo pipefail

if (( $# == 0 )); then
    echo "usage: bash .github/scripts/test-network.sh <command> [args...]" >&2
    exit 2
fi

exec unshare --net -- bash -euc '
    ip link set lo up
    ip link add dlep-test type dummy
    ip addr add 192.0.2.1/24 dev dlep-test
    ip link set dlep-test up multicast on
    ip -6 addr add fe80::1/64 dev dlep-test nodad
    ip -6 addr add fd00::1/64 dev dlep-test nodad
    ip route add default dev dlep-test
    exec "$@"
' -- "$@"
