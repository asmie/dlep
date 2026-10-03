#!/usr/bin/env bash
# As with test-network.sh, run via sudo or a root-mapped user namespace.
set -euo pipefail
export DLEP_INTEROP_PARENT_NETNS
DLEP_INTEROP_PARENT_NETNS=$(readlink /proc/self/ns/net)
exec bash .github/scripts/test-network.sh bash -euc '
    # dlepard uses the system TCP TTL. Only this disposable namespace changes.
    sysctl -w net.ipv4.ip_default_ttl=255
    exec python3 .github/scripts/interop-dlepard.py "$@"
' -- "$@"
