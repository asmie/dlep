#!/usr/bin/env bash
# Build interop_router and the pinned image first; see doc/ci.md.
set -euo pipefail
mkdir -p target/interop-ll-dlep
exec docker run --rm --network none --cap-drop ALL --cap-add NET_RAW --cap-add DAC_OVERRIDE \
    --security-opt no-new-privileges --sysctl net.ipv4.ip_default_ttl=255 \
    --mount "type=bind,src=$PWD,dst=/work,readonly" \
    --mount "type=bind,src=$PWD/target/interop-ll-dlep,dst=/artifacts" \
    dlep-interop-ll:184e148 \
    python3 -B .github/scripts/interop-ll-dlep.py --output /artifacts
