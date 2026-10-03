# Pinned independent peer; no protocol source patches are applied.
FROM ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates git cmake make g++ libboost-thread-dev libboost-system-dev \
    libboost-test-dev libxml2-dev libxml2-utils libreadline-dev libprotobuf-dev \
    protobuf-compiler doxygen graphviz python3 \
    && rm -rf /var/lib/apt/lists/*
# The example client lacks an explicit <map> include with modern Boost/GCC.
# Force that standard header at compile time; leave upstream source untouched.
RUN git clone https://github.com/mit-ll/LL-DLEP.git /opt/ll-dlep \
    && git -C /opt/ll-dlep checkout --detach 184e148ae4747dee11263a7ccedf952e36861ec0 \
    && cmake -S /opt/ll-dlep -B /opt/ll-dlep-build -DWARNINGS_AS_ERRORS=OFF \
        -DCMAKE_CXX_FLAGS="-include map" \
    && cmake --build /opt/ll-dlep-build --target Dlep --parallel 2
WORKDIR /work
