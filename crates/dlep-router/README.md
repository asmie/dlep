# dlep-router

Linux router daemon for DLEP (RFC 8175), with discovery, TLS, and reconnect support.

Requires Rust 1.85 or newer.

```sh
cargo install dlep-router --version 0.2.0 --locked
dlep-router --help
```

TLS is enabled by default. Provision certificates and configure the network before starting the daemon. Both daemons require CAP_NET_RAW for strict TCP GTSM.

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
