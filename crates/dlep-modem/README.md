# dlep-modem

Linux modem daemon for DLEP (RFC 8175), with discovery, TLS, and graceful shutdown.

Requires Rust 1.85 or newer.

```sh
cargo install dlep-modem --version 0.2.0 --locked
dlep-modem --help
```

TLS is enabled by default. Provision certificates and configure the network before starting the daemon. The modem normally needs CAP_NET_BIND_SERVICE for port 854. Both daemons require CAP_NET_RAW for strict TCP GTSM.

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
