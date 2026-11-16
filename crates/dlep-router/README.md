# dlep-router

Linux router daemon for DLEP (RFC 8175), with discovery, TLS, and reconnect support.
Experimental macOS/FreeBSD transport requires `[network].gtsm_enforce = false`.
Native macOS loopback checks passed; native FreeBSD validation is pending.

Requires Rust 1.85 or newer.

Static IPv6 link-local peers can name an interface, for example
`--peer '[fe80::1%eth0]:854'` or the same string in TOML `static_peers`.
Retries resolve the current interface index; TLS verifies the IPv6 address.

Configure `[adapter]` to run an external routing integration process. It receives
complete session/destination snapshots over JSON Lines and can submit targeted
destination and link-characteristic commands. See the
[router adapter protocol](https://github.com/asmie/dlep/blob/master/doc/router-adapter.md).

```sh
cargo install dlep-router --version 0.2.0 --locked
dlep-router --help
```

TLS is enabled by default. Provision certificates and configure the network before starting the daemon. Both daemons require CAP_NET_RAW for strict TCP GTSM.

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
