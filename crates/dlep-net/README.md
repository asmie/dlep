# dlep-net

UDP discovery, TCP/TLS transport, framing, and GTSM for DLEP (RFC 8175).
Linux strict TCP reset monitoring requires CAP_NET_RAW. Experimental macOS
transport requires `Connector::with_gtsm(false)` and the acceptor's
`plain_with_gtsm` / `tls_with_gtsm` constructors with `enforce = false`.
Outbound TTL/hop limit 255 and inbound discovery checks remain enabled. Strict TCP enforcement
fails explicitly on macOS. Native macOS runtime validation is pending.

Requires Rust 1.85 or newer.

`Connector::connect_host(host, port)` resolves names using the system resolver,
tries up to 16 distinct answers within 15 seconds, and preserves the hostname
for TLS verification and SNI. `connect_with_server_name(addr, ServerName)` uses
an explicit TLS identity at a numeric endpoint. `connect(addr)` verifies the
endpoint IP. All paths retain the connector's TLS and GTSM settings.

```toml
[dependencies]
dlep-net = "0.2.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
