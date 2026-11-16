# dlep-daemon

Embeddable asynchronous router and modem runtime for DLEP (RFC 8175). Requires Linux; strict TCP GTSM requires CAP_NET_RAW.

Requires Rust 1.85 or newer.

Router handles support numeric peers with `connect_static(addr)`, named peers
with `connect_named(host, port)`, and explicit certificate identities with
`connect_static_with_server_name(addr, name)`. Named connections preserve the
requested host for TLS verification and try up to 16 distinct resolver answers
within 15 seconds. Events use the connected numeric endpoint; applications own
reconnection and resolve again by calling `connect_named` again. Wait for
`SessionUp` after connecting before issuing session commands.

```toml
[dependencies]
dlep-daemon = "0.2.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
