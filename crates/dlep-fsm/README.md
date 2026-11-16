# dlep-fsm

Synchronous router and modem state machines for DLEP (RFC 8175), with deterministic events, actions, and timers. No network runtime is required.

Requires Rust 1.85 or newer.

`ModemDiscoveryFsm::with_offer_retries(count, interval)` enables up to five
additional offers after a probe's immediate reply, with intervals of at least
one second. The default sends no extras. Bursts are bounded to 64 endpoints;
repeated probes do not extend them. Runtimes retain the originating packet
metadata for retry timers and can cancel a peer's burst with
`FsmEvent::AppStopDiscoveryOffers { peer }` when TCP is accepted.

```toml
[dependencies]
dlep-fsm = "0.3.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.3.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
