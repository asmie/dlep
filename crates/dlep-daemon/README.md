# dlep-daemon

Embeddable asynchronous router and modem runtime for DLEP (RFC 8175).
Linux strict TCP GTSM requires CAP_NET_RAW. Experimental macOS/FreeBSD transport requires
`config.shared.network.gtsm_enforce = false`; configuration checks and builders
reject the strict default before startup. Native macOS loopback checks passed;
native FreeBSD validation is pending.

Requires Rust 1.85 or newer.

Modems can set `config.discovery.offer_retries` (0–5, default 0) and
`offer_retry_interval_ms` (minimum/default 1000) for additional unicast Peer
Offers after a valid probe. Each socket retains at most 64 bursts, preserving
packet metadata and outgoing extension hooks. Connected routers suppress/cancel
retries, and shutdown owns all timers. Full `ModemConfig` initializers need the
new `discovery` field or a default.

Set `config.shared.network.discovery_dual_stack = true` with an explicit
`interface` to run IPv4 and IPv6 discovery together. Both usable address
families are required. `bind_addr` still selects the modem's single TCP listener;
both discovery transports advertise its concrete endpoint. Startup failure,
shutdown, and cancellation clean up the complete discovery group.

Router handles support numeric peers with `connect_static(addr)`, named peers
with `connect_named(host, port)`, and explicit certificate identities with
`connect_static_with_server_name(addr, name)`. Named connections preserve the
requested host for TLS verification and try up to 16 distinct resolver answers
within 15 seconds. Events use the connected numeric endpoint; applications own
reconnection and resolve again by calling `connect_named` again. Wait for
`SessionUp` after connecting before issuing session commands.

`ScopedPeer::new(ipv6, "eth0", port)` represents a link-local peer with a named
interface. `connect_scoped(&peer)` resolves that interface afresh and verifies
the IPv6 IP SAN. Configured peers use `RouterConfig.scoped_peers`; serialization
combines them with numeric/DNS peers in TOML `static_peers`. Full router struct
initializers need the new field or a default.

Applications can configure plugins with `[extensions.NAME]` tables, stored in
`config.shared.extensions`. Register a matching factory on either daemon builder:

```rust,ignore
let daemon = RouterDaemon::builder()
    .config(config)
    .register_extension_factory("radio", make_radio)
    .with_rustls_client(client_tls)
    .spawn()
    .await?;
```

Here the application's `make_radio` has signature
`Fn(&ExtensionConfig) -> Result<Arc<dyn DlepExtension>, String>` and is
`Send + Sync + 'static`. `ExtensionConfig` is a TOML table; the factory validates
its schema and constructs the plugin. Missing tables supply empty settings.
Factories run before daemon networking and keep their registration order with
prebuilt extensions.

For reusable recipes, populate an `ExtensionCatalog`, validate with
`check_router_config_with_extensions(&config, &catalog)` or the modem equivalent,
then pass the catalog with `.extension_catalog(catalog)`. Each check/build invokes
the factories again, so constructors should validate settings and create local
state without starting session work. Catalog clones share recipes; factories
can create independent instances for each daemon. Prebuilt plugin instances
remain shared exactly as before. Unknown settings names and duplicate factory
names fail before factory invocation. The bundled commands have no dynamic
plugin loader and reject settings without registered factories.

Registered plugins can explicitly enable UDP discovery hooks with
`supports_discovery()`. Both daemon roles automatically pass their configured
plugins into discovery. The hooks can append bounded extension TLVs or inspect
validated signals with packet metadata, while core fields, GTSM, interface
filtering, and session negotiation remain managed by the existing paths.
Low-level discovery runners can use `run_discovery_with_extensions`; the
original `run_discovery` keeps its no-hook behavior. See the
[extension API](https://github.com/asmie/dlep/blob/master/crates/dlep-ext/README.md#discovery-hooks)
for the pre-session callback contract.

```toml
[dependencies]
dlep-daemon = "0.2.0"
```

See the [workspace documentation](https://github.com/asmie/dlep),
[deployment guide](https://github.com/asmie/dlep/blob/master/doc/deployment.md),
and [0.2.0 release notes](https://github.com/asmie/dlep/blob/master/CHANGELOG.md).

Licensed under MIT; see [LICENSE](LICENSE).
