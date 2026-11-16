# Deploying dlep-router and dlep-modem

This guide covers building, certificate provisioning, configuration, the
privileged-port question, firewalls, and native service managers. Working example
configs and service definitions live in [`examples/`](../examples/).

## 1. Build and install

Requires Rust 1.85+ (edition 2024). Linux supports strict TCP GTSM. Experimental
macOS and FreeBSD transport require an explicit TCP enforcement opt-out as described below.
See [CI documentation](ci.md) for validation scope.

Install version 0.2.0 from crates.io after publication:

```bash
cargo install dlep-router dlep-modem --version 0.2.0 --locked
```

Alternatively, `cargo install dlep --version 0.2.0 --locked` installs a single
launcher: `dlep router ...` and `dlep modem ...` accept all the corresponding
standalone flags and run in-process. When granting capabilities to this combined
binary, grant `cap_net_raw,cap_net_bind_service=ep` to the installed `dlep` path
if it will run the modem on port 854. The supplied systemd units use the
standalone executables. Cargo installs into `$CARGO_HOME/bin` (normally
`$HOME/.cargo/bin`); copy binaries to `/usr/local/bin` if using those units.

To build from a source checkout:

```bash
cargo build --release --workspace --locked
sudo install -m 0755 target/release/dlep-router target/release/dlep-modem /usr/local/bin/
```

### macOS transport

The experimental macOS path supports TCP/TLS sessions and ports discovery's
ancillary-data handling. Each macOS process must explicitly opt out of strict
TCP receive enforcement:

```toml
[network]
gtsm_enforce = false
```

Apply this to each role's configuration before `--check-config` or startup.
The default remains `true` and fails with an unsupported-platform error on
macOS, including for a router that has not connected yet. This validation opens
no sockets and checks platform support, not Linux packet-monitor privileges.
TLS validation, outbound TTL/hop limit 255, and UDP discovery's inbound TTL
checks remain enabled independently of this opt-out. Use a port above 1023 when
running without privileged-port access; Linux capability and systemd examples
below apply only to Linux.

Discovery uses `IP_PKTINFO` to retain the ingress interface and selects a usable
IPv4 address on that interface because Darwin leaves `ipi_spec_dst` empty.
Selected IPv4 egress uses `IP_BOUND_IF` plus the preferred source address;
IPv6 retains scoped packet information. Apple reports IPv4 TTL as one byte and
IPv6 hop limit as an integer; both are required and checked before decoding.
See Apple's [receive control-message implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_input.c)
and [IPv6 socket-option implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/ip6_output.c).

Native macOS CI builds the workspace commands and runs unprivileged
IPv4/IPv6 plaintext/TLS sessions, destination delivery, and discovery unicast
metadata checks. Those checks passed for `43f0ffd` in
[CI](https://github.com/asmie/dlep/actions/runs/43921858827). Physical-link
multicast and strict TCP reset monitoring remain follow-up work.

### FreeBSD transport

The experimental FreeBSD path also requires an explicit opt-out in each daemon:

```toml
[network]
gtsm_enforce = false
```

The strict default fails configuration checks and startup; it is never disabled
automatically. TLS verification and outbound TTL/hop limit 255 remain enabled,
and discovery still requires a received value of 255 before decoding. Use UDP
and TCP ports above 1023 for an ordinary user. Linux capabilities and systemd
examples do not apply to FreeBSD.

IPv4 discovery obtains ingress scope from `IP_RECVIF` and destination addresses
from `IP_RECVDSTADDR`. Multicast destinations are replaced with a usable unicast
address on the ingress interface for wildcard TCP offers. Multicast egress uses
the configured interface; unicast replies select its configured source address
with `IP_SENDSRCADDR` and follow the system routing table. IPv6 retains scoped
packet information. As on macOS, the IPv6 unicast-hop option also sets mapped
IPv4 TTL, so no unsupported IPv4 option is applied to IPv6 TCP sockets. See
FreeBSD's [IPv4 socket interface](https://github.com/freebsd/freebsd-src/blob/main/share/man/man4/ip.4)
and [IPv6 socket options](https://github.com/freebsd/freebsd-src/blob/main/sys/netinet6/ip6_output.c).

The new FreeBSD 15.1 VM job builds all workspace libraries/commands, tests the
portable protocol crates, and runs unprivileged loopback TCP/TLS and discovery
metadata cases. Native FreeBSD results are pending until this change is pushed.
Local Rust type-checks bypass native crypto compilation in an isolated temporary
copy; they do not establish native build/runtime support. Physical-link multicast,
strict TCP reset monitoring, and other BSD variants remain outside this evidence.

### Shell completions

All three commands accept `--generate-completions SHELL`, with `bash`, `elvish`,
`fish`, `powershell`, or `zsh`. The script goes to stdout and generation exits
before loading configuration, initializing logging, or opening sockets. Generate
it again after upgrading to keep options aligned with the installed version.

For Bash, load the script in the current shell:

```bash
source <(dlep --generate-completions bash)
```

For persistent Bash completion with the `bash-completion` package installed:

```sh
mkdir -p ~/.local/share/bash-completion/completions
dlep --generate-completions bash > ~/.local/share/bash-completion/completions/dlep
```

For Fish:

```sh
mkdir -p ~/.config/fish/completions
dlep --generate-completions fish > ~/.config/fish/completions/dlep.fish
```

For Zsh, save `dlep --generate-completions zsh` as `_dlep` in a directory on
`$fpath`, then initialize completion with `autoload -Uz compinit; compinit` in
your Zsh startup configuration. For PowerShell, save the generated script as a
`.ps1` file and dot-source it from your profile. For Elvish, save the script in
your library directory and load it from `rc.elv` with `use`.

The launcher script includes `router` and `modem` and their role-specific flags.
Requesting completions with `dlep router --generate-completions SHELL` or
`dlep modem --generate-completions SHELL` prints the same launcher script.
For standalone installations, generate a separate script with each installed
command (`dlep-router` and `dlep-modem`), using that command's name for the file
(`_dlep-router` for Zsh, `dlep-router.fish` for Fish, and so on).

## 2. Certificates

TLS is **on by default** (RFC 8175 security guidance). DLEP runs on
closed router↔modem links, so the expected setup is a small private CA —
there is deliberately no fallback to the system trust store. Certificate
revocation (CRLs) is not supported; rotate by reissuing and restarting.

Create a CA, a modem (server) certificate, and a router (client)
certificate. The modem certificate's subjectAltName **must** contain the
identity routers request: an IP SAN for numeric peers, or a DNS SAN for named
peers. This example uses an IP address:

```bash
MODEM_IP=192.0.2.10   # the address routers will connect to

# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout ca.key -out ca.pem -days 3650 -subj "/CN=dlep-ca"

# Modem (server) certificate with IP SAN
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout modem.key -out modem.csr -subj "/CN=dlep-modem"
openssl x509 -req -in modem.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out modem.pem -days 825 -extfile <(printf "subjectAltName=IP:%s" "$MODEM_IP")

# Router (client) certificate for mutual TLS
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout router.key -out router.csr -subj "/CN=dlep-router"
openssl x509 -req -in router.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out router.pem -days 825 -extfile <(printf "extendedKeyUsage=clientAuth")
```

Install to `/etc/dlep/pki/`. The shipped systemd units run as a static
`dlep` service user, so make the private keys readable by it and nobody
else:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin dlep
sudo install -d -m 0755 /etc/dlep /etc/dlep/pki
# On the modem host:
sudo install -m 0644 ca.pem modem.pem /etc/dlep/pki/
sudo install -m 0640 -g dlep modem.key /etc/dlep/pki/
# On the router host (create the same service user and directories there):
sudo install -m 0644 ca.pem router.pem /etc/dlep/pki/
sudo install -m 0640 -g dlep router.key /etc/dlep/pki/
```

The router needs: `ca.pem` (to verify the modem), `router.pem` + `router.key`
(its identity, when the modem sets `require_client_cert = true`).
The modem needs: `modem.pem` + `modem.key`, plus `ca.pem` when requiring
client certificates (recommended).

Library routers can instead use `connect_named("modem.example", 854)` with a
certificate containing `subjectAltName=DNS:modem.example`, or
`connect_static_with_server_name(addr, "modem.example")` to select that identity
without resolving DNS. CA trust and certificate validation still apply.
Named connections resolve afresh on each call and try up to 16 distinct answers
in resolver order within 15 seconds; the caller owns automatic retries and
hostname-to-session tracking. Events expose the connected numeric endpoint.
The CLI also accepts DNS peers and manages their retries as described below.

## 3. Configuration

Both binaries read a TOML file via `--config/-c` (env:
`DLEP_ROUTER_CONFIG` / `DLEP_MODEM_CONFIG`). Start from
[`examples/router.toml`](../examples/router.toml) and
[`examples/modem.toml`](../examples/modem.toml). All sections and fields
are optional; defaults select port 854, TLS on, and router discovery. TLS
identities and trust roots must still be supplied before startup.
Unknown keys and sections are rejected at parse time, including top-level
typos and settings for the wrong role (such as `[metrics]` on the router).
Finish each edit with `--check-config` to validate timer values, interfaces,
metrics, and TLS material as well.

Network flags override the loaded TOML for both `--check-config` and startup:

```sh
dlep modem --config /etc/dlep/modem.toml --interface radio0 \
  --bind-addr 192.0.2.10 --tcp-port 1854 --discovery-port 1854
dlep router --config /etc/dlep/router.toml --interface radio0 \
  --bind-addr 192.0.2.1 --discovery-port 1854
```

The standalone commands accept the same flags. `--bind-addr` takes a bare IPv4
or IPv6 address; select the interface separately for IPv6 scope. On the modem,
it controls the TCP listener and discovery address. On the router, it selects
the local discovery address/family; it does not set the TCP source address.
`--discovery-port` controls the modem UDP listener and router multicast
destination. Routers use an ephemeral source port and obtain each TCP address
and port from `--peer` or a Peer Offer; `--tcp-port` is therefore modem-only.
Its value may be zero to request an allocated TCP listen port, which discovery
advertises. Ports are numeric values from 0 to 65535; use a nonzero matching
discovery port for deployment (zero is useful only for ephemeral/local setups).

### DNS peers

Use an explicit port with a DNS name, IPv4 address, or bracketed IPv6 address:

```sh
dlep router --config /etc/dlep/router.toml --peer modem.example:854
```

Or set these top-level keys before any TOML section:

```toml
mode = "static"
static_peers = ["modem.example:854", "192.0.2.20:854", "[2001:db8::20]:854"]
```

Names must be valid ASCII DNS names (use their IDNA/punycode form when needed).
They are normalized to lowercase; a trailing dot retains absolute-name resolver
semantics. The system resolver runs on every connection attempt, including
retries after transport failures, failed initialization, and dropped sessions.
Up to 16 distinct answers are tried in resolver order within a shared 15-second
deadline. Resolution failures use the same 1–30 second reconnect backoff.
`--check-config` validates syntax and TLS files without DNS queries.

TLS verifies the configured hostname and sends it as SNI, including when a
later answer changes address family. Issue the modem certificate with a matching
DNS SAN. Numeric peers continue to require matching IP SANs. Events, snapshots,
and adapter records identify the connected numeric endpoint.

Duplicate configured entries are coalesced. If names or numeric peers overlap,
the driver reserves each endpoint during connection and skips active endpoints;
an alias remains queued with backoff rather than borrowing another identity's
authenticated session. At most eight connection jobs run concurrently, with
resolution counted toward admission against the session budget. Shutdown cancels
pending jobs; the OS resolver may finish its underlying blocking work afterward.

Rust callers keep numeric peers in `RouterConfig.static_peers` and add validated
DNS peers with `RouterConfig.named_peers.push(NamedPeer::new("modem.example", 854)?)`.
Serialization combines numeric, DNS, and named-zone lists into TOML
`static_peers`; `named_peers` and `scoped_peers` are not separate TOML settings.
The library handle does not automatically connect these lists; embedders own
connection scheduling. See [named IPv6 interfaces](#named-ipv6-peer-interfaces).

An optional router `[adapter]` section runs an external integration process;
`command` is an absolute executable path and `args` defaults to `[]`.
`--check-config` checks the section and command file without running it. The
adapter receives complete session/destination snapshots and can issue targeted
session address, announce, withdrawal, and link-characteristic commands. See the
[router adapter protocol](router-adapter.md) and
[example consumer](../examples/router-adapter.py). Routing policy stays in the
adapter. It shares the service sandbox and user, with ambient capabilities
cleared; provision access to your routing service explicitly.

### Named IPv6 peer interfaces

Static link-local peers can use an interface name instead of its current numeric
scope ID:

```sh
dlep router --config /etc/dlep/router.toml --peer '[fe80::1%eth0]:854'
```

```toml
mode = "static"
static_peers = ["[fe80::1%eth0]:854"]
```

The name is case-sensitive and local to the router. It selects the destination
zone; it does not bind the TCP source address or set the discovery interface.
Names are resolved to an interface index on every connection attempt, including
retries after missing devices or dropped sessions. A recreated interface can
therefore use a new index without editing configuration. Resolution errors use
the existing reconnect backoff. `--check-config` checks syntax without querying
the named peer interface, so the device may be absent during validation.

Named zones require a unicast IPv6 link-local address and a nonempty interface
name within the platform's name-length limit. Numeric scopes such as
`[fe80::1%3]:854` retain their existing behavior. This is endpoint syntax, not
URI syntax; `%` is written literally. `--bind-addr` still takes a bare IP and
uses the separate `--interface` setting for discovery/listener scope.

TLS verifies the bare IPv6 address against an IP SAN. The interface name is
never a DNS identity or SNI value. Numeric and named-zone entries resolving to
the same endpoint share connection reservations, preventing duplicate sessions.
Connection limits, initialization deadlines, backoff, cancellation, and bounded
numeric history also apply. Events and adapter snapshots retain numeric scope
IDs in their connected endpoint.

Rust callers use `ScopedPeer::new(ipv6, "eth0", port)` and
`RouterDaemon::connect_scoped(&peer)`, or add it to `RouterConfig.scoped_peers`
for the bundled driver's startup scheduling. `ScopedPeer::resolve()` performs a
fresh interface lookup without DNS; custom callers own reconnect scheduling.
Full `RouterConfig` initializers need the new `scoped_peers` field or a default.

### Configured extension factories

Embedded applications can configure registered plugins on either role:

```toml
[extensions.radio]
threshold = 12
channels = [1, 6, 11]
```

These keys are illustrative: the plugin factory owns its entire settings schema,
including nested values and defaults. Applications register a matching name with
`register_extension_factory("radio", factory)` on the daemon builder, or supply
an `ExtensionCatalog` with `.extension_catalog(catalog)`. The factory receives an
`ExtensionConfig` (a TOML table) and returns `Result<Arc<dyn DlepExtension>, String>`.
For typed schemas, deserialize `toml::Value::Table(settings.clone())` with
`try_into()`; `#[serde(deny_unknown_fields)]` rejects plugin-setting typos.

Settings are stored in `SharedConfig.extensions`. A missing table supplies empty
settings so the factory can apply defaults. Every registered factory runs once
per build, in registration order alongside prebuilt plugins. Catalog clones
share factory recipes, allowing each build to create its own instances; they
continue to share explicitly registered prebuilt instances. Factories should
validate and construct local state without starting session work. Configuration
checks also invoke them, then discard the constructed instances.

Use `check_router_config_with_extensions(config, catalog)` or
`check_modem_config_with_extensions(config, catalog)` for embedded applications;
the ordinary checks use an empty catalog. Unregistered settings, empty/duplicate
factory names, and factory validation errors fail startup before daemon sockets
or tasks. Factory names are case-sensitive. Replacing a builder's catalog with
`.extension_catalog(...)` replaces all its prior registrations.

The bundled `dlep`, `dlep-router`, and `dlep-modem` commands have no dynamic plugin
loader. They reject nonempty extension settings before TLS setup, adapter
startup, or networking. An application must register the relevant factories;
adding a TOML section alone does not install a plugin. Settings are fixed when
the daemon starts; restart or construct another daemon to change them.

### Destination admission

Routers accept all unsolicited Destination Up announcements by default. A
router-only `[destinations]` section can select which MAC addresses to accept:

```toml
[destinations]
default_accept = false
allow = ["02:00:00:00:00:01", "02:00:00:00:00:02"]
```

Alternatively, use `default_accept = true` with `deny = ["02:00:00:00:00:03"]`
to accept everything except listed destinations. An empty allow list with
`default_accept = false` declines every unsolicited destination. MACs must use
six or eight colon-separated hexadecimal octets matching
`network.mac_address_format`; duplicates, conflicting entries, and unknown
fields fail `--check-config` and library startup.

A declined Up receives Not Interested, as permitted by
[RFC 8175 §12.12](https://www.rfc-editor.org/rfc/rfc8175.html#section-12.12).
The router publishes no Destination Up event or retained destination for it.
The modem retains its physical data and reports the refusal through its normal
Up-response event. Explicit router Announce commands still express interest and
can retrieve such a destination, including later metric/address changes. This
is unsolicited-announcement admission, not an access-control boundary.

Policy is fixed at daemon startup, applies to all modem sessions, and takes
effect again on reconnect. Existing accepted destinations retain their normal
update/withdrawal behavior. Restart the router to change the configured policy.
Library users can set `RouterConfig.destinations` using `DestinationPolicyConfig`;
direct FSM users can set the typed `SessionConfig.destination_policy` using
`DestinationPolicy`. Typed policies give explicit denials precedence if a caller
includes an address in both sets; TOML configuration rejects that conflict.

### Modem secured-medium declaration

Set the modem's top-level `secured_medium` value before any TOML section:

```toml
peer_description = "radio modem"
secured_medium = true

[network]
use_tls = true
```

The default is `false`. This advertises the Peer Type Secured Medium flag in
Peer Offers and Session Initialization Responses. Under
[RFC 8175 §13.4](https://www.rfc-editor.org/rfc/rfc8175.html#section-13.4), it
declares that the shared RF medium implements access control. It is independent
of DLEP TLS, encryption, and certificate validation; setting it does not enforce
access control or change any transport security setting. Configure it to match
the actual modem medium. Router configuration rejects this modem-only field.

Library callers use `ModemConfig.secured_medium`. Router-side `PeerOffer` and
`PeerInfo` expose `secured_medium: Option<bool>`, and retained session snapshots
carry the same value in `peer`. An offer without Peer Type has `None`; validated
modem session initialization supplies `Some(true)` or `Some(false)`. A modem's
metadata about its remote router uses `None` because the flag has no meaning
when sent by a router. The initialization response is authoritative for session
metadata, even if a discovery offer advertised a different value.

| Section | Field | Default | Meaning |
|---|---|---|---|
| top level (router) | `mode` | `"discovery"` | `"discovery"` or `"static"` |
| top level (router) | `static_peers` | `[]` | static modem endpoints: `HOST:PORT`, `IPv4:PORT`, `[IPv6]:PORT`, or `[fe80::IP%INTERFACE]:PORT` |
| top level | `peer_description` | binary name | Peer Type data item text |
| top level (modem) | `secured_medium` | `false` | Modem declaration of access control on the shared RF medium; independent of TLS |
| `[extensions.NAME]` | plugin-defined | none | Settings for a named factory registered by an embedded application |
| `[limits]` (router) | `max_sessions` | `64` | positive bound on TCP/TLS attempts plus registered sessions |
| `[limits]` (router) | `max_discovered_peers` | `256` | positive bound on retained non-static endpoints, including active peers |
| `[limits]` (router) | `peer_retention_secs` | `300` | positive retention window for inactive non-static peers; failed retries do not refresh it |
| `[network]` | `interface` | none | Discovery interface name: membership, sending, and receive filtering |
| `[network]` | `discovery_dual_stack` | `false` | Run both discovery families; requires an explicit interface with usable IPv4 and IPv6 addresses |
| `[network]` | `mac_address_format` | `"eui48"` | Destination MAC format: `"eui48"` or `"eui64"`; must match the modem's router-facing link |
| `[network]` | `discovery_v4_group` | `224.0.0.117` | IPv4 discovery multicast group |
| `[network]` | `discovery_v6_group` | `ff02::1:7` | IPv6 discovery multicast group (IPv6 bind or dual-stack discovery) |
| `[network]` | `discovery_port` | `854` | modem UDP listen port / router multicast destination port; router source port is ephemeral |
| `[network]` | `tcp_port` | `854` | modem TCP/TLS listen port; ignored by router (which uses offered/static endpoints) |
| `[network]` | `bind_addr` | `0.0.0.0` | discovery source preference/default family and modem TCP listener address; does not bind router TCP sources |
| `[network]` | `use_tls` | `true` | TLS for the session transport |
| `[network]` | `gtsm_enforce` | `true` | Linux TCP minimum-TTL filter and strict reset monitor (`CAP_NET_RAW`); discovery always checks TTL |
| `[tls]` | `cert` / `key` | none | identity (modem: required; router: mTLS) |
| `[tls]` | `ca_bundle` | none | trust roots (router: required; modem: for mTLS) |
| `[tls]` | `require_client_cert` | `false` | modem requires router client certs; not used by router |
| `[timers]` | `heartbeat_interval_ms` | `60000` | heartbeat interval, minimum 1000 ms |
| `[timers]` | `discovery_interval_ms` | `5000` | Peer Discovery resend interval, minimum 1000 ms |
| `[timers]` | `session_init_timeout_ms` | `5000` | positive deadline for initialization: router awaits response, modem awaits request |
| `[timers]` | `termination_timeout_ms` | omitted: `4 × heartbeat_interval_ms` | positive explicit override for Session Termination Response; default resolves to `240000` ms |
| `[discovery]` (modem) | `offer_retries` | `0` | Extra Peer Offers after the immediate reply, 0–5 |
| `[discovery]` (modem) | `offer_retry_interval_ms` | `1000` | Interval between additional offers, minimum 1000 ms |
| `[metrics]` (modem) | `max_data_rate_rx_bps` / `max_data_rate_tx_bps` | `0` | maximum receive/transmit rates, bits/second |
| `[metrics]` (modem) | `current_data_rate_rx_bps` / `current_data_rate_tx_bps` | `0` | current receive/transmit rates, bits/second |
| `[metrics]` (modem) | `latency_us` | `0` | transmission delay, microseconds |
| `[metrics]` (modem) | `resources` / `rlq_rx` / `rlq_tx` | omitted | supported resource/link quality percentages, 0–100 |
| `[metrics]` (modem) | `mtu` | omitted | supported MTU, bytes |

Configure mandatory rates and latency for your actual link. Only set optional
metrics that the modem can supply: omitted optional fields declare them
unsupported and keep them off the wire. Explicit zero remains a reported value.
Support is fixed for each session; enabling another optional metric requires a
new session. Configured current rates cannot exceed their maximum rates.

Set `mac_address_format` on both peers to match the modem's router-facing
link-layer format ([RFC 8175 §13.7](https://www.rfc-editor.org/rfc/rfc8175.html#section-13.7)).
It is an explicit local policy, not negotiated or inferred from the first
destination or the discovery interface. The default is EUI-48; EUI-64 links
must set `mac_address_format = "eui64"`. A daemon applies this policy to all its
sessions; deployments with different link formats need separately configured
daemon instances (direct FSM embedders configure each `SessionConfig`).
The format cannot change during a session, even after every destination is
removed. Incorrect local destination commands return
`CommandError::MacAddressFormatMismatch`; incorrect received MAC items cause
Session Termination with Invalid Data (130). Negotiated extensions must also
respect this policy: an incompatible queued core MAC item is rejected before
writing and ends the session through runtime error cleanup.

DLEP transactions do not have individual deadlines (RFC 8175 §8). The session
heartbeat mechanism detects a silent peer. Remove the previously introduced
`[timers].link_characteristics_timeout_ms` setting if present; it is no longer
supported and configuration parsing rejects it.

Each peer sends heartbeats at its own advertised interval. Valid received
traffic refreshes a separate silence deadline of twice the remote peer's
interval; it does not postpone local sends. The two peers may use different
intervals. See [RFC 8175 §12.20](https://www.rfc-editor.org/rfc/rfc8175.html#section-12.20)
and [Appendix B.7](https://www.rfc-editor.org/rfc/rfc8175.html#appendix-B.7).

CLI flags override the file: `--interface`, `--dual-stack-discovery`, `--no-tls`, `--cert`, `--key`,
`--ca-bundle`, and (router) `--peer ADDR` (repeatable; implies static mode).

For discovery on a particular link, set `interface = "eth1"` under `[network]`
or pass `--interface eth1`. Keep the modem's `bind_addr = "0.0.0.0"` to listen on
all TCP addresses, or supply an IPv4 address assigned to that interface. The
address is also used as the preferred discovery source. Otherwise the lowest
IPv4 address on the named interface is selected. Discovery traffic arriving on
other interfaces is discarded before decoding; replies use the selected
interface and source address. This uses ordinary IP socket options, without
an additional capability requirement.

An explicit name is checked against the current host by `--check-config` and at
startup: the interface must exist, be up, and have a usable address in the
chosen family and multicast support (loopback is allowed for IPv4 testing). Socket setup errors for a named interface fail
startup. With no name, a specific IPv4 `bind_addr` selects its interface;
`0.0.0.0` leaves selection to the kernel routing table. `interface` controls
discovery only, not TCP device binding.

For IPv6 discovery, configure both peers with an IPv6 `bind_addr` and use
`discovery_v6_group` (default `ff02::1:7`). By default, each daemon discovers over one family:
IPv4 with `0.0.0.0`, IPv6 with `::`. For example:

```toml
[network]
interface = "eth1"
bind_addr = "::"
discovery_v6_group = "ff02::1:7"
```

An IPv6 wildcard requires `interface`; a concrete address identifies its
interface if unambiguous. Without a preferred address, a link-local address is
preferred, then the lowest usable address. The modem replaces a wildcard
Connection Point with that unicast address, and the router supplies the local
interface scope when connecting to link-local endpoints. A link-local TCP
listener also obtains its scope from the interface. Both multicast and unicast
signals use hop limit 255, with received hop limits checked before decoding.
Use a multicast-capable interface for IPv6 discovery; Linux loopback alone does
not provide the link multicast route.

To run IPv4 and IPv6 discovery together, enable:

```toml
[network]
interface = "eth1"
discovery_dual_stack = true
bind_addr = "0.0.0.0"
```

The equivalent CLI options are `--dual-stack-discovery --interface eth1`.
The interface must be up, support multicast, and have usable addresses in both
families. `--check-config` validates both. The flag enables the setting; omitting
it preserves the TOML value, whose default is `false`. A concrete `bind_addr`
selects the preferred discovery source in its family; the other family selects
an interface address automatically, preferring IPv6 link-local addresses.

The modem still has one TCP listener, selected by `bind_addr` and `tcp_port`.
Both discovery transports advertise its address, resolving wildcard listeners
to a concrete address on the interface in the TCP listener's family. An offer
received over IPv6 can therefore advertise IPv4 TCP, or the reverse. TLS uses
that advertised TCP identity. Link-local endpoints retain their ingress scope.
The modem shares one UDP discovery port across both families, including when
port `0` requests an ephemeral port; routers use independent ephemeral source
ports. Both sockets bind before discovery tasks start. Partial startup failure
releases the sockets and modem TCP listener; shutdown or cancellation stops both
families, and an unexpected child-task exit stops the complete discovery group.

Connected-router suppression still matches the established TCP source address
and scope. A probe using the router's other IP family can receive an offer;
endpoint scheduling prevents duplicate TCP connections to an occupied endpoint.
Rust callers using full `NetworkConfig` initializers must supply the new
`discovery_dual_stack` field or use `..NetworkConfig::default()`.


### Modem Peer Offer retries

The default modem behavior is one immediate Peer Offer per valid Peer Discovery.
To recover lost offers before the router's next periodic probe, configure the
modem only:

```toml
[discovery]
offer_retries = 2
offer_retry_interval_ms = 1000
```

This sends the immediate response and up to two further unicast offers, one
second apart. It is an optional delivery policy; the immediate response and
router's regular probes still follow [RFC 8175 §7.1](https://www.rfc-editor.org/rfc/rfc8175.html#section-7.1).
At most five additional attempts are allowed, with a minimum one-second
interval even when the configured retry count is zero. `--check-config` and
startup use the same validation; routers reject this modem-only section.

Each discovery socket retains at most 64 pending bursts, keyed by the router's
UDP endpoint (including IPv6 scope). At capacity, new probes still receive their
immediate response but do not schedule retries. Repeated probes from a pending
endpoint also receive immediate replies without extending or resetting its
burst. Dual-stack discovery has an independent bounded queue for each family.
Failed sends consume attempts, so an unavailable route cannot cause unlimited
retries.

Each retry rebuilds the offer and runs outgoing extension hooks with the
original probe's local address, interface index, and reply endpoint. Wildcard
TCP connection points remain usable, and TLS/secured-medium declarations are
preserved. Retries check the connected-router registry before sending or
calling hooks. An observed TCP connection cancels the remaining burst,
including during TLS/DLEP initialization; a later probe can start a new burst
after that connection closes. Existing address/scope matching also applies
across UDP and TCP families. Shutdown or task cancellation releases all timers.

For Rust callers, `ModemConfig.discovery` contains `ModemDiscoveryConfig`;
full modem struct initializers need the field or `..ModemConfig::default()`.
Low-level users can enable the same bounded FSM policy with
`ModemDiscoveryFsm::with_offer_retries(count, interval)`. Daemon runners supply
connected-router suppression automatically; separate custom runtimes must
deliver `FsmEvent::AppStopDiscoveryOffers { peer }` when appropriate.

### Configuration validation

Validate without starting the daemon:

```bash
dlep-router --config /etc/dlep/router.toml --check-config
dlep-modem  --config /etc/dlep/modem.toml  --check-config
```

`configuration OK` on stdout and exit code 0 mean the TOML parses, static
mode has peers, any explicit discovery interface is usable on this host, modem
metrics/offer-retry settings and timers pass validation, and all TLS material loads. This does
not open sockets or check GTSM capabilities, firewall rules, or peer reachability.

Router `[limits]` values are checked by `--check-config` and daemon startup.
The session budget is reserved before opening TCP and held through TLS,
initialization, session operation, and cleanup; cancellation and failures release
it. The binary defers static peers and retry deadlines while the budget is full.
Library callers receive `SessionLimitReached` and may retry after capacity returns.

The peer-history budget includes active and inactive endpoints absent from
`static_peers`. New endpoints evict the oldest inactive entry when full; active
entries are never evicted. If all retained entries are active, admission returns
`PeerHistoryFull`. Inactive discovered peers expire after `peer_retention_secs`,
with cleanup at least once a second. Successful initialization resets the window,
which starts at disconnect; failed initialization and TCP/TLS retries do not
extend it. Initial unsuccessful sessions start the window at registration.
Expired or evicted peers stop retrying until a new discovery offer or explicit
connection request. Configured numeric static peers never expire or consume discovered
history slots; their storage is bounded by the configured list. DNS answers use
the bounded endpoint history, but configured hostnames remain eligible for retry
after answers expire or are evicted. These limits do
not require a static-peer count smaller than the session budget.

`connection_states()` subscribers must discard retry records for removed
non-static endpoints. The `establishment_count` field is now an opaque daemon-wide
establishment generation, not a per-endpoint arithmetic count: compare it for
change, so eviction/re-admission coalesced into one snapshot still resets backoff.

Timer limits are checked by `--check-config` and by both daemon builders before
opening sockets. Heartbeat and discovery intervals below 1000 ms are rejected
(RFC 8175 §7.3.1 and §7.1); initialization and termination timeouts must be at
least 1 ms. Errors name the field, minimum, and supplied value. Zero does not
disable a timer.

### Structured logging

Both standalone daemons and `dlep router` / `dlep modem` accept
`--log-format text|json`. Precedence is the CLI flag, then `DLEP_LOG_FORMAT`,
then `text`. Invalid formats fail argument parsing before daemon startup.
The existing `--log-level` / `DLEP_LOG` filter applies to either format.

```sh
dlep router --config /usr/local/etc/dlep/router.toml --log-format json
# Or set the service environment:
DLEP_LOG_FORMAT=json dlep-modem --config /usr/local/etc/dlep/modem.toml
```

JSON mode writes one tracing event per line to stdout without ANSI escapes.
Records contain `timestamp`, `level`, `target`, and a `fields` object containing
the message and event values. Numbers and booleans retain their types; quoted
or multiline descriptions are escaped within one physical line. For example:

```json
{"timestamp":"2026-11-16T12:00:00Z","level":"INFO","fields":{"message":"session up","addr":"192.0.2.10:1854","tls":true},"target":"dlep_router"}
```

Additional fields and span context may appear. Event messages and event-specific
fields are operational logs, not a versioned state API; use the router adapter
for retained session/destination state. The format uses
[tracing-subscriber's JSON formatter](https://docs.rs/tracing-subscriber/0.3.23/tracing_subscriber/fmt/format/struct.Json.html).

Help/version, shell completions, and the `configuration OK` result remain plain
command output. CLI errors, invalid-filter warnings, and inherited adapter
stderr keep their existing diagnostic formats. Collect tracing stdout separately
if the collector requires every line to be JSON. In systemd use a drop-in with
`Environment=DLEP_LOG_FORMAT=json`; for launchd add `DLEP_LOG_FORMAT` to the
plist's `EnvironmentVariables` dictionary. FreeBSD's rc.d environment override
is `dlep_router_env="DLEP_LOG_FORMAT=json"` (or `dlep_modem_env`); the supervisor
still prefixes its syslog output.

## 4. Socket privileges

The modem listens on the DLEP well-known port (854, UDP and TCP), which normally
requires `CAP_NET_BIND_SERVICE` on Linux. The router uses ephemeral UDP and TCP
source ports and needs no bind capability. Strict TCP GTSM requires
`CAP_NET_RAW` on both roles, independently of port numbers.

Use the supplied systemd units to grant these capabilities to the `dlep` service
user, or apply file capabilities for manual runs:

```sh
sudo setcap cap_net_bind_service,cap_net_raw=ep /usr/local/bin/dlep-modem
sudo setcap cap_net_raw=ep /usr/local/bin/dlep-router
```

To avoid privileged binds, choose modem `discovery_port` and `tcp_port` values
of at least 1024. Set the router's `discovery_port` to the same UDP port; TCP
uses the modem's advertised port, or the explicit port in `static_peers`.
Setting the router's `tcp_port` has no effect. Nonstandard ports do not remove
the strict GTSM monitoring capability requirement.

Do **not** run the daemons as root.

## 5. Firewall

| Direction | Proto | Port | Purpose |
|---|---|---|---|
| router → 224.0.0.117 or ff02::1:7 | UDP | 854 | Peer Discovery multicast on the selected family/interface |
| modem → router | UDP | ephemeral | unicast Peer Offer reply |
| router → modem | TCP | 854 | DLEP session (TLS) |

Discovery sends with TTL 255 and drops discovery packets whose TTL is not 255 (GTSM, RFC 5082) —
discovery only works between directly-connected (one-hop) peers. The receive
socket filters TTL/hop limit before decoding. Malformed or truncated signals
are discarded without delaying other peers or producing a warning per packet.
Socket errors use a receive retry delay while timers and shutdown remain active.

Strict TCP GTSM also requires `CAP_NET_RAW` on Linux to monitor rejected packets
and reset the affected connection immediately (RFC 8175 §14). The sample
systemd units grant this capability; manual installation commands are in §4.

Reinstalling a binary may remove its file capabilities. Missing monitoring
privileges cause an explicit error; `gtsm_enforce = false` is an opt-out for
nonconforming development peers, not a production default.

## 6. systemd

```bash
sudo install -m 0644 examples/modem.toml /etc/dlep/modem.toml
# Edit the configuration and provision PKI, then validate as the service user:
sudo -u dlep /usr/local/bin/dlep-modem --config /etc/dlep/modem.toml --check-config
sudo install -m 0644 examples/dlep-modem.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dlep-modem
journalctl -u dlep-modem -f
```

Same for `dlep-router.service`. Log verbosity: `--log-level
trace|debug|info|warn|error` or the `DLEP_LOG` env var (add
`Environment=DLEP_LOG=debug` to the unit). `--log-level` takes precedence over
`DLEP_LOG`; the default is `info`. `RUST_LOG` is not read.

The units restrict filesystem writes, device access, kernel/control-group
changes, real-time scheduling, and set-ID file creation. Socket families include
`AF_PACKET` for strict GTSM monitoring and `AF_NETLINK` for interface enumeration.
The router grants only `CAP_NET_RAW`; the modem also grants
`CAP_NET_BIND_SERVICE`. A [radio adapter](radio-adapter.md#systemd) started by
the modem runs in the same sandbox without the modem's capabilities; one that
needs a device or writable state requires a drop-in such as
`PrivateDevices=no` with `DeviceAllow=`. If the adapter fails, the modem exits
with an error and `Restart=on-failure` restarts both.

Both binaries handle SIGTERM (`systemctl stop`) and SIGINT (Ctrl-C). They stop
new work and send Session Termination with Shutting Down status to established
peers, then wait for the responses or `termination_timeout_ms`. Repeated stop
signals leave that exchange running. Incomplete TLS handshakes are cancelled;
the router also interrupts TCP/TLS connection attempts during startup, discovery,
and reconnection. The example units use `KillSignal=SIGTERM` explicitly.
Keep systemd's `TimeoutStopSec` longer than the configured termination timeout
plus the transport write timeout (5 seconds), allowing scheduling overhead.
When `termination_timeout_ms` is omitted, the deadline is four local heartbeat
intervals, following RFC 8175 §7.4. At the default 60-second heartbeat this is
240 seconds. A response closes the session immediately; the full deadline is
used only if the peer does not respond. The example units use
`TimeoutStopSec=300s`; increase it if you increase the effective protocol
deadline. An explicit positive `termination_timeout_ms` overrides the derived
value; shorter values are a deployment choice departing from the RFC's
recommendation.

The router runs up to eight TCP/TLS connection attempts concurrently across
static startup, discovery, and reconnection. A slow endpoint does not block
other attempts or event handling. Static peers that are unavailable at startup
remain eligible for retry instead of stopping the process. Static peers and
retries wait when the pool is full; extra discovery offers are skipped until a
later offer. Endpoints within a single offer retain their preference order,
with fallback attempted sequentially. Shutdown cancels pending attempts before
gracefully terminating registered sessions.

After a session drops, the router binary waits 1 second before retrying, then
doubles the delay after unsuccessful retries, up to 30 seconds. Connection
failures start the next delay when the attempt finishes. Pending TCP/TLS
connections and DLEP initialization suspend further attempts without clearing
the failure history. Rejection or failure during initialization resumes
the retained delay when the session closes. Successful DLEP initialization resets
it. Discovery offers do not bypass the delay for that endpoint; new endpoints
remain eligible for connection. Reconnection uses retained daemon connection
state, so event-stream lag does not strand a disconnected peer or lose a
successful initialization's backoff reset. Other application events can still
be lost when a broadcast subscriber falls behind.

A modem stops answering discovery from a router's source IP while it has an
accepted TCP connection from that address, including during TLS handshakes and
DLEP initialization. UDP and TCP source ports do not need to match. IPv6
link-local addresses are matched within their interface scope. Other router
addresses remain eligible; the last connection closing restores replies.

## 7. macOS launchd and FreeBSD rc.d

The experimental native services use the standalone executables in
`/usr/local/bin`, a dedicated non-login `dlep` user/group, and configuration in
`/usr/local/etc/dlep`. Provision that account with your platform's account
management tools before loading a service. On FreeBSD, for example:

```sh
sudo pw groupadd dlep
sudo pw useradd dlep -g dlep -d /nonexistent -s /usr/sbin/nologin
```

On macOS, provision a non-login `dlep` account and `dlep` group using your site's
directory-service policy; the launchd definitions refer to both by name.
Installing a plist does not create them.

Use the shared [native router](../examples/native/router.toml) and
[native modem](../examples/native/modem.toml) configurations. Both explicitly
set `gtsm_enforce = false`, retain TLS, and use UDP/TCP port **1854** so the DLEP
process needs no privileged-port access. A router in discovery mode must use
the modem's UDP port. For static mode, use the modem's TCP port in `static_peers`.
These settings do not change the Linux examples or protocol defaults.

On each host, install only that host's role, and adjust its interface and PKI
paths before starting it. For a modem:

```sh
sudo install -d -o root -g dlep -m 0750 /usr/local/etc/dlep /usr/local/etc/dlep/pki
sudo install -o root -g dlep -m 0640 examples/native/modem.toml /usr/local/etc/dlep/modem.toml
# Generate certificates as in section 2, with the modem's real IP/DNS SAN.
sudo install -o root -g dlep -m 0640 ca.pem modem.pem modem.key /usr/local/etc/dlep/pki/
# Edit /usr/local/etc/dlep/modem.toml, then validate with the service identity:
sudo -u dlep /usr/local/bin/dlep-modem --config /usr/local/etc/dlep/modem.toml --check-config
```

Use `router.toml`, `router.pem`, `router.key`, and `dlep-router` for the router.
The CA's private key stays off both service hosts. Match firewall rules to the
chosen port. Adapters inherit the service identity and need their own device
or routing permissions. These services provide user separation and supervision;
they do not reproduce the Linux systemd sandbox.

### macOS launchd services

Install [the modem plist](../examples/launchd/org.dlep.modem.plist) as a root-owned
LaunchDaemon after validating its configuration:

```sh
sudo install -d -o root -g dlep -m 0750 /var/log/dlep
sudo touch /var/log/dlep/modem.log /var/log/dlep/modem.err.log
sudo chown dlep:dlep /var/log/dlep/modem.log /var/log/dlep/modem.err.log
sudo chmod 0640 /var/log/dlep/modem.log /var/log/dlep/modem.err.log
sudo install -o root -g wheel -m 0644 examples/launchd/org.dlep.modem.plist /Library/LaunchDaemons/
plutil -lint /Library/LaunchDaemons/org.dlep.modem.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/org.dlep.modem.plist
sudo launchctl print system/org.dlep.modem
sudo tail -f /var/log/dlep/modem.log /var/log/dlep/modem.err.log
```

Use `org.dlep.router.plist` and label `org.dlep.router` for the router. The daemon
runs with `router.log` and `router.err.log`; provision those files the same way.
The log directory stays root-owned, while each log file is writable by `dlep`.
It runs in the foreground as `dlep`, starts when loaded, and restarts after a
nonzero exit with a two-second throttle. A successful exit is left stopped.
The files use absolute paths; shell variables are not expanded in plist values.

To stop and unload the job:

```sh
sudo launchctl bootout system/org.dlep.modem
```

To apply changed configuration, boot out and bootstrap the job again. Avoid
`kickstart -k` when a graceful DLEP shutdown is required. `ExitTimeOut = 300`
allows the default 240-second protocol termination deadline plus transport I/O;
increase it if your configured deadline is longer. See Apple's
[launchd property-list reference](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5)
for restart and shutdown settings. Manage log rotation according to local
policy; unload/reload the job when replacing its open log files.

### FreeBSD rc.d services

Install [the modem script](../examples/rc.d/dlep_modem), enable it, and start it:

```sh
sudo install -o root -g wheel -m 0555 examples/rc.d/dlep_modem /usr/local/etc/rc.d/dlep_modem
sudo sysrc dlep_modem_enable=YES
sudo service dlep_modem start
sudo service dlep_modem status
sudo tail -f /var/log/messages
```

Use `dlep_router` and `dlep_router_enable` for the router. Each script defaults
to disabled. `daemon(8)` supervises the DLEP child as `dlep`, routes stdout/stderr
to syslog at notice priority with the service name, and restarts it after two
seconds on exit.
The supervisor stays privileged to maintain its root-owned PID file in
`/var/run`; the DLEP process runs without those privileges. Keep the scripts'
supervisor options intact; configure DLEP through its TOML file.

Stop or restart after editing configuration:

```sh
sudo service dlep_modem stop
# Or restart, allowing the existing process to shut down first:
sudo service dlep_modem restart
```

The script targets the **supervisor** PID. SIGTERM is forwarded to DLEP, and
the supervisor waits for the termination exchange before exiting, without
restarting the child. A child PID would instead trigger an unwanted restart.
See FreeBSD's [daemon(8) reference](https://github.com/freebsd/freebsd-src/blob/releng/15.1/usr.sbin/daemon/daemon.8)
and [rc.d guide](https://docs.freebsd.org/en/articles/rc-scripting/).
Allow the machine-wide `rcshutdown_timeout` enough time for the configured
termination deadline and other services during system shutdown; a watchdog
that expires sooner can interrupt that exchange. No reload command is provided.

CI checks plist and shell syntax. Native launchd/rc.d start, restart, and stop
execution is not yet validated; the portable transport tests exercise sessions
independently of these service definitions.

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `tls.ca_bundle is required when use_tls = true` | Router with TLS on but no trust roots. Set `[tls] ca_bundle` or pass `--ca-bundle`. |
| `tls.cert is required on the modem (server) side…` | Modem with TLS on but no identity. Set `[tls] cert` + `key`. |
| `tls.key is required on the modem (server) side…` | Modem with a cert but no private key. Set `[tls] key`. |
| `tls.require_client_cert = true requires tls.ca_bundle` | The modem can't verify client certs without roots. |
| `tls.cert and tls.key must be set together; only … is set` | One half of the identity is missing (check both TOML and CLI overrides). |
| `failed to read TLS material from <path>` | Path wrong, or the service user can't read it (keys should be `root:dlep` mode `0640`; is it accessible with the unit's `ProtectHome=yes`?). |
| `<path> contains no PEM certificates` | File exists but isn't PEM (`openssl x509 -in <path> -noout` to check). |
| `rustls rejected the TLS material from …` | Cert/key mismatch or corrupt PEM payload; the message names the field and file. |
| `use_tls = true requires RouterBuilder::with_rustls_client(...)` / `…ModemBuilder::with_rustls_server(...)` | Library embedder didn't supply a rustls config — binaries never hit this. |
| TLS handshake fails with certificate errors | Modem cert SAN doesn't contain the IP the router dialed, or peers disagree about the CA. |
| `IPv6 discovery with bind_addr = :: requires an interface` | Set `[network].interface` or `--interface` to the link used for IPv6 discovery. |
| Session drops and never re-establishes | The router retries from retained connection state; inspect connection/TLS errors and verify the offered addresses remain reachable. |
| `invalid discovery interface` / `has no usable IPv4/IPv6 address` | Check the interface name, link state, address assignment, and that a specific `bind_addr` belongs to it. |
| Discovery finds nothing | Peers more than one hop apart (GTSM), multicast blocked, or wrong `interface`. Try static mode (`--peer`) to isolate. |
| `permission denied` binding port 854 | See §4. |
