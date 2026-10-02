# Deploying dlep-router and dlep-modem

This guide covers building, certificate provisioning, configuration, the
privileged-port question, firewalls, and systemd. Working example configs
and unit files live in [`examples/`](../examples/).

## 1. Build and install

Requires Linux and Rust 1.85+ (edition 2024). macOS CI covers the portable
protocol crates, not the daemon transport. See [CI documentation](../.github/README.md).

```bash
cargo build --release --workspace --locked
sudo install -m 0755 target/release/dlep-router target/release/dlep-modem /usr/local/bin/
```

## 2. Certificates

TLS is **on by default** (RFC 8175 security guidance). DLEP runs on
closed router↔modem links, so the expected setup is a small private CA —
there is deliberately no fallback to the system trust store. Certificate
revocation (CRLs) is not supported; rotate by reissuing and restarting.

Create a CA, a modem (server) certificate, and a router (client)
certificate. The modem certificate's subjectAltName **must** contain the
IP address routers connect to (hostname verification uses the IP; DNS
names are not yet supported):

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

| Section | Field | Default | Meaning |
|---|---|---|---|
| top level (router) | `mode` | `"discovery"` | `"discovery"` or `"static"` |
| top level (router) | `static_peers` | `[]` | modem `addr:port` list for static mode |
| top level | `peer_description` | binary name | Peer Type data item text |
| `[network]` | `interface` | none | Discovery interface name: membership, sending, and receive filtering |
| `[network]` | `mac_address_format` | `"eui48"` | Destination MAC format: `"eui48"` or `"eui64"`; must match the modem's router-facing link |
| `[network]` | `discovery_v4_group` | `224.0.0.117` | IPv4 discovery multicast group |
| `[network]` | `discovery_v6_group` | `ff02::1:7` | IPv6 discovery multicast group (used with an IPv6 `bind_addr`) |
| `[network]` | `discovery_port` | `854` | modem UDP listen port / router multicast destination port; router source port is ephemeral |
| `[network]` | `tcp_port` | `854` | modem TCP/TLS listen port; ignored by router (which uses offered/static endpoints) |
| `[network]` | `bind_addr` | `0.0.0.0` | discovery source preference/family and modem TCP listener address; does not bind router TCP sources |
| `[network]` | `use_tls` | `true` | TLS for the session transport |
| `[network]` | `gtsm_enforce` | `true` | Linux TCP minimum-TTL filter and strict reset monitor (`CAP_NET_RAW`); discovery always checks TTL |
| `[tls]` | `cert` / `key` | none | identity (modem: required; router: mTLS) |
| `[tls]` | `ca_bundle` | none | trust roots (router: required; modem: for mTLS) |
| `[tls]` | `require_client_cert` | `false` | modem requires router client certs; not used by router |
| `[timers]` | `heartbeat_interval_ms` | `60000` | heartbeat interval, minimum 1000 ms |
| `[timers]` | `discovery_interval_ms` | `5000` | Peer Discovery resend interval, minimum 1000 ms |
| `[timers]` | `session_init_timeout_ms` | `5000` | positive deadline for initialization: router awaits response, modem awaits request |
| `[timers]` | `termination_timeout_ms` | omitted: `4 × heartbeat_interval_ms` | positive explicit override for Session Termination Response; default resolves to `240000` ms |
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

CLI flags override the file: `--interface`, `--no-tls`, `--cert`, `--key`,
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
`discovery_v6_group` (default `ff02::1:7`). Each daemon discovers over one family:
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


Validate without starting the daemon:

```bash
dlep-router --config /etc/dlep/router.toml --check-config
dlep-modem  --config /etc/dlep/modem.toml  --check-config
```

`configuration OK` on stdout and exit code 0 mean the TOML parses, static
mode has peers, any explicit discovery interface is usable on this host, modem
metric values and timers pass validation, and all TLS material loads. This does
not open sockets or check GTSM capabilities, firewall rules, or peer reachability.

Timer limits are checked by `--check-config` and by both daemon builders before
opening sockets. Heartbeat and discovery intervals below 1000 ms are rejected
(RFC 8175 §7.3.1 and §7.1); initialization and termination timeouts must be at
least 1 ms. Errors name the field, minimum, and supplied value. Zero does not
disable a timer.

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
`CAP_NET_BIND_SERVICE`. A future modem backend needing device access will need
a corresponding unit override.

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

## 7. Troubleshooting

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
