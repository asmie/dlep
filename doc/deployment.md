# Deploying dlep-router and dlep-modem

This guide covers building, certificate provisioning, configuration, the
privileged-port question, firewalls, and systemd. Working example configs
and unit files live in [`examples/`](../examples/).

## 1. Build and install

Requires Rust 1.85+ (edition 2024).

```bash
cargo install --path crates/dlep-router
cargo install --path crates/dlep-modem
# or: cargo build --release && cp target/release/dlep-{router,modem} /usr/local/bin/
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
useradd --system --no-create-home --shell /usr/sbin/nologin dlep
install -d -m 0755 /etc/dlep /etc/dlep/pki
install -m 0644 ca.pem modem.pem /etc/dlep/pki/        # certs are public
install -m 0640 -g dlep modem.key /etc/dlep/pki/       # keys: root:dlep 0640
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
are optional; defaults follow the RFC (port 854, TLS on, discovery on).
Misspelled keys inside `[network]`/`[tls]`/`[timers]` are rejected at
parse time; top-level typos are silently ignored, so always finish an
edit with `--check-config`.

| Section | Field | Default | Meaning |
|---|---|---|---|
| top level (router) | `mode` | `"discovery"` | `"discovery"` or `"static"` |
| top level (router) | `static_peers` | `[]` | modem `addr:port` list for static mode |
| top level | `peer_description` | binary name | Peer Type data item text |
| `[network]` | `interface` | none | discovery interface override |
| `[network]` | `discovery_v4_group` | `224.0.0.117` | IPv4 discovery multicast group |
| `[network]` | `discovery_v6_group` | `ff02::1:7` | IPv6 discovery multicast group (reserved; discovery is IPv4-only today) |
| `[network]` | `discovery_port` | `854` | UDP discovery port |
| `[network]` | `tcp_port` | `854` | TCP/TLS session port |
| `[network]` | `bind_addr` | `0.0.0.0` | modem listener bind address |
| `[network]` | `use_tls` | `true` | TLS for the session transport |
| `[network]` | `gtsm_enforce` | `true` | Linux TCP minimum-TTL filter and strict reset monitor (`CAP_NET_RAW`); discovery always checks TTL |
| `[tls]` | `cert` / `key` | none | identity (modem: required; router: mTLS) |
| `[tls]` | `ca_bundle` | none | trust roots (router: required; modem: for mTLS) |
| `[tls]` | `require_client_cert` | `false` | modem requires router client certs |
| `[timers]` | `heartbeat_interval_ms` | `60000` | RFC 8175 heartbeat interval |
| `[timers]` | `discovery_interval_ms` | `5000` | Peer Discovery resend interval |
| `[timers]` | `session_init_timeout_ms` | `5000` | deadline for Session Initialization Response |
| `[timers]` | `termination_timeout_ms` | `1000` | deadline for Session Termination Response |
| `[timers]` | `link_characteristics_timeout_ms` | `60000` | router deadline for Link Characteristics Response; must be positive when requesting changes |

CLI flags override the file: `--interface`, `--no-tls`, `--cert`, `--key`,
`--ca-bundle`, and (router) `--peer ADDR` (repeatable; implies static mode).

Validate without starting the daemon:

```bash
dlep-router --config /etc/dlep/router.toml --check-config
dlep-modem  --config /etc/dlep/modem.toml  --check-config
```

`configuration OK` on stdout and exit code 0 mean the TOML parses, static
mode has peers, and all TLS material loads.

## 4. Port 854 privileges

The DLEP well-known port (854, UDP and TCP) is below 1024 and requires
`CAP_NET_BIND_SERVICE` on Linux. Pick one:

1. **systemd (recommended)** — the shipped units grant
   `AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW` to the unprivileged `dlep`
   service user.
2. **setcap** — `sudo setcap cap_net_bind_service=+ep /usr/local/bin/dlep-modem`
   (repeat after each binary update).
3. **Unprivileged ports** — set `discovery_port`/`tcp_port` ≥ 1024 on both
   sides (non-standard; both peers must agree).

Do **not** run the daemons as root.

## 5. Firewall

| Direction | Proto | Port | Purpose |
|---|---|---|---|
| router → 224.0.0.117 | UDP | 854 | Peer Discovery multicast |
| modem → router | UDP | ephemeral | unicast Peer Offer reply |
| router → modem | TCP | 854 | DLEP session (TLS) |

Discovery sends with TTL 255 and drops discovery packets whose TTL is not 255 (GTSM, RFC 5082) —
discovery only works between directly-connected (one-hop) peers.

Strict TCP GTSM also requires `CAP_NET_RAW` on Linux to monitor rejected packets
and reset the affected connection immediately (RFC 8175 §14). The sample
systemd units grant this capability. For manual runs, grant the capability to
the installed executable, for example:

```sh
sudo setcap cap_net_bind_service,cap_net_raw=ep /usr/local/bin/dlep-modem
sudo setcap cap_net_raw=ep /usr/local/bin/dlep-router
```

Reinstalling a binary may remove its file capabilities. Missing monitoring
privileges cause an explicit error; `gtsm_enforce = false` is an opt-out for
nonconforming development peers, not a production default.

## 6. systemd

```bash
sudo cp examples/dlep-modem.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dlep-modem
journalctl -u dlep-modem -f
```

Same for `dlep-router.service`. Log verbosity: `--log-level
trace|debug|info|warn|error` or the `DLEP_LOG` env var (add
`Environment=DLEP_LOG=debug` to the unit).

## 7. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `tls.ca_bundle is required when use_tls = true` | Router with TLS on but no trust roots. Set `[tls] ca_bundle` or pass `--ca-bundle`. |
| `tls.cert is required on the modem (server) side…` | Modem with TLS on but no identity. Set `[tls] cert` + `key`. |
| `tls.key is required on the modem (server) side…` | Modem with a cert but no private key. Set `[tls] key`. |
| `tls.require_client_cert = true requires tls.ca_bundle` | The modem can't verify client certs without roots. |
| `tls.cert and tls.key must be set together; only … is set` | One half of the identity is missing (check both TOML and CLI overrides). |
| `failed to read TLS material from <path>` | Path wrong, or the service user can't read it (keys should be `root:dlep` mode `0640`; is the path under the unit's `ReadOnlyPaths`?). |
| `<path> contains no PEM certificates` | File exists but isn't PEM (`openssl x509 -in <path> -noout` to check). |
| `rustls rejected the TLS material from …` | Cert/key mismatch or corrupt PEM payload; the message names the field and file. |
| `use_tls = true requires RouterBuilder::with_rustls_client(...)` / `…ModemBuilder::with_rustls_server(...)` | Library embedder didn't supply a rustls config — binaries never hit this. |
| TLS handshake fails with certificate errors | Modem cert SAN doesn't contain the IP the router dialed, or peers disagree about the CA. |
| `M6 discovery only supports v4 bind_addr` | Discovery mode with an IPv6 `bind_addr` passes `--check-config` but fails at startup; use an IPv4 `bind_addr` or static mode. |
| Session drops and never re-establishes | The router retries after `SessionDown`; inspect connection/TLS errors and verify the offered addresses remain reachable. |
| Discovery finds nothing | Peers more than one hop apart (GTSM), multicast blocked, or wrong `interface`. Try static mode (`--peer`) to isolate. |
| `permission denied` binding port 854 | See §4. |
