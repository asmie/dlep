# Router adapter protocol

`dlep-router` can run an external integration process that consumes DLEP state
and submits router commands. The adapter chooses how to use link information;
route selection and metric-to-routing-policy mapping belong to that process.
Library embedders can instead use `RouterDaemon::state()` and the command API.

```toml
[adapter]
command = "/usr/local/libexec/dlep-routing-adapter"
args = ["--interface", "radio0"] # optional
```

The command must be an absolute executable path; it is not searched in PATH.
`--check-config` validates the section and checks that the command is a file,
without executing it. The router starts the adapter before connecting to peers.
Adding `RouterConfig.adapter: Option<RouterAdapterConfig>` requires updating
exhaustive Rust struct literals; `..Default::default()` remains compatible.

## Process and framing

The router writes UTF-8 JSON Lines to the adapter's stdin and reads commands from
its stdout. Stderr is inherited for diagnostics. Flush stdout after each command.
The adapter runs as the router's user inside its service sandbox, with the
router's ambient capabilities cleared. Integration with a routing service must
use permissions and interfaces explicitly provisioned for the adapter.

Input command lines are limited to 64 KiB excluding the newline. Blank lines
are ignored. Unknown message types are ignored for forward compatibility;
unknown fields in known commands, malformed JSON, and invalid field types are
fatal. A syntactically valid command with invalid values, such as a malformed
MAC/address string or empty link request, receives a rejection.

Output records are streamed rather than placing an entire destination table on
one line. The 64 KiB command limit does not constrain output records; for example,
an escaped peer description can exceed it. Queues hold at most 64 input lines
and 64 output notices. State updates coalesce in a retained watch feed, without
an event backlog. A write that makes insufficient progress to complete its record
within five seconds fails the adapter connection. Snapshot output is independent
of the router's discovery/reconnect loop.

Adapter exit (including status zero), closed output, a malformed command, or
failed/stalled input delivery makes the router terminate sessions and exit with
an error. The example systemd unit's `Restart=on-failure` restarts both processes.
On graceful shutdown, the router sends its final empty state and closes adapter
stdin. The adapter must exit on EOF; it is killed if it does not finish within
two seconds. Treat EOF as loss of all DLEP state even if no final snapshot arrived.

## Router to adapter: state

The initial state and subsequent changes are complete snapshots. Build a staging
table after `snapshot_begin` and replace the applied table only after its matching
`snapshot_end`. Remove sessions, destinations, and addresses absent from the new
table. Discard incomplete snapshots on EOF. Snapshot records are never interleaved
with another snapshot or an output notice.

| `type` | Fields | Meaning |
| --- | --- | --- |
| `snapshot_begin` | `version` (currently 1), `generation` | Starts a complete replacement. |
| `session` | `session`, `peer`, `is_tls`, `peer_description`, `phase`, `extensions`, `metrics` | One modem session. Description may be null; extensions are numeric IDs. |
| `destination` | `session`, `mac`, `phase`, `metrics` | One destination on that session. |
| `address` | `session`, `mac`, `kind`, `address` | An address or subnet; null `mac` means the remote peer's session address. |
| `snapshot_end` | `generation` | Commits the replacement. Must match the opening generation. |

Session IDs are unique within one router process lifetime. Always key a
destination by **both session and MAC**: different modems can report the same
MAC. Peer endpoints use socket-address notation, such as `192.0.2.1:854` or
`[fe80::1%2]:854`. MAC strings contain six or eight hexadecimal octets.

Session phases are `established` and `terminating`; initializing sessions are
absent and ended sessions are removed. Destination phases are `up`, `pending_up`,
`pending_down`, or `withdrawn` (the router normally exposes `up`/`pending_down`).
`kind` is `ipv4`, `ipv6`, `ipv4_subnet`, or `ipv6_subnet`; subnet values use CIDR.

Metrics use `max_data_rate_rx_bps`, `max_data_rate_tx_bps`,
`current_data_rate_rx_bps`, `current_data_rate_tx_bps`, and `latency_us`.
Optional `resources`, `rlq_rx`, `rlq_tx`, and `mtu` are omitted when unsupported;
an explicit zero remains a value. All metrics in a snapshot are effective values,
not deltas. Receive/transmit directions retain the daemon's modem-link meaning.

Generations increase when retained state changes. Slow consumers can skip
intermediate generations. Explicit resynchronization can repeat a generation.
Do not apply older transient notices over snapshot state.

```json
{"type":"snapshot_begin","version":1,"generation":7}
{"type":"session","session":1,"peer":"192.0.2.1:854","is_tls":false,"peer_description":"radio","phase":"established","extensions":[],"metrics":{"max_data_rate_rx_bps":10000000,"max_data_rate_tx_bps":10000000,"current_data_rate_rx_bps":5000000,"current_data_rate_tx_bps":5000000,"latency_us":2500}}
{"type":"destination","session":1,"mac":"02:00:00:00:00:01","phase":"up","metrics":{"max_data_rate_rx_bps":10000000,"max_data_rate_tx_bps":10000000,"current_data_rate_rx_bps":5000000,"current_data_rate_tx_bps":5000000,"latency_us":2500}}
{"type":"address","session":1,"mac":"02:00:00:00:00:01","kind":"ipv4","address":"192.0.2.10"}
{"type":"snapshot_end","generation":7}
```

## Adapter to router: commands

| `type` | Fields | Effect |
| --- | --- | --- |
| `resync` | none | Sends another complete current snapshot; no command-result notice. |
| `session_addresses` | `request`, `session`, optional `add`, `remove` | Advertises changes to the router's own addresses on one modem session. |
| `destination_announce` | `request`, `session`, `mac`, optional `add`, `remove` | Requests information about a destination on one modem, optionally supplying IP address hints. |
| `destination_down` | `request`, `session`, `mac` | Withdraws interest from one modem. |
| `link_request` | `request`, `session`, `mac`, `requested` | Requests rate or latency changes for one destination. |

`requested` contains at least one of `current_data_rate_rx_bps`,
`current_data_rate_tx_bps`, and `latency_us`. Omitted fields are not requests to
change that characteristic. All numeric command fields are unsigned integers.

For `session_addresses`, `add` and `remove` are objects containing optional
`ipv4`, `ipv6`, `ipv4_subnets`, and `ipv6_subnets` arrays of strings. Omitted
objects and arrays are empty; subnet strings use CIDR. The daemon normalizes
subnet host bits before comparing or sending them. Invalid addresses/prefixes,
duplicates within an array, and adding and removing the same address or network
in one command receive `invalid_input`. Batches that cannot fit one DLEP Session
Update also receive `invalid_input`, even if their JSON fits the input limit.
Unknown nested fields and incorrect JSON types remain fatal framing errors.

Session address commands are deltas: adding an already advertised address or removing
an absent address has no effect. Empty or unchanged deltas are accepted without
a wire update or completion notice, unless the session is busy. Changed deltas
use address-only Session Update messages and preserve metrics. These locally
advertised router addresses are not included in snapshots, whose session
addresses belong to the remote modem. Address state is scoped to the session;
the adapter must advertise it again on a new session after reconnecting.

For `destination_announce`, optional `add`/`remove` objects use the same address
array names, but only `ipv4` and `ipv6` may be nonempty. Destination Announce
does not permit attached subnets ([RFC 8175 §12.13](https://www.rfc-editor.org/rfc/rfc8175.html#section-12.13));
nonempty subnet arrays receive `invalid_input`. Invalid IP addresses, duplicate
or conflicting entries, and hints that exceed the complete Announce wire budget
(including the MAC) also receive `invalid_input`, without sending a request.
Unknown nested fields and incorrect JSON types remain fatal framing errors.

Announce hints express requested IP address additions/removals; they do not
change router session addresses or create destination state. The modem's reply
reports its actual destination data, and its radio adapter receives the hints
in a `destination_announced` notice even when the request was denied. Omitting
both objects preserves the original Announce behavior. Empty hints still send
a request and produce a peer response; they are not an address-update no-op.
Hints are scoped to this request and are not replayed after reconnection.

`request` must be positive and strictly increase for every new command during
this adapter process lifetime. Even rejected commands consume their ID. Repeated
or decreasing IDs are rejected without re-executing the operation. Unknown message
types and `resync` do not consume IDs. Busy commands are not automatically retried;
retry with a new ID after the preceding transaction completes.

```json
{"type":"resync"}
{"type":"link_request","request":1,"session":1,"mac":"02:00:00:00:00:01","requested":{"current_data_rate_tx_bps":2000000}}
{"type":"destination_down","request":2,"session":1,"mac":"02:00:00:00:00:01"}
{"type":"session_addresses","request":3,"session":1,"add":{"ipv4":["192.0.2.10"],"ipv6_subnets":["2001:db8:1::/64"]}}
{"type":"destination_announce","request":4,"session":1,"mac":"01:00:5e:00:00:05","add":{"ipv4":["224.0.0.5"]}}
```

## Command results and transient notices

`command_result` contains `request`, `outcome`, and `code`. Outcome is:

- `accepted`: the daemon accepted the local command; this is not a peer response.
- `rejected`: the operation was rejected locally, with a code such as `busy`,
  `not_ready`, `unknown_destination`, `already_exists`, `mac_format_mismatch`,
  `invalid_mac`, `invalid_input`, `stale_session`, `session_unavailable`,
  `shutting_down`, or `request_id_not_increasing`.
- `unknown`: local acceptance was not observed; the operation may have taken
  effect. Codes are `acceptance_timeout`, `receipt_lost`, or `daemon_error`.

The five-second local acceptance deadline does not cancel an enqueued operation
and does not impose a deadline on the DLEP transaction. Do not blindly retry an
unknown outcome. The session heartbeat mechanism still detects peer silence.

Additional notices are best effort and can appear between complete snapshots:

| `type` | Fields | Meaning |
| --- | --- | --- |
| `announce_response` | `session`, `mac`, `status`, `text` | A validated, nonfatal Destination Announce Response, including denial; status is the numeric DLEP code. |
| `link_response` | `session`, `mac`, `status`, `text`, `metrics` | A peer Link Characteristics Response; status is the numeric DLEP code. |
| `destination_down` | `session`, `mac`, `status` | Destination withdrawal/removal outcome. |
| `down_response` | `session`, `mac`, `status`, `text` | A validated, nonfatal reply to a router-originated Destination Down, preserving the peer's status text. |
| `session_down` | `session`, `peer`, `status` | Session termination reason. |
| `session_update_response` | `session`, `status`, `text` | A validated, nonfatal reply to a locally originated Session Update. Zero means success. |
| `event_gap` | `skipped` | Public events were lost; a current snapshot follows. |

Destination responses identify session/MAC, not the adapter's request ID. Serialize requests
for each destination when tracking completions. After `event_gap`, outstanding
peer-response outcomes may be unknown; snapshots recover current state but
cannot reconstruct lost responses or reasons. Notices queued before a gap can
still arrive afterwards and must not overwrite snapshot state. A snapshot may
arrive before its command-result or peer-response notice.

`announce_response` completes the peer transaction, so a denied Announce can be
retried with a new command ID. Status zero means success; other nonfatal statuses
leave destination state unchanged. For example, an accepted command can receive
`{"type":"announce_response","session":1,"mac":"02:00:00:00:00:01","status":2,"text":"unreachable"}`.
Success also creates the destination in retained state. Read its metrics and
addresses from snapshots; large address sets can continue arriving in subsequent
updates after the response. Invalid, unsolicited, duplicate, or fatal replies
follow session termination instead of producing an announce-response notice.

`down_response` follows the existing `destination_down` removal notice when the
modem replies to a withdrawal command. Removal occurs for every validated,
nonfatal reply, including a nonzero status. Modem-originated destination loss
produces only `destination_down`. Invalid, unsolicited, duplicate, or fatal
replies terminate the session instead of producing a completion notice. A later
Announce or Up can recreate the same MAC; use snapshots for its current state.

`session_update_response` exposes replies to `session_addresses` commands and
address updates originated through the daemon API. Each notice represents one
wire reply and identifies the session, without the adapter's request ID.
Serialize address commands per session when tracking completion; another session
transaction returns `busy` until the peer responds. Repeating unchanged local
addresses sends no update and produces no completion. Refusal preserves the
daemon's local address state. Invalid, unsolicited, duplicate, or fatal replies
terminate the session instead of producing this notice. Snapshots and `resync`
cannot recover lost completion outcomes or the locally advertised address state.

[`examples/router-adapter.py`](../examples/router-adapter.py) is a runnable
consumer that maintains replacement tables and logs their size. It does not
install routes; adapt its completed-snapshot handler to your routing service.
