# Radio adapter protocol

The `dlep-modem` binary has no built-in radio driver. A `[radio]` section makes
it start one external program, the *adapter*, which reports destinations and
link metrics from the radio and decides router Link Characteristics Requests
(RFC 8175 §12.18–12.19). Library embedders can use
`ModemDaemon` and `ModemBuilder::link_control` directly instead; see the
[README](../README.md#library-use).

```toml
[radio]
command = "/usr/local/libexec/dlep-radio"  # absolute path, not searched in PATH
args = ["--device", "/dev/ttyUSB0"]        # optional
link_request_timeout_ms = 30000            # optional, default 30000
```

`dlep-modem --check-config` validates the section and checks that `command` is
a file. It does not run the adapter.

## Process model

- The modem starts the adapter before opening sockets, with standard input and
  output as pipes and standard error inherited (the modem's log, or the journal
  under systemd). The adapter runs as the modem's user without the modem's
  ambient capabilities.
- Messages are [JSON Lines](https://jsonlines.org/): one UTF-8 JSON object per
  line with a `"type"` field. Adapter output sent to the modem is limited to
  64 KiB per line, excluding the newline; blank lines are ignored. Flush standard
  output after each line. Modem notices can exceed this limit when JSON escaping
  expands a peer's status text or a session snapshot contains many addresses,
  so do not apply it to the adapter's stdin.
- The adapter must exit when its standard input closes. On shutdown the modem
  terminates its DLEP sessions, closes the adapter's input, and kills the
  adapter if it is still running two seconds later.
- If the adapter exits, closes its output, or writes a line that is not valid
  JSON for a known message type, the modem terminates its sessions with
  Shutting Down and exits with an error. Under the example systemd unit,
  `Restart=on-failure` restarts both, and the restarted adapter reports the
  current radio state again.
- Failed writes to the adapter's input, or writes that cannot complete one
  record within five seconds, trigger the same failure shutdown. Input and
  output queues each hold at most 64 records. A full output queue pauses the
  bridge until the writer makes room or fails; the daemon's session tasks keep
  running. Keep reading stdin while applying slow radio changes so ordinary
  notices do not fill the pipe.
- Unknown message types are ignored in both directions, so adapters must ignore
  types they do not recognize. Unknown fields in known messages sent by the
  adapter are errors. Adapters should tolerate added fields in modem notices.

## Values

- `mac`: colon-separated hexadecimal octets, six for EUI-48 or eight for EUI-64,
  for example `"02:00:00:00:00:01"`. The format must match
  `[network].mac_address_format`. An incompatible `destination_up` is logged
  and ignored before it enters the replay cache, even with no connected routers.
  The configured format remains fixed after all destinations are removed; it
  is never inferred from radio reports.
- `metrics`: an object using the `[metrics]` names: `max_data_rate_rx_bps`,
  `max_data_rate_tx_bps`, `current_data_rate_rx_bps`,
  `current_data_rate_tx_bps`, `latency_us`, and the optional `resources`,
  `rlq_rx`, `rlq_tx` (percent) and `mtu` (bytes). Every field is optional;
  omitted fields keep their previous values. Optional metrics are accepted only
  if declared in `[metrics]`, and current rates must not exceed maximum rates.
- `addresses`: an object with optional arrays `ipv4`, `ipv6`, `ipv4_subnets`
  and `ipv6_subnets`, for example
  `{"ipv4": ["192.0.2.10"], "ipv6_subnets": ["2001:db8:1::/48"]}`.

## Adapter to modem

| `type` | Fields | Effect |
| --- | --- | --- |
| `resync` | none | Requests a fresh `session_sync` with membership and router addresses, even when unchanged or empty. |
| `destination_up` | `mac`, optional `metrics`, `addresses` | Reports a new destination to every router. Omitted metrics take the current session-wide values. |
| `destination_update` | `mac`, `metrics` | Sends changed metrics for a known destination. |
| `destination_addresses` | `mac`, optional `add`, `remove` (addresses) | Sends address and subnet changes. |
| `destination_down` | `mac` | Withdraws the destination from every router. |
| `session_metrics` | `metrics` | Sends session-wide metrics in a Session Update. Routers apply them to every destination too (RFC 8175 §12.7). |
| `link_response` | `request`, `status`, optional `text`, `metrics` | Answers a `link_request`. |

```json
{"type":"resync"}
{"type":"destination_up","mac":"02:00:00:00:00:01","metrics":{"current_data_rate_tx_bps":5000000},"addresses":{"ipv4":["192.0.2.10"]}}
{"type":"link_response","request":7,"status":"success","text":"applied","metrics":{"current_data_rate_tx_bps":2000000}}
```

The modem keeps the destination table and replays it, together with changed
session metrics, to each router that connects later. Report each destination
once with `destination_up`; a repeated `destination_up`, or a message for an
unknown destination, is logged and ignored. Messages the modem rejects as
invalid, such as undeclared optional metrics, are also logged and ignored
without changing its state.

Address updates must leave a complete destination that fits in one Destination
Up message, including its MAC and metrics. Individually small batches can reach
this limit as addresses accumulate. An oversized result rejects the whole batch
before sending it to any router or changing the cached addresses, including any
removals in that batch. Remove enough addresses, either in the same batch or a
later one, before adding more. This check also applies when no routers are
connected, so the retained destination remains replayable.

Effective address changes may span multiple Destination Update messages,
especially when several reports coalesce while Up awaits acknowledgement.
Removals precede additions across messages, and any coalesced metrics appear
once. Routers can observe intermediate address snapshots before all changes arrive.
Re-announcing a large destination also accounts for the response's required
Status item. A successful response includes its metrics and fitting addresses;
any remaining addresses follow in updates on the same session. The complete
cached destination is preserved.

Replay uses retained daemon session state and recovers even if the internal
event subscriber falls behind. It retries busy session initialization, preserves
existing per-session destination metrics, and respects a router's withdrawal.
Closed sessions release pending adapter requests and command retries.
Send `{"type":"resync"}` whenever the adapter needs a fresh session list and
router address snapshot. Each request produces `session_sync` even if membership
is unchanged or empty, and takes no additional fields. It does not create an
`event_gap` or re-announce destinations to existing sessions. Keep answering
pending link requests during refresh; it does not cancel them. Newly observed
sessions still receive normal replay. Membership cannot reconstruct lost
responses or destination interest history.
Default replay preserves the session's live destination values within one
command; it does not restore metrics from the earlier membership snapshot.
A link grant completed after that snapshot therefore remains in effect.
Session defaults precede any needed destination corrections on the wire, so
routers may briefly observe the defaults before the corrections arrive.

Busy destination operations and initial session replay share one retry per
session and operation (and MAC for a destination operation), using the latest
cached values. Further reports keep the first retry deadline instead of
postponing it. A later accepted command cancels that operation's retry only for
the sessions that accepted it; other busy sessions keep their work.

`session_metrics` instead coalesces inside each session into one pending update
while a session transaction is busy. Accepted values immediately update the
modem's retained state and become the basis for later reports and link answers.
The latest combined update is sent when the preceding response arrives, followed
by Destination Updates that preserve later destination changes. Receivers may
briefly observe the defaults before those corrections. Pending Up destinations
receive corrections after their Up response; withdrawn destinations retain their
local values without being re-announced. Queue storage is bounded to one metric
set per session, regardless of the number of reports.

Omitted fields build on the modem's current view: a new destination starts
from the session-wide metrics, and `session_metrics` also updates every known
destination, so a later partial `destination_update` keeps those values.

A destination can be withdrawn while a link request for it is pending; the
modem sends the Destination Down after the request is answered. After
`destination_down`, the same MAC may be reported up again. The modem re-adds it
on each router once that router has acknowledged the withdrawal, using the
latest metrics and addresses.
A further withdrawal cancels a deferred re-add. If the previous Down is already
awaiting acknowledgement or has completed, the modem does not queue another
Down that could withdraw the replacement destination.

Continue answering outstanding link requests for the withdrawn destination.
Their replies complete the original session transactions, but cannot change
the cached metrics of a replacement reported under the same MAC. This also
applies to requests that were queued inside the modem when the withdrawal
arrived. New requests for the replacement can update its cached metrics normally.

## Modem to adapter

| `type` | Fields | Meaning |
| --- | --- | --- |
| `session_sync` | `sessions` (array of objects with `session`, `peer`, `addresses`) | Authoritative current session membership and router addresses, sent at bridge startup, whenever either changes, after an event gap, and on `resync`. Replace the adapter's session list and address sets; an empty array means no sessions. |
| `event_gap` | `skipped` | Daemon broadcast events were lost. A fresh `session_sync` follows, even if membership is unchanged. |
| `session_up` | `session`, `peer` | A router session is established. |
| `session_down` | `session`, `peer`, `status` (numeric RFC 8175 status code) | A router session ended. |
| `session_update_response` | `session`, `status`, `text` | The router's validated, nonfatal reply to a Session Update, including initial replay of changed defaults. Zero means success. |
| `destination_up_response` | `session`, `mac`, `status`, `text` | The router's validated, nonfatal reply to Destination Up. Zero means accepted; other status codes mean it declined reports for this destination. |
| `destination_down_response` | `session`, `mac`, `status`, `text` | The router's validated, nonfatal reply to a modem-originated Destination Down. Zero means success. |
| `destination_withdrawn` | `session`, `mac` | The router withdrew interest in this destination on this session. Physical destination knowledge remains cached. |
| `destination_announced` | `session`, `mac` | The router asked about a destination it has not been told about (§12.13). The modem has already answered; send `destination_up` if the radio can reach it. |
| `link_request` | `request`, `session`, `peer`, `mac`, `requested`, `current` | A router asks to change a destination's link. |

Each `session_sync` entry contains the numeric session ID, the peer's socket
address, and the complete addresses advertised by that router. `addresses`
always contains `ipv4`, `ipv6`, `ipv4_subnets`, and `ipv6_subnets` arrays, including
empty arrays; subnets use canonical CIDR notation. Replace these sets on every
snapshot, including removals and a return to empty sets. These are remote router
addresses, separate from the modem's own addresses and destination addresses.
Initialization addresses are included in the first snapshot. Updates can
coalesce; the bridge uses retained state so delayed address events cannot
overwrite newer values. Address changes do not replay destinations or defaults.

```json
{"type":"session_sync","sessions":[{"session":1,"peer":"192.0.2.1:41000","addresses":{"ipv4":["192.0.2.10"],"ipv6":[],"ipv4_subnets":[],"ipv6_subnets":["2001:db8:1::/64"]}}]}
```

Sessions remain in `session_sync` while terminating and disappear when they end.
Session IDs are unique during a modem process lifetime. Intermediate sessions
may be omitted if they start and end before the bridge observes them.
`session_up` accompanies replay for a newly observed established session;
`session_down` supplies the termination reason when its event is available.
Session termination, response, and destination notices may be lost under event
lag. The bridge sends `event_gap` and then refreshes `session_sync` from retained
state. `skipped` counts lost daemon events, including events that would not have
produced adapter notices. Further gaps can occur while recovery is in progress.
Use `session_sync` to reconcile membership and router addresses; a delayed down
notice for an absent ID is harmless. Older adapters may ignore `session_sync`
under the unknown-message rule, but then cannot recover missing lifecycle notices.
Older versions of the modem omit `addresses`; treat an absent field as unavailable
address information.

Recovery does not replay destinations or defaults to existing sessions, so a
router's withdrawal or session-specific link grant remains intact. Newly
observed sessions receive normal replay and may produce `session_up` before
the refreshed membership notice. Lost response outcomes and destination interest
history remain unknown; membership cannot reconstruct them. Queued older notices
may arrive around a gap and must not override current membership. Link requests
use a separate delivery path and are not cancelled by event loss; continue
answering outstanding requests.

`session_update_response` preserves the peer's status text, including on refusal.
It reports one wire reply, so coalesced `session_metrics` lines do not each
produce a notice. A queued next update may already be pending when the notice
arrives. Refusal leaves the radio's cached metrics and destination reports intact;
later replay uses those latest values. Membership snapshots cannot recover lost
responses. Invalid, unsolicited, duplicate, or fatal replies terminate the
session instead of producing this notice.

`destination_up_response` reports that router's outcome, including any status
text. A refusal stops reports on that session but preserves the modem's cached
destination, metrics, and addresses. It does not withdraw the physical destination
or affect other routers; later routers still receive normal replay. Do not send
`destination_down` solely because one router declined the destination. Session
membership snapshots cannot recover a lost response or its explanation.
Invalid, unsolicited, duplicate, or fatal replies follow session termination
instead of producing an Up-response notice.

`destination_down_response` preserves the router's status and explanation after
removing the old destination from that session, even for a nonzero status. It
does not alter the physical cache: a replacement reported under the same MAC
can already exist when this notice arrives. Do not remove that replacement in
response to the notice. If the router had already declined or withdrawn
interest, physical removal can be local-only and produces no reply notice.
Invalid, unsolicited, duplicate, or fatal replies terminate the session instead.
Membership snapshots cannot recover lost completion notices.

`destination_withdrawn` reports a router's later withdrawal of interest. The
modem has acknowledged it and stopped reports on that session. Keep reporting
physical changes: other routers still receive them, later routers receive the
cached destination, and the withdrawing router can request reports again with
Destination Announce. A physical `destination_down` sent by the adapter does
not produce this notice. Session membership snapshots cannot recover lost
destination interest notices.

```json
{"type":"link_request","request":7,"session":1,"peer":"192.0.2.1:41000","mac":"02:00:00:00:00:01","requested":{"current_data_rate_tx_bps":2000000},"current":{"max_data_rate_rx_bps":10000000,"max_data_rate_tx_bps":10000000,"current_data_rate_rx_bps":5000000,"current_data_rate_tx_bps":5000000,"latency_us":2500}}
```

`requested` contains only the characteristics the router asked to change:
`current_data_rate_rx_bps`, `current_data_rate_tx_bps` and/or `latency_us`.
`current` holds the destination's metrics on that session when the request
arrived. Reports received while the request is pending can change these values.

### Answering link requests

Answer every `link_request` with a `link_response` carrying the same `request`
number, in any order:

- `"status": "success"` means the change was applied. `"denied"` means it cannot
  be met (Request Denied).
- `metrics` describe the link after processing. Supplied fields replace the
  destination's latest values on the requesting session; omitted fields retain
  those latest values, including reports received after the request. Without
  `metrics` (or with `{}`), the response reports the latest values unchanged,
  so include the new values when granting. The response always carries every
  declared metric.
- `text` is sent to the router as the status text.

Granted metrics update this router's view and, if the physical destination has
not been withdrawn since the request, the modem's table. Each view merges the
supplied fields independently: a partial grant retains earlier grants from
other sessions in the table without copying those session-specific changes
into this router's response. Routers already connected learn of another
session's grant only through a `destination_update`, so send one if they should
see it. Later routers receive the accumulated cached values.

For a valid reply, the bridge waits for the requesting session to accept and
write the response before updating the table or processing the next radio
report. This preserves the order of a grant followed immediately by newer
metrics. A reply rejected during termination or lost before local acceptance
leaves the table unchanged. Local acceptance does not acknowledge receipt by
the router.

Both merged results must use declared metrics and fit the wire format. The
complete response, including the MAC, status text, and every declared metric,
must also fit the 65,535-byte DLEP message body. Text counts in UTF-8 bytes;
fitting the adapter's 64 KiB JSON-line limit does not guarantee that the response
fits. Invalid metrics or an oversized response turn the answer into Request
Denied without your text. Both the requesting router and the replay table keep
their previous metric values.

Each destination has at most one outstanding request per session; requests for
different destinations or sessions may overlap. RFC 8175 §8 gives requests no
deadline, but `link_request_timeout_ms` bounds a stalled adapter: when it
expires the modem replies Request Denied with the text
`radio adapter timed out`, and a later answer is ignored without updating the
table. A request is abandoned without an answer if its session ends.

The modem queues at most 64 link requests waiting for the bridge and tracks at
most 64 requests awaiting adapter answers, across all sessions and destinations.
Excess requests receive Request Denied with `radio adapter busy`; they are not
forwarded or retried automatically. Completed, cancelled, and timed-out requests
release capacity. The configured answer timeout includes time waiting in the
bridge or output queue, separately from the five-second write deadline.
Requests cancelled or expired before output can be queued are discarded.
Already queued or delivered requests cannot be recalled; late answers remain
ignored as described above.

## Example

A minimal adapter in Python that reports one destination and grants every
requested data rate:

```python
#!/usr/bin/env python3
import json, sys

def send(message):
    print(json.dumps(message), flush=True)

send({"type": "destination_up", "mac": "02:00:00:00:00:01",
      "metrics": {"current_data_rate_tx_bps": 5_000_000}})
for line in sys.stdin:
    message = json.loads(line)
    if message["type"] != "link_request":
        continue
    requested = message["requested"]
    if "latency_us" in requested:
        send({"type": "link_response", "request": message["request"],
              "status": "denied", "text": "latency is fixed"})
    else:
        send({"type": "link_response", "request": message["request"],
              "status": "success", "metrics": requested})
```

This example assumes the radio accepts any rate up to the advertised maximum.
A real adapter should apply the change and report the measured result.

## systemd

The adapter runs inside the modem's service sandbox. The example unit sets
`PrivateDevices=yes` and `ProtectSystem=strict`, so an adapter that needs a
device or writable state requires a drop-in, for example:

```ini
# /etc/systemd/system/dlep-modem.service.d/radio.conf
[Service]
PrivateDevices=no
DeviceAllow=/dev/ttyUSB0 rw
SupplementaryGroups=dialout
ReadWritePaths=/var/lib/dlep-radio
```

`RestrictAddressFamilies` also applies to the adapter. Extend it if the adapter
talks to the radio over another socket family.
