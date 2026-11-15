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
  line, at most 64 KiB, with a `"type"` field. Blank lines are ignored.
  Flush standard output after each line.
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
  types they do not recognize. Unknown fields in known messages are errors.

## Values

- `mac`: colon-separated hexadecimal octets, six for EUI-48 or eight for EUI-64,
  for example `"02:00:00:00:00:01"`. The format must match
  `[network].mac_address_format`.
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
| `destination_up` | `mac`, optional `metrics`, `addresses` | Reports a new destination to every router. Omitted metrics take the current session-wide values. |
| `destination_update` | `mac`, `metrics` | Sends changed metrics for a known destination. |
| `destination_addresses` | `mac`, optional `add`, `remove` (addresses) | Sends address and subnet changes. |
| `destination_down` | `mac` | Withdraws the destination from every router. |
| `session_metrics` | `metrics` | Sends session-wide metrics in a Session Update. Routers apply them to every destination too (RFC 8175 §12.7). |
| `link_response` | `request`, `status`, optional `text`, `metrics` | Answers a `link_request`. |

```json
{"type":"destination_up","mac":"02:00:00:00:00:01","metrics":{"current_data_rate_tx_bps":5000000},"addresses":{"ipv4":["192.0.2.10"]}}
{"type":"link_response","request":7,"status":"success","text":"applied","metrics":{"current_data_rate_tx_bps":2000000}}
```

The modem keeps the destination table and replays it, together with changed
session metrics, to each router that connects later. Report each destination
once with `destination_up`; a repeated `destination_up`, or a message for an
unknown destination, is logged and ignored. Messages the modem rejects as
invalid, such as undeclared optional metrics, are also logged and ignored
without changing its state.

Replay uses retained daemon session state and recovers even if the internal
event subscriber falls behind. It retries busy session initialization, preserves
existing per-session destination metrics, and respects a router's withdrawal.
Closed sessions release pending adapter requests and command retries.

Busy operations share one retry per session and operation (and MAC for a
destination operation), using the latest cached values. Further reports keep
the first retry deadline instead of postponing it. A later accepted command
cancels that operation's retry only for the sessions that accepted it; other
busy sessions keep their work. Retry storage therefore follows distinct pending
work, not the number of radio reports.

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

## Modem to adapter

| `type` | Fields | Meaning |
| --- | --- | --- |
| `session_sync` | `sessions` (array of `{ "session": number, "peer": "address:port" }`) | Authoritative current session membership, sent at bridge startup and whenever membership changes. Replace the adapter's session list with this list; an empty array means no sessions. |
| `session_up` | `session`, `peer` | A router session is established. |
| `session_down` | `session`, `peer`, `status` (numeric RFC 8175 status code) | A router session ended. |
| `destination_announced` | `session`, `mac` | The router asked about a destination it has not been told about (§12.13). The modem has already answered; send `destination_up` if the radio can reach it. |
| `link_request` | `request`, `session`, `peer`, `mac`, `requested`, `current` | A router asks to change a destination's link. |

Sessions remain in `session_sync` while terminating and disappear when they end.
Session IDs are unique during a modem process lifetime. Intermediate sessions
may be omitted if they start and end before the bridge observes them.
`session_up` accompanies replay for a newly observed established session;
`session_down` supplies the termination reason when its event is available.
Transient down/announce notices may be lost under event lag. Use `session_sync`
to reconcile membership; a delayed down notice for an absent ID is harmless.
Link requests use a separate delivery path. Older adapters may ignore
`session_sync` under the unknown-message rule, but then cannot recover missing
lifecycle notices.

```json
{"type":"link_request","request":7,"session":1,"peer":"192.0.2.1:41000","mac":"02:00:00:00:00:01","requested":{"current_data_rate_tx_bps":2000000},"current":{"max_data_rate_rx_bps":10000000,"max_data_rate_tx_bps":10000000,"current_data_rate_rx_bps":5000000,"current_data_rate_tx_bps":5000000,"latency_us":2500}}
```

`requested` contains only the characteristics the router asked to change:
`current_data_rate_rx_bps`, `current_data_rate_tx_bps` and/or `latency_us`.
`current` holds the destination's metrics on that session.

### Answering link requests

Answer every `link_request` with a `link_response` carrying the same `request`
number, in any order:

- `"status": "success"` means the change was applied. `"denied"` means it cannot
  be met (Request Denied).
- `metrics` describe the link after processing, overlaid on `current`. Without
  `metrics`, the router receives `current` unchanged, so include the new values
  when granting. The response always carries every declared metric.
- `text` is sent to the router as the status text.

Granted metrics update this router's view and the modem's table. Other routers
learn of the change only through a `destination_update`, so send one if they
should see it. Metrics the modem cannot send, such as undeclared optional
metrics, turn the answer into Request Denied without your text, and the table
keeps its previous values.

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
