#!/usr/bin/env python3
"""Consume router snapshots; replace the completion handler with routing policy."""
import json
import sys

state = {}
pending = None
generation = None
for line in sys.stdin:
    message = json.loads(line)
    kind = message["type"]
    if kind == "snapshot_begin":
        if message["version"] != 1:
            raise ValueError("unsupported router adapter protocol version")
        pending, generation = {}, message["generation"]
    elif kind == "session" and pending is not None:
        pending[message["session"]] = {**message, "addresses": [], "destinations": {}}
    elif kind == "destination" and pending is not None:
        pending[message["session"]]["destinations"][message["mac"]] = {
            **message, "addresses": []
        }
    elif kind == "address" and pending is not None:
        owner = pending[message["session"]]
        if message["mac"] is not None:
            owner = owner["destinations"][message["mac"]]
        owner["addresses"].append((message["kind"], message["address"]))
    elif kind == "snapshot_end":
        if pending is None or message["generation"] != generation:
            raise ValueError("mismatched snapshot boundary")
        state, pending = pending, None
        count = sum(len(s["destinations"]) for s in state.values())
        print(f"generation {generation}: {len(state)} sessions, {count} destinations",
              file=sys.stderr, flush=True)
    elif kind == "event_gap":
        print("transient responses lost; awaiting current state", file=sys.stderr)
    # Ignore unknown record types for forward compatibility. Stdout is reserved
    # for JSON commands, each flushed immediately; diagnostics go to stderr.

# EOF invalidates all DLEP state, even when the last snapshot was incomplete.
state.clear()
pending = None
