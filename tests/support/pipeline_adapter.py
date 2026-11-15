#!/usr/bin/env python3
"""Test adapter: public protocol on stdio; deterministic control on a Unix socket.

The control socket never contacts the daemons. All test actions still traverse
the real adapter pipes, daemons, and DLEP connection. It also allows the test to
pause stdin consumption without sleeping or stopping either daemon.
"""
import array
import collections
import fcntl
import json
import os
import selectors
import socket
import sys
import termios

role, control_path, final_path = sys.argv[1:]
control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
control.connect(control_path)
selector = selectors.DefaultSelector()
selector.register(control, selectors.EVENT_READ, "control")
selector.register(0, selectors.EVENT_READ, "stdin")
buffers = {"control": b"", "stdin": b""}
state, pending, generation, pending_generation = {}, None, None, None
notices = collections.deque(maxlen=4096)
generations = collections.deque(maxlen=512)
reading, records = True, 0


def reply(value):
    control.sendall((json.dumps(value) + "\n").encode())


def send(messages):
    sys.stdout.write("".join(json.dumps(m) + "\n" for m in messages))
    sys.stdout.flush()


def status():
    queued = array.array("i", [0])
    fcntl.ioctl(0, termios.FIONREAD, queued)
    return {"state": state, "generation": generation,
            "notices": list(notices), "generations": list(generations),
            "records": records, "queued_bytes": queued[0], "reading": reading}


def command(message):
    global reading
    op = message["op"]
    if op == "send":
        send(message["messages"])
    elif op == "pause":
        # Bound the amount of output needed to exercise actual pipe pressure.
        # This changes only our own stdin pipe, never the daemon's network I/O.
        fcntl.fcntl(0, fcntl.F_SETPIPE_SZ, 4096)
        if reading:
            selector.unregister(0)
            reading = False
    elif op == "resume":
        if not reading:
            selector.register(0, selectors.EVENT_READ, "stdin")
            reading = True
    elif op == "crash":
        sys.exit(3)
    elif op != "status":
        raise ValueError("unknown test control operation")
    reply({"reply": message["id"], **status()})


def record(message):
    global records, state, pending, generation, pending_generation
    records += 1
    kind = message["type"]
    if role != "router":
        notices.append(message)
    elif kind == "snapshot_begin":
        assert pending is None, "nested snapshot"
        assert message["version"] == 1
        pending, pending_generation = {}, message["generation"]
        assert generation is None or pending_generation >= generation
    elif kind == "session":
        assert pending is not None and message["session"] not in pending
        pending[message["session"]] = {**message, "addresses": [], "destinations": {}}
    elif kind == "destination":
        session = pending[message["session"]]
        assert message["mac"] not in session["destinations"]
        session["destinations"][message["mac"]] = {**message, "addresses": []}
    elif kind == "address":
        owner = pending[message["session"]]
        if message["mac"] is not None:
            owner = owner["destinations"][message["mac"]]
        owner["addresses"].append({"kind": message["kind"], "address": message["address"]})
    elif kind == "snapshot_end":
        assert pending is not None and message["generation"] == pending_generation
        state, pending, generation = pending, None, pending_generation
        generations.append(generation)
    else:
        assert pending is None, "notice interleaved with a snapshot"
        notices.append(message)


reply({"hello": role, "pid": os.getpid()})
while True:
    for key, _ in selector.select():
        name = key.data
        if name == "stdin" and not reading:
            continue
        data = os.read(key.fd, 65536)
        if not data:
            if name == "stdin":
                # Preserve what was actually applied before clearing on EOF.
                with open(final_path, "w") as output:
                    json.dump({"last_state": state, "generation": generation,
                               "incomplete": pending is not None}, output)
            sys.exit(0)
        buffers[name] += data
        while b"\n" in buffers[name]:
            line, buffers[name] = buffers[name].split(b"\n", 1)
            if line.strip():
                message = json.loads(line)
                if name == "control":
                    command(message)
                else:
                    record(message)
