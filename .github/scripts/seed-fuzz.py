"""Create deterministic starting inputs; libFuzzer grows ignored corpus copies."""
from pathlib import Path
import struct


def item(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def message(kind, body=b""):
    return struct.pack("!HH", kind, len(body)) + body


def main():
    heartbeat = item(5, struct.pack("!I", 1000))
    peer = item(4, b"\0fuzz")
    status = item(1, b"\0")
    mac = item(7, bytes.fromhex("020000000001"))
    init = message(1, heartbeat + peer)
    reply = message(2, status + heartbeat + peer + b"".join(
        item(kind, (1000).to_bytes(8, "big")) for kind in range(12, 17)))
    messages = {
        "initialization": init, "initialization-response": reply,
        "heartbeat": message(16), "up": message(7, mac),
        "up-response": message(8, mac + status), "announce": message(9, mac),
        "down": message(11, mac + status), "termination": message(5, item(1, b"\xffbye")),
        "unknown": message(65535, item(65535, b"unknown")),
        "duplicate-metric": message(3, item(16, bytes(8)) * 2),
        "invalid-subnet": message(3, item(10, b"\1\xc0\0\2\0\x21")),
        "truncated": bytes.fromhex("000300090008000501"),
    }
    seeds = {"wire_decode": dict(messages), "session_sequence": {}}
    seeds["wire_decode"].update({
        "discovery": b"DLEP" + message(1, peer),
        "offer-v4": b"DLEP" + message(2, item(2, bytes.fromhex("00c00002010356"))),
        "offer-v6": b"DLEP" + message(2, item(3, b"\0" + bytes.fromhex("fe800000000000000000000000000001") + b"\3\x56")),
        "item-eui64": item(7, bytes.fromhex("0200000000000001")),
        "invalid-utf8": item(4, b"\0\xff"),
        "max-message": message(65535, item(65535, bytes(65531))),
        "max-signal": b"DLEP" + message(65535, item(65535, bytes(65531))),
    })
    for mode in range(4):
        # Valid peer exchange plus application operations, heartbeat and shutdown.
        seeds["session_sequence"][f"lifecycle-{mode}"] = bytes([mode, 1, 3, 0x84, 2, 5, 6, 7, 8, 0x88, 12])
        for name, payload in messages.items():
            for side in (0, 128):
                seeds["session_sequence"][f"{mode}-{side}-{name}"] = bytes([mode, side]) + struct.pack("!H", len(payload)) + payload
    signals = {
        "discovery": b"DLEP" + message(1, peer),
        "fallback": b"DLEP" + message(2),
        "offer-v4": seeds["wire_decode"]["offer-v4"],
        "offer-v6": seeds["wire_decode"]["offer-v6"],
        "duplicate-peer": b"DLEP" + message(2, peer * 2),
        "unknown-item": b"DLEP" + message(2, item(65535, b"x")),
        "truncated": b"DLEP\0\2\0\x08\0",
    }
    cp = item(2, bytes.fromhex("00c00002020356"))
    other = item(2, bytes.fromhex("00c00002030356"))
    signals["interleaved-duplicates"] = b"DLEP" + message(2, cp + other + item(2, bytes.fromhex("00c0000202")))
    signals["tls-order"] = b"DLEP" + message(2, cp + item(2, bytes.fromhex("01c00002020356"))
        + item(3, b"\1" + bytes.fromhex("fe800000000000000000000000000001") + b"\3\x56"))
    signals["unusable-endpoints"] = b"DLEP" + message(2,
        item(2, bytes.fromhex("00000000000356"))
        + item(2, bytes.fromhex("00e00000750356"))
        + item(2, bytes.fromhex("00c00002020000"))
        + item(3, b"\0" + bytes(16) + b"\3\x56"))
    signals["invalid-flags"] = b"DLEP" + message(2, item(2, bytes.fromhex("80c00002020356")))
    seeds["discovery_sequence"] = {}
    for mode in range(8):
        seeds["discovery_sequence"][f"lifecycle-{mode}"] = bytes([mode, 1, 2, 3, 1, 7, 1])
        for name, payload in signals.items():
            for side in (0, 128):
                seeds["discovery_sequence"][f"{mode}-{side}-{name}"] = bytes([mode, side]) + struct.pack("!H", len(payload)) + payload
    for target, inputs in seeds.items():
        root = Path("fuzz/corpus") / target
        root.mkdir(parents=True, exist_ok=True)
        for name, payload in inputs.items():
            (root / name).write_bytes(payload)
        print(f"{target}: {len(inputs)} seeds")


if __name__ == "__main__":
    main()
