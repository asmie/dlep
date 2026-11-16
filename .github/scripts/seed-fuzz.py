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
    streams = dict(messages)
    streams.update({
        "empty": b"", "coalesced": init + reply + message(16) * 3,
        "partial-header": message(16) + b"\0\3\0",
        "partial-body": message(16) + bytes.fromhex("000300090008000501"),
        "malformed-between": message(16) + messages["invalid-subnet"] + message(16),
        "maximum": seeds["wire_decode"]["max-message"],
    })
    seeds["message_framing"] = {}
    for first, later in [(0, 0), (1, 1), (2, 3), (3, 4), (4, 255)]:
        for name, payload in streams.items():
            seeds["message_framing"][f"{first}-{later}-{name}"] = bytes([first, later]) + payload
    def payload(flags=79, number=1, value=1000, percent=100, mask=15, status=0):
        return bytes([flags, number]) + value.to_bytes(8, 'big') + bytes([percent, 24, 64, status, mask, 2])

    normal = payload()
    clear = payload(mask=0)
    scenarios = {
        'address-lifecycle': [(1, normal), (0x40, payload(mask=47)),
            (0x40, payload(number=2)), (0x41, normal), (0x46, payload(number=3)),
            (0x46, clear), (0x82, normal), (0xc2, payload(mask=3))],
        'link-grant': [(1, normal), (0xc3, payload(flags=7)), (0x44, normal),
            (3, payload(value=2000)), (0x45, payload(value=3000))],
        'link-denial': [(1, normal), (0xc3, payload(flags=7)),
            (0x44, payload(flags=0, status=2)), (0xc3, payload(flags=7)), (0x44, normal)],
        'invalid-and-recovery': [(1, payload(mask=31)), (1, payload(percent=255)),
            (1, normal), (0x40, payload(mask=79)), (0xc2, normal),
            (0x43, payload(flags=0)), (0x44, payload(status=128)),
            (3, payload(flags=128, value=18446744073709551615)), (3, normal)],
        'session-addresses': [(0x41, normal), (0x46, payload(number=2)),
            (0x41, payload(number=2, mask=47)), (0x46, clear),
            (0xc1, payload(mask=3)), (0xc1, payload(mask=35))],
    }
    for mode in [5, 7, 13, 15, 29, 31]:
        for name, commands in scenarios.items():
            seeds['session_sequence'][f'structured-{mode}-{name}'] = bytes([mode]) + b''.join(
                bytes([op]) + data for op, data in commands)

    for target, inputs in seeds.items():
        root = Path("fuzz/corpus") / target
        root.mkdir(parents=True, exist_ok=True)
        for name, payload in inputs.items():
            (root / name).write_bytes(payload)
        print(f"{target}: {len(inputs)} seeds")


if __name__ == "__main__":
    main()
