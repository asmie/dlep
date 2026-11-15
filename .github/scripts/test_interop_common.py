"""Regression checks for evidence parsing; no sockets or external peers needed."""
import ipaddress
import pathlib
import struct
import tempfile
import unittest

from interop_common import address_items, wire_records

HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def packet(source, dest, sequence, payload=b"", syn=False):
    frame = bytearray(54 + len(payload))
    frame[12:14] = b"\x08\x00"
    frame[14], frame[22], frame[23] = 0x45, 255, 6
    struct.pack_into("!H", frame, 16, 40 + len(payload))
    struct.pack_into("!HHI", frame, 34, source, dest, sequence)
    frame[46], frame[47] = 0x50, 2 if syn else 0x10
    frame[54:] = payload
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def item(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def message(kind, items=b""):
    return struct.pack("!HH", kind, len(items)) + items


class CaptureTests(unittest.TestCase):
    def read(self, packets):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "capture.pcap"
            path.write_bytes(HEADER + b"".join(packets))
            return wire_records(path, 4854)

    def connection(self, payload):
        return [packet(40000, 4854, 100, syn=True), packet(4854, 40000, 200, syn=True),
                packet(4854, 40000, 201, message(16)), packet(40000, 4854, 101, payload)]

    def test_split_reordered_and_retransmitted_segments_preserve_address_flags(self):
        items = item(8, b"\x01" + ipaddress.ip_address("192.0.2.1").packed)
        items += item(9, b"\x00" + ipaddress.ip_address("2001:db8::1").packed)
        items += item(10, b"\x01" + ipaddress.ip_address("198.51.100.0").packed + b"\x18")
        items += item(11, b"\x00" + ipaddress.ip_address("2001:db8:1::").packed + b"\x40")
        payload = message(3, items) + message(16)
        records = self.read([
            packet(40000, 4854, 0xFFFFFFFF, syn=True), packet(4854, 40000, 200, syn=True),
            packet(40000, 4854, 7, payload[7:]), packet(40000, 4854, 0, payload[:12]),
            packet(40000, 4854, 0, payload[:12]), packet(4854, 40000, 201, message(4, item(1, b"\0"))),
        ])
        self.assertEqual([m["type"] for m in records["router"]], [3, 16])
        self.assertEqual(address_items(records["router"][0]), [
            (8, 1, "192.0.2.1"), (9, 0, "2001:db8::1"),
            (10, 1, "198.51.100.0/24"), (11, 0, "2001:db8:1::/64"),
        ])
        self.assertEqual(address_items(records["modem"][0]), [])

    def test_gaps_conflicts_missing_syn_and_extra_connections_fail(self):
        valid = self.connection(message(16))
        for packets in [
            valid[:-1] + [packet(40000, 4854, 102, message(16))],
            valid + [packet(40000, 4854, 101, message(3))],
            valid[1:], valid[:-1],
            valid + [packet(40001, 4854, 100, syn=True), packet(40001, 4854, 101, message(16))],
        ]:
            with self.subTest(packets=packets), self.assertRaises(AssertionError):
                self.read(packets)

    def test_truncated_captures_messages_and_items_fail(self):
        valid = self.connection(message(16))
        for payload in [b"\x00", b"\x00\x03\x00\x01", message(3, b"\x00"),
                        message(3, b"\x00\x08\x00\x05\x01")]:
            with self.subTest(payload=payload), self.assertRaises(AssertionError):
                self.read(self.connection(payload))
        with self.assertRaises(AssertionError):
            self.read(valid[:-1] + [valid[-1][:-1]])
        with self.assertRaises(AssertionError):
            self.read(valid + [b"\0"])

    def test_invalid_address_items_cannot_pass_evidence_checks(self):
        for kind, value in [(8, b"\x02\xc0\x00\x02\x01"), (9, b"\x01"),
                            (10, b"\x01\xc0\x00\x02\x00\x21"),
                            (11, b"\0" + bytes(16) + b"\x81")]:
            with self.subTest(kind=kind, value=value), self.assertRaises((AssertionError, ValueError)):
                address_items({"items": [(kind, value)]})


if __name__ == "__main__":
    unittest.main()
