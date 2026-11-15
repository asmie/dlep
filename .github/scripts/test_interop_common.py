"""Regression checks for evidence parsing; no sockets or external peers needed."""
import copy
import ipaddress
import pathlib
import struct
import tempfile
import unittest

from interop_common import address_items, discovery_exchange, discovery_records, wire_records

HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def packet(source, dest, sequence, payload=b"", syn=False, *, ip_version=4):
    tcp = 34 if ip_version == 4 else 54
    frame = bytearray(tcp + 20 + len(payload))
    if ip_version == 4:
        frame[12:14] = b"\x08\x00"
        frame[14], frame[22], frame[23] = 0x45, 255, 6
        frame[26:30] = frame[30:34] = ipaddress.ip_address("127.0.0.1").packed
        struct.pack_into("!H", frame, 16, 40 + len(payload))
    else:
        frame[12:14] = b"\x86\xdd"
        frame[14], frame[20], frame[21] = 0x60, 6, 255
        frame[22:38] = frame[38:54] = ipaddress.ip_address("::1").packed
        struct.pack_into("!H", frame, 18, 20 + len(payload))
    struct.pack_into("!HHI", frame, tcp, source, dest, sequence)
    frame[tcp + 12], frame[tcp + 13] = 0x50, 2 if syn else 0x10
    frame[tcp + 20:] = payload
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


def item(kind, value):
    return struct.pack("!HH", kind, len(value)) + value


def message(kind, items=b""):
    return struct.pack("!HH", kind, len(items)) + items


class CaptureTests(unittest.TestCase):
    ip_version = 4

    def packet(self, *args, **kwargs):
        return packet(*args, **kwargs, ip_version=self.ip_version)

    def read(self, packets):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "capture.pcap"
            path.write_bytes(HEADER + b"".join(packets))
            return wire_records(path, 4854, self.ip_version)

    def connection(self, payload):
        return [self.packet(40000, 4854, 100, syn=True), self.packet(4854, 40000, 200, syn=True),
                self.packet(4854, 40000, 201, message(16)), self.packet(40000, 4854, 101, payload)]

    def test_split_reordered_and_retransmitted_segments_preserve_address_flags(self):
        items = item(8, b"\x01" + ipaddress.ip_address("192.0.2.1").packed)
        items += item(9, b"\x00" + ipaddress.ip_address("2001:db8::1").packed)
        items += item(10, b"\x01" + ipaddress.ip_address("198.51.100.0").packed + b"\x18")
        items += item(11, b"\x00" + ipaddress.ip_address("2001:db8:1::").packed + b"\x40")
        payload = message(3, items) + message(16)
        records = self.read([
            self.packet(40000, 4854, 0xFFFFFFFF, syn=True), self.packet(4854, 40000, 200, syn=True),
            self.packet(40000, 4854, 7, payload[7:]), self.packet(40000, 4854, 0, payload[:12]),
            self.packet(40000, 4854, 0, payload[:12]), self.packet(4854, 40000, 201, message(4, item(1, b"\0"))),
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
            valid[:-1] + [self.packet(40000, 4854, 102, message(16))],
            valid + [self.packet(40000, 4854, 101, message(3))],
            valid[1:], valid[:-1],
            valid + [self.packet(40001, 4854, 100, syn=True), self.packet(40001, 4854, 101, message(16))],
            valid + [self.packet(40001, 4854, 101)],
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

    def test_packet_headers_and_hop_limit_are_checked(self):
        valid = self.connection(message(16))
        if self.ip_version == 4:
            changes = [(14, b"\x44"), (14, b"\x65"), (16, b"\0\0"),
                       (16, b"\xff\xff"), (20, b"\x20\0"), (20, b"\0\x01"),
                       (22, b"\xfe"), (23, b"\x11"), (46, b"\x40")]
        else:
            changes = [(14, b"\x40"), (18, b"\0\0"), (18, b"\xff\xff"),
                       (20, b"\0"), (20, b"\x2c"), (20, b"\x11"),
                       (21, b"\xfe"), (66, b"\x40")]
        for offset, value in changes:
            broken = bytearray(valid[-1])
            broken[16 + offset:16 + offset + len(value)] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(AssertionError):
                self.read(valid[:-1] + [broken])
        other_family = packet(40000, 4854, 101, message(16),
                              ip_version=6 if self.ip_version == 4 else 4)
        with self.assertRaisesRegex(AssertionError, "unexpected IP family"):
            self.read(valid[:-1] + [other_family])

    def test_ip_addresses_identify_the_connection(self):
        valid = self.connection(message(16))
        offset, address = ((26, "127.0.0.2") if self.ip_version == 4 else (22, "::2"))
        address = ipaddress.ip_address(address).packed
        # Matching ports and sequence numbers from a different IP must not merge.
        changed = list(valid)
        for index in [1, 2]:
            changed[index] = bytearray(changed[index])
            changed[index][16 + offset:16 + offset + len(address)] = address
        with self.assertRaisesRegex(AssertionError, "mismatched TCP peers"):
            self.read(changed)
        # Even an extra SYN without any data invalidates the single-session capture.
        with self.assertRaisesRegex(AssertionError, "exactly one TCP connection"):
            self.read(valid + [changed[1]])

    def test_invalid_address_items_cannot_pass_evidence_checks(self):
        for kind, value in [(8, b"\x02\xc0\x00\x02\x01"), (9, b"\x01"),
                            (10, b"\x01\xc0\x00\x02\x00\x21"),
                            (11, b"\0" + bytes(16) + b"\x81")]:
            with self.subTest(kind=kind, value=value), self.assertRaises((AssertionError, ValueError)):
                address_items({"items": [(kind, value)]})


class IPv6CaptureTests(CaptureTests):
    ip_version = 6


class DiscoveryCaptureTests(unittest.TestCase):
    ip_version = 4

    @property
    def address(self):
        return "127.0.0.1" if self.ip_version == 4 else "fe80::2"

    @property
    def group(self):
        return "224.0.0.117" if self.ip_version == 4 else "ff02::1:7"

    def datagram(self, payload, source, dest, source_port, dest_port):
        udp = 34 if self.ip_version == 4 else 54
        frame = bytearray(packet(0, 0, 0, ip_version=self.ip_version)[16:16 + udp])
        frame.extend(struct.pack("!HHHH", source_port, dest_port, 8 + len(payload), 0) + payload)
        if self.ip_version == 4:
            frame[23] = 17
            frame[26:30], frame[30:34] = ipaddress.ip_address(source).packed, ipaddress.ip_address(dest).packed
            struct.pack_into("!H", frame, 16, len(frame) - 14)
        else:
            frame[20] = 17
            frame[22:38], frame[38:54] = ipaddress.ip_address(source).packed, ipaddress.ip_address(dest).packed
            struct.pack_into("!H", frame, 18, len(frame) - 54)
        return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame

    def read(self, packets):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "discovery.pcap"
            path.write_bytes(HEADER + b"".join(packets))
            return discovery_records(path, self.ip_version)

    def exchange(self, legacy=False):
        connection = item(2 if self.ip_version == 4 else 3,
                          b"\0" + ipaddress.ip_address(self.address).packed + struct.pack("!H", 4854))
        return [self.datagram(b"DLEP" + message(1), self.address, self.group, 40000, 49854),
                self.datagram(b"DLEP" + message(2, connection), self.address, self.address,
                              41000 if legacy else 49854, 49854 if legacy else 40000)]

    def test_valid_discovery_preserves_advertised_endpoint_and_reply_ports(self):
        records = self.read(self.exchange())
        self.assertEqual(discovery_exchange(records, self.address, 4854),
                         {"requests": 1, "offers": 1, "reply_ports": "correct"})
        # Repeated discovery attempts are valid and remain individually checked.
        self.assertEqual(discovery_exchange(records * 2, self.address, 4854)["offers"], 2)

    def test_legacy_ports_are_diagnosed_but_never_count_as_compatible(self):
        records = self.read(self.exchange(legacy=True))
        with self.assertRaisesRegex(AssertionError, "requesting socket"):
            discovery_exchange(records, self.address, 4854)
        self.assertEqual(discovery_exchange(records, self.address, 4854, legacy_ports=True)["reply_ports"],
                         "incompatible")
        with self.assertRaises(AssertionError):
            discovery_exchange(self.read(self.exchange()), self.address, 4854, legacy_ports=True)

    def test_malformed_datagrams_and_signals_fail(self):
        for payload in [b"DLEP", b"FAIL" + message(1), b"DLEP" + message(3),
                        b"DLEP\0\1\0\x01", b"DLEP" + message(1, b"\0"),
                        b"DLEP" + message(2, b"\0\2\0\x07\0")]:
            with self.subTest(payload=payload), self.assertRaises(AssertionError):
                self.read([self.datagram(payload, self.address, self.group, 40000, 49854)])
        valid = self.exchange()
        udp = 34 if self.ip_version == 4 else 54
        for offset, value in [(udp + 4, b"\0\x07"), (udp + 4, b"\xff\xff"),
                              (22 if self.ip_version == 4 else 21, b"\xfe")]:
            broken = bytearray(valid[0])
            broken[16 + offset:16 + offset + len(value)] = value
            with self.subTest(offset=offset, value=value), self.assertRaises(AssertionError):
                self.read([broken, valid[1]])
        for packets in [[], [valid[0][:-1]], valid + [b"\0"]]:
            with self.subTest(packets=packets), self.assertRaises(AssertionError):
                self.read(packets)

    def test_missing_signals_wrong_endpoints_and_connection_points_fail(self):
        records = self.read(self.exchange())
        for index, key, value in [
            (0, "dest", (self.address, 49854)), (0, "source", (self.address, 49854)),
            (1, "dest", (self.address, 40001)), (1, "source", (self.address, 41000)),
            (1, "items", []), (1, "items", records[1]["items"] * 2),
            (1, "items", [(2, b"\0")]),
            (1, "items", [(records[1]["items"][0][0], b"\1" + records[1]["items"][0][1][1:])]),
        ]:
            wrong = copy.deepcopy(records)
            wrong[index][key] = value
            with self.subTest(index=index, key=key, value=value), self.assertRaises(AssertionError):
                discovery_exchange(wrong, self.address, 4854)
        for missing in [records[:1], records[1:]]:
            with self.assertRaises(AssertionError):
                discovery_exchange(missing, self.address, 4854)
        with self.assertRaisesRegex(AssertionError, "connection point"):
            discovery_exchange(records, self.address, 4855)


class IPv6DiscoveryCaptureTests(DiscoveryCaptureTests):
    ip_version = 6


if __name__ == "__main__":
    unittest.main()
