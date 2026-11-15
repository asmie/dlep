"""Bounded waits and isolated loopback packet capture for peer checks."""
import asyncio
import ipaddress
import socket
import struct
import time


def wire_records(path, modem_port):
    """Reassemble the single IPv4 connection in our loopback Ethernet capture.

    Decode framing/TLV boundaries only; neither peer's codec is used. Require
    both SYN sequence bases, identical retransmissions, and complete messages.
    """
    data = path.read_bytes()
    assert data[:24] == struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    streams, starts = {}, {}
    offset = 24
    while offset < len(data):
        assert offset + 16 <= len(data), "truncated PCAP record"
        _, _, length, original = struct.unpack_from("<IIII", data, offset)
        assert length == original
        offset += 16
        frame = data[offset:offset + length]
        assert len(frame) == length and length >= 54, "truncated Ethernet/IP/TCP frame"
        offset += length
        assert frame[12:14] == b"\x08\x00" and frame[14] >> 4 == 4 and frame[23] == 6
        ip_header = (frame[14] & 15) * 4
        ip_end = 14 + struct.unpack_from("!H", frame, 16)[0]
        tcp = 14 + ip_header
        assert ip_header >= 20 and tcp + 20 <= ip_end <= len(frame)
        source, dest, sequence = struct.unpack_from("!HHI", frame, tcp)
        assert modem_port in (source, dest), "unexpected TCP connection"
        flow = (source, dest)
        if frame[tcp + 13] & 2:
            base = (sequence + 1) & 0xFFFFFFFF
            assert flow not in starts or starts[flow] == base, "multiple TCP connections"
            starts[flow] = base
        tcp_header = (frame[tcp + 12] >> 4) * 4
        assert tcp_header >= 20 and tcp + tcp_header <= ip_end
        payload = frame[tcp + tcp_header:ip_end]
        if payload:
            assert flow in starts, "capture is missing SYN"
            streams.setdefault(flow, []).append(((sequence - starts[flow]) & 0xFFFFFFFF, payload))
    records = {}
    for (source, _), segments in streams.items():
        stream = bytearray()
        for position, payload in sorted(segments):
            assert position <= len(stream), "capture has a gap in TCP data"
            overlap = min(len(stream) - position, len(payload))
            assert stream[position:position + overlap] == payload[:overlap], "conflicting retransmission"
            stream.extend(payload[overlap:])
        messages, offset = [], 0
        while offset < len(stream):
            assert offset + 4 <= len(stream), "truncated DLEP header"
            kind, length = struct.unpack_from("!HH", stream, offset)
            offset += 4
            end = offset + length
            assert end <= len(stream), "truncated DLEP message"
            items = []
            while offset < end:
                assert offset + 4 <= end, "truncated Data Item header"
                item, size = struct.unpack_from("!HH", stream, offset)
                offset += 4
                assert offset + size <= end, "truncated Data Item"
                items.append((item, bytes(stream[offset:offset + size])))
                offset += size
            messages.append({"type": kind, "items": items})
        role = "modem" if source == modem_port else "router"
        assert role not in records, "multiple TCP connections"
        records[role] = messages
    assert set(records) == {"router", "modem"}, "capture is missing a peer"
    return records


def address_items(message):
    """Return sorted (item type, add flag, IP/CIDR) triples for address TLVs."""
    addresses = []
    for kind, value in message["items"]:
        if kind not in (8, 9, 10, 11):
            continue
        size = 4 if kind in (8, 10) else 16
        subnet = kind in (10, 11)
        assert len(value) == 1 + size + subnet and value[0] in (0, 1)
        address = ipaddress.ip_address(value[1:1 + size])
        if subnet:
            address = ipaddress.ip_network(f"{address}/{value[-1]}")
        addresses.append((kind, value[0], str(address)))
    return sorted(addresses)


async def until(predicate, description, seconds=15):
    async def poll():
        while not predicate():
            await asyncio.sleep(0.02)
    try:
        await asyncio.wait_for(poll(), seconds)
    except TimeoutError as error:
        raise AssertionError(f"timed out waiting for {description}") from error


async def capture(path, counts):
    # AF_PACKET SOCK_RAW includes the Ethernet header even on Linux loopback.
    # Ignore the outgoing duplicate; record only IPv4 TCP, confined to lo.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sock:
        sock.bind(("lo", 0))
        sock.setblocking(False)
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            while True:
                packet, address = await asyncio.get_running_loop().sock_recvfrom(sock, 65535)
                if address[2] == socket.PACKET_OUTGOING or len(packet) < 34 or packet[23] != 6:
                    continue
                counts["tcp_packets"] += 1
                counts["wrong_ttl"] += packet[22] != 255
                stamp = time.time_ns()
                output.write(struct.pack("<IIII", stamp // 10**9, (stamp % 10**9) // 1000,
                                         len(packet), len(packet)))
                output.write(packet)
                output.flush()


