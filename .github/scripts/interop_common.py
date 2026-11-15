"""Bounded waits and isolated loopback packet capture for peer checks."""
import asyncio
import ipaddress
import socket
import struct
import time


def tcp_frame(frame, ip_version):
    """Validate an unfragmented TCP frame from our controlled loopback peers."""
    assert ip_version in (4, 6)
    assert len(frame) >= 14 + (20 if ip_version == 4 else 40), "truncated Ethernet/IP frame"
    ethertype = b"\x08\x00" if ip_version == 4 else b"\x86\xdd"
    assert frame[12:14] == ethertype and frame[14] >> 4 == ip_version, "unexpected IP family"
    if ip_version == 4:
        ip_header = (frame[14] & 15) * 4
        assert ip_header >= 20 and frame[23] == 6, "expected IPv4 TCP"
        assert struct.unpack_from("!H", frame, 20)[0] & 0x3FFF == 0, "fragmented IPv4 packet"
        ip_end = 14 + struct.unpack_from("!H", frame, 16)[0]
        source_ip, dest_ip, hops = bytes(frame[26:30]), bytes(frame[30:34]), frame[22]
    else:
        ip_header = 40
        # These fixtures send plain TCP, without extension headers or fragments.
        # Reject unsupported headers instead of misreading them as TCP evidence.
        assert frame[20] == 6, "expected IPv6 TCP without extension headers"
        ip_end = 54 + struct.unpack_from("!H", frame, 18)[0]
        source_ip, dest_ip, hops = bytes(frame[22:38]), bytes(frame[38:54]), frame[21]
    tcp = 14 + ip_header
    assert tcp + 20 <= ip_end <= len(frame), "truncated IP/TCP frame"
    return tcp, ip_end, source_ip, dest_ip, hops


def wire_records(path, modem_port, ip_version=4):
    """Reassemble one IPv4 or IPv6 connection in our loopback Ethernet capture.

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
        assert len(frame) == length, "truncated Ethernet/IP/TCP frame"
        offset += length
        tcp, ip_end, source_ip, dest_ip, hops = tcp_frame(frame, ip_version)
        assert hops == 255, "unexpected TTL/hop limit"
        source, dest, sequence = struct.unpack_from("!HHI", frame, tcp)
        assert modem_port in (source, dest), "unexpected TCP connection"
        flow = (source_ip, source, dest_ip, dest)
        if frame[tcp + 13] & 2:
            base = (sequence + 1) & 0xFFFFFFFF
            assert flow not in starts or starts[flow] == base, "multiple TCP connections"
            starts[flow] = base
        assert flow in starts, "capture is missing SYN"
        tcp_header = (frame[tcp + 12] >> 4) * 4
        assert tcp_header >= 20 and tcp + tcp_header <= ip_end
        payload = frame[tcp + tcp_header:ip_end]
        if payload:
            streams.setdefault(flow, []).append(((sequence - starts[flow]) & 0xFFFFFFFF, payload))
    assert len(starts) == 2, "capture must contain exactly one TCP connection"
    source_ip, source, dest_ip, dest = next(iter(starts))
    assert (dest_ip, dest, source_ip, source) in starts, "mismatched TCP peers"
    records = {}
    for (_, source, _, _), segments in streams.items():
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


async def capture(path, counts, ip_version=4):
    # AF_PACKET SOCK_RAW includes the Ethernet header even on Linux loopback.
    # Ignore the outgoing duplicate; record only the selected family's TCP on lo.
    assert ip_version in (4, 6)
    ethertype = 0x0800 if ip_version == 4 else 0x86DD
    minimum, protocol_offset, hops_offset = (34, 23, 22) if ip_version == 4 else (54, 20, 21)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype)) as sock:
        sock.bind(("lo", 0))
        sock.setblocking(False)
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            while True:
                packet, address = await asyncio.get_running_loop().sock_recvfrom(sock, 65535)
                if (address[2] == socket.PACKET_OUTGOING or len(packet) < minimum
                        or packet[protocol_offset] != 6):
                    continue
                counts["tcp_packets"] += 1
                # Preserve the existing summary key; for IPv6 this is the hop limit.
                counts["wrong_ttl"] += packet[hops_offset] != 255
                stamp = time.time_ns()
                output.write(struct.pack("<IIII", stamp // 10**9, (stamp % 10**9) // 1000,
                                         len(packet), len(packet)))
                output.write(packet)
                output.flush()


