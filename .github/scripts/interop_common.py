"""Bounded waits and isolated packet capture for peer checks."""
import asyncio
import ipaddress
import socket
import struct
import time


def ip_frame(frame, ip_version, protocol=6):
    """Validate an unfragmented TCP/UDP frame from our controlled peers."""
    assert ip_version in (4, 6)
    assert len(frame) >= 14 + (20 if ip_version == 4 else 40), "truncated Ethernet/IP frame"
    ethertype = b"\x08\x00" if ip_version == 4 else b"\x86\xdd"
    assert frame[12:14] == ethertype and frame[14] >> 4 == ip_version, "unexpected IP family"
    if ip_version == 4:
        ip_header = (frame[14] & 15) * 4
        assert ip_header >= 20 and frame[23] == protocol, "unexpected IPv4 protocol"
        assert struct.unpack_from("!H", frame, 20)[0] & 0x3FFF == 0, "fragmented IPv4 packet"
        ip_end = 14 + struct.unpack_from("!H", frame, 16)[0]
        source_ip, dest_ip, hops = bytes(frame[26:30]), bytes(frame[30:34]), frame[22]
    else:
        ip_header = 40
        # These fixtures send TCP/UDP without extension headers or fragments.
        # Reject unsupported headers instead of misreading them as TCP evidence.
        assert frame[20] == protocol, "unexpected IPv6 protocol or extension header"
        ip_end = 54 + struct.unpack_from("!H", frame, 18)[0]
        source_ip, dest_ip, hops = bytes(frame[22:38]), bytes(frame[38:54]), frame[21]
    transport = 14 + ip_header
    assert transport + (20 if protocol == 6 else 8) <= ip_end <= len(frame), "truncated IP/transport frame"
    return transport, ip_end, source_ip, dest_ip, hops


def pcap_frames(path):
    data = path.read_bytes()
    assert data[:24] == struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    offset = 24
    while offset < len(data):
        assert offset + 16 <= len(data), "truncated PCAP record"
        _, _, length, original = struct.unpack_from("<IIII", data, offset)
        assert length == original
        offset += 16
        frame = data[offset:offset + length]
        assert len(frame) == length, "truncated Ethernet/IP frame"
        offset += length
        yield frame


def wire_records(path, modem_port, ip_version=4):
    """Reassemble one TCP connection without using either peer's codec."""
    streams, starts = {}, {}
    for frame in pcap_frames(path):
        tcp, ip_end, source_ip, dest_ip, hops = ip_frame(frame, ip_version)
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


def discovery_records(path, ip_version=4):
    """Decode captured UDP signals, preserving endpoints for port checks."""
    records = []
    for frame in pcap_frames(path):
        udp, end, source, dest, hops = ip_frame(frame, ip_version, 17)
        assert hops == 255, "unexpected discovery TTL/hop limit"
        source_port, dest_port, length = struct.unpack_from("!HHH", frame, udp)
        assert length >= 16 and udp + length == end, "invalid UDP length"
        payload = frame[udp + 8:end]
        assert payload[:4] == b"DLEP", "invalid signal prefix"
        kind, size = struct.unpack_from("!HH", payload, 4)
        assert kind in (1, 2) and size == len(payload) - 8, "invalid signal header"
        items, offset = [], 8
        while offset < len(payload):
            assert offset + 4 <= len(payload), "truncated signal item header"
            item, size = struct.unpack_from("!HH", payload, offset)
            offset += 4
            assert offset + size <= len(payload), "truncated signal item"
            items.append((item, bytes(payload[offset:offset + size])))
            offset += size
        records.append({"type": kind, "items": items,
                        "source": (str(ipaddress.ip_address(source)), source_port),
                        "dest": (str(ipaddress.ip_address(dest)), dest_port)})
    assert records, "capture contains no discovery signals"
    return records


def discovery_exchange(records, address, session_port, discovery_port=49854, *, legacy_ports=False):
    """Check request/offer endpoints and the exact advertised connection point.

    legacy_ports diagnoses pinned LL-DLEP's wrong reply ports; it does not
    classify that exchange as interoperable with our ephemeral-port router.
    """
    address = ipaddress.ip_address(address)
    group = "224.0.0.117" if address.version == 4 else "ff02::1:7"
    requests = [r for r in records if r["type"] == 1]
    offers = [r for r in records if r["type"] == 2]
    assert requests and offers, "missing discovery request or offer"
    sources = set()
    for request in requests:
        assert request["dest"] == (group, discovery_port), "wrong multicast destination"
        assert request["source"][0] == str(address), "wrong discovery source"
        assert request["source"][1] not in (0, discovery_port), "expected ephemeral source port"
        sources.add(request["source"])
    expected = (2 if address.version == 4 else 3,
                b"\0" + address.packed + struct.pack("!H", session_port))
    for offer in offers:
        if legacy_ports:
            assert offer["dest"] == (str(address), discovery_port), "legacy destination port changed"
            assert offer["source"][0] == str(address) and offer["source"][1] not in (0, discovery_port)
        else:
            assert offer["dest"] in sources, "offer does not return to requesting socket"
            assert offer["source"] == (str(address), discovery_port), "wrong offer source port"
        assert [i for i in offer["items"] if i[0] in (2, 3)] == [expected], "wrong connection point"
    return {"requests": len(requests), "offers": len(offers),
            "reply_ports": "incompatible" if legacy_ports else "correct"}


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


async def capture(path, counts, ip_version=4, *, protocol=6, interface="lo", outgoing=False):
    # AF_PACKET SOCK_RAW includes the Ethernet header even on Linux loopback.
    # EtherType-bound sockets see received packets. ETH_P_ALL is needed for
    # outgoing multicast on the diagnostic dummy interface; filter its family
    # below. TCP captures retain only received packets to avoid loopback copies.
    assert ip_version in (4, 6)
    ethertype = 0x0800 if ip_version == 4 else 0x86DD
    minimum, protocol_offset, hops_offset = (34, 23, 22) if ip_version == 4 else (54, 20, 21)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(0x0003 if outgoing else ethertype)) as sock:
        if interface is not None:
            sock.bind((interface, 0))
        sock.setblocking(False)
        with path.open("wb") as output:
            output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            while True:
                packet, address = await asyncio.get_running_loop().sock_recvfrom(sock, 65535)
                if ((address[2] == socket.PACKET_OUTGOING and not outgoing) or len(packet) < minimum
                        or packet[12:14] != ethertype.to_bytes(2, "big")
                        or packet[protocol_offset] != protocol):
                    continue
                counts["tcp_packets" if protocol == 6 else "udp_packets"] += 1
                # Preserve the existing summary key; for IPv6 this is the hop limit.
                counts["wrong_ttl"] += packet[hops_offset] != 255
                stamp = time.time_ns()
                output.write(struct.pack("<IIII", stamp // 10**9, (stamp % 10**9) // 1000,
                                         len(packet), len(packet)))
                output.write(packet)
                output.flush()


