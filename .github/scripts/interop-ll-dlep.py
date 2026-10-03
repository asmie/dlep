#!/usr/bin/env python3
"""Run our router against unmodified, pinned MIT LL-DLEP in a networkless container."""
import argparse
import asyncio
import contextlib
import json
import pathlib
import re
import struct
import subprocess
import xml.etree.ElementTree as ET

from interop_common import capture, until

REVISION = "184e148ae4747dee11263a7ccedf952e36861ec0"
PEER = pathlib.Path("/opt/ll-dlep")
MAC = "02:00:00:00:00:01"
INITIAL = ("Maximum_Data_Rate_Receive 10000000 Maximum_Data_Rate_Transmit 20000000 "
           "Current_Data_Rate_Receive 5000000 Current_Data_Rate_Transmit 7000000 Latency 2500")


def wire_messages(path):
    """Read our bounded loopback capture, checking TCP continuity and framing.

    This is only for the single IPv4 connection in each scenario. It decodes
    message headers, never data items, independently of either protocol codec.
    """
    data = path.read_bytes()
    streams, starts = {}, {}
    offset = 24  # Our capture helper writes a little-endian Ethernet PCAP.
    while offset < len(data):
        _, _, length, original = struct.unpack_from("<IIII", data, offset)
        assert length == original
        offset += 16
        frame = data[offset:offset + length]
        assert len(frame) == length
        offset += length
        tcp = 14 + (frame[14] & 15) * 4
        source, dest, sequence = struct.unpack_from("!HHI", frame, tcp)
        flow = (source, dest)
        if frame[tcp + 13] & 2:  # SYN establishes each direction's sequence base.
            starts[flow] = (sequence + 1) & 0xFFFFFFFF
        ip_end = 14 + struct.unpack_from("!H", frame, 16)[0]
        payload = frame[tcp + (frame[tcp + 12] >> 4) * 4:ip_end]
        if payload:
            streams.setdefault(flow, []).append(((sequence - starts[flow]) & 0xFFFFFFFF, payload))
    messages = {}
    for (source, dest), segments in streams.items():
        stream = bytearray()
        for position, payload in sorted(segments):
            assert position <= len(stream), "capture has a gap in TCP data"
            overlap = min(len(stream) - position, len(payload))
            assert stream[position:position + overlap] == payload[:overlap]
            stream.extend(payload[overlap:])
        types, offset = [], 0
        while offset < len(stream):
            kind, length = struct.unpack_from("!HH", stream, offset)
            offset += 4 + length
            assert offset <= len(stream), "truncated DLEP message in capture"
            types.append(kind)
        messages["modem" if source == 4854 else "router"] = types
        assert 4854 in (source, dest)
    assert set(messages) == {"router", "modem"}
    return messages


class Process:
    def __init__(self, child, output, reader):
        self.child, self.output, self.reader = child, output, reader

    @classmethod
    async def start(cls, args, path):
        child = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE,
                                                    stderr=asyncio.subprocess.STDOUT)
        output = bytearray()

        async def read():
            with path.open("wb") as log:
                while data := await child.stdout.read(4096):
                    output.extend(data)
                    log.write(data)
                    log.flush()

        return cls(child, output, asyncio.create_task(read()))

    def text(self):
        return self.output.decode(errors="replace")

    async def command(self, line):
        self.child.stdin.write((line + "\n").encode())
        await self.child.stdin.drain()

    async def expect(self, text):
        await until(lambda: text in self.text(), text)

    async def finished(self):
        await asyncio.wait_for(self.child.wait(), 10)
        await self.reader
        assert self.child.returncode == 0, self.text()

    async def close(self):
        if self.child.returncode is None:
            self.child.kill()
            await self.child.wait()
        await self.reader


async def scenario(output, initiator):
    counts = {"tcp_packets": 0, "wrong_ttl": 0}
    packet_task = asyncio.create_task(capture(output / f"{initiator}.pcap", counts))
    await asyncio.sleep(0)
    if packet_task.done():
        packet_task.result()
    modem = router = None
    log_path = output / f"{initiator}-peer.log"
    try:
        modem = await Process.start([
            "/opt/ll-dlep-build/Dlep", "local-type", "modem", "discovery-enable", "0",
            "session-address", "127.0.0.1", "session-port", "4854",
            "heartbeat-interval", "1", "session-ttl", "255",
            "linkchar-autoreply", "0",
            "protocol-config-file", str(output / "core-protocol.xml"),
            "protocol-config-schema", str(PEER / "config/protocol/protocol-config.xsd"),
            "log-file", str(log_path), "log-level", "1",
        ], output / f"{initiator}-modem.log")
        await modem.expect("DlepInit succeeded")
        # A show command after peer update forms a CLI processing barrier.
        await modem.command("peer update " + INITIAL)
        await modem.command("show peer")
        await until(lambda: modem.text().count("DlepService returns: ok") >= 2,
                    "LL-DLEP accepting initial peer metrics")
        router = await Process.start(["/work/target/debug/examples/interop_router", "127.0.0.1:4854"],
                                     output / f"{initiator}-router.log")
        await router.expect("UP\n")
        await router.expect("METRICS 10000000 20000000 5000000 7000000 2500\n")
        await modem.expect("Peer up,")
        await modem.command(f"dest up {MAC} " + INITIAL)
        await router.expect("DEST_UP 10000000 20000000 5000000 7000000 2500\n")
        await modem.command(f"dest update {MAC} Current_Data_Rate_Receive 4000000 Latency 3500")
        await router.expect("DEST_UPDATE 10000000 20000000 4000000 7000000 3500\n")
        await modem.command("peer update Current_Data_Rate_Transmit 6000000")
        await router.expect("METRICS 10000000 20000000 5000000 6000000 2500\n")
        await router.command("link")
        await modem.expect("Linkchar request, peer = ")
        peer_id = re.search(r"Linkchar request, peer = ([^,]+),", modem.text()).group(1)
        # Upstream's convenience autoreply echoes only requested items. Supply
        # all supported metrics through its CLI, as RFC 8175 section 12.19 needs.
        await modem.command(
            f"linkchar reply {peer_id} {MAC} Status 0;OK "
            "Maximum_Data_Rate_Receive 10000000 Maximum_Data_Rate_Transmit 20000000 "
            "Current_Data_Rate_Receive 2000000 Current_Data_Rate_Transmit 3000000 "
            "Latency 4500 Resources 0 Relative_Link_Quality_Receive 0 "
            "Relative_Link_Quality_Transmit 0 Maximum_Transmission_Unit 0"
        )
        await router.expect("LINK_STATUS 0\n")
        await router.expect("LINK_METRICS 10000000 20000000 2000000 3000000 4500\n")
        await modem.command(f"dest down {MAC}")
        await router.expect("DEST_DOWN\n")
        # Assert the independent modem both sends and processes heartbeats;
        # merely waiting with an open TCP connection is insufficient evidence.
        await until(lambda: log_path.read_text().count("Send Heartbeat to peer ID=") >= 2
                    and log_path.read_text().count("handle_heartbeat(): from peer=") >= 2,
                    "bidirectional periodic heartbeats")
        assert "DOWN " not in router.text(), router.text()
        if initiator == "modem":
            await modem.command("quit")
            await router.expect("DOWN 0\n")
            await modem.finished()
        await router.command("shutdown")
        await router.finished()
        if initiator == "router":
            await modem.expect("Peer down,")
            await modem.command("quit")
            await modem.finished()
        lines = router.text().splitlines()
        expected_down = "DOWN 0" if initiator == "modem" else "DOWN 255"
        assert lines.count("UP") == 1 and lines.count(expected_down) == 1, lines
        assert sum(line.startswith("DOWN ") for line in lines) == 1, lines
        assert "STOPPED" in lines, lines
        assert counts["tcp_packets"] > 0 and counts["wrong_ttl"] == 0, counts
        packet_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await packet_task
        messages = wire_messages(output / f"{initiator}.pcap")
        # Verify the wire exchange, not just a TCP close retaining the shutdown
        # reason. Type 5 is Termination; type 6 is its required Response.
        responder = "modem" if initiator == "router" else "router"
        assert messages[initiator].count(5) == 1, messages
        assert messages[responder].count(6) == 1, messages
        assert all(types.count(16) >= 2 for types in messages.values()), messages
        peer_log = log_path.read_text()
        return {"initiator": initiator, **counts,
                "heartbeats_sent": peer_log.count("Send Heartbeat to peer ID="),
                "heartbeats_received": peer_log.count("handle_heartbeat(): from peer="),
                "wire_messages": messages,
                "result": "passed"}
    finally:
        for peer in [router, modem]:
            if peer:
                await peer.close()
        packet_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await packet_task


async def run(output):
    # Upstream's example profile includes experimental extensions, whose metric
    # defaults are emitted even when they were not negotiated. Select core only
    # via its supported XML configuration rather than weakening our validation.
    profile = ET.parse(PEER / "config/protocol/dlep-rfc-8175.xml")
    for extension in profile.getroot().findall("{http://www.w3.org/2001/XInclude}include"):
        profile.getroot().remove(extension)
    # The upstream core profile omits RFC 8175 table 2's Shutting Down status.
    # Its configurable validator otherwise rejects our normal termination.
    status = ET.SubElement(profile.getroot().find("module"), "status_code")
    for tag, value in [("name", "Shutting_Down"), ("id", "255"), ("failure_mode", "terminate")]:
        ET.SubElement(status, tag).text = value
    profile.write(output / "core-protocol.xml", encoding="utf-8", xml_declaration=True)
    results = []
    for initiator in ["router", "modem"]:
        results.append(await scenario(output, initiator))
    summary = {"peer": "mit-ll/LL-DLEP", "revision": REVISION,
               "transport": "static IPv4 TCP, strict GTSM, no TLS", "scenarios": results}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "-C", str(PEER), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(PEER), "status", "--porcelain", "--untracked-files=no"], text=True)
    if revision != REVISION or dirty:
        parser.error("independent peer checkout must match the clean pinned revision")
    # The supported wrapper uses --network none; never capture a host interface.
    if sorted(p.name for p in pathlib.Path("/sys/class/net").iterdir()) != ["lo"]:
        parser.error("run with interop-ll-dlep.sh in its networkless container")
    if pathlib.Path("/proc/sys/net/ipv4/ip_default_ttl").read_text().strip() != "255":
        parser.error("the container's default TTL must be 255 for the TCP handshake")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").unlink(missing_ok=True)
    asyncio.run(run(args.output))


if __name__ == "__main__":
    main()
