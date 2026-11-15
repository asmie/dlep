#!/usr/bin/env python3
"""Run our router against unmodified, pinned MIT LL-DLEP in a networkless container."""
import argparse
import asyncio
import contextlib
import json
import pathlib
import re
import socket
import subprocess
import xml.etree.ElementTree as ET

from interop_common import address_items, capture, discovery_exchange, discovery_records, until, wire_records

REVISION = "184e148ae4747dee11263a7ccedf952e36861ec0"
PEER = pathlib.Path("/opt/ll-dlep")
MAC = "02:00:00:00:00:01"
UNKNOWN_MAC = "02:00:00:00:00:02"
INITIAL = ("Maximum_Data_Rate_Receive 10000000 Maximum_Data_Rate_Transmit 20000000 "
           "Current_Data_Rate_Receive 5000000 Current_Data_Rate_Transmit 7000000 Latency 2500")


def address_values(n):
    return [("IPv4_Address", f"192.0.2.{n}"), ("IPv6_Address", f"2001:db8::{n}"),
            ("IPv4_Attached_Subnet", f"198.51.{n}.0;24"),
            ("IPv6_Attached_Subnet", f"2001:db8:{n}::;64")]


def cli_addresses(n, add=1):
    return " ".join(f"{name} {add};{value}" for name, value in address_values(n))


def expected_addresses(n, add=1, subnets=True):
    if n is None:
        return []
    return [(kind, add, value.replace(";", "/"))
            for kind, (_, value) in enumerate(address_values(n), 8)
            if subnets or kind < 10]


def state_addresses(n):
    return " ".join(value for _, _, value in expected_addresses(n)) if n is not None else "- - - -"


async def state(router, peer, local, destination):
    after = len(router.text())
    await router.command("state")
    await router.expect("OK state\n", after)
    await router.expect(f"STATE_PEER {state_addresses(peer)}\n", after)
    await router.expect(f"STATE_LOCAL {state_addresses(local)}\n", after)
    await router.expect(f"STATE_DEST {state_addresses(destination)}\n", after)


async def retained_router_addresses(modem, peer_id, expected):
    after = len(modem.text())
    await modem.command(f"show peer {peer_id}")
    await modem.expect("DlepService returns: ok", after)
    # The CLI omits "default metrics:" when the retained set is empty.
    # Start at the queried peer metadata so an earlier callback cannot match.
    output = modem.text()[after:].split("type = dlep-router", 1)[1]
    actual = re.findall(r"^(IPv[46]_(?:Address|Attached_Subnet)) ([^\r\n]+)", output, re.M)
    wanted = [] if expected is None else [(name, f"1;{value}") for name, value in address_values(expected)]
    assert sorted(actual) == sorted(wanted), output


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

    async def expect(self, text, after=0):
        await until(lambda: text in self.text()[after:], text)

    async def finished(self):
        await asyncio.wait_for(self.child.wait(), 10)
        await self.reader
        assert self.child.returncode == 0, self.text()

    async def close(self):
        if self.child.returncode is None:
            self.child.kill()
            await self.child.wait()
        await self.reader


async def scenario(output, initiator, ip_version):
    name = f"ipv{ip_version}-{initiator}"
    address = "127.0.0.1" if ip_version == 4 else "fe80::1"
    endpoint = (f"{address}:4854" if ip_version == 4
                else f"[{address}%{socket.if_nametoindex('lo')}]:4854")
    counts = {"tcp_packets": 0, "wrong_ttl": 0}
    packet_task = asyncio.create_task(capture(output / f"{name}.pcap", counts, ip_version))
    await asyncio.sleep(0)
    if packet_task.done():
        packet_task.result()
    modem = router = None
    log_path = output / f"{name}-peer.log"
    try:
        modem = await Process.start([
            "/opt/ll-dlep-build/Dlep", "local-type", "modem", "discovery-enable", "0",
            "session-address", address, "session-port", "4854",
            "heartbeat-interval", "1", "session-ttl", "255",
            "linkchar-autoreply", "0",
            "protocol-config-file", str(output / "core-protocol.xml"),
            "protocol-config-schema", str(PEER / "config/protocol/protocol-config.xsd"),
            "log-file", str(log_path), "log-level", "1",
        ], output / f"{name}-modem.log")
        await modem.expect("DlepInit succeeded")
        # A show command after peer update forms a CLI processing barrier.
        await modem.command("peer update " + INITIAL + " " + cli_addresses(10))
        await modem.command("show peer")
        await until(lambda: modem.text().count("DlepService returns: ok") >= 2,
                    "LL-DLEP accepting initial peer metrics")
        router = await Process.start(["/work/target/debug/examples/interop_router", endpoint],
                                     output / f"{name}-router.log")
        await router.expect("UP\n")
        await router.expect("METRICS 10000000 20000000 5000000 7000000 2500\n")
        await modem.expect("Peer up,")
        peer_id = re.search(r"Peer up, .*?peer id = ([^\r\n]+)", modem.text()).group(1)
        await modem.command(f"dest up {MAC} " + INITIAL + " " + cli_addresses(20))
        await router.expect("DEST_UP 10000000 20000000 5000000 7000000 2500\n")
        await state(router, 10, None, 20)
        await modem.command(f"dest update {MAC} Current_Data_Rate_Receive 4000000 Latency 3500")
        await router.expect("DEST_UPDATE 10000000 20000000 4000000 7000000 3500\n")
        await modem.command("peer update Current_Data_Rate_Transmit 6000000")
        await router.expect("METRICS 10000000 20000000 5000000 6000000 2500\n")
        await modem.command("peer update " + cli_addresses(10, 0) + " " + cli_addresses(11))
        await router.expect(f"PEER_ADDR {state_addresses(11)}\n")
        await modem.command(f"dest update {MAC} " + cli_addresses(20, 0) + " " + cli_addresses(21))
        await router.expect(f"DEST_ADDR {state_addresses(21)}\n")
        for command, expected in [("session-add", 40), ("session-replace", 41), ("session-clear", None)]:
            after = len(router.text())
            await router.command(command)
            await router.expect(f"OK {command}\n", after)
            await router.expect("SESSION_STATUS 0\n", after)
            await retained_router_addresses(modem, peer_id, expected)
            await state(router, 11, expected, 21)
        await router.command("link")
        await modem.expect("Linkchar request, peer = ")
        assert re.search(r"Linkchar request, peer = ([^,]+),", modem.text()).group(1) == peer_id
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
        await router.command("withdraw")
        await router.expect(f"WITHDRAW {MAC} 0\n")
        # Update the independent modem's retained physical data while withdrawn.
        after = len(modem.text())
        await modem.command(f"dest update {MAC} " + INITIAL.replace("Latency 2500", "Latency 5500"))
        await modem.expect("DlepService returns: ok", after)
        await router.command("announce")
        await router.expect(f"ANNOUNCE {MAC} 0\n")
        await state(router, 11, None, 21)
        # This comes from the modem's stored data, not the requested hints.
        await router.expect("STATE_METRICS 10000000 20000000 5000000 7000000 5500\n")
        await modem.command(f"dest response {UNKNOWN_MAC} Request_Denied")
        # This command has no acknowledgement; a show forms a processing barrier.
        after = len(modem.text())
        await modem.command("show peer")
        await modem.expect("DlepService returns: ok", after)
        await router.command("announce-denied")
        await router.expect(f"ANNOUNCE {UNKNOWN_MAC} 2\n")
        await modem.expect(f"mac = {UNKNOWN_MAC}")
        await state(router, 11, None, 21)
        await modem.command(f"dest update {MAC} " + cli_addresses(21, 0))
        await router.expect("DEST_ADDR - - - -\n")
        await modem.command("peer update " + cli_addresses(11, 0))
        await router.expect("PEER_ADDR - - - -\n")
        await state(router, None, None, None)
        after = len(router.text())
        await modem.command(f"dest down {MAC}")
        await router.expect("DEST_DOWN\n", after)
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
        records = wire_records(output / f"{name}.pcap", 4854, ip_version)
        messages = {role: [m["type"] for m in values] for role, values in records.items()}
        def payloads(role, kind):
            return [address_items(m) for m in records[role] if m["type"] == kind]
        assert payloads("modem", 2) == [expected_addresses(10)]
        assert payloads("modem", 7) == [expected_addresses(20)]
        assert payloads("router", 3) == [expected_addresses(40),
            sorted(expected_addresses(40, 0) + expected_addresses(41)), expected_addresses(41, 0)]
        assert [p for p in payloads("modem", 3) if p] == [
            sorted(expected_addresses(10, 0) + expected_addresses(11)), expected_addresses(11, 0)]
        assert [p for p in payloads("modem", 13) if p] == [
            sorted(expected_addresses(20, 0) + expected_addresses(21)), expected_addresses(21, 0)]
        hints = sorted(expected_addresses(30, subnets=False) + expected_addresses(31, 0, subnets=False))
        assert payloads("router", 9) == [hints, hints]
        assert payloads("modem", 10) == [expected_addresses(21), []]
        responses = [m for m in records["modem"] if m["type"] == 10]
        assert [next(v[0] for k, v in m["items"] if k == 1) for m in responses] == [0, 2]
        # Verify the wire exchange, not just a TCP close retaining the shutdown
        # reason. Type 5 is Termination; type 6 is its required Response.
        responder = "modem" if initiator == "router" else "router"
        assert messages[initiator].count(5) == 1, messages
        assert messages[responder].count(6) == 1, messages
        assert all(types.count(16) >= 2 for types in messages.values()), messages
        peer_log = log_path.read_text()
        return {"ip_version": ip_version, "initiator": initiator, **counts,
                "heartbeats_sent": peer_log.count("Send Heartbeat to peer ID="),
                "heartbeats_received": peer_log.count("handle_heartbeat(): from peer="),
                "wire_messages": messages,
                "address_checks": ["modem initialization IPv4/IPv6 addresses and subnets",
                                   "bidirectional session add/replace/remove",
                                   "destination add/replace/remove",
                                   "Announce hints, successful physical replay and denial"],
                "result": "passed"}
    finally:
        for peer in [router, modem]:
            if peer:
                await peer.close()
        packet_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await packet_task


async def discovery_probe(output, ip_version):
    """Record the pinned peer's incompatible UDP reply ports without a relay."""
    name = f"ipv{ip_version}-discovery"
    address = "192.0.2.1" if ip_version == 4 else "fe80::2"
    group = "224.0.0.117" if ip_version == 4 else "ff02::1:7"
    counts = {"udp_packets": 0, "wrong_ttl": 0}
    tcp_counts = {"tcp_packets": 0, "wrong_ttl": 0}
    tasks = [asyncio.create_task(capture(output / f"{name}.pcap", counts, ip_version,
                                        protocol=17, interface=None, outgoing=True)),
             asyncio.create_task(capture(output / f"{name}-tcp.pcap", tcp_counts, ip_version))]
    await asyncio.sleep(0)
    for task in tasks:
        if task.done():
            task.result()
    modem = router = None
    try:
        modem = await Process.start([
            "/opt/ll-dlep-build/Dlep", "local-type", "modem", "discovery-enable", "1",
            "discovery-iface", "dlep-interop", "discovery-mcast-address", group,
            "discovery-port", "49854", "discovery-ttl", "255",
            "session-address", address, "session-port", "4854", "session-ttl", "255",
            "protocol-config-file", str(output / "core-protocol.xml"),
            "protocol-config-schema", str(PEER / "config/protocol/protocol-config.xsd"),
            "log-file", str(output / f"{name}-peer.log"), "log-level", "1",
        ], output / f"{name}-modem.log")
        await modem.expect("DlepInit succeeded")
        router = await Process.start([
            "/work/target/debug/examples/interop_router", "--discover", address, "dlep-interop",
        ], output / f"{name}-router.log")
        await router.expect("NO_OFFER\n")
        await router.finished()
        assert "UP\n" not in router.text() and "DISCOVERED " not in router.text()
        await modem.command("quit")
        await modem.finished()
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        signals = discovery_records(output / f"{name}.pcap", ip_version)
        exchange = discovery_exchange(signals, address, 4854, legacy_ports=True)
        assert counts["wrong_ttl"] == 0 and tcp_counts["tcp_packets"] == 0
        return {"ip_version": ip_version, "result": "incompatible", **exchange,
                "reason": "Peer Offer sent from an ephemeral port to the discovery port",
                "router_result": "NO_OFFER", **counts, "tcp_packets": tcp_counts["tcp_packets"]}
    finally:
        for peer in [router, modem]:
            if peer:
                await peer.close()
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


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
    for ip_version in [4, 6]:
        for initiator in ["router", "modem"]:
            results.append(await scenario(output, initiator, ip_version))
    probes = [await discovery_probe(output, ip_version) for ip_version in [4, 6]]
    summary = {"peer": "mit-ll/LL-DLEP", "revision": REVISION,
               "transport": "static IPv4/IPv6 TCP, strict GTSM, no TLS", "scenarios": results,
               "discovery_probes": probes}
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
    if pathlib.Path("/proc/sys/net/ipv6/conf/lo/hop_limit").read_text().strip() != "255":
        parser.error("the container's loopback hop limit must be 255 for the IPv6 TCP handshake")
    if pathlib.Path("/proc/sys/net/ipv6/conf/lo/disable_ipv6").read_text().strip() != "0":
        parser.error("IPv6 must be enabled on the container's loopback interface")
    # Pinned LL-DLEP rejects non-link-local IPv6 session addresses. This runs
    # only after the networkless-container check, never on a host interface.
    subprocess.run(["ip", "-6", "addr", "replace", "fe80::1/64", "dev", "lo", "nodad"], check=True)
    # A disposable multicast-capable interface exercises real discovery egress.
    for command in [
        ["link", "add", "dlep-interop", "type", "dummy"],
        ["addr", "add", "192.0.2.1/24", "dev", "dlep-interop"],
        ["link", "set", "dlep-interop", "up", "multicast", "on"],
        ["-6", "addr", "add", "fe80::2/64", "dev", "dlep-interop", "nodad"],
    ]:
        subprocess.run(["ip", *command], check=True)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").unlink(missing_ok=True)
    asyncio.run(run(args.output))


if __name__ == "__main__":
    main()
