#!/usr/bin/env python3
"""Exercise our modem against a pinned, unmodified dlepard router.

Run in test-network.sh's disposable namespace with ip_default_ttl=255.
Only the upstream session/codec modules are used; no REST service is needed.
"""
import argparse
import asyncio
import contextlib
import json
import logging
import os
import pathlib
import subprocess
import sys

from interop_common import capture, until

REVISION = "9300773a566290897839b845c4ec9f2feba3e93b"


class Heartbeats(logging.Handler):
    def __init__(self):
        super().__init__()
        self.sent = 0
        self.received = 0

    def emit(self, record):
        message = record.getMessage()
        self.sent += message == "sending Heartbeat"
        self.received += message == "-> received Heartbeat Message"


async def scenario(args, initiator):
    from dlepard.dlepsession import DLEPSession, DlepSessionState

    lines = []
    counts = {"tcp_packets": 0, "wrong_ttl": 0}
    capture_task = asyncio.create_task(capture(args.output / f"{initiator}.pcap", counts))
    await asyncio.sleep(0)  # Bind the capture socket before either peer starts.
    if capture_task.done():
        capture_task.result()
    stderr = (args.output / f"{initiator}-modem.stderr").open("w")
    process = await asyncio.create_subprocess_exec(
        str(args.modem), stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=stderr,
    )
    session = None
    beats = Heartbeats()
    logging.getLogger("DLEPard").addHandler(beats)

    async def read_output():
        with (args.output / f"{initiator}-modem.stdout").open("w") as output:
            async for line in process.stdout:
                line = line.decode().strip()
                lines.append(line)
                output.write(line + "\n")
                output.flush()

    reader = asyncio.create_task(read_output())

    async def command(name):
        process.stdin.write((name + "\n").encode())
        await process.stdin.drain()
        if name != "shutdown":
            await until(lambda: f"OK {name}" in lines, f"modem accepting {name}")

    try:
        await until(lambda: any(line.startswith("READY ") for line in lines), "modem listener")
        endpoint = next(line.split()[1] for line in lines if line.startswith("READY "))
        host, port = endpoint.rsplit(":", 1)
        session = DLEPSession({
            "local_ipv4addr": ["127.0.0.1"],
            "discovery": {"disabled": True},
            "tcp": {"127.0.0.1": {"ipv4addr": host, "port": int(port)}},
            "heartbeat_interval_ms": 6000,
            "enable_lid_ext": False,
        }, "127.0.0.1", loop=asyncio.get_running_loop())
        await session.start()
        await until(lambda: session.state == DlepSessionState.IN_SESSION_STATE and "UP" in lines,
                    "both peers completing initialization")
        peer = session.peer_information_base
        assert (peer.max_datarate_rx, peer.max_datarate_tx, peer.curr_datarate_rx,
                peer.curr_datarate_tx, peer.latency) == (10_000_000, 20_000_000, 5_000_000, 7_000_000, 2500)
        assert session.peer_heartbeat == 1000

        await command("add")
        await until(lambda: len(session.destination_information_base) == 1, "Destination Up")
        destination = session.destination_information_base[0]
        assert destination.mac_address.lower() == "02:00:00:00:00:01"
        assert (destination.curr_datarate_rx, destination.curr_datarate_tx, destination.latency) == (4_000_000, 6_000_000, 3500)
        # Wait for independent router heartbeats, allowing its Up response to
        # complete the transaction before asking the modem for an update.
        await until(lambda: beats.sent > 0 and beats.received > 0, "bidirectional heartbeats")
        assert session.state == DlepSessionState.IN_SESSION_STATE
        assert not any(line.startswith("DOWN ") for line in lines)
        await command("update")
        await until(lambda: session.destination_information_base[0].curr_datarate_rx == 2_000_000,
                    "Destination Update")
        destination = session.destination_information_base[0]
        assert (destination.curr_datarate_tx, destination.latency) == (3_000_000, 4500)
        await command("drop")
        await until(lambda: not session.destination_information_base, "Destination Down")
        if initiator == "router":
            session.enter_session_termination_state()
            await until(lambda: "DOWN 132" in lines, "router-initiated termination")
            await until(lambda: session.state == DlepSessionState.PEER_DISCOVERY_STATE,
                        "independent router receiving termination response")
        await command("shutdown")
        await asyncio.wait_for(process.wait(), 10)
        await reader
        assert process.returncode == 0, lines
        assert lines.count("UP") == 1, lines
        expected_down = "DOWN 132" if initiator == "router" else "DOWN 255"
        assert [line for line in lines if line.startswith("DOWN ")] == [expected_down], lines
        assert "STOPPED" in lines, lines
        assert session.state == DlepSessionState.PEER_DISCOVERY_STATE
        assert counts["tcp_packets"] > 0 and counts["wrong_ttl"] == 0, counts
        return {"initiator": initiator, "heartbeats_sent": beats.sent,
                "heartbeats_received": beats.received, **counts, "result": "passed"}
    finally:
        logging.getLogger("DLEPard").removeHandler(beats)
        if session:
            for timer in [session.heartbeat_timer, session.heartbeat_watchdog]:
                if timer:
                    timer.stop()
            if session.tcp_proxy and session.tcp_proxy.transport:
                session.tcp_proxy.transport.close()
        if process.returncode is None:
            process.kill()
            await process.wait()
        await reader
        stderr.close()
        capture_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await capture_task


async def run(args):
    errors = []
    loop = asyncio.get_running_loop()

    def failed_callback(event_loop, context):
        errors.append(context)
        event_loop.default_exception_handler(context)

    loop.set_exception_handler(failed_callback)
    results = []
    for initiator in ["modem", "router"]:
        results.append(await scenario(args, initiator))
    assert not errors, f"independent peer raised asynchronous errors: {errors}"
    report = {"peer": "Rohde-Schwarz/dlepard", "revision": REVISION,
              "transport": "static IPv4 TCP, strict GTSM, no TLS", "scenarios": results}
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer-source", required=True, type=pathlib.Path)
    parser.add_argument("--modem", type=pathlib.Path, default=pathlib.Path("target/debug/examples/interop_modem"))
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("target/interop-dlepard"))
    args = parser.parse_args()
    args.peer_source = args.peer_source.resolve()
    args.modem = args.modem.resolve()
    # CI checks out as the runner user and executes networking as root. Scope
    # this read-only ownership exception to this explicit peer checkout.
    git = ["git", "-c", f"safe.directory={args.peer_source}", "-C", str(args.peer_source)]
    revision = subprocess.check_output([*git, "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output([*git, "status", "--porcelain", "--untracked-files=no"], text=True)
    if revision != REVISION or dirty:
        parser.error(f"peer source must be clean at {REVISION}")
    parent_netns = os.environ.get("DLEP_INTEROP_PARENT_NETNS")
    if not parent_netns or os.readlink("/proc/self/ns/net") == parent_netns:
        parser.error("run in a disposable network namespace using interop-dlepard.sh")
    if pathlib.Path("/proc/sys/net/ipv4/ip_default_ttl").read_text().strip() != "255":
        parser.error("set net.ipv4.ip_default_ttl=255 inside the disposable namespace")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "summary.json").unlink(missing_ok=True)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.peer_source / "src"))
    logging.basicConfig(filename=args.output / "router.log", filemode="w", level=logging.DEBUG)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
