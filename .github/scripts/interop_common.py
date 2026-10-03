"""Bounded waits and isolated loopback packet capture for peer checks."""
import asyncio
import socket
import struct
import time


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


