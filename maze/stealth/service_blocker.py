import asyncio
import subprocess
from maze.utils.logger import log


class ServiceBlocker:
    """Block mDNS/NetBIOS broadcast leaks through the Maze firewall table."""

    _PORTS = [("udp", 5353), ("udp", 137), ("udp", 138)]

    def __init__(self):
        self._active = False

    async def start(self, bus) -> None:
        await asyncio.to_thread(self._apply)

    async def stop(self) -> None:
        await asyncio.to_thread(self._remove)

    def _apply(self) -> None:
        for proto, port in self._PORTS:
            r = subprocess.run(
                ["nft", "add", "element", "inet", "maze_firewall",
                 f"blocked_ports_{proto}", "{", str(port), "}"],
                capture_output=True, check=False,
            )
            if r.returncode != 0:
                log.warning(f"ServiceBlocker: could not block {proto}/{port}: {r.stderr.strip()}")
        self._active = True

    def _remove(self) -> None:
        for proto, port in self._PORTS:
            subprocess.run(
                ["nft", "delete", "element", "inet", "maze_firewall",
                 f"blocked_ports_{proto}", "{", str(port), "}"],
                capture_output=True, check=False,
            )
        self._active = False
