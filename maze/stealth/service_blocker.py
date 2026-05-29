import asyncio
import subprocess
from maze.utils.logger import log

# Imported lazily to avoid circular import at module load time
_INIT_RULESET: str | None = None


def _ensure_ruleset() -> None:
    global _INIT_RULESET
    if _INIT_RULESET is None:
        from maze.protection.firewall import _INIT_RULESET as rs
        _INIT_RULESET = rs

    # Check if the maze_firewall table already exists
    r = subprocess.run(
        ["nft", "list", "table", "inet", "maze_firewall"],
        capture_output=True,
    )
    if r.returncode != 0:
        # Table missing — initialize it
        subprocess.run(
            ["nft", "-f", "-"],
            input=_INIT_RULESET, text=True, capture_output=True,
        )


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
        _ensure_ruleset()
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
