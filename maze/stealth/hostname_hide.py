import asyncio
import subprocess
from pathlib import Path

_STATE_FILE = Path("/tmp/maze-hostname-state")


class HostnameHider:
    def __init__(self):
        self._mdns_was_running = False

    async def start(self, bus) -> None:
        await asyncio.to_thread(self._disable)

    async def stop(self) -> None:
        await asyncio.to_thread(self._restore)

    def _disable(self) -> None:
        result = subprocess.run(
            ["systemctl", "is-active", "avahi-daemon"],
            capture_output=True, text=True,
        )
        self._mdns_was_running = result.stdout.strip() == "active"
        # Persist state so crash recovery works
        _STATE_FILE.write_text("1" if self._mdns_was_running else "0")

        if self._mdns_was_running:
            subprocess.run(["systemctl", "stop", "avahi-daemon"],
                           check=False, capture_output=True)

    def _restore(self) -> None:
        was_running = self._mdns_was_running
        # Also check persisted state (handles crash recovery)
        if _STATE_FILE.exists():
            was_running = was_running or _STATE_FILE.read_text().strip() == "1"
            _STATE_FILE.unlink(missing_ok=True)

        if was_running:
            subprocess.run(["systemctl", "start", "avahi-daemon"],
                           check=False, capture_output=True)
        self._mdns_was_running = False
