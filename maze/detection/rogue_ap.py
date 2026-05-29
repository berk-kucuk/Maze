import asyncio
import os
import subprocess
from maze.core.events import Event, EventBus, EventType, ThreatLevel


def _is_wireless(interface: str) -> bool:
    return os.path.exists(f"/sys/class/net/{interface}/wireless")


class RogueAPDetector:
    def __init__(self, interface: str):
        self.interface = interface
        self._is_wifi = _is_wireless(interface)
        self._known_bssid: str | None = None
        self._known_ssid: str | None = None
        self._redirects_warned = False
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        if self._is_wifi:
            self._known_ssid, self._known_bssid = await asyncio.to_thread(
                self._current_ap
            )
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    def _current_ap(self) -> tuple[str | None, str | None]:
        try:
            ssid = subprocess.check_output(
                ["iwgetid", self.interface, "--raw"], text=True
            ).strip() or None
            bssid = subprocess.check_output(
                ["iwgetid", self.interface, "--ap", "--raw"], text=True
            ).strip() or None
            return ssid, bssid
        except Exception:
            return None, None

    async def _monitor(self) -> None:
        # One-time ICMP redirect check (both WiFi and Ethernet)
        await self._check_icmp_redirects()
        while True:
            await asyncio.sleep(15)
            if self._is_wifi:
                ssid, bssid = await asyncio.to_thread(self._current_ap)
                if ssid and ssid == self._known_ssid and bssid != self._known_bssid:
                    await self._bus.emit(Event(
                        type=EventType.ROGUE_AP,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Evil Twin AP detected: '{ssid}' BSSID changed "
                                f"({self._known_bssid} → {bssid})",
                        data={"ssid": ssid,
                              "old_bssid": self._known_bssid,
                              "new_bssid": bssid},
                    ))

    async def _check_icmp_redirects(self) -> None:
        """Alert if ICMP redirect acceptance is enabled on a wireless interface.

        ICMP redirect attacks require a rogue device on the same L2 segment and
        are only practically exploitable on shared wireless networks. On wired
        home connections the router itself may legitimately send redirects, so
        warning there produces constant false positives with no security value.
        """
        if not self._is_wifi:
            return
        try:
            path = f"/proc/sys/net/ipv4/conf/{self.interface}/accept_redirects"
            val = await asyncio.to_thread(lambda: open(path).read().strip())
            if val == "1" and not self._redirects_warned:
                self._redirects_warned = True
                await self._bus.emit(Event(
                    type=EventType.ROGUE_AP,
                    level=ThreatLevel.SUSPICIOUS,
                    message=f"ICMP redirect acceptance enabled on {self.interface} — "
                            f"an attacker on the network can reroute your traffic",
                    data={"interface": self.interface},
                ))
        except Exception:
            pass
