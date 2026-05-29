import asyncio
import socket
import struct
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log


class DNSLeakPreventer:
    """
    Detects plaintext DNS traffic leaving outside the expected resolver.
    Emits SUSPICIOUS events visible in the Events tab when a leak is found.
    Does NOT modify /etc/resolv.conf or apply firewall rules — those require
    explicit user action from the Firewall tab.
    """

    def __init__(self, doh_proxy_port: int = 5053):
        self.doh_proxy_port = doh_proxy_port
        self._task: asyncio.Task | None = None
        self._bus = None
        self._warned: set[str] = set()

    async def start(self, bus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _monitor(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                leaks = await asyncio.to_thread(self._find_leaks)
                for ip in leaks:
                    if ip not in self._warned:
                        self._warned.add(ip)
                        await self._bus.emit(Event(
                            type=EventType.DNS_SPOOF,
                            level=ThreatLevel.SUSPICIOUS,
                            message=f"DNS leak: plaintext DNS query to {ip} "
                                    f"(outside VPN tunnel) — consider blocking port 53",
                            data={"ip": ip},
                        ))
            except Exception as exc:
                log.warning(f"DNSLeakPreventer check error: {exc}")

    def _find_leaks(self) -> list[str]:
        leaking = []
        try:
            with open("/proc/net/udp") as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 3:
                    continue
                rem_ip_hex, rem_port_hex = parts[2].split(":")
                if int(rem_port_hex, 16) != 53:
                    continue
                rem_ip = socket.inet_ntoa(struct.pack("<I", int(rem_ip_hex, 16)))
                if (not rem_ip.startswith("127.")
                        and not rem_ip.startswith("10.")
                        and rem_ip != "0.0.0.0"):
                    leaking.append(rem_ip)
        except Exception:
            pass
        return leaking
