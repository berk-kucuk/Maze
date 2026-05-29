import asyncio
import re
import subprocess
from datetime import datetime
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log

_GW_IP_RE   = re.compile(r'default via (\S+)')
_LLADDR_RE  = re.compile(r'lladdr\s+([0-9a-f:]{17})')


def _get_gateway_info() -> tuple[str | None, str | None]:
    """Return (gateway_ip, gateway_mac) using ip-route and ip-neigh."""
    try:
        route = subprocess.check_output(['ip', 'route'], text=True)
        m = _GW_IP_RE.search(route)
        if not m:
            return None, None
        gw_ip = m.group(1)
        neigh = subprocess.check_output(['ip', 'neigh', 'show', gw_ip], text=True)
        mac_m = _LLADDR_RE.search(neigh)
        return gw_ip, mac_m.group(1) if mac_m else None
    except Exception:
        return None, None


class ARPWatcher:
    def __init__(self, interface: str, whitelist: list[str] | None = None):
        self.interface = interface
        self._whitelist = set(whitelist or [])
        self.devices: dict[str, dict] = {}
        self._arp_table: dict[str, str] = {}
        self._gw_ip: str | None = None
        self._gw_mac: str | None = None
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._gw_task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._loop = asyncio.get_event_loop()
        self._gw_ip, self._gw_mac = await asyncio.to_thread(_get_gateway_info)
        if helper and helper.is_connected():
            helper.on_event(self._on_helper_event)
        else:
            self._task = asyncio.create_task(self._run_direct())
            log.warning("ARPWatcher: helper unavailable, trying direct sniff")
        self._gw_task = asyncio.create_task(self._monitor_gateway())

    async def stop(self) -> None:
        for t in (self._task, self._gw_task):
            if t:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    async def _on_helper_event(self, msg: dict) -> None:
        if msg.get("event") == "arp":
            self._process(msg["src"], msg["mac"])

    async def _run_direct(self) -> None:
        try:
            await asyncio.get_event_loop().run_in_executor(None, self._sniff)
        except Exception as e:
            log.warning(f"ARPWatcher sniff error: {e}")

    def _sniff(self) -> None:
        from scapy.all import ARP, sniff
        sniff(
            iface=self.interface, filter="arp",
            prn=lambda p: self._process(p[ARP].psrc, p[ARP].hwsrc)
                          if p.haslayer(ARP) and p[ARP].op == 2 else None,
            store=False,
            stop_filter=lambda _: self._task and self._task.cancelled(),
        )

    def _process(self, ip: str, mac: str) -> None:
        if ip in self._whitelist:
            return
        if ip not in self.devices:
            self.devices[ip] = {"mac": mac, "first_seen": datetime.now()}
            asyncio.run_coroutine_threadsafe(
                self._bus.emit(Event(
                    type=EventType.DEVICE_FOUND, level=ThreatLevel.SAFE,
                    message=f"New device: {ip} ({mac})",
                    data={"ip": ip, "mac": mac},
                )), self._loop)
        elif self._arp_table.get(ip) and self._arp_table[ip] != mac:
            asyncio.run_coroutine_threadsafe(
                self._bus.emit(Event(
                    type=EventType.ARP_SPOOF, level=ThreatLevel.DANGEROUS,
                    message=f"ARP spoofing: {ip} changed MAC from "
                            f"{self._arp_table[ip]} to {mac} — possible MITM",
                    data={"ip": ip, "old_mac": self._arp_table[ip], "new_mac": mac},
                )), self._loop)
            self.devices[ip]["mac"] = mac
        self._arp_table[ip] = mac

    async def _monitor_gateway(self) -> None:
        """Periodically verify default gateway IP and MAC — early MITM indicator."""
        while True:
            await asyncio.sleep(20)
            try:
                gw_ip, gw_mac = await asyncio.to_thread(_get_gateway_info)
                if not gw_ip:
                    continue
                if self._gw_ip is None:
                    self._gw_ip, self._gw_mac = gw_ip, gw_mac
                    continue
                if gw_ip != self._gw_ip:
                    await self._bus.emit(Event(
                        type=EventType.ARP_SPOOF,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Default gateway changed: {self._gw_ip} → {gw_ip} — possible MITM",
                        data={"ip": gw_ip, "old_ip": self._gw_ip},
                    ))
                    self._gw_ip, self._gw_mac = gw_ip, gw_mac
                elif gw_mac and gw_mac != self._gw_mac:
                    await self._bus.emit(Event(
                        type=EventType.ARP_SPOOF,
                        level=ThreatLevel.DANGEROUS,
                        message=f"Gateway MAC changed: {self._gw_ip} "
                                f"({self._gw_mac} → {gw_mac}) — possible MITM",
                        data={"ip": gw_ip, "old_mac": self._gw_mac, "new_mac": gw_mac},
                    ))
                    self._gw_mac = gw_mac
            except Exception:
                pass
