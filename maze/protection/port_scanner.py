import asyncio
from collections import defaultdict
from maze.core.events import Event, EventBus, EventType, ThreatLevel
from maze.utils.logger import log


class PortScanDetector:
    def __init__(self, interface: str, threshold: int = 10,
                 whitelist: list[str] | None = None):
        self.interface = interface
        self.threshold = threshold
        self._whitelist = set(whitelist or [])
        self._syn_count: dict[str, int] = defaultdict(int)
        self._blocked: set[str] = set()
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._helper = None

    @property
    def blocked_ips(self) -> set[str]:
        return self._blocked

    @property
    def scan_attempts(self) -> dict[str, int]:
        return dict(self._syn_count)

    async def start(self, bus: EventBus, helper=None) -> None:
        self._bus = bus
        self._loop = asyncio.get_event_loop()
        self._helper = helper
        if helper and helper.is_connected():
            helper.on_event(self._on_helper_event)
        else:
            self._task = asyncio.create_task(self._run_direct())
            log.warning("PortScanDetector: helper unavailable, trying direct sniff")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _on_helper_event(self, msg: dict) -> None:
        if msg.get("event") == "syn":
            await self._process(msg["src"])

    async def _run_direct(self) -> None:
        try:
            from scapy.all import TCP, sniff
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sniff(
                    iface=self.interface,
                    filter="tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0",
                    prn=lambda p: asyncio.run_coroutine_threadsafe(
                        self._process(p["IP"].src if p.haslayer("IP") else None),
                        self._loop,
                    ),
                    store=False,
                ),
            )
        except Exception as e:
            log.warning(f"PortScanDetector sniff error: {e}")

    async def _process(self, src: str | None) -> None:
        if not src:
            return
        if src in self._whitelist:
            return
        self._syn_count[src] += 1
        count = self._syn_count[src]

        if count == self.threshold:
            await self._bus.emit(Event(
                type=EventType.PORT_SCAN,
                level=ThreatLevel.SUSPICIOUS,
                message=f"Port scan detected from {src} ({count} SYN packets)",
                data={"src": src, "syn_count": count},
            ))
        elif count == self.threshold * 3:
            await self._bus.emit(Event(
                type=EventType.PORT_SCAN,
                level=ThreatLevel.DANGEROUS,
                message=f"Port scan attack from {src} ({count} SYN packets) — right-click to block",
                data={"src": src, "syn_count": count},
            ))
