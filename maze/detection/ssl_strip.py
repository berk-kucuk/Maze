import asyncio
import httpx
from maze.core.events import Event, EventBus, EventType, ThreatLevel


class SSLStripDetector:
    def __init__(self):
        self._bus: EventBus | None = None
        self._checked: set[str] = set()  # deduplicate per session

    async def start(self, bus: EventBus) -> None:
        self._bus = bus

    async def stop(self) -> None:
        pass

    async def check(self, url: str) -> None:
        """
        Check if a host reachable via HTTP also supports HTTPS.
        Only fires if the host was known-HTTPS (cert store) and is now
        serving HTTP — call this from engine when that condition is met.
        """
        if not url.startswith("http://"):
            return
        hostname = url.split("/")[2]
        if hostname in self._checked:
            return
        self._checked.add(hostname)

        https_url = f"https://{hostname}"
        try:
            async with httpx.AsyncClient(follow_redirects=False) as client:
                resp = await client.get(https_url, timeout=5)
                if resp.status_code in (200, 301, 302):
                    await self._bus.emit(Event(
                        type=EventType.SSL_STRIP,
                        level=ThreatLevel.DANGEROUS,
                        message=f"SSL Strip detected: {hostname} supports HTTPS "
                                f"but HTTP response received — possible MITM",
                        data={"hostname": hostname},
                    ))
        except Exception:
            pass
