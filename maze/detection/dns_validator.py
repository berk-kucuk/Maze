import asyncio
import httpx
from maze.core.events import Event, EventBus, EventType, ThreatLevel

DOH_RESOLVERS = {
    "cloudflare": "https://cloudflare-dns.com/dns-query",
    "google":     "https://dns.google/dns-query",
    "quad9":      "https://dns.quad9.net/dns-query",
}

# Domains periodically cross-validated across all three resolvers.
# Disagreement between resolvers indicates possible DNS poisoning.
_CANARY_DOMAINS = ["google.com", "cloudflare.com", "github.com"]


class DNSValidator:
    def __init__(self):
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _monitor(self) -> None:
        await asyncio.sleep(30)  # let network settle before first check
        while True:
            for domain in _CANARY_DOMAINS:
                try:
                    await self.validate(domain)
                except Exception:
                    pass
            await asyncio.sleep(120)

    async def validate(self, domain: str) -> bool:
        results = await asyncio.gather(*[
            self._doh_resolve(name, url, domain)
            for name, url in DOH_RESOLVERS.items()
        ], return_exceptions=True)

        valid = [r for r in results if isinstance(r, set) and r]
        if len(valid) < 2:
            return True

        if not all(v == valid[0] for v in valid):
            await self._bus.emit(Event(
                type=EventType.DNS_SPOOF,
                level=ThreatLevel.SUSPICIOUS,
                message=f"DNS spoofing suspected: resolvers disagree on '{domain}'",
                data={"domain": domain,
                      "results": {k: list(v)
                                  for k, v in zip(DOH_RESOLVERS, valid)}},
            ))
            return False
        return True

    async def _doh_resolve(self, name: str, url: str, domain: str) -> set[str]:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                url,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            data = resp.json()
            return {r["data"] for r in data.get("Answer", []) if r["type"] == 1}
