import asyncio
import hashlib
import ssl
import socket
from maze.core.events import Event, EventBus, EventType, ThreatLevel

# Hosts whose TLS certs are monitored as MITM canaries.
# If a cert hash changes between checks, someone is intercepting HTTPS.
_CANARY_HOSTS = ["google.com", "cloudflare.com", "github.com"]


class TLSMonitor:
    def __init__(self):
        self._cert_store: dict[str, str] = {}
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def _monitor(self) -> None:
        # Seed cert hashes silently (no alerts on first run)
        for host in _CANARY_HOSTS:
            h = await asyncio.to_thread(self._get_cert_hash, host, 443)
            if h:
                self._cert_store[host] = h
        # Periodic checks — alert only if hash changes
        while True:
            await asyncio.sleep(300)
            for host in _CANARY_HOSTS:
                await self.check(host)

    async def check(self, hostname: str, port: int = 443) -> None:
        cert_hash = await asyncio.to_thread(self._get_cert_hash, hostname, port)
        if cert_hash is None:
            return
        known = self._cert_store.get(hostname)
        if known and known != cert_hash:
            await self._bus.emit(Event(
                type=EventType.TLS_CHANGE,
                level=ThreatLevel.SUSPICIOUS,
                message=f"TLS certificate changed for {hostname} — possible MITM",
                data={"hostname": hostname, "old": known, "new": cert_hash},
            ))
        self._cert_store[hostname] = cert_hash

    def _get_cert_hash(self, hostname: str, port: int) -> str | None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return hashlib.sha256(der).hexdigest()
        except Exception:
            return None
