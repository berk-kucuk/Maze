from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable


class ThreatLevel(Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class EventType(Enum):
    ARP_SPOOF      = "arp_spoof"
    ROGUE_AP       = "rogue_ap"
    DNS_SPOOF      = "dns_spoof"
    TLS_CHANGE     = "tls_change"
    SSL_STRIP      = "ssl_strip"
    PORT_SCAN      = "port_scan"
    UNKNOWN_PROCESS= "unknown_process"
    DNS_LEAK       = "dns_leak"
    MAC_CHANGED    = "mac_changed"
    PROFILE_CHANGED= "profile_changed"
    DEVICE_FOUND   = "device_found"
    MODULE_TOGGLED = "module_toggled"
    ENGINE_READY   = "engine_ready"
    RECON_RESULT   = "recon_result"


@dataclass
class Event:
    type: EventType
    level: ThreatLevel
    message: str
    data: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


class EventBus:
    def __init__(self):
        self._listeners: dict[EventType, list[Callable]] = {}
        self._catch_all: list[Callable] = []

    def subscribe(self, event_type: EventType, callback: Callable) -> None:
        self._listeners.setdefault(event_type, []).append(callback)

    def subscribe_all(self, callback: Callable) -> None:
        self._catch_all.append(callback)

    async def emit(self, event: Event) -> None:
        for cb in self._listeners.get(event.type, []):
            await cb(event)
        for cb in self._catch_all:
            await cb(event)
