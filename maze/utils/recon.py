"""
Passive IP reconnaissance — triggered automatically on DANGEROUS events.
Gathers: reverse DNS, MAC+vendor, open ports, service banners, OS hint.
"""
import asyncio
import re
import socket
import subprocess
from dataclasses import dataclass, field

_LLADDR_RE = re.compile(r'lladdr\s+([0-9a-f:]{17})')

_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    1883, 2375, 3306, 3389, 4444, 5432, 5900, 6379,
    8080, 8443, 9200, 27017,
]
_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    1883: "MQTT", 2375: "Docker", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit?", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

# OUI prefix → vendor. All keys: uppercase hex, no colons, exactly 6 chars (3 octets).
# Exception: "0242" (4 chars) for Docker's 2-octet prefix 02:42:xx:xx:xx:xx.
_OUI: dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox (host-only)",
    "525400": "QEMU/KVM", "525401": "QEMU/KVM",
    "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "DC2B61": "Raspberry Pi",
    "0242":   "Docker",  # 2-octet prefix match
}


@dataclass
class ReconResult:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)
    os_hint: str = ""


async def recon_ip(ip: str, port_timeout: float = 1.5) -> ReconResult:
    result = ReconResult(ip=ip)

    hostname, ports, os_hint, mac = await asyncio.gather(
        _reverse_dns(ip),
        _scan_ports(ip, port_timeout),
        _guess_os(ip),
        _get_mac(ip),
        return_exceptions=True,
    )

    if isinstance(hostname, str):
        result.hostname = hostname
    if isinstance(ports, list):
        result.open_ports = ports
    if isinstance(os_hint, str):
        result.os_hint = os_hint
    if isinstance(mac, str) and mac:
        result.mac = mac
        result.vendor = _oui_lookup(mac)

    # Banner grab only for open ports where banners are meaningful
    if isinstance(ports, list) and ports:
        grab_ports = [p for p, _ in ports if p in (21, 22, 80, 8080, 23, 25)]
        if grab_ports:
            banner_results = await asyncio.gather(
                *[_banner_grab(ip, p, 2.0) for p in grab_ports],
                return_exceptions=True,
            )
            for port, banner in zip(grab_ports, banner_results):
                if isinstance(banner, str) and banner:
                    result.banners[port] = banner

    return result


async def _reverse_dns(ip: str) -> str:
    try:
        loop = asyncio.get_event_loop()
        info = await loop.run_in_executor(
            None, lambda: socket.getnameinfo((ip, 0), 0)
        )
        hostname = info[0]
        return hostname if hostname != ip else ""
    except Exception:
        return ""


async def _get_mac(ip: str) -> str:
    try:
        out = await asyncio.to_thread(
            subprocess.check_output, ["ip", "neigh", "show", ip], text=True
        )
        m = _LLADDR_RE.search(out)
        return m.group(1) if m else ""
    except Exception:
        return ""


def _oui_lookup(mac: str) -> str:
    clean = mac.replace(":", "").upper()
    # Full 3-octet OUI first, then 2-octet prefix fallback (Docker)
    return _OUI.get(clean[:6]) or _OUI.get(clean[:4]) or ""


async def _scan_ports(ip: str, timeout: float) -> list[tuple[int, str]]:
    tasks = [_check_port(ip, p, timeout) for p in _COMMON_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [
        (p, _PORT_NAMES.get(p, "?"))
        for p, r in zip(_COMMON_PORTS, results)
        if r is True
    ]


async def _check_port(ip: str, port: int, timeout: float) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def _banner_grab(ip: str, port: int, timeout: float) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        banner = ""
        if port in (21, 22, 23, 25):
            # These protocols send banners on connect
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
            banner = data.decode(errors="replace").split("\n")[0].strip()[:80]
        elif port in (80, 8080):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            for line in data.decode(errors="replace").splitlines():
                if line.lower().startswith("server:"):
                    banner = line[7:].strip()[:80]
                    break
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner
    except Exception:
        return ""


async def _guess_os(ip: str) -> str:
    try:
        r = await asyncio.to_thread(
            subprocess.run,
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0:
            m = re.search(r"ttl=(\d+)", r.stdout.lower())
            if m:
                ttl = int(m.group(1))
                if ttl <= 64:  return "Linux / Unix"
                if ttl <= 128: return "Windows"
                return "Network device"
    except Exception:
        pass
    return ""


def format_recon(result: ReconResult) -> str:
    parts = [f"Recon: {result.ip}"]
    if result.mac:
        mac_str = result.mac
        if result.vendor:
            mac_str += f" ({result.vendor})"
        parts.append(f"mac={mac_str}")
    if result.hostname:
        parts.append(f"hostname={result.hostname}")
    if result.os_hint:
        parts.append(f"os={result.os_hint}")
    if result.open_ports:
        ports_str = ", ".join(f"{p}/{n}" for p, n in result.open_ports[:8])
        parts.append(f"open_ports=[{ports_str}]")
    if result.banners:
        banner_parts = [f"{p}:{b}" for p, b in list(result.banners.items())[:3]]
        parts.append(f"banners=[{'; '.join(banner_parts)}]")
    return " | ".join(parts)
