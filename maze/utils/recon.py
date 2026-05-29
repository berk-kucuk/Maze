"""
Passive IP reconnaissance — triggered automatically on DANGEROUS events.
Uses only Python stdlib + ping; no nmap dependency.
"""
import asyncio
import re
import socket
import subprocess
from dataclasses import dataclass, field

_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 3306, 3389, 5432, 6379, 8080, 8443, 27017]
_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}


@dataclass
class ReconResult:
    ip: str
    hostname: str = ""
    open_ports: list[tuple[int, str]] = field(default_factory=list)
    os_hint: str = ""


async def recon_ip(ip: str, port_timeout: float = 1.5) -> ReconResult:
    result = ReconResult(ip=ip)

    hostname, ports, os_hint = await asyncio.gather(
        _reverse_dns(ip),
        _scan_ports(ip, port_timeout),
        _guess_os(ip),
        return_exceptions=True,
    )

    if isinstance(hostname, str): result.hostname = hostname
    if isinstance(ports, list):   result.open_ports = ports
    if isinstance(os_hint, str):  result.os_hint = os_hint

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
    if result.hostname:
        parts.append(f"hostname={result.hostname}")
    if result.os_hint:
        parts.append(f"os={result.os_hint}")
    if result.open_ports:
        ports_str = ", ".join(f"{p}/{n}" for p, n in result.open_ports[:8])
        parts.append(f"open_ports=[{ports_str}]")
    return " | ".join(parts)
