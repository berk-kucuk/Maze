"""
Passive IP reconnaissance — triggered automatically on DANGEROUS events.
Gathers: reverse DNS, MAC+vendor, open ports, service banners, OS fingerprint.
"""
import asyncio
import re
import socket
import struct
import subprocess
from dataclasses import dataclass, field

_LLADDR_RE = re.compile(r'lladdr\s+([0-9a-f:]{17})')

_COMMON_PORTS = [
    # Standard services
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    # Apple / macOS
    548, 631,
    # IoT / embedded
    1883, 2375,
    # Databases
    3306, 3389, 5432, 6379, 9200, 27017,
    # Attack / backdoor indicators
    4444, 5900,
    # Android ADB
    5555,
    # HTTP alt
    8080, 8443,
    # iOS lockdownd
    62078,
]
_PORT_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 548: "AFP", 631: "IPP/CUPS",
    1883: "MQTT", 2375: "Docker", 3306: "MySQL", 3389: "RDP",
    4444: "Metasploit?", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    9200: "Elasticsearch", 27017: "MongoDB", 62078: "iOS/lockdownd",
}

# OUI prefix → vendor. All keys: uppercase hex, no colons, exactly 6 chars.
# Exception: "0242" (4 chars) for Docker's 2-octet prefix 02:42:xx:xx:xx:xx.
_OUI: dict[str, str] = {
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox (host-only)",
    "525400": "QEMU/KVM", "525401": "QEMU/KVM",
    "DCA632": "Raspberry Pi", "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi", "DC2B61": "Raspberry Pi",
    "0242":   "Docker",
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
    netbios_name: str = ""


async def recon_ip(ip: str, port_timeout: float = 1.5) -> ReconResult:
    result = ReconResult(ip=ip)

    hostname, ports, ttl_hint, mac, netbios = await asyncio.gather(
        _reverse_dns(ip),
        _scan_ports(ip, port_timeout),
        _guess_os_ttl(ip),
        _get_mac(ip),
        _netbios_query(ip),
        return_exceptions=True,
    )

    if isinstance(hostname, str):
        result.hostname = hostname
    if isinstance(ports, list):
        result.open_ports = ports
    if isinstance(mac, str) and mac:
        result.mac = mac
        result.vendor = _oui_lookup(mac)
    if isinstance(netbios, str) and netbios:
        result.netbios_name = netbios

    # Enrich OS guess: combine TTL hint + port profile
    base_hint = ttl_hint if isinstance(ttl_hint, str) else ""
    port_nums = {p for p, _ in result.open_ports}
    result.os_hint = _enrich_os(base_hint, port_nums)

    # Banner grab for open ports with meaningful banners
    if result.open_ports:
        grab_ports = [p for p, _ in result.open_ports if p in (21, 22, 23, 25, 80, 8080)]
        if grab_ports:
            banner_results = await asyncio.gather(
                *[_banner_grab(ip, p, 2.0) for p in grab_ports],
                return_exceptions=True,
            )
            for port, banner in zip(grab_ports, banner_results):
                if isinstance(banner, str) and banner:
                    result.banners[port] = banner

    return result


# ── OS detection ──────────────────────────────────────────────────────────────

async def _guess_os_ttl(ip: str) -> str:
    """Coarse OS hint from ICMP TTL value."""
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


def _enrich_os(base: str, port_nums: set[int]) -> str:
    """Refine OS classification using discovered port profile.

    TTL=64 alone covers Linux, macOS, Android, iOS, FreeBSD — open ports
    let us narrow it down significantly.
    """
    # Android: ADB port is a very strong signal
    if 5555 in port_nums:
        return "Android (ADB enabled)"

    # iOS: lockdownd on 62078
    if 62078 in port_nums:
        return "iOS"

    # Windows: MSRPC or SMB+NetBIOS (TTL can be 64 on some configs)
    if 135 in port_nums or (445 in port_nums and 139 in port_nums):
        return "Windows"

    # macOS: AFP or CUPS printing
    if 548 in port_nums or (631 in port_nums and 445 not in port_nums):
        return "macOS"

    # Router / embedded: has web UI but no SSH, SMB, or known desktop ports
    if (80 in port_nums or 443 in port_nums or 8080 in port_nums) and \
       not port_nums & {22, 445, 135, 3389}:
        if base == "Network device" or (base == "Linux / Unix" and
           not port_nums & {22, 25, 110, 143, 5432, 3306}):
            return "Router / Embedded device"

    return base


# ── NetBIOS name query ────────────────────────────────────────────────────────

async def _netbios_query(ip: str, timeout: float = 1.5) -> str:
    """Query NetBIOS Name Service (UDP 137) for the Windows machine name.

    Sends a Node Status Request and parses the first workstation-type name
    from the response. Returns empty string if unreachable or not Windows.
    """
    # NetBIOS Node Status Request packet (RFC 1002)
    pkt = (
        b'\xab\xcd'          # Transaction ID
        b'\x00\x00'          # Flags: request
        b'\x00\x01'          # Questions: 1
        b'\x00\x00'          # Answer RRs
        b'\x00\x00'          # Authority RRs
        b'\x00\x00'          # Additional RRs
        b'\x20'              # Length of encoded name (32)
        + b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'  # Encoded wildcard '*'
        + b'\x00'            # Root label
        b'\x00\x21'          # Type: NBSTAT
        b'\x00\x01'          # Class: IN
    )
    try:
        loop = asyncio.get_event_loop()
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _send_netbios, ip, pkt),
            timeout=timeout,
        )
        return result
    except Exception:
        return ""


def _send_netbios(ip: str, pkt: bytes) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(pkt, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        # Parse: skip 56-byte header, then read num_names (1 byte)
        if len(data) < 57:
            return ""
        num_names = data[56]
        offset = 57
        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name = data[offset:offset + 15].decode(errors="replace").strip()
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            # Type 0x0000 = workstation name (machine name)
            if flags & 0x8000 == 0 and name:
                return name
            offset += 18
    except Exception:
        pass
    return ""


# ── helpers ───────────────────────────────────────────────────────────────────

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


# ── formatter ─────────────────────────────────────────────────────────────────

def format_recon(result: ReconResult) -> str:
    parts = [f"Recon: {result.ip}"]
    if result.mac:
        mac_str = result.mac
        if result.vendor:
            mac_str += f" ({result.vendor})"
        parts.append(f"mac={mac_str}")
    name = result.netbios_name or result.hostname
    if name:
        parts.append(f"hostname={name}")
    if result.os_hint:
        parts.append(f"os={result.os_hint}")
    if result.open_ports:
        ports_str = ", ".join(f"{p}/{n}" for p, n in result.open_ports[:8])
        parts.append(f"open_ports=[{ports_str}]")
    if result.banners:
        banner_parts = [f"{p}:{b}" for p, b in list(result.banners.items())[:3]]
        parts.append(f"banners=[{'; '.join(banner_parts)}]")
    return " | ".join(parts)
