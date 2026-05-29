"""
Maze privileged helper — run as root via sudo.
"""
import asyncio
import json
import os
import re
import signal
import time
import socket as _socket
import struct
import subprocess
import sys
import threading

_SOCK_PATH = "/tmp/maze-{uid}.sock"
_MAC_RE    = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
_IP_RE     = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')
_IFACE_RE  = re.compile(r'^[a-zA-Z0-9_\-]{1,15}$')
_TABLE_RE  = re.compile(r'^[a-zA-Z0-9_\-]{1,32}$')
_NFT_OPS        = {"add", "delete", "list", "flush", "get"}
_SYSCTL_ALLOWED = {
    "net.ipv4.ip_default_ttl",
    "net.ipv4.tcp_window_scaling",
}
SO_PEERCRED = 17

_clients: list[asyncio.StreamWriter] = []
_loop: asyncio.AbstractEventLoop | None = None
_owner_uid: int = 0


def _peer_uid(writer: asyncio.StreamWriter) -> int:
    try:
        sock = writer.get_extra_info('socket')
        cred = sock.getsockopt(_socket.SOL_SOCKET, SO_PEERCRED, struct.calcsize('3i'))
        _, uid, _ = struct.unpack('3i', cred)
        return uid
    except Exception:
        return -1


def _push(event: dict) -> None:
    if not _loop or not _clients:
        return
    data = (json.dumps(event) + "\n").encode()
    for w in list(_clients):
        try:
            _loop.call_soon_threadsafe(w.write, data)
        except Exception:
            pass


def _get_iface_ips(iface: str) -> set[str]:
    """Return all IPv4 addresses assigned to iface (to filter own SYN packets)."""
    import re as _re
    own: set[str] = set()
    try:
        out = subprocess.check_output(
            ["ip", "addr", "show", iface], text=True, timeout=3)
        for m in _re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)/', out):
            own.add(m.group(1))
    except Exception:
        pass
    return own


def _sniff_thread(iface: str) -> None:
    try:
        from scapy.all import ARP, IP, TCP, sniff

        own_ips: set[str] = _get_iface_ips(iface)
        own_ips_refreshed_at: float = time.monotonic()

        def handle(pkt):
            nonlocal own_ips, own_ips_refreshed_at
            # Refresh every 60 s — replace (not update) so old-network IPs evict.
            now = time.monotonic()
            if now - own_ips_refreshed_at >= 60:
                own_ips = _get_iface_ips(iface)
                own_ips_refreshed_at = now

            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                _push({"event": "arp", "src": pkt[ARP].psrc,
                       "mac": pkt[ARP].hwsrc, "dst": pkt[ARP].pdst})
            elif pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt[TCP].flags == "S":
                src = pkt[IP].src
                if src not in own_ips:  # skip own outgoing SYN packets
                    _push({"event": "syn", "src": src,
                           "dst": pkt[IP].dst, "dport": pkt[TCP].dport})

        sniff(iface=iface,
              filter="arp or (tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0)",
              prn=handle, store=False)
    except Exception as exc:
        _push({"event": "error", "msg": str(exc)})


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    # Verify caller is the invoking user, not an arbitrary local process
    if _owner_uid and _peer_uid(writer) != _owner_uid:
        writer.close()
        return

    _clients.append(writer)
    try:
        async for raw in reader:
            line = raw.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue

            cmd    = req.get("cmd", "")
            req_id = req.get("id", 0)
            resp: dict = {"id": req_id, "ok": False}

            if cmd == "ping":
                resp["ok"] = True

            elif cmd == "nft_list":
                r = subprocess.run(["nft", "list", "ruleset"],
                                   capture_output=True, text=True)
                resp.update(ok=r.returncode == 0, data=r.stdout)

            elif cmd == "nft_apply":
                rules = req.get("rules", "")
                if not isinstance(rules, str) or len(rules) > 65536:
                    resp["err"] = "invalid rules"
                else:
                    r = subprocess.run(["nft", "-f", "-"],
                                       input=rules, text=True, capture_output=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr)

            elif cmd == "nft_delete":
                table = req.get("table", "")
                if not _TABLE_RE.match(table):
                    resp["err"] = "invalid table name"
                else:
                    r = subprocess.run(["nft", "delete", "table", "inet", table],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0)

            elif cmd == "fw_cmd":
                args = req.get("args", [])
                if (isinstance(args, list) and len(args) >= 2
                        and args[0] == "nft" and args[1] in _NFT_OPS):
                    r = subprocess.run(args, capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr.strip())
                else:
                    resp["err"] = f"disallowed nft op: {args[1] if len(args) > 1 else '?'}"

            elif cmd == "fw_list":
                import re as _re
                data = {"ips": [], "ports_tcp": [], "ports_udp": []}
                r = subprocess.run(["nft", "list", "table", "inet", "maze_firewall"],
                                   capture_output=True, text=True)
                if r.returncode == 0:
                    current_set = None
                    for ln in r.stdout.splitlines():
                        if "blocked_ips" in ln:       current_set = "ips"
                        elif "blocked_ports_tcp" in ln: current_set = "ports_tcp"
                        elif "blocked_ports_udp" in ln: current_set = "ports_udp"
                        m = _re.search(r"elements\s*=\s*\{([^}]+)\}", ln)
                        if m and current_set:
                            els = [e.strip() for e in m.group(1).split(",") if e.strip()]
                            if current_set == "ips":
                                data["ips"] = els
                            else:
                                data[current_set] = [int(p) for p in els if p.isdigit()]
                resp.update(ok=True, data=data)

            elif cmd == "sysctl_get":
                key = req.get("key", "")
                if key not in _SYSCTL_ALLOWED:
                    resp["err"] = "disallowed sysctl key"
                else:
                    r = subprocess.run(["sysctl", "-n", key],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, data=r.stdout.strip())

            elif cmd == "sysctl_set":
                key   = req.get("key", "")
                value = str(req.get("value", ""))
                if key not in _SYSCTL_ALLOWED:
                    resp["err"] = "disallowed sysctl key"
                elif not re.match(r'^\d+$', value):
                    resp["err"] = "invalid sysctl value (digits only)"
                else:
                    r = subprocess.run(["sysctl", "-w", f"{key}={value}"],
                                       capture_output=True, text=True)
                    resp.update(ok=r.returncode == 0, err=r.stderr.strip())

            elif cmd == "set_mac":
                iface = req.get("iface", "")
                mac   = req.get("mac", "")
                if not _IFACE_RE.match(iface):
                    resp["err"] = "invalid interface name"
                elif not _MAC_RE.match(mac):
                    resp["err"] = "invalid MAC format"
                else:
                    try:
                        for args in (
                            ["ip", "link", "set", iface, "down"],
                            ["ip", "link", "set", iface, "address", mac],
                            ["ip", "link", "set", iface, "up"],
                        ):
                            subprocess.run(args, check=True, capture_output=True)
                        resp["ok"] = True
                    except subprocess.CalledProcessError as e:
                        resp["err"] = str(e)

            writer.write((json.dumps(resp) + "\n").encode())
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        if writer in _clients:
            _clients.remove(writer)
        writer.close()


async def _serve(sock_path: str, iface: str) -> None:
    global _loop
    _loop = asyncio.get_running_loop()

    try:
        os.unlink(sock_path)
    except FileNotFoundError:
        pass

    # Create socket with restrictive permissions from the start
    old_umask = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(_handle, sock_path)
    finally:
        os.umask(old_umask)

    uid = int(os.environ.get("SUDO_UID", "0"))
    gid = int(os.environ.get("SUDO_GID", "0"))
    if uid:
        os.chown(sock_path, uid, gid)

    threading.Thread(target=_sniff_thread, args=(iface,), daemon=True).start()
    _loop.add_signal_handler(signal.SIGTERM, _loop.stop)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    if os.getuid() != 0:
        print("maze.helper must run as root", file=sys.stderr)
        sys.exit(1)

    _owner_uid = int(os.environ.get("SUDO_UID", "0"))
    uid   = os.environ.get("SUDO_UID", "0")
    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    sock  = _SOCK_PATH.format(uid=uid)

    from pathlib import Path as _Path
    operstate_path = _Path("/sys/class/net") / iface / "operstate"
    if not operstate_path.exists() or operstate_path.read_text().strip() not in ("up", "unknown"):
        sys.path.insert(0, str(_Path(__file__).parent.parent))
        try:
            from maze.utils.network_info import get_active_physical_interface
            detected = get_active_physical_interface()
            if detected != "—":
                iface = detected
        except Exception:
            pass

    asyncio.run(_serve(sock, iface))
