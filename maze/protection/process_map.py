import asyncio
import os
import socket
import struct
from dataclasses import dataclass
from maze.core.events import Event, EventBus, EventType, ThreatLevel


@dataclass
class Connection:
    pid: int
    process: str
    local_addr: str
    remote_addr: str
    remote_ip: str
    remote_port: int


def _hex_to_ip(hex_str: str) -> str:
    addr = int(hex_str, 16)
    return socket.inet_ntoa(struct.pack("<I", addr))


def _read_proc_net_tcp() -> list[dict]:
    entries = []
    try:
        with open("/proc/net/tcp") as f:
            lines = f.readlines()[1:]
        for line in lines:
            parts = line.split()
            if len(parts) < 10:
                continue
            local = parts[1]
            remote = parts[2]
            inode = parts[9]
            local_ip, local_port = local.split(":")
            remote_ip, remote_port = remote.split(":")
            entries.append({
                "local": f"{_hex_to_ip(local_ip)}:{int(local_port, 16)}",
                "remote_ip": _hex_to_ip(remote_ip),
                "remote_port": int(remote_port, 16),
                "inode": inode,
            })
    except Exception:
        pass
    return entries


def _inode_to_pid(inode: str) -> tuple[int, str] | None:
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            fd_dir = f"/proc/{pid}/fd"
            for fd in os.listdir(fd_dir):
                link = os.readlink(f"{fd_dir}/{fd}")
                if f"socket:[{inode}]" in link:
                    with open(f"/proc/{pid}/comm") as f:
                        name = f.read().strip()
                    return int(pid), name
        except (PermissionError, FileNotFoundError):
            continue
    return None


class ProcessNetworkMonitor:
    def __init__(self, known_processes: set[str] | None = None,
                 whitelist: list[str] | None = None):
        self._known = known_processes or set()
        self._whitelist = set(whitelist or [])
        self._bus: EventBus | None = None
        self._task: asyncio.Task | None = None

    async def start(self, bus: EventBus) -> None:
        self._bus = bus
        self._task = asyncio.create_task(self._monitor())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()

    async def snapshot(self) -> list[Connection]:
        return await asyncio.to_thread(self._build_snapshot)

    def _build_snapshot(self) -> list[Connection]:
        conns = []
        for entry in _read_proc_net_tcp():
            if entry["remote_ip"] == "0.0.0.0":
                continue
            result = _inode_to_pid(entry["inode"])
            if result:
                pid, name = result
                conns.append(Connection(
                    pid=pid,
                    process=name,
                    local_addr=entry["local"],
                    remote_addr=f"{entry['remote_ip']}:{entry['remote_port']}",
                    remote_ip=entry["remote_ip"],
                    remote_port=entry["remote_port"],
                ))
        return conns

    _NORMAL_PORTS = {80, 443, 8080, 8443, 53, 22, 5353, 8888, 1194, 51820}

    async def _monitor(self) -> None:
        seen: set[tuple] = set()
        while True:
            await asyncio.sleep(10)
            conns = await self.snapshot()
            for conn in conns:
                if conn.remote_ip in self._whitelist:
                    continue
                if self._known and conn.process not in self._known:
                    if conn.remote_port in self._NORMAL_PORTS:
                        continue
                    key = (conn.process, conn.remote_ip, conn.remote_port)
                    if key in seen:
                        continue
                    seen.add(key)
                    await self._bus.emit(Event(
                        type=EventType.UNKNOWN_PROCESS,
                        level=ThreatLevel.SUSPICIOUS,
                        message=f"Unknown process connected externally: "
                                f"{conn.process} (PID {conn.pid}) → {conn.remote_addr}",
                        data={"process": conn.process, "pid": conn.pid,
                              "remote": conn.remote_addr},
                    ))
