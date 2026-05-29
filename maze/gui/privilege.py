"""
Starts the Maze privileged helper (as root via sudo) and connects to it.
The GUI itself always runs as the normal user.
"""
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QApplication,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

_HELPER_MODULE = str(Path(__file__).parent.parent / "helper.py")
_SOCK_TEMPLATE  = "/tmp/maze-{uid}.sock"


def _sock_path() -> str:
    return _SOCK_TEMPLATE.format(uid=os.getuid())


def _launch_helper(password: str, iface: str) -> bool:
    """
    Validate the password with sudo, then launch the helper daemon detached.
    Returns True if the helper started and its socket appeared within 5 s.
    """
    # 1. Validate password (quick)
    try:
        check = subprocess.run(
            ["sudo", "-S", "true"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=6,
        )
    except subprocess.TimeoutExpired:
        return False
    if check.returncode != 0:
        return False

    # 1b. Kill any previously running helper (runs as root, so needs sudo)
    subprocess.run(
        ["sudo", "-S", "pkill", "-f", "maze/helper.py"],
        input=password + "\n",
        text=True,
        capture_output=True,
        timeout=4,
    )
    # Give it a moment to release the socket
    time.sleep(0.3)

    # 2. Launch helper as root, detached from this process
    env_keys = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS", "HOME", "USER", "LANG")
    env_pairs = [f"{k}={os.environ[k]}" for k in env_keys if k in os.environ]
    cmd = (["sudo", "-S", "env"] + env_pairs +
           [sys.executable, _HELPER_MODULE, iface])

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    )
    proc.stdin.write(password + "\n")
    proc.stdin.close()

    # 3. Wait for socket to appear (helper signals readiness by creating it)
    sock = _sock_path()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if Path(sock).exists():
            return True
        time.sleep(0.1)
    return False


async def connect_helper(iface: str = "eth0"):
    """
    Connect to a running helper. Returns a connected HelperClient or None.
    Tries to connect immediately (helper might already be running).
    """
    from maze.helper_client import HelperClient
    client = HelperClient(uid=os.getuid())
    if await client.connect():
        return client
    return None


# ── GUI ───────────────────────────────────────────────────────────────────────

class PrivilegeDialog(QDialog):
    def __init__(self, iface: str):
        super().__init__()
        self._iface = iface
        self._helper = None

        self.setWindowTitle("Maze")
        self.setFixedWidth(420)
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)

        root = QVBoxLayout(self)
        root.setContentsMargins(32, 28, 32, 28)
        root.setSpacing(14)

        # Header row
        from maze.gui.icons import create_app_icon
        hdr = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(create_app_icon(32).pixmap(32, 32))
        icon.setFixedSize(32, 32)
        hdr.addWidget(icon)
        title = QLabel("MAZE")
        title.setFont(QFont("sans-serif", 15, QFont.Weight.Bold))
        hdr.addWidget(title)
        hdr.addStretch()
        root.addLayout(hdr)

        # Description
        desc = QLabel(
            "A privileged helper is needed for:\n"
            "  •  Firewall monitoring (nftables)\n"
            "  •  Packet capture / attack detection\n"
            "  •  MAC address randomization\n\n"
            "The helper runs as root. The app window\n"
            "itself stays in your normal user session."
        )
        desc.setStyleSheet("font-size: 13px;")
        root.addWidget(desc)

        # Password field
        self._pwd = QLineEdit()
        self._pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self._pwd.setPlaceholderText("Sudo password")
        self._pwd.setFixedHeight(36)
        self._pwd.returnPressed.connect(self._try_auth)
        root.addWidget(self._pwd)

        # Error label
        self._err = QLabel("Incorrect password — try again.")
        self._err.setStyleSheet("color: #ff3d00; font-size: 12px;")
        self._err.hide()
        root.addWidget(self._err)

        # Buttons
        btn_row = QHBoxLayout()
        skip = QPushButton("Skip (limited mode)")
        skip.setStyleSheet("color: #888; font-size: 12px; border: none; background: transparent;")
        skip.clicked.connect(self.reject)
        btn_row.addWidget(skip)
        btn_row.addStretch()

        self._ok = QPushButton("Start helper")
        self._ok.setDefault(True)
        self._ok.setFixedWidth(120)
        self._ok.clicked.connect(self._try_auth)
        btn_row.addWidget(self._ok)
        root.addLayout(btn_row)

        self._pwd.setFocus()

    def get_helper(self):
        return self._helper

    def _try_auth(self) -> None:
        password = self._pwd.text()
        if not password:
            return
        self._ok.setEnabled(False)
        self._ok.setText("Starting…")
        self._err.hide()
        QApplication.processEvents()

        ok = _launch_helper(password, self._iface)
        if ok:
            self.accept()
        else:
            self._pwd.clear()
            self._pwd.setFocus()
            self._err.show()
            self._ok.setEnabled(True)
            self._ok.setText("Start helper")


def show_privilege_dialog(app: QApplication, iface: str) -> bool:
    """
    Show the password dialog. Returns True if the helper was launched
    successfully (caller should then connect_helper()).
    Returns False if user skipped.
    """
    from maze.gui.theme import get_stylesheet
    app.setStyleSheet(get_stylesheet("dark"))

    dlg = PrivilegeDialog(iface)
    return dlg.exec() == QDialog.DialogCode.Accepted
