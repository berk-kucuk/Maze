import json
from pathlib import Path
from dataclasses import dataclass, field


CONFIG_PATH = Path.home() / ".config" / "maze" / "config.json"


def _detect_interface() -> str:
    from maze.utils.network_info import get_active_physical_interface
    iface = get_active_physical_interface()
    return iface if iface != "—" else "eth0"


@dataclass
class CustomProfileConfig:
    name: str
    mac_randomize: bool = False
    hide_hostname: bool = False
    block_incoming: bool = False
    doh_enabled: bool = False
    port_scan_detect: bool = True
    process_monitor: bool = True
    fingerprint_protect: bool = False

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "CustomProfileConfig":
        return CustomProfileConfig(**{k: v for k, v in d.items() if k in CustomProfileConfig.__dataclass_fields__})


@dataclass
class MazeConfig:
    interface: str = field(default=None)
    mac_rotation_minutes: int = 30
    port_scan_threshold: int = 10
    theme: str = "dark"
    language: str = "en"
    known_processes: list = field(default_factory=lambda: [
        # Browsers
        "firefox", "chromium", "brave", "brave-browser", "chrome",
        "chromium-browser", "opera", "vivaldi",
        # VPN clients
        "protonvpn-app", "protonvpn", "proton-vpn-gnom", "openvpn",
        "wg", "wg-quick", "nordvpn", "mullvad", "expressvpn",
        "openconnect", "vpnc",
        # Music / media streaming
        "spotify", "Spotify", "spotifyd",
        # Communication
        "discord", "slack", "telegram-desktop", "signal-desktop",
        "zoom", "teams", "skype",
        # System / dev tools
        "curl", "wget", "ssh", "git", "python3", "python", "node",
        "npm", "cargo", "rustup", "code", "claude",
        "systemd", "systemd-resolved", "NetworkManager",
        # Package managers / update services
        "pacman", "apt", "dnf", "snap", "flatpak",
        "packagekitd", "fwupd", "pamac",
    ])
    trusted_networks: list = field(default_factory=list)
    custom_profiles: list = field(default_factory=list)
    whitelist_ips: list = field(default_factory=list)

    def __post_init__(self):
        if self.interface is None:
            self.interface = _detect_interface()
        else:
            # Re-detect if saved interface is gone or down
            operstate = Path("/sys/class/net") / self.interface / "operstate"
            if not operstate.exists():
                self.interface = _detect_interface()
            else:
                state = operstate.read_text().strip()
                if state not in ("up", "unknown"):
                    self.interface = _detect_interface()


def load_config() -> MazeConfig:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            valid = set(MazeConfig.__dataclass_fields__)
            cfg = MazeConfig(**{k: v for k, v in data.items() if k in valid})
            # Reconstruct CustomProfileConfig objects
            cfg.custom_profiles = [
                CustomProfileConfig.from_dict(p) if isinstance(p, dict) else p
                for p in cfg.custom_profiles
            ]
            return cfg
        except Exception:
            pass
    return MazeConfig()


def save_config(cfg: MazeConfig) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in cfg.__dict__.items()}
    data["custom_profiles"] = [
        p.to_dict() if hasattr(p, "to_dict") else p
        for p in cfg.custom_profiles
    ]
    CONFIG_PATH.write_text(json.dumps(data, indent=2))
