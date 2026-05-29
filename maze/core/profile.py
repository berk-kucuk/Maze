from dataclasses import dataclass
from enum import Enum


class Profile(Enum):
    HOME = "home"
    PUBLIC = "public"
    PARANOID = "paranoid"
    MANUAL = "manual"


@dataclass
class ProfileConfig:
    mac_randomize: bool
    hide_hostname: bool
    block_incoming: bool
    doh_enabled: bool
    port_scan_detect: bool
    process_monitor: bool
    fingerprint_protect: bool


PROFILES: dict[Profile, ProfileConfig] = {
    Profile.HOME: ProfileConfig(
        mac_randomize=False,
        hide_hostname=False,
        block_incoming=False,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=False,
    ),
    Profile.PUBLIC: ProfileConfig(
        mac_randomize=True,
        hide_hostname=True,
        block_incoming=True,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=True,
    ),
    Profile.PARANOID: ProfileConfig(
        mac_randomize=True,
        hide_hostname=True,
        block_incoming=True,
        doh_enabled=True,
        port_scan_detect=True,
        process_monitor=True,
        fingerprint_protect=True,
    ),
    Profile.MANUAL: ProfileConfig(
        mac_randomize=False,
        hide_hostname=False,
        block_incoming=False,
        doh_enabled=False,
        port_scan_detect=False,
        process_monitor=False,
        fingerprint_protect=False,
    ),
}


class ProfileManager:
    def __init__(self):
        self.current = Profile.MANUAL
        self._listeners: list = []

    def set(self, profile: Profile) -> None:
        self.current = profile
        for cb in self._listeners:
            cb(profile)

    @property
    def config(self) -> ProfileConfig:
        return PROFILES[self.current]

    def on_change(self, callback) -> None:
        self._listeners.append(callback)
