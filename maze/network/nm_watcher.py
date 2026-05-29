import asyncio
import dbus
import dbus.mainloop.glib
from gi.repository import GLib
from maze.core.profile import Profile


NM_BUS = "org.freedesktop.NetworkManager"
NM_PATH = "/org/freedesktop/NetworkManager"
NM_IFACE = "org.freedesktop.NetworkManager"

NM_STATE_CONNECTED_GLOBAL = 70

NM_CONNECTIVITY_NONE = 1


class NetworkManagerWatcher:
    def __init__(self, on_network_change):
        self._callback = on_network_change
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self, bus) -> None:
        self._loop = asyncio.get_event_loop()
        await asyncio.to_thread(self._setup_dbus)

    async def stop(self) -> None:
        pass

    def _setup_dbus(self) -> None:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        system_bus = dbus.SystemBus()
        system_bus.add_signal_receiver(
            self._on_state_change,
            signal_name="StateChanged",
            dbus_interface=NM_IFACE,
            bus_name=NM_BUS,
        )
        GLib.MainLoop().run()

    def _on_state_change(self, state: int) -> None:
        if state == NM_STATE_CONNECTED_GLOBAL:
            profile = self._detect_profile()
            asyncio.run_coroutine_threadsafe(
                self._callback(profile),
                self._loop,
            )

    def _detect_profile(self) -> Profile:
        # Bağlı ağ bilinen ağlar listesinde değilse → PUBLIC
        return Profile.PUBLIC
