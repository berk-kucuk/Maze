import asyncio
import sys
import qasync
from PyQt6.QtWidgets import QApplication
from maze.gui.app_state import AppState
from maze.gui.dashboard import Dashboard
from maze.gui.privilege import show_privilege_dialog, connect_helper
from maze.gui.theme import get_stylesheet
from maze.core.engine import MazeEngine
from maze.gui.icons import create_app_icon
from maze.utils.config import load_config, save_config


def run() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Maze")
    app.setOrganizationName("maze")
    app.setWindowIcon(create_app_icon(64))

    cfg = load_config()

    # Ask for sudo password to start the privileged helper.
    # The GUI itself stays as the normal user — only the helper runs as root.
    helper_launched = show_privilege_dialog(app, cfg.interface)

    state = AppState(theme=cfg.theme, language=cfg.language)
    app.setStyleSheet(get_stylesheet(state.theme))
    state.theme_changed.connect(lambda t: app.setStyleSheet(get_stylesheet(t)))

    def _save_theme(t: str) -> None:
        cfg.theme = t
        save_config(cfg)

    def _save_language(l: str) -> None:
        cfg.language = l
        save_config(cfg)

    state.theme_changed.connect(_save_theme)
    state.language_changed.connect(_save_language)

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    async def _boot():
        helper = None
        if helper_launched:
            helper = await connect_helper(cfg.interface)

        engine = MazeEngine(cfg, helper=helper)
        window = Dashboard(engine, cfg, state)
        window.show()
        await engine.start()

    with loop:
        loop.run_until_complete(_boot())
        loop.run_forever()
