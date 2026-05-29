from PyQt6.QtWidgets import QWidget, QHBoxLayout, QLabel
from maze.core.events import ThreatLevel
from maze.gui.theme import THREAT_COLORS


class ThreatLevelWidget(QWidget):
    def __init__(self, state):
        super().__init__()
        self._state = state
        self._level = ThreatLevel.SAFE

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(7)

        self._dot = QLabel("●")
        self._dot.setStyleSheet("font-size: 16px;")

        self._label = QLabel()
        self._label.setStyleSheet("font-weight: bold; font-size: 13px; letter-spacing: 1px;")

        layout.addWidget(self._dot)
        layout.addWidget(self._label)

        state.language_changed.connect(self._retranslate)
        self._apply(ThreatLevel.SAFE)

    def update_level(self, level: ThreatLevel) -> None:
        if level.value in [l.value for l in ThreatLevel]:
            self._level = level
        self._apply(level)

    def _apply(self, level: ThreatLevel) -> None:
        color = THREAT_COLORS[level.value]
        self._dot.setStyleSheet(f"font-size: 16px; color: {color};")
        self._label.setStyleSheet(
            f"font-weight: bold; font-size: 13px; letter-spacing: 1px; color: {color};"
        )
        self._label.setText(self._state.t(f"threat_{level.value}"))

    def _retranslate(self, _lang: str = None) -> None:
        self._apply(self._level)
