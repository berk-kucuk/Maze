import asyncio
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QScrollArea, QFrame, QHBoxLayout,
    QLabel, QPushButton,
)
from PyQt6.QtCore import Qt


# (engine_key, i18n_key, category_i18n_key)
MODULES = [
    ("arp_watch",       "module_arp_watch",       "cat_detection"),
    ("rogue_ap",        "module_rogue_ap",         "cat_detection"),
    ("dns_validate",    "module_dns_validate",     "cat_detection"),
    ("tls",             "module_tls",              "cat_detection"),
    ("ssl_strip",       "module_ssl_strip",        "cat_detection"),
    ("mac",             "module_mac",              "cat_stealth"),
    ("hostname",        "module_hostname",         "cat_stealth"),
    ("service_blocker", "module_service_blocker",  "cat_stealth"),
    ("fingerprint",     "module_fingerprint",      "cat_stealth"),
    ("firewall",        "module_firewall",         "cat_protection"),
    ("port_scan",       "module_port_scan",        "cat_protection"),
    ("process",         "module_process",          "cat_protection"),
    ("dns_leak",        "module_dns_leak",         "cat_protection"),
]


def _polish(btn: QPushButton) -> None:
    btn.style().unpolish(btn)
    btn.style().polish(btn)
    btn.update()


class ModuleStatusWidget(QWidget):
    def __init__(self, state, engine):
        super().__init__()
        self._state = state
        self._engine = engine
        self._rows: dict[str, tuple[QLabel, QLabel, QPushButton]] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        self._inner = QVBoxLayout(container)
        self._inner.setContentsMargins(24, 16, 24, 16)
        self._inner.setSpacing(0)

        scroll.setWidget(container)
        layout.addWidget(scroll)

        self._build_rows()
        state.language_changed.connect(self.retranslate)

    def _build_rows(self) -> None:
        current_cat = None
        states = self._engine.module_states()

        for key, i18n_key, cat_key in MODULES:
            if cat_key != current_cat:
                current_cat = cat_key
                self._add_category_header(cat_key)

            active = states.get(key, False)
            name_lbl = QLabel(self._state.t(i18n_key))
            name_lbl.setStyleSheet("font-size: 13px;")

            status_lbl = QLabel(self._state.t("status_active" if active else "status_inactive"))
            status_lbl.setFixedWidth(80)
            status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            status_lbl.setStyleSheet(
                f"color: {'#00e676' if active else '#555555'}; font-size: 12px;"
            )

            btn = QPushButton("●" if active else "○")
            btn.setFixedWidth(44)
            btn.setFixedHeight(30)
            btn.setProperty("active", active)
            btn.clicked.connect(lambda _, k=key: self._toggle(k))
            _polish(btn)

            self._rows[key] = (name_lbl, status_lbl, btn)

            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(12)
            row_layout.addWidget(name_lbl)
            row_layout.addStretch()
            row_layout.addWidget(status_lbl)
            row_layout.addWidget(btn)

            self._inner.addWidget(row_widget)

            # Thin separator
            sep = QFrame()
            sep.setFrameShape(QFrame.Shape.HLine)
            sep.setFixedHeight(1)
            self._inner.addWidget(sep)

        self._inner.addStretch()

    def _add_category_header(self, cat_key: str) -> None:
        lbl = QLabel(self._state.t(cat_key).upper())
        lbl.setStyleSheet(
            "font-size: 10px; font-weight: bold; letter-spacing: 2px; "
            "color: #555555; padding-top: 16px; padding-bottom: 6px;"
        )
        self._inner.addWidget(lbl)

    def _toggle(self, key: str) -> None:
        asyncio.create_task(self._async_toggle(key))

    async def _async_toggle(self, key: str) -> None:
        await self._engine.toggle_module(key)
        self.refresh()

    def refresh(self) -> None:
        states = self._engine.module_states()
        for key, (name_lbl, status_lbl, btn) in self._rows.items():
            active = states.get(key, False)
            status_lbl.setText(self._state.t("status_active" if active else "status_inactive"))
            status_lbl.setStyleSheet(
                f"color: {'#00e676' if active else '#555555'}; font-size: 12px;"
            )
            btn.setText("●" if active else "○")
            btn.setProperty("active", active)
            _polish(btn)

    def retranslate(self, _lang: str = None) -> None:
        for key, (name_lbl, status_lbl, btn) in self._rows.items():
            i18n_key = next(m[1] for m in MODULES if m[0] == key)
            name_lbl.setText(self._state.t(i18n_key))
            active = self._engine.module_states().get(key, False)
            status_lbl.setText(self._state.t("status_active" if active else "status_inactive"))
