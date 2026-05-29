from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt


class DeviceListWidget(QWidget):
    def __init__(self, state):
        super().__init__()
        self._state = state
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, 3)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 140)
        self._table.setColumnWidth(1, 160)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        layout.addWidget(self._table)
        state.language_changed.connect(self.retranslate)
        self.retranslate()

    def update_devices(self, devices: dict[str, dict]) -> None:
        self._table.setRowCount(0)
        for ip, info in devices.items():
            row = self._table.rowCount()
            self._table.insertRow(row)
            ts: datetime = info.get("first_seen", datetime.now())
            for col, text in enumerate([
                ip,
                info.get("mac", ""),
                ts.strftime("%H:%M:%S"),
            ]):
                item = QTableWidgetItem(text)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self._table.setItem(row, col, item)

    def retranslate(self, _lang: str = None) -> None:
        self._table.setHorizontalHeaderLabels([
            self._state.t("col_ip"),
            self._state.t("col_mac"),
            self._state.t("col_first_seen"),
        ])
