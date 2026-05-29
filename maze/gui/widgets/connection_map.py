from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView,
)
from PyQt6.QtCore import Qt
from maze.protection.process_map import Connection


class ConnectionMapWidget(QWidget):
    def __init__(self, state):
        super().__init__()
        self._state = state
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self._table = QTableWidget(0, 4)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(0, 60)
        self._table.setColumnWidth(1, 140)
        self._table.setColumnWidth(2, 180)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)

        layout.addWidget(self._table)
        state.language_changed.connect(self.retranslate)
        self.retranslate()

    def update_connections(self, conns: list[Connection]) -> None:
        self._table.setRowCount(0)
        for conn in conns:
            row = self._table.rowCount()
            self._table.insertRow(row)
            for col, text in enumerate([
                str(conn.pid),
                conn.process,
                conn.local_addr,
                conn.remote_addr,
            ]):
                item = QTableWidgetItem(text)
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                self._table.setItem(row, col, item)

    def retranslate(self, _lang: str = None) -> None:
        self._table.setHorizontalHeaderLabels([
            self._state.t("col_pid"),
            self._state.t("col_process"),
            self._state.t("col_local"),
            self._state.t("col_remote"),
        ])
