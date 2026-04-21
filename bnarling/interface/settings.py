import colorsys
import random

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


def random_color():
    r, g, b = colorsys.hls_to_rgb(random.random(), 0.5, 1.0)
    # 0xBBGGRR — matches idarling's server expectations
    return int(b * 255) << 16 | int(g * 255) << 8 | int(r * 255)


def ida_color_to_qcolor(c):
    r = c & 0xFF
    g = (c >> 8) & 0xFF
    b = (c >> 16) & 0xFF
    return QColor(r, g, b)


def qcolor_to_ida_color(c):
    return (c.blue() << 16) | (c.green() << 8) | c.red()


class SettingsDialog(QDialog):
    """Settings dialog mirroring the IDA plugin but simplified for BN."""

    def __init__(self, plugin, parent=None):
        super().__init__(parent)
        self._plugin = plugin
        self.setWindowTitle("bnarling Settings")
        self.resize(640, 480)

        layout = QVBoxLayout(self)

        # --- User info ---
        user_box = QWidget()
        user_layout = QFormLayout(user_box)
        self._name_edit = QLineEdit(plugin.config["user"]["name"])
        user_layout.addRow("User name:", self._name_edit)

        color_row = QHBoxLayout()
        self._color = plugin.config["user"]["color"]
        self._color_button = QPushButton()
        self._update_color_button()
        self._color_button.clicked.connect(self._pick_color)
        color_row.addWidget(self._color_button)
        color_widget = QWidget()
        color_widget.setLayout(color_row)
        user_layout.addRow("User color:", color_widget)

        self._notifications = QCheckBox()
        self._notifications.setChecked(
            plugin.config["user"].get("notifications", True)
        )
        user_layout.addRow("Notifications:", self._notifications)

        layout.addWidget(QLabel("<b>User</b>"))
        layout.addWidget(user_box)

        # --- Servers ---
        layout.addWidget(QLabel("<b>Servers</b>"))
        self._servers_table = QTableWidget(0, 4)
        self._servers_table.setHorizontalHeaderLabels(
            ["Host", "Port", "No SSL", "Auto-connect"]
        )
        try:
            self._servers_table.horizontalHeader().setSectionResizeMode(
                QHeaderView.ResizeMode.Stretch
            )
        except AttributeError:
            self._servers_table.horizontalHeader().setSectionResizeMode(
                QHeaderView.Stretch
            )
        layout.addWidget(self._servers_table)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._add_server)
        rm_btn = QPushButton("Remove selected")
        rm_btn.clicked.connect(self._remove_server)
        btn_row.addWidget(add_btn)
        btn_row.addWidget(rm_btn)
        btn_row.addStretch()
        btn_wrap = QWidget()
        btn_wrap.setLayout(btn_row)
        layout.addWidget(btn_wrap)

        self._load_servers()

        # --- Session override (project/binary/snapshot) ---
        layout.addWidget(QLabel("<b>Session</b>"))
        sess_box = QWidget()
        sess_layout = QFormLayout(sess_box)
        self._project = QLineEdit(plugin.core.project or "")
        self._binary = QLineEdit(plugin.core.binary or "")
        self._snapshot = QLineEdit(plugin.core.snapshot or "")
        sess_layout.addRow("Project:", self._project)
        sess_layout.addRow("Binary:", self._binary)
        sess_layout.addRow("Snapshot:", self._snapshot)
        layout.addWidget(sess_box)

        # --- Buttons ---
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _update_color_button(self):
        qc = ida_color_to_qcolor(self._color)
        self._color_button.setStyleSheet(
            "background-color: rgb(%d,%d,%d); color: white;"
            % (qc.red(), qc.green(), qc.blue())
        )
        self._color_button.setText("#%02x%02x%02x" % (qc.red(), qc.green(), qc.blue()))

    def _pick_color(self):
        qc = QColorDialog.getColor(ida_color_to_qcolor(self._color), self)
        if qc.isValid():
            self._color = qcolor_to_ida_color(qc)
            self._update_color_button()

    def _load_servers(self):
        self._servers_table.setRowCount(0)
        for server in self._plugin.config["servers"]:
            self._append_server_row(server)

    def _append_server_row(self, server):
        row = self._servers_table.rowCount()
        self._servers_table.insertRow(row)
        self._servers_table.setItem(
            row, 0, QTableWidgetItem(server.get("host", ""))
        )
        self._servers_table.setItem(
            row, 1, QTableWidgetItem(str(server.get("port", 31013)))
        )
        ns = QTableWidgetItem()
        ns.setFlags(ns.flags() | Qt.ItemIsUserCheckable)
        ns.setCheckState(Qt.Checked if server.get("no_ssl", True) else Qt.Unchecked)
        self._servers_table.setItem(row, 2, ns)
        ac = QTableWidgetItem()
        ac.setFlags(ac.flags() | Qt.ItemIsUserCheckable)
        ac.setCheckState(
            Qt.Checked if server.get("auto_connect", False) else Qt.Unchecked
        )
        self._servers_table.setItem(row, 3, ac)

    def _add_server(self):
        self._append_server_row(
            {"host": "127.0.0.1", "port": 31013, "no_ssl": True, "auto_connect": False}
        )

    def _remove_server(self):
        rows = sorted({i.row() for i in self._servers_table.selectedIndexes()}, reverse=True)
        for row in rows:
            self._servers_table.removeRow(row)

    def _collect_servers(self):
        servers = []
        for row in range(self._servers_table.rowCount()):
            try:
                host = self._servers_table.item(row, 0).text().strip()
                port = int(self._servers_table.item(row, 1).text().strip())
            except Exception:
                continue
            if not host:
                continue
            no_ssl = self._servers_table.item(row, 2).checkState() == Qt.Checked
            auto_connect = self._servers_table.item(row, 3).checkState() == Qt.Checked
            servers.append(
                {
                    "host": host,
                    "port": port,
                    "no_ssl": no_ssl,
                    "auto_connect": auto_connect,
                }
            )
        return servers

    def _accept(self):
        cfg = self._plugin.config
        cfg["user"]["name"] = self._name_edit.text().strip() or "unnamed"
        cfg["user"]["color"] = self._color
        cfg["user"]["notifications"] = self._notifications.isChecked()
        cfg["servers"] = self._collect_servers()
        self._plugin.save_config()

        project = self._project.text().strip() or None
        binary = self._binary.text().strip() or None
        snapshot = self._snapshot.text().strip() or None
        changed = (
            project != self._plugin.core.project
            or binary != self._plugin.core.binary
            or snapshot != self._plugin.core.snapshot
        )
        if changed:
            self._plugin.core.leave_session()
            self._plugin.core.project = project
            self._plugin.core.binary = binary
            self._plugin.core.snapshot = snapshot
            if self._plugin.network.connected:
                self._plugin.core.join_session()

        self._plugin.interface.refresh()
        self.accept()
