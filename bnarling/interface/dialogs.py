"""
Open/Save dialogs for bnarling — simplified from idarling's OpenDialog/SaveDialog.

Binary Ninja manages snapshots inside the BNDB itself, so we expose only
projects and binaries to the user. The idarling server still stores one
server-side "snapshot" per (project, binary); we hardcode it to "default".
"""

import datetime
from functools import partial

from PySide6.QtCore import QRegularExpression, Qt
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..core.core import BINARY_TYPE_BNDB, DEFAULT_SNAPSHOT
from ..shared.commands import (
    CreateBinary,
    CreateProject,
    CreateSnapshot,
    DeleteBinary,
    DeleteProject,
    ListBinaries,
    ListProjects,
    ListSnapshots,
)
from ..shared.models import Binary, Project, Snapshot


try:
    _HV_STRETCH = QHeaderView.ResizeMode.Stretch
except AttributeError:
    _HV_STRETCH = QHeaderView.Stretch


class _ProjectBinaryDialog(QDialog):
    """
    Two-column dialog: projects on the left, binaries on the right, with a
    details panel. Base for both OpenDialog and SaveDialog.
    """

    def __init__(self, plugin, title):
        super().__init__()
        self._plugin = plugin
        self._projects = []
        self._binaries = []

        self.setWindowTitle(title)
        self.resize(900, 500)

        root = QVBoxLayout(self)
        main = QWidget(self)
        grid = QGridLayout(main)
        root.addWidget(main)

        # Projects column
        self._projects_table = QTableWidget(0, 1, self)
        self._projects_table.setHorizontalHeaderLabels(("Projects",))
        self._projects_table.horizontalHeader().setStretchLastSection(True)
        self._projects_table.verticalHeader().setVisible(False)
        self._projects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._projects_table.setSelectionMode(QTableWidget.SingleSelection)
        self._projects_table.itemSelectionChanged.connect(self._project_selected)
        grid.addWidget(self._projects_table, 0, 0)
        grid.setColumnStretch(0, 1)

        # Binaries column
        self._binaries_table = QTableWidget(0, 2, self)
        self._binaries_table.setHorizontalHeaderLabels(("Binary", "Type"))
        self._binaries_table.horizontalHeader().setStretchLastSection(True)
        self._binaries_table.verticalHeader().setVisible(False)
        self._binaries_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._binaries_table.setSelectionMode(QTableWidget.SingleSelection)
        self._binaries_table.itemSelectionChanged.connect(self._binary_selected)
        self._binaries_table.itemDoubleClicked.connect(self._binary_double_clicked)
        grid.addWidget(self._binaries_table, 0, 1)
        grid.setColumnStretch(1, 2)

        # Details panel
        details = QGroupBox("Details", self)
        details_layout = QGridLayout(details)
        self._file_label = QLabel("<b>File:</b>")
        self._hash_label = QLabel("<b>Hash:</b>")
        self._type_label = QLabel("<b>Type:</b>")
        self._date_label = QLabel("<b>Date:</b>")
        details_layout.addWidget(self._file_label, 0, 0)
        details_layout.addWidget(self._hash_label, 1, 0)
        details_layout.addWidget(self._type_label, 0, 1)
        details_layout.addWidget(self._date_label, 1, 1)
        root.addWidget(details)

        # Buttons
        buttons = QHBoxLayout()
        buttons.addStretch()
        self._accept_button = QPushButton("OK")
        self._accept_button.setEnabled(False)
        self._accept_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(cancel_button)
        buttons.addWidget(self._accept_button)
        root.addLayout(buttons)

        # Kick off project listing
        d = self._plugin.network.send_packet(ListProjects.Query())
        if d:
            d.add_callback(self._projects_listed)
            d.add_errback(self._plugin.logger.exception)

    # ---- projects ----

    def _projects_listed(self, reply):
        self._projects = sorted(reply.projects, key=lambda p: p.name)
        self._refresh_projects()

    def _refresh_projects(self):
        self._projects_table.setRowCount(len(self._projects))
        for i, project in enumerate(self._projects):
            item = QTableWidgetItem(project.name)
            item.setData(Qt.UserRole, project)
            item.setFlags(item.flags() & ~Qt.ItemIsEditable)
            self._projects_table.setItem(i, 0, item)

    def _selected_project(self):
        items = self._projects_table.selectedItems()
        return items[0].data(Qt.UserRole) if items else None

    def _project_selected(self):
        project = self._selected_project()
        if project is None:
            return
        self._binaries = []
        self._binaries_table.setRowCount(0)
        self._accept_button.setEnabled(False)
        d = self._plugin.network.send_packet(ListBinaries.Query(project.name))
        if d:
            d.add_callback(self._binaries_listed)
            d.add_errback(self._plugin.logger.exception)
        self._on_project_selected(project)

    # Subclass hook
    def _on_project_selected(self, project):
        pass

    # ---- binaries ----

    def _binaries_listed(self, reply):
        self._binaries = sorted(reply.binaries, key=lambda b: b.name)
        self._refresh_binaries()

    def _refresh_binaries(self):
        self._binaries_table.setRowCount(len(self._binaries))
        for i, binary in enumerate(self._binaries):
            name_item = QTableWidgetItem(binary.name)
            name_item.setData(Qt.UserRole, binary)
            name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
            type_item = QTableWidgetItem(binary.type or "")
            type_item.setData(Qt.UserRole, binary)
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self._binaries_table.setItem(i, 0, name_item)
            self._binaries_table.setItem(i, 1, type_item)
            self._style_binary_row(i, binary)

    def _style_binary_row(self, row, binary):
        """Subclasses can override to enable/disable rows."""
        pass

    def _selected_binary(self):
        items = self._binaries_table.selectedItems()
        return items[0].data(Qt.UserRole) if items else None

    def _binary_selected(self):
        binary = self._selected_binary()
        if binary is None:
            return
        self._file_label.setText("<b>File:</b> %s" % (binary.file or "",))
        self._hash_label.setText("<b>Hash:</b> %s" % (binary.hash or "",))
        self._type_label.setText("<b>Type:</b> %s" % (binary.type or "",))
        self._date_label.setText("<b>Date:</b> %s" % (binary.date or "",))
        self._on_binary_selected(binary)

    def _on_binary_selected(self, binary):
        self._accept_button.setEnabled(True)

    def _binary_double_clicked(self, _item):
        if self._accept_button.isEnabled():
            self.accept()

    # ---- result ----

    def get_result(self):
        return self._selected_project(), self._selected_binary()


class OpenDialog(_ProjectBinaryDialog):
    """Dialog for picking a remote BNDB to download and open."""

    def __init__(self, plugin):
        super().__init__(plugin, "Open from Remote Server")
        self._accept_button.setText("Open")

        delete_project = QPushButton("Delete Project")
        delete_project.clicked.connect(self._delete_project)
        delete_binary = QPushButton("Delete Binary")
        delete_binary.clicked.connect(self._delete_binary)
        extras = QHBoxLayout()
        extras.addWidget(delete_project)
        extras.addWidget(delete_binary)
        extras.addStretch()
        # Insert extras row between main grid and details — we put it at the
        # bottom for simplicity.
        self.layout().insertLayout(1, extras)

    def _style_binary_row(self, row, binary):
        if binary.type != BINARY_TYPE_BNDB:
            # Non-BNDB entries (IDA) are greyed out but still visible so
            # users can see what's on the server.
            for col in range(self._binaries_table.columnCount()):
                item = self._binaries_table.item(row, col)
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _on_binary_selected(self, binary):
        # Only BNDB binaries can be opened from Binary Ninja.
        self._accept_button.setEnabled(binary.type == BINARY_TYPE_BNDB)

    def _delete_project(self):
        project = self._selected_project()
        if project is None:
            return
        d = self._plugin.network.send_packet(DeleteProject.Query(project.name))
        if d:
            d.add_callback(partial(self._project_deleted, project))
            d.add_errback(self._plugin.logger.exception)

    def _project_deleted(self, project, reply):
        if not reply.deleted:
            QMessageBox.warning(
                self,
                "bnarling",
                "Unable to delete project (maybe another client is connected?)",
            )
            return
        self._projects = [p for p in self._projects if p.name != project.name]
        self._refresh_projects()
        self._binaries = []
        self._refresh_binaries()

    def _delete_binary(self):
        project = self._selected_project()
        binary = self._selected_binary()
        if project is None or binary is None:
            return
        d = self._plugin.network.send_packet(
            DeleteBinary.Query(project.name, binary.name)
        )
        if d:
            d.add_callback(partial(self._binary_deleted, binary))
            d.add_errback(self._plugin.logger.exception)

    def _binary_deleted(self, binary, reply):
        if not reply.deleted:
            QMessageBox.warning(
                self,
                "bnarling",
                "Unable to delete binary (maybe another client is connected?)",
            )
            return
        self._binaries = [b for b in self._binaries if b.name != binary.name]
        self._refresh_binaries()


class SaveDialog(_ProjectBinaryDialog):
    """Dialog for picking / creating a project+binary to upload the current BNDB to."""

    def __init__(self, plugin, bndb_name=None, bndb_hash=None):
        super().__init__(plugin, "Save to Remote Server")
        self._accept_button.setText("Save")
        self._bndb_name = bndb_name or ""
        self._bndb_hash = bndb_hash or ""

        create_project = QPushButton("Create Project")
        create_project.clicked.connect(self._create_project)
        self._create_binary_button = QPushButton("Create Binary")
        self._create_binary_button.setEnabled(False)
        self._create_binary_button.clicked.connect(self._create_binary)

        extras = QHBoxLayout()
        extras.addWidget(create_project)
        extras.addWidget(self._create_binary_button)
        extras.addStretch()
        self.layout().insertLayout(1, extras)

    def _on_project_selected(self, project):
        self._create_binary_button.setEnabled(True)

    def _style_binary_row(self, row, binary):
        # Non-BNDB or hash-mismatched binaries are disabled; you should not
        # be overwriting an IDB with a BNDB, or mixing two different files.
        if binary.type != BINARY_TYPE_BNDB or (
            self._bndb_hash and binary.hash and binary.hash != self._bndb_hash
        ):
            for col in range(self._binaries_table.columnCount()):
                item = self._binaries_table.item(row, col)
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)

    def _on_binary_selected(self, binary):
        allow = binary.type == BINARY_TYPE_BNDB and (
            not self._bndb_hash or not binary.hash or binary.hash == self._bndb_hash
        )
        self._accept_button.setEnabled(allow)

    # ---- creation ----

    def _create_project(self):
        dialog = _NameDialog("Create Project", "Project name", self)
        if dialog.exec_() != QDialog.Accepted:
            return
        name = dialog.get_name()
        if not name:
            return
        if any(p.name == name for p in self._projects):
            QMessageBox.warning(self, "bnarling", "A project with that name already exists.")
            return
        date = datetime.datetime.now().strftime("%Y/%m/%d %H:%M")
        project = Project(name, date)
        d = self._plugin.network.send_packet(CreateProject.Query(project))
        if d:
            d.add_callback(partial(self._project_created, project))
            d.add_errback(self._plugin.logger.exception)

    def _project_created(self, project, _reply):
        self._projects.append(project)
        self._projects = sorted(self._projects, key=lambda p: p.name)
        self._refresh_projects()
        for row in range(self._projects_table.rowCount()):
            item = self._projects_table.item(row, 0)
            if item.data(Qt.UserRole).name == project.name:
                self._projects_table.selectRow(row)
                break

    def _create_binary(self):
        project = self._selected_project()
        if project is None:
            return
        dialog = _NameDialog(
            "Create Binary", "Binary name", self, default=self._bndb_name
        )
        if dialog.exec_() != QDialog.Accepted:
            return
        name = dialog.get_name()
        if not name:
            return
        if any(b.name == name for b in self._binaries):
            QMessageBox.warning(self, "bnarling", "A binary with that name already exists.")
            return
        date = datetime.datetime.now().strftime("%Y/%m/%d %H:%M")
        binary = Binary(
            project.name,
            name,
            self._bndb_hash,
            self._bndb_name,
            BINARY_TYPE_BNDB,
            date,
        )
        d = self._plugin.network.send_packet(CreateBinary.Query(binary))
        if d:
            d.add_callback(partial(self._binary_created, binary))
            d.add_errback(self._plugin.logger.exception)

    def _binary_created(self, binary, _reply):
        self._binaries.append(binary)
        self._binaries = sorted(self._binaries, key=lambda b: b.name)
        self._refresh_binaries()
        for row in range(self._binaries_table.rowCount()):
            item = self._binaries_table.item(row, 0)
            if item.data(Qt.UserRole).name == binary.name:
                self._binaries_table.selectRow(row)
                break


class _NameDialog(QDialog):
    """Small dialog asking the user for a single name."""

    def __init__(self, title, label, parent=None, default=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("<b>%s</b>" % label))
        self._edit = QLineEdit(default)
        self._edit.setValidator(
            QRegularExpressionValidator(QRegularExpression(r"[a-zA-Z0-9_.\-]+"))
        )
        layout.addWidget(self._edit)

        buttons = QHBoxLayout()
        buttons.addStretch()
        ok_button = QPushButton("Create")
        ok_button.clicked.connect(self.accept)
        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        buttons.addWidget(cancel_button)
        buttons.addWidget(ok_button)
        layout.addLayout(buttons)

    def get_name(self):
        return self._edit.text().strip()


def ensure_default_snapshot(plugin, project_name, binary_name, on_done, on_error=None):
    """
    Ensure that a "default" snapshot exists for (project, binary) on the server,
    then call on_done(). Used by the save flow before uploading.
    """

    def snapshots_listed(reply):
        if any(s.name == DEFAULT_SNAPSHOT for s in reply.snapshots):
            on_done()
            return
        date = datetime.datetime.now().strftime("%Y/%m/%d %H:%M")
        snap = Snapshot(project_name, binary_name, DEFAULT_SNAPSHOT, date, 0)
        cd = plugin.network.send_packet(CreateSnapshot.Query(snap))
        if cd:
            cd.add_callback(lambda _r: on_done())
            cd.add_errback(on_error or plugin.logger.exception)

    d = plugin.network.send_packet(ListSnapshots.Query(project_name, binary_name))
    if d:
        d.add_callback(snapshots_listed)
        d.add_errback(on_error or plugin.logger.exception)
