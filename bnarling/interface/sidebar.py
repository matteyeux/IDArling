import time
from functools import partial

from binaryninjaui import (
    Sidebar,
    SidebarContextSensitivity,
    SidebarWidget,
    SidebarWidgetLocation,
    SidebarWidgetType,
    UIActionHandler,
)
from PySide6.QtCore import Qt, QRectF, QSize, QTimer
from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ..shared.commands import InviteToLocation
from .actions import open_from_server, save_to_server
from .settings import SettingsDialog, ida_color_to_qcolor


def _user_dot(color):
    """Build a 10x10 round color-swatch QPixmap for a user's sidebar row."""
    pm = QPixmap(10, 10)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(ida_color_to_qcolor(color))
    p.drawEllipse(0, 0, 10, 10)
    p.end()
    return pm


def _section_header(text):
    lbl = QLabel(text)
    lbl.setStyleSheet(
        "font-weight: bold; text-transform: uppercase; letter-spacing: 1px;"
    )
    return lbl


def _hline():
    f = QFrame()
    f.setFrameShape(QFrame.HLine)
    f.setFrameShadow(QFrame.Sunken)
    return f


class BnarlingSidebarWidget(SidebarWidget):
    """Main sidebar panel: connection state, session info, user list."""

    def __init__(self, plugin, name):
        SidebarWidget.__init__(self, name)
        self._plugin = plugin
        self.actionHandler = UIActionHandler()
        self.actionHandler.setupActionHandler(self)

        root = QVBoxLayout()
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # --- connection block ---
        root.addWidget(_section_header("Connection"))

        self._status_label = QLabel("Disconnected")
        self._status_label.setTextFormat(Qt.RichText)
        root.addWidget(self._status_label)

        self._server_label = QLabel("No server")
        self._server_label.setWordWrap(True)
        root.addWidget(self._server_label)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(4)
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._connect_clicked)
        self._settings_btn = QPushButton("Settings")
        self._settings_btn.clicked.connect(self._settings_clicked)
        btn_row.addWidget(self._connect_btn)
        btn_row.addWidget(self._settings_btn)
        btn_wrap = QWidget()
        btn_wrap.setLayout(btn_row)
        root.addWidget(btn_wrap)

        root.addWidget(_hline())

        # --- session block ---
        root.addWidget(_section_header("Session"))

        self._session_label = QLabel("No session")
        self._session_label.setWordWrap(True)
        self._session_label.setTextFormat(Qt.RichText)
        root.addWidget(self._session_label)

        remote_row = QHBoxLayout()
        remote_row.setSpacing(4)
        self._open_btn = QPushButton("Open from server…")
        self._open_btn.clicked.connect(self._open_clicked)
        self._save_btn = QPushButton("Save to server…")
        self._save_btn.clicked.connect(self._save_clicked)
        remote_row.addWidget(self._open_btn)
        remote_row.addWidget(self._save_btn)
        remote_wrap = QWidget()
        remote_wrap.setLayout(remote_row)
        root.addWidget(remote_wrap)

        root.addWidget(_hline())

        # --- users block ---
        users_header = QHBoxLayout()
        users_header.setContentsMargins(0, 0, 0, 0)
        users_header.addWidget(_section_header("Users"))
        users_header.addStretch(1)
        self._users_count = QLabel("0")
        users_header.addWidget(self._users_count)
        users_header_wrap = QWidget()
        users_header_wrap.setLayout(users_header)
        root.addWidget(users_header_wrap)

        self._users_list = QListWidget()
        self._users_list.setIconSize(QSize(10, 10))
        self._users_list.setFrameShape(QFrame.NoFrame)
        self._users_list.itemDoubleClicked.connect(self._user_double_clicked)
        self._users_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self._users_list.customContextMenuRequested.connect(self._users_menu)
        root.addWidget(self._users_list, 1)

        self.setLayout(root)

        self._plugin.interface.register_widget(self)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

        self.refresh()

    # ---- BN callbacks ----

    def notifyViewChanged(self, view_frame):  # noqa: N802
        if view_frame is None:
            self._plugin.core.set_view(None)
            return
        try:
            view = view_frame.getCurrentViewInterface().getData()
        except Exception:
            view = None
        self._plugin.core.set_view(view)
        self.refresh()

    def notifyOffsetChanged(self, offset):  # noqa: N802
        self._plugin.core.notify_location(offset)

    # ---- UI actions ----

    def _connect_clicked(self):
        network = self._plugin.network
        if network.connected or network.client:
            network.disconnect()
            return
        servers = self._plugin.config["servers"]
        if not servers:
            self._settings_clicked()
            return
        menu = QMenu(self)
        for server in servers:
            action = menu.addAction("%s:%d" % (server["host"], server["port"]))
            action.triggered.connect(partial(network.connect, server))
        disc = self._plugin.network.discovery.servers
        disc = [s for s, t in disc if time.time() - t < 10.0]
        disc = [s for s in disc if s not in servers]
        if disc:
            menu.addSeparator()
            for server in disc:
                action = menu.addAction(
                    "Discovered %s:%d" % (server["host"], server["port"])
                )
                action.triggered.connect(partial(network.connect, server))
        menu.exec_(self._connect_btn.mapToGlobal(self._connect_btn.rect().bottomLeft()))

    def _settings_clicked(self):
        SettingsDialog(self._plugin, parent=self).exec_()
        self.refresh()

    def _open_clicked(self):
        open_from_server(self._plugin, parent=self)

    def _save_clicked(self):
        save_to_server(self._plugin, parent=self)

    def _user_double_clicked(self, item):
        name = item.data(Qt.UserRole)
        user = self._plugin.core.get_user(name)
        if user is not None:
            self._plugin.interface.jumpto(user["ea"])

    def _users_menu(self, point):
        item = self._users_list.itemAt(point)
        menu = QMenu(self)
        interface = self._plugin.interface
        followed = interface.followed

        if item is not None:
            name = item.data(Qt.UserRole)
            jump = menu.addAction("Jump to %s" % name)
            jump.triggered.connect(lambda: self._user_double_clicked(item))
            menu.addSeparator()
            follow = menu.addAction("Follow %s" % name)
            follow.setCheckable(True)
            follow.setChecked(followed == name)
            follow.triggered.connect(
                lambda: setattr(interface, "followed", None if followed == name else name)
            )
            follow_all = menu.addAction("Follow everyone")
            follow_all.setCheckable(True)
            follow_all.setChecked(followed == "everyone")
            follow_all.triggered.connect(
                lambda: setattr(
                    interface,
                    "followed",
                    None if followed == "everyone" else "everyone",
                )
            )
            menu.addSeparator()
            invite = menu.addAction("Invite %s here" % name)
            invite.triggered.connect(partial(self._invite_user, name))

        invite_all = menu.addAction("Invite everyone here")
        invite_all.triggered.connect(partial(self._invite_user, "everyone"))

        if followed is not None:
            menu.addSeparator()
            stop = menu.addAction("Stop following")
            stop.triggered.connect(lambda: setattr(interface, "followed", None))

        menu.exec_(self._users_list.mapToGlobal(point))

    def _invite_user(self, name):
        invite_here(self._plugin, name)

    # ---- refresh ----

    def refresh(self):
        network = self._plugin.network
        if network.connected:
            self._status_label.setText(
                "<span style='color:#2ecc71;'>&#9679;</span> <b>Connected</b>"
            )
        elif network.client:
            self._status_label.setText(
                "<span style='color:#f39c12;'>&#9679;</span> <b>Connecting…</b>"
            )
        else:
            self._status_label.setText(
                "<span style='color:#e74c3c;'>&#9679;</span> <b>Disconnected</b>"
            )

        if network.server:
            self._server_label.setText(
                "%s:%d" % (network.server["host"], network.server["port"])
            )
        else:
            self._server_label.setText("No server")

        core = self._plugin.core
        if core.project or core.binary or core.snapshot:
            self._session_label.setText(
                "<b>Project:</b> %s<br>"
                "<b>Binary:</b> %s<br>"
                "<b>Snapshot:</b> %s"
                % (core.project or "?", core.binary or "?", core.snapshot or "?")
            )
        else:
            self._session_label.setText(
                "<i>No session — use <b>Open from server</b> or "
                "<b>Save to server</b>.</i>"
            )

        self._connect_btn.setText(
            "Disconnect" if (network.connected or network.client) else "Connect"
        )
        self._open_btn.setEnabled(network.connected)
        self._save_btn.setEnabled(network.connected)

        users = core.get_users()
        self._users_count.setText(str(len(users)))
        self._users_list.clear()
        for name, user in users.items():
            ea = user.get("ea", 0) or 0
            label = "%s — 0x%x" % (name, ea)
            if self._plugin.interface.followed in (name, "everyone"):
                label += "  (following)"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, name)
            item.setIcon(_user_dot(user.get("color", 0)))
            self._users_list.addItem(item)

    def contextMenuEvent(self, event):  # noqa: N802
        self.m_contextMenuManager.show(self.m_menu, self.actionHandler)


# ---- shared "Invite here" command ----


def invite_here(plugin, target):
    """Send an InviteToLocation for the current address to `target`
    (a user name, or "everyone")."""
    if not plugin.network.connected:
        plugin.logger.info("Not connected; can't invite")
        return
    if not plugin.core.session_joined:
        plugin.logger.info("Not in a session; can't invite")
        return
    ea = plugin.interface.current_ea()
    plugin.network.send_packet(InviteToLocation(target, ea))
    plugin.logger.info("Invited %s to 0x%x" % (target, ea))


class BnarlingSidebarWidgetType(SidebarWidgetType):
    """Registers the bnarling sidebar widget type."""

    _plugin = None
    NAME = "bnarling"

    def __init__(self, plugin):
        BnarlingSidebarWidgetType._plugin = plugin
        icon = QImage(56, 56, QImage.Format_RGB32)
        icon.fill(0)
        p = QPainter()
        p.begin(icon)
        p.setFont(QFont("Open Sans", 40))
        p.setPen(QColor(255, 255, 255, 255))
        p.drawText(QRectF(0, 0, 56, 56), Qt.AlignCenter, "bN")
        p.end()
        SidebarWidgetType.__init__(self, icon, self.NAME)

    def createWidget(self, frame, data):  # noqa: N802
        return BnarlingSidebarWidget(BnarlingSidebarWidgetType._plugin, self.NAME)

    def defaultLocation(self):  # noqa: N802
        return SidebarWidgetLocation.RightContent

    def contextSensitivity(self):  # noqa: N802
        return SidebarContextSensitivity.SelfManagedSidebarContext


def register(plugin):
    Sidebar.addSidebarWidgetType(BnarlingSidebarWidgetType(plugin))
