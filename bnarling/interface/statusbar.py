"""
Permanent footer label in BN's main window status bar.

Shows the currently connected server (or a dim 'bnarling: offline' marker
when disconnected), similar to BN's enterprise-mode server indicator.
"""

from binaryninjaui import UIContext
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel


class StatusBar:
    def __init__(self, plugin):
        self._plugin = plugin
        self._label = None

    def install(self):
        self._ensure_label()
        self.refresh()

    def uninstall(self):
        if self._label is None:
            return
        try:
            self._label.setParent(None)
            self._label.deleteLater()
        except Exception:
            pass
        self._label = None

    def _ensure_label(self):
        if self._label is not None:
            return True
        try:
            ctx = UIContext.activeContext()
            if ctx is None:
                return False
            main = ctx.mainWindow()
            if main is None:
                return False
            sb = main.statusBar()
            if sb is None:
                return False
            label = QLabel()
            label.setTextFormat(Qt.RichText)
            label.setContentsMargins(8, 0, 8, 0)
            sb.addPermanentWidget(label)
            self._label = label
            return True
        except Exception as e:
            self._plugin.logger.debug("statusbar install failed: %s" % e)
            return False

    def refresh(self):
        if not self._ensure_label():
            return
        network = self._plugin.network
        core = self._plugin.core
        try:
            if network.connected and network.server:
                host = network.server["host"]
                port = network.server["port"]
                if core.project and core.binary:
                    text = (
                        "<span style='color:#2ecc71;'>&#9679;</span> "
                        "<b>bnarling</b> %s:%d — %s / %s"
                        % (host, port, core.project, core.binary)
                    )
                else:
                    text = (
                        "<span style='color:#2ecc71;'>&#9679;</span> "
                        "<b>bnarling</b> %s:%d" % (host, port)
                    )
            elif network.client:
                text = (
                    "<span style='color:#f39c12;'>&#9679;</span> "
                    "<b>bnarling</b> connecting…"
                )
            else:
                text = (
                    "<span style='color:#7f8c8d;'>&#9679;</span> "
                    "<b>bnarling</b> offline"
                )
            self._label.setText(text)
        except Exception as e:
            self._plugin.logger.debug("statusbar refresh failed: %s" % e)
