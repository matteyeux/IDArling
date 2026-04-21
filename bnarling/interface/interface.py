import binaryninja
from binaryninjaui import UIContext

from ..module import Module
from .painter import Painter
from .statusbar import StatusBar
from . import sidebar


class Interface(Module):
    """Coordinates the BN-facing UI: sidebar widget, status bar, user follow."""

    def __init__(self, plugin):
        super(Interface, self).__init__(plugin)
        self._followed = None
        self._widgets = []
        self._registered = False
        self._painter = Painter(plugin)
        self._statusbar = StatusBar(plugin)

    @property
    def painter(self):
        return self._painter

    @property
    def statusbar(self):
        return self._statusbar

    def _install(self):
        if not self._registered:
            sidebar.register(self._plugin)
            self._registered = True
        self._statusbar.install()
        return True

    def _uninstall(self):
        self._statusbar.uninstall()
        self._widgets = []
        return True

    # --- properties ---

    @property
    def followed(self):
        return self._followed

    @followed.setter
    def followed(self, value):
        self._followed = value
        self.refresh()

    def register_widget(self, widget):
        self._widgets.append(widget)

    # --- notifications (now just logged) ---

    def show_invite(self, text, color=None, callback=None):
        """Surface a notification in the BN log. `color` and `callback` are
        accepted for API compatibility with the IDA side but ignored."""
        if not self._plugin.config["user"].get("notifications", True):
            return
        self._plugin.logger.info(text)
        try:
            binaryninja.log_info("[bnarling] %s" % text)
        except Exception:
            pass

    def clear_invites(self):
        # Kept as a no-op so existing callers (e.g. Client.terminate) don't
        # need to know the invites list is gone.
        pass

    # --- navigation ---

    def current_ea(self):
        try:
            ctx = UIContext.activeContext()
            if ctx is None:
                return 0
            frame = ctx.getCurrentViewFrame()
            if frame is None:
                return 0
            return frame.getCurrentOffset()
        except Exception:
            return 0

    def jumpto(self, ea):
        try:
            ctx = UIContext.activeContext()
            if ctx is None:
                return
            frame = ctx.getCurrentViewFrame()
            if frame is None:
                return
            view_name = frame.getCurrentView() or "Linear:"
            frame.navigate(view_name, ea, True, True)
        except Exception as e:
            self._plugin.logger.debug("jumpto failed: %s" % e)

    # --- refresh ---

    def update(self):
        self._statusbar.refresh()
        self.refresh()

    def refresh(self):
        self._statusbar.refresh()
        for widget in list(self._widgets):
            try:
                widget.refresh()
            except RuntimeError:
                # widget was deleted by Qt
                self._widgets.remove(widget)
            except Exception as e:
                self._plugin.logger.debug("widget refresh failed: %s" % e)
