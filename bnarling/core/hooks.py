"""
Binary Ninja UI hooks that feed the core module:
  - active BinaryView changes (so we can load session metadata)
  - cursor / address changes (so we can send UpdateLocation)
"""

from binaryninjaui import UIContext, UIContextNotification


class BnHooks(UIContextNotification):
    """Bridges BN UIContext events into the core module."""

    def __init__(self, plugin):
        UIContextNotification.__init__(self)
        self._plugin = plugin
        self._last_ea = None

    def install(self):
        UIContext.registerNotification(self)
        self._plugin.logger.debug("Installed UIContext notifications")
        # The plugin may be loaded after a file is already open (e.g. reload
        # or first-time install); snap to whatever's active right now.
        self._snap_to_current_view()

    def uninstall(self):
        try:
            UIContext.unregisterNotification(self)
        except Exception:
            pass

    def _snap_to_current_view(self):
        try:
            ctx = UIContext.activeContext()
            if ctx is None:
                return
            frame = ctx.getCurrentViewFrame()
            if frame is None:
                return
            view = frame.getCurrentViewInterface().getData()
            self._plugin.core.set_view(view)
            if view is not None:
                self._plugin.core.join_session()
        except Exception as e:
            self._plugin.logger.debug("snap_to_current_view failed: %s" % e)

    # --- view lifecycle ---

    def OnAfterOpenFile(self, context, file, frame):  # noqa: N802
        try:
            view = frame.getCurrentViewInterface().getData()
        except Exception:
            view = None
        self._plugin.core.set_view(view)
        if view is not None:
            self._plugin.core.join_session()

    def OnViewChange(self, context, frame, type_):  # noqa: N802
        if frame is None:
            self._plugin.core.set_view(None)
            return
        try:
            view = frame.getCurrentViewInterface().getData()
        except Exception:
            view = None
        prev = self._plugin.core._view
        self._plugin.core.set_view(view)
        # If we actually switched to a different BV that has session info,
        # re-join. (set_view is a no-op when the view didn't change.)
        if view is not None and view is not prev:
            self._plugin.core.join_session()

    def OnBeforeCloseFile(self, context, file, frame):  # noqa: N802
        self._plugin.core.leave_session()
        return True

    # --- cursor tracking ---

    def OnAddressChange(self, context, frame, view, location):  # noqa: N802
        try:
            ea = location.getOffset()
        except Exception:
            return
        if ea == self._last_ea:
            return
        self._last_ea = ea
        self._plugin.core.notify_location(ea)
