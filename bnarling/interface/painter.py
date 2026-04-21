"""
User-cursor painter for bnarling.

Highlights the instruction at each remote user's current address in the
active BinaryView, colored with that user's color. Uses BN's auto-instr
highlight API (session-only, not persisted to the BNDB).
"""

from .settings import ida_color_to_qcolor


def _ida_color_to_rgb(c):
    return c & 0xFF, (c >> 8) & 0xFF, (c >> 16) & 0xFF


class Painter(object):
    """Paints remote users' cursors as instruction highlights in BN."""

    def __init__(self, plugin):
        self._plugin = plugin
        self._view = None
        self._highlights = {}  # name -> (function, ea)

    # --- view lifecycle ---

    def set_view(self, view):
        # Clearing highlights on the previous view is unnecessary — auto
        # highlights are tied to the Function object from that view and
        # don't leak across BVs. Just drop our bookkeeping.
        self._highlights.clear()
        self._view = view
        for name, user in self._plugin.core.get_users().items():
            self._paint(name, user.get("ea", 0) or 0, user.get("color", 0) or 0)

    # --- user events ---

    def update_user(self, name, ea, color):
        """Repaint a user's cursor at a new address."""
        self._clear(name)
        self._paint(name, ea, color)

    def clear_user(self, name):
        """Remove a user's cursor (e.g. they left the session)."""
        self._clear(name)

    def clear_all(self):
        for name in list(self._highlights.keys()):
            self._clear(name)

    # --- internals ---

    def _paint(self, name, ea, color):
        if self._view is None or not ea or not color:
            return
        try:
            from binaryninja import HighlightColor

            funcs = self._view.get_functions_containing(ea)
            if not funcs:
                return
            func = funcs[0]
            r, g, b = _ida_color_to_rgb(color)
            hl = HighlightColor(red=r, green=g, blue=b, alpha=192)
            func.set_auto_instr_highlight(ea, hl)
            self._highlights[name] = (func, ea)
        except Exception as e:
            self._plugin.logger.debug("paint failed: %s" % e)

    def _clear(self, name):
        prev = self._highlights.pop(name, None)
        if prev is None:
            return
        func, ea = prev
        try:
            from binaryninja import HighlightColor, HighlightStandardColor

            func.set_auto_instr_highlight(
                ea,
                HighlightColor(color=HighlightStandardColor.NoHighlightColor),
            )
        except Exception as e:
            self._plugin.logger.debug("clear failed: %s" % e)

    # --- colour helper re-exported for sidebar use ---

    @staticmethod
    def color_to_qcolor(c):
        return ida_color_to_qcolor(c)
