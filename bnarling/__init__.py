"""
bnarling — Binary Ninja port of the idarling client.

Connects Binary Ninja to an idarling server for collaborative reverse
engineering: presence, real-time cursor sharing, follow-the-user, and
invites. Database-level events (renames, types, etc.) are NOT synced
because BN and IDA don't share an event model.
"""

try:
    import binaryninjaui  # noqa: F401
    _UI_AVAILABLE = True
except ImportError:
    _UI_AVAILABLE = False


_plugin = None


def _get_plugin():
    global _plugin
    if _plugin is None and _UI_AVAILABLE:
        from .plugin import BnarlingPlugin

        instance = BnarlingPlugin()
        if instance.init():
            _plugin = instance
    return _plugin


# Instantiate at import time so the sidebar widget is registered and
# auto-connect can fire as soon as Binary Ninja loads the plugin.
_get_plugin()
