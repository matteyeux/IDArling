from ..module import Module
from ..shared.commands import (
    JoinSession,
    LeaveSession,
    ListSnapshots,
    UpdateLocation,
)


METADATA_PROJECT = "bnarling_project"
METADATA_BINARY = "bnarling_binary"
METADATA_SNAPSHOT = "bnarling_snapshot"
METADATA_TICK = "bnarling_tick"

# Binary Ninja manages its own snapshots inside a BNDB, so from the
# idarling-server point of view every BN binary has exactly one snapshot.
DEFAULT_SNAPSHOT = "default"
BINARY_TYPE_BNDB = "BNDB"


class Core(Module):
    """
    Tracks the current collaborative session: which (project, binary, snapshot)
    the active BinaryView belongs to, which users are currently connected,
    and the per-session tick counter.

    Unlike the IDA core module, this one does not hook database events — BN
    cannot replay IDA-flavoured events, so the BN client participates only
    for presence/location/invites.
    """

    def __init__(self, plugin):
        super(Core, self).__init__(plugin)
        self._project = None
        self._binary = None
        self._snapshot = None
        self._tick = 0
        self._users = {}
        self._session_joined = False
        self._view = None
        # Paths → (project, binary) for files freshly downloaded from the
        # server; consumed the first time OnAfterOpenFile fires for them.
        self._pending_metadata = {}

    @property
    def project(self):
        return self._project

    @project.setter
    def project(self, value):
        self._project = value
        self._save_metadata(METADATA_PROJECT, value)

    @property
    def binary(self):
        return self._binary

    @binary.setter
    def binary(self, value):
        self._binary = value
        self._save_metadata(METADATA_BINARY, value)

    @property
    def snapshot(self):
        return self._snapshot

    @snapshot.setter
    def snapshot(self, value):
        self._snapshot = value
        self._save_metadata(METADATA_SNAPSHOT, value)

    @property
    def tick(self):
        return self._tick

    @tick.setter
    def tick(self, value):
        self._tick = value
        self._save_metadata(METADATA_TICK, str(value))

    @property
    def session_joined(self):
        return self._session_joined

    def set_view(self, view):
        """Called when the active BN view changes."""
        if view is self._view:
            return
        self.leave_session()
        self._view = view
        self._load_metadata()
        self._apply_pending_metadata()
        self._plugin.interface.painter.set_view(view)
        self._plugin.logger.debug(
            "set_view → project=%s binary=%s snapshot=%s"
            % (self._project, self._binary, self._snapshot)
        )

    def _install(self):
        return True

    def _uninstall(self):
        self.leave_session()
        return True

    # --- users ---

    def add_user(self, name, user):
        self._users[name] = user
        self._plugin.interface.refresh()

    def remove_user(self, name):
        user = self._users.pop(name, None)
        self._plugin.interface.refresh()
        return user

    def get_user(self, name):
        return self._users.get(name)

    def get_users(self):
        return self._users

    def clear_users(self):
        self._users = {}
        self._plugin.interface.refresh()

    # --- download registry (path → pending project/binary) ---

    def remember_downloaded(self, path, project, binary):
        self._pending_metadata[path] = (project, binary)

    def _apply_pending_metadata(self):
        if self._view is None:
            return
        try:
            path = self._view.file.filename
        except Exception:
            return
        pending = self._pending_metadata.pop(path, None)
        if pending is None:
            # Also match .bndb / no-.bndb variants
            for registered, value in list(self._pending_metadata.items()):
                if registered == path or registered.rstrip(".bndb") == path.rstrip(".bndb"):
                    pending = self._pending_metadata.pop(registered)
                    break
        if pending is None:
            return
        project, binary = pending
        self.project = project
        self.binary = binary
        self.snapshot = DEFAULT_SNAPSHOT
        self.tick = 0

    # --- metadata ---

    def _save_metadata(self, key, value):
        if self._view is None or value is None:
            return
        try:
            self._view.store_metadata(key, str(value))
        except Exception as e:
            self._plugin.logger.debug("store_metadata failed: %s" % e)

    def _load_metadata(self):
        self._project = None
        self._binary = None
        self._snapshot = None
        self._tick = 0
        if self._view is None:
            return
        try:
            self._project = self._view.query_metadata(METADATA_PROJECT)
        except Exception:
            pass
        try:
            self._binary = self._view.query_metadata(METADATA_BINARY)
        except Exception:
            pass
        try:
            self._snapshot = self._view.query_metadata(METADATA_SNAPSHOT)
        except Exception:
            pass
        try:
            self._tick = int(self._view.query_metadata(METADATA_TICK) or "0")
        except Exception:
            self._tick = 0

    # --- session lifecycle ---

    def join_session(self):
        if self._session_joined:
            self._plugin.logger.debug("Already joined; skipping join_session")
            return
        if not (self._project and self._binary and self._snapshot):
            self._plugin.logger.info(
                "No session metadata on this BNDB (project=%r binary=%r "
                "snapshot=%r); use Open/Save from server to associate it."
                % (self._project, self._binary, self._snapshot)
            )
            self._session_joined = False
            return

        if not self._plugin.network.connected:
            self._plugin.logger.debug("Not connected, deferring session join")
            return

        self._plugin.logger.info(
            "Joining session %s/%s/%s"
            % (self._project, self._binary, self._snapshot)
        )

        def snapshots_listed(reply):
            if not any(d.name == self._snapshot for d in reply.snapshots):
                self._plugin.logger.warning(
                    "Snapshot %s not on server" % self._snapshot
                )
                return
            name = self._plugin.config["user"]["name"]
            color = self._plugin.config["user"]["color"]
            ea = self._plugin.interface.current_ea()
            self._plugin.network.send_packet(
                JoinSession(
                    self._project,
                    self._binary,
                    self._snapshot,
                    self._tick,
                    name,
                    color,
                    ea,
                )
            )
            self._session_joined = True
            self._users.clear()
            self._plugin.interface.refresh()
            self._plugin.logger.info("Joined as %s" % name)

        d = self._plugin.network.send_packet(
            ListSnapshots.Query(self._project, self._binary)
        )
        if d:
            d.add_callback(snapshots_listed)
            d.add_errback(self._plugin.logger.exception)

    def leave_session(self):
        if not self._session_joined:
            return
        self._plugin.logger.debug("Leaving session")
        if self._project and self._binary and self._snapshot:
            name = self._plugin.config["user"]["name"]
            self._plugin.network.send_packet(LeaveSession(name))
        self._users.clear()
        self._session_joined = False

    def notify_location(self, ea):
        """Called by the UI hook when the cursor moves."""
        if not self._session_joined or not self._plugin.network.connected:
            return
        name = self._plugin.config["user"]["name"]
        color = self._plugin.config["user"]["color"]
        self._plugin.network.send_packet(UpdateLocation(name, ea, color))
