# Binary Ninja client adapted from idarling/network/client.py
from ..shared.commands import (
    InviteToLocation,
    JoinSession,
    LeaveSession,
    UpdateLocation,
    UpdateUserColor,
    UpdateUserName,
    DeleteProject,
    DeleteBinary,
    DeleteSnapshot,
)
from ..shared.packets import Command, Event
from ..shared.sockets import ClientSocket


class Client(ClientSocket):
    """
    Client socket for Binary Ninja. Handles the subset of server commands
    that make sense outside IDA (presence, invites, session membership).
    Database sync events from IDA are not applied to a BN view — they are
    simply dropped so the BN client can still coexist in a session.
    """

    def __init__(self, plugin, parent=None):
        ClientSocket.__init__(self, plugin.logger, parent)
        self._plugin = plugin

        self._handlers = {
            JoinSession: self._handle_join_session,
            LeaveSession: self._handle_leave_session,
            UpdateLocation: self._handle_update_location,
            InviteToLocation: self._handle_invite_to_location,
            UpdateUserName: self._handle_update_user_name,
            UpdateUserColor: self._handle_update_user_color,
            DeleteProject: self._handle_delete,
            DeleteBinary: self._handle_delete,
            DeleteSnapshot: self._handle_delete,
        }

    def recv_packet(self, packet):
        if isinstance(packet, Command):
            handler = self._handlers.get(packet.__class__)
            if handler is not None:
                handler(packet)
            else:
                self._logger.debug("Unhandled command: %s" % packet)
        elif isinstance(packet, Event):
            # Binary Ninja does not replay IDA IDB events — drop silently.
            self._logger.debug("Dropping IDA event: %s" % packet)
        else:
            return False
        return True

    def send_packet(self, packet):
        if isinstance(packet, Event):
            # We don't originate IDA events from BN, but be safe.
            self._plugin.core.tick += 1
            packet.tick = self._plugin.core.tick
        return ClientSocket.send_packet(self, packet)

    def terminate(self, err=None):
        ret = ClientSocket.close_connection(self, err)
        self._plugin.network._client = None
        self._plugin.network._server = None
        self._plugin.interface.update()
        self._plugin.interface.clear_invites()
        self._plugin.interface.painter.clear_all()
        self._plugin.core.clear_users()
        return ret

    def _check_socket(self):
        was_connected = self._connected
        ret = ClientSocket._check_socket(self)
        if not was_connected and self._connected:
            self._plugin.interface.update()
            self._plugin.core.join_session()
        return ret

    def _handle_join_session(self, packet):
        user = {"color": packet.color, "ea": packet.ea}
        self._plugin.core.add_user(packet.name, user)
        self._plugin.interface.painter.update_user(
            packet.name, packet.ea, packet.color
        )
        if packet.silent:
            return
        self._plugin.interface.show_invite(
            "%s joined the session" % packet.name, packet.color
        )

    def _handle_leave_session(self, packet):
        user = self._plugin.core.remove_user(packet.name)
        self._plugin.interface.painter.clear_user(packet.name)
        if packet.silent or user is None:
            return
        self._plugin.interface.show_invite(
            "%s left the session" % packet.name, user.get("color", 0)
        )

    def _handle_invite_to_location(self, packet):
        text = "%s - Jump to 0x%x" % (packet.name, packet.loc)

        def callback():
            self._plugin.interface.jumpto(packet.loc)

        self._plugin.interface.show_invite(text, None, callback)

    def _handle_update_user_name(self, packet):
        user = self._plugin.core.remove_user(packet.old_name)
        if user is not None:
            self._plugin.core.add_user(packet.new_name, user)

    def _handle_update_user_color(self, packet):
        user = self._plugin.core.get_user(packet.name)
        if user is not None:
            user["color"] = packet.new_color
            self._plugin.core.add_user(packet.name, user)
            self._plugin.interface.painter.update_user(
                packet.name, user.get("ea", 0), packet.new_color
            )

    def _handle_update_location(self, packet):
        user = self._plugin.core.get_user(packet.name)
        if user is None:
            user = {"color": packet.color, "ea": packet.ea}
        else:
            user["ea"] = packet.ea
        self._plugin.core.add_user(packet.name, user)
        self._plugin.interface.painter.update_user(
            packet.name, packet.ea, user.get("color", packet.color)
        )

        followed = self._plugin.interface.followed
        if followed == packet.name or followed == "everyone":
            self._plugin.interface.jumpto(packet.ea)

    def _handle_delete(self, packet):
        self.terminate()
