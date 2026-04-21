import errno
import os
import socket
import ssl

from .client import Client
from ..module import Module
from ..shared.discovery import ServersDiscovery


class Network(Module):
    """
    Manages the TCP connection to the idarling server, plus local-network
    server discovery. Adapted from idarling/network/network.py; the
    integrated server is dropped because BN doesn't ship one.
    """

    def __init__(self, plugin):
        super(Network, self).__init__(plugin)
        self._discovery = ServersDiscovery(plugin.logger)

        self._client = None
        self._server = None

    @property
    def client(self):
        return self._client

    @property
    def server(self):
        return self._server

    @property
    def discovery(self):
        return self._discovery

    @property
    def connected(self):
        return self._client.connected if self._client else False

    def _install(self):
        try:
            self._discovery.start()
        except Exception as e:
            self._plugin.logger.warning("Discovery could not start: %s" % e)
        return True

    def _uninstall(self):
        try:
            self._discovery.stop()
        except Exception:
            pass
        self.disconnect()
        return True

    def connect(self, server):
        if self._client:
            return

        self._client = Client(self._plugin)
        self._server = server.copy()
        host = self._server["host"]
        if host == "0.0.0.0":
            host = "127.0.0.1"
        port = self._server["port"]
        no_ssl = self._server.get("no_ssl", True)

        self._plugin.interface.update()
        self._plugin.logger.info("Connecting to %s:%d..." % (host, port))

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        if not no_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(
                sock, server_hostname=host, do_handshake_on_connect=True
            )
        self._client.wrap_socket(sock)

        keep = self._plugin.config.get("keep", {"cnt": 4, "intvl": 15, "idle": 240})
        self._client.set_keep_alive(keep["cnt"], keep["intvl"], keep["idle"])

        sock.settimeout(0)
        sock.setblocking(0)
        try:
            err = sock.connect_ex((host, port))
            if err not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK):
                raise OSError(err, os.strerror(err), "")
        except OSError as e:
            self._plugin.logger.exception(e)
            self._client.terminate()

    def disconnect(self):
        if not self._client:
            return
        self._plugin.logger.info("Disconnecting...")
        self._client.terminate()

    def send_packet(self, packet):
        if self.connected:
            return self._client.send_packet(packet)
        return None
