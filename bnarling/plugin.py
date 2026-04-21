import json
import logging
import os
import socket

import binaryninja
from binaryninja import PluginCommand

from .core.core import Core
from .core.hooks import BnHooks
from .interface.interface import Interface
from .interface.settings import random_color
from .interface.sidebar import invite_here
from .network.network import Network
from .shared.utils import start_logging


def _user_plugin_dir():
    """Where we keep bnarling's logs/config — under BN's user plugins dir."""
    try:
        base = binaryninja.user_plugin_path()
    except Exception:
        base = os.path.expanduser("~/.binaryninja/plugins")
    return os.path.join(base, "bnarling")


class BnarlingPlugin:
    """
    Top-level plugin object; mirrors idarling.plugin.IdarlingPlugin but
    without IDA-isms. Holds the three modules (core, interface, network).
    """

    PLUGIN_NAME = "bnarling"
    PLUGIN_VERSION = "0.0.1"
    PLUGIN_AUTHORS = "Ported from IDArling"

    @staticmethod
    def description():
        return "%s v%s" % (BnarlingPlugin.PLUGIN_NAME, BnarlingPlugin.PLUGIN_VERSION)

    @staticmethod
    def default_config():
        try:
            default_name = socket.gethostname() or "unnamed"
        except Exception:
            default_name = "unnamed"
        return {
            "level": logging.INFO,
            "servers": [],
            "keep": {"cnt": 4, "intvl": 15, "idle": 240},
            "user": {
                "color": random_color(),
                "name": default_name,
                "notifications": True,
            },
        }

    def __init__(self):
        self._config = self.default_config()

        user_dir = _user_plugin_dir()
        for sub in ("logs", "files"):
            d = os.path.join(user_dir, sub)
            if not os.path.exists(d):
                os.makedirs(d, 0o755)

        log_path = os.path.join(user_dir, "logs", "bnarling.%d.log" % os.getpid())
        self._config_path = os.path.join(user_dir, "files", "config.json")

        self._logger = start_logging(log_path, "bnarling", self._config["level"])
        self.load_config()

        # Default user name to the machine hostname so sessions don't all
        # show up as "unnamed".
        if self._config["user"].get("name") in (None, "", "unnamed"):
            try:
                self._config["user"]["name"] = socket.gethostname() or "unnamed"
            except Exception:
                pass

        self._core = Core(self)
        self._interface = Interface(self)
        self._network = Network(self)
        self._hooks = BnHooks(self)

    @property
    def config(self):
        return self._config

    @property
    def logger(self):
        return self._logger

    @property
    def core(self):
        return self._core

    @property
    def interface(self):
        return self._interface

    @property
    def network(self):
        return self._network

    # --- lifecycle ---

    def init(self):
        try:
            self._interface.install()
            self._network.install()
            self._core.install()
            self._hooks.install()
            self._register_commands()
        except Exception as e:
            self._logger.error("Failed to initialize")
            self._logger.exception(e)
            return False

        self._logger.info("-" * 60)
        self._logger.info("%s (c) %s" % (self.description(), self.PLUGIN_AUTHORS))
        self._logger.info("-" * 60)

        self._auto_connect()
        return True

    def _register_commands(self):
        def _invite_everyone_here(_bv, _addr):
            invite_here(self, "everyone")

        try:
            PluginCommand.register_for_address(
                "bnarling\\Invite everyone here",
                "Tell every user in the current session to jump to this address",
                _invite_everyone_here,
            )
        except Exception as e:
            # Registering the same command twice (plugin reload) raises.
            self._logger.debug("register_for_address failed: %s" % e)

    def term(self):
        try:
            self._hooks.uninstall()
            self._core.uninstall()
            self._network.uninstall()
            self._interface.uninstall()
            self.save_config()
        except Exception as e:
            self._logger.exception(e)

    def _auto_connect(self):
        for server in self._config["servers"]:
            if server.get("auto_connect"):
                self._logger.info(
                    "Auto-connecting to %s:%d" % (server["host"], server["port"])
                )
                self._network.connect(server)
                break

    # --- config ---

    def load_config(self):
        if not os.path.isfile(self._config_path):
            return
        try:
            with open(self._config_path, "r") as f:
                self._config.update(json.load(f))
        except Exception as e:
            self._logger.warning("Couldn't read config: %s" % e)
            return
        self._logger.setLevel(self._config.get("level", logging.INFO))

    def save_config(self):
        try:
            with open(self._config_path, "w") as f:
                json.dump(self._config, f, indent=2)
        except Exception as e:
            self._logger.warning("Couldn't save config: %s" % e)
