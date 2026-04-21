# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
import logging

_loggers = {}


class _BinaryNinjaLogHandler(logging.Handler):
    """Forward Python log records to BN's log API with matching severity.

    The default StreamHandler writes to stderr, which BN's log pane paints
    red regardless of level. Routing through log_info / log_warn / log_error
    lets INFO/DEBUG lines render in the normal foreground color.
    """

    def emit(self, record):
        try:
            import binaryninja as bn
        except Exception:
            return
        try:
            msg = self.format(record)
        except Exception:
            return
        lvl = record.levelno
        try:
            if lvl >= logging.ERROR:
                bn.log_error(msg)
            elif lvl >= logging.WARNING:
                bn.log_warn(msg)
            elif lvl >= logging.INFO:
                bn.log_info(msg)
            else:
                bn.log_debug(msg)
        except Exception:
            pass


def start_logging(log_path, log_name, level):
    """
    Setup the logger: add a new log level, create a logger which logs into
    the console and also into a log files located at: logs/idarling.%pid%.log.
    """
    global _loggers

    if log_name in _loggers:
        return _loggers[log_name]

    # Add a new log level called TRACE, and more verbose that DEBUG.
    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, "TRACE")
    logging.Logger.trace = lambda inst, msg, *args, **kwargs: inst.log(
        logging.TRACE, msg, *args, **kwargs
    )
    logging.trace = lambda msg, *args, **kwargs: logging.log(
        logging.TRACE, msg, *args, **kwargs
    )

    logger = logging.getLogger(log_name)
    if level != None:
        if not isinstance(level, int):
            level = getattr(logging, level)
        logger.setLevel(level)

    logger.propagate = False  # avoid having 2 log lines

    # Route to BN's log pane with per-level coloring instead of stderr.
    bn_handler = _BinaryNinjaLogHandler()
    bn_handler.setFormatter(
        logging.Formatter(fmt="[%(levelname)s] %(message)s")
    )
    logger.addHandler(bn_handler)

    # Log to disk as well, with timestamps.
    file_handler = logging.FileHandler(log_path)
    log_format = "[%(asctime)s][%(levelname)s] %(message)s"
    formatter = logging.Formatter(fmt=log_format, datefmt="%H:%M:%S")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    _loggers[log_name] = logger
    return logger
