"""
Open-from-server / Save-to-server actions for bnarling.

These are invoked from the sidebar widget (not IDA menus, as in idarling).
The download flow pulls a BNDB from the server, writes it under
~/<plugins>/bnarling/files/, and opens it via the BN UIContext.
The upload flow saves the current BinaryView to a temporary BNDB and ships
it back to the server with UpdateFile.
"""

import bz2
import os
from functools import partial

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMessageBox, QProgressDialog

from ..core.core import BINARY_TYPE_BNDB, DEFAULT_SNAPSHOT
from ..shared.commands import DownloadFile, UpdateFile
from .dialogs import OpenDialog, SaveDialog, ensure_default_snapshot


def _files_dir(plugin):
    """Where to keep downloaded BNDBs locally."""
    from ..plugin import _user_plugin_dir

    d = os.path.join(_user_plugin_dir(), "files")
    if not os.path.exists(d):
        os.makedirs(d, 0o755)
    return d


def _make_progress(title, text):
    progress = QProgressDialog(text, "Cancel", 0, 1)
    progress.setCancelButton(None)
    progress.setModal(True)
    progress.setWindowFlags(progress.windowFlags() & ~Qt.WindowCloseButtonHint)
    progress.setWindowTitle(title)
    return progress


def _on_progress(progress, count, total):
    progress.setRange(0, total)
    progress.setValue(count)


# ---------------------------------------------------------------- open flow


def open_from_server(plugin, parent=None):
    """Show the Open dialog; on accept, download+open the selected BNDB."""
    if not plugin.network.connected:
        QMessageBox.warning(parent, "bnarling", "Not connected to a server.")
        return
    dialog = OpenDialog(plugin)
    if dialog.exec_() != OpenDialog.Accepted:
        return
    project, binary = dialog.get_result()
    if project is None or binary is None:
        return
    if binary.type != BINARY_TYPE_BNDB:
        QMessageBox.warning(
            parent,
            "bnarling",
            "This binary isn't a BNDB — Binary Ninja can't open it.",
        )
        return
    _download_and_open(plugin, project, binary, parent=parent)


def _download_and_open(plugin, project, binary, parent=None):
    progress = _make_progress(
        "Open from server", "Downloading BNDB from server, please wait..."
    )

    packet = DownloadFile.Query(project.name, binary.name, DEFAULT_SNAPSHOT)

    def set_download_callback(reply):
        reply.downback = partial(_on_progress, progress)

    d = plugin.network.send_packet(packet)
    if not d:
        progress.close()
        return
    d.add_initback(set_download_callback)
    d.add_callback(partial(_file_downloaded, plugin, project, binary, progress))
    d.add_errback(partial(_download_failed, plugin, progress))
    progress.show()


def _download_failed(plugin, progress, exc):
    progress.close()
    plugin.logger.exception(exc)


def _file_downloaded(plugin, project, binary, progress, reply):
    progress.close()

    # Write the decompressed BNDB to our local files dir.
    file_name = "%s_%s.bndb" % (project.name, binary.name)
    file_path = os.path.join(_files_dir(plugin), file_name)
    try:
        decompressed = bz2.decompress(reply.content)
        with open(file_path, "wb") as f:
            f.write(decompressed)
    except Exception as e:
        plugin.logger.exception(e)
        QMessageBox.critical(None, "bnarling", "Failed to save downloaded file.")
        return
    plugin.logger.info("Saved %s" % file_path)

    # Remember the server-side identity so the core module picks it up the
    # first time the BNDB opens in a BN view.
    plugin.core.remember_downloaded(file_path, project.name, binary.name)

    # Open the BNDB in Binary Ninja. Use UIContext.openFilename so BN
    # dispatches to its database loader (otherwise a .bndb opens as raw
    # SQLite3 via the generic loader).
    try:
        from binaryninjaui import UIContext

        ctx = UIContext.activeContext()
        if ctx is None:
            raise RuntimeError("No active UIContext")
        if not ctx.openFilename(file_path):
            raise RuntimeError("UIContext.openFilename returned False")
    except Exception as e:
        plugin.logger.exception(e)
        QMessageBox.warning(
            None,
            "bnarling",
            "File downloaded to %s, but Binary Ninja couldn't open it "
            "automatically.\nOpen it manually to join the session." % file_path,
        )


# ---------------------------------------------------------------- save flow


def _current_view_and_name(plugin):
    """Return (bv, file_name, sha256) for the currently active BN view."""
    try:
        from binaryninjaui import UIContext

        ctx = UIContext.activeContext()
        if ctx is None:
            return None, "", ""
        frame = ctx.getCurrentViewFrame()
        if frame is None:
            return None, "", ""
        bv = frame.getCurrentViewInterface().getData()
        if bv is None:
            return None, "", ""
        filename = ""
        try:
            filename = os.path.basename(bv.file.filename or "")
        except Exception:
            pass
        sha256 = ""
        try:
            # Original file hash if available; falls back to empty string.
            if bv.parent_view is not None and bv.parent_view.parent_view is not None:
                raw = bv.parent_view.parent_view
                data = raw.read(0, raw.length)
                import hashlib

                sha256 = hashlib.sha256(data).hexdigest()
        except Exception:
            pass
        return bv, filename, sha256
    except Exception:
        return None, "", ""


def save_to_server(plugin, parent=None):
    """Show the Save dialog; on accept, push the current BNDB to the server."""
    if not plugin.network.connected:
        QMessageBox.warning(parent, "bnarling", "Not connected to a server.")
        return
    bv, filename, sha256 = _current_view_and_name(plugin)
    if bv is None:
        QMessageBox.warning(parent, "bnarling", "No active BinaryView to save.")
        return

    dialog = SaveDialog(plugin, bndb_name=filename, bndb_hash=sha256)
    if dialog.exec_() != SaveDialog.Accepted:
        return
    project, binary = dialog.get_result()
    if project is None or binary is None:
        return

    # Ensure the server has a "default" snapshot for this binary before we
    # upload. Snapshots are server-side only — BN has its own BNDB-native ones.
    ensure_default_snapshot(
        plugin,
        project.name,
        binary.name,
        on_done=lambda: _upload(plugin, bv, project, binary),
    )


def _upload(plugin, bv, project, binary):
    # Save BV to a fresh BNDB on disk; then read and compress.
    file_name = "%s_%s.bndb" % (project.name, binary.name)
    file_path = os.path.join(_files_dir(plugin), file_name)

    progress = _make_progress("Save to server", "Saving BNDB locally...")
    progress.setRange(0, 0)
    progress.show()

    try:
        settings = None
        try:
            import binaryninja

            settings = binaryninja.SaveSettings()
        except Exception:
            settings = None
        if not bv.file.create_database(file_path, None, settings):
            raise RuntimeError("create_database returned False")
    except Exception as e:
        progress.close()
        plugin.logger.exception(e)
        QMessageBox.critical(None, "bnarling", "Failed to create BNDB on disk.")
        return

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except Exception as e:
        progress.close()
        plugin.logger.exception(e)
        QMessageBox.critical(None, "bnarling", "Failed to read BNDB for upload.")
        return

    packet = UpdateFile.Query(project.name, binary.name, DEFAULT_SNAPSHOT)
    packet.content = bz2.compress(raw)
    packet.upback = partial(_on_progress, progress)

    progress.setLabelText("Uploading BNDB to server, please wait...")
    progress.setRange(0, 1)

    d = plugin.network.send_packet(packet)
    if not d:
        progress.close()
        return
    d.add_callback(partial(_upload_done, plugin, project, binary, progress))
    d.add_errback(partial(_upload_failed, plugin, progress))


def _upload_failed(plugin, progress, exc):
    progress.close()
    plugin.logger.exception(exc)
    QMessageBox.critical(None, "bnarling", "Upload failed; see log for details.")


def _upload_done(plugin, project, binary, progress, _reply):
    progress.close()
    # Stamp the current BV so subsequent sessions resume automatically.
    plugin.core.project = project.name
    plugin.core.binary = binary.name
    plugin.core.snapshot = DEFAULT_SNAPSHOT
    plugin.core.tick = 0
    plugin.core.join_session()
    QMessageBox.information(None, "bnarling", "BNDB uploaded successfully.")
