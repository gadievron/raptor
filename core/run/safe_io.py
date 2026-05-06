"""Symlink-safe run-dir creation for raptor outputs.

The standard run-dir naming pattern in :func:`core.run.output.unique_run_suffix`
is ``timestamp + PID``, predictable to a co-resident local attacker. Combined
with the codebase's prevalent ``Path.mkdir(exist_ok=True)`` pattern, that gives
a TOCTOU window where an attacker can pre-create the predicted path as a
symlink and redirect raptor's writes to a chosen target.

This module's :func:`safe_run_mkdir` closes that window:

  - :func:`os.mkdir` (not ``Path.mkdir``) creates the dir atomically with the
    requested mode. ``Path.mkdir`` calls ``os.mkdir`` underneath, but using the
    raw call here makes the umask-vs-mode interaction explicit.
  - On :class:`FileExistsError`, :func:`os.lstat` reads the path metadata
    without following symlinks. We refuse if the path is anything other than a
    real directory owned by the current user, or if it is world-writable.

Group-writable existing dirs (e.g. mode ``0o775`` from default umask ``0o002``
on systemd-style "user private group" setups) are accepted with a logged
warning rather than refused. The default-umask shape would otherwise refuse
on every existing dir during upgrade.

The check guards the *final* path component only; symlinks higher in the path
resolve normally. An attacker who can manipulate parent directories has access
beyond what this module is intended to defend against.

Threat model assumptions:
  - Single-tenant or low-trust-multi-tenant analysis box
  - Attacker can read ``/proc`` to enumerate PIDs and predict the next one
  - Attacker has write access under the parent of the run-dir-to-be
  - Attacker does NOT share the user's UID
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Union

from core.logging import get_logger

logger = get_logger()


class UnsafeRunDirError(PermissionError):
    """Raised when an output dir cannot be created or used safely."""


def safe_run_mkdir(path: Union[Path, str]) -> None:
    """Create *path* if absent, or accept it if already present and safe.

    Behaviour:
      - If *path* does not exist: created via :func:`os.mkdir` with mode
        ``0o700``. Any umask in effect can only mask away owner bits, which
        ``0o700`` already lacks beyond the owner triplet — so the resulting
        mode is always ``0o700`` regardless of the caller's umask.
      - If *path* exists as a real directory owned by the current user and
        not world-writable: accepted (no chmod, no chown).
      - Group-writable existing dirs: accepted with a warning logged.
      - Anything else (symlink, regular file, foreign UID, world-writable):
        :class:`UnsafeRunDirError` raised.

    The function is idempotent for safe pre-existing dirs. It does NOT create
    intermediate parents — callers should ensure the parent exists, or use
    :func:`pathlib.Path.parent.mkdir` separately for parents that are not
    raptor-controlled run-dirs.
    """
    path = Path(path)

    try:
        os.mkdir(path, mode=0o700)
        return
    except FileExistsError:
        pass

    st = os.lstat(path)

    if not stat.S_ISDIR(st.st_mode):
        raise UnsafeRunDirError(
            f"refusing non-directory output path: {path} "
            f"(may be a symlink or regular file)"
        )

    euid = os.geteuid()
    if st.st_uid != euid:
        raise UnsafeRunDirError(
            f"output dir not owned by current user "
            f"(uid {st.st_uid} ≠ {euid}): {path}"
        )

    if st.st_mode & 0o002:
        raise UnsafeRunDirError(
            f"output dir is world-writable "
            f"(mode {oct(st.st_mode & 0o777)}): {path} "
            f"— chmod o-w to use, or move the dir"
        )

    if st.st_mode & 0o020:
        logger.warning(
            f"output dir is group-writable "
            f"(mode {oct(st.st_mode & 0o777)}, gid {st.st_gid}): {path} "
            f"— attacker injection possible if group has untrusted members"
        )
