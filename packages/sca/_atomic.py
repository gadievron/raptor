"""Atomic file writes for raptor-sca.

When ``raptor-sca fix --apply`` modifies a user's manifest files, the
write must not leave the file in a torn state if the process is
interrupted (Ctrl-C, OOM kill, disk full, power loss). A direct
``write_text()`` opens the file with ``O_TRUNC`` first, then writes —
leaving a window where the file is empty or partially written. A
``shutil.copy2`` has the same problem.

This module provides two primitives:

  - ``atomic_write_text(path, content)`` — for source-text manifests
  - ``atomic_write_bytes(path, content)`` — for binary writes

Pattern:

  1. Write the new content to ``<path>.tmp.<pid>`` in the same dir.
  2. fsync the file contents.
  3. ``os.replace(tmp, path)`` — atomic rename in the same directory.
  4. Best-effort fsync of the parent directory so the rename is durable.

Either the old file or the new file is visible at all times — never a
truncated or partial file. On any exception before the rename, the
temp file is best-effort cleaned up so we don't leave debris in the
user's tree. ``BaseException`` (which includes ``KeyboardInterrupt``)
is caught — that's exactly when a torn write would otherwise happen.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Union


def atomic_write_text(
    path: Union[str, Path],
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Replace ``path`` with ``content`` atomically. See module docstring."""
    atomic_write_bytes(path, content.encode(encoding))


def atomic_write_bytes(
    path: Union[str, Path],
    content: bytes,
) -> None:
    """Replace ``path`` with ``content`` atomically. See module docstring."""
    path = Path(path)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    # If the destination already exists, capture its mode bits up-front
    # so we can reapply them to the temp file before rename. Operators
    # occasionally chmod manifests to 0o600 (e.g. CI deploy keys
    # embedded in a Directory.Packages.props PropertyGroup); without
    # this preservation the rewrite would silently widen those perms
    # to 0o644. We only carry the permission bits (S_IMODE); the file-
    # type bits stay as O_CREAT's default (regular file).
    #
    # A stat-then-write race is benign here: this is a permission-
    # preserve hint, not a security boundary. Worst case under a
    # racing chmod we apply the pre-race mode and the operator re-
    # runs the chmod.
    preserve_mode: int = 0o644
    try:
        import stat as _stat
        preserve_mode = _stat.S_IMODE(path.stat().st_mode)
    except (OSError, ValueError):
        # File doesn't exist yet (new manifest write) or stat
        # surfaced something the platform can't represent — fall
        # back to the historical default.
        pass

    # PID suffix avoids collision when concurrent runs target the same
    # path (e.g. parallel CI matrix jobs, two operators on a shared
    # filesystem).
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")

    try:
        # O_CREAT|O_WRONLY|O_TRUNC matches the semantics of write_text.
        # The mode argument is umask-modified on creation; we ``fchmod``
        # after open so the captured preserve_mode lands verbatim.
        fd = os.open(
            tmp,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            preserve_mode,
        )
        try:
            try:
                os.fchmod(fd, preserve_mode)
            except (OSError, AttributeError):
                # Windows + a handful of mounted filesystems don't
                # honour fchmod — the O_CREAT mode argument already
                # provided the best-effort fallback.
                pass
            os.write(fd, content)
            os.fsync(fd)
        finally:
            os.close(fd)
        # Atomic rename. On POSIX this is a same-FS rename and atomic
        # by spec; on Windows ``os.replace`` succeeds on same-volume
        # rename. The temp file is consumed by this call.
        os.replace(tmp, path)
        # Best-effort durability: fsync the parent directory so the
        # rename survives a power loss. Some platforms (Windows) don't
        # support directory fsync — silent fallback is fine; we've
        # already done the right thing for the data.
        try:
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except BaseException:
        # Best-effort cleanup of the temp file. If the temp doesn't
        # exist we're already past the rename, so nothing to clean.
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


__all__ = ["atomic_write_text", "atomic_write_bytes"]
