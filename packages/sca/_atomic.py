"""Atomic file writes for raptor-sca — thin wrapper over the shared
core primitive.

Historical note: this module implemented an independent atomic-write
primitive before ``core.atomic_fs`` existed. The functions below are
now thin wrappers over :mod:`core.atomic_fs`, preserving the sca-side
API (positional args, no ``mode=`` kwarg) so the 15+ callers in
``packages/sca/`` continue to work unchanged.

When ``raptor-sca fix --apply`` modifies a user's manifest files, the
write must not leave the file in a torn state if the process is
interrupted (Ctrl-C, OOM kill, disk full, power loss). See
``core/atomic_fs/__init__.py`` for the full contract; the sca-relevant
guarantees are:

  * A concurrent reader NEVER sees a partial file — either the old
    bytes or the new bytes, never a truncation-in-progress.
  * On failure — including ``KeyboardInterrupt`` — the temporary is
    cleaned up and ``path`` is left in its prior state.
  * When the destination already exists, its permission bits are
    preserved (regular-file destinations only) — an operator ``chmod
    0o600`` on a manifest carrying credentials is not silently widened
    back to 0o644 by a rewrite.

Semantic delta from the prior in-module implementation:

  * Perm preservation now uses ``lstat`` (does not follow symlinks)
    and only preserves for regular files. A symlink'd manifest (e.g.
    yarn-workspace-style package.json symlinks) is replaced by a
    regular file at the conventional 0o644 default rather than
    inheriting the symlink target's mode bits. This matches the
    "atomic write to path X" convention followed by every other
    consumer of the shared primitive.
  * Tempfile naming carries PID + TID + random suffix (was PID +
    hostname). The random suffix + O_EXCL + O_NOFOLLOW closes the
    tempfile-squat and symlink-through windows the prior naming was
    exposed to.
"""

from __future__ import annotations

from pathlib import Path
from typing import Union

from core.atomic_fs import write_bytes_atomically, write_text_atomically


def atomic_write_text(
    path: Union[str, Path],
    content: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Replace ``path`` with ``content`` atomically. See module docstring."""
    write_text_atomically(path, content, encoding=encoding)


def atomic_write_bytes(
    path: Union[str, Path],
    content: bytes,
) -> None:
    """Replace ``path`` with ``content`` atomically. See module docstring."""
    write_bytes_atomically(path, content)


__all__ = ["atomic_write_text", "atomic_write_bytes"]
