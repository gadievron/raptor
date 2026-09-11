"""lstat-gated, bounded file IO for resolver inputs.

Resolvers read and copy manifest / lockfile paths that live inside
the SCANNED (hostile) directory. A plain ``read_bytes()`` /
``shutil.copy2()`` there follows symlinks (``gradle.lockfile ->
~/.ssh/id_ed25519`` exfiltrates operator files into run artifacts)
and opens FIFOs (a blocking ``open`` hangs the resolver worker).

These helpers gate on ``lstat`` BEFORE any open: only regular,
non-symlink files of sane size are read. The open itself uses
``O_NOFOLLOW | O_NONBLOCK`` plus an ``fstat`` re-check so a swap
between the lstat and the open (symlink or FIFO raced in) fails
closed instead of following or hanging.

The byte-mode sibling of ``packages.sca.parsers._safe_read`` (which
is text-mode with lossy decode — wrong for lockfile bytes that must
round-trip verbatim).
"""

from __future__ import annotations

import logging
import os
import stat as _stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# Same bound rationale as ``parsers._safe_read``: above the largest
# legitimate lockfiles seen in the wild (~30-40 MB monorepo locks),
# well below DoS-payload magnitudes.
_MAX_RESOLVER_FILE_BYTES = 50 * 1024 * 1024


def read_regular_bytes(
    path: Path, *, max_bytes: int = _MAX_RESOLVER_FILE_BYTES,
) -> bytes | None:
    """Read ``path`` as bytes; ``None`` when it is missing, not a
    regular non-symlink file, or exceeds ``max_bytes``."""
    try:
        st = path.lstat()
    except OSError:
        return None
    if not _stat.S_ISREG(st.st_mode):
        logger.warning(
            "sca.resolvers: refusing to read %s (not a regular file: "
            "mode=0o%o) — symlinks/FIFOs from the scanned directory "
            "are not followed", path, st.st_mode,
        )
        return None
    if st.st_size > max_bytes:
        logger.warning(
            "sca.resolvers: refusing to read %s (size=%d > max=%d)",
            path, st.st_size, max_bytes,
        )
        return None
    try:
        # O_NOFOLLOW: a symlink raced in after the lstat fails with
        # ELOOP instead of being followed. O_NONBLOCK: a FIFO raced
        # in opens without blocking; the fstat below then rejects it.
        # O_NONBLOCK has no effect on regular-file reads.
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        logger.warning("sca.resolvers: cannot open %s: %s", path, e)
        return None
    try:
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            logger.warning(
                "sca.resolvers: refusing %s — replaced by a "
                "non-regular file between stat and open", path,
            )
            return None
        with os.fdopen(fd, "rb", closefd=True) as fh:
            fd = -1
            raw = fh.read(max_bytes + 1)
    except OSError as e:
        logger.warning("sca.resolvers: cannot read %s: %s", path, e)
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > max_bytes:
        logger.warning(
            "sca.resolvers: %s grew past max during read (>%d)",
            path, max_bytes,
        )
        return None
    return raw


def read_regular_text(
    path: Path, *, max_bytes: int = _MAX_RESOLVER_FILE_BYTES,
) -> str | None:
    """``read_regular_bytes`` decoded as UTF-8 (lossy on bad bytes)."""
    raw = read_regular_bytes(path, max_bytes=max_bytes)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def copy_regular_file(
    src: Path, dst: Path, *,
    max_bytes: int = _MAX_RESOLVER_FILE_BYTES,
) -> bool:
    """Copy ``src`` → ``dst`` content-only, with the same lstat gate
    and size bound as :func:`read_regular_bytes`.

    Returns False (already logged) when ``src`` was refused. ``dst``
    is a path we own (a fresh tempdir), so a plain write is fine.
    """
    raw = read_regular_bytes(src, max_bytes=max_bytes)
    if raw is None:
        return False
    dst.write_bytes(raw)
    return True


__all__ = [
    "copy_regular_file",
    "read_regular_bytes",
    "read_regular_text",
]
