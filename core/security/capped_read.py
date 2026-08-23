"""Hardened, size-capped file read for config/trust scanners.

Owns the open-flags dance the CC-side and CodeQL-side trust scanners
previously each carried a private copy of. The cap stays with the
caller (the two scanners historically chose different limits), the
hardening lives here once.
"""

from __future__ import annotations

import os
import stat
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def read_capped(path: Path, max_bytes: int) -> bytes | None:
    """Read up to ``max_bytes`` from ``path``; None on oversized,
    non-regular, or unreadable.

    O_NONBLOCK + fstat(S_ISREG) closes the FIFO-DoS and stat-vs-open
    TOCTOU holes. O_NOFOLLOW closes the symlink-redirect hole — the
    callers' walk-side symlink checks record symlinks as findings
    without reading them, but a TOCTOU race could swap a regular file
    for a symlink between that check and the open here. With
    O_NOFOLLOW the open fails with ELOOP and we fail-closed (return
    None). Broad except for any I/O surprise — fail-closed is the
    safe stance.
    """
    try:
        fd = os.open(
            str(path),
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except Exception:  # noqa: BLE001
        return None
    data: bytes | None = None
    try:
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, "rb", closefd=False) as f:
                data = f.read(max_bytes + 1)
        except Exception:  # noqa: BLE001
            return None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    if data is None or len(data) > max_bytes:
        return None
    return data
