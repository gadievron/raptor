"""Shared cross-process lock for load → merge → write artifact windows.

THE flock idiom RAPTOR's durable JSON stores use, hoisted so new
writers stop re-implementing it (the spec store, the coverage store,
and the study promotion each carry a local copy; new call sites route
here). Contract, matching those siblings:

- lock a sibling ``<artifact>.lock`` file, never the artifact itself —
  the artifact is atomically replaced on save, and flocking a replaced
  inode splits lockers;
- hold the lock across the WHOLE load → merge → write cycle;
- ``O_NOFOLLOW``: the lock file may live in a directory broader write
  grants reach — a planted symlink must not steer the flock to an
  attacker-chosen path. A refused open degrades to the unlocked path
  with a loud warning rather than failing the (best-effort) writer;
- degrade to a no-op without ``fcntl`` (non-POSIX);
- the lock file is deliberately never unlinked — unlink-after-unlock
  races split lockers across two inodes.

Client-locality caveat (WSL drvfs/9p, no behaviour change): on a
Windows-interop mount, ``flock`` is implemented by the 9p client —
it serialises processes within one distro (one client) exactly as on
a local filesystem, but grants no exclusion against Windows-side
writers or other WSL distros mounting the same drive. Artifacts on
such mounts keep same-distro correctness and silently lose the
cross-context guarantee; placement guidance lives in docs/wsl.md.
"""

from __future__ import annotations

import contextlib
import logging
import os
from collections.abc import Iterator
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:  # non-POSIX (Windows) — locks degrade to no-ops
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def artifact_lock(artifact: Path, *, subject: str = "artifact") -> Iterator[None]:
    """Exclusive cross-process lock over *artifact*'s read-modify-write
    window (flocks the sibling ``<artifact>.lock``).

    *subject* names the guarded resource in the degrade warning.
    """
    if not _HAS_FCNTL:
        yield
        return
    lock_path = artifact.with_suffix(artifact.suffix + ".lock")
    flags = (
        os.O_WRONLY | os.O_CREAT
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), flags, 0o600)
    except OSError as exc:
        logger.warning(
            "%s lock %s: refusing to open (%s); proceeding WITHOUT "
            "cross-process lock — concurrent writers may drop each "
            "other's contributions; investigate a planted symlink at "
            "that path", subject, lock_path, exc,
        )
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
