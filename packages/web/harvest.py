#!/usr/bin/env python3
"""Harvest child-written artifacts out of an anonymous sandbox workspace.

Anonymous-workspace callers give the sandboxed child a throwaway
scratch dir as its writable bind (the run dir's path carries the
run/project marker name, and the mountinfo root field of the bind
re-leaks the source path to the child). Anything the run must keep is
carried out of the workspace before its teardown by the helpers here.

The source dir was the child's write grant, so every name in it is
attacker-influenced: the child ran a network-facing tool against a
possibly hostile target. The helpers never follow a planted symlink,
never block on a planted FIFO, and write every destination as a fresh
0600 inode so a pre-planted file at the predictable destination name
is displaced, not appended to.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from core.logging import get_logger

logger = get_logger()


def harvest_regular_file(src: Path, dst: Path) -> bool:
    """Copy one child-written workspace file to its parent-side home.

    O_NOFOLLOW refuses a planted symlink (copying whatever it aims at
    into the run dir); O_NONBLOCK keeps the open from hanging on a
    planted FIFO so the fstat S_ISREG check is actually reached, and
    that check then refuses FIFOs/devices. The destination is a fresh
    0600 inode — the artifact may embed delivered credentials until a
    scrub pass rewrites it. Size is bounded upstream by the sandbox's
    file-size rlimit on the child, exactly as when the child wrote
    into the run dir directly. A missing source (the tool died before
    flushing) is a normal no-op.
    """
    try:
        # O_NONBLOCK is a no-op for regular-file reads; it only
        # changes the open(2) semantics of a FIFO, which would
        # otherwise block until a writer appears.
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            logger.warning(
                "refusing to harvest %s: not a regular file", src.name,
            )
            return False
        dst.unlink(missing_ok=True)
        out_fd = os.open(
            dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(out_fd, "wb") as out:
            while chunk := os.read(fd, 1 << 20):
                out.write(chunk)
        return True
    except OSError as exc:
        logger.warning("could not harvest %s: %s", src.name, exc)
        return False
    finally:
        os.close(fd)


def harvest_tree(src_dir: Path, dst_dir: Path) -> None:
    """Carry a child-written directory tree out of the workspace.

    Mirrors the tree under ``dst_dir`` with 0700 directories and
    per-file :func:`harvest_regular_file` copies. Symlinked
    directories are pruned from the walk (``followlinks=False`` keeps
    ``os.walk`` from descending, but the link itself would still be
    mirrored as a directory without the prune); symlinked and
    non-regular files are refused by the per-file helper. A missing
    source tree (the tool stored nothing) is a normal no-op.
    """
    if not src_dir.is_dir() or src_dir.is_symlink():
        return
    if not _fresh_dir(dst_dir, parents=True):
        return
    for root, dirs, files in os.walk(src_dir):
        dirs[:] = [d for d in dirs if not (Path(root) / d).is_symlink()]
        rel = Path(root).relative_to(src_dir)
        for name in dirs:
            _fresh_dir(dst_dir / rel / name)
        for name in files:
            harvest_regular_file(Path(root) / name, dst_dir / rel / name)


def _fresh_dir(path: Path, *, parents: bool = False) -> bool:
    """mkdir that never follows a planted symlink at the dir name.

    The destination tree in the run dir may predate the
    anonymous-workspace conversion, when the child wrote there
    directly and could leave a symlink at any predictable name —
    ``mkdir(exist_ok=True)`` would silently accept a symlink-to-dir
    and route every subsequent file harvest through it.
    """
    try:
        if path.is_symlink():
            path.unlink()
        path.mkdir(mode=0o700, parents=parents, exist_ok=True)
        return True
    except OSError as exc:
        logger.warning("could not create harvest dir %s: %s", path, exc)
        return False
