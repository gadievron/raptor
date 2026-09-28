"""Symlink-safe file enumeration for untrusted target trees.

A hostile target shipping ``dir -> /`` (or a symlink loop) must not
steer the enumeration — which runs in the UNSANDBOXED parent — across
the host filesystem: the callers here read file content (1 MB per
file, no aggregate cap) into audit prompts. ``Path.rglob`` recurses
into directory symlinks only via 3.13's ``recurse_symlinks=True``
opt-in (``glob.glob(recursive=True)`` is the API that followed them
by default); walking with ``os.walk(followlinks=False)`` keeps the
refusal explicit — same idiom as core/security/codeql_trust.py.
"""

from __future__ import annotations

import os
from collections.abc import Collection, Iterator
from pathlib import Path

from core.logging import get_logger

logger = get_logger()

# Cap on files yielded by one enumeration of an untrusted target. Too
# low silently truncates header/macro context on big legitimate trees
# (missing enrichment in audit prompts); too high lets a hostile file
# farm dominate wall time and memory. 100k files sits an order of
# magnitude above the largest targets this pipeline scans.
_MAX_WALK_FILES = 100_000
# Cap on directory entries EXAMINED: the yield cap alone let a hostile
# tree of non-matching names walk in full (the wall-time half of the
# same farm). 20x the yield cap leaves room for legitimately
# header-sparse trees while bounding total walk work.
_MAX_WALK_SCAN = 20 * _MAX_WALK_FILES


def iter_regular_files(
    root: Path,
    suffixes: Collection[str],
    *,
    max_files: int = _MAX_WALK_FILES,
) -> Iterator[Path]:
    """Yield regular files under ``root`` whose ``.suffix`` is in
    ``suffixes``, never entering directory symlinks.

    File symlinks and non-regular entries (fifos, sockets) are skipped
    — matching the per-file ``is_symlink()`` filter the call sites
    already applied. Unreadable subtrees are skipped (``os.walk``
    default). Stops with a warning after ``max_files`` yields.
    """
    yielded = 0
    scanned = 0
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            scanned += 1
            if scanned > _MAX_WALK_SCAN:
                logger.warning(
                    "file enumeration under %s examined %d directory "
                    "entries — walk stopped, remaining files are not "
                    "indexed", root, _MAX_WALK_SCAN,
                )
                return
            p = Path(dirpath) / name
            if p.suffix not in suffixes:
                continue
            try:
                if p.is_symlink() or not p.is_file():
                    continue
            except OSError:
                continue
            yield p
            yielded += 1
            if yielded >= max_files:
                logger.warning(
                    "file enumeration under %s hit the %d-file cap — "
                    "remaining files are not indexed", root, max_files,
                )
                return
