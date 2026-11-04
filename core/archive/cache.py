"""Content-addressed cache-name helper for extracted archives.

The cache layout is ``<sources_root>/<safe-archive-name>-<sha>/``.
Used by ``raptor.py:_unpack_archive_target`` when /scan / /agentic
unpack into a project's ``_sources/`` shared cache, and by
``packages/describe/cli.py`` to check whether the operator already
extracted the archive via a prior run (cache hit → reuse without
re-extracting).

The function is colocated with the rest of the archive substrate
(``core.archive``) rather than left private to ``raptor.py`` —
two consumers proves the abstraction.
"""

from __future__ import annotations

import stat
from pathlib import Path

_CACHE_NAME_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def safe_cache_name(archive_name: str, sha: str) -> str:
    """Content-cache dir name: ``<sanitised archive name>-<sha>``.

    Readable AND collision-free. The archive name is
    attacker-influenced, so it's reduced to a safe charset,
    stripped of leading separators, length-capped, and then the
    sha (which alone guarantees uniqueness) is appended.
    """
    base = "".join(
        c if c in _CACHE_NAME_ALLOWED else "_" for c in archive_name
    )
    base = base.strip("._-")[:64] or "archive"
    return f"{base}-{sha}"


def is_cached_extraction(path: Path) -> bool:
    """Whether the cache slot itself is a real directory, without following links.

    Published cache directories remain compatible with existing runs. Missing
    slots are misses; unexpected I/O errors propagate to the caller.
    """
    try:
        return stat.S_ISDIR(path.lstat().st_mode)
    except (FileNotFoundError, NotADirectoryError):
        return False


__all__ = ["is_cached_extraction", "safe_cache_name"]
