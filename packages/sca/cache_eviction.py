"""Cache eviction for ``~/.raptor/cache/sca/``.

Walks the cache root and unlinks every regular file whose mtime is
older than the configured horizon. Empty subdirectories are removed
too. Top-level cache root and its first-level subdirs (``queries``,
``vulns``, ``kev``, ``epss``, …) are left in place even when empty —
they get recreated on the next run anyway.

The eviction is best-effort: any single OSError on a file is logged
and skipped (don't break the gate over a permission quirk on one
stale entry). Callers get an :class:`EvictionResult` with counts.

Why files-not-time-buckets: the cache stores its own per-entry TTL
inside each envelope (see :class:`core.json.cache.JsonCache`), so
fresh-in-content but old-on-disk entries DO get re-fetched normally.
The 30-day broom is a *space-reclamation* concern — entries we
haven't touched in a month are unlikely to be touched again, and a
busy SCA cache can grow unbounded otherwise.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger(__name__)

DEFAULT_MAX_AGE_DAYS = 30


@dataclass
class EvictionResult:
    files_scanned: int = 0
    files_removed: int = 0
    bytes_freed: int = 0
    errors: int = 0
    dirs_removed: int = 0


def evict_stale(
    cache_root: Path,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    now: float | None = None,
) -> EvictionResult:
    """Remove cache files whose mtime is older than ``max_age_days``.

    Args:
        cache_root: typically ``~/.raptor/cache/sca/`` (or whatever the
            operator set ``--cache-root`` to).
        max_age_days: integer day count. Files mtime'd before
            ``now - max_age_days`` are removed.
        now: override clock for tests; default :func:`time.time`.

    Returns counts on the work done. Missing or unwritable cache root
    returns a zeroed result without raising — both are common
    operator states (cache not yet warmed; running on a read-only
    filesystem).
    """
    result = EvictionResult()
    if not cache_root.exists() or not cache_root.is_dir():
        return result
    now_t = now if now is not None else time.time()
    cutoff = now_t - max_age_days * 86400

    # Two-pass: first remove stale files, then remove empty subdirs
    # so directory rmdir() succeeds. The cache root itself is never
    # removed.
    for entry in _iter_files(cache_root):
        result.files_scanned += 1
        try:
            st = entry.stat()
        except OSError as e:
            logger.debug("sca.cache_eviction: stat %s failed: %s", entry, e)
            result.errors += 1
            continue
        if st.st_mtime >= cutoff:
            continue
        try:
            entry.unlink()
        except OSError as e:
            logger.debug("sca.cache_eviction: unlink %s failed: %s", entry, e)
            result.errors += 1
            continue
        result.files_removed += 1
        result.bytes_freed += st.st_size

    # Remove empty directories. Deepest-first so parents are eligible
    # only after their children.
    dirs = sorted(_iter_dirs(cache_root),
                  key=lambda p: len(p.parts), reverse=True)
    for d in dirs:
        if d == cache_root:
            continue
        try:
            d.rmdir()                       # only succeeds if empty
        except OSError:
            continue                        # not empty or permission — fine
        result.dirs_removed += 1

    return result


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield every regular file under ``root`` (depth-first)."""
    try:
        entries = list(root.rglob("*"))
    except OSError:
        return
    for p in entries:
        try:
            if p.is_file():
                yield p
        except OSError:
            continue


def _iter_dirs(root: Path) -> Iterable[Path]:
    """Yield every directory under ``root`` (including ``root`` itself)."""
    try:
        entries = list(root.rglob("*"))
    except OSError:
        return
    for p in entries:
        try:
            if p.is_dir():
                yield p
        except OSError:
            continue


__all__ = ["DEFAULT_MAX_AGE_DAYS", "EvictionResult", "evict_stale"]
