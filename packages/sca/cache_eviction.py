"""Cache eviction for ``~/.raptor/cache/sca/``.

Walks the cache root and unlinks every regular file whose mtime is
older than the configured horizon. Empty subdirectories (at any
depth) are removed too; only the cache root itself is kept — the
first-level subdirs (``queries``, ``vulns``, ``kev``, ``epss``, …)
get recreated on the next run anyway.

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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_MAX_AGE_DAYS = 30

# First-level subdirs that hold STATE, not cache: the image-drift
# fingerprint baselines live under ``<cache_root>/fingerprints`` and
# are the comparison anchor the drift gate needs FOREVER — they carry
# no TTL envelope and are only rewritten when a scan sees the ref.
# The 30-day broom deleted a rarely-scanned ref's baseline, and the
# next scan then read as "first-ever scan, no signal": the CI drift
# gate silently disarmed. Never evict from these.
_STATE_DIR_NAMES = frozenset({"fingerprints"})


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

    # One rglob walk shared by both passes (files first, then empty
    # subdirs so rmdir() succeeds). The cache root itself is never
    # removed.
    entries = [
        e for e in _list_entries(cache_root)
        if not _in_state_dir(e, cache_root)
    ]
    for entry in _iter_files(entries):
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
    dirs = sorted(_iter_dirs(entries),
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


def _in_state_dir(entry: Path, root: Path) -> bool:
    """True when ``entry`` is (or lives under) a protected state dir."""
    try:
        rel = entry.relative_to(root)
    except ValueError:
        return False
    return bool(rel.parts) and rel.parts[0] in _STATE_DIR_NAMES


def _list_entries(root: Path) -> list[Path]:
    """One recursive walk of ``root`` — shared by the file and dir
    passes (rglob'ing twice materialised the whole tree twice)."""
    try:
        return list(root.rglob("*"))
    except OSError:
        return []


def _iter_files(entries: list[Path]) -> Iterable[Path]:
    """Yield every regular file among ``entries``."""
    for p in entries:
        try:
            if p.is_file():
                yield p
        except OSError as e:
            logger.debug("sca.cache_eviction: is_file %s failed: %s", p, e)
            continue


def _iter_dirs(entries: list[Path]) -> Iterable[Path]:
    """Yield every directory among ``entries``."""
    for p in entries:
        try:
            if p.is_dir():
                yield p
        except OSError:
            continue


__all__ = ["DEFAULT_MAX_AGE_DAYS", "EvictionResult", "evict_stale"]
