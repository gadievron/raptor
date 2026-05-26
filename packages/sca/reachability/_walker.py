"""One source-tree walk per ``(target, max_depth)``, memoised across
the per-ecosystem reach scanners.

Pre-fix each of the 8 reach scanners (``nodejs`` / ``python`` /
``gomod`` / ``composer`` / ``gemfile`` / ``cargo`` / ``nuget`` /
``maven``) did its own ``os.walk`` of the target tree. On a polyglot
codebase (Grafana = TS + Go + Py + Java) that's seven redundant
traversals before the function-level tier even starts; on a 50k-file
repo each walk adds noticeable wallclock and stat() pressure.

The unified walker emits every source file once, keyed by lowercased
suffix. Each scanner consumes via :func:`iter_source_files` with its
own ``extensions`` set and any ecosystem-specific extra directory
exclusions (``bin``/``obj`` for .NET, ``var``/``cache`` for PHP).
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Set, Tuple

from ..discovery import EXCLUDED_DIR_NAMES

logger = logging.getLogger(__name__)


# Same default as the per-scanner walkers had before the refactor —
# keeping the depth ceiling so any test fixture deeper than 12 levels
# (rare) sees the same behaviour as before.
DEFAULT_MAX_DEPTH = 12


_CACHE_LOCK = threading.Lock()
# Keyed on ``(resolved_target_str, max_depth)``. Cached as an
# immutable tuple so a scanner can't poison the cache by mutating
# the returned list. Memory: ~50 bytes per row × ~50k rows on
# Grafana ≈ 2.5 MB — trivial. Bounded so a test sweep over many
# distinct targets in one process can't grow unbounded.
_CACHE: Dict[Tuple[str, int], Tuple[Tuple[Path, str], ...]] = {}
_CACHE_MAX_TARGETS = 4


def walk_source_files(
    target: Path, *, max_depth: int = DEFAULT_MAX_DEPTH,
) -> Tuple[Tuple[Path, str], ...]:
    """Return every file under ``target`` that survives the canonical
    SCA dir-exclusion list, as ``(path, suffix_lower)`` tuples.

    Symlinks are not followed (parity with the per-scanner walks).
    Depth is counted in ``Path.parts`` from the target root.
    """
    target = target.resolve()
    key = (str(target), max_depth)
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None:
            return cached
    base_depth = len(target.parts)
    out: List[Tuple[Path, str]] = []
    try:
        walker = os.walk(str(target), followlinks=False)
    except OSError as e:
        logger.debug(
            "sca.reachability._walker: os.walk failed on %s (%s)",
            target, e,
        )
        return ()
    for dirpath, dirnames, filenames in walker:
        depth = len(Path(dirpath).parts) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in dirnames if d not in EXCLUDED_DIR_NAMES
            ]
        dp = Path(dirpath)
        for fn in filenames:
            dot = fn.rfind(".")
            suffix = fn[dot:].lower() if dot > 0 else ""
            out.append((dp / fn, suffix))
    result = tuple(out)
    with _CACHE_LOCK:
        if len(_CACHE) >= _CACHE_MAX_TARGETS and key not in _CACHE:
            oldest = next(iter(_CACHE))
            _CACHE.pop(oldest, None)
        _CACHE[key] = result
    return result


def iter_source_files(
    target: Path,
    extensions: Set[str],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    extra_excluded_dir_names: FrozenSet[str] = frozenset(),
) -> Iterable[Path]:
    """Yield files under ``target`` whose suffix is in ``extensions``.

    ``extensions`` is a set of lowercased suffixes including the dot
    (``{".py"}``, ``{".js", ".ts"}``). ``extra_excluded_dir_names`` is
    a set of directory names beyond the canonical exclusion list —
    apply the per-scanner extras here (``bin``/``obj`` for .NET,
    ``var``/``cache`` for PHP, etc.) rather than in the shared walk
    so unrelated scanners still see those subtrees.
    """
    target_resolved = target.resolve()
    rows = walk_source_files(target_resolved, max_depth=max_depth)
    if not extra_excluded_dir_names:
        for path, suffix in rows:
            if suffix in extensions:
                yield path
        return
    extras = extra_excluded_dir_names
    # Match dir-name exclusions only against path components BELOW
    # the target root. Pre-fix the system tempdir component (e.g.
    # ``/tmp/...``) collided with PHP's ``"cache"`` / Ruby's
    # ``"tmp"`` extras and the scanner silently emitted nothing for
    # files under a pytest ``tmp_path``.
    for path, suffix in rows:
        if suffix not in extensions:
            continue
        try:
            rel = path.relative_to(target_resolved)
        except ValueError:
            # ``path`` not under target — shouldn't happen because
            # ``walk_source_files`` walks from target; but be
            # defensive rather than yield something we can't classify.
            continue
        if any(p in extras for p in rel.parts):
            continue
        yield path


def _reset_cache_for_tests() -> None:
    """Tests that share a ``tmp_path`` across reach scanners need the
    cached walk evicted between cases; production never calls this."""
    with _CACHE_LOCK:
        _CACHE.clear()


__all__ = [
    "DEFAULT_MAX_DEPTH",
    "walk_source_files",
    "iter_source_files",
]
