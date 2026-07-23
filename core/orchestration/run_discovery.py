"""Shared sibling-run discovery for cross-skill orchestration bridges.

All bridges (audit, exploit, understand) need to find output from a
prior run in a different skill. The search pattern is identical:

  1. Scan sibling directories (same project) for a marker file
  2. Fall back to the global out/ directory
  3. Deduplicate by resolved path
  4. Pick the best candidate (newest by mtime)

This module extracts that pattern so each bridge only specifies what
marker file to look for and any additional filter logic.
"""

from __future__ import annotations

import logging
from pathlib import Path
from collections.abc import Callable

logger = logging.getLogger(__name__)


def find_sibling_run(
    origin_dir: Path,
    marker: str,
    *,
    dir_filter: Callable[[Path], bool] | None = None,
    search_global: bool = True,
    exclude: Path | None = None,
    search_root: Path | None = None,
) -> Path | None:
    """Find the most recent sibling run directory containing a marker file.

    Args:
        origin_dir: The current run's output directory. Its parent is
            searched first (project siblings).
        marker: Filename to look for (e.g. "constraints.json").
        dir_filter: Optional predicate on candidate directories. Return
            True to include, False to skip.
        search_global: Whether to fall back to the global out/ root.
        exclude: Directory to skip (typically origin_dir itself).
        search_root: Override the sibling search root instead of using
            origin_dir.parent. Use when the caller already knows the
            project directory (e.g. exploit_bridge receives project_dir).

    Returns:
        Path to the best matching directory, or None.
    """
    candidates = collect_sibling_runs(
        origin_dir, marker,
        dir_filter=dir_filter,
        search_global=search_global,
        exclude=exclude,
        search_root=search_root,
    )
    return _pick_newest(candidates, marker)


def collect_sibling_runs(
    origin_dir: Path,
    marker: str,
    *,
    dir_filter: Callable[[Path], bool] | None = None,
    search_global: bool = True,
    exclude: Path | None = None,
    search_root: Path | None = None,
) -> list[Path]:
    """Collect all sibling run directories containing a marker file.

    Returns deduplicated list (by resolved path), unsorted.
    """
    origin_dir = Path(origin_dir)
    exclude = Path(exclude) if exclude else origin_dir

    seen: set = set()
    results: list[Path] = []

    parent = Path(search_root) if search_root else origin_dir.parent
    _scan_dir(parent, marker, exclude, dir_filter, seen, results)

    if search_global and results == []:
        try:
            from core.config import RaptorConfig
            out_root = Path(RaptorConfig.get_out_dir())
        except Exception:
            out_root = None
        if out_root and out_root.is_dir() and out_root.resolve() != parent.resolve():
            _scan_dir(out_root, marker, exclude, dir_filter, seen, results)

    return results


def _scan_dir(
    parent: Path,
    marker: str,
    exclude: Path,
    dir_filter: Callable[[Path], bool] | None,
    seen: set,
    results: list[Path],
) -> None:
    """Scan a directory for subdirectories containing the marker file."""
    if not parent.is_dir():
        return
    try:
        children = list(parent.iterdir())
    except OSError:
        return

    for child in children:
        try:
            if not child.is_dir():
                continue
            if child == exclude:
                continue
            if child.name.startswith((".", "_")):
                continue
            if not (child / marker).exists():
                continue
            if dir_filter and not dir_filter(child):
                continue
        except OSError:
            continue

        resolved = child.resolve()
        if resolved not in seen:
            seen.add(resolved)
            results.append(child)


def _pick_newest(candidates: list[Path], marker: str) -> Path | None:
    """Pick the most recent candidate by marker file mtime."""
    if not candidates:
        return None

    def _safe_mtime(p: Path) -> float:
        try:
            return (p / marker).stat().st_mtime
        except OSError:
            return 0.0

    candidates.sort(key=_safe_mtime, reverse=True)
    return candidates[0]
