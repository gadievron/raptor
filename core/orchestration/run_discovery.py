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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
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
    target_path: Path | str | None = None,
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
        target_path=target_path,
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
    target_path: Path | str | None = None,
) -> list[Path]:
    """Collect all sibling run directories containing a marker file.

    Tier 0 is the session RUN LEDGER — the exact list of runs this
    session produced (project and standalone alike): the natural cache
    scope for the /understand → /validate handoff, and it can never
    pick up a NEIGHBOUR session's in-flight run the way a bare
    newest-dir scan can. Ledger entries are candidate HINTS only —
    the marker, dir_filter, and target gate still decide.

    ``target_path`` is the recorded-target gate: a candidate whose
    ``.raptor-run.json`` records a DIFFERENT target is rejected
    (metadata-less legacy dirs are admitted, as the audit bridge
    always did) — cross-target artifacts must never steer a run just
    because they share an out root.

    Returns deduplicated list (by resolved path), unsorted.
    """
    origin_dir = Path(origin_dir)
    exclude = Path(exclude) if exclude else origin_dir

    seen: set = set()
    results: list[Path] = []

    for led in _ledger_candidates(marker, exclude, dir_filter):
        # Resolved-Path keys, same as _scan_dir — mixed key types made
        # cross-tier dedup silently miss.
        key = led.resolve()
        if key not in seen:
            seen.add(key)
            results.append(led)

    parent = Path(search_root) if search_root else origin_dir.parent
    _scan_dir(parent, marker, exclude, dir_filter, seen, results)

    # Target gate BEFORE the global-fallback decision: wrong-target
    # siblings must not count as "found" — pre-fix they suppressed the
    # global scan and were then filtered out, losing valid prior
    # evidence that only existed under the global out root.
    def _target_gated(dirs: list[Path]) -> list[Path]:
        if target_path is None:
            return dirs
        return [d for d in dirs
                if recorded_target_matches(d, target_path)]

    results = _target_gated(results)

    if search_global and not results:
        try:
            from core.config import RaptorConfig
            out_root = Path(RaptorConfig.get_out_dir())
        except Exception:
            out_root = None
        if out_root and out_root.is_dir() and out_root.resolve() != parent.resolve():
            _scan_dir(out_root, marker, exclude, seen=seen, results=results,
                      dir_filter=dir_filter)
            results = _target_gated(results)

    return results


def _ledger_candidates(marker, exclude, dir_filter):
    """Session-ledger run dirs carrying *marker* (tier 0)."""
    out = []
    try:
        from core.project.sessions import ledger_runs
        for record in ledger_runs():
            d = Path(record["run_dir"])
            try:
                if exclude is not None and \
                        d.resolve() == Path(exclude).resolve():
                    continue
                if not (d / marker).is_file():
                    continue
            except OSError:
                continue
            if dir_filter is not None and not dir_filter(d):
                continue
            out.append(d)
    except Exception:  # noqa: BLE001 — tier 0 is an aid, never a gate
        logger.debug("ledger tier-0 discovery failed", exc_info=True)
    return out


def recorded_target_matches(run_dir: Path,
                            target_path: Path | str) -> bool:
    """False only when the candidate's run metadata records a target
    that is NOT *target_path* (resolved comparison, containment
    either way). Metadata-less dirs are admitted — legacy tolerance."""
    try:
        from core.json import load_json
        meta = load_json(Path(run_dir) / ".raptor-run.json",
                         max_bytes=1024 * 1024)
        recorded = (meta or {}).get("target_path") if isinstance(meta, dict) else None
        if recorded is None or recorded == "":
            return True
        if not isinstance(recorded, str):
            return False  # typed corruption is tamper, not legacy
        from core.run.output import _URL_SCHEME_RE
        rec_url = bool(_URL_SCHEME_RE.match(recorded))
        qry_url = bool(_URL_SCHEME_RE.match(str(target_path)))
        if rec_url or qry_url:
            # URLs are opaque: never Path-resolve (a URL resolved
            # against a cwd inside the queried target read as a
            # same-target sibling). URL vs filesystem never matches.
            return (rec_url and qry_url
                    and recorded.rstrip("/")
                    == str(target_path).rstrip("/"))
        a = Path(recorded).resolve()
        b = Path(target_path).resolve()
        return a == b or a in b.parents or b in a.parents
    except Exception:  # noqa: BLE001 — unreadable metadata: admit (legacy)
        return True


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
