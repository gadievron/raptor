"""Apply Ghidra diff priority to a checklist.

When a version-diff.json exists (from a prior ``/ghidra diff`` run),
marks changed and added functions as ``priority=high`` in the
checklist so they are analysed first by ``/agentic`` or ``/audit``.

The diff is found by scanning the project's output dirs for
``version-diff.json``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)


def _find_version_diff(target_path: Path) -> Optional[Path]:
    """Find the most recent version-diff.json for the target."""
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        project = mgr.find_project_for_target(str(target_path))
        if project is None:
            return None
        for run_dir in project.get_run_dirs():
            candidate = run_dir / "version-diff.json"
            if candidate.is_file():
                return candidate
    except Exception:  # noqa: BLE001
        pass

    # Configured out base, NOT the process CWD: a caller launched
    # outside the repo root (API consumers, tests, a future daemon)
    # silently got "no version diff" from a bare Path("out").
    try:
        from core.config import RaptorConfig
        out_base = RaptorConfig.get_out_dir()
    except Exception:  # noqa: BLE001 — probe fallback only
        out_base = Path("out")
    for candidate in out_base.glob("ghidra-diff-*/version-diff.json"):
        if candidate.is_file():
            return candidate

    return None


def _load_changed_names(diff_path: Path) -> Set[str]:
    """Load changed/added function names from a version-diff.json."""
    # RAPTOR-written input, budgeted like the package's other cache
    # readers; missing/corrupt/oversize all degrade to "no diff".
    from core.json import load_json

    from .context_inject import _MAX_CACHE_BYTES
    data = load_json(diff_path, max_bytes=_MAX_CACHE_BYTES)
    if not isinstance(data, dict):
        logger.debug("version diff unreadable: %s", diff_path)
        return set()

    names = set()
    for entry in data.get("added", []):
        name = entry.get("name", "")
        if name:
            names.add(name)
    for entry in data.get("changed", []):
        # matched diffs carry both names for renamed pairs; the
        # checklist may be keyed on either side's naming
        for key in ("name", "name_new"):
            name = entry.get(key, "")
            if name:
                names.add(name)

    return names


def _boost_items(checklist: dict, changed_names: Set[str]) -> int:
    """Mark changed/added functions ``priority=high`` in place.

    Returns the number of items boosted (already-high items are
    untouched and uncounted).
    """
    boosted = 0
    for file_entry in checklist.get("files", []):
        for item in file_entry.get("items", []):
            func_name = item.get("function", item.get("name", ""))
            if func_name in changed_names:
                existing = item.get("priority", "")
                if existing != "high":
                    item["priority"] = "high"
                    item["priority_reason"] = (
                        item.get("priority_reason", "")
                        + " [ghidra-diff: changed between versions]"
                    ).strip()
                    boosted += 1
    return boosted


def apply_diff_priority(
    target_path: Path,
    checklist_path: Path,
) -> int:
    """Boost changed functions in a checklist.

    *checklist_path* names a ``checklist.json`` slot; reads and the
    boost write both go through the ``core.inventory`` accessors on
    that slot's directory (flock, symlink containment, sharded-layout
    support, frame authentication — like ``bookmarks_bridge``, which
    routes through ``save_checklist``). A raw load + ``save_json``
    here would preserve a stale frame token, self-bricking the very
    checklist it boosts as tampered on the next accessor read.

    Returns the number of functions boosted (0 when there is no diff,
    no matching items, or the checklist is unreadable/refused).
    """
    diff_path = _find_version_diff(target_path)
    if diff_path is None:
        return 0

    changed_names = _load_changed_names(diff_path)
    if not changed_names:
        return 0

    from core.inventory import read_checklist, update_checklist

    output_dir = checklist_path.parent
    checklist = read_checklist(output_dir)
    if not checklist:
        logger.debug("checklist unreadable: %s", checklist_path)
        return 0

    # Dry-run count on the gated read: only write when something
    # changes — a no-op boost must not rewrite (and re-stamp) the
    # artifact.
    if _boost_items(checklist, changed_names) == 0:
        return 0

    boosted = 0

    def _transform(current: dict) -> dict:
        # Re-apply on the RMW's own locked read — the dry-run copy
        # above may be stale by the time the lock is held.
        nonlocal boosted
        boosted = _boost_items(current, changed_names)
        return current

    try:
        update_checklist(output_dir, _transform)
    except ValueError as exc:
        # The RMW refused (frame/integrity failure between the gated
        # read and the locked write). Degrade like every other miss
        # in this module: no boost, loud enough to diagnose.
        logger.warning("diff priority: checklist write refused: %s", exc)
        return 0

    if boosted > 0:
        logger.info(
            "diff priority: boosted %d functions from %s",
            boosted, diff_path.name,
        )
    return boosted
