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


def apply_diff_priority(
    target_path: Path,
    checklist_path: Path,
) -> int:
    """Boost changed functions in a checklist.

    Returns the number of functions boosted.
    """
    diff_path = _find_version_diff(target_path)
    if diff_path is None:
        return 0

    changed_names = _load_changed_names(diff_path)
    if not changed_names:
        return 0

    from core.json import load_json

    from .context_inject import _MAX_CACHE_BYTES
    checklist = load_json(checklist_path, max_bytes=_MAX_CACHE_BYTES)
    if not isinstance(checklist, dict):
        logger.debug("checklist unreadable: %s", checklist_path)
        return 0

    items = []
    for file_entry in checklist.get("files", []):
        items.extend(file_entry.get("items", []))
    boosted = 0
    for item in items:
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

    if boosted > 0:
        # Atomic replace: checklist.json is a shared pipeline artifact
        # with concurrent lock-free readers (bookmarks_bridge writes
        # the same file via save_json for exactly this reason) — a
        # truncate-in-place write hands a reader the empty-file window
        # and a JSONDecodeError mid-pipeline.
        from core.json import save_json
        save_json(checklist_path, checklist)
        logger.info(
            "diff priority: boosted %d functions from %s",
            boosted, diff_path.name,
        )

    return boosted
