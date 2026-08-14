"""Source-hash + audit-log helpers for the /audit review loop.

Post-migration surface: ``record_review`` and the ``coverage-audit.json``
writer path were removed as part of the annotation → journal migration
(see ``design/coverage-annotation-redesign-amendment-2026-07-28.md``).
The review journal is the sole authority for LLM review state; the
coverage store imports LLM review existence from the journal, not from
this module.

What remains here:

- :func:`_compute_hash` — source-content hash for staleness detection.
  Called by :func:`core.audit.collector.append_journal_for_outcome`.
- :func:`load_audit_log` / :func:`append_audit_log` — the
  ``.audit-log.jsonl`` event log (context-load / tool-dispatch / batch-
  flush events). Review outcomes went to the review journal from
  2026-07-28 onwards; this log carries non-review events only.
- :func:`_resolve_annotations_dir` — project-level annotations dir
  resolution, used by consumers that write / read human annotations.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _resolve_annotations_dir(out_dir: Path) -> Path:
    """Resolve annotations directory to project level when possible.

    Project runs have out_dir = project_dir/<run_name>/, so
    out_dir.parent is the project directory. Annotations at the project
    level survive /project clean (which deletes run dirs).

    Detection: a run dir contains .raptor-run.json (written by
    raptor-run-lifecycle start). If present, the parent is the
    project directory.
    """
    run_marker = out_dir / ".raptor-run.json"
    if run_marker.exists():
        project_dir = out_dir.parent
        if project_dir and project_dir != out_dir:
            return project_dir / "annotations"
    return out_dir / "annotations"


def load_audit_log(out_dir: Path) -> List[Dict[str, Any]]:
    """Load the audit event log (one JSON record per line).

    Since 2026-07-28 this log carries non-review events only —
    ``action=context``, ``action=tool_dispatch``, ``action=batch_flush``,
    ``action=record_migrated`` stub (one-shot per run for grep
    discoverability), etc. Review outcomes moved to
    ``review-journal.jsonl`` in the same directory.
    """
    log_path = out_dir / ".audit-log.jsonl"
    if not log_path.exists():
        return []
    records = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def append_audit_log(out_dir: Path, entry: Dict[str, Any]) -> None:
    """Append an entry to the audit event log."""
    log_path = out_dir / ".audit-log.jsonl"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _compute_hash(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: Optional[int],
) -> Optional[str]:
    """Compute source hash for staleness detection.

    Returns None if the source file is missing or hashing failed —
    callers treat a missing hash as ``source_hash=""`` on journal
    entries, which effectively disables staleness checks for that
    function (safe over-review, not silent miss).
    """
    full_path = target_path / file_path
    if not full_path.exists():
        return None

    try:
        from core.annotations.storage import compute_function_hash
        end = line_end if line_end is not None else line_start
        return compute_function_hash(full_path, line_start, end)
    except Exception:
        logger.debug("hash computation failed for %s:%d", file_path, line_start)
        return None
