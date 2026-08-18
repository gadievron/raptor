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
  ``.audit-log.jsonl`` event log. Carries non-review events
  (context-load / tool-dispatch / batch-flush) PLUS per-review
  telemetry: Collector.submit still appends one
  ``action="orchestrator_review"`` record per review (status,
  hypothesis, evidence_tool, cost) which strategy_stats aggregates
  for cross-run strategy win rates. The review journal (from
  2026-07-28 onwards) remains the sole AUTHORITY for verdicts —
  these log records are telemetry, not review state.
- :func:`_resolve_annotations_dir` — project-level annotations dir
  resolution, used by consumers that write / read human annotations.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

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


def load_audit_log(out_dir: Path) -> list[dict[str, Any]]:
    """Load the audit event log (one JSON record per line).

    Carries operational events — ``action=context``,
    ``action=tool_dispatch``, ``action=batch_flush``,
    ``action=record_migrated`` stub (one-shot per run for grep
    discoverability) — plus one ``action=orchestrator_review``
    telemetry record per review (written by Collector, consumed by
    strategy_stats). Authoritative review VERDICTS live in
    ``review-journal.jsonl`` in the same directory (since 2026-07-28).
    """
    log_path = out_dir / ".audit-log.jsonl"
    from core.json import load_jsonl
    return load_jsonl(log_path)


def append_audit_log(out_dir: Path, entry: dict[str, Any]) -> None:
    """Append an entry to the audit event log.

    Routed through ``core.json.append_jsonl`` so the trail gets the
    same O_APPEND line-atomicity and O_NOFOLLOW symlink refusal as
    every other JSONL trail writer.
    """
    log_path = out_dir / ".audit-log.jsonl"
    from core.json import append_jsonl
    append_jsonl(log_path, entry, compact=True)


def _compute_hash(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: int | None,
) -> str | None:
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
    except Exception:  # noqa: BLE001 — best-effort: missing hash only widens review
        logger.debug("hash computation failed for %s:%d", file_path, line_start)
        return None
