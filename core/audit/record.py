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
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

#: Read budgets for the audit event log (see load_audit_log). A
#: legitimate log is a few MB on the largest runs; the reads-manifest
#: uses the same 64 MiB ceiling class.
_AUDIT_LOG_MAX_BYTES = 64 * 1024 * 1024
_AUDIT_LOG_MAX_LINE_BYTES = 1024 * 1024


def _resolve_annotations_dir(out_dir: Path) -> Path:
    """Resolve annotations directory to project level when possible.

    Project runs have out_dir = project_dir/<run_name>/, so
    out_dir.parent is the project directory. Annotations at the project
    level survive /project clean (which deletes run dirs).

    Detection: a run dir contains .raptor-run.json (written by
    raptor-run-lifecycle start). If present, the parent is the
    project directory.
    """
    # The run pin decides the project level — pre-fix bare
    # out_dir.parent lost the operator's human-grade annotation inputs
    # (Reflexion veto, FP primers) for --out runs, and standalone runs
    # shared a pseudo project dir. Pin-less legacy dirs keep the
    # marker+parent probe.
    try:
        from core.run.pin import pin_project_dir, resolve_run_pin
        pin = resolve_run_pin(out_dir)
        if pin.authoritative:
            project_dir = pin_project_dir(out_dir)
            if project_dir is not None and project_dir != out_dir:
                return project_dir / "annotations"
            return out_dir / "annotations"
    except Exception:  # noqa: BLE001 — legacy probe below
        pass
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

    Row contract: rows written by this install carry the per-purpose,
    run-bound ``integrity`` stamp (see :func:`stamp_audit_log_row`)
    and are returned WITH it — consumers read fields and must
    tolerate the stamp like any additive key; only the resume
    suppression reader gives it meaning.
    """
    log_path = out_dir / ".audit-log.jsonl"
    from core.json import load_jsonl
    # Byte-budgeted: the log is sandbox-writable run-dir input that
    # now carries suppression authority — same intake rule as the
    # journal's cap; an over-budget trail loads as [] (nothing
    # suppresses, telemetry consumers degrade — over-review).
    return load_jsonl(
        log_path,
        max_total_bytes=_AUDIT_LOG_MAX_BYTES,
        max_line_bytes=_AUDIT_LOG_MAX_LINE_BYTES,
    )


def load_verified_audit_log(out_dir: Path) -> list[dict[str, Any]]:
    """Rows of the audit event log whose run-bound integrity token
    verifies — the loader for AUTHORITY-bearing consumers.

    The log lives in the target-writable run dir; any consumer whose
    read SUPPRESSES work or relaxes a gate (resume dedup, fail_open
    census-site deferral, the end-of-run re-log join, cmd_record's
    mechanical gates) must judge only rows this install minted for
    THIS run directory, or a planted row steers the decision
    (``core.coverage.journal_mac``, audit-log domain, run-bound).
    Unstamped (pre-MAC legacy or forged), tampered, and cross-run-
    replayed rows are dropped here and thereby fail toward
    NOT-suppressing — the same tolerant-reader compromise as the
    journal's unstamped tier. Telemetry consumers (strategy stats,
    critique, gate-engagement summaries) keep reading
    :func:`load_audit_log` directly: dropped rows keep their
    telemetry value, they just never carry authority. The consumer
    census test pins which readers sit on which side.
    """
    from core.coverage import journal_mac
    binding = journal_mac.audit_log_run_binding(out_dir)
    verified: list[dict[str, Any]] = []
    dropped = 0
    for row in load_audit_log(out_dir):
        if not isinstance(row, dict):
            dropped += 1
            continue
        if journal_mac.verify_audit_log_row(
            row, row.get(journal_mac.TOKEN_KEY), binding,
        ):
            verified.append(row)
        else:
            dropped += 1
    if dropped:
        logger.warning(
            "audit log: %d row(s) without a verifying integrity token "
            "excluded from an authority-bearing read (telemetry "
            "consumers still see them; affected functions/sites "
            "re-review)", dropped,
        )
    return verified


def stamp_audit_log_row(
    entry: dict[str, Any], out_dir: Path,
) -> dict[str, Any]:
    """The entry with its integrity token minted (a copy).

    The log lives in the target-writable run dir, and one row class
    (``action=record`` / ``orchestrator_review``) grants resume
    review-SUPPRESSION authority — the same forged-clean-row lever
    the journal MAC closed, so the same per-purpose key mechanism
    stamps this lane (``core.coverage.journal_mac``, audit-log
    domain), run-bound to *out_dir* so a row copied from a sibling
    run's log never verifies here. No usable key = persist unstamped:
    the row keeps its telemetry value and simply never suppresses.
    """
    from core.coverage import journal_mac
    stamped = {
        k: v for k, v in entry.items() if k != journal_mac.TOKEN_KEY
    }
    token = journal_mac.mint_audit_log_row(
        stamped, journal_mac.audit_log_run_binding(out_dir))
    if token:
        stamped[journal_mac.TOKEN_KEY] = token
    return stamped


def append_audit_log(out_dir: Path, entry: dict[str, Any]) -> None:
    """Append an entry to the audit event log.

    Routed through ``core.json.append_jsonl`` so the trail gets the
    same O_APPEND line-atomicity and O_NOFOLLOW symlink refusal as
    every other JSONL trail writer, and stamped with the audit-log
    integrity token (see :func:`stamp_audit_log_row`) — the row
    lands on disk with the ``integrity`` key appended and otherwise
    byte-identical to *entry* (compact separators).
    """
    log_path = out_dir / ".audit-log.jsonl"
    from core.json import append_jsonl
    append_jsonl(log_path, stamp_audit_log_row(entry, out_dir),
                 compact=True)


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

def binary_item_hash(file_entry: dict, item: dict) -> str | None:
    """Staleness anchor for a binary checklist item.

    Binds the review to the BINARY's content (the file entry's
    sha256, stamped at checklist build) and the function's
    address/size — a rebuilt binary or a moved/resized function
    invalidates the review instead of silently suppressing it.
    Self-describing ``bin:`` prefix so the journal fold can route it.
    """
    sha = file_entry.get("sha256") or ""
    addr = item.get("address")
    if addr is None:
        addr = (item.get("metadata") or {}).get("address")
    if not sha or addr is None:
        return None
    size = item.get("size") or (item.get("metadata") or {}).get("size") or 0
    # Checklists round-trip through JSON and other producers may spell
    # addresses as hex strings — coerce so both forms hash identically;
    # unparsable values return None (missing hash only widens review)
    # instead of raising out of the caller's checklist walk.
    addr = _as_int(addr)
    size = _as_int(size)
    if addr is None or size is None:
        return None
    return f"bin:{sha[:12]}:{addr:x}:{size:x}"


def _as_int(value: Any) -> int | None:
    """``value`` as an int; accepts hex/octal/binary string spellings
    (``int(x, 0)``). None when unparsable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def binary_source_hash(
    out_dir: Path, file_path: str, function_name: str,
) -> str | None:
    """Write-time twin of :func:`binary_item_hash` — resolves the
    item from the run's checklist."""
    try:
        from pathlib import Path as _Path

        from core.audit.gaps import load_checklist
        cl = load_checklist(_Path(out_dir))
        for fe in (cl or {}).get("files", []):
            if fe.get("path") != file_path:
                continue
            items = fe.get("items", fe.get("functions", [])) or []
            for item in items:
                if item.get("name") == function_name:
                    return binary_item_hash(fe, item)
    except Exception:  # noqa: BLE001 — missing hash only widens review
        logger.debug(
            "binary source hash failed for %s:%s",
            file_path, function_name, exc_info=True,
        )
    return None
