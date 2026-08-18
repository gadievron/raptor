"""Same-run resume substrate for /audit — ``raptor-audit resume``.

An audit killed by an external supervisor (harness background-shell
cap, SIGTERM, OOM) leaves coherent artifacts: the review journal holds
every completed verdict, ``cost-breakdown.json`` holds the reconciled
spend ledger, and ``checklist.json`` pins the original scope. This
module provides the mechanical pieces that let a later invocation
re-enter that run AS THE SAME RUN:

* ``audit-run-config.json`` — the run's resolved options, persisted at
  ``raptor-audit run`` start so resume recomputes the remaining work
  against the ORIGINAL checklist/scope/pins/budget, not fresh flags;
* eligibility — refuse to resume a completed run (its results are
  final; new work belongs in a new run where cross-run verdict reuse
  imports the priors at $0) or a run whose worker is still alive;
* the staleness gate — compare the journal's recorded per-function
  ``source_hash`` values against the target tree NOW (same hash checks
  as the cross-run fold, ``core.staleness.hash_spans``); any drift
  refuses the resume unless ``--allow-drift``, which instead
  resurfaces each drifted function for a real re-review, loudly;
* the budget math — remaining budget = original cap minus booked
  spend, where the reconciled ledger (``cost-breakdown.json``
  ``totals.total_spend_usd``) is authoritative;
* resume-marker rows — appended to the run's audit log and LLM
  telemetry JSONL so both ledgers record the segment boundary.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RUN_CONFIG_FILENAME = "audit-run-config.json"


# ── Run-config persistence ───────────────────────────────────────────

def save_run_config(out_dir: Path, config: dict[str, Any]) -> Path:
    """Atomically persist the run's resolved options.

    Written once at ``raptor-audit run`` start (segment 1). Resume
    reads it back so segment N runs under the ORIGINAL configuration;
    it never re-derives options from fresh CLI flags.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RUN_CONFIG_FILENAME
    fd, tmp = tempfile.mkstemp(
        dir=str(out_dir), prefix=".audit-run-config-", suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, default=str)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return path


def load_run_config(out_dir: Path) -> dict[str, Any] | None:
    """Load ``audit-run-config.json``, or ``None`` when absent/corrupt."""
    path = Path(out_dir) / RUN_CONFIG_FILENAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("could not read %s", path, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


# ── Eligibility ──────────────────────────────────────────────────────

def resume_ineligibility(out_dir: Path) -> str | None:
    """Why *out_dir* may NOT be resumed. ``None`` when eligible.

    Refusals:
    * no run metadata — not a run directory;
    * status ``completed`` — final results; point the operator at a
      fresh run (verdict reuse re-imports the priors at $0 there);
    * status ``running`` with the recorded worker still alive — the
      run is actually in flight, resuming would double-drive it.
    """
    from core.run.metadata import (
        RESUMABLE_STATUSES,
        STATUS_RUNNING,
        _tool_pid_alive,
        load_run_metadata,
    )

    meta = load_run_metadata(Path(out_dir))
    if not meta:
        return f"no .raptor-run.json in {out_dir} — not a run directory"
    status = meta.get("status")
    if status == "completed":
        return (
            "run is completed — completed runs are never resumed. "
            "Start a new run on the same project instead: cross-run "
            "verdict reuse imports this run's verdicts at $0 and "
            "reviews only the remaining gaps."
        )
    if status not in RESUMABLE_STATUSES:
        return f"run status {status!r} is not resumable"
    if status == STATUS_RUNNING and _tool_pid_alive(meta.get("tool_pid")):
        return (
            "run is still in flight (recorded worker process is "
            "alive) — resuming now would double-drive it. Wait for "
            "it to stop, or kill it first."
        )
    return None


# ── Staleness gate ───────────────────────────────────────────────────

@dataclass
class DriftItem:
    """One journaled verdict whose source has changed since review."""

    file: str
    function: str
    stored_hash: str
    current_hash: str  # "" when the file/span is gone or unreadable


def compute_drift(
    out_dir: Path,
    target_path: Path,
) -> tuple[list[DriftItem], int]:
    """Re-verify every hashed journal verdict against the target NOW.

    Returns ``(drifted, checked)`` where *checked* counts the entries
    that carried a verifiable ``source_hash``. Uses the same span
    hashing as the cross-run reuse fold (``core.staleness.hash_spans``,
    common-prefix comparison), so the resume gate and the in-run fold
    can never disagree about what "changed" means.

    Error verdicts are skipped (they are retried, not reused); entries
    without a recorded hash cannot be verified and are not counted.
    """
    from core.staleness import hash_spans

    from .journal import latest_entries

    by_file: dict[str, list[Any]] = {}
    for entry in latest_entries(Path(out_dir)).values():
        if entry.verdict == "error" or not entry.source_hash:
            continue
        if not entry.line_start:
            continue
        by_file.setdefault(entry.file, []).append(entry)

    drifted: list[DriftItem] = []
    checked = 0
    target_path = Path(target_path)
    for file_path, entries in sorted(by_file.items()):
        resolved = _safe_target_join(target_path, file_path)
        spans = [
            (e.line_start, e.line_end or e.line_start) for e in entries
        ]
        if resolved is None or not resolved.is_file():
            current_hashes = [""] * len(entries)
        else:
            current_hashes = hash_spans(resolved, spans)
        for entry, current in zip(entries, current_hashes):
            checked += 1
            stored = entry.source_hash
            if not current or current[:len(stored)] != stored[:len(current)]:
                drifted.append(DriftItem(
                    file=entry.file,
                    function=entry.function,
                    stored_hash=stored,
                    current_hash=current,
                ))
    return drifted, checked


def _safe_target_join(target_path: Path, rel: str) -> Path | None:
    """Join a journal-recorded relative path under the target root,
    refusing traversal — journal files are run artifacts, not trusted
    path input. Same helper the reuse fold uses."""
    from ._util import safe_join
    return safe_join(target_path, rel)


# ── Budget math ──────────────────────────────────────────────────────

def load_prior_cost_breakdown(out_dir: Path) -> dict[str, Any] | None:
    """The prior segments' reconciled ledger (``cost-breakdown.json``)."""
    path = Path(out_dir) / "cost-breakdown.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("could not read %s", path, exc_info=True)
        return None
    return data if isinstance(data, dict) else None


def booked_spend_usd(breakdown: dict[str, Any] | None) -> float:
    """Booked spend from a reconciled ledger dict.

    ``totals.total_spend_usd`` (the authoritative client ledger,
    injected at reconciliation) when present; otherwise the sum of
    what the phases captured. A missing ledger books $0 — a run
    killed before its first reconciliation spent whatever the journal
    entries carry, and those are $-stamped per entry; the honest floor
    for the *ledger* is zero, and the operator-facing resume line
    states which figure was used.
    """
    if not breakdown:
        return 0.0
    totals = breakdown.get("totals") or {}
    spend = totals.get("total_spend_usd")
    if isinstance(spend, (int, float)) and not isinstance(spend, bool):
        return max(0.0, float(spend))
    tracked = 0.0
    for key in ("cost_usd", "failed_attempts_cost_usd"):
        v = totals.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            tracked += float(v)
    return max(0.0, tracked)


def journal_spend_usd(out_dir: Path) -> float:
    """Fallback booked-spend floor: per-entry ``cost_usd`` sums from
    the review journal. Used when no reconciled ledger exists (the run
    died before its first reconciliation) — the journal records what
    each completed review cost, so this is a demonstrable lower bound.
    """
    from .journal import load_entries

    total = 0.0
    try:
        for entry in load_entries(Path(out_dir)):
            cost = entry.cost_usd
            if isinstance(cost, (int, float)) and not isinstance(cost, bool):
                total += max(0.0, float(cost))
    except Exception:
        logger.debug("journal spend fallback failed", exc_info=True)
    return total


SPEND_FLOOR_FILENAME = "spend-floor.json"


def persist_spend_floor(
    out_dir: Path,
    spend_usd: float,
    segment: int | None = None,
) -> None:
    """Atomically persist an incremental whole-run spend floor.

    ``cost-breakdown.json`` is only written at reconciliation/salvage,
    so a segment killed hard (SIGKILL, OOM) booked $0 and the next
    segment's remaining budget overspent the cap by the dead segment's
    whole spend. This sidecar is updated cheaply during the run; the
    resume budget math takes ``max(reconciled ledger, journal floor,
    spend floor)``.

    Monotonic: never lowers the recorded figure (a resumed segment's
    ledger starts below the whole-run floor until it re-books the
    prior segments).
    """
    out_dir = Path(out_dir)
    if not out_dir.is_dir():
        return
    spend_usd = max(0.0, float(spend_usd))
    if spend_usd <= spend_floor_usd(out_dir):
        return
    payload: dict[str, Any] = {"spend_usd": round(spend_usd, 6)}
    if segment is not None:
        payload["segment"] = segment
    path = out_dir / SPEND_FLOOR_FILENAME
    fd, tmp = tempfile.mkstemp(
        dir=str(out_dir), prefix=".spend-floor-", suffix=".json",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def spend_floor_usd(out_dir: Path) -> float:
    """The persisted incremental spend floor, $0 when absent/corrupt."""
    path = Path(out_dir) / SPEND_FLOOR_FILENAME
    if not path.is_file():
        return 0.0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.debug("could not read %s", path, exc_info=True)
        return 0.0
    if not isinstance(data, dict):
        return 0.0
    spend = data.get("spend_usd")
    if isinstance(spend, (int, float)) and not isinstance(spend, bool):
        return max(0.0, float(spend))
    return 0.0


#: Effective cap handed to the pipeline when the remaining budget is
#: zero or negative: small enough that the reservation gate refuses
#: every LLM call, while the $0 verdict re-import, the mechanical
#: passes, and the final report still run.
EXHAUSTED_BUDGET_EPSILON_USD = 1e-6


def remaining_budget_usd(
    original_cap: float | None,
    booked: float,
) -> float | None:
    """Remaining budget = original cap minus booked spend.

    ``None`` (no cap) stays ``None``. A fully-consumed cap returns
    :data:`EXHAUSTED_BUDGET_EPSILON_USD` rather than 0/negative —
    ``max_cost_usd=0`` reads as "no cap" throughout the orchestrator,
    which would be the exact opposite of the operator's intent.
    """
    if original_cap is None:
        return None
    remaining = float(original_cap) - max(0.0, booked)
    if remaining <= 0:
        return EXHAUSTED_BUDGET_EPSILON_USD
    return remaining


# ── Resume markers ───────────────────────────────────────────────────

def append_resume_markers(out_dir: Path, segment: int) -> None:
    """Append one resume-marker row to each append-ledger.

    * audit log (``.audit-log.jsonl``): ``{"action": "resume", ...}``;
    * LLM telemetry (``llm-telemetry.jsonl``): an ``event:
      "resume_marker"`` row (consumers aggregate by ``call_class`` and
      tolerate foreign rows).

    Best-effort — a marker failure must never block the resume.
    """
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    try:
        from .record import append_audit_log
        append_audit_log(Path(out_dir), {
            "action": "resume",
            "segment": segment,
            "ts": ts,
        })
    except Exception:
        logger.debug("audit-log resume marker failed", exc_info=True)
    try:
        from core.llm.telemetry import TELEMETRY_FILENAME
        row = {
            "event": "resume_marker",
            "call_class": "resume_marker",
            "segment": segment,
            "ts": ts,
        }
        path = Path(out_dir) / TELEMETRY_FILENAME
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
    except Exception:
        logger.debug("telemetry resume marker failed", exc_info=True)
