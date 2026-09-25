"""Same-run resume for /audit — ``raptor-audit resume``.

An audit killed by an external supervisor (harness background-shell
cap, SIGTERM, OOM) leaves coherent artifacts: the review journal holds
every completed verdict, ``cost-breakdown.json`` holds the reconciled
spend ledger, and ``checklist.json`` pins the original scope. This
module provides the audit-specific legs that let a later invocation
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

The pipeline-agnostic mechanics (config pinning, eligibility, the
span-hash drift compare, spend-evidence clamping, the incremental
spend floor, the budget math) live in :mod:`core.run.resume`; this
module binds them to the audit's journal, ledger, and artifacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.json.jsonl import append_jsonl
from core.json.utils import load_json
from core.run.resume import (  # noqa: F401 — re-exported audit surface
    _MAX_SPEND_EVIDENCE_USD,
    EXHAUSTED_BUDGET_EPSILON_USD,
    SPEND_FLOOR_FILENAME,
    SpanDriftRecord,
    _spend_value,
    max_of_evidence,
    persist_spend_floor,
    remaining_budget_usd,
    spans_drift,
    spend_floor_usd,
)
from core.run.resume import load_run_config as _load_run_config
from core.run.resume import (
    resume_ineligibility as _resume_ineligibility,
)
from core.run.resume import save_run_config as _save_run_config

logger = logging.getLogger(__name__)

RUN_CONFIG_FILENAME = "audit-run-config.json"

# Byte budget for loading audit resume evidence (run config, prior
# ledger, pipeline-tail marker). Real payloads are a few KiB; 8 MiB is
# generous headroom while keeping a planted oversize file unread.
_RUN_CONFIG_MAX_BYTES = 8 * 1024 * 1024

#: Staged by a launcher that owns this run's validation at the
#: pipeline level (the /agentic --gap-audit post-pass runs the audit
#: with --no-validate and validates the findings itself). When the
#: audit is interrupted and later resumed, that parent pipeline has
#: long since completed — the marker lets resume tell the operator
#: which tail steps nobody will run automatically.
PIPELINE_TAIL_FILENAME = "pipeline-tail.json"


# ── Run-config persistence ───────────────────────────────────────────

def save_run_config(out_dir: Path, config: dict[str, Any]) -> Path:
    """Atomically persist the run's resolved options.

    Written once at ``raptor-audit run`` start (segment 1). Resume
    reads it back so segment N runs under the ORIGINAL configuration;
    it never re-derives options from fresh CLI flags.
    """
    return _save_run_config(out_dir, config, filename=RUN_CONFIG_FILENAME)


def load_run_config(out_dir: Path) -> dict[str, Any] | None:
    """Load ``audit-run-config.json``, or ``None`` when absent/corrupt.

    Bounded load (see :func:`core.run.resume.load_run_config`): an
    oversize or unreadable config degrades to ``None`` like a corrupt
    one. ``_RUN_CONFIG_MAX_BYTES`` is read at call time so tests can
    tighten the budget.
    """
    return _load_run_config(
        out_dir, filename=RUN_CONFIG_FILENAME,
        max_bytes=_RUN_CONFIG_MAX_BYTES,
    )


# ── Eligibility ──────────────────────────────────────────────────────

def resume_ineligibility(out_dir: Path, reopen: bool = False) -> str | None:
    """Why *out_dir* may NOT be resumed. ``None`` when eligible.

    The substrate gates (see :func:`core.run.resume.resume_ineligibility`)
    bound to the audit's completion artifact: a genuinely completed
    audit always has an ``audit-report.json`` (the pipeline tail
    writes it before the lifecycle completes), so ``completed``
    WITHOUT a report means the status was stamped by a step that did
    not own the run (observed: a mapping-phase lifecycle complete on
    the audit dir) — ``reopen=True`` flips that contradiction — and
    only that contradiction — back to ``interrupted``.
    """
    return _resume_ineligibility(
        out_dir,
        completion_artifacts=("audit-report.json",),
        reopen=reopen,
        completed_hint=(
            "Start a new run on the same project instead: cross-run "
            "verdict reuse imports this run's verdicts at $0 and "
            "reviews only the remaining gaps."
        ),
        contradiction_example=(
            " (e.g. a mapping-phase lifecycle complete on the audit "
            "dir)"
        ),
    )


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
    common-prefix comparison — via :func:`core.run.resume.spans_drift`),
    so the resume gate and the in-run fold can never disagree about
    what "changed" means.

    Error verdicts are skipped (they are retried, not reused); entries
    without a recorded hash cannot be verified and are not counted.
    """
    from .journal import latest_entries

    by_file: dict[str, list[Any]] = {}
    for entry in latest_entries(Path(out_dir)).values():
        if entry.verdict == "error" or not entry.source_hash:
            continue
        if not entry.line_start:
            continue
        by_file.setdefault(entry.file, []).append(entry)

    records = [
        SpanDriftRecord(
            file=entry.file,
            label=entry.function,
            stored_hash=entry.source_hash,
            line_start=entry.line_start,
            line_end=entry.line_end or entry.line_start,
        )
        for _file, entries in sorted(by_file.items())
        for entry in entries
    ]
    drifted, checked = spans_drift(Path(target_path), records)
    return (
        [
            DriftItem(
                file=d.file,
                function=d.label,
                stored_hash=d.stored_hash,
                current_hash=d.current_hash,
            )
            for d in drifted
        ],
        checked,
    )


# ── Budget math ──────────────────────────────────────────────────────

def load_prior_cost_breakdown(out_dir: Path) -> dict[str, Any] | None:
    """The prior segments' reconciled ledger (``cost-breakdown.json``)."""
    path = Path(out_dir) / "cost-breakdown.json"
    if not path.is_file():
        return None
    data = load_json(path, max_bytes=_RUN_CONFIG_MAX_BYTES)
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
    spend = _spend_value(totals.get("total_spend_usd"))
    if spend is not None:
        return spend
    tracked = 0.0
    for key in ("cost_usd", "failed_attempts_cost_usd"):
        v = _spend_value(totals.get(key))
        if v is not None:
            tracked += v
    return tracked


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
            cost = _spend_value(entry.cost_usd)
            if cost is not None:
                total += cost
    except Exception:
        logger.debug("journal spend fallback failed", exc_info=True)
    return total


def resolve_prior_spend(out_dir: Path) -> tuple[float, str]:
    """Resolve the whole-run spend booked by all prior segments.

    Returns ``(booked_usd, note)`` where *note* names the winning
    source for the operator-facing resume line. The rule (single
    source of truth for both the remaining-budget math and the amount
    the resumed segment books into its OWN rewritten ledger): the MAX
    of the three surviving evidence sources —

    * the reconciled ledger (``cost-breakdown.json``
      ``totals.total_spend_usd``);
    * the review journal's per-entry cost floor — never
      double-counting, since reused verdicts journal at ``cost_usd=0``
      and a healthy cumulative ledger always meets or exceeds it; the
      journal can EXCEED a legacy own-segment-only ledger, where it is
      the best surviving evidence of the chain;
    * the incremental spend floor (``spend-floor.json``) — a
      hard-killed segment (SIGKILL/OOM) never reconciled, but the
      floor was persisted while it ran.

    The resolved figure MUST be what the resumed segment carries
    forward: booking only the prior ledger used to drop every segment
    before the immediately-prior one whenever a segment died
    unreconciled (observed live: segment 4 booked $47.29 of a ~$4,534
    run — a ~99% under-report in the final ledger).
    """
    out_dir = Path(out_dir)
    breakdown = load_prior_cost_breakdown(out_dir)
    ledger = booked_spend_usd(breakdown)
    journal = journal_spend_usd(out_dir)
    floor = spend_floor_usd(out_dir)
    journal_note = (
        "journal per-entry floor — exceeds the reconciled ledger"
        if breakdown is not None
        else "journal per-entry floor — the run died before its "
             "first ledger reconciliation"
    )
    evidence: list[tuple[float, str]] = []
    if breakdown is not None:
        evidence.append((ledger, "reconciled ledger"))
    evidence.append((journal, journal_note))
    evidence.append((
        floor,
        "incremental spend floor — the prior segment died before "
        "its ledger reconciliation",
    ))
    return max_of_evidence(evidence)


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
        append_jsonl(path, row, compact=True)
    except Exception:
        logger.debug("telemetry resume marker failed", exc_info=True)


def pipeline_tail_hint(out_dir: Path, findings_count: int) -> str | None:
    """Operator instructions for a resumed run's deferred pipeline tail.

    Returns None when no ``pipeline-tail.json`` marker exists, the
    marker is unreadable, or the run produced no findings (nothing to
    validate). Best-effort — never raises.
    """
    marker = Path(out_dir) / PIPELINE_TAIL_FILENAME
    data = load_json(marker, max_bytes=_RUN_CONFIG_MAX_BYTES)
    if not isinstance(data, dict) or findings_count <= 0:
        return None
    deferred = data.get("deferred") or []
    if not deferred:
        return None
    findings = Path(out_dir) / "findings.json"
    lines = [
        "This run was launched by a pipeline that deferred "
        f"{' + '.join(str(d) for d in deferred)} to itself; the parent "
        "run has completed and will not perform them for this resumed "
        "segment. To finish the tail:",
    ]
    if "validate" in deferred:
        lines.append(f"  /validate <target> --findings {findings}")
    if "feedback" in deferred:
        lines.append(
            "  libexec/raptor-audit feedback --validation-report "
            "<validate-out>/findings.json --annotations-dir "
            f"<annotations> --audit-out {Path(out_dir)}"
        )
    return "\n".join(lines)
