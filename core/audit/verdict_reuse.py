"""Cross-run verdict reuse — import prior journal verdicts at $0.

When a prior run's journal entry for a function still matches the
function's current source (hash-verified by the gap fold, see
``gaps._fold_project_index``), the prior verdict is imported into THIS
run as a ``reused`` outcome instead of being silently suppressed:

* the run's journal gets a fresh entry (``reused=true``,
  ``reused_from_run=<original run>``, cost $0), so every run carries a
  complete record of the project state it asserted;
* the run summary counts them distinctly ("N reused from prior runs");
* reused findings / suspicious verdicts re-enter mechanical sweeps
  validation — a reused finding must re-earn tool backing with a live
  receipt, never inherit TOOL_BACKED status from a dead one. Until a
  live tool re-confirms, its evidence is ``journal:recall:<run>``
  (graded as non-tool evidence) and its ``tools_dispatched`` set is
  empty, so ``compute_tier()`` caps it at LLM_ONLY.

Eligibility is decided at fold time (hash match + not
context-reduced + no model/strategy change — ``gaps._reuse_ineligibility``);
this module only materialises the already-screened candidates.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def outcome_from_entry(entry: Any) -> Any:
    """Build a ``reused`` ReviewOutcome from a prior journal entry.

    Evidence conservatism: the outcome's ``evidence_tool`` is
    ``journal:recall:<origin run>`` — the prior entry's tool receipts
    are recorded in ``review_result["prior_evidence_tools"]`` for the
    operator but deliberately NOT replayed as live evidence.
    """
    from .orchestrator import ReviewOutcome

    origin = getattr(entry, "reused_from_run", None) or entry.run_id
    hypotheses = [
        h for h in (entry.hypotheses or [])
        if isinstance(h, dict) and h.get("mechanism")
    ]
    hypothesis = hypotheses[0]["mechanism"] if hypotheses else ""

    review_result: dict[str, Any] = {
        "status": entry.verdict,
        "reused": True,
        "reused_from_run": origin,
    }
    if entry.cwe:
        review_result["cwe"] = entry.cwe
    if entry.evidence_tools:
        review_result["prior_evidence_tools"] = list(entry.evidence_tools)

    outcome = ReviewOutcome(
        file=entry.file,
        function=entry.function,
        status=entry.verdict,
        body=(
            f"[reused: verdict imported from run {origin}; "
            f"source hash unchanged]\n\n{entry.body or ''}"
        ),
        hypothesis=hypothesis,
        hypotheses=hypotheses or None,
        evidence_tool=f"journal:recall:{origin}",
        cost_usd=0.0,
        model=entry.model or "",
        duration_s=0.0,
        review_result=review_result,
    )
    outcome.line = entry.line_start or 0
    outcome.reused = True
    outcome.reused_from_run = origin
    return outcome


def import_reused_verdicts(
    candidates: dict[str, Any],
    config: Any,
    result: Any,
    *,
    collector: Any = None,
    sarif_cache: Any = None,
    evidence_index: Any = None,
    joern_server: Any = None,
    reviewed_outcomes: Any = None,
    same_run: bool = False,
) -> int:
    """Materialise reuse candidates as outcomes on this run.

    Returns the number of verdicts imported. Best-effort per entry —
    one malformed candidate must not cost the rest.

    ``same_run=True`` is the resume path (``raptor-audit resume``):
    the candidates ARE this run's own journal entries (hash-verified
    by the same-run fold), so the own-journal idempotence guard is
    skipped — re-importing them is the point. Each import appends a
    fresh ``reused=true`` journal row; ``latest_entries`` keeps one
    verdict per function, so counts stay coherent across segments.
    """
    if not candidates:
        return 0

    from .orchestrator import (
        _commit_outcome,
        _proactive_validate,
        _sweep_validate,
        _tally_outcome,
    )

    # Idempotence guard: an ensemble/multi-pass run reusing cached
    # prep would otherwise import the same candidates once per pass —
    # skip anything this run's own journal already carries. Bypassed
    # for same-run resume, whose candidates are by construction in
    # this run's journal.
    already: set = set()
    if not same_run:
        try:
            from .journal import reviewed_set
            if getattr(config, "out_dir", None):
                already = reviewed_set(config.out_dir)
        except Exception:
            logger.debug(
                "verdict reuse: journal pre-read failed", exc_info=True,
            )

    imported = 0
    resweep_confirmed = 0
    resweep_demoted = 0
    by_status: dict[str, int] = {}

    for key in sorted(candidates):
        entry = candidates[key]
        if key in already:
            continue
        try:
            outcome = outcome_from_entry(entry)
        except Exception:
            logger.debug(
                "verdict reuse: could not build outcome for %s",
                key, exc_info=True,
            )
            continue

        # Mechanical re-confirmation: reused findings re-enter the
        # sweeps chain (cheap, no LLM). A finding the tools no longer
        # confirm is demoted by the sweep's own rules; one they do
        # confirm re-earns a live receipt (fresh evidence_tool +
        # tools_dispatched), restoring tool-backed grading honestly.
        if outcome.status == "finding" and config.sweep_validate_findings:
            pre_status = outcome.status
            try:
                outcome = _sweep_validate(
                    outcome,
                    config,
                    sarif_cache,
                    tier_counters=result.tier_counters,
                    evidence_index=evidence_index,
                    joern_server=joern_server,
                )
            except Exception:
                logger.debug(
                    "verdict reuse: sweep validation failed for %s",
                    key, exc_info=True,
                )
            with result._lock:
                if outcome.status == "finding":
                    result.sweep_validated += 1
                    resweep_confirmed += 1
                else:
                    result.sweep_demoted += 1
                    resweep_demoted += 1
            if outcome.status != pre_status:
                logger.info(
                    "verdict reuse: %s demoted %s → %s by mechanical "
                    "re-validation", key, pre_status, outcome.status,
                )

        if outcome.status in ("finding", "suspicious"):
            try:
                outcome = _proactive_validate(
                    outcome,
                    config,
                    evidence_index,
                    tier_counters=result.tier_counters,
                    dispatched_tools=outcome.tools_dispatched,
                    joern_server=joern_server,
                )
            except Exception:
                logger.debug(
                    "verdict reuse: proactive validation failed for %s",
                    key, exc_info=True,
                )

        gap = {
            "file": entry.file,
            "name": entry.function,
            "line_start": entry.line_start or 0,
            "line_end": entry.line_end,
            "strategies": list(entry.strategies or []),
        }
        try:
            if collector is not None:
                collector.submit(outcome, gap)
            else:
                _commit_outcome(config, outcome, gap)
        except Exception:
            logger.warning(
                "verdict reuse: commit failed for %s", key, exc_info=True,
            )

        _tally_outcome(result, outcome, reused=True)
        if reviewed_outcomes is not None:
            reviewed_outcomes[key] = outcome
        by_status[outcome.status] = by_status.get(outcome.status, 0) + 1
        imported += 1

    if imported:
        breakdown = ", ".join(
            f"{n} {s}" for s, n in sorted(by_status.items())
        )
        origin_label = (
            "this run's prior segments" if same_run else "prior runs"
        )
        line = (
            f"verdict reuse: {imported} imported from "
            f"{origin_label} ({breakdown})"
        )
        if resweep_confirmed or resweep_demoted:
            line += (
                f"; findings mechanically re-validated: "
                f"{resweep_confirmed} confirmed, {resweep_demoted} demoted"
            )
        logger.info(line)

    return imported
