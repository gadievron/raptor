"""Producer wiring for ``EventType.MULTI_MODEL_CONSENSUS``.

When /agentic dispatches multiple analysis models on the same finding,
post-dispatch correlation tags each finding as ``"high"`` (everyone
agreed exploitable), ``"high-negative"`` (everyone agreed not),
or ``"disputed"`` (split). For disputed findings, this producer
records:

  * each minority model → ``incorrect``
  * each majority model → ``correct``

against the ``(model, decision_class)`` cell, where decision_class is
``agentic:<rule_id>``. Agreed findings produce no signal — they're
useful for downstream confidence math but don't tell us which models
drift from panel consensus over time.

Ties (e.g. 1-vs-1 in a 2-model panel) are skipped: there's no clear
majority and arbitrarily declaring one model wrong would inject noise
into the cell. The cheap-tier ``CHEAP_SHORT_CIRCUIT`` counter is
untouched — this producer feeds its own event slot only and never
shifts the auto-policy gate.

Sister producers in the same family:

  * ``core.llm.scorecard.prefilter`` — ``CHEAP_SHORT_CIRCUIT`` (the
    fast-tier prefilter producer; landed first; drives the
    auto-policy gate).
  * ``core.llm.scorecard.judge`` — ``JUDGE_REVIEW`` (judge model
    overruling primary; landed alongside this).
  * ``core.llm.scorecard.tool_evidence`` — ``TOOL_EVIDENCE``
    (downstream validation back-propagation).

These all use the same ``record_event`` substrate API + same
decision_class shape (``<consumer>:<rule_id>``). Naming and
policy-isolation conventions live here so future producers added to
the family stay in lock-step.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


_MAX_REASONING_CHARS = 500


def record_consensus_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    correlation: Dict[str, Any],
    results_by_id: Dict[str, Dict],
    per_finding_results: Optional[Dict[str, Any]] = None,
    decision_class_prefix: str = "agentic",
) -> int:
    """Walk a correlation result; record one
    ``MULTI_MODEL_CONSENSUS`` event per (model, finding) pair on
    disputed findings.

    Returns the number of events written.

    No-op when ``scorecard`` is ``None`` (operator opted out via
    ``scorecard_enabled=False`` or the consumer didn't have a
    scorecard available). No-op when ``correlation`` is empty
    (single-model run).

    ``per_finding_results`` (optional): mapping ``{finding_id: [
    per-model result dict, ...]}`` from the orchestrator's
    per-model dispatch. When supplied, the producer captures each
    minority model's OWN reasoning into the disagreement-samples
    log (rather than the primary's, which is misleading attribution).
    Passing ``None`` skips per-model reasoning capture — the cell
    still gets the correct/incorrect counter bumps, just no sample
    text. Decoupled from ``results_by_id`` to avoid mutating the
    primary records the orchestrator later serialises into
    ``orchestrated_report.json``.

    The ``decision_class_prefix`` follows the existing convention —
    ``"agentic"`` for /agentic-dispatched findings, matching the
    prefilter producer's ``agentic:<rule_id>`` cell shape so consensus
    and prefilter signals share the same cell.

    Failure path: any per-event ``record_event`` exception is logged
    at debug level and swallowed; one bad event must not abort the
    whole batch and must never block the calling orchestrator's
    flow. Operators who care will see the per-event log line.
    """
    if scorecard is None or not correlation:
        return 0
    matrix = correlation.get("agreement_matrix") or {}
    confidence = correlation.get("confidence_signals") or {}
    if not matrix:
        return 0

    n_recorded = 0
    for fid, per_model in matrix.items():
        if confidence.get(fid) != "disputed":
            continue

        verdicts: Dict[str, bool] = {}
        for model, mr in per_model.items():
            v = mr.get("is_exploitable")
            if v is None:
                # Result missing the verdict (handler error / schema
                # failure); can't classify against majority, skip
                # this model for this finding.
                continue
            verdicts[str(model)] = bool(v)
        if len(verdicts) < 2:
            # Need at least two models with verdicts to define a
            # majority direction. ``confidence == "disputed"`` should
            # imply this but be defensive against dirty inputs.
            continue

        exploitable_count = sum(1 for v in verdicts.values() if v)
        non_exploitable_count = len(verdicts) - exploitable_count
        if exploitable_count == 0 or non_exploitable_count == 0:
            # Defensive: if everyone with a verdict agrees, the
            # finding shouldn't be tagged disputed. Skip to avoid
            # recording noise.
            continue
        if exploitable_count == non_exploitable_count:
            # No clear majority — typically a 1-vs-1 split in a
            # 2-model panel. Recording would arbitrarily declare one
            # model "incorrect" against the other; skip rather than
            # inject noise.
            continue

        majority_says_exploitable = exploitable_count > non_exploitable_count

        result = results_by_id.get(fid) or {}
        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"

        # Look up this finding's per-model result list (when the
        # caller supplied one) so we can attribute reasoning to the
        # actual minority model rather than mis-attributing the
        # primary's reasoning to a dissenter.
        this_finding_per_model = (
            (per_finding_results or {}).get(fid) or []
        )

        for model, verdict in verdicts.items():
            with_majority = (verdict == majority_says_exploitable)
            outcome = "correct" if with_majority else "incorrect"
            sample = None
            if outcome == "incorrect":
                # Capture the minority model's OWN reasoning. If we
                # can't find it in ``per_finding_results`` (caller
                # didn't supply, or the per-model record is missing),
                # skip the sample rather than fall back to the
                # primary's reasoning — that would mis-attribute the
                # majority's text to the dissenter.
                this_model_result = next(
                    (r for r in this_finding_per_model
                     if str(r.get("analysed_by") or r.get("model") or "") == model),
                    None,
                )
                if this_model_result is not None:
                    reasoning = str(this_model_result.get("reasoning") or "")
                    sample = {
                        "this_reasoning": reasoning[:_MAX_REASONING_CHARS],
                        "other_reasoning": (
                            f"majority of {len(verdicts)} models voted "
                            f"{'exploitable' if majority_says_exploitable else 'not exploitable'}"
                        ),
                    }
            try:
                scorecard.record_event(
                    decision_class=decision_class,
                    model=model,
                    event_type=EventType.MULTI_MODEL_CONSENSUS,
                    outcome=outcome,
                    sample=sample,
                )
                n_recorded += 1
            except Exception as e:                       # noqa: BLE001
                # WARNING (not DEBUG): operators rarely run with
                # DEBUG enabled in production, so a regressed
                # producer would have been invisible. Per-event
                # failures here are real signal — the scorecard
                # write path failed for an attributable
                # (model, decision_class, finding) cell. If this
                # logs frequently in practice, the underlying issue
                # (lock contention, disk full, schema corruption)
                # warrants attention regardless of log volume.
                logger.warning(
                    "record_consensus_outcomes: failed to record %s/%s "
                    "on %s: %s",
                    model, decision_class, fid, e,
                )
    return n_recorded


__all__ = ["record_consensus_outcomes"]
