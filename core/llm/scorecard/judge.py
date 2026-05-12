"""Producer wiring for ``EventType.JUDGE_REVIEW``.

When /agentic dispatches a judge panel (``--judge <model>``,
``--judge <m1> <m2>`` etc.) over the primary's analysis, the
``JudgeTask`` finalises a final verdict by majority vote across
(primary + judges). Disputes — where one or more participants
disagreed — are this producer's signal:

  * Primary's vote != final → primary's model gets ``incorrect``.
  * Primary's vote == final → primary's model gets ``correct``.
  * Each judge's vote vs final → same.

Single-judge mode is INTENTIONALLY SKIPPED. There the ``JudgeTask``
keeps the primary's verdict (``final = primary_exploitable``) and
just flags the dispute for operator review — there's no automated
truth signal worth recording. Multi-judge mode is where the panel
collectively overrules and the producer can attribute correctness.

Agreed findings produce no signal — every model voted the same way
so the cell would just bump uniformly without distinguishing models.
Same skip pattern as ``record_consensus_outcomes``.

Cells are keyed by ``agentic:<rule_id>``, shared with the
multi-model-consensus and prefilter producers; different event
slots (``JUDGE_REVIEW`` vs ``MULTI_MODEL_CONSENSUS`` vs
``CHEAP_SHORT_CIRCUIT``) keep their counters isolated. The
auto-policy gate's Wilson math runs over the cheap-tier slot
only — judge events do NOT shift the prefilter gate.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_judge_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    results_by_id: Dict[str, Dict],
    primary_verdicts_before_judge: Dict[str, bool],
    decision_class_prefix: str = "agentic",
) -> int:
    """Walk results that ran through ``JudgeTask``; record one
    ``JUDGE_REVIEW`` event per (model, finding) for disputed
    multi-judge findings.

    ``primary_verdicts_before_judge`` is a snapshot of each finding's
    primary verdict captured BEFORE ``JudgeTask`` ran — JudgeTask
    overwrites ``primary["is_exploitable"]`` with the final majority
    verdict, so we need the snapshot to know which way primary
    originally voted.

    Returns count of events written. No-op on ``scorecard=None``.
    """
    if scorecard is None or not results_by_id:
        return 0

    n_recorded = 0
    for fid, result in results_by_id.items():
        if not isinstance(result, dict) or "error" in result:
            continue
        if result.get("judge") != "disputed":
            continue

        judge_analyses = result.get("judge_analyses") or []
        if len(judge_analyses) < 2:
            # Single-judge disputes don't yield a panel-majority
            # signal — JudgeTask keeps the primary's verdict in that
            # case and only flags the dispute for operator review.
            # Recording a "primary correct, judge incorrect" event
            # would be wrong — the dispute is real, the resolution
            # isn't operator-trusted.
            continue

        if fid not in primary_verdicts_before_judge:
            # Defensive — caller didn't snapshot this finding. Skip
            # rather than mis-attribute against the now-overwritten
            # primary verdict.
            continue

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        final_verdict = bool(result.get("is_exploitable"))
        primary_model = str(result.get("analysed_by") or "?")
        primary_vote = bool(primary_verdicts_before_judge[fid])

        # Primary's outcome
        primary_correct = (primary_vote == final_verdict)
        _record_one(
            scorecard,
            decision_class=decision_class,
            model=primary_model,
            outcome="correct" if primary_correct else "incorrect",
            sample_reasoning=(
                None if primary_correct
                else str(result.get("reasoning") or "")
            ),
            other_summary=(
                f"panel of {len(judge_analyses)} judge(s) voted "
                f"{'exploitable' if final_verdict else 'not exploitable'}"
            ),
        )
        n_recorded += 1

        # Each judge's outcome
        for ja in judge_analyses:
            judge_model = str(ja.get("model") or "?")
            judge_vote = bool(ja.get("is_exploitable"))
            judge_correct = (judge_vote == final_verdict)
            _record_one(
                scorecard,
                decision_class=decision_class,
                model=judge_model,
                outcome="correct" if judge_correct else "incorrect",
                sample_reasoning=(
                    None if judge_correct
                    else str(ja.get("reasoning") or "")
                ),
                other_summary=(
                    f"panel majority voted "
                    f"{'exploitable' if final_verdict else 'not exploitable'}"
                ),
            )
            n_recorded += 1
    return n_recorded


def _record_one(
    scorecard: ModelScorecard,
    *,
    decision_class: str,
    model: str,
    outcome: str,
    sample_reasoning: Optional[str],
    other_summary: str,
) -> None:
    sample = None
    if outcome == "incorrect" and sample_reasoning is not None:
        sample = {
            "this_reasoning": sample_reasoning[:_MAX_REASONING_CHARS],
            "other_reasoning": other_summary,
        }
    try:
        scorecard.record_event(
            decision_class=decision_class,
            model=model,
            event_type=EventType.JUDGE_REVIEW,
            outcome=outcome,
            sample=sample,
        )
    except Exception as e:                              # noqa: BLE001
        # WARNING (not DEBUG): see consensus.py for rationale.
        logger.warning(
            "record_judge_outcomes: failed to record %s/%s: %s",
            model, decision_class, e,
        )


__all__ = ["record_judge_outcomes"]
