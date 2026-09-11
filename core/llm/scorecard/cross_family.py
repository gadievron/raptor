"""Producer for ``EventType.CROSS_FAMILY_CONSISTENCY``.

When a finding triggers a cross-family re-analysis (different model
family from the primary), the checker either agrees or disputes.
Records one consistency event per cross-family-checked finding:

  * Checker agreed with primary → ``correct`` (consistent pair)
  * Checker disputed primary → ``incorrect`` (unresolved dispute)

This is an observability axis, NOT a correctness verdict: the pair is
1-vs-1 with no ground truth, so a dispute never establishes which side
was wrong (same reasoning as the consensus producer's even-split
skip). The event type is therefore kept out of the correctness-graded
reliability pools — recording it under a reliability-pooled type would
let mere disagreement penalise dissent and reward agreeing with the
primary.

Skips findings where the checker fell back to the same family
(no independent signal).
"""

from __future__ import annotations

import logging
from typing import Any

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_cross_family_outcomes(
    scorecard: ModelScorecard | None,
    *,
    results_by_id: dict[str, dict[str, Any]],
    decision_class_prefix: str = "agentic",
) -> int:
    """Record cross-family check outcomes on the scorecard.

    Returns the number of events recorded.
    """
    if scorecard is None:
        return 0

    n_recorded = 0
    for fid, result in results_by_id.items():
        cf = result.get("cross_family_check")
        if not isinstance(cf, dict):
            continue

        verdict = cf.get("verdict", "")
        if verdict.startswith("skipped"):
            continue

        checker_model = cf.get("checker_model")
        if not checker_model:
            continue

        # Derive agreed/disputed from the verdict string rather than
        # relying on the separate top-level boolean flags — those are
        # set by a different code path and could fall out of sync.
        # Either way the event is a consistency observation: with one
        # primary and one checker a dispute is an even split with no
        # ground truth, so neither side earns a correctness
        # attribution from it.
        if "disputed" in verdict:
            outcome = "incorrect"
        elif result.get("cross_family_agreed") or "agreed" in verdict:
            outcome = "correct"
        else:
            continue

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        model_version = cf.get("checker_model")

        sample = None
        if outcome == "incorrect":
            sample = {
                "trigger": cf.get("trigger", ""),
                "checker_ruling": str(
                    cf.get("checker_ruling", "")
                )[:_MAX_REASONING_CHARS],
            }

        try:
            scorecard.record_event(
                decision_class,
                str(checker_model),
                EventType.CROSS_FAMILY_CONSISTENCY,
                outcome,
                model_version=model_version,
                sample=sample,
            )
            n_recorded += 1
        except Exception:
            logger.warning(
                "cross-family check: record_event failed for %s",
                fid, exc_info=True,
            )

    return n_recorded
