"""Producer for ``EventType.CROSS_FAMILY_CHECK``.

When a finding triggers a cross-family re-analysis (different model
family from the primary), the checker either agrees or disputes.
Records one scorecard event per cross-family-checked finding:

  * Checker agreed with primary → ``correct``
  * Checker disputed primary → ``incorrect``

Skips findings where the checker fell back to the same family
(no independent signal).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_cross_family_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    results_by_id: Dict[str, Dict[str, Any]],
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
                EventType.CROSS_FAMILY_CHECK,
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
