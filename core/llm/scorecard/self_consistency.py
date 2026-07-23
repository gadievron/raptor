"""Producer for ``EventType.SELF_CONSISTENCY``.

Stage F retries findings that are self-contradictory or whose
exploitability score falls in the indecisive band.  When a retry
runs, the verdict either holds or flips:

  * Verdict held after retry → ``correct``
  * Verdict flipped after retry → ``incorrect``

Findings that were retried but remained low-confidence (indecisive
band, not contradictory) are recorded as ``correct`` — the model
consistently couldn't decide, which is a stable signal.

Requires a pre-retry verdict snapshot (``verdicts_pre_retry``)
captured before ``RetryTask`` runs, since the task overwrites
``is_exploitable`` in place on decisive retries.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_self_consistency_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    results_by_id: Dict[str, Dict[str, Any]],
    verdicts_pre_retry: Dict[str, bool],
    decision_class_prefix: str = "agentic",
) -> int:
    """Record self-consistency outcomes for retried findings.

    ``verdicts_pre_retry`` maps ``finding_id → is_exploitable``
    captured before ``RetryTask`` ran.

    Returns the number of events recorded.
    """
    if scorecard is None:
        return 0

    n_recorded = 0
    for fid, result in results_by_id.items():
        if not result.get("retried"):
            continue

        pre_verdict = verdicts_pre_retry.get(fid)
        if pre_verdict is None:
            continue

        post_verdict = result.get("is_exploitable")
        if post_verdict is None:
            continue

        held = bool(pre_verdict) == bool(post_verdict)
        outcome = "correct" if held else "incorrect"

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        model = str(result.get("analysed_by") or "")
        if not model:
            continue
        model_version = result.get("resolved_model")

        sample = None
        if not held:
            reasoning = str(result.get("reasoning") or "")
            sample = {
                "pre_verdict": "positive" if pre_verdict else "negative",
                "post_verdict": "positive" if post_verdict else "negative",
                "post_reasoning": reasoning[:_MAX_REASONING_CHARS],
            }

        try:
            scorecard.record_event(
                decision_class,
                model,
                EventType.SELF_CONSISTENCY,
                outcome,
                model_version=model_version,
                sample=sample,
            )
            n_recorded += 1
        except Exception:
            logger.warning(
                "self-consistency: record_event failed for %s",
                fid, exc_info=True,
            )

    return n_recorded
