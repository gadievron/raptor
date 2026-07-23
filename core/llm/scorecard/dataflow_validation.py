"""Producer for ``EventType.DATAFLOW_VALIDATION``.

When mechanical dataflow analysis (CodeQL/IRIS or structural
tree-sitter) checks the LLM's reachability claim, the verdict
is one of confirmed / refuted / inconclusive.

  * ``confirmed`` → ``correct`` (mechanical evidence supports the LLM)
  * ``refuted`` → ``incorrect`` (mechanical evidence contradicts the LLM)
  * ``inconclusive`` → skipped (no signal either way)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


def record_dataflow_validation_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    results_by_id: Dict[str, Dict[str, Any]],
    decision_class_prefix: str = "agentic",
) -> int:
    """Record dataflow validation outcomes on the scorecard.

    Returns the number of events recorded.
    """
    if scorecard is None:
        return 0

    n_recorded = 0
    for fid, result in results_by_id.items():
        dv = result.get("dataflow_validation")
        if not isinstance(dv, dict):
            continue

        verdict = dv.get("verdict", "")
        if verdict == "confirmed":
            outcome = "correct"
        elif verdict == "refuted":
            outcome = "incorrect"
        else:
            continue

        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"
        model = str(result.get("analysed_by") or "")
        if not model:
            continue
        model_version = result.get("resolved_model")

        sample = None
        if outcome == "incorrect":
            reasoning = str(dv.get("reasoning") or "")
            sample = {
                "method": dv.get("method", ""),
                "reasoning": reasoning[:_MAX_REASONING_CHARS],
            }

        try:
            scorecard.record_event(
                decision_class,
                model,
                EventType.DATAFLOW_VALIDATION,
                outcome,
                model_version=model_version,
                sample=sample,
            )
            n_recorded += 1
        except Exception:
            logger.warning(
                "dataflow-validation: record_event failed for %s",
                fid, exc_info=True,
            )

    return n_recorded
