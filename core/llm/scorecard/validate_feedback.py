"""Producer for ``EventType.VALIDATE_FEEDBACK``.

The live writer of ``audit:<CWE>`` reliability cells. Before this
producer, the only writer of audit decision-class cells was the
offline corpus harness — production audit runs recorded nothing, so
``core.audit.calibrated_merge`` ran permanently cold-start.

Wired from ``core.audit.feedback.import_validation_results``: when a
/validate run comes back on a prior audit LLM verdict (the Reflexion
loop), the agreement between the model's journal verdict and
/validate's conclusion becomes one reliability event:

* positive verdict (finding/suspicious) confirmed  → ``correct``
* positive verdict disproven (same finding)        → ``incorrect``
* clean verdict, /validate confirmed a finding     → ``incorrect``
  (the model missed it)
* clean verdict, /validate disproved the finding   → ``correct``

Inconclusive /validate verdicts and decoy-vetoed disprovals (the
feedback importer's CWE/line mismatch guard) are never recorded.

Decision-class convention matches the corpus harness:
``audit:<CWE>`` when the journal entry carries a CWE, else the
consumer-side default ``audit:review``.
"""

from __future__ import annotations

import logging
from typing import Any

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)

_POSITIVE_VERDICTS = frozenset({"finding", "suspicious"})


def _decision_class(cwe: str | None) -> str:
    cwe = (cwe or "").strip().upper()
    if cwe:
        return f"audit:{cwe}"
    # Keep in sync with core.audit.calibrated_merge.DEFAULT_DECISION_CLASS
    # (not imported — core/llm must not depend on core/audit).
    return "audit:review"


def classify_outcome(
    prior_verdict: str, validate_verdict: str,
) -> str | None:
    """Map (audit verdict, /validate verdict) to a reliability outcome.

    Returns ``"correct"`` / ``"incorrect"``, or ``None`` when the pair
    carries no reliability signal (inconclusive /validate verdict, or
    an audit verdict outside the finding/suspicious/clean vocabulary).
    """
    prior = (prior_verdict or "").strip().lower()
    val = (validate_verdict or "").strip().lower()
    if val not in ("confirmed", "disproven"):
        return None
    if prior in _POSITIVE_VERDICTS:
        return "correct" if val == "confirmed" else "incorrect"
    if prior == "clean":
        return "incorrect" if val == "confirmed" else "correct"
    return None


def record_validate_feedback_outcome(
    scorecard: ModelScorecard | None,
    *,
    model: str,
    cwe: str | None,
    prior_verdict: str,
    validate_verdict: str,
    file: str = "",
    function: str = "",
    reason: str = "",
) -> bool:
    """Record one VALIDATE_FEEDBACK event. Returns True when recorded."""
    if scorecard is None or not model:
        return False
    outcome = classify_outcome(prior_verdict, validate_verdict)
    if outcome is None:
        return False
    sample = None
    if outcome == "incorrect":
        sample = {
            "function_id": f"{file}:{function}",
            "prior_verdict": prior_verdict,
            "validate_verdict": validate_verdict,
            "reason": (reason or "")[:_MAX_REASONING_CHARS],
        }
    try:
        scorecard.record_event(
            decision_class=_decision_class(cwe),
            model=str(model),
            event_type=EventType.VALIDATE_FEEDBACK,
            outcome=outcome,
            sample=sample,
        )
        return True
    except Exception as e:  # noqa: BLE001 — telemetry must never break the feedback import
        logger.warning(
            "record_validate_feedback_outcome: %s/%s failed: %s",
            model, _decision_class(cwe), e,
        )
        return False


def record_validate_feedback_outcomes(
    records: list[dict[str, Any]],
    scorecard: ModelScorecard | None = None,
) -> int:
    """Record a batch of feedback records; returns the count recorded.

    Each record: ``{model, cwe, prior_verdict, validate_verdict,
    file, function, reason}``. When ``scorecard`` is None the default
    sidecar is resolved via RAPTOR_DIR (same convention as the
    tool-evidence producer) so an import run from any cwd writes to
    the sidecar the rest of RAPTOR reads.
    """
    if not records:
        return 0
    if scorecard is None:
        import os
        from pathlib import Path
        raptor_dir = os.environ.get("RAPTOR_DIR")
        if raptor_dir:
            default_path = Path(raptor_dir) / "out" / "llm_scorecard.json"
        else:
            default_path = Path("out/llm_scorecard.json")
        try:
            scorecard = ModelScorecard(default_path)
        except Exception:
            logger.debug("validate_feedback: scorecard unavailable",
                         exc_info=True)
            return 0
    n = 0
    for rec in records:
        if record_validate_feedback_outcome(
            scorecard,
            model=rec.get("model") or "",
            cwe=rec.get("cwe"),
            prior_verdict=rec.get("prior_verdict") or "",
            validate_verdict=rec.get("validate_verdict") or "",
            file=rec.get("file") or "",
            function=rec.get("function") or "",
            reason=rec.get("reason") or "",
        ):
            n += 1
    if n:
        logger.info("validate-feedback scorecard: %d events", n)
    return n


__all__ = [
    "classify_outcome",
    "record_validate_feedback_outcome",
    "record_validate_feedback_outcomes",
]
