"""Producer wiring for ``EventType.TOOL_EVIDENCE``.

Back-propagates downstream-validation outcomes onto the (model,
decision_class) cells of the models that emitted the original
analysis verdicts. Specifically:

  * /agentic produces an analysis verdict for finding F:
    ``(model, rule_id, is_exploitable)``.
  * /validate runs Stages 0-F on F and concludes
    ``(is_exploitable=True|False|None)``. Stage F is the exploit
    attempt — strongest signal in the pipeline.
  * If both verdicts agree → model gets ``correct``; if they
    disagree → ``incorrect``; ``None`` (inconclusive) → no signal.

Decoupled from /validate's internals: the producer accepts plain
records (analysis-side dict + validation-side bool) so the consumer
shape can evolve without touching the substrate. Two entry points:

  * :func:`record_tool_evidence_outcome` — single-record primitive,
    the testable atom.
  * :func:`record_tool_evidence_outcomes` — bulk variant that walks
    aligned records.

The CLI ``mark`` command is the operator-driven analogue
(``OPERATOR_FEEDBACK``); this producer is the automated analogue
(``TOOL_EVIDENCE``). Both write into different event slots so the
auto-policy gate (Wilson over ``CHEAP_SHORT_CIRCUIT``) is unaffected.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, Optional

from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)


_MAX_REASONING_CHARS = 500


def record_tool_evidence_outcome(
    scorecard: Optional[ModelScorecard],
    *,
    model: str,
    rule_id: str,
    analysis_verdict: bool,
    validation_verdict: Optional[bool],
    finding_id: Optional[str] = None,
    analysis_reasoning: Optional[str] = None,
    decision_class_prefix: str = "agentic",
) -> bool:
    """Record one ``TOOL_EVIDENCE`` event when downstream validation
    confirms or refutes a model's analysis verdict.

    Returns True if an event was recorded, False otherwise (skip
    cases: scorecard None, validation_verdict None, missing model).

    ``analysis_verdict`` is the model's ``is_exploitable`` from
    /agentic (or any consumer with a verdict). ``validation_verdict``
    is the downstream pipeline's conclusion — bool when concrete,
    ``None`` when inconclusive (no signal, skip).

    ``finding_id`` is recorded into the disagreement-samples log on
    incorrect outcomes so an operator inspecting the cell can trace
    back to the specific finding that contradicted the model's
    verdict.
    """
    if scorecard is None or validation_verdict is None:
        return False
    if not model or not rule_id:
        return False
    decision_class = f"{decision_class_prefix}:{rule_id}"
    # F088 idempotency gate (W21): when finding_id is provided, the
    # claim-and-record happens under a single lock-and-persist cycle
    # via scorecard.claim_and_record_tool_evidence — closes the
    # atomicity gap where the prior split-call sequence (claim then
    # record_event) could persist the claim, then crash before the
    # event landed, leaving finding_id permanently marked "seen"
    # with zero events. When finding_id is absent we cannot dedup and
    # fall back to the legacy always-record path — preserves behaviour
    # for non-CLI callers that lack finding_id.
    is_correct = (bool(analysis_verdict) == bool(validation_verdict))
    sample = None
    if not is_correct:
        sample = {
            "this_reasoning": (analysis_reasoning or "")[:_MAX_REASONING_CHARS],
            "other_reasoning": (
                f"validation pipeline concluded "
                f"{'exploitable' if validation_verdict else 'not exploitable'}"
                + (f" on finding {finding_id}" if finding_id else "")
            ),
        }
    outcome = "correct" if is_correct else "incorrect"
    if finding_id:
        try:
            recorded = scorecard.claim_and_record_tool_evidence(
                decision_class=decision_class,
                model=str(model),
                finding_id=str(finding_id),
                outcome=outcome,
                sample=sample,
            )
        except Exception as e:                          # noqa: BLE001
            # WARNING (not DEBUG): see consensus.py for rationale.
            logger.warning(
                "record_tool_evidence_outcome: atomic "
                "claim-and-record failed for %s/%s/%s: %s",
                model, decision_class, finding_id, e,
            )
            return False
        if not recorded:
            logger.debug(
                "record_tool_evidence_outcome: %s/%s/%s already "
                "recorded; skipping (F088 idempotency)",
                model, decision_class, finding_id,
            )
            return False
        return True
    try:
        scorecard.record_event(
            decision_class=decision_class,
            model=str(model),
            event_type=EventType.TOOL_EVIDENCE,
            outcome=outcome,
            sample=sample,
        )
        return True
    except Exception as e:                              # noqa: BLE001
        # WARNING (not DEBUG): see consensus.py for rationale.
        logger.warning(
            "record_tool_evidence_outcome: %s/%s failed: %s",
            model, decision_class, e,
        )
        return False


def record_tool_evidence_outcomes(
    scorecard: Optional[ModelScorecard],
    *,
    records: Iterable[Dict[str, Any]],
    decision_class_prefix: str = "agentic",
) -> int:
    """Bulk variant. Each record is a dict with keys:

      * ``model`` (str, required)
      * ``rule_id`` (str, required)
      * ``analysis_verdict`` (bool, required)
      * ``validation_verdict`` (bool|None, required — None skips)
      * ``finding_id`` (str, optional — for sample log)
      * ``analysis_reasoning`` (str, optional — for sample log on
        incorrect outcomes)

    Returns the count of events written. Records missing required
    fields are skipped (logged at debug); one bad record never aborts
    the batch.
    """
    if scorecard is None:
        return 0
    n = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        try:
            ok = record_tool_evidence_outcome(
                scorecard,
                model=str(rec.get("model") or ""),
                rule_id=str(rec.get("rule_id") or ""),
                analysis_verdict=bool(rec.get("analysis_verdict")),
                validation_verdict=rec.get("validation_verdict"),
                finding_id=rec.get("finding_id"),
                analysis_reasoning=rec.get("analysis_reasoning"),
                decision_class_prefix=decision_class_prefix,
            )
        except Exception as e:                          # noqa: BLE001
            # WARNING: a malformed record is a real signal — caller
            # gave us shape we can't process. See consensus.py for
            # the broader rationale on the family-wide promotion.
            logger.warning(
                "record_tool_evidence_outcomes: bad record %r: %s",
                rec, e,
            )
            continue
        if ok:
            n += 1
    return n


__all__ = [
    "record_tool_evidence_outcome",
    "record_tool_evidence_outcomes",
]
