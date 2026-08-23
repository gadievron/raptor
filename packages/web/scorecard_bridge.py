"""Web verification outcomes → model scorecard (self-labeling).

The web pipeline earns per-model confusion matrices without human
labels: every recorded injection hit is a positive first-pass claim
made with the model's payloads, and the Phase 6v verification oracle
later grades that claim mechanically (replay + control legs). A
verified hit marks the model correct, a control-refuted hit marks it
incorrect, and inconclusive/skipped verdicts carry no signal.

Decision classes follow the oracle's evidence shape rather than the
vulnerability taxonomy: xss is graded on unescaped reflection
(``web:xss-reflection-triage``); the marker classes are graded on the
baseline/attack response differential
(``web:response-diff-classification``). Events land in the
TOOL_EVIDENCE slot, so the auto-policy gate (Wilson over
CHEAP_SHORT_CIRCUIT) is unaffected.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from core.logging import get_logger

logger = get_logger()

# vuln_type -> scorecard rule id (decision class = "web:<rule id>").
_RULE_BY_VULN: dict[str, str] = {
    "xss": "xss-reflection-triage",
    "sqli": "response-diff-classification",
    "ssti": "response-diff-classification",
    "command_injection": "response-diff-classification",
    "path_traversal": "response-diff-classification",
}


def record_web_oracle_outcomes(llm: Any, hits: list[dict]) -> int:
    """Back-propagate verification verdicts onto the payload model.

    ``hits`` are the raw injection hits after ``_verify_findings``
    annotated each with its ``verification`` block. Returns the number
    of scorecard events recorded. Every failure path degrades to 0 —
    scorecard bookkeeping must never break a scan.
    """
    if llm is None or not hits:
        return 0
    try:
        scorecard = llm.scorecard
        primary = getattr(llm.config, "primary_model", None)
        model = getattr(primary, "model_name", None)
    except Exception:
        logger.debug("web scorecard bridge: no scorecard/model", exc_info=True)
        return 0
    if scorecard is None or not model:
        return 0

    from core.llm.scorecard.tool_evidence import record_tool_evidence_outcome

    recorded = 0
    for hit in hits:
        status = (hit.get("verification") or {}).get("status")
        if status == "verified":
            verdict: bool | None = True
        elif status == "refuted":
            # The oracle issues "refuted" only from a positive control
            # experiment, never from a mere failed replay.
            verdict = False
        else:
            continue
        rule = _RULE_BY_VULN.get(str(hit.get("vulnerability_type") or ""))
        if rule is None:
            continue
        endpoint = str(hit.get("endpoint") or hit.get("url") or "")
        finding_id = (
            f"web:{hit.get('vulnerability_type')}:"
            f"{urlparse(endpoint).path or '/'}:{hit.get('parameter', '')}"
        )
        try:
            if record_tool_evidence_outcome(
                scorecard,
                model=str(model),
                rule_id=rule,
                analysis_verdict=True,
                validation_verdict=verdict,
                finding_id=finding_id,
                analysis_reasoning=str(hit.get("oracle_signal") or "")[:200],
                decision_class_prefix="web",
            ):
                recorded += 1
        except Exception:
            logger.debug(
                "web scorecard bridge: record failed for %s",
                finding_id, exc_info=True,
            )
    if recorded:
        logger.info(
            "Scorecard: %d web oracle outcome(s) recorded for %s",
            recorded, model,
        )
    return recorded
