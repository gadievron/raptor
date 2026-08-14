"""Bridge between IRIS refinement outcomes and the model scorecard.

After each refinement round, confirmed/refuted specs are recorded as
``tool_evidence`` events on the ``iris_spec_quality`` decision class.
This lets operators query per-model IRIS accuracy via ``/scorecard``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Sequence

from .specs import TaintSpec
from .store import _spec_key

logger = logging.getLogger(__name__)

DECISION_CLASS = "iris_spec_quality"

TAINT_CLASS_TO_CWE = {
    "sql": "CWE-89",
    "command": "CWE-78",
    "xss": "CWE-79",
    "path": "CWE-22",
    "deserialize": "CWE-502",
    "ssrf": "CWE-918",
    "ldap": "CWE-90",
    "xpath": "CWE-643",
    "template": "CWE-1336",
    "redirect": "CWE-601",
    "log": "CWE-117",
    "eval": "CWE-94",
    "crypto": "CWE-327",
    "xml": "CWE-611",
    "nosql": "CWE-943",
}


@dataclass
class SpecOutcome:
    """Outcome of one spec after tool validation."""

    function: str
    file: str
    role: str
    model: str
    round: int
    confirmed: bool | None
    taint_classes: list[str] = field(default_factory=list)
    finding_count: int = 0


def record_refinement_outcomes(
    scorecard: Any,
    specs: Sequence[TaintSpec],
    confirmed_keys: Sequence[str],
    refuted_keys: Sequence[str],
    *,
    model: str,
    round_num: int = 0,
    model_version: str | None = None,
) -> list[SpecOutcome]:
    """Record per-spec TP/FP outcomes to the scorecard.

    Returns the list of ``SpecOutcome`` records for callers that want
    to persist them (e.g. per-CWE quality tracking in the store).
    """
    if scorecard is None:
        return []

    confirmed_set = set(confirmed_keys)
    refuted_set = set(refuted_keys)
    outcomes: list[SpecOutcome] = []

    for spec in specs:
        key = _spec_key(spec)
        if key in confirmed_set:
            confirmed = True
        elif key in refuted_set:
            confirmed = False
        else:
            continue

        outcome = SpecOutcome(
            function=spec.function,
            file=spec.file,
            role=spec.role,
            model=model,
            round=round_num,
            confirmed=confirmed,
            taint_classes=list(spec.taint_classes),
        )
        outcomes.append(outcome)

        try:
            scorecard.record_event(
                DECISION_CLASS,
                model,
                "tool_evidence",
                "correct" if confirmed else "incorrect",
                model_version=model_version,
                sample=_build_sample(spec, round_num) if not confirmed else None,
            )
        except Exception:
            logger.debug(
                "iris.scorecard_bridge: failed to record event for %s",
                key, exc_info=True,
            )

    if outcomes:
        n_tp = sum(1 for o in outcomes if o.confirmed)
        n_fp = sum(1 for o in outcomes if not o.confirmed)
        logger.info(
            "iris.scorecard_bridge: recorded %d outcomes (round %d, "
            "model=%s, %d TP, %d FP)",
            len(outcomes), round_num, model, n_tp, n_fp,
        )

    return outcomes


def cwe_quality_summary(outcomes: Sequence[SpecOutcome]) -> dict[str, dict[str, Any]]:
    """Aggregate per-CWE spec quality from a batch of outcomes.

    Returns a dict keyed by CWE ID with counts and TP rate.
    """
    by_cwe: dict[str, dict[str, int]] = {}
    for outcome in outcomes:
        cwes = set()
        for tc in outcome.taint_classes:
            cwe = TAINT_CLASS_TO_CWE.get(tc)
            if cwe:
                cwes.add(cwe)
        if not cwes:
            cwes = {"unknown"}
        for cwe in cwes:
            bucket = by_cwe.setdefault(cwe, {"confirmed": 0, "refuted": 0})
            if outcome.confirmed:
                bucket["confirmed"] += 1
            elif outcome.confirmed is False:
                bucket["refuted"] += 1

    result: dict[str, dict[str, Any]] = {}
    for cwe, counts in sorted(by_cwe.items()):
        total = counts["confirmed"] + counts["refuted"]
        tp_rate = counts["confirmed"] / total if total else None
        coverage = "good" if tp_rate is not None and tp_rate >= 0.7 else "gap"
        result[cwe] = {
            "n_specs": total,
            "tp_rate": tp_rate,
            "coverage": coverage,
        }
    return result


def _build_sample(spec: TaintSpec, round_num: int) -> dict[str, str]:
    return {
        "function": spec.function,
        "file": spec.file,
        "role": spec.role,
        "round": str(round_num),
    }
