"""Compositional safety assumptions for multi-tier bug detection.

A SafetyAssumption captures "function F is safe IF precondition P holds,
enforced by function G."  Unlike flat TaintSpecs (this function IS a sink),
assumptions model relationships between functions — the composition that
creates or prevents a vulnerability.

Named categories constrain the query shape:
- sanitisation/validation → data-flow: does taint reach the target
  without passing through the enforcer?
- ordering/state → control-flow: does the caller invoke the target
  without first invoking the enforcer?
- type_constraint → combined: does an underminer sit between the source
  and the enforcer, defeating the enforcer's precondition?
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from core.evidence import EvidenceTier

logger = logging.getLogger(__name__)


class AssumptionCategory(str, Enum):
    SANITISATION = "sanitisation"
    VALIDATION = "validation"
    ORDERING = "ordering"
    STATE = "state"
    TYPE_CONSTRAINT = "type_constraint"
    PROVENANCE = "provenance"


@dataclass
class SafetyAssumption:
    """A compositional safety specification.

    ``target`` is safe IF ``enforced_by`` was called on the path from
    any entry point to ``target``.  When ``underminer`` is set, the
    assumption is violated even when the enforcer IS present — if
    the underminer sits between the source and the enforcer.
    """

    target: str
    file: str
    assumption: str
    category: AssumptionCategory
    enforced_by: list[str] = field(default_factory=list)
    bug_class: str = ""
    params_affected: list[int] = field(default_factory=list)
    confidence: float = 0.5
    evidence_tier: EvidenceTier = EvidenceTier.HEURISTIC
    source: str = ""
    underminer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "target": self.target,
            "file": self.file,
            "assumption": self.assumption,
            "category": self.category.value,
            "enforced_by": self.enforced_by,
            "bug_class": self.bug_class,
            "params_affected": self.params_affected,
            "confidence": self.confidence,
            "evidence_tier": self.evidence_tier.value,
        }
        if self.source:
            d["source"] = self.source
        if self.underminer:
            d["underminer"] = self.underminer
        return d


@dataclass
class BypassFinding:
    """A detected bypass of a safety assumption."""

    assumption: SafetyAssumption
    caller_file: str
    caller_function: str
    missing_enforcer: str = ""
    via_intermediate: str | None = None
    is_transitive: bool = False
    ordering_violation: bool = False
    line_info: dict[str, int] = field(default_factory=dict)
    evidence_tier: EvidenceTier = EvidenceTier.XREF_BACKED

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "caller_file": self.caller_file,
            "caller_function": self.caller_function,
            "missing_enforcer": self.missing_enforcer,
            "is_transitive": self.is_transitive,
            "ordering_violation": self.ordering_violation,
            "evidence_tier": self.evidence_tier.value,
            "assumption": {
                "target": self.assumption.target,
                "file": self.assumption.file,
                "assumption": self.assumption.assumption,
                "category": self.assumption.category.value,
                "bug_class": self.assumption.bug_class,
                "enforced_by": list(self.assumption.enforced_by),
            },
        }
        if self.via_intermediate:
            d["via_intermediate"] = self.via_intermediate
        if self.line_info:
            d["line_info"] = self.line_info
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> BypassFinding:
        a_data = d.get("assumption", {})
        try:
            cat = AssumptionCategory(a_data.get("category", "sanitisation"))
        except ValueError:
            cat = AssumptionCategory.SANITISATION
        assumption = SafetyAssumption(
            target=a_data.get("target", ""),
            file=a_data.get("file", ""),
            assumption=a_data.get("assumption", ""),
            category=cat,
            bug_class=a_data.get("bug_class", ""),
            enforced_by=a_data.get("enforced_by") or [],
        )
        try:
            tier = EvidenceTier(d.get("evidence_tier", "xref_backed"))
        except ValueError:
            tier = EvidenceTier.XREF_BACKED
        return cls(
            assumption=assumption,
            caller_file=d.get("caller_file", ""),
            caller_function=d.get("caller_function", ""),
            missing_enforcer=d.get("missing_enforcer", ""),
            via_intermediate=d.get("via_intermediate"),
            is_transitive=d.get("is_transitive", False),
            ordering_violation=d.get("ordering_violation", False),
            line_info=d.get("line_info", {}),
            evidence_tier=tier,
        )


def _assumption_key(a: SafetyAssumption) -> str:
    enforcers = ",".join(sorted(a.enforced_by))
    underminer = a.underminer or ""
    return f"{a.file}\0{a.target}\0{a.category.value}\0{enforcers}\0{underminer}"


def assumption_from_dict(d: dict[str, Any]) -> SafetyAssumption:
    try:
        cat = AssumptionCategory(d.get("category", "sanitisation"))
    except ValueError:
        cat = AssumptionCategory.SANITISATION
    try:
        tier = EvidenceTier(d.get("evidence_tier", "heuristic"))
    except ValueError:
        tier = EvidenceTier.HEURISTIC

    raw_enforced = d.get("enforced_by") or []
    if isinstance(raw_enforced, str):
        raw_enforced = [raw_enforced]
    elif not isinstance(raw_enforced, list):
        raw_enforced = []

    raw_params = d.get("params_affected") or []
    if isinstance(raw_params, (int, float)) or isinstance(raw_params, str):
        raw_params = [raw_params]
    elif not isinstance(raw_params, list):
        raw_params = []
    params_affected: list[int] = []
    for p in raw_params:
        try:
            params_affected.append(int(p))
        except (TypeError, ValueError):
            continue

    return SafetyAssumption(
        target=d.get("target", ""),
        file=d.get("file", ""),
        assumption=d.get("assumption", ""),
        category=cat,
        enforced_by=raw_enforced,
        bug_class=d.get("bug_class", ""),
        params_affected=params_affected,
        confidence=d.get("confidence", 0.5),
        evidence_tier=tier,
        source=d.get("source", ""),
        underminer=d.get("underminer"),
    )


def assumptions_from_list(items: list[dict[str, Any]]) -> list[SafetyAssumption]:
    result = []
    for d in items:
        try:
            result.append(assumption_from_dict(d))
        except Exception:  # noqa: BLE001
            logger.debug("skipping malformed assumption: %s", d)
    return result


def merge_assumptions(
    existing: list[SafetyAssumption],
    new: list[SafetyAssumption],
) -> list[SafetyAssumption]:
    """Merge new assumptions into existing, dedup by key.

    Higher evidence tier wins.  If equal, new wins (fresher).
    """
    from core.evidence import stronger

    by_key: dict[str, SafetyAssumption] = {}
    for a in existing:
        by_key[_assumption_key(a)] = a

    for a in new:
        key = _assumption_key(a)
        old = by_key.get(key)
        if old is None:
            by_key[key] = a
        else:
            winner_tier = stronger(old.evidence_tier, a.evidence_tier)
            if winner_tier != old.evidence_tier or winner_tier == a.evidence_tier:
                by_key[key] = a
    return list(by_key.values())


def evict_stale_assumptions(
    assumptions: list[SafetyAssumption],
    current_files: set[str],
    *,
    keep_above: EvidenceTier = EvidenceTier.XREF_BACKED,
) -> list[SafetyAssumption]:
    """Remove assumptions for files no longer in the project."""
    from core.evidence import TIER_RANK

    kept = [a for a in assumptions if a.file in current_files or TIER_RANK.get(a.evidence_tier, 0) >= TIER_RANK.get(keep_above, 0)]
    return kept
