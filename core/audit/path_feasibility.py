"""SMT path feasibility for LLM-generated cross-function paths.

Extracts branch conditions from flow traces and annotations, builds
condition sets for source-to-sink paths, and validates them via the
``validate-path`` SMT verb.

Integration patterns:
1. Inline with /audit review — after an LLM generates a hypothesis
   about a path being reachable, extract conditions and validate.
2. Post-sweep — bulk-check all flow traces that have path_conditions.
3. As an evidence tool — review_fn can call check_path_feasibility()
   and include the result in the annotation.

Condition extraction:
- Flow traces carry ``path_conditions`` per step (from --trace)
- Annotations may record conditions in metadata
- LLM hypotheses that reference specific branch conditions
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


@dataclass
class PathCondition:
    text: str
    negated: bool = False
    source: str = ""

    def to_smt_condition(self) -> str | dict[str, Any]:
        if self.negated:
            return {"text": self.text, "negated": True}
        return self.text


@dataclass
class FeasibilityResult:
    feasible: bool | None = None
    conditions: list[PathCondition] = field(default_factory=list)
    reasoning: str = ""
    error: str = ""


def extract_conditions_from_flow_trace(
    trace: dict[str, Any],
) -> list[PathCondition]:
    """Extract branch conditions from a flow trace's steps.

    Flow traces from /understand --trace may carry per-step
    path_conditions in two formats:
    - List of strings: ["size > 0", "buf != NULL"]
    - List of dicts: [{"text": "size > 0", "negated": false}]
    """
    conditions = []

    for step in trace.get("steps", trace.get("hops", [])):
        raw_conditions = step.get("path_conditions", [])
        for cond in raw_conditions:
            if isinstance(cond, str):
                conditions.append(PathCondition(
                    text=cond,
                    source=step.get("definition", step.get("file", "")),
                ))
            elif isinstance(cond, dict):
                conditions.append(PathCondition(
                    text=cond.get("text", ""),
                    negated=bool(cond.get("negated", False)),
                    source=step.get("definition", step.get("file", "")),
                ))

    top_level = trace.get("path_conditions", [])
    for cond in top_level:
        if isinstance(cond, str):
            conditions.append(PathCondition(text=cond, source="trace"))
        elif isinstance(cond, dict):
            conditions.append(PathCondition(
                text=cond.get("text", ""),
                negated=bool(cond.get("negated", False)),
                source="trace",
            ))

    return conditions


def extract_conditions_from_hypothesis(
    hypothesis: str,
) -> list[PathCondition]:
    """Best-effort extraction of branch conditions from LLM hypothesis text.

    Looks for patterns like:
    - "if (size > MAX_BUF)" or "when len < 0"
    - "assuming X is non-null" → X != NULL
    - "provided that Y > 0"
    """

    if_patterns = re.findall(
        r'(?:if|when|where|provided that|assuming)\s*\(?\s*'
        r'([a-zA-Z_]\w*\s*(?:[<>=!]+|!=|==)\s*(?:\w+|0x[0-9a-fA-F]+|\d+))',
        hypothesis,
        re.IGNORECASE,
    )
    conditions = [PathCondition(
            text=match.strip(),
            source="hypothesis",
        ) for match in if_patterns]

    null_patterns = re.findall(
        r'(\w+)\s+is\s+(?:non-null|not null|not NULL)',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{var} != NULL",
            source="hypothesis",
        ) for var in null_patterns)

    nonneg_patterns = re.findall(
        r'(\w+)\s+(?:is|must be)\s+(?:non-negative|positive|greater than zero)',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{var} > 0",
            source="hypothesis",
        ) for var in nonneg_patterns)

    return conditions


def extract_conditions_from_annotation(
    annotation_metadata: dict[str, str],
    annotation_body: str = "",
) -> list[PathCondition]:
    """Extract conditions from annotation metadata and body."""
    conditions = []

    cond_str = annotation_metadata.get("path_conditions", "")
    if cond_str:
        for part in cond_str.split(";"):
            part = part.strip()
            if part:
                conditions.append(PathCondition(
                    text=part, source="annotation",
                ))

    if annotation_body:
        conditions.extend(extract_conditions_from_hypothesis(annotation_body))

    return conditions


def check_path_feasibility(
    conditions: Sequence[PathCondition],
    *,
    profile: dict[str, Any] | None = None,
) -> FeasibilityResult:
    """Check whether a set of path conditions are jointly satisfiable.

    Delegates to the validate-path SMT verb via run_smt_sweep.
    Returns a FeasibilityResult with the solver's verdict.
    """
    if not conditions:
        return FeasibilityResult(
            feasible=None,
            reasoning="no conditions to check",
        )

    smt_conditions = [c.to_smt_condition() for c in conditions if c.text]
    if not smt_conditions:
        return FeasibilityResult(
            feasible=None,
            reasoning="all conditions were empty after filtering",
        )

    try:
        from .sweep import run_smt_sweep

        smt_args: dict[str, Any] = {"conditions": smt_conditions}
        if profile:
            smt_args["profile"] = profile

        result = run_smt_sweep(
            file_path="(path-check)",
            function_name="(path-check)",
            verb="validate-path",
            smt_args=smt_args,
        )

        if result.outcome == "confirmed":
            return FeasibilityResult(
                feasible=True,
                conditions=list(conditions),
                reasoning=result.raw_output or "conditions are satisfiable",
            )
        if result.outcome == "refuted":
            return FeasibilityResult(
                feasible=False,
                conditions=list(conditions),
                reasoning=result.raw_output or "conditions are unsatisfiable",
            )
        return FeasibilityResult(
            feasible=None,
            conditions=list(conditions),
            reasoning=result.raw_output or "inconclusive",
            error="; ".join(result.errors) if result.errors else "",
        )

    except Exception as exc:
        return FeasibilityResult(
            feasible=None,
            conditions=list(conditions),
            error=str(exc),
        )


def check_flow_trace_feasibility(
    trace: dict[str, Any],
    *,
    profile: dict[str, Any] | None = None,
) -> FeasibilityResult:
    """Check feasibility of a single flow trace's path conditions."""
    conditions = extract_conditions_from_flow_trace(trace)
    if not conditions:
        return FeasibilityResult(
            feasible=None,
            reasoning="no path conditions in trace",
        )
    return check_path_feasibility(conditions, profile=profile)
