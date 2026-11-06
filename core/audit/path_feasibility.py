"""SMT path feasibility for LLM-generated cross-function paths.

Extracts branch conditions from flow traces and annotations, builds
condition sets for source-to-sink paths, and checks their mathematical
satisfiability via the ``validate-path`` SMT verb. These inputs are not a
source-semantics model: SAT does not prove a defect, and UNSAT does not
refute a finding across all possible paths.

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

from core.smt_solver._validation import require_bool

logger = logging.getLogger(__name__)


@dataclass
class PathCondition:
    text: str
    negated: bool = False
    source: str = ""

    def __post_init__(self):
        require_bool(self.negated, argument="negated")

    def to_smt_condition(self) -> str | dict[str, Any]:
        require_bool(self.negated, argument="negated")
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

    A present negated flag must be a Boolean. Invalid polarity raises
    ValueError so the enclosing check can decline the entire trace.
    """
    conditions = []

    raw_steps = trace.get("steps", trace.get("hops", []))
    if not isinstance(raw_steps, list):
        # LLM-authored traces can carry ``steps: null`` or scalar
        # shapes; degrade to no steps rather than raising.
        raw_steps = []
    for step in raw_steps:
        if not isinstance(step, dict):
            # LLM-authored traces can carry malformed steps.
            continue
        raw_conditions = step.get("path_conditions", [])
        if isinstance(raw_conditions, str):
            # A bare string char-iterates into one-character
            # conditions handed to the SMT verb — treat it as a
            # single condition.
            raw_conditions = [raw_conditions]
        elif not isinstance(raw_conditions, list):
            raw_conditions = []
        for cond in raw_conditions:
            if isinstance(cond, str):
                conditions.append(PathCondition(
                    text=cond,
                    source=step.get("definition", step.get("file", "")) or "",
                ))
            elif isinstance(cond, dict):
                conditions.append(PathCondition(
                    text=cond.get("text", ""),
                    negated=cond.get("negated", False),
                    source=step.get("definition", step.get("file", "")) or "",
                ))

    top_level = trace.get("path_conditions", [])
    if isinstance(top_level, str):
        top_level = [top_level]
    elif not isinstance(top_level, list):
        top_level = []
    for cond in top_level:
        if isinstance(cond, str):
            conditions.append(PathCondition(text=cond, source="trace"))
        elif isinstance(cond, dict):
            conditions.append(PathCondition(
                text=cond.get("text", ""),
                negated=cond.get("negated", False),
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

    Extract atomic comparisons only; do not shorten arithmetic, call,
    member-access, or Boolean expressions into different predicates.
    These remain tentative predicates, not source reachability evidence.
    """

    # Gated optional paren — the naive ``\(?\s*`` pair was
    # quadratic on a keyword followed by a whitespace run.
    # \b pins each attempt to a word start: unanchored, a hostile
    # word run retries every suffix — quadratic. A mid-word keyword
    # ('elif' read as 'if') was a false token, not a condition.
    if_patterns = re.findall(
        r'\b(?:if|when|where|provided that|assuming)\s*(\(\s*)?'
        r'([a-zA-Z_]\w*\s*(?:<=|>=|==|!=|<|>)\s*'
        r'(?:0x[0-9a-fA-F]+|[a-zA-Z_]\w*|\d+))'
        # A parenthesized atom must reach its closing delimiter. Otherwise
        # prevent expression truncation and RHS-token backtracking.
        r'(?(1)\s*\)|(?!\w)(?!\s*(?:[-+*/%&|^<>=!~?:\[(]|\.(?=\s*\w)|\b(?:and|or)\b)))',
        hypothesis,
        re.IGNORECASE,
    )
    conditions = [PathCondition(
            text=match.strip(),
            source="hypothesis",
        ) for _, match in if_patterns]

    null_patterns = re.findall(
        r'\b(\w+)\s+is\s+(?:non-null|not null)(?![\w-])',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{var} != NULL",
            source="hypothesis",
        ) for var in null_patterns)

    nonneg_patterns = re.findall(
        r'\b(\w+)\s+(?:is|must be)\s+(non-negative|positive|greater than zero)(?![\w-])',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{var} {'>=' if phrase.lower() == 'non-negative' else '>'} 0",
            source="hypothesis",
        ) for var, phrase in nonneg_patterns)

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

    try:
        smt_conditions = [c.to_smt_condition() for c in conditions if c.text]
        if not smt_conditions:
            return FeasibilityResult(
                feasible=None,
                reasoning="all conditions were empty after filtering",
            )

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

        # The sweep's outcome is about claim admission; these explicit
        # details answer only the mathematical question about our inputs.
        details = result.details or {}
        if details.get("oracle_scope") == "supplied-predicates" and not result.errors:
            feasible = details.get("feasible")
            return FeasibilityResult(
                feasible=feasible if isinstance(feasible, bool) else None,
                conditions=list(conditions),
                reasoning=result.raw_output or "predicate feasibility observation",
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
    try:
        conditions = extract_conditions_from_flow_trace(trace)
    except (ValueError, TypeError) as exc:
        return FeasibilityResult(
            feasible=None, reasoning="invalid path-condition metadata", error=str(exc),
        )
    if not conditions:
        return FeasibilityResult(
            feasible=None,
            reasoning="no path conditions in trace",
        )
    return check_path_feasibility(conditions, profile=profile)
