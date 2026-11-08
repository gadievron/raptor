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
_PREDICATE_JOIN_RE = re.compile(r"(?:and|or)\b", re.IGNORECASE)


def _require_condition_text(text: Any) -> str:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("path-condition text must be a non-empty string")
    return text


@dataclass
class PathCondition:
    text: str
    negated: bool = False
    source: str = ""

    def __post_init__(self):
        require_bool(self.negated, argument="negated")

    def to_smt_condition(self) -> str | dict[str, Any]:
        require_bool(self.negated, argument="negated")
        _require_condition_text(self.text)
        if self.negated:
            return {"text": self.text, "negated": True}
        return self.text


@dataclass
class FeasibilityResult:
    feasible: bool | None = None
    conditions: list[PathCondition] = field(default_factory=list)
    reasoning: str = ""
    error: str = ""


def _trace_conditions(raw: Any, source: str) -> list[PathCondition]:
    """Admit a complete condition collection without dropping malformed cells."""
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raise ValueError("path_conditions must be a string or a list")
    conditions = []
    for value in raw:
        if isinstance(value, str):
            conditions.append(PathCondition(_require_condition_text(value), source=source))
        elif isinstance(value, dict):
            conditions.append(PathCondition(
                _require_condition_text(value.get("text")),
                negated=value.get("negated", False), source=source,
            ))
        else:
            raise ValueError("each path condition must be a string or a text record")
    return conditions


def extract_conditions_from_flow_trace(
    trace: dict[str, Any],
) -> list[PathCondition]:
    """Extract branch conditions from a flow trace's steps.

    Flow traces from /understand --trace may carry per-step
    path_conditions in two formats:
    - List of strings: ["size > 0", "buf != NULL"]
    - List of dicts: [{"text": "size > 0", "negated": false}]

    Condition collections and cells must be complete, with nonempty text
    and Boolean polarity. Invalid metadata raises ValueError so the enclosing
    check can decline the entire trace rather than solve a shortened subset.
    """
    if not isinstance(trace, dict):
        raise ValueError("flow trace must be a dictionary")
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
        conditions.extend(_trace_conditions(
            step.get("path_conditions", []),
            step.get("definition", step.get("file", "")) or "",
        ))

    conditions.extend(_trace_conditions(trace.get("path_conditions", []), "trace"))

    return conditions


def _atomic_predicate_context(text: str, start: int, end: int) -> bool:
    """Reject expression fragments around a complete extraction candidate.

    Parentheses may enclose a prose predicate, but cannot hide its negation
    or a continuation outside the wrapper. Inspect adjacent tokens by index
    rather than repeatedly copying the entire preceding hypothesis.
    """
    left, wrappers = start - 1, 0
    while left >= 0:
        if text[left].isspace():
            left -= 1
        elif text[left] == "(":
            wrappers += 1
            left -= 1
        else:
            break
    if left >= 0 and text[left] in ".:<>!=~?+-*/%&|^[":
        return False
    word_end = left + 1
    while left >= 0 and (text[left].isalnum() or text[left] == "_"):
        left -= 1
    if text[left + 1:word_end].lower() in {"and", "or", "not"}:
        return False

    right = end
    while right < len(text) and text[right].isspace():
        right += 1
    for _ in range(wrappers):
        if right >= len(text) or text[right] != ")":
            return False
        right += 1
        while right < len(text) and text[right].isspace():
            right += 1
    if right < len(text) and text[right] in "+-*/%&|^<>=!~?:[()]":
        return False
    if right < len(text) and text[right] == ".":
        following = right + 1
        while following < len(text) and text[following].isspace():
            following += 1
        if following < len(text) and (text[following].isalnum() or text[following] == "_"):
            return False
    return _PREDICATE_JOIN_RE.match(text, right) is None


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
    if_patterns = re.finditer(
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
            text=match.group(2).strip(),
            source="hypothesis",
        ) for match in if_patterns if _atomic_predicate_context(hypothesis, *match.span())]

    null_patterns = re.finditer(
        r'\b([A-Za-z_][A-Za-z0-9_]*)\s+is\s+(?:non-null|not null)(?![\w-])',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{match.group(1)} != NULL",
            source="hypothesis",
        ) for match in null_patterns if _atomic_predicate_context(hypothesis, *match.span()))

    nonneg_patterns = re.finditer(
        r'\b([A-Za-z_][A-Za-z0-9_]*)\s+(?:is|must be)\s+(non-negative|positive|greater than zero)(?![\w-])',
        hypothesis,
        re.IGNORECASE,
    )
    conditions.extend(PathCondition(
            text=f"{match.group(1)} {'>=' if match.group(2).lower() == 'non-negative' else '>'} 0",
            source="hypothesis",
        ) for match in nonneg_patterns if _atomic_predicate_context(hypothesis, *match.span()))

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
        smt_conditions = [c.to_smt_condition() for c in conditions]

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
        if result.errors:
            return FeasibilityResult(
                conditions=list(conditions),
                reasoning=result.raw_output or "SMT path-condition query failed",
                error="; ".join(result.errors),
            )
        if details.get("smt_available") is False:
            return FeasibilityResult(
                conditions=list(conditions), reasoning="SMT solver unavailable",
            )
        partial = bool(details.get("unknown") or details.get("unknown_reasons"))
        if details.get("oracle_scope") == "supplied-predicates":
            feasible = details.get("feasible")
            return FeasibilityResult(
                feasible=feasible if isinstance(feasible, bool) and not (feasible and partial) else None,
                conditions=list(conditions),
                reasoning=("encoded predicate subset is satisfiable; complete conjunction unavailable"
                           if feasible is True and partial else result.raw_output or "predicate feasibility observation"),
            )
        if result.outcome == "confirmed":
            return FeasibilityResult(
                feasible=None if partial else True,
                conditions=list(conditions),
                reasoning=("encoded predicate subset is satisfiable; complete conjunction unavailable"
                           if partial else result.raw_output or "conditions are satisfiable"),
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
            reasoning="path-condition query incomplete: " + str(exc),
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
