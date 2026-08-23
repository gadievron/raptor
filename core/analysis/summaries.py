"""Per-function security summaries for inter-procedural reasoning.

Summaries capture security-relevant function behavior: taint propagation
rules, precondition guards, return conditions, error paths, and resolved
callees/callers.  Two producers:

1. Mechanical (Joern CPG) — structural facts, high confidence.
2. LLM review — semantic understanding from the review loop,
   medium confidence, covers behavior Joern can't see (conditional
   sanitization, protocol semantics, design intent).

Summaries are injected into the LLM's review context for callee
functions so the reviewer has inter-procedural knowledge without
re-reading every callee's source.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from core.evidence import EvidenceTier

logger = logging.getLogger(__name__)


@dataclass
class TaintRule:
    """A parameter→callee taint propagation path from the CPG."""
    source_param: str
    source_index: int
    sink_call: str
    sink_arg_index: int
    hop_count: int = 0
    evidence_tier: EvidenceTier = EvidenceTier.XREF_BACKED


@dataclass
class Precondition:
    """A conditional guard on a parameter extracted from the CPG."""
    param: str
    param_index: int
    conditions: list
    evidence_tier: EvidenceTier = EvidenceTier.XREF_BACKED


@dataclass
class ReturnCondition:
    """A return statement with its dominating conditions."""
    code: str
    line: int = -1
    conditions: list = field(default_factory=list)
    evidence_tier: EvidenceTier = EvidenceTier.XREF_BACKED


@dataclass
class FunctionSummary:
    """Security summary of a function from mechanical or LLM analysis."""

    function: str
    file: str
    taint_rules: list[TaintRule] = field(default_factory=list)
    preconditions: list[Precondition] = field(default_factory=list)
    returns: list[ReturnCondition] = field(default_factory=list)
    error_paths: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)
    callers: list[str] = field(default_factory=list)
    state_transitions: list[str] = field(default_factory=list)
    evidence_tier: EvidenceTier = EvidenceTier.XREF_BACKED
    source: str = "mechanical"
    confidence: str = "high"

    def is_empty(self) -> bool:
        return (
            not self.taint_rules
            and not self.preconditions
            and not self.returns
            and not self.error_paths
        )

    def format_for_context(self, depth: str = "full") -> str:
        """Render as text for LLM context injection.

        depth="oneline" — one-sentence summary for GLANCE context.
        depth="full"    — complete summary for DEEP_DIVE context.
        """
        if self.is_empty():
            if depth == "oneline":
                return f"`{self.function}()`: no CPG-derived security signals."
            return ""

        if depth == "oneline":
            parts = []
            if self.taint_rules:
                sinks = sorted({r.sink_call for r in self.taint_rules})
                parts.append(f"taint→{','.join(sinks)}")
            if self.preconditions:
                parts.append(f"{len(self.preconditions)} guards")
            if self.error_paths:
                parts.append(f"{len(self.error_paths)} error returns")
            detail = "; ".join(parts) if parts else "utility"
            return f"`{self.function}()`: {detail}."

        lines = [f"### CPG summary: `{self.function}()` [{self.evidence_tier.value}]"]

        if self.taint_rules:
            lines.append("**Taint propagation:**")
            for r in self.taint_rules:
                tier_tag = f" [{r.evidence_tier.value}]" if r.evidence_tier != self.evidence_tier else ""
                lines.append(
                    f"- param `{r.source_param}` → `{r.sink_call}()` arg #{r.sink_arg_index}"
                    + (f" ({r.hop_count} hops)" if r.hop_count > 1 else "")
                    + tier_tag
                )

        if self.preconditions:
            lines.append("**Guards:**")
            for p in self.preconditions:
                conds = ", ".join(str(c)[:80] for c in p.conditions[:3])
                lines.append(f"- param `{p.param}` guarded by: {conds}")

        if self.returns:
            lines.append("**Returns:**")
            for r in self.returns[:5]:
                cond_str = ""
                if r.conditions:
                    cond_str = f" when {r.conditions[0][:60]}"
                lines.append(f"- `{r.code[:80]}`{cond_str}")

        if self.error_paths:
            lines.append("**Error returns:**")
            lines.extend(f"- `{ep[:80]}`" for ep in self.error_paths[:3])

        if self.state_transitions:
            lines.append("**State transitions:**")
            lines.extend(f"- {st[:80]}" for st in self.state_transitions[:5])

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function,
            "file": self.file,
            "taint_rules": [
                {
                    "source_param": r.source_param,
                    "source_index": r.source_index,
                    "sink_call": r.sink_call,
                    "sink_arg_index": r.sink_arg_index,
                    "hop_count": r.hop_count,
                    "evidence_tier": r.evidence_tier.value,
                }
                for r in self.taint_rules
            ],
            "preconditions": [
                {
                    "param": p.param,
                    "param_index": p.param_index,
                    "conditions": p.conditions,
                    "evidence_tier": p.evidence_tier.value,
                }
                for p in self.preconditions
            ],
            "returns": [
                {
                    "code": r.code,
                    "line": r.line,
                    "conditions": r.conditions,
                    "evidence_tier": r.evidence_tier.value,
                }
                for r in self.returns
            ],
            "error_paths": self.error_paths,
            "callees": self.callees,
            "callers": self.callers,
            "state_transitions": self.state_transitions,
            "evidence_tier": self.evidence_tier.value,
            "source": self.source,
            "confidence": self.confidence,
        }


def _parse_evidence_tier(data: dict[str, Any]) -> EvidenceTier:
    """Parse an evidence tier from a dict, defaulting to XREF_BACKED."""
    raw = data.get("evidence_tier", "")
    if raw:
        try:
            return EvidenceTier(raw)
        except ValueError:
            pass
    return EvidenceTier.XREF_BACKED


def parse_taint_lines(raw: str) -> list[TaintRule]:
    """Parse SUMMARY_TAINT: lines from Joern query output."""
    rules = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("SUMMARY_TAINT:"):
            continue
        try:
            data = json.loads(line[len("SUMMARY_TAINT:"):].strip())
            rules.append(TaintRule(
                source_param=data.get("source_param", ""),
                source_index=data.get("source_index", -1),
                sink_call=data.get("sink_call", ""),
                sink_arg_index=data.get("sink_arg_index", -1),
                hop_count=data.get("hop_count", 0),
                evidence_tier=_parse_evidence_tier(data),
            ))
        except (json.JSONDecodeError, KeyError, AttributeError):
            logger.debug("failed to parse taint line: %s", line[:200])
    return rules


def parse_guard_lines(raw: str) -> list[Precondition]:
    """Parse SUMMARY_GUARD: lines from Joern query output."""
    guards = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("SUMMARY_GUARD:"):
            continue
        try:
            data = json.loads(line[len("SUMMARY_GUARD:"):].strip())
            guards.append(Precondition(
                param=data.get("param", ""),
                param_index=data.get("param_index", -1),
                conditions=data.get("conditions", []),
                evidence_tier=_parse_evidence_tier(data),
            ))
        except (json.JSONDecodeError, KeyError, AttributeError):
            logger.debug("failed to parse guard line: %s", line[:200])
    return guards


def parse_return_lines(raw: str) -> list[ReturnCondition]:
    """Parse SUMMARY_RETURN: lines from Joern query output."""
    returns = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("SUMMARY_RETURN:"):
            continue
        try:
            data = json.loads(line[len("SUMMARY_RETURN:"):].strip())
            returns.append(ReturnCondition(
                code=data.get("code", ""),
                line=data.get("line", -1),
                conditions=data.get("conditions", []),
                evidence_tier=_parse_evidence_tier(data),
            ))
        except (json.JSONDecodeError, KeyError, AttributeError):
            logger.debug("failed to parse return line: %s", line[:200])
    return returns


def parse_error_lines(raw: str) -> list[str]:
    """Parse SUMMARY_ERROR: lines from Joern query output."""
    errors = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("SUMMARY_ERROR:"):
            continue
        try:
            data = json.loads(line[len("SUMMARY_ERROR:"):].strip())
            errors.append(data.get("code", ""))
        except (json.JSONDecodeError, KeyError, AttributeError):
            logger.debug("failed to parse error line: %s", line[:200])
    return errors


def build_summary_from_query_outputs(
    function: str,
    file: str,
    *,
    taint_output: str = "",
    guard_output: str = "",
    return_output: str = "",
    error_output: str = "",
    callees: list[str] | None = None,
    callers: list[str] | None = None,
    state_transitions: list[str] | None = None,
    source: str = "mechanical",
    confidence: str = "high",
) -> FunctionSummary:
    """Build a FunctionSummary from raw Joern query output strings."""
    return FunctionSummary(
        function=function,
        file=file,
        taint_rules=parse_taint_lines(taint_output),
        preconditions=parse_guard_lines(guard_output),
        returns=parse_return_lines(return_output),
        error_paths=parse_error_lines(error_output),
        callees=callees or [],
        callers=callers or [],
        state_transitions=state_transitions or [],
        source=source,
        confidence=confidence,
    )


def summary_from_review_result(
    function: str,
    file: str,
    review_result: dict[str, Any],
) -> FunctionSummary | None:
    """Extract a FunctionSummary from an LLM review outcome.

    The LLM discovers security behavior that Joern can't see —
    conditional sanitization, protocol semantics, design intent.
    This converts the structured review output into a summary
    that flows to subsequent callers via taint_summary_results.
    """
    if not review_result:
        return None

    preconditions = []
    for pc in review_result.get("preconditions") or []:
        param = pc.get("parameter", pc.get("param", ""))
        assumption = pc.get("assumption", "")
        if param and assumption:
            preconditions.append(Precondition(
                param=param,
                param_index=pc.get("param_index", 0),
                conditions=[assumption],
                evidence_tier=EvidenceTier.HEURISTIC,
            ))

    callees = review_result.get("callees", [])
    callers = review_result.get("callers", [])

    if not preconditions and not callees and not callers:
        return None

    return FunctionSummary(
        function=function,
        file=file,
        preconditions=preconditions,
        callees=callees[:20] if isinstance(callees, list) else [],
        callers=callers[:20] if isinstance(callers, list) else [],
        source="llm",
        confidence="medium",
        evidence_tier=EvidenceTier.HEURISTIC,
    )


def propagate_taint_upward(
    callee_summary: FunctionSummary,
    caller_summary: FunctionSummary,
    call_args: list[dict[str, Any]],
) -> list[TaintRule]:
    """Inherit callee taint rules into the caller's summary.

    If ``parse_header(user_input)`` has taint_rule param[0]→return,
    and ``handle_request`` calls it with its own param ``user_input``,
    then handle_request inherits: param.user_input → var.header_result.

    call_args maps callee param indices to caller param names:
      [{"callee_index": 0, "caller_param": "user_input"}]

    Returns new TaintRule objects added to caller_summary.
    """
    if not callee_summary.taint_rules or not call_args:
        return []

    arg_map = {a["callee_index"]: a["caller_param"] for a in call_args if "callee_index" in a}
    inherited = []

    for rule in callee_summary.taint_rules:
        caller_param = arg_map.get(rule.source_index)
        if not caller_param:
            continue

        new_rule = TaintRule(
            source_param=caller_param,
            source_index=-1,
            sink_call=rule.sink_call,
            sink_arg_index=rule.sink_arg_index,
            hop_count=rule.hop_count + 1,
            evidence_tier=EvidenceTier.HEURISTIC,
        )
        if not any(
            r.source_param == new_rule.source_param and r.sink_call == new_rule.sink_call
            for r in caller_summary.taint_rules
        ):
            caller_summary.taint_rules.append(new_rule)
            inherited.append(new_rule)

    return inherited


def resolve_scc_summaries(
    scc: list[str],
    summaries: dict[str, FunctionSummary],
    call_edges: list[dict[str, Any]],
    max_iterations: int = 3,
) -> int:
    """Fixed-point propagation for strongly-connected components.

    Functions in an SCC are mutually recursive — callee-first ordering
    can't break the cycle. Iterate taint propagation within the SCC
    until no new rules are discovered or max_iterations is reached.

    Returns the number of new rules propagated.
    """
    total_new = 0

    for _iteration in range(max_iterations):
        round_new = 0
        for edge in call_edges:
            caller_key = f"{edge.get('caller_file', '')}:{edge.get('caller', '')}"
            callee_file = edge.get("callee_file") or edge.get("caller_file", "")
            callee_key = f"{callee_file}:{edge.get('callee', '')}"

            if caller_key not in scc or callee_key not in scc:
                continue
            if caller_key not in summaries or callee_key not in summaries:
                continue

            call_args = edge.get("args", [])
            new_rules = propagate_taint_upward(
                summaries[callee_key], summaries[caller_key], call_args,
            )
            round_new += len(new_rules)

        total_new += round_new
        if round_new == 0:
            break

    return total_new
