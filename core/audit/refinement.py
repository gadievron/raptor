"""Iterative hypothesis refinement for audit review.

When the sweep is inconclusive (tools dispatched but none confirmed),
feed the tool results back to the LLM for a refined hypothesis.
Max 2 refinement rounds per function.

Also implements clean-check refinement: for high-depth clean verdicts,
run a focused tool sweep and feed any discovered flows back to the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

DEFAULT_MAX_REFINEMENTS = 2
MIN_SLOC_CLEAN_CHECK = 20


@dataclass
class RefinementContext:
    """Context for a refinement round."""

    prior_hypothesis: str
    prior_status: str
    tool_results: List[Dict[str, str]]
    tools_dispatched: Set[str]
    round_number: int
    tool_query_suggestion: str = ""


def should_refine(
    outcome: Any,
    triage_bucket: str,
    *,
    round_number: int = 0,
    max_refinements: int = DEFAULT_MAX_REFINEMENTS,
) -> bool:
    """Decide whether to run a refinement round.

    Triggers when:
    - Status is finding or suspicious
    - At least one tool was dispatched but none confirmed (no evidence_tool)
    - Triage bucket is investigate or deep_dive
    - Haven't exceeded max refinement rounds
    """
    if round_number >= max_refinements:
        return False

    status = getattr(outcome, "status", "")
    if status not in ("finding", "suspicious"):
        return False

    if triage_bucket not in ("investigate", "deep_dive"):
        return False

    from .evidence_grade import is_tool_evidence
    evidence_tool = getattr(outcome, "evidence_tool", "") or ""
    if is_tool_evidence(evidence_tool):
        return False

    return True


def build_refinement_prompt(
    ctx: Dict[str, Any],
    refinement: RefinementContext,
) -> str:
    """Build the refinement section injected into the review context.

    Tells the LLM what it hypothesised, what the tools found, and
    asks it to refine.
    """
    lines = [
        f"## Refinement round {refinement.round_number}",
        "",
        f"Your prior hypothesis: \"{refinement.prior_hypothesis}\"",
        f"Prior verdict: {refinement.prior_status}",
        "",
        f"Tools dispatched: {', '.join(sorted(refinement.tools_dispatched))}",
        "",
    ]

    if refinement.tool_results:
        lines.append("Tool results:")
        for tr in refinement.tool_results:
            tool = tr.get("tool", "unknown")
            result = tr.get("result", "no output")
            lines.append(f"- **{tool}**: {result}")
        lines.append("")

    if refinement.tool_query_suggestion:
        lines.extend([
            f"Your prior suggested check: \"{refinement.tool_query_suggestion}\"",
            "",
        ])

    lines.extend([
        "None of the mechanical tools confirmed your hypothesis.",
        "",
        "Refine your hypothesis based on this evidence:",
        "- If the tool missed an indirect path, specify the intermediate "
        "functions in your revised hypothesis.",
        "- If the tool refuted your hypothesis, try an alternative mechanism.",
        "- If you believe the hypothesis is correct despite no tool confirmation, "
        "explain why the tools would miss it (e.g. context-dependent flow, "
        "runtime-only reachability).",
        "- If after reconsideration you believe the function is clean, "
        "say so — do not force a finding.",
    ])

    return "\n".join(lines)


def merge_outcomes(original: Any, refined: Any) -> Any:
    """Merge a refined outcome with the original, keeping stronger evidence.

    Rules:
    - If refined has tool-confirmed evidence, use refined
    - If refined promotes from suspicious to finding, use refined
    - If refined demotes from finding to clean, keep original (don't regress)
    - Otherwise use refined
    """
    from .evidence_grade import is_tool_evidence
    refined_tool = getattr(refined, "evidence_tool", "") or ""
    original_tool = getattr(original, "evidence_tool", "") or ""

    if is_tool_evidence(refined_tool):
        return refined

    orig_status = getattr(original, "status", "")
    ref_status = getattr(refined, "status", "")

    if orig_status == "finding" and ref_status == "clean":
        return original

    if orig_status == "suspicious" and ref_status == "finding":
        return refined

    if ref_status == "finding" and not refined_tool and original_tool:
        refined.evidence_tool = original_tool

    return refined


def should_clean_check(
    outcome: Any,
    triage_bucket: str,
    is_entry_point: bool,
    is_sink: bool,
    sloc: int = 0,
) -> bool:
    """Decide whether to run a clean-check sweep.

    Triggers when:
    - Status is clean
    - Triage bucket is deep_dive, OR function is entry point / sink
    - Function has sufficient SLOC
    """
    status = getattr(outcome, "status", "")
    if status != "clean":
        return False

    if sloc > 0 and sloc < MIN_SLOC_CLEAN_CHECK:
        return False

    if triage_bucket == "deep_dive":
        return True

    if is_entry_point or is_sink:
        return True

    return False


def build_clean_check_prompt(
    ctx: Dict[str, Any],
    tool_flows: str,
) -> str:
    """Build the clean-check prompt injected into the review context.

    Tells the LLM it marked the function clean, but the mechanical tool
    found flows it didn't mention. Asks it to reconsider.
    """
    lines = [
        "## Clean-check: tool found flows you did not mention",
        "",
        "You marked this function clean. However, the mechanical tool found:",
        "",
        tool_flows,
        "",
        "Is this flow security-relevant? Could it represent a vulnerability "
        "you missed on first review?",
        "",
        "Answer with a revised assessment. If the flow is benign (e.g. "
        "sanitized before the sink, bounds-checked, or not reachable from "
        "untrusted input), explain why and confirm clean. If it represents "
        "a real issue, revise your status to finding or suspicious.",
    ]

    return "\n".join(lines)


def collect_tool_results(
    outcome: Any,
    evidence_index: Any = None,
) -> List[Dict[str, str]]:
    """Collect tool result summaries for the refinement prompt.

    Gathers what each dispatched tool found (or didn't find) so the
    LLM understands what was checked.
    """
    results: List[Dict[str, str]] = []
    dispatched = getattr(outcome, "tools_dispatched", None) or set()

    key = f"{getattr(outcome, 'file', '')}:{getattr(outcome, 'function', '')}"

    for tool in sorted(dispatched):
        result_text = _describe_tool_result(tool, key, evidence_index)
        results.append({"tool": tool, "result": result_text})

    return results


def _describe_tool_result(
    tool: str,
    key: str,
    evidence_index: Any = None,
) -> str:
    """Describe what a specific tool found for a function."""
    if evidence_index is None:
        return "dispatched but no result captured"

    rec = evidence_index.get(key) if isinstance(evidence_index, dict) else None
    if rec is None:
        return "no evidence record found"

    if tool == "semgrep":
        hits = getattr(rec, "semgrep_hits", None)
        if hits:
            rules = [h.get("rule_id", "?") for h in hits[:3]]
            return f"matched {len(hits)} rule(s): {', '.join(rules)}"
        return "no matches"

    if tool == "coccinelle":
        return "no matches"

    if tool == "codeql":
        alerts = getattr(rec, "codeql_alerts", None)
        if alerts:
            rules = [a.get("rule_id", "?") for a in alerts[:3]]
            return f"found {len(alerts)} alert(s): {', '.join(rules)}"
        return "no alerts for this function"

    if tool == "smt":
        return "dispatched, no confirmation"

    if tool == "joern":
        flows = rec.all_joern_flows() if hasattr(rec, "all_joern_flows") else []
        if flows:
            return f"found {len(flows)} taint flow(s)"
        return "no taint flows found"

    return "dispatched, result not captured"
