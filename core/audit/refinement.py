"""Iterative hypothesis refinement for audit review.

When the sweep is inconclusive (tools dispatched but none confirmed),
feed the tool results back to the LLM for a refined hypothesis.
Max 2 refinement rounds per function.

Also implements clean-check refinement: for high-depth clean verdicts,
run a focused tool sweep and feed any discovered flows back to the LLM.
"""

from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_REFINEMENTS = 2
MIN_SLOC_CLEAN_CHECK = 20


@dataclass
class RefinementContext:
    """Context for a refinement round."""

    prior_hypothesis: str
    prior_status: str
    tool_results: list[dict[str, str]]
    tools_dispatched: set[str]
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
    return not is_tool_evidence(evidence_tool)


def build_refinement_prompt(
    _ctx: dict[str, Any],
    refinement: RefinementContext,
) -> str:
    """Build the refinement section injected into the review context.

    Tells the LLM what it hypothesised, what the tools found, and
    asks it to refine.  Prior-LLM and tool-output free text is
    untrusted — it lands inside the main review prompt, so it is
    wrapped with ``wrap_untrusted`` (per-call nonce, autofetch-markup
    strip, tag-forgery neutralisation): forged envelope tags or
    markdown headings in a poisoned hypothesis / tool result must
    not read as trusted prompt structure.
    """
    from core.security.prompt_envelope import wrap_untrusted

    lines = [
        f"## Refinement round {refinement.round_number}",
        "",
        "Your prior hypothesis:",
        wrap_untrusted(
            refinement.prior_hypothesis,
            kind="prior-hypothesis",
            origin="audit-prior-round",
        ),
        f"Prior verdict: {refinement.prior_status}",
        "",
        f"Tools dispatched: {', '.join(sorted(refinement.tools_dispatched))}",
        "",
    ]

    if refinement.tool_results:
        body = "\n".join(
            f"- **{tr.get('tool', 'unknown')}**: {tr.get('result', 'no output')}"
            for tr in refinement.tool_results
        )
        lines.append("Tool results:")
        lines.append(
            wrap_untrusted(
                body, kind="tool-results", origin="audit-refinement-tools",
            )
        )
        lines.append("")

    if refinement.tool_query_suggestion:
        lines.extend([
            "Your prior suggested check:",
            wrap_untrusted(
                refinement.tool_query_suggestion,
                kind="prior-tool-suggestion",
                origin="audit-prior-round",
            ),
            "",
        ])

    lines.extend([
        "None of the mechanical tools confirmed your hypothesis.",
        "",
        "Refine your hypothesis based on this evidence:",
        ("- If the tool missed an indirect path, specify the intermediate "
         "functions in your revised hypothesis."),
        "- If the tool refuted your hypothesis, try an alternative mechanism.",
        ("- If you believe the hypothesis is correct despite no tool confirmation, "
         "explain why the tools would miss it (e.g. context-dependent flow, "
         "runtime-only reachability)."),
        ("- If after reconsideration you believe the function is clean, "
         "say so — do not force a finding."),
    ])

    return "\n".join(lines)


def merge_outcomes(original: Any, refined: Any) -> Any:
    """Merge a refined outcome with the original, keeping stronger evidence.

    Rules:
    - If refined has tool-confirmed evidence, use refined
    - If refined promotes from suspicious to finding, use refined
    - If refined demotes from finding to clean, keep original (don't regress)
    - Otherwise use refined

    Whichever verdict wins, the surviving outcome carries the SUMMED
    cost / duration / token usage of both rounds. The merge picks a
    verdict, not a bill — replacing the ledger fields silently dropped
    every earlier refinement round's spend from the journal and
    cost-breakdown (one measured run under-reported by $5.27, which
    then surfaced as an unexplained budget death).

    The mechanical dispatch record (tools_dispatched / tools_errored /
    tools_skipped) survives the merge the same way: both rounds
    describe the SAME function, so the union is true whichever verdict
    wins. Dropping it made gate resolution read "no covering channel
    ever ran" (dark) for a function whose tools demonstrably looked —
    and erased the did-not-look skips that keep phantom coverage out
    of class-coverage credit. A channel dispatched in either round did
    look, so it leaves the merged skip set.
    """
    from .evidence_grade import is_tool_evidence
    refined_tool = getattr(refined, "evidence_tool", "") or ""
    original_tool = getattr(original, "evidence_tool", "") or ""

    def _summed(winner: Any) -> Any:
        for attr in (
            "cost_usd", "duration_s", "tokens_in", "tokens_out",
            "cache_read_tokens", "cache_write_tokens",
        ):
            total = (
                (getattr(original, attr, 0) or 0)
                + (getattr(refined, attr, 0) or 0)
            )
            try:
                setattr(winner, attr, total)
            except AttributeError:
                pass  # duck-typed outcome without the field
        merged: dict[str, set] = {}
        for attr in ("tools_dispatched", "tools_errored", "tools_skipped"):
            merged[attr] = (
                set(getattr(original, attr, None) or set())
                | set(getattr(refined, attr, None) or set())
            )
        merged["tools_skipped"] -= merged["tools_dispatched"]
        for attr in ("tools_dispatched", "tools_errored"):
            if merged[attr]:
                try:
                    setattr(winner, attr, merged[attr])
                except AttributeError:
                    pass  # duck-typed outcome without the field
        # tools_skipped is corrected in BOTH directions: a channel the
        # union shows dispatched must also leave the WINNER'S own
        # stale skip set (a channel left in both sets reads as looked
        # AND did-not-look in the journal), so the subtracted set is
        # written whenever either side disagrees — an empty result
        # clears to None, keeping the no-records shape.
        skipped = merged["tools_skipped"]
        if skipped or getattr(winner, "tools_skipped", None):
            try:
                winner.tools_skipped = skipped or None
            except AttributeError:
                pass  # duck-typed outcome without the field
        return winner

    if is_tool_evidence(refined_tool):
        return _summed(refined)

    orig_status = getattr(original, "status", "")
    ref_status = getattr(refined, "status", "")

    if orig_status == "finding" and ref_status == "clean":
        return _summed(original)

    # Carry the original round's evidence stamp forward only when that
    # round's own verdict backed the finding (finding/suspicious). In
    # the clean-check rescue path the original outcome is CLEAN — its
    # tool stamp confirmed nothing, and copying it would let an
    # LLM-only rescue grade as tool-confirmed downstream. The rescue
    # survives either way; only the evidence grade degrades.
    if (
        ref_status == "finding"
        and orig_status in ("finding", "suspicious")
        and not refined_tool
        and original_tool
    ):
        refined.evidence_tool = original_tool

    return _summed(refined)


def clean_check_applicable(
    triage_bucket: str,
    is_entry_point: bool,
    is_sink: bool,
    sloc: int = 0,
) -> bool:
    """The verdict-independent half of the clean-check gate.

    True when the function is in the clean-check population: triage
    bucket deep_dive OR entry point / sink, with sufficient SLOC.
    Shared by the post-verdict rescue (which additionally requires a
    clean status) and the pre-review flow sweep (which runs before
    any verdict exists).
    """
    if sloc > 0 and sloc < MIN_SLOC_CLEAN_CHECK:
        return False

    if triage_bucket == "deep_dive":
        return True

    return bool(is_entry_point or is_sink)


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

    return clean_check_applicable(
        triage_bucket, is_entry_point, is_sink, sloc=sloc,
    )


def build_clean_check_prompt(
    _ctx: dict[str, Any],
    tool_flows: str,
) -> str:
    """Build the clean-check prompt injected into the review context.

    Tells the LLM it marked the function clean, but the mechanical tool
    found flows it didn't mention. Asks it to reconsider.  The flow
    text quotes target identifiers via the tool output, so it is
    defanged with ``neutralize_tag_forgery`` before interpolation.
    """
    from core.security.prompt_envelope import neutralize_tag_forgery

    lines = [
        "## Clean-check: tool found flows you did not mention",
        "",
        "You marked this function clean. However, the mechanical tool found:",
        "",
        neutralize_tag_forgery(tool_flows),
        "",
        ("Is this flow security-relevant? Could it represent a vulnerability "
         "you missed on first review?"),
        "",
        ("Answer with a revised assessment. If the flow is benign (e.g. "
         "sanitized before the sink, bounds-checked, or not reachable from "
         "untrusted input), explain why and confirm clean. If it represents "
         "a real issue, revise your status to finding or suspicious."),
    ]

    return "\n".join(lines)


def build_flow_preview_prompt(tool_flows: str) -> str:
    """Build the pre-review flow-preview section.

    Same mechanical sweep output the post-verdict clean-check rescue
    presents, surfaced in the FIRST review prompt instead — the model
    must address the flows up front rather than being re-asked after a
    clean verdict.  The flow text quotes target identifiers via the
    tool output, so it is defanged with ``neutralize_tag_forgery``
    before interpolation.
    """
    from core.security.prompt_envelope import neutralize_tag_forgery

    lines = [
        "## Mechanical flow sweep",
        "",
        "The mechanical tools found these flows in this function:",
        "",
        neutralize_tag_forgery(tool_flows),
        "",
        ("Address each flow explicitly in your review. If a flow is "
         "benign (e.g. sanitized before the sink, bounds-checked, or "
         "not reachable from untrusted input), say why. If it "
         "represents a real issue, factor it into your hypotheses and "
         "verdict."),
    ]

    return "\n".join(lines)


def collect_tool_results(
    outcome: Any,
    evidence_index: Any = None,
) -> list[dict[str, str]]:
    """Collect tool result summaries for the refinement prompt.

    Gathers what each dispatched tool found (or didn't find) so the
    LLM understands what was checked.
    """
    results: list[dict[str, str]] = []
    dispatched = getattr(outcome, "tools_dispatched", None) or set()

    key = f"{getattr(outcome, 'file', '')}:{getattr(outcome, 'function', '')}"

    for tool in sorted(dispatched):
        result_text = _describe_tool_result(
            tool, key, evidence_index, outcome=outcome,
        )
        results.append({"tool": tool, "result": result_text})

    return results


def _describe_tool_result(
    tool: str,
    key: str,
    evidence_index: Any = None,
    outcome: Any = None,
) -> str:
    """Describe what a specific tool found for a function.

    The description must reflect the outcome's ACTUAL evidence: a
    hardcoded negative ("no matches") that contradicts the confirming
    receipt the verdict carries steers the refinement LLM to walk back
    a tool-confirmed hypothesis.
    """
    # The confirming receipt on the outcome is authoritative — it is
    # the only per-function record for channels the evidence index
    # does not carry (coccinelle, smt).
    receipt = str(getattr(outcome, "evidence_tool", "") or "")
    if receipt == tool or receipt.startswith(f"{tool}:"):
        return f"confirmed the hypothesis ({receipt})"
    if tool in (getattr(outcome, "tools_errored", None) or set()):
        return "errored or timed out — did not meaningfully run"

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

    if tool in ("coccinelle", "smt"):
        # No per-function record in the evidence index for these
        # channels — "ran and found nothing" cannot be claimed, only
        # the absence of a confirming receipt.
        return "dispatched; no confirming output recorded"

    if tool == "codeql":
        alerts = getattr(rec, "codeql_alerts", None)
        if alerts:
            rules = [a.get("rule_id", "?") for a in alerts[:3]]
            return f"found {len(alerts)} alert(s): {', '.join(rules)}"
        return "no alerts for this function"

    if tool == "joern":
        flows = rec.all_joern_flows() if hasattr(rec, "all_joern_flows") else []
        if flows:
            return f"found {len(flows)} taint flow(s)"
        return "no taint flows found"

    return "dispatched, result not captured"


def dispatch_suggestion(
    suggestion: str,
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
) -> list[dict[str, str]]:
    """Dispatch a tool_query_suggestion as a real tool call.

    Parses the free-text suggestion and routes to the appropriate
    mechanical tool. Returns a list of tool results (same format as
    collect_tool_results).
    """
    if not suggestion:
        return []

    results: list[dict[str, str]] = []
    suggestion_lower = suggestion.lower()

    try:
        from .hypothesis_mapping import (
            hypothesis_to_cocci_check,
            hypothesis_to_semgrep_rule_keyed,
            hypothesis_to_smt_verb,
        )

        smt_verb = hypothesis_to_smt_verb(suggestion)
        if smt_verb:
            result = _dispatch_smt(
                smt_verb, suggestion, outcome, ctx, config,
            )
            if result:
                results.append(result)
                return results

        cocci_rule = hypothesis_to_cocci_check(suggestion)
        if cocci_rule:
            result = _dispatch_coccinelle(
                cocci_rule, outcome, ctx, config,
            )
            if result:
                results.append(result)
                return results

        if any(kw in suggestion_lower for kw in (
            "semgrep", "pattern", "rule", "regex",
        )):
            keyed = hypothesis_to_semgrep_rule_keyed(
                suggestion, ctx.get("file", ""),
            )
            if keyed:
                rule_path, rule_keyword = keyed
                try:
                    result = _dispatch_semgrep(
                        rule_path, outcome, ctx, config,
                        rule_keyword=rule_keyword,
                    )
                    if result:
                        results.append(result)
                        return results
                finally:
                    with contextlib.suppress(OSError):
                        os.unlink(rule_path)

    except ImportError:
        logger.debug("hypothesis_mapping import failed", exc_info=True)

    return results


def _dispatch_smt(
    smt_verb: str,
    suggestion: str,
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
) -> dict[str, str] | None:
    """Run an SMT check based on the suggestion."""
    try:
        from .sweep import run_smt_verb_direct

        source = ctx.get("source", "")
        hypothesis = getattr(outcome, "hypothesis", "") or suggestion
        file_path = ctx.get("file", "")

        target = getattr(config, "target_path", None)
        result = run_smt_verb_direct(
            verb=smt_verb,
            source=source,
            hypothesis=hypothesis,
            file_path=file_path,
            function_name=ctx.get("function", ""),
            target_path=str(target) if target else None,
        )
        if result:
            status = result.outcome
            return {
                "tool": f"smt:{smt_verb}",
                "result": f"{status}: {result.raw_output[:200] if result.raw_output else 'no detail'}",
            }
    except Exception:
        logger.debug("SMT dispatch failed", exc_info=True)
    return None


def _dispatch_coccinelle(
    rule_path: str,
    _outcome: Any,
    ctx: dict[str, Any],
    config: Any,
) -> dict[str, str] | None:
    """Run a Coccinelle rule based on the suggestion."""
    try:
        from pathlib import Path

        from .sweep import run_coccinelle_sweep

        target = getattr(config, "target_path", None)
        if not target:
            return None

        file_path = ctx.get("file", "")
        func_name = ctx.get("function", "")
        line_start = ctx.get("line_start", 0)
        line_end = ctx.get("line_end", 0)

        result = run_coccinelle_sweep(
            cocci_rule=rule_path,
            target_path=target,
            file_path=file_path,
            function_name=func_name,
            line_start=line_start,
            line_end=line_end,
        )
        if result:
            return {
                "tool": f"coccinelle:{Path(rule_path).stem}",
                "result": f"{result.outcome}: {len(result.matches)} match(es)",
            }
    except Exception:
        logger.debug("Coccinelle dispatch failed", exc_info=True)
    return None


def _dispatch_semgrep(
    rule_path: str,
    outcome: Any,
    ctx: dict[str, Any],
    config: Any,
    *,
    rule_keyword: str = "",
) -> dict[str, str] | None:
    """Run a Semgrep rule based on the suggestion.

    ``rule_keyword`` and the outcome's hypothesis thread the sweep's
    per-rule caps: without them the negative-control (presence
    detector) and identifier-window checks keyed on them were
    disarmed for every refinement dispatch — a dynamic rule that also
    matches the guarded fixture could 'confirm' here.
    """
    try:
        from pathlib import Path

        from .sweep import run_semgrep_sweep

        target = getattr(config, "target_path", None)
        if not target:
            return None

        file_path = ctx.get("file", "")
        func_name = ctx.get("function", "")
        line_start = ctx.get("line_start", 0)
        line_end = ctx.get("line_end", 0)

        # Same inventory language hint as the main tool-chain lane:
        # without it the suggested-rule re-run silently skipped
        # content-probed unknown-extension files (inconclusive) while
        # the main lane confirmed/refuted them.
        from .orchestrator import _inventory_language_hint
        language = _inventory_language_hint(config, file_path)

        result = run_semgrep_sweep(
            rule_config=rule_path,
            target_path=target,
            file_path=file_path,
            function_name=func_name,
            line_start=line_start,
            line_end=line_end,
            language=language,
            hypothesis=getattr(outcome, "hypothesis", "") or "",
            rule_keyword=rule_keyword,
        )
        if result:
            return {
                "tool": f"semgrep:{Path(rule_path).stem}",
                "result": f"{result.outcome}: {len(result.matches)} match(es)",
            }
    except Exception:
        logger.debug("Semgrep dispatch failed", exc_info=True)
    return None
