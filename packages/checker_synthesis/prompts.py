"""Prompt templates for checker synthesis + match triage.

Two LLM tasks live here:

  * ``synthesis`` — given a confirmed bug, produce a checker rule.
  * ``triage``    — given a candidate match from running that rule,
                    classify it as variant / false_positive / uncertain.

Both produce structured JSON responses validated against schemas
defined in this module. The schemas double as in-prompt
documentation — the LLM sees them, so the output shape is explicit.
"""

from __future__ import annotations

from typing import Any, Dict

from .models import SeedBug, SynthesisedRule, Match


# Cap on ``seed.snippet`` going into the synthesis prompt. A huge
# snippet doesn't help the LLM derive a structural pattern — the
# function's shape, sources/sinks, and missing checks are what
# matter — and bloats prompt cost. Mirrors the constant in
# ``synthesise.py`` so both sites stay in sync.
_SEED_SNIPPET_MAX_BYTES = 8_192


def _truncate_snippet(snippet: str) -> str:
    """Cap ``snippet`` at ``_SEED_SNIPPET_MAX_BYTES`` UTF-8 bytes.
    When truncated, append a marker so the LLM knows it's incomplete."""
    encoded = snippet.encode("utf-8")
    if len(encoded) <= _SEED_SNIPPET_MAX_BYTES:
        return snippet
    truncated = encoded[:_SEED_SNIPPET_MAX_BYTES].decode(
        "utf-8", errors="ignore",
    )
    return truncated + "\n... (snippet truncated)"


# ---------------------------------------------------------------------------
# Synthesis
# ---------------------------------------------------------------------------


SYNTHESIS_SYSTEM = (
    "You are a security analyst translating a confirmed code-level bug "
    "into a static analysis rule. The rule must:\n"
    "  1. Match the original bug's pattern (positive control).\n"
    "  2. Be tight enough that running it across the codebase surfaces "
    "VARIANTS of the same bug class — not every superficially similar "
    "construct.\n"
    "  3. Be syntactically valid for the chosen engine (Semgrep YAML "
    "or Coccinelle .cocci).\n\n"
    "Avoid rules that match every call to a common API (e.g. every "
    "``subprocess.run``). Match the structural shape that makes the "
    "ORIGINAL bug unsafe — typically the absence of a check, the use "
    "of a tainted value at a sink, or a missing cleanup."
)


SYNTHESIS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["rule_body", "rationale"],
    "properties": {
        "rule_body": {
            "type": "string",
            "description": (
                "The complete rule text — Semgrep YAML or Coccinelle "
                ".cocci syntax depending on engine. Must be valid as "
                "written (no placeholders, no '...' literals as code)."
            ),
        },
        "rationale": {
            "type": "string",
            "description": (
                "One paragraph explaining what structural pattern this "
                "rule captures and why a variant matching this rule is "
                "likely to be the same bug class."
            ),
        },
    },
}


def build_synthesis_prompt(
    seed: SeedBug, engine: str,
    retry_feedback: str = "",
    prior_fps: "Iterable[Match]" = (),
) -> str:
    """Compose the synthesis prompt body.

    ``retry_feedback`` is non-empty on a retry — it carries the
    failure mode of the previous attempt (e.g. "rule did not match
    the seed function" or "rule produced invalid YAML") so the LLM
    can refine rather than regenerate from scratch.

    ``prior_fps`` is non-empty during the iterative FP-elimination
    loop — it carries matches from previous iterations that
    triage classified as false positives. The synthesis prompt
    appends them as negative examples so the next rule tightens
    away from those locations while still hitting the seed bug.
    """
    parts = [
        f"BUG TO REPLICATE AS A CHECKER ({engine})",
        "",
        f"File:     {seed.file}",
        f"Function: {seed.function}",
        f"Lines:    {seed.line_start}–{seed.line_end}",
        f"CWE:      {seed.cwe}",
        "",
        "Reasoning from the original analysis:",
        seed.reasoning.strip() or "(no reasoning provided)",
    ]
    if seed.snippet:
        parts += [
            "",
            "Source of the buggy function:",
            "```",
            _truncate_snippet(seed.snippet).rstrip(),
            "```",
        ]
    parts += [
        "",
        "TASK:",
        f"Output a {engine} rule that:",
        "  1. Matches the original bug at the lines above.",
        "  2. Captures the structural shape, not the exact text — so "
        "running it across the codebase finds variants that share the "
        "same flaw.",
        "  3. Is tight enough to avoid mass false positives. If your "
        "first instinct is a single ``pattern: foo(...)`` that would "
        "match every call to ``foo``, refine it.",
        "",
        "Respond with JSON: {\"rule_body\": \"...\", \"rationale\": \"...\"}.",
    ]
    if retry_feedback:
        parts += [
            "",
            "RETRY — the previous attempt failed:",
            retry_feedback,
            "Refine the rule, don't regenerate from scratch.",
        ]
    fps = list(prior_fps) if prior_fps else []
    if fps:
        parts += [
            "",
            "PRIOR FALSE POSITIVES — earlier rules matched the "
            "following locations that triage classified as NOT the "
            "same bug. Refine your rule to AVOID matching these "
            "while still hitting the seed at the lines above:",
        ]
        # Cap the per-prompt FP context to avoid context blow-up.
        # 8 examples × ~200 chars each ≈ 1.6KB — enough signal,
        # bounded cost.
        for fp in fps[:8]:
            line = f"  - {fp.file}:{fp.line}"
            if fp.snippet:
                # Trim the snippet so context stays bounded.
                snip = " ".join(fp.snippet.split())[:160]
                line += f"\n      {snip}"
            parts.append(line)
        if len(fps) > 8:
            parts.append(
                f"  ... ({len(fps) - 8} more false positives elided)"
            )
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------


TRIAGE_SYSTEM = (
    "You are evaluating whether a candidate match is the same bug "
    "class as the seed bug, or a false positive of the synthesised "
    "rule. Be strict: 'variant' requires the same underlying flaw, "
    "not just superficial syntactic similarity. When the snippet "
    "lacks context to decide confidently, return 'uncertain' rather "
    "than guessing."
)


TRIAGE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "required": ["status", "reasoning"],
    "properties": {
        "status": {
            "type": "string",
            "enum": ["variant", "false_positive", "uncertain"],
        },
        "reasoning": {
            "type": "string",
            "description": "One short paragraph justifying the verdict.",
        },
    },
}


def build_triage_prompt(
    seed: SeedBug, rule: SynthesisedRule, match: Match,
) -> str:
    """Compose the triage prompt for one candidate match."""
    parts = [
        f"SEED BUG (the confirmed instance, used as ground truth):",
        f"  File:     {seed.file}",
        f"  Function: {seed.function}",
        f"  Lines:    {seed.line_start}–{seed.line_end}",
        f"  CWE:      {seed.cwe}",
        f"  Reasoning: {seed.reasoning.strip() or '(none)'}",
        "",
        f"SYNTHESISED RULE ({rule.engine}, id={rule.rule_id}):",
        f"  Rationale: {rule.rationale or '(none)'}",
        "",
        "CANDIDATE MATCH (rule fired here, same bug or false positive?):",
        f"  File: {match.file}",
        f"  Line: {match.line}",
    ]
    if match.snippet:
        parts += [
            "  Snippet:",
            "  ```",
            "  " + match.snippet.rstrip().replace("\n", "\n  "),
            "  ```",
        ]
    parts += [
        "",
        "TASK: classify this match.",
        "  * variant         — same underlying flaw as the seed bug.",
        "  * false_positive  — the rule matched but the code is safe.",
        "  * uncertain       — not enough context to decide.",
        "",
        "Respond with JSON: "
        "{\"status\": \"variant|false_positive|uncertain\", "
        "\"reasoning\": \"...\"}.",
    ]
    return "\n".join(parts)
