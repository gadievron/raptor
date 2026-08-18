"""Graceful degradation for /audit tool availability.

Every optional tool has a fallback.  This module defines the
degradation matrix and provides dispatch helpers that route
to fallback paths when primary tools are unavailable.

The minimum viable audit is LLM + source code + tree-sitter.
Every capability above that is additive — present means better
evidence; absent means the audit still runs with lower confidence.

The triage classifier degrades conservatively: when a signal is
unavailable, assume the function is reachable/present (review more,
skip less).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Fallback:
    """Describes a fallback when a primary tool is unavailable."""

    tool: str
    fallback_tool: str
    impact: str
    fallback_description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "fallback_tool": self.fallback_tool,
            "impact": self.impact,
            "fallback_description": self.fallback_description,
        }


_DEGRADATION_MATRIX: list[Fallback] = [
    Fallback(
        tool="joern",
        fallback_tool="tree-sitter + LLM",
        impact="Higher LLM cost (~70% vs ~20-30% of functions need LLM summaries), "
               "lower summary precision. Cross-file resolution falls back to import-based resolver. "
               "release_order channel: the guard-dominance cross-check leg is skipped — "
               "verdicts carry single-engine (engine=\"cfg\") receipts.",
        fallback_description="tree-sitter for AST extraction, LLM for summaries",
    ),
    Fallback(
        tool="frida",
        fallback_tool="static-only",
        impact="No runtime confirmation. Findings stay at HEURISTIC or XREF_BACKED. "
               "Higher FP rate on negative-space findings.",
        fallback_description="Static-only evidence, no OBSERVED_RUNTIME upgrades",
    ),
    Fallback(
        tool="r2",
        fallback_tool="objdump + grep",
        impact="Lose path-sensitive binary checks (return-value checking, lock/unlock, "
               "canary-per-function). Keep flat checks (gets, format string, dangerous imports).",
        fallback_description="Tier 5 flat patterns via objdump",
    ),
    Fallback(
        tool="binary",
        fallback_tool="source-only",
        impact="Lose binary-derived mechanical intelligence and the "
               "binary oracle. The Layer 0 source-pattern pre-sweep "
               "still runs (it reads source, not binaries).",
        fallback_description="Layers 1-2-3 plus source-pattern Layer 0 "
                             "(no binary-backed evidence)",
    ),
    Fallback(
        tool="semgrep",
        fallback_tool="LLM pattern search",
        impact="Lose cheapest checker synthesis path. Findings from the main "
               "audit loop are unaffected.",
        fallback_description="LLM-based pattern search (more expensive)",
    ),
    Fallback(
        tool="coccinelle",
        fallback_tool="semgrep",
        impact="Lose C-specific semantic matching. Semgrep syntactic patterns "
               "are adequate for most use cases.",
        fallback_description="Semgrep for C syntactic patterns",
    ),
    Fallback(
        tool="codeql",
        fallback_tool="semgrep taint mode",
        impact="Lose CodeQL-quality dataflow. Checker synthesis uses "
               "Semgrep/Coccinelle instead.",
        fallback_description="Semgrep taint mode or Joern for taint confirmation",
    ),
    Fallback(
        tool="ghidra",
        fallback_tool="r2 decompiler",
        impact="If neither available, LLM reviews raw disassembly. "
               "Lower finding quality for binary-only targets.",
        fallback_description="r2 pseudo-C decompilation, or raw disassembly",
    ),
    Fallback(
        tool="dwarf",
        fallback_tool="stack frame inference",
        impact="Layer 0 findings degrade from XREF_BACKED to HEURISTIC for "
               "size-based checks. Function matching degrades to name-only.",
        fallback_description="Infer types from stack frame layout and symbol names",
    ),
    Fallback(
        tool="cxxfilt",
        fallback_tool="mangled names",
        impact="Minor — LLM can parse mangled names, or audit proceeds on "
               "function addresses.",
        fallback_description="Pass mangled symbol names through to LLM",
    ),
    Fallback(
        tool="build_detector",
        fallback_tool="heuristic file scanning",
        impact="Cannot auto-detect build system for compile_commands.json "
               "generation. Joern/CodeQL may miss includes and macros.",
        fallback_description="Scan for Makefile/CMakeLists/meson.build and infer flags",
    ),
    Fallback(
        tool="tree-sitter",
        fallback_tool="ast + line-regex heuristics",
        impact="fail_open channel: Python handler classification is "
               "unaffected (stdlib ast); the C ignored-return and "
               "tri-state legs degrade to line-regex shape matching "
               "with parser=\"regex\" recorded on every receipt — "
               "comparison shapes the regex cannot classify gate to "
               "inconclusive('handler-undecided') rather than guessing; "
               "the Java catch-clause and Go discard/recover legs have "
               "no honest line-shape fallback and report "
               "inconclusive('language-unsupported'). "
               "consistency channel: the return census keeps its coarse "
               "regex classes (no read-scan, no acknowledged/tested "
               "split beyond line shapes); the flag/mode and cleanup "
               "comparators need trees and report "
               "inconclusive('extractor-unavailable') / detect nothing. "
               "field census: regex-tier records only — verdicts that "
               "need rhs provenance gate to "
               "inconclusive('census-incomplete') (ptr_lifecycle "
               "refuses to guess alias edges; the field-parity leg "
               "detects nothing). "
               "resource_bounds channel: the bound-witness comparator "
               "needs the CFG/dominator walk and reports "
               "inconclusive('census-degraded') rather than confirming "
               "a no-bound claim without the guard walk. release_order "
               "channel: dominance needs the CFG and reports "
               "inconclusive('cfg-unavailable'). protocol_state "
               "channel: a violable site without the CFG guard leg "
               "reports inconclusive('census-degraded') — never a "
               "confirmation on a partial census.",
        fallback_description="ast for Python handlers, line-regex for "
                             "C call-site shapes and the coarse census",
    ),
    Fallback(
        tool="z3",
        fallback_tool="none (verdict-honest degradation)",
        impact="smt_invariant channel: invariant preservation reports "
               "inconclusive('z3 unavailable'). protocol_state "
               "channel: leg 3 (census-driven multi-site invariant "
               "harness) reports inconclusive('z3-unavailable'); the "
               "legs-1+2 lead receipts (dead-state, unvalidated "
               "peer-write) still emit — they are census facts, not "
               "SMT verdicts.",
        fallback_description="pip install z3-solver restores the "
                             "invariant channels",
    ),
]

_FALLBACK_BY_TOOL = {f.tool: f for f in _DEGRADATION_MATRIX}


def get_fallback(tool: str) -> Fallback | None:
    return _FALLBACK_BY_TOOL.get(tool.lower())


@dataclass
class DegradationReport:
    """Tracks which tools are available and which degraded."""

    available: list[str] = field(default_factory=list)
    degraded: list[Fallback] = field(default_factory=list)
    unavailable_no_fallback: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "degraded": [f.to_dict() for f in self.degraded],
            "unavailable_no_fallback": self.unavailable_no_fallback,
        }


def assess_degradation(
    capabilities: dict[str, bool],
) -> DegradationReport:
    """Assess which tools are available and which need fallbacks.

    Takes the capabilities dict from AuditCapabilities.to_dict()
    and produces a degradation report.
    """
    report = DegradationReport()

    for tool, is_available in capabilities.items():
        if is_available:
            report.available.append(tool)
            continue

        fallback = get_fallback(tool)
        if fallback is not None:
            report.degraded.append(fallback)
        else:
            report.unavailable_no_fallback.append(tool)

    return report


def format_degradation_report(report: DegradationReport) -> str:
    """Format degradation assessment for the operator."""
    lines = []

    if report.available:
        lines.append(f"Available: {', '.join(sorted(report.available))}")

    if report.degraded:
        lines.append("")
        lines.append("Degraded (fallback active):")
        for fb in report.degraded:
            lines.append(f"  {fb.tool} → {fb.fallback_tool}")
            lines.append(f"    Impact: {fb.impact}")

    if report.unavailable_no_fallback:
        lines.append("")
        lines.append(
            f"Unavailable (no fallback): "
            f"{', '.join(sorted(report.unavailable_no_fallback))}"
        )

    return "\n".join(lines)


def format_capabilities_table(
    capabilities: dict[str, bool],
) -> str:
    """Format capabilities as a markdown table for the audit report."""
    lines = [
        "| Tool | Available | Fallback |",
        "|---|---|---|",
    ]
    for tool in sorted(capabilities):
        avail = "Yes" if capabilities[tool] else "No"
        fallback = ""
        if not capabilities[tool]:
            fb = get_fallback(tool)
            if fb:
                fallback = fb.fallback_tool
            else:
                fallback = "none"
        lines.append(f"| {tool} | {avail} | {fallback} |")
    return "\n".join(lines)


# ── Triage signal degradation ─────────────────────────────────────

@dataclass(frozen=True)
class TriageSignalAvailability:
    """Which triage signals are available for function classification."""

    joern_reachability: bool = False
    binary_oracle: bool = False
    layer0_findings: bool = False
    complexity_metrics: bool = True

    def conservative_defaults(self) -> dict[str, bool]:
        """When a signal is unavailable, return the conservative default.

        Conservative = assume reachable/present (review more, not less).
        """
        return {
            "on_reachable_path": True if not self.joern_reachability else None,
            "binary_present": True if not self.binary_oracle else None,
        }

    def summary(self) -> str:
        signals = {
            "Joern reachability": self.joern_reachability,
            "Binary oracle": self.binary_oracle,
            "Layer 0": self.layer0_findings,
            "Complexity": self.complexity_metrics,
        }
        available = [k for k, v in signals.items() if v]
        missing = [k for k, v in signals.items() if not v]

        parts = []
        if available:
            parts.append(f"Available: {', '.join(available)}")
        if missing:
            parts.append(
                f"Missing (conservative defaults): {', '.join(missing)}"
            )
        return "; ".join(parts)
