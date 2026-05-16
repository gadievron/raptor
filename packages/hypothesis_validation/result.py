"""Validation result — the runner's verdict on a hypothesis.

Verdicts are NOT LLM opinions; they are derived from tool evidence:

  confirmed   — at least one tool produced concrete evidence (file/line
                matches, dataflow path, satisfiable constraint) consistent
                with the hypothesis claim.
  refuted     — tool ran successfully but produced no evidence supporting
                the hypothesis (and at least one tool was applicable).
  inconclusive — no applicable tool, all tools failed, or evidence was
                ambiguous. The runner does NOT downgrade to "refuted" in
                this case — absence of mechanical evidence is not absence
                of bug.

Verdicts are auditable: every evidence item records the exact tool
invocation (rule text, command, target) and tool output. A reviewer can
re-run any invocation to verify.
"""

from dataclasses import dataclass, field
from typing import List, Literal


Verdict = Literal["confirmed", "refuted", "inconclusive"]


@dataclass
class Evidence:
    """A single piece of evidence from one tool invocation.

    Multiple evidence items can support a single hypothesis (different
    tools, different rules, different match locations).
    """

    tool: str
    """Name of the adapter that produced this evidence (e.g. "coccinelle")."""

    rule: str
    """The rule text or query that the LLM generated and the tool ran."""

    summary: str
    """Human-readable summary (e.g. "3 matches in 2 files")."""

    matches: List[dict] = field(default_factory=list)
    """Tool-specific match details. Schema varies by tool — callers should
    consult the originating adapter's documentation for fields."""

    success: bool = True
    """Whether the tool ran successfully. False indicates the rule failed
    to compile, the tool errored, or timed out."""

    error: str = ""
    """Error message when success=False."""

    refers_to: str = ""
    """Stable hash of the hypothesis this evidence was produced for.
    Empty string means "unknown" (e.g. evidence built before provenance
    tracking was wired up). The runner refuses to combine evidence whose
    non-empty `refers_to` values differ — see `provenance.py`."""

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool,
            "rule": self.rule,
            "summary": self.summary,
            "matches": list(self.matches),
            "success": self.success,
            "error": self.error,
        }
        # Only emit refers_to when populated, so the legacy serialized
        # shape stays untouched for callers that don't set it.
        if self.refers_to:
            d["refers_to"] = self.refers_to
        return d


@dataclass
class ValidationResult:
    """The result of validating a hypothesis.

    A confirmed hypothesis becomes a finding with concrete tool evidence.
    A refuted hypothesis is discarded. Inconclusive hypotheses are
    annotated as "requires manual review" — they do not become findings,
    but neither are they marked clean.
    """

    verdict: Verdict
    """Final ruling derived from evidence."""

    evidence: List[Evidence] = field(default_factory=list)
    """All tool runs for this hypothesis, including refutations and errors.
    Auditable record of what was tested and how."""

    iterations: int = 1
    """Number of LLM↔tool round-trips. 1 = single-shot, no refinement."""

    reasoning: str = ""
    """Optional final LLM reasoning explaining how the verdict was reached.
    Captures any nuance the structured fields miss."""

    @property
    def confirmed(self) -> bool:
        return self.verdict == "confirmed"

    @property
    def refuted(self) -> bool:
        return self.verdict == "refuted"

    @property
    def inconclusive(self) -> bool:
        return self.verdict == "inconclusive"

    @property
    def supporting_evidence(self) -> List[Evidence]:
        """Evidence items consistent with the hypothesis (success + matches present)."""
        return [e for e in self.evidence if e.success and e.matches]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "evidence": [e.to_dict() for e in self.evidence],
            "iterations": self.iterations,
            "reasoning": self.reasoning,
        }
