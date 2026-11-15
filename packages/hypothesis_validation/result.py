"""Hypothesis verdict labels and their recorded tool observations.

The runner combines a model evaluation with mechanical downgrade rules:
failed or incomplete tool runs remain inconclusive, and match presence
constrains which claims can be accepted. Definitive SMT directions follow
the hypothesis's declared polarity over the supplied predicates.

These labels retain the scope of the rule, query or predicate model that
produced them. Source-backed promotion and refutation require the consuming
pipeline's admission and evidence checks.

Each evidence record stores the adapter name, rule text, summary, matches,
execution status and optional hypothesis reference. Reproducing an invocation
also requires the target content and tool configuration from its owning run.
"""

from dataclasses import dataclass, field
from typing import Literal

from .provenance import ensure_same_provenance

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

    matches: list[dict] = field(default_factory=list)
    """Tool-specific match details. Schema varies by tool — callers should
    consult the originating adapter's documentation for fields."""

    success: bool = True
    """Whether the tool ran successfully. False indicates the rule failed
    to compile, the tool errored, or timed out."""

    error: str = ""
    """Error message when success=False."""

    empty_matches_conclusive: bool = False
    """Adapter assertion that a clean run with no matches is itself a
    definitive tool result (e.g. SMT unsat proving infeasibility) rather
    than mere absence of evidence. Consulted by the verdict ladder before
    downgrading a confirmed claim with no matches to refuted."""

    refers_to: str = ""
    """Stable hash of the hypothesis this evidence was produced for.
    Empty string means "unknown" (e.g. evidence built before provenance
    tracking was wired up). The runner refuses to combine evidence whose
    non-empty `refers_to` values differ — see `provenance.py`."""

    predicate_verdict: str = ""
    """Definitive supplied-predicate SMT result (``sat``/``unsat``).
    This records mathematical feasibility, not source execution."""

    def to_dict(self) -> dict:
        d = {
            "tool": self.tool,
            "rule": self.rule,
            "summary": self.summary,
            "matches": list(self.matches),
            "success": self.success,
            "error": self.error,
        }
        # Only emit refers_to / empty_matches_conclusive when populated,
        # so the legacy serialized shape stays untouched for callers
        # that don't set them.
        if self.refers_to:
            d["refers_to"] = self.refers_to
        if self.empty_matches_conclusive:
            d["empty_matches_conclusive"] = True
        if self.predicate_verdict:
            d["predicate_verdict"] = self.predicate_verdict
        return d


@dataclass
class ValidationResult:
    """The result of validating a hypothesis.

    The owning pipeline interprets these labels under its evidence policy.
    Inconclusive retains failed, incomplete or ambiguous analysis for review.
    Recorded matches and model results keep their original scope.
    """

    verdict: Verdict
    """Final ruling derived from evidence."""

    evidence: list[Evidence] = field(default_factory=list)
    """All tool runs for this hypothesis, including refutations and errors.
    Auditable record of what was tested and how."""

    iterations: int = 1
    """Number of LLM↔tool round-trips. 1 = single-shot, no refinement."""

    reasoning: str = ""
    """Optional final LLM reasoning explaining how the verdict was reached.
    Captures any nuance the structured fields miss."""

    def __post_init__(self) -> None:
        ensure_same_provenance(self.evidence)

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
    def supporting_evidence(self) -> list[Evidence]:
        """Evidence items consistent with the hypothesis (success + matches present)."""
        return [e for e in self.evidence if e.success and e.matches]

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "evidence": [e.to_dict() for e in self.evidence],
            "iterations": self.iterations,
            "reasoning": self.reasoning,
        }
