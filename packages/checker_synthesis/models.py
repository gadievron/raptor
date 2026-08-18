"""Dataclasses for the checker-synthesis pipeline.

Kept simple and serialisable so ``/audit`` can persist
synthesis attempts as JSON alongside its annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Synthesis verdict for an individual cross-codebase match. Mirrors
# the annotation status enum where it makes sense, but adds
# ``uncertain`` for cases the LLM can't classify confidently.
TRIAGE_STATUSES = ("variant", "false_positive", "uncertain", "skipped")


@dataclass(frozen=True)
class SeedBug:
    """The confirmed bug that seeds a synthesis attempt.

    ``reasoning`` is the LLM's prose from the original analysis —
    what makes this code buggy, the assumption being violated, the
    operation that's unsafe. The synthesis prompt uses it to derive
    the rule's structural pattern.
    """

    file: str  # repo-relative path
    function: str
    line_start: int
    line_end: int
    cwe: str
    reasoning: str
    snippet: str = ""  # function source text; populated when available
    # Where the seed came from: "" (legacy in-run outcome),
    # "journal:<run>", "crash:<id>", "cvefix:<cve>", ... Rides into
    # to_dict() so persisted synthesis results are auditable.
    provenance: str = ""


@dataclass(frozen=True)
class SynthesisedRule:
    """One LLM-proposed checker rule.

    ``engine`` is ``"semgrep"`` or ``"coccinelle"``. The rule body
    is the verbatim text the LLM produced. ``rule_id`` is a stable
    identifier used in filenames + log lines; derived from the seed
    bug's location + a sequence number.
    """

    engine: str
    rule_id: str
    body: str
    rationale: str = ""  # LLM's explanation of what the rule looks for
    test_positive: str = ""  # minimal vulnerable snippet the rule must match
    test_negative: str = ""  # minimal safe snippet the rule must NOT match
    # Minimal guard-insertion fix for the seed's line range.  Applied
    # mechanically to a COPY of the seed file for the fix-mutant
    # control: the rule must stop matching once the guard is in place.
    fix_patch: str = ""


@dataclass(frozen=True)
class Match:
    """One cross-codebase hit from running a synthesised rule."""

    file: str  # repo-relative
    line: int
    snippet: str = ""  # the matched code fragment, when the engine provides it
    metavars: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchTriage:
    """Per-match LLM verdict from the optional triage pass."""

    match: Match
    status: str  # one of TRIAGE_STATUSES
    reasoning: str = ""


@dataclass
class CheckerSynthesisResult:
    """Top-level output of ``synthesise_and_run``.

    Fields:
      * ``seed`` — the input bug that seeded the run.
      * ``rule`` — the LLM's final proposed rule, or None if synthesis
        failed entirely (positive control never satisfied, syntax
        error, LLM unavailable).
      * ``rule_path`` — where ``rule.body`` was written on disk.
      * ``positive_control`` — did the rule match the seed bug? Always
        True for results where ``rule`` is not None (we retry / give
        up before returning a bad rule).
      * ``matches`` — cross-codebase matches found by the rule.
      * ``triage`` — optional LLM verdicts per match, in match order.
      * ``fix_mutant_control`` — mechanical fix-mutant gate verdict:
        True (patched seed no longer matches), False (rule cannot
        distinguish fixed from unfixed code), None (patch missing or
        failed to apply — fail-closed).
      * ``rule_tier`` — ``"library"`` when every mechanical control
        (positive, dual, fix-mutant) passed and the rule may be
        promoted into the persistent library; ``"sweep_once"`` when
        the rule may only be used for this run's codebase sweep.
      * ``capped`` — True when the match count exceeded
        ``max_matches`` and the result was truncated.
      * ``errors`` — best-effort log of failures along the way (rule
        synthesis errors, run errors, triage failures).
    """

    seed: SeedBug
    rule: SynthesisedRule | None = None
    rule_path: Path | None = None
    positive_control: bool = False
    dual_control: bool = False
    fix_mutant_control: bool | None = None
    rule_tier: str = "sweep_once"
    matches: list[Match] = field(default_factory=list)
    triage: list[MatchTriage] = field(default_factory=list)
    capped: bool = False
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable view for persistence next to annotations."""
        return {
            "seed": {
                "file": self.seed.file,
                "function": self.seed.function,
                "line_start": self.seed.line_start,
                "line_end": self.seed.line_end,
                "cwe": self.seed.cwe,
                "reasoning": self.seed.reasoning,
                "provenance": self.seed.provenance,
            },
            "rule": (
                None if self.rule is None
                else {
                    "engine": self.rule.engine,
                    "rule_id": self.rule.rule_id,
                    "body": self.rule.body,
                    "rationale": self.rule.rationale,
                }
            ),
            "rule_path": str(self.rule_path) if self.rule_path else None,
            "positive_control": self.positive_control,
            "dual_control": self.dual_control,
            "fix_mutant_control": self.fix_mutant_control,
            "rule_tier": self.rule_tier,
            "matches": [
                {
                    "file": m.file, "line": m.line,
                    "snippet": m.snippet, "metavars": dict(m.metavars),
                }
                for m in self.matches
            ],
            "triage": [
                {
                    "match": {
                        "file": t.match.file, "line": t.match.line,
                        "snippet": t.match.snippet,
                    },
                    "status": t.status,
                    "reasoning": t.reasoning,
                }
                for t in self.triage
            ],
            "capped": self.capped,
            "errors": list(self.errors),
        }
