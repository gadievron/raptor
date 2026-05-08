"""Dataclasses for the checker-synthesis pipeline.

Kept simple and serialisable so ``/audit`` can persist
synthesis attempts as JSON alongside its annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


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


@dataclass(frozen=True)
class Match:
    """One cross-codebase hit from running a synthesised rule."""

    file: str  # repo-relative
    line: int
    snippet: str = ""  # the matched code fragment, when the engine provides it
    metavars: Dict[str, str] = field(default_factory=dict)


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
      * ``capped`` — True when the match count exceeded
        ``max_matches`` and the result was truncated.
      * ``errors`` — best-effort log of failures along the way (rule
        synthesis errors, run errors, triage failures).
    """

    seed: SeedBug
    rule: Optional[SynthesisedRule] = None
    rule_path: Optional[Path] = None
    positive_control: bool = False
    matches: List[Match] = field(default_factory=list)
    triage: List[MatchTriage] = field(default_factory=list)
    capped: bool = False
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view for persistence next to annotations."""
        return {
            "seed": {
                "file": self.seed.file,
                "function": self.seed.function,
                "line_start": self.seed.line_start,
                "line_end": self.seed.line_end,
                "cwe": self.seed.cwe,
                "reasoning": self.seed.reasoning,
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
