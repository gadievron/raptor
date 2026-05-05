"""Iteration progress guard — standalone, not yet wired in.

A future iteration loop wants a precondition: each refinement step must
strictly reduce uncertainty before another LLM call is permitted. The
IEEE-ISTAS 2025 result PR #309 cites — 37.6% more critical findings
after five rounds of pure self-critique — is exactly the failure mode
this guard prevents. A "refine" that does not strictly progress is
rejected before any tool runs; a loop that cannot progress terminates
by construction.

Two pieces, both standalone (no runner wiring yet):

    IterationStep                      one round of (hypothesis, evidence)
    must_progress(prev, curr)          raise IterationStalled if not strict

`uncertainty` is the metric the guard checks. We define it as the count
of evidence items that are *not yet conclusive* — tool failures plus
clean-but-no-match results that the LLM has not yet ruled on. Strict
progress means this count must go down between steps. The metric is
deliberately coarse for now; a future revision can swap it for a real
entropy measure once the evidence schema stabilises.
"""

from dataclasses import dataclass, field
from typing import List

from .hypothesis import Hypothesis
from .result import Evidence


class IterationStalled(RuntimeError):
    """Raised by `must_progress` when an iteration would not progress."""


@dataclass
class IterationStep:
    """One round of the LLM↔tool loop.

    Plain dataclass — no validators, no Pydantic. The runner that owns
    iteration enforces invariants externally (via `must_progress`).
    """

    hypothesis: Hypothesis
    evidence: List[Evidence] = field(default_factory=list)


def uncertainty(step: IterationStep) -> int:
    """How many evidence items remain unresolved.

    Counts evidence that did not produce a clean answer:
      - tool failures (success=False)
      - tool ran but produced no matches (the runner falls back to LLM
        opinion here, so it's only "resolved" once the LLM has spoken;
        for the purposes of this metric we count it as residual
        uncertainty until then)

    A future revision that tracks per-evidence verdicts can refine this
    to count items still pending evaluation rather than items missing
    matches. Today's coarse metric is enough to make `must_progress`
    enforce monotonicity without committing to a particular shape.
    """
    n = 0
    for e in step.evidence:
        if not getattr(e, "success", True):
            n += 1
            continue
        if not getattr(e, "matches", []):
            n += 1
    return n


def must_progress(prev: IterationStep, curr: IterationStep) -> None:
    """Hoare postcondition: uncertainty must strictly decrease.

    Two conditions, both required:
      1. The hypothesis itself must change (no rerunning the same claim
         and calling it a refinement).
      2. Uncertainty must strictly decrease (more grounded evidence
         than before — a refine that adds no new conclusive evidence is
         rejected before any tool runs).

    Raises IterationStalled with a specific reason on either failure.
    The caller is responsible for halting the loop on the exception;
    this function is intentionally side-effect-free apart from raising.
    """
    if curr.hypothesis == prev.hypothesis:
        raise IterationStalled("refinement produced an identical hypothesis")
    prev_u = uncertainty(prev)
    curr_u = uncertainty(curr)
    if curr_u >= prev_u:
        raise IterationStalled(
            f"uncertainty did not strictly decrease "
            f"(prev={prev_u}, curr={curr_u})"
        )


__all__ = [
    "IterationStep",
    "IterationStalled",
    "uncertainty",
    "must_progress",
]
