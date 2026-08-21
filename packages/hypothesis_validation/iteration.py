"""Iteration progress guard for the hypothesis validation loop.

Each refinement step must strictly reduce uncertainty before another LLM
call is permitted.  The IEEE-ISTAS 2025 result PR #309 cites — 37.6%
more critical findings after five rounds of pure self-critique — is
exactly the failure mode this guard prevents.  A "refine" that does not
strictly progress is rejected before any tool runs; a loop that cannot
progress terminates by construction.

Wired into ``runner.validate()`` — called between consecutive
LLM-tool round-trips.

    IterationStep                      one round of (hypothesis, evidence)
    must_progress(prev, curr)          raise IterationStalled if not strict

`uncertainty` counts evidence items that are *not yet conclusive* —
tool failures plus clean-but-no-match results that the LLM has not yet
ruled on. The guard itself checks `resolved_fraction` (resolved items
over total items): the runner passes cumulative evidence per step, so
an absolute count can only grow while the fraction rises exactly when
a round contributes conclusive evidence. Strict progress means the
fraction must go up between steps. The metric is deliberately coarse
for now; a future revision can swap it for a real entropy measure once
the evidence schema stabilises.
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


def resolved_fraction(step: IterationStep) -> float:
    """Fraction of the step's evidence that is resolved.

    Complements :func:`uncertainty`: where ``uncertainty`` counts
    unresolved items in absolute terms, the fraction normalises by the
    evidence count. That matters because the runner builds each step
    from the CUMULATIVE evidence of all rounds so far — an absolute
    count over a growing superset can never decrease, but the fraction
    increases exactly when the fresh round contributed conclusive
    evidence. An empty step has nothing resolved (0.0).
    """
    if not step.evidence:
        return 0.0
    unresolved = uncertainty(step)
    return (len(step.evidence) - unresolved) / len(step.evidence)


def must_progress(prev: IterationStep, curr: IterationStep) -> None:
    """Hoare postcondition: uncertainty must strictly decrease.

    Two conditions, both required:
      1. The hypothesis itself must change (no rerunning the same claim
         and calling it a refinement).
      2. The resolved fraction of the evidence must strictly increase.
         Pre-fix this compared absolute ``uncertainty`` counts — but
         the runner passes cumulative evidence (each round's step is a
         superset of the previous round's), so the unresolved count
         could never go down and the guard stalled every loop at round
         two regardless of real progress. The fraction is stable under
         superset growth: it rises iff the new round's evidence is
         more conclusive than the running average.

    Raises IterationStalled with a specific reason on either failure.
    The caller is responsible for halting the loop on the exception;
    this function is intentionally side-effect-free apart from raising.
    """
    if curr.hypothesis == prev.hypothesis:
        raise IterationStalled("refinement produced an identical hypothesis")
    prev_f = resolved_fraction(prev)
    curr_f = resolved_fraction(curr)
    if curr_f <= prev_f:
        raise IterationStalled(
            f"uncertainty did not strictly decrease "
            f"(resolved fraction prev={prev_f:.2f}, curr={curr_f:.2f})"
        )


__all__ = [
    "IterationStep",
    "IterationStalled",
    "uncertainty",
    "resolved_fraction",
    "must_progress",
]
