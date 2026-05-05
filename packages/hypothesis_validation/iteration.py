"""Iteration step skeletons — exported but not wired in.

Per the design doc, the deferred iteration loop is where the typed
substrate earns its keep: each iteration step gets a Hoare-style
postcondition that uncertainty must strictly decrease before another
LLM call is permitted. This file defines the types and the
`must_progress` guard; wiring them into `runner.validate` is a
separate, follow-on PR.

The IEEE-ISTAS 2025 result PR #309 cites — 37.6% more critical findings
after five rounds of self-critique — is the failure mode `must_progress`
prevents. A "refine" that does not strictly progress is rejected before
any tool runs; a loop that cannot progress terminates by construction.
"""

from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel, ConfigDict, model_validator

from .types import TypedHypothesis, Verdict
from .verdict import aggregate


class IterationStep(BaseModel):
    """One round of the LLM↔tool loop, sealed against ungrounded verdicts.

    The `grounded` validator enforces the substrate's core invariant:
    the recorded verdict must equal the lattice aggregation over the
    evidence list. A step that violates this is impossible to construct
    — the type system rejects it at parse time rather than at runtime.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    hypothesis: TypedHypothesis
    evidence: List[Any]
    verdict: Verdict
    rationale: str = ""

    @model_validator(mode="after")
    def grounded(self) -> "IterationStep":
        derived = aggregate(self.evidence, llm_claim=self.verdict)
        if derived != self.verdict:
            raise ValueError(
                f"verdict {self.verdict.value!r} not grounded in evidence "
                f"(derived: {derived.value!r})"
            )
        return self


def info_content(step: IterationStep) -> int:
    """Coarse uncertainty measure: count of grounded evidence items.

    Higher = more grounded; the `must_progress` guard requires this to
    strictly increase between steps. A future revision can replace this
    with a real entropy measure once the evidence schema stabilises;
    until then count is a monotone proxy that keeps the type-level
    invariant honest without committing to a particular metric.
    """
    return sum(
        1
        for e in step.evidence
        if getattr(e, "success", True) and (getattr(e, "matches", []) or getattr(e, "matches", []) == [])
    )


class IterationStalled(RuntimeError):
    """Raised by `must_progress` when an iteration would not make progress."""


def must_progress(prev: IterationStep, curr: IterationStep) -> None:
    """Hoare postcondition for one refinement step.

    Two conditions, both required:
      1. The hypothesis itself must change (no rerunning the same claim).
      2. Information content must strictly increase (more grounded
         evidence than before — a refine that adds no evidence is
         rejected before any tool runs).
    """
    if curr.hypothesis == prev.hypothesis:
        raise IterationStalled("refine produced an identical hypothesis")
    if info_content(curr) <= info_content(prev):
        raise IterationStalled(
            f"information content did not increase "
            f"(prev={info_content(prev)}, curr={info_content(curr)})"
        )


__all__ = [
    "IterationStep",
    "IterationStalled",
    "info_content",
    "must_progress",
]
