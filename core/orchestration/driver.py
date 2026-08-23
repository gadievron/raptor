"""Generate-and-verify loop — the shared synthesis primitive.

Propose candidate -> build artifact -> test against mechanical oracle ->
refine -> stop on oracle satisfaction or budget exhaustion.

Goal-agnostic: the driver does not know what is being synthesised.
The oracle is the seam — pluggable, reliability-classed, first-class.

Consumers:
  - concept compiler (dual control oracle)
  - barrier_synth (CodeQL adjudication oracle)
  - /exploit (sandbox effect oracle, pending)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Verdict
# ------------------------------------------------------------------

@dataclass
class Verdict:
    """Result of oracle evaluation on a candidate."""

    passed: bool
    feedback: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)


# ------------------------------------------------------------------
# Protocols
# ------------------------------------------------------------------

@runtime_checkable
class Oracle(Protocol):
    """Mechanical test for candidate quality.

    ``reliability_class`` is ``"decisive"`` (deterministic, trusted
    unsupervised) or ``"judgement"`` (LLM-based, requires downstream
    validation).  The driver does not act on the class — it is
    metadata for the caller.
    """

    reliability_class: str

    def judge(self, candidate: Any, context: Any) -> Verdict: ...


@runtime_checkable
class Proposer(Protocol):
    """Generates candidates from context and feedback."""

    def propose(
        self,
        context: Any,
        feedback: str,
        *,
        prior_verdict: Verdict | None = None,
    ) -> Any: ...


# ------------------------------------------------------------------
# Config and result
# ------------------------------------------------------------------

@dataclass
class DriverConfig:
    """Budget for the generate-and-verify loop.

    *max_attempts*: per-cycle proposal retries (error -> feedback -> retry).
    *max_refine_cycles*: refinement rounds when the oracle says "compiled
    but not good enough" (0 = single axis, no refinement).
    *retry_on_failure*: when True (default), a non-passing verdict retries
    within the inner loop.  When False, any verdict (passed or not) exits
    the inner loop — only exceptions trigger retries.  Use False when
    compile retries (exceptions) and soundness refinement (verdicts) are
    separate axes.
    """

    max_attempts: int = 3
    max_refine_cycles: int = 0
    retry_on_failure: bool = True


@dataclass
class DriverResult:
    """Outcome of the generate-and-verify loop."""

    candidate: Any | None = None
    verdict: Verdict | None = None
    attempts: int = 0
    refine_cycles: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.verdict is not None and self.verdict.passed


# ------------------------------------------------------------------
# Helpers: wrap plain callables as Protocol objects
# ------------------------------------------------------------------

class _FnOracle:
    def __init__(self, fn, reliability_class) -> None:
        self.reliability_class = reliability_class
        self._fn = fn

    def judge(self, candidate, context):
        return self._fn(candidate, context)


def oracle_from_fn(fn, *, reliability_class: str="decisive"):
    """Wrap a ``(candidate, context) -> Verdict`` callable as an Oracle."""
    return _FnOracle(fn, reliability_class)


class _FnProposer:
    def __init__(self, fn) -> None:
        self._fn = fn

    def propose(self, context, feedback, *, prior_verdict=None):
        return self._fn(context, feedback, prior_verdict=prior_verdict)


def proposer_from_fn(fn):
    """Wrap a ``(context, feedback, *, prior_verdict) -> candidate`` callable."""
    return _FnProposer(fn)


# ------------------------------------------------------------------
# The loop
# ------------------------------------------------------------------

def run(
    proposer: Proposer,
    oracle: Oracle,
    context: Any,
    *,
    config: DriverConfig | None = None,
) -> DriverResult:
    """Run the generate-and-verify loop.

    Two retry axes:

      * **Compile retries** (*config.max_attempts*): proposal generation
        or oracle evaluation failed mechanically.  Error string fed back
        to the proposer for correction.

      * **Refinement cycles** (*config.max_refine_cycles*): candidate
        was testable but the oracle says not good enough.  The full
        :class:`Verdict` (with evidence) is fed to the proposer via
        *prior_verdict* for structural correction.  Each refinement
        cycle resets the compile-retry budget.
    """
    cfg = config or DriverConfig()
    result = DriverResult()
    prior_verdict: Verdict | None = None

    while True:
        feedback = ""
        cycle_candidate = None
        cycle_verdict = None

        for attempt in range(1, cfg.max_attempts + 1):
            result.attempts += 1

            try:
                candidate = proposer.propose(
                    context, feedback, prior_verdict=prior_verdict,
                )
            except Exception as exc:
                feedback = str(exc)
                result.errors.append(f"attempt {attempt}: propose: {feedback}")
                logger.debug("attempt %d propose error: %s", attempt, feedback)
                continue

            try:
                verdict = oracle.judge(candidate, context)
            except Exception as exc:
                feedback = str(exc)
                result.errors.append(f"attempt {attempt}: oracle: {feedback}")
                logger.debug("attempt %d oracle error: %s", attempt, feedback)
                continue

            cycle_candidate = candidate
            cycle_verdict = verdict

            if verdict.passed:
                break

            if not cfg.retry_on_failure:
                break

            feedback = verdict.feedback
            if feedback:
                result.errors.append(f"attempt {attempt}: {feedback}")

        if cycle_candidate is None:
            return result

        result.candidate = cycle_candidate
        result.verdict = cycle_verdict

        if cycle_verdict.passed:
            return result

        if result.refine_cycles >= cfg.max_refine_cycles:
            return result

        result.refine_cycles += 1
        prior_verdict = cycle_verdict
