"""Consumer-side prefilter helpers.

Provide the uniform glue every consumer needs around the scorecard:

  * :func:`prefilter_decision` — given that the cheap-tier model has
    just answered "is this a clear false positive?", decide whether
    to short-circuit (trust the cheap verdict) or fall through to
    the consumer's full analysis path.

  * :func:`record_prefilter_outcome` — given both the cheap and full
    verdicts, record an event back to the scorecard so its trust
    math reflects the latest observation.

The cheap-prompt construction itself is consumer-specific (codeql's
"is this finding a confident FP?" looks nothing like SCA's "is this
major-version bump safe?") — those prompts live in their respective
packages. The scorecard side stays uniform.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .scorecard import EventType, ModelScorecard, Policy


@dataclass
class PrefilterDecision:
    """The scorecard's verdict on whether the cheap model's
    "clear FP" answer should be acted on.

    ``short_circuit=True`` means: skip the full analysis, return a
    consumer-shaped FP result built from the cheap reasoning. The
    consumer is responsible for materialising that result; the
    scorecard only decides whether the short-circuit is allowed.

    ``short_circuit=False`` means: run the full analysis path. In
    learning mode (no track record yet) and in fall-through mode
    (measured miss-rate too high) we always fall through.
    """
    short_circuit: bool
    decision_class: str
    model: str
    policy: str          # Policy.SHORT_CIRCUIT / FALL_THROUGH / LEARNING


def prefilter_decision(
    scorecard: Optional[ModelScorecard],
    *,
    decision_class: str,
    model: str,
    cheap_says_fp: bool,
) -> PrefilterDecision:
    """Decide whether to short-circuit on the cheap verdict.

    Behaviour table::

      cheap_says_fp   scorecard policy   →   short_circuit
      False           any                    False  (cheap didn't claim FP)
      True            SHORT_CIRCUIT          True
      True            FALL_THROUGH           False  (untrusted history)
      True            LEARNING               False  (need data)
      True            (scorecard=None)       False  (operator opted out)

    ``cheap_says_fp=False`` short-circuits on its own — the cheap
    model didn't make a confident FP claim, so there's nothing to
    gate; full analysis runs.
    """
    if not cheap_says_fp:
        return PrefilterDecision(
            short_circuit=False,
            decision_class=decision_class,
            model=model,
            policy=Policy.FALL_THROUGH,
        )
    if scorecard is None:
        return PrefilterDecision(
            short_circuit=False,
            decision_class=decision_class,
            model=model,
            policy=Policy.FALL_THROUGH,
        )
    policy = scorecard.should_short_circuit(decision_class, model)
    return PrefilterDecision(
        short_circuit=(policy == Policy.SHORT_CIRCUIT),
        decision_class=decision_class,
        model=model,
        policy=policy,
    )


def record_prefilter_outcome(
    scorecard: Optional[ModelScorecard],
    *,
    decision_class: str,
    model: str,
    cheap_says_fp: bool,
    full_says_fp: bool,
    cheap_reasoning: str = "",
    full_reasoning: str = "",
    model_version: Optional[str] = None,
) -> None:
    """Record one observation of cheap-vs-full agreement.

    Only events where ``cheap_says_fp=True`` are recorded — the
    short-circuit gate's Wilson math is computed over "cheap claimed
    FP and was right vs cheap claimed FP and was wrong". When cheap
    didn't claim FP, the full call ran for analysis reasons
    independent of trust, and there's nothing to learn about the
    short-circuit gate.

    No-op when ``scorecard`` is None (opted out) or when
    ``cheap_says_fp=False``. Disagreement reasoning text is
    truncated and forwarded to the scorecard's bounded sample log
    on ``incorrect`` outcomes.
    """
    if scorecard is None:
        return
    if not cheap_says_fp:
        return
    outcome = "correct" if full_says_fp else "incorrect"
    sample = None
    if outcome == "incorrect":
        sample = {
            # Cap reasoning text length to bound on-disk storage and
            # reduce risk of operator-inspectable code snippets
            # ending up in the scorecard. The first ~500 chars are
            # almost always the model's verdict-summary; the rest
            # is usually procedural or restating the question.
            "this_reasoning": (cheap_reasoning or "")[:500],
            "other_reasoning": (full_reasoning or "")[:500],
        }
    scorecard.record_event(
        decision_class=decision_class,
        model=model,
        event_type=EventType.CHEAP_SHORT_CIRCUIT,
        outcome=outcome,
        model_version=model_version,
        sample=sample,
    )


__all__ = [
    "PrefilterDecision",
    "prefilter_decision",
    "record_prefilter_outcome",
]
