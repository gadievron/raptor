"""Consumer-side prefilter helpers.

Provide the uniform glue every consumer needs around the scorecard:

  * :func:`prefilter_decision` — given that the cheap-tier model has
    just answered "is this a clear false positive?", decide whether
    to short-circuit (trust the cheap verdict) or fall through to
    the consumer's full analysis path.

  * :func:`record_prefilter_outcome` — given both the cheap and full
    verdicts, record an event back to the scorecard so its trust
    math reflects the latest observation.

  * :func:`run_cheap_fp_check` — the cheap-tier call itself: the
    CONSERVATIVE-profile envelope, the ``VERDICT_BINARY`` structured
    call, and the verdict validation that every consumer had copied
    verbatim. Fails soft (``None`` = no signal, run full analysis).

  * :func:`fast_tier_model_name` — which model the ``VERDICT_BINARY``
    task routes to, i.e. the model whose track record the scorecard
    accumulates against. Pure config reading; previously duplicated
    verbatim in four consumer packages because "core must not depend
    on consumers" — this direction (consumers → core.llm) is correct.

The cheap-prompt TEXT stays consumer-specific (codeql's "is this
finding a confident FP?" looks nothing like SCA's "is this
major-version bump safe?") — prompts and schemas live in their
respective packages, passed in. The call mechanics and the scorecard
side stay uniform here.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .scorecard import EventType, ModelScorecard, Policy

_logger = logging.getLogger(__name__)


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
    scorecard: ModelScorecard | None,
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
    scorecard: ModelScorecard | None,
    *,
    decision_class: str,
    model: str,
    cheap_says_fp: bool,
    full_says_fp: bool,
    cheap_reasoning: str = "",
    full_reasoning: str = "",
    model_version: str | None = None,
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


def fast_tier_model_name(config: Any) -> str:
    """Return the model_name routed to for ``TaskType.VERDICT_BINARY``
    — the model whose track record the scorecard accumulates against.

    Falls back to the primary model when the operator hasn't
    configured (or auto-config didn't seed) a fast-tier mapping — in
    that case fast-tier and primary are the same model and scorecard
    cells naturally key by the primary. ``""`` when neither exists.
    """
    from core.llm.task_types import TaskType
    specialized = config.specialized_models.get(TaskType.VERDICT_BINARY)
    if specialized is not None and specialized.enabled:
        return specialized.model_name
    if config.primary_model is not None:
        return config.primary_model.model_name
    return ""


def run_cheap_fp_check(
    client: Any,
    *,
    system: str,
    schema: Mapping[str, Any],
    untrusted_blocks: Sequence[Any] = (),
    slots: Mapping[str, Any] | None = None,
    allowed_verdicts: Sequence[str] = ("clear_fp", "needs_analysis"),
    log: logging.Logger | None = None,
) -> tuple[str, str] | None:
    """Run the cheap-tier "is this a clear false positive?" call.

    The consumer supplies WHAT to ask (``system`` prompt text,
    ``schema``, envelope ``untrusted_blocks`` / ``slots`` — all
    consumer-owned); this helper owns HOW: the CONSERVATIVE-profile
    :func:`core.security.prompt_envelope.build_prompt` envelope, the
    ``TaskType.VERDICT_BINARY`` structured call, response unwrapping,
    and verdict validation against ``allowed_verdicts`` (SCA-style
    consumers pass their own literals, e.g. ``("clear_safe",
    "needs_analysis")``).

    Returns ``(verdict, reasoning)`` on success. Fails SOFT: any call
    failure or an out-of-set verdict returns ``None`` — "no signal",
    the consumer runs its full analysis path exactly as if the cheap
    tier didn't exist. Asymmetric by design: the cheap model is never
    used to greenlight a true positive, only to identify confident
    false positives.
    """
    from core.llm.coerce import structured_result
    from core.llm.task_types import TaskType
    from core.security.prompt_defense_profiles import CONSERVATIVE
    from core.security.prompt_envelope import build_prompt

    logger = log or _logger
    bundle = build_prompt(
        system=system,
        profile=CONSERVATIVE,
        untrusted_blocks=tuple(untrusted_blocks),
        slots=dict(slots) if slots is not None else None,
    )
    system_prompt = next(
        (m.content for m in bundle.messages if m.role == "system"), None,
    )
    prompt = next(
        (m.content for m in bundle.messages if m.role == "user"), "",
    )
    try:
        response = client.generate_structured(
            prompt=prompt,
            schema=dict(schema),
            system_prompt=system_prompt,
            task_type=TaskType.VERDICT_BINARY,
        )
    except Exception as e:  # noqa: BLE001 — any cheap-call failure = no signal
        logger.debug("Cheap FP check failed (falling through to full): %s", e)
        return None
    result = structured_result(response, default={})
    if not isinstance(result, Mapping):
        result = {}
    verdict = (result.get("verdict") or "").strip().lower()
    reasoning = result.get("reasoning") or ""
    if verdict not in allowed_verdicts:
        # Defensive: an unexpected verdict string means we can't gate
        # on it. Fall through to full analysis.
        logger.debug(
            "Cheap FP check returned unexpected verdict %r — falling through",
            verdict,
        )
        return None
    return verdict, reasoning


__all__ = [
    "PrefilterDecision",
    "fast_tier_model_name",
    "prefilter_decision",
    "record_prefilter_outcome",
    "run_cheap_fp_check",
]
