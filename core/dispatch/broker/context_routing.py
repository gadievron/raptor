"""Context-window routing — select the cheapest model that fits.

Uses ``MODEL_LIMITS`` for context windows and ``price_for()`` for
cost comparison.  This is the first routing primitive the broker
uses: before scorecard ranking, health, or RPM — a model that
can't hold the prompt is not a candidate.
"""

from __future__ import annotations

from core.llm.model_data import (
    MODEL_LIMITS,
    context_window_for,
    price_for,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hints import ModelHint


class ContextRoutingError(RuntimeError):
    """No candidate model can fit the prompt."""


def select_by_context(
    prompt_tokens: int,
    candidates: list[str],
    *,
    hint: ModelHint | None = None,
    headroom: float = 0.9,
) -> str:
    """Pick the cheapest model whose context window fits *prompt_tokens*.

    ``headroom`` (0–1) reserves a fraction of the context window for
    output tokens — a prompt that fills 100% of the window leaves no
    room for the response.  Default 0.9 means the prompt must fit in
    90% of the window.

    When a ``hint`` is provided:

    - ``require``: return the required model if it fits, raise if not.
    - ``prefer``: return the preferred model if it fits, else fall
      through to best-fit selection among remaining candidates.
    - ``defer``: pure best-fit selection.

    Among equally-fitting candidates, the cheapest (lowest output
    price per million tokens) wins.  Ties broken by input price.

    Raises ``ContextRoutingError`` if no candidate fits.
    """
    if hint and hint.tier == "require":
        try:
            limit = _effective_limit(hint.model, headroom)
        except KeyError:
            msg = (
                f"{hint.model} is not in MODEL_LIMITS — "
                f"cannot verify context window fit"
            )
            raise ContextRoutingError(msg) from None
        if prompt_tokens > limit:
            msg = (
                f"{hint.model} context window ({limit:,} usable of "
                f"{context_window_for(hint.model):,}) cannot fit "
                f"{prompt_tokens:,} prompt tokens"
            )
            raise ContextRoutingError(msg)
        return hint.model

    if hint and hint.tier == "prefer":
        if hint.model not in (hint.exclude_models or frozenset()):
            try:
                limit = _effective_limit(hint.model, headroom)
                if prompt_tokens <= limit:
                    return hint.model
            except KeyError:
                pass

    exclude = hint.exclude_models if hint else frozenset()
    eligible = []
    for model in candidates:
        if model in exclude:
            continue
        try:
            limit = _effective_limit(model, headroom)
        except KeyError:
            continue
        if prompt_tokens <= limit:
            eligible.append(model)

    if not eligible:
        msg = (
            f"no candidate model fits {prompt_tokens:,} prompt tokens "
            f"(candidates: {candidates}, headroom={headroom})"
        )
        raise ContextRoutingError(msg)

    eligible.sort(key=_cost_sort_key)
    return eligible[0]


def models_fitting(
    prompt_tokens: int,
    *,
    headroom: float = 0.9,
) -> list[str]:
    """Return all known models whose context window fits *prompt_tokens*,
    sorted cheapest-first.  Useful for building candidate lists."""
    result = []
    for model in MODEL_LIMITS:
        try:
            limit = _effective_limit(model, headroom)
        except KeyError:
            continue
        if prompt_tokens <= limit:
            result.append(model)
    result.sort(key=_cost_sort_key)
    return result


def _effective_limit(model: str, headroom: float) -> int:
    return int(context_window_for(model) * headroom)


def _cost_sort_key(model: str) -> tuple[float, float]:
    inp, out = price_for(model)
    return (out, inp)
