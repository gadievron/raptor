"""Model hint protocol — how consumers express model preference.

Three tiers:

  ``require`` — hard pin; fail if unavailable.
  ``prefer``  — try this first; broker can override on failure.
  ``defer``   — broker decides from task shape + scorecard.

Optional fields apply to all tiers: ``exclude_models`` prevents
fallback collision in multi-model panels, ``speed_tier`` controls
the latency/cost trade-off, ``max_cost_usd`` caps per-call spend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


class SpeedTier(Enum):
    EXPRESS = "express"
    ECONOMY = "economy"
    BATCH = "batch"


@dataclass(frozen=True)
class ModelHint:
    """Consumer's model preference for a single dispatch call.

    Construct via the convenience helpers ``require()``, ``prefer()``,
    ``defer()`` rather than setting ``tier`` directly — they read
    better at call sites and catch mistakes (e.g. ``require`` without
    a model name).
    """

    tier: Literal["require", "prefer", "defer"] = "defer"
    model: str = ""
    exclude_models: frozenset[str] = field(default_factory=frozenset)
    speed_tier: SpeedTier = SpeedTier.EXPRESS
    max_cost_usd: float | None = None
    decision_class: str = ""

    def __post_init__(self) -> None:
        if self.tier == "require" and not self.model:
            msg = "require tier needs a model name"
            raise ValueError(msg)
        if self.tier == "defer" and self.model:
            msg = (
                "defer tier should not specify a model — "
                "use prefer() if you have a preference"
            )
            raise ValueError(msg)


def require(
    model: str,
    *,
    exclude_models: frozenset[str] | set[str] | None = None,
    speed_tier: SpeedTier = SpeedTier.EXPRESS,
    max_cost_usd: float | None = None,
    decision_class: str = "",
) -> ModelHint:
    return ModelHint(
        tier="require",
        model=model,
        exclude_models=frozenset(exclude_models or ()),
        speed_tier=speed_tier,
        max_cost_usd=max_cost_usd,
        decision_class=decision_class,
    )


def prefer(
    model: str,
    *,
    exclude_models: frozenset[str] | set[str] | None = None,
    speed_tier: SpeedTier = SpeedTier.EXPRESS,
    max_cost_usd: float | None = None,
    decision_class: str = "",
) -> ModelHint:
    return ModelHint(
        tier="prefer",
        model=model,
        exclude_models=frozenset(exclude_models or ()),
        speed_tier=speed_tier,
        max_cost_usd=max_cost_usd,
        decision_class=decision_class,
    )


def defer(
    *,
    exclude_models: frozenset[str] | set[str] | None = None,
    speed_tier: SpeedTier = SpeedTier.EXPRESS,
    max_cost_usd: float | None = None,
    decision_class: str = "",
) -> ModelHint:
    return ModelHint(
        tier="defer",
        exclude_models=frozenset(exclude_models or ()),
        speed_tier=speed_tier,
        max_cost_usd=max_cost_usd,
        decision_class=decision_class,
    )
