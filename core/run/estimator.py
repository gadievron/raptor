"""Cost-and-time estimator (QoL #21).

Derives run estimates from the model scorecard — real per-model call
history: observed cost-per-call and latency-per-call, scaled by finding
count and divided by ``max_parallel``.  Model- and parallelism-aware.

Returns ``None`` when the scorecard has insufficient data for the
requested model (< 5 calls). No estimate is better than a wrong one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class RunEstimate:
    """Estimated cost + time for a run.

    ``cost_low / cost_high`` in USD; ``time_low / time_high`` in
    minutes.

    """

    cost_low: float
    cost_high: float
    time_low: int
    time_high: int
    target_type: str
    source: str = "scorecard"


def estimate_from_scorecard(
    model: str,
    n_findings: int,
    *,
    max_parallel: int = 3,
    scorecard_path: Optional[Path] = None,
) -> Optional[RunEstimate]:
    """Derive a cost + time estimate from the model's scorecard history.

    Aggregates ``calls``, ``cost_usd``, and ``latency_ms_sum`` across
    all decision classes for the given model, then scales by
    ``n_findings`` and ``max_parallel``.

    Returns ``None`` when the scorecard is unavailable, the model has
    no recorded calls, or latency data is missing.
    """
    if n_findings <= 0:
        return None
    try:
        from core.llm.scorecard.scorecard import ModelScorecard
    except ImportError:
        return None
    try:
        sc = ModelScorecard(path=scorecard_path) if scorecard_path else ModelScorecard()
        stats = sc.get_stats()
    except Exception:  # noqa: BLE001
        return None

    total_calls = 0
    total_cost = 0.0
    total_latency_ms = 0
    for cell in stats:
        if cell.model != model:
            continue
        total_calls += cell.calls
        total_cost += cell.cost_usd
        total_latency_ms += cell.latency_ms_sum

    if total_calls < 5:
        return None

    avg_cost = total_cost / total_calls
    avg_latency_s = total_latency_ms / (total_calls * 1000)

    parallel = max(1, max_parallel)
    wall_time_s = (n_findings * avg_latency_s) / parallel
    wall_time_min = wall_time_s / 60

    cost_est = n_findings * avg_cost
    # ±30% range to reflect variance
    cost_low = cost_est * 0.7
    cost_high = cost_est * 1.3
    time_low = max(1, math.floor(wall_time_min * 0.7))
    time_high = max(1, math.ceil(wall_time_min * 1.3))

    return RunEstimate(
        cost_low=round(cost_low, 2),
        cost_high=round(cost_high, 2),
        time_low=time_low,
        time_high=time_high,
        target_type=f"{model} (scorecard)",
        source="scorecard",
    )


def format_estimate(est: Optional[RunEstimate]) -> str:
    """Operator-facing one-liner. Empty string when ``est`` is
    None — caller can unconditionally append to output, no None
    check needed at the print site.

    ::

        Expected: $25-$50, 40-75 min (claude-opus-4-7, from scorecard)

    Ranges with low == high collapse to a single value.
    Cost or time only renders just the populated half.
    """
    if est is None:
        return ""

    def _money(low: float, high: float) -> str:
        if low <= 0 and high <= 0:
            return ""
        if low == high:
            return f"${low:.0f}"
        return f"${low:.0f}-${high:.0f}"

    def _mins(low: int, high: int) -> str:
        if low <= 0 and high <= 0:
            return ""
        if low == high:
            return f"{low} min"
        return f"{low}-{high} min"

    money = _money(est.cost_low, est.cost_high)
    mins = _mins(est.time_low, est.time_high)
    parts = [p for p in (money, mins) if p]
    if not parts:
        return ""
    label = f"{est.target_type.split(' (scorecard)')[0]}, from scorecard"
    return f"Expected: {', '.join(parts)} ({label})"
