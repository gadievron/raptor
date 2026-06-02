"""Cost-and-time estimator (QoL #21).

Reads ``pipeline.estimated_cost_usd`` + ``estimated_time_min`` from
the matched target-type catalog entry and renders an operator-facing
summary at lifecycle start. Composition layer over the catalog
substrate — no per-target heuristics live here; the catalog is the
single source of truth.

Consumers:
  * ``raptor.py:_run_with_lifecycle`` — print at run start.
  * ``libexec/raptor-run-lifecycle start`` — print on the skills
    invocation path (parity with raptor.py).
  * ``--max-cost-usd`` pre-flight gate — hard-fails the run before
    any LLM spend when the catalog estimate exceeds the operator's
    declared cap.

Returns ``None`` when:
  * ``target_path`` is None (no target → no detection possible).
  * The catalog doesn't match any entry, or the matched entry
    carries zero-valued estimate pairs (the ``generic`` fallback
    + entries that haven't filled in cost/time hints).
  * The catalog loader raises (best-effort; substrate failures
    must never break the lifecycle).

A ``None`` return is the signal to the renderer to print nothing —
operators get the estimate when it's available, silence when it
isn't, never a placeholder.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class RunEstimate:
    """Estimated cost + time for a run, sourced from the target-type catalog.

    ``cost_low / cost_high`` in USD; ``time_low / time_high`` in
    minutes. The pair represents the catalog author's expected
    range, not a confidence interval — read as "typical runs land
    here." Wide ranges (``$10 - $50``) signal high variance in the
    target shape; narrow ranges signal predictable runs.

    ``target_type`` is the catalog entry name that matched
    (e.g. ``c.userspace-daemon``); ``generic`` is filtered out at
    construction time so a None return is the no-useful-data signal.
    """

    cost_low: float
    cost_high: float
    time_low: int
    time_high: int
    target_type: str


def estimate_run(target_path: Optional[Path]) -> Optional[RunEstimate]:
    """Best-effort estimate from the target-type catalog. None when
    no useful data is available (see module docstring for the
    None-return conditions)."""
    if target_path is None:
        return None
    try:
        from core.run.target_types import load
        entry = load(Path(target_path))
    except Exception:  # noqa: BLE001
        return None
    if entry is None:
        return None
    cost_low, cost_high = entry.estimated_cost_usd
    time_low, time_high = entry.estimated_time_min
    # Filter out zero-valued estimates — the ``generic`` fallback
    # entry and any catalog entry that hasn't filled in cost/time
    # hints both surface as (0.0, 0.0) / (0, 0). Returning a
    # ``$0-$0`` estimate would be misleading; None is the
    # no-useful-data signal.
    if cost_high <= 0 and time_high <= 0:
        return None
    return RunEstimate(
        cost_low=cost_low,
        cost_high=cost_high,
        time_low=time_low,
        time_high=time_high,
        target_type=entry.name,
    )


def format_estimate(est: Optional[RunEstimate]) -> str:
    """Operator-facing one-liner. Empty string when ``est`` is
    None — caller can unconditionally append to output, no None
    check needed at the print site.

    Format::

        Expected: $25-$50, 40-75 min (target type: c.userspace-daemon)

    Ranges with low == high collapse to a single value::

        Expected: $30, 60 min (target type: c.userspace-daemon)

    Cost or time only (the other side is zero-valued in the
    catalog) renders just the populated half.
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
    return (
        f"Expected: {', '.join(parts)} "
        f"(target type: {est.target_type})"
    )
