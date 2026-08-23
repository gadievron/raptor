"""Shared cost sanitisation.

Every fire/attempt/lesson record carries a ``cost_usd`` field. A
provider glitch or a division-by-zero somewhere upstream can put
``NaN``, ``+inf``, or a negative float into that slot, and downstream
consumers (aggregators, dashboards, scorecards) then see garbage:

  * ``NaN + x = NaN`` poisons the running total.
  * ``+inf`` masks the real spend and breaks budget-cap enforcement.
  * negative values look like "we made money" and confuse review.

Rather than defend at every aggregator, sanitise at every WRITE.
Consumers that persist ``cost_usd`` / iteration counts route
through the helpers here so a spelling change (e.g. adopting a
Decimal-friendly variant) lands in one place.
"""

from __future__ import annotations

import math
from typing import Any


def sanitize_cost(raw: Any) -> float:
    """Return a bounded, finite, non-negative float.

    ``None`` / non-numeric input → ``0.0``.
    ``NaN`` / ``±inf`` → ``0.0``.
    Negative → ``0.0``.
    Otherwise → ``float(raw)``.

    Callers accumulate through this at write / record time. Reading
    the sanitised field downstream is then plain float arithmetic
    with no defensive checks needed at each aggregation point.
    """
    if raw is None:
        return 0.0
    if isinstance(raw, bool):
        # Python bool subclasses int, but treating True as 1.0 in a
        # cost field is a caller error — surface as 0.0.
        return 0.0
    if not isinstance(raw, (int, float)):
        # A string that happens to be numeric ("0.05") is a caller
        # error we don't try to parse — silent stringification of
        # cost is how NaN got into records in the first place.
        return 0.0
    try:
        as_float = float(raw)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(as_float) or as_float < 0:
        return 0.0
    return as_float


def sanitize_iterations(raw: Any) -> int:
    """Return a non-negative int iteration count.

    Same contract shape as :func:`sanitize_cost`: guard at write
    time. Negative iterations / non-int / None all clamp to 0.
    """
    if not isinstance(raw, int) or isinstance(raw, bool):
        return 0
    return max(raw, 0)


__all__ = ["sanitize_cost", "sanitize_iterations"]
