"""Compute rails for differential family execution.

Every constant here bounds sandboxed process spawns, so each carries
its trade-off in both directions and a regression test pins both
(raising OR lowering one is a deliberate act, never drift).
"""

from __future__ import annotations

import time
from typing import Callable

#: Per-run ceiling on member executions (every sandboxed harness run
#: counts one, whatever its outcome). Lower and a run with several
#: eligible leads starves — one fully-fanned lead can spend
#: (1 deviant + MAX_CONFORMING_EXECUTED) * MAX_VECTORS_PER_LEAD = 27
#: executions, so 150 covers about five such leads plus smaller ones.
#: Higher and the post-loop pass turns into an unbounded tail of
#: process spawns (each costs seconds of sandbox setup) that dwarfs
#: the review loop it is meant to follow.
MAX_DIFFERENTIAL_EXECUTIONS = 150

#: Per-run wall-clock ceiling for the whole pass, seconds. Lower and
#: a slow host gets cut off mid-family, poisoning vectors that would
#: have classified cleanly; higher and a pathological target (slow
#: module imports, heavy per-call setup) monopolises the run's tail
#: long after the execution budget would have ended it.
MAX_DIFFERENTIAL_WALL_S = 900.0

#: Minimum conforming members that must execute VALIDLY for a vector
#: to classify at all. Lower and a single peer's behaviour can
#: masquerade as "the family agrees/rejects"; higher and the pass
#: refuses verdicts on small legitimate families that the census
#: itself accepted at its own floors.
MIN_CONFORMING_EXECUTED = 3

#: Maximum conforming members executed per family (the deviant always
#: executes, so a family costs at most 1 + this per vector). Lower
#: and the record loses corroborating breadth it could have carried
#: for free; higher and every vector multiplies sandbox spawns with
#: no verdict effect — unanimity over eight peers is already
#: decisive, and the classifier never weighs nine higher than eight.
MAX_CONFORMING_EXECUTED = 8

#: Argument vectors executed per lead. Lower and one malformed or
#: unlucky proposal wastes the lead entirely (a single vector has no
#: retry); higher and vector fishing lets one lead burn the run
#: budget probing the same family over and over.
MAX_VECTORS_PER_LEAD = 3

#: Equivalence pairs executed per metamorphic relation (each pair is
#: two executions, plus four for the trust controls). Lower and one
#: relation gets a single shot at the invariant; higher and one
#: relation's pair list crowds out the run budget the same way vector
#: fishing would.
MAX_RELATION_PAIRS = 3


class DifferentialBudget:
    """Charge-before-run accounting for the two per-run rails.

    ``try_charge`` must be called BEFORE each member execution; when
    it returns False the execution must not happen and
    ``over_reason`` names which rail closed the pass (telemetry is
    the caller's job — witnesses skipped over budget are recorded,
    never silent).
    """

    def __init__(
        self,
        *,
        max_executions: int = MAX_DIFFERENTIAL_EXECUTIONS,
        max_wall_s: float = MAX_DIFFERENTIAL_WALL_S,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_executions = max_executions
        self._max_wall_s = max_wall_s
        self._clock = clock
        self._start = clock()
        self.executions = 0

    def over_reason(self) -> str | None:
        """Which rail is closed, or None while both are open."""
        if self.executions >= self._max_executions:
            return (
                f"execution budget exhausted "
                f"({self.executions}/{self._max_executions})"
            )
        elapsed = self._clock() - self._start
        if elapsed >= self._max_wall_s:
            return (
                f"wall budget exhausted "
                f"({elapsed:.0f}s/{self._max_wall_s:.0f}s)"
            )
        return None

    def try_charge(self, n: int = 1) -> bool:
        """Reserve *n* executions; False (nothing charged) when either
        rail refuses."""
        if self.over_reason() is not None:
            return False
        if self.executions + n > self._max_executions:
            return False
        self.executions += n
        return True
