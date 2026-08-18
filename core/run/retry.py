"""Retry with explicit policy — the one way to write an attempt loop.

Consolidates the bespoke ``for attempt in range(...)`` / doubling
``time.sleep`` engines scattered across the tree (NVD client, SCA feed
refresh, codeql pack download, cve_diff pipeline, ...). The recurring
defect in the copies was BLIND retry — ``except Exception`` loops that
burn the whole budget on hard failures (bad credentials, 4xx) that can
never succeed. This module makes the retryable-predicate a REQUIRED
part of the policy: callers must say what is transient.

Explicitly out of scope: the LLM client's internal retry/backoff stack
(``core/llm/client.py`` + ``core/llm/concurrency.py`` — budget-aware,
provider-specific) and ``core/http``'s transport engine (fixed
schedule + circuit breaker + wall-clock deadline). Consumers layering
on ``core.http`` should pass ``retries=0`` to the transport and own
the policy here, the way the NVD client does — never double-retry.

Feedback-driven generate-and-verify loops (propose → judge → feed the
error back into the next prompt) are a different species and live in
``core/orchestration/driver.py``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TypeVar

__all__ = ["RetryPolicy", "retry_call"]

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    """How many attempts, what is retryable, and the backoff shape.

    ``attempts`` is the TOTAL attempt count including the first
    (``attempts=1`` = no retries). ``retryable`` classifies a raised
    exception; anything it rejects propagates immediately.

    Backoff: an explicit ``delays`` schedule wins when given (delay
    before retry *i*, clamped to the last entry when retries outrun
    the schedule); otherwise exponential
    ``base_delay * multiplier**i``, optionally capped at
    ``max_delay``. No jitter — the consolidated engines had none, and
    determinism keeps tests exact; add it here (once) if thundering
    herds ever show up.
    """

    attempts: int
    retryable: Callable[[Exception], bool]
    delays: Sequence[float] | None = None
    base_delay: float = 1.0
    multiplier: float = 2.0
    max_delay: float | None = None

    def delay_for(self, retry_index: int) -> float:
        """Delay in seconds before retry *retry_index* (0-based)."""
        if self.delays is not None:
            if not self.delays:
                return 0.0
            delay = self.delays[min(retry_index, len(self.delays) - 1)]
        else:
            delay = self.base_delay * (self.multiplier ** retry_index)
        if self.max_delay is not None:
            delay = min(delay, self.max_delay)
        return float(delay)


def retry_call(
    fn: Callable[[], T],
    *,
    policy: RetryPolicy,
    retry_result: Callable[[T], bool] | None = None,
    delay_override: Callable[[Exception, float], float] | None = None,
    on_retry: Callable[[int, Exception | None, float], None] | None = None,
    sleep: Callable[[float], None] | None = None,
) -> T:
    """Call *fn* up to ``policy.attempts`` times.

    * A raised exception is retried when ``policy.retryable(exc)``
      says so; otherwise (or once attempts are exhausted) it
      propagates. On exhaustion the LAST exception is re-raised.
    * A returned result is retried when ``retry_result`` (optional)
      flags it; on exhaustion the last result is RETURNED — the caller
      inspects it (soft-fail engines return None themselves).
    * ``delay_override(exc, scheduled)`` lets exception retries adjust
      the sleep (e.g. honour ``Retry-After``); result retries always
      use the schedule.
    * ``on_retry(retry_index, exc_or_none, delay)`` fires before each
      sleep — logging/telemetry hook.
    * ``sleep`` defaults to ``time.sleep`` looked up at call time (so
      test monkeypatches of ``time.sleep`` apply to the default too);
      only positive delays sleep.
    """
    if policy.attempts < 1:
        raise ValueError(f"policy.attempts must be >= 1, got {policy.attempts}")
    do_sleep = sleep if sleep is not None else time.sleep

    def _pause(retry_index: int, exc: Exception | None) -> None:
        delay = policy.delay_for(retry_index)
        if exc is not None and delay_override is not None:
            delay = delay_override(exc, delay)
        if on_retry is not None:
            on_retry(retry_index, exc, delay)
        if delay > 0:
            do_sleep(delay)

    result: T
    for attempt in range(policy.attempts):
        is_last = attempt + 1 >= policy.attempts
        try:
            result = fn()
        except Exception as exc:
            if is_last or not policy.retryable(exc):
                raise
            _pause(attempt, exc)
            continue
        if retry_result is not None and not is_last and retry_result(result):
            _pause(attempt, None)
            continue
        return result
    return result  # exhausted on retry_result — hand back the last one
