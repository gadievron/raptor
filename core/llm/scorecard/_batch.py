"""Shared batched-write helper for scorecard event producers.

Producers collect their events per run and hand them over in one go:
:meth:`ModelScorecard.record_events` applies the whole batch under a
single lock + load + verify + atomic-rewrite cycle, where per-event
:meth:`~ModelScorecard.record_event` pays that full cycle for every
(model, finding) pair.

The producers' failure contract is the opposite of the batch API's
all-or-nothing validation: one bad event must not abort the rest and
must never block the calling orchestrator. So when the batch write is
rejected, degrade to per-event writes with per-event swallow — the
slow path only runs when something is already wrong.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import logging

    from .scorecard import ModelScorecard


def record_event_batch(
    scorecard: ModelScorecard,
    events: list[dict[str, Any]],
    *,
    log: logging.Logger,
    producer: str,
) -> int:
    """Write ``events`` (record_events entry shape) in one cycle;
    fall back to isolated per-event writes on batch failure.
    Returns the number of events recorded. Never raises.
    """
    if not events:
        return 0
    try:
        scorecard.record_events(events)
    except Exception:  # noqa: BLE001 — producer contract: never block the caller
        log.warning(
            "%s: batched record_events failed; retrying per event",
            producer, exc_info=True,
        )
    else:
        return len(events)
    n_recorded = 0
    for ev in events:
        try:
            scorecard.record_event(
                ev["decision_class"],
                ev["model"],
                ev["event_type"],
                ev["outcome"],
                model_version=ev.get("model_version"),
                sample=ev.get("sample"),
            )
            n_recorded += 1
        except Exception:  # noqa: BLE001 — one bad event must not abort the rest
            # WARNING (not DEBUG): operators rarely run with DEBUG in
            # production; a regressed producer would be invisible.
            log.warning(
                "%s: failed to record %s/%s",
                producer, ev.get("model"), ev.get("decision_class"),
                exc_info=True,
            )
    return n_recorded
