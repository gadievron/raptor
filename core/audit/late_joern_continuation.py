"""Adapt late Joern context to the existing unit continuation owner."""
from __future__ import annotations

from threading import Lock

from .continuation_context import context_version
from .knowledge_calls import KnowledgeCallRefused


class LateJoernContinuations:
    """No new scheduler, model router, counters, or evidence authority."""

    def __init__(self, runtime, review_fn, admission):
        self.runtime = runtime
        self.review_fn = runtime.wrap_review(review_fn)
        self.admission = admission
        self._lock = Lock()
        self._passes = {}

    def dispatch(self, index, ctx, config):
        value = ctx.get("mechanical_evidence")
        if not isinstance(value, str) or not value:
            raise KnowledgeCallRefused("late_joern_context_unavailable")
        version = context_version(value)
        self.runtime.offer_context_delta(ctx, kind="late_joern", version=version)
        reservation = self.runtime.reserve_context_continuation(
            ctx, admission=self.admission, required_context_id=f"context:late_joern:{version}")
        if reservation is None:
            raise KnowledgeCallRefused("late_joern_continuation_deferred")
        with self._lock:
            self._passes[index] = (reservation, ctx)
        try:
            if not self.runtime.enrich_context(ctx, reservation):
                raise KnowledgeCallRefused("late_joern_context_stale")
            return self.review_fn(ctx, config)
        except BaseException:
            self.fail(index, "late_joern_review_failed")
            raise

    def can_publish(self, index):
        with self._lock:
            owned = self._passes.get(index)
        return bool(owned and self.runtime.can_publish(owned[0])
                    and self.runtime.context_was_delivered(owned[0]))

    def complete(self, index, published_status):
        with self._lock:
            owned = self._passes.pop(index, None)
        if owned is not None:
            reservation, ctx = owned
            return self.runtime.complete(reservation, ctx, published_status=published_status,
                                         reason="late_joern_context_reviewed")
        return False

    def fail(self, index, reason):
        with self._lock:
            owned = self._passes.pop(index, None)
        if owned is not None:
            return self.runtime.fail(owned[0], reason=reason, ctx=owned[1])
        return False

    def close(self):
        with self._lock:
            indices = tuple(self._passes)
        for index in indices:
            self.fail(index, "late_joern_publication_incomplete")
