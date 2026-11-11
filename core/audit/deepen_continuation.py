"""Bounded audit-quality selection through the existing continuation owner.

A selection is a policy decision to spend attention, never new source evidence.
"""
from __future__ import annotations

from threading import Lock

from .continuation_context import context_version
from .knowledge_calls import KnowledgeCallRefused

QUALITY_POLICY = "deepen-quality-v1"
_QUALITY_REASONS = {
    "unresolved_concern": "an unresolved concern selected for another bounded review",
    "reduced_context": "a prior assessment produced with reduced context selected for a full-context review",
}


def render_deepen_selection(value) -> str:
    """Render an allowlisted policy reason, without model prose or fresh IDs."""
    if not isinstance(value, dict) or value.get("policy") != QUALITY_POLICY:
        return ""
    reason = value.get("reason")
    if not isinstance(reason, str) or reason not in _QUALITY_REASONS:
        return ""
    return ("\n### Bounded audit-quality review\n"
            f"Selection policy: {QUALITY_POLICY}; reason: {reason}.\n"
            f"This function has {_QUALITY_REASONS[reason]}. "
            "This selection is not new information, verification evidence, or a finding. "
            "Read the supplied source independently, consider alternative hypotheses, "
            "and state remaining limitations. The shared continuation and call limits still apply.")


class DeepenContinuations:
    """Own only pass handles; all admission and limits belong to the runtime."""

    def __init__(self, runtime, review_fn, admission):
        self.runtime = runtime
        self.review_fn = runtime.wrap_review(review_fn)
        self.admission = admission
        self._lock = Lock()
        self._passes = {}

    def dispatch(self, index, ctx, config):
        value = render_deepen_selection(ctx.get("deepen_quality_selection"))
        if not value:
            raise KnowledgeCallRefused("deepen_quality_selection_unavailable")
        with self._lock:
            if index in self._passes:
                raise KnowledgeCallRefused("deepen_pass_already_owned")
        version = context_version(value)
        self.runtime.offer_context_delta(ctx, kind="deepen_quality", version=version)
        width = max(1, config.review_passes,
                    len(config.models or []) if config.multi_model else 1)
        reservation = self.runtime.reserve_context_continuation(
            ctx, admission=self.admission, required_calls=width,
            required_context_id=f"context:deepen_quality:{version}")
        if reservation is None:
            raise KnowledgeCallRefused("deepen_continuation_deferred")
        with self._lock:
            self._passes[index] = (reservation, ctx)
        try:
            if not self.runtime.enrich_context(ctx, reservation):
                raise KnowledgeCallRefused("deepen_context_stale")
            return self.review_fn(ctx, config)
        except BaseException:
            self.fail(index, "deepen_review_failed")
            raise

    def reservation(self, index):
        with self._lock:
            owned = self._passes.get(index)
        return owned[0] if owned is not None else None

    def can_publish(self, index):
        reservation = self.reservation(index)
        return bool(reservation is not None and self.runtime.can_publish(reservation)
                    and self.runtime.context_was_delivered(reservation))

    def complete(self, index, published_status):
        with self._lock:
            owned = self._passes.pop(index, None)
        if owned is None:
            return False
        reservation, ctx = owned
        return self.runtime.complete(reservation, ctx, published_status=published_status,
                                     reason="deepen_quality_reviewed")

    def fail(self, index, reason):
        with self._lock:
            owned = self._passes.pop(index, None)
        if owned is None:
            return False
        return self.runtime.fail(owned[0], reason=reason, ctx=owned[1])

    def close(self):
        with self._lock:
            indices = tuple(self._passes)
        for index in indices:
            self.fail(index, "deepen_publication_incomplete")
