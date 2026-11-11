"""Live-sink classification context through the existing continuation owner.

Classifications are advisory leads, not execution or verification facts.
"""
from __future__ import annotations

from threading import Lock

from .continuation_context import context_version
from .knowledge_calls import KnowledgeCallRefused

MAX_LIVE_SINKS = 15


def render_live_sink_context(value, *, defend_identifier) -> str:
    """Render bounded classification leads, never execution or reachability proof."""
    from hashlib import sha256
    import json

    if (not isinstance(value, (list, tuple)) or not value
            or any(not isinstance(name, str) or not name for name in value)):
        return ""
    try:
        for name in value:
            name.encode("utf-8")
    except UnicodeEncodeError:
        return ""
    names = sorted(set(value))
    shown = names[:MAX_LIVE_SINKS]
    lines = [
        "\n### Advisory live-sink classification leads",
        "These names were proposed as sink classifications for this run. "
        "They do not establish actual execution, guaranteed reachability, a "
        "verified dataflow, or confirmation or refutation of a concern. "
        "Review the supplied source independently and state unresolved assumptions.",
    ]
    for name in shown:
        anchor = sha256(json.dumps(name, ensure_ascii=True).encode("ascii")).hexdigest()
        lines.append(f"- Classification name sha256 {anchor}: "
                     + defend_identifier(name, max_length=200))
    if len(names) > len(shown):
        lines.append(f"Additional classification leads not shown: {len(names) - len(shown)}.")
    return "\n".join(lines)


class LiveSinkContinuations:
    """Own only pass handles; all admission and limits belong to the runtime."""

    def __init__(self, runtime, review_fn, admission):
        self.runtime = runtime
        self.review_fn = runtime.wrap_review(review_fn)
        self.admission = admission
        self._lock = Lock()
        self._passes = {}

    def dispatch(self, index, ctx, config):
        from .context import _defend_identifier

        value = render_live_sink_context(ctx.get("live_sinks"), defend_identifier=_defend_identifier)
        if not value:
            raise KnowledgeCallRefused("live_sink_context_unavailable")
        with self._lock:
            if index in self._passes:
                raise KnowledgeCallRefused("live_sink_pass_already_owned")
        from .ready_review_context import offer_ready_disagreement_context
        offer_ready_disagreement_context(self.runtime, ctx)
        version = context_version(value)
        self.runtime.offer_context_delta(ctx, kind="live_sinks", version=version)
        width = max(1, config.review_passes,
                    len(config.models or []) if config.multi_model else 1)
        reservation = self.runtime.reserve_context_continuation(
            ctx, admission=self.admission, required_calls=width,
            required_context_id=f"context:live_sinks:{version}")
        if reservation is None:
            raise KnowledgeCallRefused("live_sink_continuation_deferred")
        with self._lock:
            self._passes[index] = (reservation, ctx)
        try:
            if not self.runtime.enrich_context(ctx, reservation):
                raise KnowledgeCallRefused("live_sink_context_stale")
            return self.review_fn(ctx, config)
        except BaseException:
            self.fail(index, "live_sink_review_failed")
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
                                     reason="live_sink_context_reviewed")

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
            self.fail(index, "live_sink_publication_incomplete")


def retain_unbound_advisory_input_limit(outcome, reservation):
    """Unavailable original classification provenance cannot become source proof."""
    from .review_claims import read_history
    from .review_context_inputs import context_inputs_from_sources, merge_context_inputs

    history = read_history((outcome.review_result or {}).get("review_claims"))
    if history is not None:
        origin = reservation.origin
        incomplete = context_inputs_from_sources(
            [("target", origin.file, origin.source_identity.sha256)], complete=False)
        history["source_inputs"] = merge_context_inputs(history.get("source_inputs"), incomplete)
        outcome.review_result = {**(outcome.review_result or {}), "review_claims": history}
