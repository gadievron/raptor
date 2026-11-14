"""Prepare advisory synthesis input without dispatch or new source authority."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from core.source.lines import split_lines

from core.audit.knowledge_requests import KnowledgeOrigin
from core.audit.ready_review_context import ReadyReviewFrame
from core.audit.refutation_source import capture_source_identity
from core.audit.review_claims import read_history
from core.audit.review_input_scope import ReviewInputScope
from core.audit.synthesis_review_context import (
    SynthesisReviewContext, build_synthesis_review_context,
    render_synthesis_review_context,
)


@dataclass(frozen=True)
class SynthesisPreparationUnavailable:
    reason: str


@dataclass(frozen=True)
class PreparedSynthesisFrame:
    frame: ReadyReviewFrame
    payload: SynthesisReviewContext

    @property
    def context_id(self) -> str:
        return "context:synthesis_match:" + self.payload.version


def prepare_synthesis_frame(
    *, gap: dict, context: dict, prior: object, target_root: Path,
) -> PreparedSynthesisFrame | SynthesisPreparationUnavailable:
    """Retain a live canonical outcome's original scope; never recapture it.

    A fresh read only checks that the assembled source is that original input.
    The caller still owns exact canonical identity, Runtime admission, normal
    continuation limits, actual prompt fitting and acknowledged publication.
    """
    payload = build_synthesis_review_context(gap)
    if payload is None or not render_synthesis_review_context(payload):
        return SynthesisPreparationUnavailable("synthesis_match_context_unavailable")
    occurrence = (payload.file, payload.function, payload.line_start)
    if (type(getattr(prior, "line", None)) is not int
            or type(context.get("line_end")) is not int or context.get("line_end") != payload.line_end
            or (getattr(prior, "file", None), getattr(prior, "function", None),
         getattr(prior, "line", None)) != occurrence
            or (context.get("file"), context.get("function"), context.get("line_start")) != occurrence
            or type(context.get("line_start")) is not int):
        return SynthesisPreparationUnavailable("synthesis_occurrence_mismatch")
    scope = getattr(prior, "review_input_scope", None)
    result = getattr(prior, "review_result", None)
    history = read_history(result.get("review_claims")) if isinstance(result, dict) else None
    if (not isinstance(scope, ReviewInputScope) or not isinstance(scope.origin, KnowledgeOrigin)
            or history is None
            or not scope.matches(file=payload.file, function=payload.function,
                                 line_start=payload.line_start, source_inputs=history.get("source_inputs"))
            or scope.origin.line_end != payload.line_end or not scope.current(target_root)):
        return SynthesisPreparationUnavailable("synthesis_original_source_scope_unavailable")
    source = context.get("source")
    if not isinstance(source, str) or not source:
        return SynthesisPreparationUnavailable("synthesis_source_context_unavailable")
    from core.audit.orchestrator import _raw_ihv_review_source

    raw = _raw_ihv_review_source(source, payload.line_start)
    if payload.line_start + len(split_lines(raw)) - 1 != scope.origin.line_end:
        return SynthesisPreparationUnavailable("synthesis_source_span_unavailable")
    observed = capture_source_identity(target_root, payload.file, excerpt=raw,
                                       line_start=payload.line_start)
    if observed is None or observed != scope.origin.source_identity:
        return SynthesisPreparationUnavailable("synthesis_source_context_changed")
    owned_context = dict(context)
    owned_context["synthesis_review_context"] = payload
    return PreparedSynthesisFrame(ReadyReviewFrame(owned_context, prior, (scope,)), payload)
