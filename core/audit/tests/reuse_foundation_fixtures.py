"""Real source and fitted reference receipts for reuse-domain fixtures."""

from pathlib import Path

from core.audit.context import format_context_for_prompt
from core.audit.gaps import read_gap_source
from core.audit.reference_foundation import foundation_answers
from core.audit.reference_inputs import reference_inputs_from_delivery, review_context_digest
from core.audit.refutation_source import capture_source_identity
from core.audit.review_context_inputs import context_inputs_from_sources
from core.audit.source_anchor import make_context_source_anchor
from core.staleness import hash_span


def current_foundation_fields(target: Path, file: str, line_start: int, line_end: int) -> dict:
    """Stamp an owned measured site at review time, before any source changes.

    Invalid or unavailable geometry is an error, never a request to infer a
    replacement site. Callers keep deliberately legacy rows outside this helper.
    """
    source = read_gap_source({"file": file, "line_start": line_start,
                              "line_end": line_end}, target)
    identity = capture_source_identity(target, file)
    if not source or identity is None:
        raise ValueError("current foundation fixture requires readable measured source")
    answers = foundation_answers("c", request_id="reuse-fixture", source=source, file=file)
    context = {"file": file, "line_start": line_start, "line_end": line_end,
               "source": source, "language": "c", "language_reference_answers": answers}
    format_context_for_prompt(context, budget_limit=100_000)
    references = reference_inputs_from_delivery(context["language_reference_delivery"], answers)
    sources = context_inputs_from_sources((("target", file, identity.sha256),))
    history = {"version": 1, "role": "review-history-only", "review": None,
               "intakes": [], "complete": False, "omissions": [],
               "source_inputs": sources, "reference_inputs": references}
    digest = review_context_digest(sources, references)
    if digest is None:
        raise ValueError("current foundation fixture requires bound delivered inputs")
    return {"source_hash": make_context_source_anchor(identity.sha256,
                hash_span(target / file, line_start, line_end), digest, context_version=3),
            "review_claims": history}


def current_review_fields(target: Path, fields: dict, overrides: dict) -> dict:
    """Bind requested positive sites, preserving explicit legacy refusal inputs."""
    result = {**fields, **overrides}
    file, start, end = result["file"], result["line_start"], result["line_end"]
    source = read_gap_source({"file": file, "line_start": start, "line_end": end}, target)
    if not source:
        return result
    # Only an actual current span hash is a positive explicit hash input.
    # Empty, stale, malformed and already-bound historical stamps stay exact.
    if "source_hash" in overrides and overrides["source_hash"] != hash_span(target / file, start, end):
        return result
    result.update(current_foundation_fields(target, file, start, end))
    if "review_claims" in overrides:
        result["review_claims"] = overrides["review_claims"]
    return result
