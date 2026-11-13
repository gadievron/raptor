"""Recombine original Runtime-owned source scopes for an initial panel."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from .review_claims import read_history
from .review_context_inputs import context_inputs_record_digest, merge_context_inputs
from .review_input_scope import MAX_LIVE_INPUTS, ReviewInputScope


def combine_source_panel_scope(
    outcome: Any, *, members: object,
    owned: Callable[[tuple[str, str]], ReviewInputScope | None], target_root: Path,
) -> ReviewInputScope | None:
    """Bind only the exact union of successfully captured member inputs.

    Durable records select original owner-held scopes; they cannot restore
    physical stamps. Conflicting versions and roots stay in the live union
    for the existing currentness barrier to refuse. No source is recaptured.
    """
    result = getattr(outcome, "review_result", None)
    history = read_history(result.get("review_claims")) if isinstance(result, dict) else None
    if history is None:
        return None
    primary = history.get("review")
    if not isinstance(primary, dict):
        return None
    origin = primary.get("origin")
    if not isinstance(origin, dict):
        return None
    primary_pass, primary_attempt = origin.get("pass_id"), primary.get("attempt_id")
    if (not isinstance(primary_pass, str) or not primary_pass
            or not isinstance(primary_attempt, str) or not primary_attempt):
        return None
    line = getattr(outcome, "line", 0)
    if type(line) is not int or line < 0:
        return None
    if line == 0:
        line = origin.get("line_start")
    if type(line) is not int or line <= 0:
        return None
    expected_site = (outcome.file, outcome.function, line)
    if members is None:
        members = [result]
    if not isinstance(members, (list, tuple)) or not members:
        return None
    scopes: dict[tuple[str, str], ReviewInputScope] = {}
    manifests = []
    for member in members:
        if isinstance(member, dict) and member.get("status") == "error":
            return None
        member_history = read_history(member.get("review_claims")) if isinstance(member, dict) else None
        if member_history is None:
            return None
        review = member_history.get("review")
        if not isinstance(review, dict):
            return None
        member_origin = review.get("origin")
        if not isinstance(member_origin, dict):
            return None
        pass_id, attempt_id = member_origin.get("pass_id"), review.get("attempt_id")
        if (not isinstance(pass_id, str) or not pass_id
                or not isinstance(attempt_id, str) or not attempt_id):
            return None
        scope = owned((pass_id, attempt_id))
        if (not isinstance(scope, ReviewInputScope)
                or type(member_origin.get("line_start")) is not int
                or (scope.origin.file, scope.origin.function, scope.origin.line_start) != expected_site
                or scope.origin.source_identity is None):
            return None
        try:
            if json.dumps(member_origin, sort_keys=True, allow_nan=False) != json.dumps(
                    asdict(scope.origin), sort_keys=True, allow_nan=False):
                return None
        except (TypeError, ValueError):
            return None
        manifest = member_history.get("source_inputs")
        if context_inputs_record_digest(manifest) != scope.record_digest:
            return None
        scopes[(pass_id, attempt_id)] = scope
        manifests.append(manifest)
    primary_scope = scopes.get((primary_pass, primary_attempt))
    if primary_scope is None:
        return None
    try:
        if json.dumps(origin, sort_keys=True, allow_nan=False) != json.dumps(
                asdict(primary_scope.origin), sort_keys=True, allow_nan=False):
            return None
    except (TypeError, ValueError):
        return None
    if any(scope.origin.source_identity != primary_scope.origin.source_identity for scope in scopes.values()):
        return None
    digest = context_inputs_record_digest(merge_context_inputs(*manifests))
    if digest is None or context_inputs_record_digest(history.get("source_inputs")) != digest:
        return None
    inputs = dict.fromkeys(source for scope in scopes.values() for source in scope.inputs)
    if len(inputs) > MAX_LIVE_INPUTS:
        return None
    combined = ReviewInputScope(primary_scope.origin, digest, tuple(inputs))
    return combined if combined.current(target_root) else None
