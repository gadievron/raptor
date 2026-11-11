"""Offer already-ready, occurrence-bound context before one review reservation."""
from __future__ import annotations

from .continuation_context import context_version


def offer_ready_joern_context(runtime, ctx, gap, ready_gaps, evidence_index) -> bool:
    """Coalesce a completed producer's actual section, without waiting for it.

    The caller supplies its pipeline-owned pre-build review inventory. Bare
    function names and legacy records without occurrence bounds do not qualify.
    This offers advisory analysis context, never verification authority.
    """
    occurrence = (gap.get("file"), gap.get("name"), gap.get("line_start"))
    if type(occurrence[2]) is not int or occurrence[2] <= 0:
        return False
    if not any((item.get("file"), item.get("name"), item.get("line_start")) == occurrence
               for item in ready_gaps):
        return False
    record = evidence_index.get(f"{occurrence[0]}:{occurrence[1]}")
    if (record is None or (record.file, record.function, record.line_start) != occurrence
            or not record.joern_flows):
        return False
    value = ctx.get("mechanical_evidence")
    if not isinstance(value, str) or not value:
        return False
    return runtime.offer_context_delta(ctx, kind="late_joern", version=context_version(value))


def prepare_ready_live_sinks(result, gaps, call_edges, classifications):
    """Snapshot classification leads for exact, already-known caller units."""
    from collections import defaultdict

    outcomes = defaultdict(list)
    declarations = defaultdict(set)
    for outcome in result.outcomes:
        key = (outcome.file, outcome.function, outcome.line)
        outcomes[key].append(outcome)
        declarations[key[:2]].add(key)
    edges = defaultdict(list)
    for edge in call_edges or ():
        if isinstance(edge, dict):
            edges[(edge.get("caller_file"), edge.get("caller"))].append(edge)
    names = tuple(sorted(classifications.sinks))
    ready = {}
    for gap in gaps:
        key = (gap.get("file"), gap.get("name"), gap.get("line_start"))
        if type(key[2]) is not int or key[2] <= 0 or len(outcomes.get(key, ())) != 1:
            continue
        callees = []
        for edge in edges.get(key[:2], ()):
            line = edge.get("caller_line_start", edge.get("caller_line", 0))
            if type(line) is not int or line < 0:
                continue
            if (line and line != key[2]) or (not line and len(declarations[key[:2]]) != 1):
                continue
            name = edge.get("callee")
            if isinstance(name, str) and name:
                callees.append(name)
        if classifications.should_upgrade_triage(f"{key[0]}:{key[1]}", callees):
            ready[key] = names
    return ready


def offer_ready_live_sink_context(runtime, ctx):
    """Offer an actual rendered advisory section, never a caller-owned flag."""
    from .context import _defend_identifier
    from .live_sink_continuation import render_live_sink_context

    value = render_live_sink_context(ctx.get("live_sinks"), defend_identifier=_defend_identifier)
    return bool(value and runtime.offer_context_delta(ctx, kind="live_sinks", version=context_version(value)))


def prepare_ready_disagreement_contexts(result, disagreements):
    """Collect one unambiguous advisory mechanical record per source unit."""
    from collections import defaultdict
    from .layer_resolution import LayerVerdict

    declarations = defaultdict(list)
    for outcome in result.outcomes:
        declarations[(outcome.file, outcome.function)].append(outcome)
    grouped = defaultdict(list)
    for disagreement in disagreements or ():
        if disagreement.winner != LayerVerdict.MECHANICAL:
            continue
        matches = declarations.get((disagreement.file, disagreement.function), ())
        line = getattr(disagreement, "line_start", None)
        if type(line) is int and line > 0:
            matches = [outcome for outcome in matches if outcome.line == line]
        if len(matches) != 1:
            continue
        outcome = matches[0]
        key = (outcome.file, outcome.function, outcome.line)
        claim = disagreement.mechanical_claim
        payload = {"resolution": disagreement.resolution,
                   "mechanical_reachable": claim.reachable if claim else None,
                   "mechanical_has_flow": claim.has_flow if claim else None}
        if payload not in grouped[key]:
            grouped[key].append(payload)
    return {key: claims[0] for key, claims in grouped.items() if len(claims) == 1}


def offer_ready_disagreement_context(runtime, ctx):
    """Offer the same exact advisory section used by the later adapter."""
    from .context import _defend_identifier
    from .disagreement_review_context import render_disagreement_context

    value = render_disagreement_context(ctx.get("disagreement_override"), defend_identifier=_defend_identifier)
    return bool(value and runtime.offer_context_delta(ctx, kind="disagreement", version=context_version(value)))
