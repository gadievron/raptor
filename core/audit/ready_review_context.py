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


class ReadyReviewFrame:
    """Pipeline-only prepared payload travelling with an existing reservation."""

    def __init__(self, context, prior, scopes):
        from copy import deepcopy
        self._context = deepcopy(context)
        self.prior = prior
        self.scopes = tuple(scopes)

    def context(self):
        from copy import deepcopy
        return deepcopy(self._context)

    def current(self, outcomes, target_root):
        return (any(item is self.prior for item in outcomes)
                and all(scope.current(target_root) for scope in self.scopes))


def collect_ready_review_frames(runtime, result, config, checklist, context_map, evidence_index, *,
                                ready_joern_gaps, call_edges, classifications,
                                disagreements, cache, assemble):
    """Offer ready advisory sections for declared request owners before reserve.

    This is preparation only. Runtime retains sole reservation/call ownership;
    cached contexts neither acknowledge delivery nor confer evidence authority.
    """
    from collections import defaultdict
    from copy import deepcopy
    from .callee_assessment_context import build_callee_assessment_bundle
    from .callee_review_context import render_callee_context
    from .context import _defend_identifier
    from core.evidence import format_evidence_prose

    # This collector handles captured source geometry only. Binary/hybrid
    # preparation requires its own module/range contract, not decompiler lines.
    if checklist.get("target_kind") == "binary":
        return {}
    owners = {(request.origin.file, request.origin.function, request.origin.line_start)
              for request in (*runtime.requests(), *runtime.caller_requests())
              if request.origin.source_identity is not None
              and type(request.origin.line_start) is int and request.origin.line_start > 0}
    with result._lock:
        outcomes = tuple(result.outcomes)
    grouped = defaultdict(list)
    for prior in outcomes:
        grouped[(prior.file, prior.function, prior.line)].append(prior)
    gaps = defaultdict(list)
    for record in checklist.get("files", ()):
        for item in record.get("items", ()):
            key = (record.get("path"), item.get("name"), item.get("line_start"))
            if key in owners:
                gaps[key].append({**item, "file": record["path"]})
    eligible_gaps = [items[0] for items in gaps.values() if len(items) == 1]
    live = (prepare_ready_live_sinks(result, eligible_gaps, call_edges, classifications)
            if classifications is not None else {})
    mechanical = prepare_ready_disagreement_contexts(result, disagreements)
    frames = {}
    for key in sorted(owners):
        if len(grouped[key]) != 1 or len(gaps[key]) != 1:
            continue
        prior, gap = grouped[key][0], gaps[key][0]
        if prior.status not in {"clean", "suspicious", "finding", "dormant"}:
            continue
        bundle = build_callee_assessment_bundle(prior, outcomes, inventory=config.inventory,
            context_map=context_map, include_graph=config.propagate_constraints,
            target_root=config.target_path)
        contributors = bundle.contributors if bundle is not None else ()
        scopes = tuple(item.review_input_scope for item in (prior, *contributors)
                       if item.review_input_scope is not None)
        if any(not scope.current(config.target_path) for scope in scopes):
            continue
        try:
            payload = {}
            if bundle is not None:
                payload["callee_contract_violation"] = bundle.payload
            if key in live:
                payload["live_sinks"] = live[key]
            if key in mechanical:
                payload["disagreement_override"] = mechanical[key]
            evidence = evidence_index.get(f"{key[0]}:{key[1]}")
            rendered_evidence = format_evidence_prose(evidence) if evidence is not None else ""
            signature = (id(prior), prior.status, prior.body, prior.hypothesis,
                         deepcopy(prior.review_result), deepcopy(payload), rendered_evidence,
                         tuple(id(scope) for scope in scopes))
            cached = cache.get(key)
            if cached is not None and cached[0] == signature:
                frame = cached[1]
            else:
                ctx = assemble(gap)
                ctx.update(deepcopy(payload))
                frame = ReadyReviewFrame(ctx, prior, scopes)
                cache[key] = (signature, frame)
            ctx = frame.context()
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            # Optional preparation never turns unavailable inputs into an
            # accepted context, nor aborts unrelated initial reviews.
            continue
        offer_ready_joern_context(runtime, ctx, gap, ready_joern_gaps, evidence_index)
        offer_ready_live_sink_context(runtime, ctx)
        offer_ready_disagreement_context(runtime, ctx)
        value = render_callee_context(ctx.get("callee_contract_violation"), defend_identifier=_defend_identifier)
        if value:
            runtime.offer_context_delta(ctx, kind="callee_contract", version=context_version(value))
        frames[key] = frame
    for key in set(cache) - owners:
        del cache[key]
    return frames
