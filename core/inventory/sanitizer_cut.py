"""Vertex-cut sanitizer suppressor — Phase 7 of the sanitizer-cut arc.

The structural FP reduction this arc was designed for. Given a finding
with a source location, a sink location, a CWE, and a language, the
suppressor answers one question:

    Does every dynamic path from source to sink cross at least one
    sanitizer recognized by the catalog?

If yes → the taint cannot reach the sink in any execution; suppress
the finding without an LLM call.

Algorithm (per ``docs/design-aggregation-dominators-wp.md`` Phase 7,
algorithm correction): a **vertex cut**.

    Suppress iff ``sink`` is unreachable from ``source`` in
    ``CFG \\ candidate_sanitizers``.

Equivalent intuition: remove every candidate sanitizer node from the
graph. If the sink becomes unreachable, every path was sanitized; if
the sink is still reachable, at least one path bypassed the
sanitizer (it was on some paths but not all) and the finding has to
go to the LLM.

Candidates come from
:func:`core.dataflow.sanitizer_catalog.match_sanitizers_in_cfg`
(every node whose statement-level calls intersect the CWE-derived
sanitizer set). No dominator-tree pre-filtering: the canonical
symmetric-sanitize case (sanitizer in both ``if`` and ``else``
branches) has the property that no single sanitizer dominates the
sink, yet their union cuts every path. Vertex-cut is a *set*
property and must be checked over the full candidate set. The
vertex-cut check itself is BFS — O(V + E).

Compared to the existing lexical check at
``core/dataflow/smt_barrier.py:1189``
(``line < sink_line and not _crosses_function_boundary(...)``), this
suppressor handles the case where a sanitizer is in a sibling
``if/elif`` branch that doesn't lexically precede the sink but is on
every dynamic path to it.

This module is pure: no IO, no logging side-effects, no scorecard
writes. The Phase 7b helper :func:`record_sanitizer_cut_suppression`
bridges the result into ``suppressions.jsonl`` for the audit trail.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    Dict,
    FrozenSet,
    Iterable,
    Set,
)

from core.dataflow.sanitizer_catalog import (
    match_sanitizers_in_cfg,
    nodes_of,
    sanitizer_callables_for_cwe,
)


logger = logging.getLogger(__name__)


# Verdict tag emitted by Phase 7b into ``suppressions.jsonl``. Sister
# tag of the binary-oracle's ``binary_oracle_absent`` — same shape, same
# file. Operators query both via the same grep.
VERDICT_SANITIZER_DOMINATED = "sanitizer_dominated"


@dataclass(frozen=True)
class SanitizerCutResult:
    """Outcome of a vertex-cut suppression check.

    ``suppress`` is the headline boolean — True iff every path from
    every source to the sink crossed a sanitizer. Phase 7b's caller
    just looks at this and either drops the finding or sends it to
    the LLM.

    ``cut_set`` is the witnessing set: the sanitizer nodes whose
    removal disconnected the sink. Empty when ``suppress`` is False
    (the finding survives) or when no sanitizer candidates were
    found.

    ``reason`` is a short human-facing string for the JSONL audit
    record. ``candidate_callables`` is the catalog-derived set the
    cut was attempted against; useful for explaining "we tried these
    but none were present on the path" in the negative case.
    """
    suppress: bool
    reason: str
    cut_set: FrozenSet
    candidate_callables: FrozenSet[str]


def _bfs_reachable_excluding(
    graph,
    sources: Iterable,
    excluded: Set,
) -> Set:
    """BFS from each source over ``graph``, skipping every node in
    ``excluded``. Returns the set of nodes reached. The excluded set
    IS removed: edges into excluded nodes are never traversed, edges
    out of them are never produced.

    Pure function; does not mutate ``graph``.
    """
    seen: Set = set()
    queue: deque = deque()
    for s in sources:
        if s not in excluded and s not in seen:
            seen.add(s)
            queue.append(s)
    while queue:
        node = queue.popleft()
        for nxt in graph.successors(node):
            if nxt in excluded or nxt in seen:
                continue
            seen.add(nxt)
            queue.append(nxt)
    return seen


def sanitizer_cuts_source_to_sink(
    graph,
    sources: Iterable,
    sink,
    cut_set: Iterable,
) -> bool:
    """Return True iff removing every node in ``cut_set`` disconnects
    ``sink`` from every node in ``sources``.

    Multi-source semantics: the check is "no source reaches sink".
    Equivalent to BFS from ``sources ∪`` over ``graph \\ cut_set``
    and asking whether ``sink`` is in the result.

    Pure graph reachability — no language semantics, no catalog
    lookup, no logging. The caller (typically
    :func:`evaluate_finding`) is responsible for constructing
    ``cut_set`` from the sanitizer catalog.
    """
    cut: Set = set(cut_set)
    if sink in cut:
        # Sink itself is a sanitizer — by convention we still call
        # this "cut": removing the sink from the graph trivially
        # disconnects it. Defensive.
        return True
    reachable = _bfs_reachable_excluding(graph, sources, cut)
    return sink not in reachable


def evaluate_finding(
    graph,
    sources: Iterable,
    sink,
    *,
    cwe: str,
    language: str,
) -> SanitizerCutResult:
    """The full Phase 7 decision for one finding.

    1. Look up :func:`sanitizer_callables_for_cwe(cwe, language)`. If
       empty (CWE not in mapping, or language not in catalog), bail
       out with ``suppress=False`` — we cannot prove sanitization.
    2. Find candidate sanitizer nodes in the graph via
       :func:`match_sanitizers_in_cfg`. The full set is used as the
       cut candidate; no dominator pre-filtering. A previous draft
       narrowed to dominators of the sink as a perceived optimisation,
       but that was incorrect: in the symmetric-sanitize case
       (sanitizer in BOTH ``if`` and ``else`` branches), neither
       call dominates the sink individually, yet their union cuts
       every path. Vertex-cut is a *set* property, not an individual-
       node property.
    3. Run :func:`sanitizer_cuts_source_to_sink` with the candidate
       set. If it disconnects the sink → suppress.

    Including a sanitizer node that's not on any source-to-sink path
    is harmless — removing more nodes from a BFS can only shrink the
    reachable set, never grow it. So the algorithm is sound without
    the pre-filter, and correctly handles the canonical case the
    lexical check at ``smt_barrier.py:1189`` misses.
    """
    sources_set = set(sources)
    if not sources_set:
        return SanitizerCutResult(
            suppress=False,
            reason="no sources supplied",
            cut_set=frozenset(),
            candidate_callables=frozenset(),
        )
    if sink is None:
        return SanitizerCutResult(
            suppress=False,
            reason="no sink supplied",
            cut_set=frozenset(),
            candidate_callables=frozenset(),
        )

    candidate_callables = sanitizer_callables_for_cwe(cwe, language)
    if not candidate_callables:
        return SanitizerCutResult(
            suppress=False,
            reason=(
                f"no catalog sanitizers for cwe={cwe!r} language={language!r}"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(),
        )

    matched_bindings = match_sanitizers_in_cfg(graph, cwe, language)
    if not matched_bindings:
        return SanitizerCutResult(
            suppress=False,
            reason="no sanitizer calls found in this CFG",
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
        )

    # The full set of catalog-matched sanitizer nodes is the cut
    # candidate. A previous draft narrowed this with the sink's
    # dominator set as an "optimisation", but that was incorrect: in
    # the symmetric-sanitize case (both ``if`` and ``else`` branches
    # call the same sanitizer), neither call dominates the sink
    # individually, but their *union* cuts every path. The vertex-cut
    # property is a property of the set, not of individual members,
    # so narrowing to dominators silently loses correct suppressions.
    #
    # Without narrowing, the worst case is an irrelevant sanitizer
    # node further down the graph wastefully included in the cut —
    # which is harmless (removing more nodes can only make BFS
    # reachability *fewer*, never more).
    #
    # Phase 3 changed the recognizer's return type from a set of
    # nodes to a set of :class:`SanitizerBinding` records (one per
    # matched call, with input/output symbols for Phase 4's
    # value-binding gate). For control-flow-only suppression we
    # project bindings back to their nodes via :func:`nodes_of`. The
    # vertex-cut consumer was never node-aware in any subtler way,
    # so this is a pure projection — the suppression decision is
    # bit-identical to Phase 7's behaviour before the rev.
    cut_candidates = nodes_of(matched_bindings)

    cuts = sanitizer_cuts_source_to_sink(
        graph, sources_set, sink, cut_candidates,
    )
    if cuts:
        return SanitizerCutResult(
            suppress=True,
            reason=(
                f"vertex-cut: sink unreachable from "
                f"{len(sources_set)} source(s) after removing "
                f"{len(cut_candidates)} sanitizer node(s)"
            ),
            cut_set=frozenset(cut_candidates),
            candidate_callables=frozenset(candidate_callables),
        )
    return SanitizerCutResult(
        suppress=False,
        reason=(
            "vertex-cut: sink still reachable after sanitizer removal — "
            "at least one path bypasses every catalog sanitizer"
        ),
        cut_set=frozenset(),
        candidate_callables=frozenset(candidate_callables),
    )


# ---------------------------------------------------------------------------
# Phase 7b — JSONL audit-trail integration
# ---------------------------------------------------------------------------


def record_sanitizer_cut_suppression(
    out_dir: Path,
    finding: Dict[str, Any],
    result: SanitizerCutResult,
) -> None:
    """Write a sanitizer-cut suppression to ``suppressions.jsonl``.

    Delegates to :func:`core.inventory.reach_chokepoint.record_suppression`
    so the audit JSONL shape matches the binary-oracle suppressor's
    (same file, same record schema). The ``verdict`` is set to
    :data:`VERDICT_SANITIZER_DOMINATED` so operators can grep / filter
    by verdict kind.

    No-op when ``result.suppress`` is False — the chokepoint records
    DROPPED findings, not surviving ones.
    """
    if not result.suppress:
        return
    from core.inventory.reach_chokepoint import record_suppression

    record_suppression(
        out_dir,
        finding=finding,
        verdict=VERDICT_SANITIZER_DOMINATED,
        reason=result.reason,
    )


__all__ = [
    "VERDICT_SANITIZER_DOMINATED",
    "SanitizerCutResult",
    "sanitizer_cuts_source_to_sink",
    "evaluate_finding",
    "record_sanitizer_cut_suppression",
]
