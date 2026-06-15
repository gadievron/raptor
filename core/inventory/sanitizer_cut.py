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
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    match_sanitizers_in_cfg,
    nodes_of,
    sanitizer_callables_for_cwe,
)
from core.inventory.dataflow import (
    ReachingDefs,
    reaching_defs,
)


logger = logging.getLogger(__name__)


# Verdict tags emitted into ``suppressions.jsonl``. Sister tags of the
# binary-oracle's ``binary_oracle_absent`` — same shape, same file,
# greppable by operators with one ``jq`` invocation.
#
# ``sanitizer_dominated`` records a Phase 4 ``suppress`` — the
# finding was dropped; ``dropped: true``.
# ``sanitizer_candidate`` records a Phase 4 ``candidate_only`` — the
# control-flow cut held but the value-bound gate didn't fire; the
# finding SURVIVED to the LLM; ``dropped: false``. Phase 6 added this
# tag so operators can see what the value-bound suppressor saw but
# didn't act on.
VERDICT_SANITIZER_DOMINATED = "sanitizer_dominated"
VERDICT_SANITIZER_CANDIDATE = "sanitizer_candidate"


# Phase 4 suppression-verdict tri-state. The legacy ``suppress: bool``
# field on :class:`SanitizerCutResult` stays — it's True iff
# ``verdict == VERDICT_SUPPRESS``. New callers should read ``verdict``
# directly to distinguish "control-flow argument holds but value
# binding unproven" (the new candidate_only state) from "the
# control-flow cut failed entirely."
VERDICT_SUPPRESS = "suppress"
VERDICT_CANDIDATE_ONLY = "candidate_only"
VERDICT_NO_SUPPRESS = "no_suppress"


@dataclass(frozen=True)
class SanitizerCutResult:
    """Outcome of a vertex-cut suppression check.

    ``suppress`` is the legacy boolean — True iff every value-bound
    path from every source to the sink crossed a sanitizer. Phase 7b's
    record helper reads this to decide whether to drop the finding.

    ``verdict`` is the Phase 4 tri-state — one of
    :data:`VERDICT_SUPPRESS`, :data:`VERDICT_CANDIDATE_ONLY`,
    :data:`VERDICT_NO_SUPPRESS`. ``candidate_only`` means the
    control-flow cut holds but the four-condition value-binding gate
    didn't — a useful audit / LLM hint without a drop. Defaults to
    ``"suppress"`` or ``"no_suppress"`` derived from ``suppress``
    when callers construct the result without specifying verdict, so
    existing Phase 7 constructors keep working unchanged.

    ``cut_set`` is the witnessing set: the sanitizer nodes whose
    removal disconnected the sink. Non-empty only when
    ``verdict == VERDICT_SUPPRESS``.

    ``reason`` is a short human-facing string for the JSONL audit
    record. ``candidate_callables`` is the catalog-derived set the
    cut was attempted against; useful for explaining "we tried these
    but none were present on the path" in the negative case.

    Phase 6 added the binding-witness fields so the audit JSONL
    record can carry the exact sanitizer calls + symbols the
    decision was based on:

    * ``value_bound_bindings`` — the bindings that satisfied gate
      conditions 2 AND 3 (taint flows in AND output reaches sink).
      Non-empty for ``VERDICT_SUPPRESS``; empty for the other two
      verdicts.
    * ``all_matched_bindings`` — every catalog match in the CFG,
      regardless of value binding. Non-empty for both
      ``VERDICT_SUPPRESS`` and ``VERDICT_CANDIDATE_ONLY`` (the
      ``candidate_only`` audit record needs them so operators can
      see what was tried).
    * ``sink_arg`` — the symbol consumed at the sink, supplied by
      the Phase 5 resolver. Empty when value context wasn't given.

    Phase 7's legacy callers don't supply value context, so all
    three fields stay at their defaults — the JSONL record omits
    the corresponding keys (or writes empty lists / strings).
    """
    suppress: bool
    reason: str
    cut_set: FrozenSet
    candidate_callables: FrozenSet[str]
    verdict: str = ""
    value_bound_bindings: FrozenSet[SanitizerBinding] = frozenset()
    all_matched_bindings: FrozenSet[SanitizerBinding] = frozenset()
    sink_arg: str = ""

    def __post_init__(self) -> None:
        # Default verdict derives from the legacy ``suppress`` flag
        # so phase 7 constructors (and any user code that built a
        # result without specifying verdict) keep working. Use
        # object.__setattr__ since the dataclass is frozen.
        if not self.verdict:
            v = VERDICT_SUPPRESS if self.suppress else VERDICT_NO_SUPPRESS
            object.__setattr__(self, "verdict", v)
            return
        # Explicit verdict — sanity-check consistency with suppress.
        # candidate_only and no_suppress both leave suppress=False;
        # suppress=True only pairs with verdict=suppress.
        if self.suppress and self.verdict != VERDICT_SUPPRESS:
            raise ValueError(
                f"suppress=True requires verdict={VERDICT_SUPPRESS!r}, "
                f"got verdict={self.verdict!r}"
            )
        if not self.suppress and self.verdict == VERDICT_SUPPRESS:
            raise ValueError(
                f"verdict={VERDICT_SUPPRESS!r} requires suppress=True, "
                "got suppress=False"
            )


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


def _may_escape_on_path(
    graph,
    sources: Iterable,
    sink,
    excluded: Set,
) -> bool:
    """Phase 10 — True iff any node with ``may_escape=True`` lies on
    a source→sink path in ``graph``, after removing ``excluded`` (the
    value-bound sanitizer cut). Forward-reachable-from-sources
    intersected with backward-reachable-to-sink gives the on-path set;
    we early-return on the first ``may_escape`` hit.

    Cheap: O(V + E) per call (one forward BFS + one reverse BFS).
    Pure function. Uses ``getattr(node, "may_escape", False)`` so
    PyCFGNode (which lacks the attribute) always returns False — the
    Python evaluate_finding paths stay bit-identical.
    """
    excl: Set = set(excluded) if excluded else set()

    # Forward BFS from sources.
    forward: Set = set()
    queue: deque = deque()
    for s in sources:
        if s not in excl and s not in forward:
            forward.add(s)
            queue.append(s)
    while queue:
        node = queue.popleft()
        for nxt in graph.successors(node):
            if nxt in excl or nxt in forward:
                continue
            forward.add(nxt)
            queue.append(nxt)

    # Build reverse adjacency for the backward walk. graph only
    # exposes successors(), so we build a one-shot reverse index over
    # the forward-reachable set (everything else is irrelevant — a
    # node not in ``forward`` can't be on a source→sink path).
    predecessors: Dict[Any, List[Any]] = {}
    for n in forward:
        for succ in graph.successors(n):
            if succ in forward:
                predecessors.setdefault(succ, []).append(n)

    # Backward BFS from sink. ``sink`` itself isn't necessarily in
    # ``forward`` (the cut might disconnect it — but then the
    # surrounding evaluate_finding wouldn't be checking us). Seed
    # only if it is.
    if sink not in forward:
        return False
    backward: Set = {sink}
    rqueue: deque = deque([sink])
    while rqueue:
        node = rqueue.popleft()
        for prev in predecessors.get(node, ()):
            if prev in backward:
                continue
            backward.add(prev)
            rqueue.append(prev)

    # On-path = forward ∩ backward. Check may_escape on each.
    for n in backward:
        if getattr(n, "may_escape", False):
            return True
    return False


def _propagate_taint(
    graph,
    rd: ReachingDefs,
    source_nodes: Iterable,
    source_symbols: Iterable[str],
) -> Mapping[Any, FrozenSet[str]]:
    """Compute the tainted-symbol set at every node's IN.

    Per-def taint is recorded in ``taint[(node, symbol)]``:

    * A def is *initially tainted* if it lives on a source node and
      its symbol is in ``source_symbols``. For ``cfg.entry`` as a
      source, the virtual param defs from
      :class:`PythonCFG.params` get the same treatment.
    * A def is *transitively tainted* if the defining node's
      ``uses`` overlap with any tainted symbol at the node's IN.

    The result projects per-node IN-tainted symbol sets — exactly
    what Phase 4 condition 2 needs to check whether the sanitizer's
    bare-name inputs intersect the live taint.

    Conservative: a sanitizer's output stays "tainted" under this
    model because we only mark transitive taint through the node's
    uses without modelling sanitization. This is fine for condition
    2 (which checks the sanitizer's IN, before it runs) and Phase 3
    handles the cleaned-output side via empty ``output_symbols`` on
    nested calls.
    """
    sources_set = set(source_nodes)
    src_syms = set(source_symbols) if source_symbols else set()
    if not src_syms:
        return {n: frozenset() for n in graph.nodes()}

    taint: Dict[Tuple[Any, str], bool] = {}

    # Seed: source_symbols at source nodes (body sources) and the
    # virtual entry defs for param sources.
    entry = getattr(graph, "entry", None)
    params: Tuple[str, ...] = tuple(getattr(graph, "params", ()) or ())
    for n in graph.nodes():
        if n not in sources_set:
            continue
        node_defs: FrozenSet[str] = getattr(n, "defs", frozenset())
        for s in node_defs & src_syms:
            taint[(n, s)] = True
        if n is entry:
            for p in params:
                if p in src_syms:
                    taint[(n, p)] = True

    # Iterate to fixed point. Monotone: taint only grows.
    changed = True
    while changed:
        changed = False
        for n in graph.nodes():
            tainted_in: Set[str] = set()
            for sym, definers in rd.all_at(n).items():
                for d in definers:
                    if taint.get((d, sym), False):
                        tainted_in.add(sym)
                        break
            uses: FrozenSet[str] = getattr(n, "uses", frozenset())
            if not (uses & tainted_in):
                continue
            node_defs = getattr(n, "defs", frozenset())
            for s in node_defs:
                if not taint.get((n, s), False):
                    taint[(n, s)] = True
                    changed = True

    # Project to per-node IN tainted symbol sets.
    result: Dict[Any, FrozenSet[str]] = {}
    for n in graph.nodes():
        tainted: Set[str] = set()
        for sym, definers in rd.all_at(n).items():
            for d in definers:
                if taint.get((d, sym), False):
                    tainted.add(sym)
                    break
        result[n] = frozenset(tainted)
    return result


def _binding_satisfies_value_gate(
    binding: SanitizerBinding,
    rd: ReachingDefs,
    tainted_at: Mapping[Any, FrozenSet[str]],
    sink: Any,
    sink_arg: str,
) -> bool:
    """Phase 4 conditions 2 and 3 for one binding.

    Condition 2: at least one of the binding's bare-name inputs is
    tainted at the binding's node IN. (Condition 1 — catalog match
    by callable — is already filtered upstream by
    :func:`match_sanitizers_in_cfg`.)

    Condition 3: the binding's call assigns ``sink_arg`` as one of
    its outputs AND the binding's node is among the reaching
    definers of ``sink_arg`` at the sink (i.e. the cleaned value
    actually arrives at the sink without being overwritten).
    """
    # Condition 2 — tainted-input check
    tainted_in = tainted_at.get(binding.node, frozenset())
    if not (binding.input_symbols & tainted_in):
        return False
    # Condition 3 — output reaches sink arg
    if sink_arg not in binding.output_symbols:
        return False
    if binding.node not in rd.at(sink, sink_arg):
        return False
    return True


def evaluate_finding(
    graph,
    sources: Iterable,
    sink,
    *,
    cwe: str,
    language: str,
    source_symbols: Optional[Iterable[str]] = None,
    sink_arg: Optional[str] = None,
    extra_bindings: Optional[Iterable[SanitizerBinding]] = None,
) -> SanitizerCutResult:
    """Phase 4 suppression decision for one finding.

    Backward-compatible with Phase 7 callers: omit ``source_symbols``
    and ``sink_arg`` → control-flow-only vertex-cut. Verdict is
    :data:`VERDICT_SUPPRESS` or :data:`VERDICT_NO_SUPPRESS`; no
    ``candidate_only`` is emitted because the gate isn't run.

    ``extra_bindings`` (Phase 14) are inter-procedural synthetic
    sanitizer bindings — typically from
    :func:`core.inventory.interproc.synthetic_sanitizer_bindings`.
    They are unioned into the catalog-matched bindings before the
    gate runs, so a sanitizer inside an in-module helper counts
    toward the cut. Each synthetic binding carries real
    ``input_symbols`` / ``output_symbols`` so it participates in the
    value-bound gate exactly like a direct sanitizer call. Omitted /
    empty → intra-procedural behaviour, bit-identical to Phase 11.

    With value context provided, the four-condition gate:

      1. ``binding.callable ∈ sanitizer_callables_for_cwe`` —
         already enforced by :func:`match_sanitizers_in_cfg`.
      2. ``binding.input_symbols ∩ symbols_tainted_at(binding.node)``
         non-empty — actual taint flows into the sanitizer.
      3. ``sink_arg ∈ binding.output_symbols`` AND
         ``binding.node ∈ rd.at(sink, sink_arg)`` — the cleaned
         value reaches the sink without being overwritten.
      4. Removing the bindings that satisfy (2) and (3) from the
         graph cuts every source → sink path.

    Verdict:

    * :data:`VERDICT_SUPPRESS` — all four hold.
    * :data:`VERDICT_CANDIDATE_ONLY` — control-flow cut over the
      *full* binding set still holds, but the value-bound subset
      doesn't cut. The sanitizer is on every path but value binding
      is unproven. Phase 6 will write this to ``suppressions.jsonl``
      with ``dropped: false`` so operators can see it.
    * :data:`VERDICT_NO_SUPPRESS` — control-flow cut fails. At least
      one path bypasses every catalog sanitizer.

    The C/C++ call-graph case is handled by Phase 3's recognizer:
    callgraph bindings carry empty input/output symbols, so
    condition 2 always fails for them. When value context is
    provided, callgraph findings auto-downgrade to
    ``candidate_only`` (if control-flow cut held) or
    ``no_suppress``. Without value context they reach the legacy
    control-flow path and either suppress or no_suppress as before.
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
    # Phase 14 — fold in inter-procedural synthetic bindings. A
    # finding whose enclosing function has NO direct catalog
    # sanitizer but DOES call an in-module helper that sanitizes
    # reaches the gate only because of these.
    if extra_bindings:
        matched_bindings = matched_bindings | frozenset(extra_bindings)
    if not matched_bindings:
        return SanitizerCutResult(
            suppress=False,
            reason="no sanitizer calls found in this CFG",
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
        )

    # Full-set control-flow cut over every matched binding's node.
    # Computing this once lets us:
    #   * decide the legacy path (no value context) directly, and
    #   * judge candidate_only vs no_suppress in the value-bound
    #     path (candidate_only requires the full-set cut to hold).
    full_cf_nodes = nodes_of(matched_bindings)
    full_cf_cut = sanitizer_cuts_source_to_sink(
        graph, sources_set, sink, full_cf_nodes,
    )

    # Legacy control-flow-only path. Suppression bit-identical to
    # Phase 7 behaviour — Phase 5 wrapper code or older callers
    # that haven't been taught about value binding land here.
    if source_symbols is None or sink_arg is None:
        if full_cf_cut:
            return SanitizerCutResult(
                suppress=True,
                reason=(
                    f"vertex-cut: sink unreachable from "
                    f"{len(sources_set)} source(s) after removing "
                    f"{len(full_cf_nodes)} sanitizer node(s)"
                ),
                cut_set=frozenset(full_cf_nodes),
                candidate_callables=frozenset(candidate_callables),
                verdict=VERDICT_SUPPRESS,
            )
        return SanitizerCutResult(
            suppress=False,
            reason=(
                "vertex-cut: sink still reachable after sanitizer "
                "removal — at least one path bypasses every catalog "
                "sanitizer"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
            verdict=VERDICT_NO_SUPPRESS,
        )

    # Value-bound path — Phase 4's four-condition gate. Compute
    # reaching-defs + taint front, then per-binding gate, then
    # value-bound vertex cut.
    rd = reaching_defs(graph)
    tainted_at = _propagate_taint(graph, rd, sources_set, source_symbols)
    value_bound_bindings = frozenset(
        b for b in matched_bindings
        if _binding_satisfies_value_gate(b, rd, tainted_at, sink, sink_arg)
    )
    value_bound_nodes = {b.node for b in value_bound_bindings}
    value_bound_cut = sanitizer_cuts_source_to_sink(
        graph, sources_set, sink, value_bound_nodes,
    )

    if value_bound_cut:
        # Phase 10 — pointer/alias conservatism. If any node on a
        # source→sink path in the *un-cut* graph is ``may_escape``,
        # the gate can't prove the cleaned value actually reaches
        # the sink: an alias could have been written through
        # indirection the gate doesn't track. Run the check over
        # the un-cut graph (excluded=empty) — the cut itself proves
        # control flow goes through the sanitizer, but says nothing
        # about whether the cleaned VALUE survives indirection on
        # that path. Downgrade SUPPRESS → CANDIDATE_ONLY rather
        # than risk a false suppression.
        if _may_escape_on_path(graph, sources_set, sink, excluded=set()):
            return SanitizerCutResult(
                suppress=False,
                reason=(
                    "candidate_only: value-bound vertex-cut held but "
                    "a node on a source→sink path is may_escape "
                    "(indirection or bulk-copy detected); cleaned "
                    "value's identity at the sink is unprovable "
                    "without alias analysis"
                ),
                cut_set=frozenset(),
                candidate_callables=frozenset(candidate_callables),
                verdict=VERDICT_CANDIDATE_ONLY,
                value_bound_bindings=value_bound_bindings,
                all_matched_bindings=matched_bindings,
                sink_arg=sink_arg,
            )
        return SanitizerCutResult(
            suppress=True,
            reason=(
                f"value-bound vertex-cut: sink unreachable from "
                f"{len(sources_set)} source(s) after removing "
                f"{len(value_bound_nodes)} value-bound sanitizer "
                f"node(s) (out of {len(matched_bindings)} catalog "
                f"matches)"
            ),
            cut_set=frozenset(value_bound_nodes),
            candidate_callables=frozenset(candidate_callables),
            verdict=VERDICT_SUPPRESS,
            value_bound_bindings=value_bound_bindings,
            all_matched_bindings=matched_bindings,
            sink_arg=sink_arg,
        )

    if full_cf_cut:
        return SanitizerCutResult(
            suppress=False,
            reason=(
                f"candidate_only: control-flow cut holds over "
                f"{len(full_cf_nodes)} catalog match(es) but value "
                f"binding unproven — "
                f"{len(matched_bindings) - len(value_bound_bindings)} "
                "of these candidates lacked tainted input or "
                "sink-arg reachability"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
            verdict=VERDICT_CANDIDATE_ONLY,
            value_bound_bindings=value_bound_bindings,
            all_matched_bindings=matched_bindings,
            sink_arg=sink_arg,
        )

    return SanitizerCutResult(
        suppress=False,
        reason=(
            "vertex-cut: sink still reachable after sanitizer "
            "removal — at least one path bypasses every catalog "
            "sanitizer"
        ),
        cut_set=frozenset(),
        candidate_callables=frozenset(candidate_callables),
        verdict=VERDICT_NO_SUPPRESS,
        all_matched_bindings=matched_bindings,
        sink_arg=sink_arg,
    )


# ---------------------------------------------------------------------------
# Phase 7b — JSONL audit-trail integration
# ---------------------------------------------------------------------------


def _binding_to_json(b: SanitizerBinding) -> Dict[str, Any]:
    """Serialise one :class:`SanitizerBinding` for the JSONL audit
    record. Frozensets become sorted lists so the JSON is stable
    across runs (sets have no inherent ordering)."""
    return {
        "callable": b.callable,
        "input_symbols": sorted(b.input_symbols),
        "output_symbols": sorted(b.output_symbols),
        "lineno": b.lineno,
    }


def record_sanitizer_cut_suppression(
    out_dir: Path,
    finding: Dict[str, Any],
    result: SanitizerCutResult,
) -> None:
    """Write a sanitizer-cut record to ``suppressions.jsonl``.

    Phase 6 extended this helper to emit records for BOTH the
    ``suppress`` verdict (the finding is dropped — ``dropped:
    true``) and the ``candidate_only`` verdict (the finding
    survives to the LLM, but the value-bound suppressor saw enough
    catalog matches to be worth recording — ``dropped: false``).
    ``no_suppress`` is still a no-op; nothing to log.

    Verdict tags:

    * :data:`VERDICT_SANITIZER_DOMINATED` for suppressions.
    * :data:`VERDICT_SANITIZER_CANDIDATE` for candidate-only
      records.

    Witness fields written into ``extra``:

    * ``sink_arg`` — the symbol consumed at the sink.
    * ``bindings`` — list of value-bound binding records
      (callable, input_symbols, output_symbols, lineno). For
      ``suppress`` these are the bindings whose nodes formed the
      cut; for ``candidate_only`` this is empty (no binding
      satisfied the value gate).
    * ``catalog_matches`` — list of ALL catalog-matched binding
      records in the CFG (a superset of ``bindings`` for
      ``suppress``; the full set for ``candidate_only`` so
      operators can see what was tried).
    * ``witness_lines`` — the source lines of every catalog
      match, sorted for stable jq filtering.

    Delegates to
    :func:`core.inventory.reach_chokepoint.record_suppression` so
    the JSONL shape stays compatible with the binary-oracle
    records that share the file. The ``dropped`` field
    distinguishes drops from surviving-but-recorded findings —
    operators can ``jq 'select(.dropped == false)'`` to see what
    the value-bound gate flagged but didn't drop.

    NOT YET WIRED into the live pipeline (review #6 on PR #794): only
    tests call this helper today, so it never races the binary-oracle
    chokepoint on a real run. When it IS wired, the binary-oracle
    reachability suppression runs first (pre-LLM), so a function it
    dropped never reaches this gate — see
    :func:`core.inventory.reach_chokepoint.record_suppression` for the
    full order-of-operations contract.
    """
    if result.verdict == VERDICT_SUPPRESS:
        verdict_tag = VERDICT_SANITIZER_DOMINATED
        dropped = True
    elif result.verdict == VERDICT_CANDIDATE_ONLY:
        verdict_tag = VERDICT_SANITIZER_CANDIDATE
        dropped = False
    else:
        # VERDICT_NO_SUPPRESS — nothing to record.
        return

    from core.inventory.reach_chokepoint import record_suppression

    catalog_matches = sorted(
        result.all_matched_bindings, key=lambda b: (b.lineno, b.callable),
    )
    value_bindings = sorted(
        result.value_bound_bindings, key=lambda b: (b.lineno, b.callable),
    )

    extra: Dict[str, Any] = {
        "sink_arg": result.sink_arg,
        "bindings": [_binding_to_json(b) for b in value_bindings],
        "catalog_matches": [_binding_to_json(b) for b in catalog_matches],
        "witness_lines": sorted({b.lineno for b in catalog_matches}),
    }

    record_suppression(
        out_dir,
        finding=finding,
        verdict=verdict_tag,
        reason=result.reason,
        dropped=dropped,
        extra=extra,
    )


__all__ = [
    "VERDICT_SANITIZER_DOMINATED",
    "VERDICT_SANITIZER_CANDIDATE",
    "VERDICT_SUPPRESS",
    "VERDICT_CANDIDATE_ONLY",
    "VERDICT_NO_SUPPRESS",
    "SanitizerCutResult",
    "sanitizer_cuts_source_to_sink",
    "evaluate_finding",
    "record_sanitizer_cut_suppression",
]
