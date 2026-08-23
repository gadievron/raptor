r"""Vertex-cut sanitizer suppressor — Phase 7 of the sanitizer-cut arc.

The structural FP reduction this arc was designed for. Given a finding
with a source location, a sink location, a CWE, and a language, the
suppressor answers one question:

    Does every dynamic path from source to sink cross at least one
    sanitizer recognized by the catalog?

If yes → the taint cannot reach the sink in any execution; suppress
the finding without an LLM call.

Algorithm: a **vertex cut**.

    Suppress iff ``sink`` is unreachable from ``source`` in
    ``CFG \ candidate_sanitizers``.

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

This module does no IO and no scorecard writes, with two narrow
carve-outs: :func:`_propagate_taint` logs a single diagnostic
warning if its fixed-point loop hits the iteration cap, and the
Phase 7b helper :func:`record_sanitizer_cut_suppression` bridges
the result into ``suppressions.jsonl`` for the audit trail.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
)
from collections.abc import Iterable, Mapping

from core.dataflow.sanitizer_catalog import (
    SanitizerBinding,
    match_sanitizers_in_cfg,
    nodes_of,
    sanitizer_callables_for_cwe,
)
from core.analysis.dataflow import (
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
      Non-empty for a value-bound ``VERDICT_SUPPRESS``; also
      carried on the value-bound gate's ``candidate_only`` results
      (the may_escape downgrade and the value-binding-unproven
      case both attach whatever bindings satisfied the gate);
      empty for ``VERDICT_NO_SUPPRESS``.
    * ``all_matched_bindings`` — every catalog match in the CFG,
      plus any Phase 14 inter-procedural synthetic bindings folded
      in via ``extra_bindings``, regardless of value binding.
      Non-empty for both
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
    cut_set: frozenset
    candidate_callables: frozenset[str]
    verdict: str = ""
    value_bound_bindings: frozenset[SanitizerBinding] = frozenset()
    all_matched_bindings: frozenset[SanitizerBinding] = frozenset()
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
            msg = (
                f"suppress=True requires verdict={VERDICT_SUPPRESS!r}, "
                f"got verdict={self.verdict!r}"
            )
            raise ValueError(msg)
        if not self.suppress and self.verdict == VERDICT_SUPPRESS:
            msg = (
                f"verdict={VERDICT_SUPPRESS!r} requires suppress=True, "
                "got suppress=False"
            )
            raise ValueError(msg)


def _bfs_reachable_excluding(
    graph,
    sources: Iterable,
    excluded: set,
) -> set:
    """BFS from each source over ``graph``, skipping every node in
    ``excluded``. Returns the set of nodes reached. The excluded set
    IS removed: edges into excluded nodes are never traversed, edges
    out of them are never produced.

    Pure function; does not mutate ``graph``.
    """
    seen: set = set()
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
    r"""Return True iff removing every node in ``cut_set`` disconnects
    ``sink`` from every node in ``sources``.

    Multi-source semantics: the check is "no source reaches sink".
    Equivalent to BFS from ``sources ∪`` over ``graph \ cut_set``
    and asking whether ``sink`` is in the result.

    Pure graph reachability — no language semantics, no catalog
    lookup, no logging. The caller (typically
    :func:`evaluate_finding`) is responsible for constructing
    ``cut_set`` from the sanitizer catalog.
    """
    cut: set = set(cut_set)
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
    excluded: set,
) -> bool:
    """Phase 10 — True iff any node with ``may_escape=True`` lies on
    a source→sink path in ``graph``, after removing ``excluded`` (the
    value-bound sanitizer cut). See
    :func:`_may_escape_nodes_on_path` for the node-returning variant
    the element-sensitive exemption reads.

    Cheap: O(V + E) per call (one forward BFS + one reverse BFS).
    Pure function. Uses ``getattr(node, "may_escape", False)`` so
    PyCFGNode (which lacks the attribute) always returns False — the
    Python evaluate_finding paths stay bit-identical.
    """
    return bool(_may_escape_nodes_on_path(graph, sources, sink, excluded))


def _may_escape_nodes_on_path(
    graph,
    sources: Iterable,
    sink,
    excluded: set,
) -> list:
    """The ``may_escape`` nodes lying on a source→sink path — the
    evidence set behind :func:`_may_escape_on_path`. The
    element-sensitive exemption inspects each node's line: a
    suppression may stand only when EVERY such node is exempt
    (its escape triggers are all tracked-array accesses; see
    :meth:`core.analysis.java_array_escape.LocalArrayIndex.exempt_line`).
    """
    excl: set = set(excluded) if excluded else set()

    # Forward BFS from sources.
    forward: set = set()
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
    predecessors: dict[Any, list[Any]] = {}
    for n in forward:
        for succ in graph.successors(n):
            if succ in forward:
                predecessors.setdefault(succ, []).append(n)

    # Backward BFS from sink. ``sink`` itself isn't necessarily in
    # ``forward`` (the cut might disconnect it — but then the
    # surrounding evaluate_finding wouldn't be checking us). Seed
    # only if it is.
    if sink not in forward:
        return []
    backward: set = {sink}
    rqueue: deque = deque([sink])
    while rqueue:
        node = rqueue.popleft()
        for prev in predecessors.get(node, ()):
            if prev in backward:
                continue
            backward.add(prev)
            rqueue.append(prev)

    # On-path = forward ∩ backward. Collect may_escape hits.
    return [n for n in backward if getattr(n, "may_escape", False)]


def _propagate_taint(
    graph,
    rd: ReachingDefs,
    source_nodes: Iterable,
    source_symbols: Iterable[str],
) -> Mapping[Any, frozenset[str]]:
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

    taint: dict[tuple[Any, str], bool] = {}

    # Seed: source_symbols at source nodes (body sources) and the
    # virtual entry defs for param sources.
    entry = getattr(graph, "entry", None)
    params: tuple[str, ...] = tuple(getattr(graph, "params", ()) or ())
    for n in graph.nodes():
        if n not in sources_set:
            continue
        node_defs: frozenset[str] = getattr(n, "defs", frozenset())
        for s in node_defs & src_syms:
            taint[(n, s)] = True
        if n is entry:
            for p in params:
                if p in src_syms:
                    taint[(n, p)] = True

    # Iterate to fixed point. Monotone: taint only grows.
    MAX_TAINT_ITERATIONS = 100
    changed = True
    taint_iter = 0
    while changed:
        taint_iter += 1
        if taint_iter > MAX_TAINT_ITERATIONS:
            logger.warning(
                "_propagate_taint hit iteration cap (%d); "
                "stopping fixed-point loop",
                MAX_TAINT_ITERATIONS,
            )
            break
        changed = False
        for n in graph.nodes():
            tainted_in: set[str] = set()
            for sym, definers in rd.all_at(n).items():
                for d in definers:
                    if taint.get((d, sym), False):
                        tainted_in.add(sym)
                        break
            uses: frozenset[str] = getattr(n, "uses", frozenset())
            if not (uses & tainted_in):
                continue
            node_defs = getattr(n, "defs", frozenset())
            for s in node_defs:
                if not taint.get((n, s), False):
                    taint[(n, s)] = True
                    changed = True

    # Project to per-node IN tainted symbol sets.
    result: dict[Any, frozenset[str]] = {}
    for n in graph.nodes():
        tainted: set[str] = set()
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
    tainted_at: Mapping[Any, frozenset[str]],
    sink: Any,
    sink_arg: str,
    sanitizer_output_nodes: set,
) -> bool:
    """Phase 4 conditions 2 and 3 for one binding.

    Condition 2: at least one of the binding's bare-name inputs is
    tainted at the binding's node IN. (Condition 1 — catalog match
    by callable — is already filtered upstream by
    :func:`match_sanitizers_in_cfg`.)

    Condition 3: the binding's call assigns ``sink_arg`` as one of
    its outputs AND **every** reaching definer of ``sink_arg`` at
    the sink is a sanitizer node whose outputs include ``sink_arg``
    (``sanitizer_output_nodes``). Mere membership of the binding's
    node among the reaching definers is not enough: when a loop (or
    any converging control flow) lets a non-sanitizer definition of
    ``sink_arg`` reach the sink alongside the sanitized one
    (``y = escape(x); for i in it: y = i; render(y)``), the cleaned
    value's identity at the sink is unproven and suppressing would
    be a false negative. The straight-line rebind case was already
    caught (the later def kills the earlier one); the exclusivity
    requirement extends the same reasoning to converging defs.
    """
    # Condition 2 — tainted-input check
    tainted_in = tainted_at.get(binding.node, frozenset())
    if not (binding.input_symbols & tainted_in):
        return False
    # Condition 3 — output reaches sink arg, exclusively via
    # sanitizer outputs
    if sink_arg not in binding.output_symbols:
        return False
    reaching = rd.at(sink, sink_arg)
    if binding.node not in reaching:
        return False
    return not any(d not in sanitizer_output_nodes for d in reaching)


def _fold_stack(graph, java_source_text: str,
                java_file_path: str | None = None,
                repo_root: str | None = None):
    """Assemble the composed constant-fold context (const index +
    table/config resolvers + the conduit/collection invocation hook)
    over the graph's line span. None on any failure — every consumer
    treats that as not-constant. Shared by the constant-definers
    pre-check and the whole-array taint-freedom check so the two can
    never diverge on resolution power."""
    try:
        from core.analysis.const_fold_java import JavaConstIndex
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return None
        span = (min(linenos), max(linenos))
        # java_file_path/repo_root activate the bounded cross-file
        # static-final/returns-literal resolver inside the index; the
        # taint-free tier stays opt-in per fold call (only the
        # taint-freedom consumers enable it).
        index = JavaConstIndex(java_source_text, span,
                               java_file_path=java_file_path,
                               repo_root=repo_root)
        try:
            from core.analysis.value_set_java import build_table_resolver
            table_resolver = build_table_resolver(java_source_text, span)
        except Exception:  # noqa: BLE001 — table support is optional
            table_resolver = None
        config_resolver = None
        if java_file_path:
            try:
                from core.analysis.config_resolve_java import (
                    make_config_resolver,
                )
                resolver = make_config_resolver(
                    java_source_text, java_file_path, repo_root,
                )
                if resolver is not None:
                    config_resolver = resolver.fold_hook
            except Exception:  # noqa: BLE001 — config support is optional
                config_resolver = None
        try:
            from core.analysis.java_wrapper_summaries import (
                make_conduit_fold_resolver,
            )
            conduit_resolver = make_conduit_fold_resolver(
                java_source_text, span,
            )
        except Exception:  # noqa: BLE001 — conduit support is optional
            conduit_resolver = None
        collection_resolver = None
        try:
            from core.analysis.java_collection_index import (
                CollectionFoldResolver,
                build_local_collection_index,
                compose_invocation_hooks,
            )
            coll_index = build_local_collection_index(
                java_source_text, span,
            )
            if coll_index is not None and coll_index.ok:
                collection_resolver = CollectionFoldResolver(coll_index)
        except Exception:  # noqa: BLE001 — collection support is optional
            collection_resolver = None
        invocation_hook = conduit_resolver
        if collection_resolver is not None:
            from core.analysis.java_collection_index import (
                compose_invocation_hooks,
            )
            invocation_hook = compose_invocation_hooks(
                conduit_resolver, collection_resolver,
            )
        return (index, table_resolver, config_resolver, invocation_hook,
                conduit_resolver, collection_resolver)
    except Exception:  # noqa: BLE001 — folding is best-effort, never fatal
        return None


def _union_member_check(cwe: str | None):
    """Danger predicate (str list -> bool) for taint-free union and
    helper-summary members of a ``cwe``-classified finding, or None
    when no class is known — the union then refuses any merge with a
    concrete string member (no danger authority, no claim).  Same
    per-element discipline as :func:`_finite_value_set_reason`: a
    compile-time constant can violate a value-based finding class on
    its own, however attacker-free."""
    if not cwe:
        return None

    def check(strs) -> bool:
        try:
            from core.analysis.collection_guard_java import (
                _literals_clear_danger,
            )
            return _literals_clear_danger(sorted(strs), cwe) is not None
        except Exception:  # noqa: BLE001 — refusal direction
            return False

    return check


def _finite_value_set_reason(
    rd, sink, sink_arg: str, index, cwe: str,
    table_resolver, config_resolver, invocation_hook,
) -> str | None:
    """Reason string when ``sink_arg``'s reaching definers fold to a
    FINITE SET of compile-time constants whose every string member
    clears the CWE's danger models; None otherwise. The set semantics
    (values need not agree) are what the all-agree point resolver
    cannot express; the danger check is the finite specialisation of
    the smt_barrier charset proof, same as the collection guard."""
    try:
        from core.analysis.collection_guard_java import (
            _literals_clear_danger,
        )
        from core.analysis.value_set_java import finite_constant_value_set
        values = finite_constant_value_set(
            rd, sink, sink_arg, index,
            array_resolver=table_resolver,
            config_resolver=config_resolver,
            conduit_resolver=invocation_hook,
        )
        if values is None or len(values) < 2:
            # A singleton is the all-agree proof's territory (it
            # already refused above — refusing here keeps the two
            # paths from disagreeing on one shape).
            return None
        str_members = [v for v in values if isinstance(v, str)]
        if str_members:
            danger_ok = _literals_clear_danger(sorted(str_members), cwe)
            if danger_ok is None:
                return None
        return (
            f"every reaching definer of the sink argument folds to a "
            f"compile-time constant in a finite set of {len(values)} "
            f"values clearing the class danger model(s)"
        )
    except Exception:  # noqa: BLE001 — folding is best-effort, never fatal
        return None


def _sink_arg_constant_reason(
    graph, sources_set, sink, sink_arg: str,
    source_symbols, java_source_text: str,
    java_file_path: str | None = None,
    repo_root: str | None = None,
    cwe: str | None = None,
    ban_tf_system_reads: bool = False,
) -> str | None:
    """Reason string when the Java constant-folder proves every
    reaching definer of ``sink_arg`` constant AND no other name in
    the sink call's arguments is tainted; None otherwise.

    The second condition is load-bearing: sink-arg selection is a
    heuristic pick among the call's argument names, so proving the
    PICKED one constant says nothing about taint riding a sibling
    argument (``sink(incidental_const, tainted)``). Constancy may
    suppress only when every other argument name is clean under the
    same taint front the value gate uses. Any failure inside the
    folder reads as not-constant.
    """
    try:
        from core.analysis.const_fold_java import (
            JavaConstIndex,
            all_definers_constant,
        )
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return None
        # java_file_path/repo_root activate the cross-file resolver
        # (b37) exactly as in _fold_stack — the two constructions must
        # not diverge on resolution power.
        index = JavaConstIndex(
            java_source_text, (min(linenos), max(linenos)),
            java_file_path=java_file_path, repo_root=repo_root,
        )
        rd = reaching_defs(graph)
        try:
            from core.analysis.value_set_java import build_table_resolver
            table_resolver = build_table_resolver(
                java_source_text, (min(linenos), max(linenos)),
            )
        except Exception:  # noqa: BLE001 — table support is optional
            table_resolver = None
        config_resolver = None
        if java_file_path:
            try:
                from core.analysis.config_resolve_java import (
                    make_config_resolver,
                )
                resolver = make_config_resolver(
                    java_source_text, java_file_path, repo_root,
                )
                if resolver is not None:
                    config_resolver = resolver.fold_hook
            except Exception:  # noqa: BLE001 — config support is optional
                config_resolver = None
        try:
            from core.analysis.java_wrapper_summaries import (
                make_conduit_fold_resolver,
            )
            conduit_resolver = make_conduit_fold_resolver(
                java_source_text, (min(linenos), max(linenos)),
            )
        except Exception:  # noqa: BLE001 — conduit support is optional
            conduit_resolver = None
        # Collection round-trips (b28): a ``get`` on a tracked local
        # map/list folds when every write to the consumed key folds to
        # the same constant. Both hooks own the method-invocation
        # slot; composition is first-claim-wins with None as the
        # fall-through, so no const_fold_java change is needed.
        collection_resolver = None
        try:
            from core.analysis.java_collection_index import (
                CollectionFoldResolver,
                build_local_collection_index,
                compose_invocation_hooks,
            )
            coll_index = build_local_collection_index(
                java_source_text, (min(linenos), max(linenos)),
            )
            if coll_index is not None and coll_index.ok:
                collection_resolver = CollectionFoldResolver(coll_index)
        except Exception:  # noqa: BLE001 — collection support is optional
            collection_resolver = None
        # Returns-taint-free helper summaries (b42): claimed LAST so
        # value-producing resolvers (conduits, collection round-trips)
        # keep first claim on calls they can fold to actual values;
        # this hook only ever yields the TAINT_FREE sentinel, which the
        # boundary pin strips for every value consumer.
        tf_helper_resolver = None
        try:
            from core.analysis.java_taint_freedom import (
                make_tf_helper_resolver,
            )
            tf_helper_resolver = make_tf_helper_resolver(
                java_source_text, (min(linenos), max(linenos)),
                member_check=_union_member_check(cwe),
            )
        except Exception:  # noqa: BLE001 — summaries are optional
            tf_helper_resolver = None
        invocation_hook = conduit_resolver
        if collection_resolver is not None:
            invocation_hook = compose_invocation_hooks(
                invocation_hook, collection_resolver,
            )
        if tf_helper_resolver is not None:
            invocation_hook = compose_invocation_hooks(
                invocation_hook, tf_helper_resolver,
            )
        reason = all_definers_constant(
            rd, sink, sink_arg, index, array_resolver=table_resolver,
            config_resolver=config_resolver,
            conduit_resolver=invocation_hook,
            ban_tf_system_reads=ban_tf_system_reads,
            union_member_check=_union_member_check(cwe),
        )
        if reason is None and cwe:
            # Finite value-set fallback (b40): the definers disagree
            # on VALUE but every one folds to a compile-time constant
            # — the if-equals-chain shape. Constancy alone is the
            # taint-freedom conclusion; the per-element danger check
            # on top keeps this pre-check honest for value-based
            # finding classes (the b34 API caveat): a set containing
            # a danger-bearing constant never suppresses here.
            reason = _finite_value_set_reason(
                rd, sink, sink_arg, index, cwe,
                table_resolver, config_resolver, invocation_hook,
            )
        if reason is None:
            return None
        if table_resolver is not None and table_resolver.hits:
            reason += " (resolved through a constant-table load)"
        if conduit_resolver is not None and conduit_resolver.hits:
            reason += " (resolved through a conduit helper)"
        if collection_resolver is not None and collection_resolver.hits:
            reason += (
                " (resolved through a constant-key collection round-trip)"
            )
        if tf_helper_resolver is not None and tf_helper_resolver.hits:
            reason += (
                " (resolved through a returns-taint-free helper union)"
            )
        call_sites = getattr(sink, "call_sites", ()) or ()
        if not call_sites:
            return None
        outermost = call_sites[-1]
        other_names = (
            (set(outermost.arg_names) | set(outermost.arg_deep_names))
            - {sink_arg}
        )
        if other_names:
            tainted_at = _propagate_taint(
                graph, rd, sources_set,
                frozenset(source_symbols or ()),
            )
            if other_names & set(tainted_at.get(sink, frozenset())):
                return None
            # The front is necessary but NOT sufficient: a sibling
            # tainted through a helper call is invisible to it
            # (observed live — see _siblings_fold_or_refuse). Every
            # sibling must additionally fold or be a catalog call.
            from core.analysis.const_fold_java import definers_all_fold
            covered = _xfile_covered_names(index, java_source_text, sink)
            for name in other_names:
                if definers_all_fold(
                        rd, sink, name, index,
                        array_resolver=table_resolver,
                        config_resolver=config_resolver,
                        conduit_resolver=invocation_hook):
                    continue
                if name in covered and not rd.at(sink, name):
                    # every occurrence sits inside an accepted
                    # taint-free chain and no local definition
                    # reaches — a class-constant segment, not a
                    # taint path.
                    continue
                # Fold-only: a catalog-sanitizer allowance would need
                # the finding's class context (a wrong-class sanitizer
                # on a sibling proves nothing), and this pre-check runs
                # before the catalog gate. Not foldable -> refuse.
                return None
        return reason
    except Exception:  # noqa: BLE001 — folding is best-effort, never fatal
        return None


def _xfile_covered_names(index, java_source_text, sink):
    """Sibling names whose every occurrence on the sink STATEMENT sits
    inside a chain the cross-file resolver accepts under the
    taint-free tier (b36 port: JDK class constants split into base
    identifiers by arg-name extraction — ``java``/``ResultSet`` from a
    three-argument prepareCall — have no reaching defs and would
    refuse forever without expression-level coverage)."""
    try:
        xfile = getattr(index, "xfile", None)
        if xfile is None or not java_source_text:
            return frozenset()
        return frozenset(xfile.covered_identifiers(
            java_source_text, getattr(sink, "lineno", 0)))
    except Exception:  # noqa: BLE001 — refusal direction
        return frozenset()


def _build_array_index(graph, java_source_text: str):
    """Best-effort :class:`LocalArrayIndex` over the graph's line
    span; None on any failure (grammar missing, parse error, no
    lined nodes)."""
    try:
        from core.analysis.java_array_escape import build_local_array_index
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return None
        return build_local_array_index(
            java_source_text, (min(linenos), max(linenos)),
        )
    except Exception:  # noqa: BLE001 — indexing is best-effort, never fatal
        return None


def _sibling_args_tainted(
    graph, sources_set, sink, sink_arg: str, source_symbols,
) -> bool:
    """True when a name OTHER than ``sink_arg`` in the sink call's
    arguments is tainted — the shared guard against the sink-arg
    inversion trap (sink_arg is a heuristic pick; proving IT safe
    says nothing about taint riding a sibling argument). Unknown
    shapes read as tainted (refusal direction)."""
    call_sites = getattr(sink, "call_sites", ()) or ()
    if not call_sites:
        return True
    outermost = call_sites[-1]
    other_names = (
        (set(outermost.arg_names) | set(outermost.arg_deep_names))
        - {sink_arg}
    )
    if not other_names:
        return False
    rd = reaching_defs(graph)
    tainted_at = _propagate_taint(
        graph, rd, sources_set, frozenset(source_symbols or ()),
    )
    return bool(other_names & set(tainted_at.get(sink, frozenset())))


def _element_exclusive_reason(
    graph,
    sources_set,
    sink,
    sink_arg: str,
    source_symbols,
    candidate_callables,
    array_index,
) -> str | None:
    """Reason string when the value the sink consumes is an element of
    a tracked local array whose every write is a catalog-sanitizer
    call; None otherwise.

    Flow-insensitive over the element writes ON PURPOSE: base-name
    reaching-defs cannot be trusted for elements (a write to ``a[1]``
    kills a prior ``a[0]`` write in the base-name lattice — trusting
    it would false-suppress ``a[0] = tainted; a[1] = sanitize(x);
    sink(a[0])``). Requiring EVERY write to the consumed element to
    be a sanitizer output makes the conclusion independent of which
    write reaches; an unwritten element reads as Java's null default,
    which carries no caller taint.

    Two consumed shapes resolve; everything else refuses:

    * direct — the sink call reads ``sink_arg[C]`` (all element reads
      of ``sink_arg`` on the sink's line, every index a literal);
    * one scalar hop — ``sink_arg`` is a scalar whose EVERY reaching
      definer at the sink is a single-writer ``sink_arg = arr[C]``
      copy (scalar reaching-defs are exact: Java locals are
      unaliasable).
    """
    if array_index is None or not array_index.ok:
        return None
    sink_lineno = getattr(sink, "lineno", 0)
    targets: list[tuple[str, int]] = []
    direct = array_index.element_reads_at(sink_lineno, sink_arg)
    if direct:
        targets = [(sink_arg, i) for i in sorted(direct)]
    else:
        rd = reaching_defs(graph)
        definers = rd.at(sink, sink_arg)
        if not definers:
            return None
        for d in definers:
            copy = array_index.scalar_copy(
                getattr(d, "lineno", 0), sink_arg,
            )
            if copy is None:
                return None
            targets.append(copy)
    if not targets:
        return None
    for name, index in targets:
        if not array_index.tracked(name):
            return None
        writes = array_index.element_writes(name, index)
        if not writes:
            return None
        for w in writes:
            if not array_index.write_is_catalog_call(
                    w, candidate_callables):
                return None
    if _sibling_args_tainted(
            graph, sources_set, sink, sink_arg, source_symbols):
        return None
    return (
        f"element-exclusive sanitizer definitions: every write to the "
        f"consumed element(s) of {len({n for n, _ in targets})} tracked "
        f"local array(s) is a catalog sanitizer call"
    )


def _vertex_cut_siblings_clean(
    graph, rd, sink, sink_arg: str,
    _matched_bindings, candidate_callables,
    *,
    java_source_text=None,
    java_file_path=None,
    repo_root=None,
    ban_tf_system_reads: bool = False,
    union_member_check=None,
) -> bool:
    """Sibling-argument guard for the value-bound vertex-cut path.

    Java findings only — the guard was evidence-forced when b41's
    resolution widening exposed the path as sibling-blind (a
    catalog-sanitized pick suppressed while taint rode the sibling of
    the same call, front-visibly AND helper-fed). Delegates to
    :func:`_siblings_fold_or_refuse` with a resolver kit built from
    the finding's own file; the table/config/conduit hooks are
    deliberately ``None`` — fewer folds only ever REFUSE more, never
    suppress more. Non-Java callers return ``True`` unchanged: their
    resolution surface did not widen and no failing fixture exists
    (the latent single-language question is noted, not guessed at).
    """
    if not java_source_text:
        return True
    try:
        from core.analysis.const_fold_java import JavaConstIndex
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return False
        # java_file_path/repo_root activate the cross-file resolver so
        # JDK-chain and static-final sibling segments get the same
        # taint-free coverage the constant pre-check grants (b36/b37);
        # without them, package-chain siblings like ``java`` from a
        # ``java.util.Locale.US`` argument would refuse forever.
        index = JavaConstIndex(
            java_source_text, (min(linenos), max(linenos)),
            java_file_path=java_file_path, repo_root=repo_root,
        )
        return _siblings_fold_or_refuse(
            graph, rd, sink, sink_arg,
            index, None, None, None,
            candidate_callables,
            java_source_text=java_source_text,
            ban_tf_system_reads=ban_tf_system_reads,
            union_member_check=union_member_check,
        )
    except Exception:  # noqa: BLE001 — guard failure reads as refuse
        return False


def _siblings_fold_or_refuse(
    _graph, rd, sink, sink_arg: str,
    index, table_resolver, config_resolver, invocation_hook,
    candidate_callables,
    java_source_text=None,
    ban_tf_system_reads: bool = False,
    union_member_check=None,
) -> bool:
    """True when every OTHER argument name of the sink call is
    provably taint-free: all its reaching definers fold to constants
    (values may differ) or are catalog-sanitizer calls. The local
    taint front is deliberately NOT trusted here — a sibling tainted
    through a helper call is invisible to it (observed live: a
    constant env array was picked as the sink argument while taint
    rode `cmd + bar` beside it, `bar` fed by a same-file helper the
    front cannot see). Fold-or-refuse is the only honest polarity for
    a suppression guard."""
    try:
        from core.analysis.const_fold_java import definers_all_fold
        call_sites = getattr(sink, "call_sites", ()) or ()
        if not call_sites:
            return False
        outermost = call_sites[-1]
        other = (
            (set(outermost.arg_names) | set(outermost.arg_deep_names))
            - {sink_arg}
        )
        covered = _xfile_covered_names(index, java_source_text, sink)
        for name in other:
            if definers_all_fold(
                    rd, sink, name, index,
                    array_resolver=table_resolver,
                    config_resolver=config_resolver,
                    conduit_resolver=invocation_hook,
                    ban_tf_system_reads=ban_tf_system_reads,
                    union_member_check=union_member_check):
                continue
            defs = rd.at(sink, name)
            if not defs:
                if name in covered:
                    continue
                return False
            for d in defs:
                rhs = index.rhs_at(getattr(d, "lineno", 0), name)
                if rhs is None or not _rhs_is_catalog_call(
                        rhs, candidate_callables):
                    return False
        return True
    except Exception:  # noqa: BLE001 — refusal direction
        return False


def _rhs_is_catalog_call(rhs, candidate_callables) -> bool:
    """Best-effort: the rhs expression is a single call whose text
    ends with a catalog callable name."""
    try:
        node = rhs
        if node.type == "cast_expression":
            node = node.child_by_field_name("value") or node
        if node.type != "method_invocation":
            return False
        txt = node.text.decode("utf-8", "replace").split("(", 1)[0]
        return any(
            txt == c or txt.endswith("." + c) or txt.endswith(c)
            for c in candidate_callables
        )
    except Exception:  # noqa: BLE001
        return False


def _whole_array_taint_free_reason(
    graph,
    _sources_set,
    sink,
    sink_arg: str,
    _source_symbols,
    candidate_callables,
    java_source_text: str,
    java_file_path: str | None = None,
    repo_root: str | None = None,
    ban_tf_system_reads: bool = False,
    union_member_check=None,
) -> str | None:
    """Reason string when the sink consumes a WHOLE local array whose
    every element is provably taint-free; None otherwise.

    Conditions, all load-bearing: ``sink_arg`` names a fresh
    initializer-form array whose ONLY escape is the single exempted
    sink-argument occurrence (any other appearance — aliasing, call
    argument, element write through an alias — violates in the index);
    every recorded element write is a catalog-sanitizer call, folds to
    a compile-time constant through the full composed resolver stack,
    or is a bare identifier whose EVERY reaching definer at the write
    site folds to a constant (values need not agree — taint-freedom,
    not value identity); and no sibling argument of the sink call is
    tainted. Any resolution failure refuses.
    """
    try:
        from core.analysis.java_array_escape import build_local_array_index
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return None
        sink_lineno = getattr(sink, "lineno", 0)
        arr = build_local_array_index(
            java_source_text, (min(linenos), max(linenos)),
            sink_exempt=(sink_lineno, sink_arg),
        )
        if arr is None or not arr.ok or not arr.whole_pass_ok(sink_arg):
            return None
        writes = [
            w for (name, _i), ws in arr._writes.items()
            if name == sink_arg for w in ws
        ]
        if not writes:
            return None
        stack = _fold_stack(graph, java_source_text,
                            java_file_path=java_file_path,
                            repo_root=repo_root)
        if stack is None:
            return None
        index, table_resolver, config_resolver, invocation_hook = stack[:4]
        from core.analysis.const_fold_java import (
            REFUSE,
            definers_all_fold,
            fold_expr_at,
        )
        rd = reaching_defs(graph)
        by_line = {}
        for n in graph.nodes():
            ln = getattr(n, "lineno", 0)
            if ln > 0 and ln not in by_line:
                by_line[ln] = n
        for w in writes:
            if arr.write_is_catalog_call(w, candidate_callables):
                continue
            at = by_line.get(w.lineno)
            if at is None or w.rhs is None:
                return None
            val = fold_expr_at(
                rd, at, w.rhs, index, array_resolver=table_resolver,
                config_resolver=config_resolver,
                conduit_resolver=invocation_hook,
            )
            if val is not REFUSE:
                continue
            if w.rhs.type == "identifier" and definers_all_fold(
                    rd, at, w.rhs.text.decode("utf-8", "replace"),
                    index, array_resolver=table_resolver,
                    config_resolver=config_resolver,
                    conduit_resolver=invocation_hook,
                    ban_tf_system_reads=ban_tf_system_reads,
                    union_member_check=union_member_check):
                continue
            return None
        if not _siblings_fold_or_refuse(
                graph, rd, sink, sink_arg,
                index, table_resolver, config_resolver, invocation_hook,
                candidate_callables,
                java_source_text=java_source_text,
                ban_tf_system_reads=ban_tf_system_reads,
                union_member_check=union_member_check):
            return None
        return (
            "taint-free array argument: the sink consumes a whole "
            "initializer-only local array whose every element is a "
            "catalog sanitizer call or folds to a compile-time constant"
        )
    except Exception:  # noqa: BLE001 — best-effort, never fatal
        return None


def _build_collection_index(graph, java_source_text: str):
    """Best-effort :class:`LocalCollectionIndex` over the graph's line
    span; None on any failure — the refusal direction."""
    try:
        from core.analysis.java_collection_index import (
            build_local_collection_index,
        )
        linenos = [
            n.lineno for n in graph.nodes()
            if getattr(n, "lineno", 0) > 0
        ]
        if not linenos:
            return None
        return build_local_collection_index(
            java_source_text, (min(linenos), max(linenos)),
        )
    except Exception:  # noqa: BLE001 — collection support is optional
        return None


def _collection_exclusive_reason(
    graph,
    sources_set,
    sink,
    sink_arg: str,
    source_symbols,
    candidate_callables,
    collection_index,
) -> str | None:
    """Reason string when the value the sink consumes is an element of
    a tracked local collection whose every write to the consumed key
    is a catalog-sanitizer call; None otherwise. The b19 array rule's
    exact mirror on map/list round-trips — flow-insensitive over the
    key's writes for the same reason (which write reaches is
    irrelevant when every write is a sanitizer output; a never-written
    key reads as null, which carries no caller taint). List reads are
    governed by ALL writes to the list (positional order is
    unprovable), which is strictly stronger.

    Two consumed shapes resolve; everything else refuses:

    * direct — the sink call reads ``sink_arg.get(K)`` on the sink's
      line (every key recorded, i.e. literal);
    * one scalar hop — every reaching definer of ``sink_arg`` at the
      sink is a single-writer ``sink_arg = <cast?> coll.get(K)`` copy.
    """
    if collection_index is None or not collection_index.ok:
        return None
    sink_lineno = getattr(sink, "lineno", 0)
    targets: list[tuple[str, str]] = []
    direct = collection_index.element_reads_at(sink_lineno, sink_arg)
    if direct:
        targets = [(sink_arg, k) for k in sorted(direct)]
    else:
        rd = reaching_defs(graph)
        definers = rd.at(sink, sink_arg)
        if not definers:
            return None
        for d in definers:
            copy = collection_index.scalar_copy(
                getattr(d, "lineno", 0), sink_arg,
            )
            if copy is None:
                return None
            targets.append(copy)
    if not targets:
        return None
    for name, key in targets:
        if not collection_index.tracked(name):
            return None
        writes = collection_index.element_writes(name, key)
        if not writes:
            return None
        for w in writes:
            if not collection_index.write_is_catalog_call(
                    w, candidate_callables):
                return None
    if _sibling_args_tainted(
            graph, sources_set, sink, sink_arg, source_symbols):
        return None
    return (
        f"element-exclusive sanitizer definitions: every write to the "
        f"consumed key(s) of {len({n for n, _ in targets})} tracked "
        f"local collection(s) is a catalog sanitizer call"
    )


_CONDUIT_CHAIN_DEPTH_CAP = 4


def _conduit_transparent_result(
    graph,
    rd: ReachingDefs,
    tainted_at,
    sources_set,
    sink,
    sink_arg: str,
    matched_bindings,
    source_symbols,
    java_source_text: str,
    candidate_callables,
    array_index,
) -> SanitizerCutResult | None:
    """Conduit-transparency extension of condition 3 (b27). None when
    it can't strengthen the flat gate's answer.

    A conduit call site (:mod:`core.analysis.java_wrapper_summaries`
    conduit summaries: returns-constant / returns-param / join) is
    value-transparent — the sink value's provenance question passes
    through to the selected argument. The walk accepts a reaching
    definer of a symbol when it is (a) a sanitizer-output binding for
    that symbol, (b) a conduit definition whose constant side is
    taint-free and whose parameter side recursively accepts, or (c) a
    plain definition whose RHS folds to a compile-time constant at
    that point. Anything else refuses the whole walk — a tainted
    argument rides through a conduit untouched, so transparency can
    never launder taint.

    Verdict composition mirrors the shipped arguments exactly:

    * all-constant chain (no sanitizer feeders) — the consumed value
      is compile-time constant through conduits; suppress under the
      same sibling-argument taint guard the constant-definers
      pre-check uses (no vertex cut needed — constancy is a value
      argument, not a path argument).
    * sanitizer-fed chain — every feeder must pass condition 2
      (taint actually flows into it) and the feeder set must pass
      condition 4 (removing the feeders cuts every source→sink
      path); the may_escape downgrade then applies exactly as on the
      flat path. A chain mixing constant-only paths with
      sanitizer-fed paths whose feeders don't cut refuses (counted
      conservatism — the vertex-cut argument doesn't cover the
      constant branch).
    """
    try:
        from core.analysis.java_wrapper_summaries import (
            CONDUIT_CONST,
            conduit_call_map,
        )
        from core.analysis.const_fold_java import (
            REFUSE,
            JavaConstIndex,
            fold_expr_at,
        )
        from core.analysis.java_wrapper_summaries import (
            make_conduit_fold_resolver,
        )
    except Exception:  # noqa: BLE001 — optional machinery
        return None
    linenos = [
        n.lineno for n in graph.nodes() if getattr(n, "lineno", 0) > 0
    ]
    if not linenos:
        return None
    span = (min(linenos), max(linenos))
    try:
        calls = conduit_call_map(java_source_text, span)
    except Exception:  # noqa: BLE001 — arbitrary scanned source
        return None
    if not calls:
        return None

    # CFG definition sites that are conduit calls: (node id, symbol) →
    # (summary, positional arg identifiers).
    conduit_defs: dict[tuple[int, str], tuple[Any, tuple]] = {}
    for node in graph.nodes():
        for cs in getattr(node, "call_sites", ()) or ():
            entry = calls.get((cs.lineno, cs.col_offset))
            if entry is None:
                continue
            for sym in cs.assigned_names:
                conduit_defs[(id(node), sym)] = entry
    if not conduit_defs:
        return None

    try:
        index = JavaConstIndex(java_source_text, span)
    except Exception:  # noqa: BLE001
        index = None
    try:
        fold_hook = make_conduit_fold_resolver(java_source_text, span)
    except Exception:  # noqa: BLE001
        fold_hook = None

    sanitizer_nodes_by_symbol: dict[str, set] = {}
    for b in matched_bindings:
        for sym in b.output_symbols:
            sanitizer_nodes_by_symbol.setdefault(sym, set()).add(b.node)

    def _def_folds_constant(d, sym) -> bool:
        if index is None or not index.ok:
            return False
        rhs = index.rhs_at(getattr(d, "lineno", 0), sym)
        if rhs is None:
            return False
        try:
            v = fold_expr_at(
                rd, d, rhs, index, conduit_resolver=fold_hook,
            )
        except Exception:  # noqa: BLE001
            return False
        return v is not REFUSE

    def _walk(sym: str, at, depth: int, visiting: set) -> set | None:
        if depth > _CONDUIT_CHAIN_DEPTH_CAP:
            return None
        defs = rd.at(at, sym)
        if not defs:
            return None
        feeders: set = set()
        for d in defs:
            if d in sanitizer_nodes_by_symbol.get(sym, ()):
                feeders.add(d)
                continue
            entry = conduit_defs.get((id(d), sym))
            if entry is not None:
                summary, arg_idents = entry
                if summary.kind == CONDUIT_CONST:
                    continue
                i = summary.param_index
                arg = (
                    arg_idents[i]
                    if i is not None and i < len(arg_idents) else None
                )
                if arg is None:
                    return None
                key = (id(d), sym)
                if key in visiting:
                    return None
                visiting.add(key)
                sub = _walk(arg, d, depth + 1, visiting)
                visiting.discard(key)
                if sub is None:
                    return None
                feeders |= sub
                continue
            if _def_folds_constant(d, sym):
                continue
            return None
        return feeders

    feeders = _walk(sink_arg, sink, 0, set())
    if feeders is None:
        return None

    if not feeders:
        if _sibling_args_tainted(
                graph, sources_set, sink, sink_arg, source_symbols):
            return None
        return SanitizerCutResult(
            suppress=True,
            reason=(
                "conduit-constant sink argument: every reaching "
                "definer chain resolves to compile-time constants "
                "through conduit helpers"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
            verdict=VERDICT_SUPPRESS,
            sink_arg=sink_arg,
        )

    feeder_bindings = frozenset(
        b for b in matched_bindings if b.node in feeders
    )
    for node in feeders:
        node_ok = any(
            b.node is node
            and (b.input_symbols & tainted_at.get(node, frozenset()))
            for b in feeder_bindings
        )
        if not node_ok:
            return None
    if not sanitizer_cuts_source_to_sink(
            graph, sources_set, sink, feeders):
        return None
    escape_nodes = _may_escape_nodes_on_path(
        graph, sources_set, sink, excluded=set(),
    )
    if escape_nodes and array_index is not None and all(
        array_index.exempt_line(getattr(n, "lineno", 0))
        for n in escape_nodes
    ):
        escape_nodes = []
    if escape_nodes:
        return SanitizerCutResult(
            suppress=False,
            reason=(
                "candidate_only: conduit-transparent value binding "
                "held but a node on a source→sink path is may_escape; "
                "cleaned value's identity at the sink is unprovable "
                "without alias analysis"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(candidate_callables),
            verdict=VERDICT_CANDIDATE_ONLY,
            value_bound_bindings=feeder_bindings,
            all_matched_bindings=matched_bindings,
            sink_arg=sink_arg,
        )
    return SanitizerCutResult(
        suppress=True,
        reason=(
            f"value-bound vertex-cut (conduit transparency): the sink "
            f"value is provably a sanitizer output through conduit "
            f"helper hops; removing {len(feeders)} feeder node(s) "
            f"cuts every source→sink path"
        ),
        cut_set=frozenset(feeders),
        candidate_callables=frozenset(candidate_callables),
        verdict=VERDICT_SUPPRESS,
        value_bound_bindings=feeder_bindings,
        all_matched_bindings=matched_bindings,
        sink_arg=sink_arg,
    )


def evaluate_finding(
    graph,
    sources: Iterable,
    sink,
    *,
    cwe: str,
    language: str,
    source_symbols: Iterable[str] | None = None,
    sink_arg: str | None = None,
    extra_bindings: Iterable[SanitizerBinding] | None = None,
    java_source_text: str | None = None,
    java_file_path: str | None = None,
    repo_root: str | None = None,
    ban_tf_system_reads: bool = False,
) -> SanitizerCutResult:
    """Phase 4 suppression decision for one finding.

    Backward-compatible with Phase 7 callers: omit ``source_symbols``
    and ``sink_arg`` → control-flow-only vertex-cut. Verdict is
    :data:`VERDICT_SUPPRESS` or :data:`VERDICT_NO_SUPPRESS`; no
    ``candidate_only`` is emitted because the gate isn't run.

    ``extra_bindings`` (Phase 14) are inter-procedural synthetic
    sanitizer bindings — typically from
    :func:`core.analysis.interproc.synthetic_sanitizer_bindings`.
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

    # Constant-definers pre-check (Java only, needs the file text):
    # when every reaching definition of the sink argument folds to the
    # same compile-time constant, the consumed value cannot carry
    # taint — a suppression that needs no sanitizer at all, so it runs
    # before the catalog gates. Java locals are unaliasable, so the
    # reaching-defs argument is airtight for the shapes the folder
    # accepts (see core/analysis/const_fold_java's refusal list).
    if (
        language == "java"
        and java_source_text
        and sink_arg
    ):
        const_reason = _sink_arg_constant_reason(
            graph, sources_set, sink, sink_arg,
            source_symbols, java_source_text,
            java_file_path=java_file_path,
            repo_root=repo_root,
            cwe=cwe,
            ban_tf_system_reads=ban_tf_system_reads,
        )
        if const_reason is not None:
            return SanitizerCutResult(
                suppress=True,
                reason=f"constant sink argument: {const_reason}",
                cut_set=frozenset(),
                candidate_callables=frozenset(),
                verdict=VERDICT_SUPPRESS,
                sink_arg=sink_arg,
            )

    # Collection-membership guard pre-check (Java only, needs the file
    # text): a dominating contains-guard over a provably-constant
    # literal set bounds the sink value to a finite language whose
    # intersection with the class danger model is decided per element
    # (the finite specialisation of the smt_barrier charset proof).
    # Runs BEFORE the catalog-empty return — allowlist guards are the
    # canonical safe idiom for classes with no call-shaped sanitizers
    # (sqli / cmdi / pathtrav in Java). Cross-file collections resolve
    # under repo_root (b22's kwarg — one root serves the config
    # resolver and this guard).
    if (
        language == "java"
        and java_source_text
        and sink_arg
    ):
        try:
            from core.analysis.collection_guard_java import (
                collection_guard_reason,
            )
            sink_line = getattr(sink, "lineno", None)
            guard_reason = collection_guard_reason(
                java_source_text, int(sink_line), sink_arg, cwe,
                source_root=repo_root,
            ) if sink_line else None
        except Exception:  # noqa: BLE001 — arbitrary scanned source
            guard_reason = None
        if guard_reason is not None:
            return SanitizerCutResult(
                suppress=True,
                reason=guard_reason,
                cut_set=frozenset(),
                candidate_callables=frozenset(),
                verdict=VERDICT_SUPPRESS,
                sink_arg=sink_arg,
            )

    candidate_callables = sanitizer_callables_for_cwe(cwe, language)

    # Whole-array taint-freedom (b34): the sink consumes the array
    # ITSELF (no element read to anchor the exclusive rule on) —
    # suppressible only when the array is initializer-only, never
    # escapes except into this sink argument, and every element is
    # provably taint-free through the full fold stack. Runs BEFORE the
    # catalog-empty return (the collection-guard precedent): the
    # constancy leg needs no sanitizer catalog, and the catalog leg is
    # naturally inert when the class has no call-shaped sanitizers.
    if language == "java" and java_source_text and sink_arg:
        wa_reason = _whole_array_taint_free_reason(
            graph, sources_set, sink, sink_arg, source_symbols,
            candidate_callables or frozenset(), java_source_text,
            java_file_path=java_file_path, repo_root=repo_root,
            ban_tf_system_reads=ban_tf_system_reads,
            union_member_check=_union_member_check(cwe),
        )
        if wa_reason is not None:
            return SanitizerCutResult(
                suppress=True,
                reason=wa_reason,
                cut_set=frozenset(),
                candidate_callables=frozenset(candidate_callables or ()),
                verdict=VERDICT_SUPPRESS,
                sink_arg=sink_arg,
            )

    if not candidate_callables:
        return SanitizerCutResult(
            suppress=False,
            reason=(
                f"no catalog sanitizers for cwe={cwe!r} language={language!r}"
            ),
            cut_set=frozenset(),
            candidate_callables=frozenset(),
        )

    # Element-sensitive pre-check (Java only, needs the file text):
    # when the sink consumes an element of a tracked local array whose
    # every write is a catalog-sanitizer call, the consumed value is a
    # sanitizer output no matter which write reaches — the standard
    # gate can't see this (element stores carry no assigned_names and
    # stamp may_escape). Runs AFTER the catalog gate so a wrong-class
    # sanitizer or a catalog-empty class can never suppress through it.
    array_index = None
    if language == "java" and java_source_text:
        array_index = _build_array_index(graph, java_source_text)
        if array_index is not None and sink_arg:
            elem_reason = _element_exclusive_reason(
                graph, sources_set, sink, sink_arg, source_symbols,
                candidate_callables, array_index,
            )
            if elem_reason is not None:
                return SanitizerCutResult(
                    suppress=True,
                    reason=elem_reason,
                    cut_set=frozenset(),
                    candidate_callables=frozenset(candidate_callables),
                    verdict=VERDICT_SUPPRESS,
                    sink_arg=sink_arg or "",
                )
        # Collection mirror of the array pre-check (b28): a sink value
        # that round-trips through a tracked local map/list whose every
        # write to the consumed key is a catalog sanitizer. Same
        # placement rationale — after the catalog gate, so wrong-class
        # or catalog-empty classes can never suppress through it.
        if sink_arg:
            collection_index = _build_collection_index(
                graph, java_source_text)
            if collection_index is not None:
                coll_reason = _collection_exclusive_reason(
                    graph, sources_set, sink, sink_arg, source_symbols,
                    candidate_callables, collection_index,
                )
                if coll_reason is not None:
                    return SanitizerCutResult(
                        suppress=True,
                        reason=coll_reason,
                        cut_set=frozenset(),
                        candidate_callables=frozenset(candidate_callables),
                        verdict=VERDICT_SUPPRESS,
                        sink_arg=sink_arg or "",
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
    # Nodes whose sanitizer call assigns ``sink_arg`` — the only
    # definers condition 3 accepts as reaching the sink (exclusivity;
    # see _binding_satisfies_value_gate).
    sanitizer_output_nodes = {
        b.node for b in matched_bindings if sink_arg in b.output_symbols
    }
    value_bound_bindings = frozenset(
        b for b in matched_bindings
        if _binding_satisfies_value_gate(
            b, rd, tainted_at, sink, sink_arg, sanitizer_output_nodes,
        )
    )
    value_bound_nodes = {b.node for b in value_bound_bindings}
    value_bound_cut = sanitizer_cuts_source_to_sink(
        graph, sources_set, sink, value_bound_nodes,
    )

    # Conduit transparency (b27): when the flat gate can't cut, retry
    # condition 3 with conduit call sites treated as value-transparent
    # (returns-constant vanishes, returns-param passes the question to
    # the argument). Bit-identical when the file has no resolvable
    # conduit calls on the def chain — the helper returns None and the
    # flat verdict logic below decides as before.
    if not value_bound_cut and language == "java" and java_source_text:
        transparent = _conduit_transparent_result(
            graph, rd, tainted_at, sources_set, sink, sink_arg,
            matched_bindings, source_symbols, java_source_text,
            candidate_callables, array_index,
        )
        if transparent is not None:
            return transparent

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
        #
        # Element-sensitive exemption: a node whose ONLY escape
        # triggers are accesses on tracked local arrays cannot break
        # the scalar binding condition 3 just proved — tracked arrays
        # never alias a scalar (Java locals are unaliasable) and their
        # references never leave the method. The exemption demands
        # positive evidence per node (a node whose trigger sits on a
        # different physical line of a multi-line statement is NOT
        # exempt) and any field store / arraycopy / untracked array
        # keeps the downgrade.
        escape_nodes = _may_escape_nodes_on_path(
            graph, sources_set, sink, excluded=set(),
        )
        if escape_nodes and array_index is not None and all(
            array_index.exempt_line(getattr(n, "lineno", 0))
            for n in escape_nodes
        ):
            escape_nodes = []
        if escape_nodes:
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
        # Sibling-argument guard (b41 — a live false suppression
        # exposed this path as sibling-blind the moment resolution
        # widened to multi-name argument surfaces): proving sink_arg
        # sanitized says nothing about taint riding another argument
        # of the same call. Every other argument name must fold to a
        # constant or be a catalog-sanitizer output — the same
        # fold-or-refuse polarity the constant and whole-array paths
        # adopted after b34's incident (the local taint front alone
        # is blind to helper-fed siblings). Downgrade, never drop:
        # the value-bound cut held, only the sibling proof is missing.
        if not _vertex_cut_siblings_clean(
                graph, rd, sink, sink_arg,
                matched_bindings, candidate_callables,
                java_source_text=java_source_text,
                java_file_path=java_file_path,
                repo_root=repo_root,
                ban_tf_system_reads=ban_tf_system_reads,
                union_member_check=_union_member_check(cwe),
        ):
            return SanitizerCutResult(
                suppress=False,
                reason=(
                    "candidate_only: value-bound vertex-cut held but "
                    "a sibling argument of the sink call is neither "
                    "constant-foldable nor a catalog-sanitizer "
                    "output; taint could ride it past the proven "
                    "argument"
                ),
                cut_set=frozenset(value_bound_nodes),
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


def _binding_to_json(b: SanitizerBinding) -> dict[str, Any]:
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
    finding: dict[str, Any],
    result: SanitizerCutResult,
    *,
    enforce: bool = False,
) -> None:
    """Write a sanitizer-cut record to ``suppressions.jsonl``.

    Phase 6 extended this helper to emit records for BOTH the
    ``suppress`` verdict and the ``candidate_only`` verdict (the
    finding survives to the LLM, but the value-bound suppressor saw
    enough catalog matches to be worth recording — ``dropped:
    false``). ``no_suppress`` is still a no-op; nothing to log.

    ``enforce`` controls the ``dropped`` field for the ``suppress``
    verdict. The default is ``False`` — record-only: the verdict is
    written as evidence (``dropped: false``, ``enforced: false``)
    without asserting that any finding was removed. The sanitizer-cut
    witness kind EARNED hard-suppression on 2026-08-19 (operator-
    approved; zero-false-suppress corpus clean at flip time — see the
    attested ``sanitizer_dominated`` entry in
    :mod:`core.analysis.reach_witness`). The enforcement consumer is
    the scan post-pass, which passes ``enforce=True`` for full-proof
    ``suppress`` verdicts only and is itself bounded by the spec's
    ``earns_suppression`` field — reverting that one field returns
    every caller to record-only. ``candidate_only`` records can never
    carry ``enforce=True`` (the postpass call structure makes it
    impossible; pinned by test).

    Verdict tags:

    * :data:`VERDICT_SANITIZER_DOMINATED` for suppressions.
    * :data:`VERDICT_SANITIZER_CANDIDATE` for candidate-only
      records.

    Witness fields written into ``extra``:

    * ``sink_arg`` — the symbol consumed at the sink.
    * ``bindings`` — list of value-bound binding records
      (callable, input_symbols, output_symbols, lineno). For
      ``suppress`` these are the bindings whose nodes formed the
      cut; for ``candidate_only`` these are the bindings that
      satisfied the value gate without yielding a suppressing
      cut (empty when none did).
    * ``catalog_matches`` — list of ALL catalog-matched binding
      records in the CFG (a superset of ``bindings`` for
      ``suppress``; the full set for ``candidate_only`` so
      operators can see what was tried).
    * ``witness_lines`` — the source lines of every catalog
      match, sorted for stable jq filtering.

    Delegates to
    :func:`core.analysis.reach_chokepoint.record_suppression` so
    the JSONL shape stays compatible with the binary-oracle
    records that share the file. The ``dropped`` field
    distinguishes drops from surviving-but-recorded findings —
    operators can ``jq 'select(.dropped == false)'`` to see what
    the value-bound gate flagged but didn't drop.

    Live wiring: :func:`core.dataflow.smt_barrier._value_bound_dominates`
    calls this (record-only, ``enforce=False``) whenever the value-bound
    gate runs with an audit directory configured
    (``sanitizer_cut_config.audit_dir``). The binary-oracle reachability
    suppression runs first (pre-LLM), so a function it dropped never
    reaches this gate — see
    :func:`core.analysis.reach_chokepoint.record_suppression` for the
    full order-of-operations contract.
    """
    if result.verdict == VERDICT_SUPPRESS:
        verdict_tag = VERDICT_SANITIZER_DOMINATED
        dropped = bool(enforce)
    elif result.verdict == VERDICT_CANDIDATE_ONLY:
        verdict_tag = VERDICT_SANITIZER_CANDIDATE
        dropped = False
    else:
        # VERDICT_NO_SUPPRESS — nothing to record.
        return

    from core.analysis.reach_chokepoint import record_suppression

    # The record MUST carry the sink line (b45, post-b44 stop-ship):
    # a record with line=null blinded the warm damage matcher — six
    # real Juliet findings were enforced away while damage read 0.
    # The single writer hardens every caller: derive line from the
    # finding's sink_line when the caller didn't set line, and warn
    # loudly when neither exists (the matcher treats such records as
    # damage against labeled files — a record that cannot prove where
    # it is cannot prove it is harmless).
    if finding.get("line") is None:
        sink_line = finding.get("sink_line")
        if sink_line is not None:
            finding = dict(finding)
            finding["line"] = int(sink_line)
        else:
            logger.warning(
                "sanitizer-cut record without a sink line (%s) — it "
                "will read as recall damage against any labeled file",
                finding.get("file_path") or finding.get("file") or "?",
            )

    catalog_matches = sorted(
        result.all_matched_bindings, key=lambda b: (b.lineno, b.callable),
    )
    value_bindings = sorted(
        result.value_bound_bindings, key=lambda b: (b.lineno, b.callable),
    )

    extra: dict[str, Any] = {
        "sink_arg": result.sink_arg,
        "bindings": [_binding_to_json(b) for b in value_bindings],
        "catalog_matches": [_binding_to_json(b) for b in catalog_matches],
        "witness_lines": sorted({b.lineno for b in catalog_matches}),
        "enforced": bool(enforce),
        # The suppressed finding's CWE — consumers matching records
        # against ground-truth entries need it to avoid cross-CWE
        # misattribution on file-level entries (observed: an XSS-rule
        # suppression on a file whose expected finding is CWE-501 read
        # as recall damage).
        "cwe": str(
            finding.get("cwe") or finding.get("cwe_id") or ""
        ),
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
    "VERDICT_CANDIDATE_ONLY",
    "VERDICT_NO_SUPPRESS",
    "VERDICT_SANITIZER_CANDIDATE",
    "VERDICT_SANITIZER_DOMINATED",
    "VERDICT_SUPPRESS",
    "SanitizerCutResult",
    "evaluate_finding",
    "record_sanitizer_cut_suppression",
    "sanitizer_cuts_source_to_sink",
]
