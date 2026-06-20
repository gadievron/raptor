"""Intra-procedural reaching-definitions — Phase 2 of the value-binding arc.

Answers one question for every ``(node, symbol)`` pair in a CFG:
*which earlier nodes' writes of this symbol could survive to this
node's entry?*

The result is the substrate Phase 4's four-condition gate reads:

* Condition 2 (taint flows into the sanitizer) needs to know, at the
  sanitizer node, which definers reach each tainted symbol — i.e.
  whether the source's parameter is still the live definer of the
  variable the sanitizer reads.
* Condition 3 (sanitizer's output reaches the sink) needs the
  reverse — at the sink node, is the sanitizer's node still the
  live definer of the symbol the sink consumes?

Standard textbook reaching-defs implemented as an iterative
worklist over the :class:`core.inventory.dominators.Graph` Protocol.
No dominator tree required — a forward CFG and node-level
``defs: frozenset[str]`` are sufficient.

Function parameters are handled by treating the CFG's entry node as
virtually defining each parameter. ``PythonCFG.params`` provides the
list; call graphs and synthetic CFGs without a ``params`` attribute
fall through with empty params, which is correct for those graph
shapes (parameters aren't a call-graph concept).

This module is pure: no IO, no logging, no global state. Termination
is guaranteed by the monotone-framework property of reaching-defs
(the IN-sets grow monotonically toward a least fixed point).
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import (
    Any,
    Deque,
    Dict,
    FrozenSet,
    Mapping,
    Set,
    Tuple,
)


# A reaching-def pair is (symbol, defining_node). Using a flat set
# of pairs (rather than a per-symbol map) keeps the worklist's
# set-union / set-difference operations to single ``frozenset`` calls.
_Pair = Tuple[str, Any]


@dataclass(frozen=True)
class ReachingDefs:
    """Per-node IN-sets, queried by symbol.

    Construct via :func:`reaching_defs`. The internal mapping is
    ``node -> frozenset[(symbol, definer_node)]`` — the set of
    definitions that survive to the node's entry. Queries project
    out the per-symbol view.

    Empty result for ``at(node, symbol)`` means **no definition of
    that symbol reaches this node** — either the symbol was never
    written along any path to here (uninitialised use, out of scope)
    or every prior definition was killed by an intervening rewrite
    on every path.
    """
    _in: Mapping[Any, FrozenSet[_Pair]]

    def at(self, node: Any, symbol: str) -> FrozenSet[Any]:
        """Definer nodes whose write of ``symbol`` reaches ``node``'s
        IN-set."""
        return frozenset(
            n for (s, n) in self._in.get(node, frozenset()) if s == symbol
        )

    def all_at(self, node: Any) -> Mapping[str, FrozenSet[Any]]:
        """Full ``{symbol -> frozenset[definer]}`` map at ``node``'s
        IN — handy for diagnostics."""
        bucket: Dict[str, Set[Any]] = defaultdict(set)
        for (s, n) in self._in.get(node, frozenset()):
            bucket[s].add(n)
        return {s: frozenset(ns) for s, ns in bucket.items()}


def reaching_defs(cfg: Any) -> ReachingDefs:
    """Compute reaching-definitions IN-sets for every node in ``cfg``.

    ``cfg`` must implement the Graph[N] Protocol from
    :mod:`core.inventory.dominators`: ``entry``, ``nodes()``,
    ``successors(node)``. Stmt nodes are expected to expose
    ``defs: frozenset[str]`` (entry / exit sentinels with no defs
    are handled correctly — :func:`getattr` defaults to empty).

    If ``cfg`` exposes ``params: tuple[str, ...]`` (as
    :class:`core.inventory.cfg_builder.PythonCFG` does), the entry
    node is treated as virtually defining each parameter. A body
    use of a parameter then resolves to the entry as its reaching
    definer.

    Algorithm: standard iterative worklist over the forward CFG.

    * ``GEN[n] = {(s, n) for s in defs(n)}``
    * ``OUT[n] = GEN[n] ∪ {(s, m) ∈ IN[n] | s ∉ defs(n)}``
    * ``IN[n] = ⋃ {OUT[p] | p ∈ preds(n)}``

    Worst-case complexity ``O((V + E) * |Symbols|)``; termination
    guaranteed by monotonicity.
    """
    nodes = list(cfg.nodes())
    if not nodes:
        return ReachingDefs(_in={})

    # Forward edges via cfg.successors; invert to get predecessors
    # for the IN-set merge step.
    preds: Dict[Any, Set[Any]] = defaultdict(set)
    for n in nodes:
        for succ in cfg.successors(n):
            preds[succ].add(n)

    params: Tuple[str, ...] = tuple(getattr(cfg, "params", ()) or ())
    entry = cfg.entry

    def _node_defs(n: Any) -> FrozenSet[str]:
        explicit: FrozenSet[str] = getattr(n, "defs", frozenset())
        if n is entry and params:
            return frozenset(set(explicit) | set(params))
        return explicit

    def _gen(n: Any) -> FrozenSet[_Pair]:
        return frozenset((s, n) for s in _node_defs(n))

    # Initial state: IN empty, OUT = GEN. The worklist then
    # propagates definitions forward to fixed point.
    in_set: Dict[Any, FrozenSet[_Pair]] = {
        n: frozenset() for n in nodes
    }
    out_set: Dict[Any, FrozenSet[_Pair]] = {
        n: _gen(n) for n in nodes
    }

    worklist: Deque[Any] = deque(nodes)
    in_worklist: Set[Any] = set(nodes)
    while worklist:
        n = worklist.popleft()
        in_worklist.discard(n)

        # IN[n] = union of OUT[p] for p in preds(n)
        new_in_acc: Set[_Pair] = set()
        for p in preds.get(n, ()):
            new_in_acc |= out_set[p]
        new_in = frozenset(new_in_acc)
        in_set[n] = new_in

        # OUT[n] = GEN[n] ∪ (IN[n] - KILL[n]). KILL[n] is "any pair
        # whose symbol n redefines"; we filter directly rather than
        # materialising KILL.
        defs = _node_defs(n)
        if defs:
            kept = frozenset((s, m) for (s, m) in new_in if s not in defs)
        else:
            kept = new_in
        new_out = _gen(n) | kept

        if new_out != out_set[n]:
            out_set[n] = new_out
            for succ in cfg.successors(n):
                if succ not in in_worklist:
                    worklist.append(succ)
                    in_worklist.add(succ)

    return ReachingDefs(_in=in_set)


__all__ = [
    "ReachingDefs",
    "reaching_defs",
]
