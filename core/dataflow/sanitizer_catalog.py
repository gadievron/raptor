"""Sanitizer catalog and CFG-aware recognizer — Phase 6 of the sanitizer-cut arc.

Layered on top of :mod:`core.dataflow.known_safe_calls` (the existing
24-entry curated table — sink classes ``xss`` / ``sqli`` / ``cmdi`` /
``pathtrav``; languages Python / Java / JavaScript / TypeScript). The
known-safe table stays the single source of truth for *which* calls are
sanitizers; this module adds two things on top:

1. A CWE → sink-class mapping so a finding tagged with a CWE
   identifier (the shape every static analyser emits) can be matched
   against the catalogue's sink-class keys.
2. A recognizer :func:`match_sanitizers_in_cfg` that walks a CFG
   produced by :mod:`core.inventory.cfg_builder` and returns the set
   of nodes whose statement-level calls (or, for the C/C++ call
   graph, whose own function name) are catalogue sanitizers for the
   given CWE + language.

Phase 7 will consume the returned node set as the *candidate
sanitizer set* in its vertex-cut suppression test: removing those
nodes from the graph and asking "is the sink still reachable from
the source?" answers the suppression question without ever calling
the LLM.

No new sanitizer data lands here — duplicating the known-safe table
risks the two going out of sync as new entries are reviewed in.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import (
    Any,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Set,
    TypeVar,
)

from core.dataflow.known_safe_calls import (
    all_entries,
)


N = TypeVar("N")


# ---------------------------------------------------------------------------
# Symbol-bound binding (Phase 3 of value-binding arc)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SanitizerBinding:
    """One catalog-matched sanitizer call located in a CFG.

    Where Phase 6 returned just the CFG node, Phase 3 returns the
    full binding: the node, the matched dotted callable, the
    *input symbols* the call's args read (bare-name surface from
    Phase 1's :class:`CallSite.arg_names`), and the *output symbols*
    the call's return flows into (Phase 1's
    :class:`CallSite.assigned_names`).

    Phase 4's four-condition gate reads these to decide whether the
    sanitizer is on the source-to-sink *value* flow — not just the
    *control* flow. The four conditions:

      1. ``callable`` is in :func:`sanitizer_callables_for_cwe`
      2. ``input_symbols ∩ symbols_tainted_at(node)`` is non-empty
      3. ``output_symbols`` reaches the sink arg via reaching-defs
      4. removing the value-bound subset of bindings cuts every
         source → sink path

    Bindings synthesised from C/C++ call-graph nodes (no value
    layer) carry empty ``input_symbols`` / ``output_symbols`` —
    condition 2 always fails, so Phase 4 downgrades to
    ``candidate_only`` rather than suppressing.
    """
    node: Any
    callable: str
    input_symbols: FrozenSet[str]
    output_symbols: FrozenSet[str]
    lineno: int


def nodes_of(bindings: Iterable[SanitizerBinding]) -> Set[Any]:
    """Project a binding set down to its underlying CFG nodes.

    Helper for Phase 7's vertex-cut consumer (which works on nodes,
    not bindings). Two bindings on the same node — e.g. a call site
    that matches two sink classes for the same CWE — collapse to
    one entry.
    """
    return {b.node for b in bindings}


# ---------------------------------------------------------------------------
# CWE → sink-class mapping
# ---------------------------------------------------------------------------


# Mapping from CWE identifier (canonical form ``CWE-<n>`` and bare
# numeric ``<n>`` both accepted by the lookup) to the catalogue's
# sink-class keys. Only the classes for which the curated table
# actually carries entries are mapped — adding a CWE here without a
# matching catalogue entry would silently mean "no sanitizers
# recognized" and is not worth modelling as data.
#
# Each tuple is the set of sink classes the CWE neutralizes. CWE-94
# (code injection) intentionally maps to nothing — the catalog has
# no recognized sanitizers for it, and pretending otherwise would
# produce false suppressions in Phase 7.
_CWE_TO_SINK_CLASSES: Mapping[str, frozenset] = {
    # Cross-site scripting and variants
    "CWE-79": frozenset({"xss"}),
    "CWE-80": frozenset({"xss"}),
    "CWE-87": frozenset({"xss"}),
    "CWE-116": frozenset({"xss"}),
    # SQL injection family
    "CWE-89": frozenset({"sqli"}),
    "CWE-564": frozenset({"sqli"}),  # Hibernate-specific SQLi variant
    # OS command / shell injection
    "CWE-77": frozenset({"cmdi"}),
    "CWE-78": frozenset({"cmdi"}),
    "CWE-88": frozenset({"cmdi"}),
    # Path traversal family
    "CWE-22": frozenset({"pathtrav"}),
    "CWE-23": frozenset({"pathtrav"}),
    "CWE-35": frozenset({"pathtrav"}),
    "CWE-36": frozenset({"pathtrav"}),
    "CWE-37": frozenset({"pathtrav"}),
    "CWE-38": frozenset({"pathtrav"}),
}


def _normalize_cwe(cwe: str) -> str:
    """Accept ``"CWE-79"``, ``"cwe-79"``, ``"79"``, ``"CWE-079"`` and
    return the canonical ``"CWE-79"`` form. Returns the input
    unchanged when it doesn't look like a CWE id so unknown lookups
    return a clean empty set rather than raising."""
    raw = cwe.strip().upper()
    if raw.startswith("CWE-"):
        raw = raw[4:]
    if raw.isdigit():
        return f"CWE-{int(raw)}"
    return cwe


def sink_classes_for_cwe(cwe: str) -> frozenset:
    """Return the catalog sink-class keys that ``cwe`` neutralizes.

    Empty frozenset for unknown CWEs — Phase 7 should treat that as
    "no sanitizer suppression possible" and let the finding through.
    """
    return _CWE_TO_SINK_CLASSES.get(_normalize_cwe(cwe), frozenset())


# ---------------------------------------------------------------------------
# Catalog query
# ---------------------------------------------------------------------------


def sanitizer_callables_for_cwe(
    cwe: str, language: str,
) -> Set[str]:
    """Return the set of ``library_call`` identifiers from the
    known-safe catalog that neutralize ``cwe`` for ``language``.

    The set this function returns is the input to Phase 7's
    vertex-cut deletion: nodes in the CFG whose called callables
    intersect this set are the sanitizer candidates.
    """
    sink_classes = sink_classes_for_cwe(cwe)
    if not sink_classes:
        return set()
    out: Set[str] = set()
    for entry in all_entries():
        if entry.sink_class in sink_classes and language in entry.languages:
            out.add(entry.library_call)
    return out


def all_sanitizer_callables(language: str) -> Set[str]:
    """Every catalog entry for ``language``, irrespective of sink class.
    Useful for callers that haven't tagged the finding with a CWE
    (they get over-broad suppression rather than none)."""
    return {
        entry.library_call
        for entry in all_entries()
        if language in entry.languages
    }


# ---------------------------------------------------------------------------
# CFG recognizer
# ---------------------------------------------------------------------------


def _node_calls(node: N) -> Iterable[str]:
    """Extract the set of callable names from a CFG node — the
    legacy projection used when the node has no Phase-1 ``call_sites``.

    Duck-typed for both producers from
    :mod:`core.inventory.cfg_builder`:

    * :class:`PyCFGNode` — ``calls`` field, frozen set of statement-
      level call names.
    * :class:`CallGraphNode` — the node ``name`` is itself the
      callee (a function-granularity call graph treats every node
      as a call).
    """
    if hasattr(node, "calls"):
        return getattr(node, "calls") or ()
    if hasattr(node, "name"):
        return (getattr(node, "name"),)
    return ()


def match_sanitizers_in_cfg(
    graph, cwe: str, language: str,
) -> FrozenSet[SanitizerBinding]:
    """Return the set of :class:`SanitizerBinding` records that
    correspond to catalog-matched sanitizer calls in ``graph`` for
    ``cwe`` + ``language``.

    The graph must satisfy :class:`core.inventory.dominators.Graph`
    (``nodes()`` available). Each binding carries the node, the
    matched callable, the call's input/output symbols (from Phase
    1's :class:`CallSite`), and the call's line number. Multiple
    matched calls on the same node produce multiple bindings; use
    :func:`nodes_of` to collapse to the legacy node-set view.

    Recognition fall-backs:

    * **Phase-1 nodes** (``call_sites`` non-empty): one binding per
      matched :class:`CallSite`, with full ``input_symbols`` and
      ``output_symbols``.
    * **Legacy ``PyCFGNode``** (only the old ``calls`` frozenset):
      one binding per matched name; symbol sets empty. Phase 4 will
      downgrade to ``candidate_only`` because the value-binding
      gate's input/output conditions can't fire.
    * **Call-graph node** (function-granularity, no call_sites and
      no calls field): one binding for the node itself when its
      ``name`` matches; symbol sets empty. Same Phase 4 downgrade.

    Returns an empty frozenset when the CWE has no catalog-recognised
    sanitizers — Phase 7 must check this and decline to suppress
    rather than falsely conclude "every path is sanitized".
    """
    sanitizer_names = sanitizer_callables_for_cwe(cwe, language)
    if not sanitizer_names:
        return frozenset()
    bindings: List[SanitizerBinding] = []
    for node in graph.nodes():
        call_sites = getattr(node, "call_sites", ()) or ()
        if call_sites:
            for cs in call_sites:
                if cs.name in sanitizer_names:
                    bindings.append(SanitizerBinding(
                        node=node,
                        callable=cs.name,
                        input_symbols=cs.arg_names,
                        output_symbols=cs.assigned_names,
                        lineno=cs.lineno,
                    ))
            continue
        # Legacy / call-graph fallback: matched names with empty
        # symbol layer. Phase 4 downgrades these to candidate_only.
        node_calls = set(_node_calls(node))
        for matched_name in node_calls & sanitizer_names:
            bindings.append(SanitizerBinding(
                node=node,
                callable=matched_name,
                input_symbols=frozenset(),
                output_symbols=frozenset(),
                lineno=getattr(node, "lineno", 0),
            ))
    return frozenset(bindings)


__all__ = [
    "SanitizerBinding",
    "nodes_of",
    "sink_classes_for_cwe",
    "sanitizer_callables_for_cwe",
    "all_sanitizer_callables",
    "match_sanitizers_in_cfg",
]
