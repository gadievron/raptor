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

from typing import Iterable, Mapping, Set, TypeVar

from core.dataflow.known_safe_calls import (
    all_entries,
)


N = TypeVar("N")


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
    """Extract the set of callable names from a CFG node.

    Duck-typed so the same recognizer serves both producers from
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
) -> Set:
    """Return the set of CFG nodes that contain a sanitizer call
    appropriate for ``cwe`` + ``language``.

    The graph must satisfy :class:`core.inventory.dominators.Graph`
    (``nodes()`` method available). Returned nodes are exactly the
    ones Phase 7 will remove from the graph in its vertex-cut
    reachability test.

    Returns an empty set when the CWE has no catalog-recognized
    sanitizers — Phase 7 must check this and decline to suppress
    rather than falsely conclude "every path is sanitized".
    """
    sanitizer_names = sanitizer_callables_for_cwe(cwe, language)
    if not sanitizer_names:
        return set()
    matched: Set = set()
    for node in graph.nodes():
        node_calls = set(_node_calls(node))
        if node_calls & sanitizer_names:
            matched.add(node)
    return matched


__all__ = [
    "sink_classes_for_cwe",
    "sanitizer_callables_for_cwe",
    "all_sanitizer_callables",
    "match_sanitizers_in_cfg",
]
