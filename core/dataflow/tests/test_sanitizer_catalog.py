"""Tests for ``core.dataflow.sanitizer_catalog`` — Phase 6 (a + b).

Three properties this module is responsible for:

1. **Data integrity** — every entry in the underlying
   ``known_safe_calls`` table is reachable via *some* CWE lookup
   (no entries are "orphaned" by an incomplete CWE → sink-class
   mapping).
2. **CWE normalization** — the canonical form (`"CWE-79"`) and
   common variants (`"cwe-79"`, `"79"`, `"CWE-079"`) all resolve to
   the same sink classes.
3. **CFG recognizer correctness** — `match_sanitizers_in_cfg`
   identifies the right nodes in a Python CFG and the right
   functions in a C/C++ call graph, and does NOT match wrong-CWE
   or wrong-language sanitizers.

The catalog itself (which calls are safe for what sink class) is
the responsibility of ``known_safe_calls`` and tested in that
module's own suite. We test the *bridge*: CWE mapping + recognizer.
"""
from __future__ import annotations

from unittest import mock

import pytest

from core.dataflow.known_safe_calls import all_entries
from core.dataflow.sanitizer_catalog import (
    all_sanitizer_callables,
    match_sanitizers_in_cfg,
    sanitizer_callables_for_cwe,
    sink_classes_for_cwe,
)
from core.inventory.cfg_builder import (
    build_cpp_callgraph,
    build_python_cfg,
)


# ---------------------------------------------------------------------------
# Data integrity — no orphaned catalog entries
# ---------------------------------------------------------------------------


def test_every_catalog_entry_is_reachable_via_some_cwe():
    """If a known_safe_calls entry exists with sink_class X, there
    must be at least one CWE in our mapping that resolves to X.
    Otherwise the entry is unreachable from any finding — it
    contributes to no suppression decision."""
    used_sink_classes: set = set()
    for entry in all_entries():
        used_sink_classes.add(entry.sink_class)
    # Walk every CWE → sink-classes mapping and union.
    from core.dataflow.sanitizer_catalog import _CWE_TO_SINK_CLASSES
    covered: set = set()
    for sinks in _CWE_TO_SINK_CLASSES.values():
        covered |= sinks
    orphans = used_sink_classes - covered
    assert not orphans, (
        f"sink classes have catalog entries but no CWE mapping: {orphans}"
    )


def test_no_cwe_maps_to_unknown_sink_class():
    """Conversely: every CWE mapping should resolve to a sink class
    that actually has catalog entries. A CWE that maps to nothing
    causes Phase 7 to falsely report 'no sanitizers possible'
    instead of warning that the mapping is dead."""
    from core.dataflow.sanitizer_catalog import _CWE_TO_SINK_CLASSES
    real_sink_classes = {e.sink_class for e in all_entries()}
    for cwe, sinks in _CWE_TO_SINK_CLASSES.items():
        unknown = sinks - real_sink_classes
        assert not unknown, (
            f"{cwe} maps to sink classes with no catalog entries: {unknown}"
        )


# ---------------------------------------------------------------------------
# CWE normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("variant", [
    "CWE-79", "cwe-79", "Cwe-79", "79", "CWE-079",
])
def test_cwe_normalization_canonicalizes(variant):
    assert sink_classes_for_cwe(variant) == frozenset({"xss"})


def test_unknown_cwe_returns_empty():
    assert sink_classes_for_cwe("CWE-99999") == frozenset()
    assert sink_classes_for_cwe("not-a-cwe") == frozenset()
    assert sink_classes_for_cwe("") == frozenset()


def test_path_traversal_family_all_mapped():
    """CWE-22, 23, 35, 36, 37, 38 all map to pathtrav — finder
    surfaces vary which they emit."""
    for cwe in ("CWE-22", "CWE-23", "CWE-35", "CWE-36", "CWE-37", "CWE-38"):
        assert sink_classes_for_cwe(cwe) == frozenset({"pathtrav"}), cwe


# ---------------------------------------------------------------------------
# Catalog lookup
# ---------------------------------------------------------------------------


def test_xss_python_returns_expected_sanitizers():
    found = sanitizer_callables_for_cwe("CWE-79", "python")
    # The catalog ships at least these four for XSS+python.
    assert "html.escape" in found
    assert "django.utils.html.escape" in found
    assert "markupsafe.escape" in found
    assert "bleach.clean" in found


def test_xss_java_returns_java_only():
    found = sanitizer_callables_for_cwe("CWE-79", "java")
    # Apache Commons is the canonical Java XSS sanitizer in the catalog.
    assert "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4" in found
    # Python-only entries must NOT appear.
    assert "html.escape" not in found


def test_sqli_javascript_returns_js_only():
    found = sanitizer_callables_for_cwe("CWE-89", "javascript")
    assert "connection.escape" in found
    # Python entries excluded
    assert "shlex.quote" not in found


def test_pathtrav_python():
    found = sanitizer_callables_for_cwe("CWE-22", "python")
    assert "werkzeug.security.safe_join" in found
    assert "werkzeug.utils.secure_filename" in found


def test_unknown_language_returns_empty():
    assert sanitizer_callables_for_cwe("CWE-79", "haskell") == set()


def test_all_sanitizer_callables_union():
    """``all_sanitizer_callables`` returns every catalog entry for a
    language, regardless of CWE."""
    py_all = all_sanitizer_callables("python")
    xss = sanitizer_callables_for_cwe("CWE-79", "python")
    sqli = sanitizer_callables_for_cwe("CWE-89", "python")
    pathtrav = sanitizer_callables_for_cwe("CWE-22", "python")
    cmdi = sanitizer_callables_for_cwe("CWE-78", "python")
    # The union of per-CWE sets is a subset of all_sanitizer_callables.
    assert (xss | sqli | pathtrav | cmdi) <= py_all


# ---------------------------------------------------------------------------
# CFG recognizer — Python
# ---------------------------------------------------------------------------


def _cfg(src: str, func: str = "handle"):
    return build_python_cfg(src, func)


def test_recognizes_bare_call_sanitizer():
    """``html.escape(x)`` should be recognized as a CWE-79 sanitizer.

    Phase 3 rev: the recognizer returns SanitizerBinding records,
    not nodes. The binding's ``callable`` field carries the matched
    dotted name."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    return y\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    assert len(matched) == 1
    binding = next(iter(matched))
    assert binding.callable == "html.escape"


def test_recognizes_dotted_attribute_call():
    """``django.utils.html.escape(x)`` should be recognized."""
    src = (
        "def handle(x):\n"
        "    y = django.utils.html.escape(x)\n"
        "    return y\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    assert len(matched) == 1


def test_recognizes_multiple_sanitizers_in_one_function():
    src = (
        "def handle(x, path):\n"
        "    y = html.escape(x)\n"
        "    p = werkzeug.security.safe_join(path)\n"
        "    return y, p\n"
    )
    cfg = _cfg(src)
    xss_matches = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    pathtrav_matches = match_sanitizers_in_cfg(cfg, "CWE-22", "python")
    assert len(xss_matches) == 1
    assert len(pathtrav_matches) == 1
    # Different bindings (different callables, different nodes) —
    # sanitizers are per-CWE.
    assert xss_matches != pathtrav_matches
    assert next(iter(xss_matches)).callable == "html.escape"
    assert next(iter(pathtrav_matches)).callable == "werkzeug.security.safe_join"


def test_wrong_cwe_does_not_match():
    """``html.escape`` should NOT be matched against CWE-89 (SQLi)."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    return y\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-89", "python")
    assert matched == frozenset()


def test_non_sanitizer_call_not_matched():
    """Random function calls (not in the catalog) shouldn't match
    even for the right CWE."""
    src = (
        "def handle(x):\n"
        "    y = my_custom_escape(x)\n"
        "    return y\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    assert matched == frozenset()


def test_no_calls_at_all_returns_empty():
    src = (
        "def handle(x):\n"
        "    return x + 1\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-79", "python")
    assert matched == frozenset()


def test_unknown_cwe_returns_empty_match_set():
    """Phase 7 must distinguish 'no known sanitizers for this CWE'
    from 'sanitizers exist but were absent' — both yield empty sets
    here but Phase 7 will check `sanitizer_callables_for_cwe()`
    separately to differentiate."""
    src = (
        "def handle(x):\n"
        "    y = html.escape(x)\n"
        "    return y\n"
    )
    cfg = _cfg(src)
    matched = match_sanitizers_in_cfg(cfg, "CWE-99999", "python")
    assert matched == frozenset()


# ---------------------------------------------------------------------------
# CFG recognizer — C/C++ call graph (duck-typed)
# ---------------------------------------------------------------------------


def _stub_edge_index(binary_path, edges):
    from core.inventory.binary_oracle_edges import (
        BinaryCallEdge, BinaryEdgeIndex,
    )
    return BinaryEdgeIndex(
        binary_path=str(binary_path),
        edges=[BinaryCallEdge(c, e, str(binary_path)) for c, e in edges],
        callees={e for _, e in edges},
    )


def test_recognizer_works_on_callgraph(tmp_path):
    """If a Java sanitizer name appears as a node in a call graph,
    the recognizer must match it. Duck-typed on ``node.name``."""
    binary = tmp_path / "fake.elf"
    binary.write_bytes(b"")
    edges = [
        ("main", "process"),
        ("process", "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"),
        ("process", "render"),
    ]
    with mock.patch(
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
        return_value=_stub_edge_index(binary, edges),
    ):
        graph = build_cpp_callgraph([binary], entry="main")
    matched = match_sanitizers_in_cfg(graph, "CWE-79", "java")
    # Call-graph nodes have no ``call_sites`` — the recognizer falls
    # back to ``node.name`` as both the callable and the matched
    # identifier. Binding's input/output symbols are empty (no value
    # layer at function granularity); Phase 4 will downgrade to
    # ``candidate_only``.
    matched_callables = {b.callable for b in matched}
    assert matched_callables == {
        "org.apache.commons.lang3.StringEscapeUtils.escapeHtml4"
    }
    for b in matched:
        assert b.input_symbols == frozenset()
        assert b.output_symbols == frozenset()


def test_recognizer_ignores_wrong_language_on_callgraph(tmp_path):
    binary = tmp_path / "fake.elf"
    binary.write_bytes(b"")
    edges = [("main", "html.escape")]  # python name in a "C" graph
    with mock.patch(
        "core.inventory.binary_oracle_edges.extract_direct_call_edges",
        return_value=_stub_edge_index(binary, edges),
    ):
        graph = build_cpp_callgraph([binary], entry="main")
    # Querying with language="java" should not match the python entry.
    matched = match_sanitizers_in_cfg(graph, "CWE-79", "java")
    assert matched == frozenset()
