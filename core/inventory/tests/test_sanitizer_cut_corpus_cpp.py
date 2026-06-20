"""Phase 11 — C / C++ corpus end-to-end tests.

Mirrors ``test_sanitizer_cut_corpus.py``: parametrise over fixtures
under ``fixtures/sanitizer_cut_corpus_cpp/`` and assert each one
resolves and produces the expected verdict end-to-end (resolver →
evaluate_finding). Each fixture's docstring documents what verdict
is expected and why.

Also includes a Phase 4 auto-downgrade regression test: the Phase
3 callgraph path (no call_sites, just a function-name match) still
returns candidate_only because the binding's input/output symbol
sets are empty. Phase 11 removed the auto-downgrade ONLY for the
intra-procedural CFG path; the callgraph path is unchanged.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.inventory.finding_resolver import (
    ResolvedFinding,
    resolve_finding,
)
from core.inventory.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_NO_SUPPRESS,
    VERDICT_SUPPRESS,
    evaluate_finding,
)

pytest.importorskip("tree_sitter_c")

_CORPUS_DIR = (
    Path(__file__).parent
    / "fixtures"
    / "sanitizer_cut_corpus_cpp"
)


# Each tuple: (fixture, cwe, source_line, sink_line, expected_verdict,
#              expected_sink_arg)
#
# source_line is the ``void handle(...)`` header line — triggers the
# function-entry / params source path in :func:`_resolve_source_cpp`.
_CORPUS_CASES = [
    ("straight_line_safe.c", "CWE-79", 12, 14, VERDICT_SUPPRESS, "y"),
    ("symmetric_sanitize.c", "CWE-79", 14, 21, VERDICT_SUPPRESS, "out"),
    ("wrong_variable.c", "CWE-79", 15, 17, VERDICT_CANDIDATE_ONLY, "user"),
    ("bypass.c", "CWE-79", 12, 19, VERDICT_NO_SUPPRESS, "safe"),
    ("may_escape.c", "CWE-79", 16, 20, VERDICT_CANDIDATE_ONLY, "y"),
]


def _native_finding(fixture: str, cwe: str, source_line: int, sink_line: int):
    return {
        "cwe": cwe,
        "file_path": str(_CORPUS_DIR / fixture),
        "source_line": source_line,
        "sink_line": sink_line,
        "language": "c",
    }


@pytest.mark.parametrize(
    "fixture,cwe,source_line,sink_line,expected_verdict,expected_sink_arg",
    _CORPUS_CASES,
)
def test_corpus_fixture_verdict(
    fixture, cwe, source_line, sink_line, expected_verdict, expected_sink_arg,
):
    """Resolve the fixture via the Phase 11 C/C++ resolver, run the
    gate, assert the verdict matches the docstring's claim."""
    finding = _native_finding(fixture, cwe, source_line, sink_line)
    resolved = resolve_finding(finding)
    assert isinstance(resolved, ResolvedFinding), (
        f"resolver failed on {fixture}: {resolved}"
    )
    assert resolved.language == "c"
    assert resolved.sink_arg == expected_sink_arg, (
        f"{fixture}: sink_arg={resolved.sink_arg!r}, "
        f"expected {expected_sink_arg!r}"
    )
    result = evaluate_finding(
        resolved.cfg, [resolved.source_node], resolved.sink_node,
        cwe=resolved.cwe, language=resolved.language,
        source_symbols=resolved.source_symbols,
        sink_arg=resolved.sink_arg,
    )
    assert result.verdict == expected_verdict, (
        f"{fixture}: verdict={result.verdict!r}, "
        f"expected {expected_verdict!r}. Reason: {result.reason}"
    )


def test_corpus_ablation_summary(capsys):
    """Print a per-fixture verdict table — the Phase 11 ablation
    report. CORPUS.md's numbers are kept in sync with this output."""
    rows = []
    for fixture, cwe, src_line, sink_line, expected, _ in _CORPUS_CASES:
        finding = _native_finding(fixture, cwe, src_line, sink_line)
        resolved = resolve_finding(finding)
        if not isinstance(resolved, ResolvedFinding):
            rows.append((fixture, "(unresolved)", expected, "fail"))
            continue
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
        )
        rows.append((fixture, result.verdict, expected,
                     "ok" if result.verdict == expected else "MISMATCH"))
    print()
    print(f"{'Fixture':<32} {'Got':<18} {'Expected':<18} {'Status':<8}")
    for fixture, got, expected, status in rows:
        print(f"{fixture:<32} {got:<18} {expected:<18} {status:<8}")
    mismatches = [r for r in rows if r[3] != "ok"]
    assert not mismatches, f"{len(mismatches)} fixture(s) mismatched"


# ---------------------------------------------------------------------------
# Resolver-level coverage
# ---------------------------------------------------------------------------


def test_resolver_returns_cppcfg_for_c_file(tmp_path):
    """Smoke: a C finding resolves to a ResolvedFinding whose ``cfg``
    is a CPPCFG (not a PythonCFG)."""
    from core.inventory.cfg_builder_cpp import CPPCFG
    src = _CORPUS_DIR / "straight_line_safe.c"
    finding = {
        "cwe": "CWE-79",
        "file_path": str(src),
        "source_line": 12,
        "sink_line": 14,
        "language": "c",
    }
    resolved = resolve_finding(finding)
    assert isinstance(resolved, ResolvedFinding)
    assert isinstance(resolved.cfg, CPPCFG)


def test_resolver_handles_cpp_language_alias(tmp_path):
    """``language="cpp"`` routes through the same C/C++ branch."""
    cpp = tmp_path / "x.cpp"
    cpp.write_text(
        "extern char *g_markup_escape_text(const char *, long);\n"
        "extern void render(const char *);\n"
        "void handle(const char *x) {\n"
        "    const char *y = g_markup_escape_text(x, -1);\n"
        "    render(y);\n"
        "}\n",
        encoding="utf-8",
    )
    finding = {
        "cwe": "CWE-79",
        "file_path": str(cpp),
        "source_line": 3,
        "sink_line": 5,
        "language": "cpp",
    }
    resolved = resolve_finding(finding)
    assert isinstance(resolved, ResolvedFinding)
    assert resolved.language == "cpp"


def test_resolver_failure_when_no_enclosing_function(tmp_path):
    """Missing enclosing function → ResolutionFailure with a
    descriptive reason. The Phase 11 path must not crash."""
    from core.inventory.finding_resolver import ResolutionFailure
    src = tmp_path / "junk.c"
    src.write_text("int x;\nint y;\n", encoding="utf-8")
    finding = {
        "cwe": "CWE-79", "file_path": str(src),
        "source_line": 1, "sink_line": 2, "language": "c",
    }
    result = resolve_finding(finding)
    assert isinstance(result, ResolutionFailure)
    assert "no enclosing" in result.reason.lower()


# ---------------------------------------------------------------------------
# Phase 4 callgraph auto-downgrade — preserved
# ---------------------------------------------------------------------------


def test_callgraph_only_still_candidate_only():
    """Phase 11 removed the auto-downgrade ONLY for the intra-proc
    CFG path. A bare callgraph node with no call_sites still
    produces a binding with empty input/output symbols → condition 2
    fails → candidate_only when control-flow cut holds. Documents
    the design's "function-level edges can't prove argument
    binding" carve-out."""
    from core.inventory.cfg_builder import CallGraphNode
    from core.dataflow.sanitizer_catalog import match_sanitizers_in_cfg

    # Synthetic callgraph-style node (no call_sites attribute) with
    # ``name`` matching a catalog entry. The recognizer's fallback
    # arm produces a binding with empty input/output symbol sets —
    # by design.
    class _StubGraph:
        def __init__(self, nodes_):
            self._nodes = nodes_

        def nodes(self):
            return self._nodes

    node = CallGraphNode(name="g_markup_escape_text")
    bindings = match_sanitizers_in_cfg(_StubGraph([node]), "CWE-79", "c")
    assert len(bindings) == 1
    binding = next(iter(bindings))
    assert binding.input_symbols == frozenset()
    assert binding.output_symbols == frozenset()
    # The empty input_symbols means Phase 4 condition 2 always fails
    # for this binding regardless of the source taint — the
    # callgraph carve-out is intact.
