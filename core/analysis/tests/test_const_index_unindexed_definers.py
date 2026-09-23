"""JavaConstIndex line-keyed ``rhs_at`` vs non-indexed definer kinds.

The index records declarators and plain ``=`` assignments. The
reaching-defs oracle also emits definers the index never records —
enhanced-for headers, catch parameters, try-with-resources names,
pattern bindings, formal parameters. When such a definer shares its
(line, name) key with an indexed write (one-liner spellings), a
line-keyed lookup cannot tell the definer nodes apart and would serve
the indexed RHS for BOTH — a constant proof minted over the tainted
binding. Same-line collision with any unindexed definer kind must
refuse; the multi-line spelling keeps folding.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import JavaConstIndex  # noqa: E402


def _index(src: str) -> JavaConstIndex:
    idx = JavaConstIndex(src, (1, src.count("\n") + 1))
    assert idx.ok
    return idx


class TestUnindexedDefinerCollision:
    def test_enhanced_for_one_liner_refuses(self):
        # The for header BINDS x from the tainted list on the same
        # line as the x = "safe" assignment: rd returns both definers,
        # rhs_at must not serve "safe" for the header.
        src = (
            "public class T {\n"
            "    void m(java.util.List<String> tainted) {\n"
            "        for (String x : tainted) {"
            " if (x.isEmpty()) x = \"safe\"; sink(x); }\n"
            "    }\n"
            "}\n"
        )
        assert _index(src).rhs_at(3, "x") is None

    def test_catch_param_one_liner_refuses(self):
        src = (
            "public class T {\n"
            "    void m() {\n"
            "        try { work(); } catch (Exception x) {"
            " x = \"safe\"; sink(x); }\n"
            "    }\n"
            "}\n"
        )
        assert _index(src).rhs_at(3, "x") is None

    def test_instanceof_pattern_one_liner_refuses(self):
        src = (
            "public class T {\n"
            "    void m(Object o) {\n"
            "        if (o instanceof String x) {"
            " x = \"safe\"; sink(x); }\n"
            "    }\n"
            "}\n"
        )
        assert _index(src).rhs_at(3, "x") is None

    def test_method_param_same_line_refuses(self):
        src = (
            "public class T {\n"
            "    void m(String x) { if (c()) x = \"safe\"; sink(x); }\n"
            "}\n"
        )
        assert _index(src).rhs_at(2, "x") is None

    def test_multi_line_spelling_still_serves(self):
        # Control: the assignment on its own line has no colliding
        # definer kind — the index keeps serving it.
        src = (
            "public class T {\n"
            "    void m(java.util.List<String> tainted) {\n"
            "        for (String x : tainted) {\n"
            "            x = \"safe\";\n"
            "            sink(x);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        assert _index(src).rhs_at(4, "x") is not None
