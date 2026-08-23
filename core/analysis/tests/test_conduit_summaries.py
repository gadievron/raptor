"""Unit tests for the b27 conduit-summary layer: derivation
classification, the constant-folder hook, and the call index. The
end-to-end verdicts (transparency walk through the production gate)
are pinned by the precision-corpus battery
(``_java_b27_fixtures`` in ``sanitizer_cut_precision``) and the
corpus test rows."""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")

from core.analysis.cfg_builder_java import _get_parser  # noqa: E402
from core.analysis.java_wrapper_summaries import (  # noqa: E402
    CONDUIT_CONST,
    CONDUIT_JOIN,
    CONDUIT_PARAM,
    conduit_call_map,
    derive_conduit_summaries,
    make_conduit_fold_resolver,
)

if _get_parser() is None:  # pragma: no cover — grammar-less host
    pytest.skip("tree-sitter java grammar unavailable",
                allow_module_level=True)


def _cls(body: str) -> str:
    return "public class T {\n" + body + "}\n"


_HANDLE = ("    public void handle(String x, java.io.PrintWriter out) {\n"
           "        out.println(x);\n    }\n")


def _summaries(source: str):
    s, decisions = derive_conduit_summaries(source, (3, 3))
    return s, decisions


class TestClassification:
    def test_plain_constant(self):
        s, _ = _summaries(_cls(
            _HANDLE
            + "    private String pick() { return \"safe\"; }\n"))
        smry = s[("T", "pick", 0)]
        assert smry.kind == CONDUIT_CONST
        assert smry.const_value == "safe"

    def test_param_identity(self):
        s, _ = _summaries(_cls(
            _HANDLE
            + "    private String pass(String p) { return p; }\n"))
        smry = s[("T", "pass", 1)]
        assert smry.kind == CONDUIT_PARAM
        assert smry.param_index == 0

    def test_folded_ternary_collapses_to_constant(self):
        s, _ = _summaries(_cls(
            _HANDLE
            + "    private String pick(String p) {\n"
            + "        int n = 42;\n"
            + "        return (7 * 42) - n > 200 ? \"safe\" : p;\n"
            + "    }\n"))
        smry = s[("T", "pick", 1)]
        assert smry.kind == CONDUIT_CONST
        assert smry.const_value == "safe"

    def test_folded_ternary_collapses_to_param(self):
        s, _ = _summaries(_cls(
            _HANDLE
            + "    private String pick(String p) {\n"
            + "        int n = 106;\n"
            + "        return (7 * 42) - n > 200 ? \"safe\" : p;\n"
            + "    }\n"))
        smry = s[("T", "pick", 1)]
        assert smry.kind == CONDUIT_PARAM
        assert smry.param_index == 0

    def test_unfoldable_ternary_is_join(self):
        s, _ = _summaries(_cls(
            _HANDLE
            + "    private String pick(String p, int m) {\n"
            + "        return m > 0 ? \"safe\" : p;\n    }\n"))
        smry = s[("T", "pick", 2)]
        assert smry.kind == CONDUIT_JOIN
        assert smry.param_index == 0
        assert smry.const_value == "safe"

    @pytest.mark.parametrize("body,reason_bit", [
        # transformation is not identity
        ("    private String f(String p) { return \"pre\" + p; }\n",
         "transformed"),
        ("    private String f(String p) { return p.trim(); }\n",
         "transformed"),
        # branch constants differ (constant-set) — refused, counted
        ("    private String f(String p, int m) {\n"
         "        return m > 0 ? \"a\" : \"b\";\n    }\n",
         "constant-set"),
        # two different parameters in a join
        ("    private String f(String p, String q, int m) {\n"
         "        return m > 0 ? q : p;\n    }\n",
         "different parameters"),
        # recursion — the self-call refuses classification
        ("    private String f(String p) { return f(p); }\n",
         "transformed"),
        # null constant — reserved sentinel
        ("    private String f() { return null; }\n", "null constant"),
    ])
    def test_refusals(self, body, reason_bit):
        s, decisions = _summaries(_cls(_HANDLE + body))
        assert not any(k[1] == "f" for k in s), decisions
        assert any(reason_bit in d for d in decisions), decisions


class TestCallIndexAndFoldHook:
    def test_creation_call_resolves_and_folds(self):
        src = _cls(
            "    public void handle(String x, java.io.PrintWriter out) {\n"
            "        String bar = new W().pick();\n"
            "        out.println(bar);\n    }\n"
            "    private class W {\n"
            "        public String pick() { return \"safe\"; }\n"
            "    }\n")
        calls = conduit_call_map(src, (3, 4))
        assert len(calls) == 1
        hook = make_conduit_fold_resolver(src, (3, 4))
        assert hook is not None
        (key, (summary, _args)), = calls.items()
        assert summary.kind == CONDUIT_CONST

    def test_anonymous_subclass_never_indexes(self):
        src = _cls(
            "    public void handle(String x, java.io.PrintWriter out) {\n"
            "        String bar = new W() {\n"
            "            public String pick() { return x; }\n"
            "        }.pick();\n"
            "        out.println(bar);\n    }\n"
            "    private static class W {\n"
            "        public String pick() { return \"safe\"; }\n"
            "    }\n")
        calls = conduit_call_map(src, (3, 6))
        assert calls == {}

    def test_fold_hook_param_kind_folds_literal_argument(self):
        src = _cls(
            "    public void handle(String x, java.io.PrintWriter out) {\n"
            "        String bar = new W().pass(\"hello\");\n"
            "        out.println(bar);\n    }\n"
            "    private class W {\n"
            "        public String pass(String p) { return p; }\n"
            "    }\n")
        hook = make_conduit_fold_resolver(src, (3, 4))
        assert hook is not None
        parser = _get_parser()
        tree = parser.parse(src.encode())
        inv = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation" and b"pass" in n.text:
                inv = n
            stack.extend(c for c in n.children if c.is_named)
        assert inv is not None

        from core.analysis.const_fold_java import REFUSE, fold_expr
        val = fold_expr(
            inv, lambda _n, _d: REFUSE, conduit_resolver=hook,
        )
        assert val == "hello"
        assert hook.hits == 1

    def test_fold_hook_join_requires_matching_constant(self):
        src = _cls(
            "    public void handle(String x, java.io.PrintWriter out,"
            " int m) {\n"
            "        String bar = new W().pick(\"other\", m);\n"
            "        out.println(bar);\n    }\n"
            "    private class W {\n"
            "        public String pick(String p, int m2) {\n"
            "            return m2 > 0 ? \"safe\" : p;\n        }\n"
            "    }\n")
        hook = make_conduit_fold_resolver(src, (3, 4))
        assert hook is not None
        parser = _get_parser()
        tree = parser.parse(src.encode())
        inv = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation" and b"pick" in n.text:
                inv = n
            stack.extend(c for c in n.children if c.is_named)
        from core.analysis.const_fold_java import REFUSE, fold_expr
        # "other" != the join's constant side "safe" → the folder's
        # single-value contract refuses rather than guessing.
        val = fold_expr(inv, lambda _n, _d: REFUSE, conduit_resolver=hook)
        assert val is REFUSE
        assert hook.hits == 0

    def test_no_conduits_returns_none(self):
        src = _cls(_HANDLE)
        assert make_conduit_fold_resolver(src, (3, 3)) is None


class TestFolderIsolation:
    def test_fold_without_hook_still_refuses_calls(self):
        """The threading is inert when no resolver is supplied — a
        method invocation refuses exactly as before b27."""
        src = _cls(
            _HANDLE
            + "    private String pick() { return \"safe\"; }\n")
        parser = _get_parser()
        tree = parser.parse(("class Q { void m() { "
                             "String v = pick(); } }").encode())
        inv = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                inv = n
            stack.extend(c for c in n.children if c.is_named)
        from core.analysis.const_fold_java import REFUSE, fold_expr
        assert fold_expr(inv, lambda _n, _d: REFUSE) is REFUSE
        del src
