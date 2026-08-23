"""Unit tests for :mod:`core.analysis.java_wrapper_summaries` — the
refusal taxonomy, positional-argument recovery, callee-name matching,
and binding synthesis. End-to-end verdicts ride the precision corpus;
these pin the summary contracts directly."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import build_java_intraproc_cfg
from core.analysis.java_wrapper_summaries import (
    derive_wrapper_summaries,
    synthetic_wrapper_bindings_java,
)

_IMP = "import org.owasp.encoder.Encode;\n"


def _src(helpers: str, body: str,
         params: str = "String x, java.io.PrintWriter out") -> str:
    return (_IMP + "public class T {\n"
            + helpers
            + f"    public void handle({params}) {{\n"
            + body
            + "    }\n}\n")


def _hint(src: str):
    lines = src.splitlines()
    hdr = next(i + 1 for i, ln in enumerate(lines)
               if "public void handle" in ln)
    return (hdr + 1, hdr + 1)


def _summaries(src: str, hint=None):
    return derive_wrapper_summaries(
        src, hint or _hint(src), "CWE-79", "java")


class TestSummaryDerivation:
    def test_direct_wrapper_qualifies(self):
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x);\n        out.println(y);\n")
        summaries, decisions = _summaries(src)
        assert ("T", "esc", 1) in summaries
        s = summaries[("T", "esc", 1)]
        assert s.sanitized_positions == frozenset({0})
        assert s.sanitizer_callables == frozenset(
            {"org.owasp.encoder.Encode.forHtml"})
        assert any("sanitizes positions [0]" in d for d in decisions)

    def test_local_chain_qualifies(self):
        src = _src(
            "    private static String esc(String s) {\n"
            "        String t = Encode.forHtml(s);\n"
            "        return t;\n"
            "    }\n",
            "        String y = esc(x);\n        out.println(y);\n")
        summaries, _ = _summaries(src)
        assert ("T", "esc", 1) in summaries

    def test_literal_concat_qualifies(self):
        src = _src(
            "    private static String esc(String s) "
            '{ return "<b>" + Encode.forHtml(s) + "</b>"; }\n',
            "        String y = esc(x);\n        out.println(y);\n")
        summaries, _ = _summaries(src)
        assert ("T", "esc", 1) in summaries

    @pytest.mark.parametrize("helper,reason_fragment", [
        # Non-sanitizing body.
        ("    private static String h(String s) { return s.trim(); }\n",
         "non-catalog call"),
        # Direct pass-through.
        ("    private static String h(String s) { return s; }\n",
         "outside a sanitizer"),
        # Param concatenated dirty next to a clean flow.
        ("    private static String h(String s) "
         "{ return Encode.forHtml(s) + s; }\n",
         "outside a sanitizer"),
        # Branchy body.
        ("    private static String h(String s) {\n"
         "        if (s.length() > 3) { return Encode.forHtml(s); }\n"
         "        return s;\n"
         "    }\n",
         "unsupported body statement"),
        # Recursion (self-call is a non-catalog call).
        ("    private static String h(String s) "
         "{ return h(Encode.forHtml(s)); }\n",
         "non-catalog call"),
        # Reassigned local.
        ("    private static String h(String s) {\n"
         "        String t = Encode.forHtml(s);\n"
         "        t = s;\n"
         "        return t;\n"
         "    }\n",
         "reassignment"),
        # Ternary in return.
        ("    private static String h(String s) "
         "{ return s.isEmpty() ? \"\" : Encode.forHtml(s); }\n",
         "unsupported return construct"),
        # Field in return.
        ("    private static String h(String s) "
         "{ return prefix + Encode.forHtml(s); }\n",
         "unknown name"),
    ])
    def test_refusals(self, helper, reason_fragment):
        src = _src(helper,
                   "        String y = h(x);\n        out.println(y);\n")
        summaries, decisions = _summaries(src)
        assert ("T", "h", 1) not in summaries
        assert any(reason_fragment in d for d in decisions), decisions

    def test_overridable_instance_method_refused(self):
        src = _src(
            "    public String h(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = h(x);\n        out.println(y);\n")
        summaries, decisions = _summaries(src)
        assert not summaries
        assert any("overridable" in d for d in decisions)

    def test_same_arity_overload_refused(self):
        src = _src(
            "    private static String h(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String h(Object s) "
            "{ return s.toString(); }\n",
            "        String y = h(x);\n        out.println(y);\n")
        summaries, decisions = _summaries(src)
        assert not summaries
        assert any("overload ambiguity" in d for d in decisions)

    def test_varargs_helper_refused(self):
        src = _src(
            "    private static String h(String... s) "
            "{ return Encode.forHtml(s[0]); }\n",
            "        String y = h(x);\n        out.println(y);\n")
        summaries, _ = _summaries(src)
        assert not summaries

    def test_wrong_cwe_catalog_yields_nothing(self):
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x);\n        out.println(y);\n")
        summaries, decisions = derive_wrapper_summaries(
            src, _hint(src), "CWE-89", "java")
        # sqli has no Java catalog entries — no summary may exist.
        assert not summaries


class TestBindingSynthesis:
    def _bindings(self, src, hint=None):
        hint = hint or _hint(src)
        cfg = build_java_intraproc_cfg(src, "handle", line_hint=hint)
        assert cfg is not None
        return synthetic_wrapper_bindings_java(
            cfg, src, hint, "CWE-79", "java")

    def test_binding_carries_caller_symbols(self):
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x);\n        out.println(y);\n")
        (b,) = self._bindings(src)
        assert b.input_symbols == frozenset({"x"})
        assert b.output_symbols == frozenset({"y"})
        assert b.callable.startswith("wrapper:T.esc->")

    def test_this_qualified_call_never_binds(self):
        # The b13 builder emits no CallSite for a ``this``-qualified
        # call (the receiver is not an identifier node), so nothing
        # exists to bind — pinned so a future builder change that
        # surfaces these calls forces a deliberate decision here.
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = this.esc(x);\n        out.println(y);\n")
        assert not self._bindings(src)

    def test_arity_mismatch_produces_no_binding(self):
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            '        String y = esc(x, "ctx");\n        out.println(y);\n')
        assert not self._bindings(src)

    def test_non_identifier_argument_produces_no_binding(self):
        src = _src(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x + x);\n        out.println(y);\n")
        assert not self._bindings(src)

    def test_other_class_static_call_binds(self):
        # b21 reverses b19's same-file cross-class scope pin: a STATIC
        # method dispatches exactly (subclass statics hide, never
        # override), so Other.esc now resolves and binds.
        src = (_IMP + "public class Other {\n"
               "    static String esc(String s) "
               "{ return Encode.forHtml(s); }\n"
               "}\n"
               "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = Other.esc(x);\n"
               "        out.println(y);\n"
               "    }\n}\n")
        cfg = build_java_intraproc_cfg(src, "handle", line_hint=(6, 8))
        assert cfg is not None
        (b,) = synthetic_wrapper_bindings_java(
            cfg, src, (6, 8), "CWE-79", "java")
        assert b.input_symbols == frozenset({"x"})
        assert b.callable.startswith("wrapper:Other.esc->")


class TestCrossClassAndDepth2:
    def _bindings(self, src, hint):
        cfg = build_java_intraproc_cfg(src, "handle", line_hint=hint)
        assert cfg is not None
        return synthetic_wrapper_bindings_java(
            cfg, src, hint, "CWE-79", "java")

    def test_inner_class_creation_binds(self):
        # The OWASP Benchmark shape: a private inner class helper
        # called through a zero-arg instance creation.
        src = (_IMP + "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = new W().doSomething(x);\n"
               "        out.println(y);\n"
               "    }\n"
               "    private class W {\n"
               "        public String doSomething(String p) "
               "{ return Encode.forHtml(p); }\n"
               "    }\n}\n")
        (b,) = self._bindings(src, (3, 5))
        assert b.input_symbols == frozenset({"x"})
        assert b.output_symbols == frozenset({"y"})
        assert b.callable.startswith("wrapper:W.doSomething->")

    def test_creation_with_args_never_binds(self):
        # A constructor argument could store taint into instance
        # state — the call site refuses regardless of the body.
        src = (_IMP + "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = new W(x).doSomething(x);\n"
               "        out.println(y);\n"
               "    }\n"
               "    private class W {\n"
               "        W(String s) { }\n"
               "        public String doSomething(String p) "
               "{ return Encode.forHtml(p); }\n"
               "    }\n}\n")
        assert not self._bindings(src, (3, 5))

    def test_anonymous_subclass_never_binds(self):
        # ``new W() { ... }`` is an anonymous SUBCLASS — dispatch
        # goes to its overrides, never to the summarised class.
        src = (_IMP + "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = new W() { "
               "public String doSomething(String p) { return p; } "
               "}.doSomething(x);\n"
               "        out.println(y);\n"
               "    }\n"
               "    private class W {\n"
               "        public String doSomething(String p) "
               "{ return Encode.forHtml(p); }\n"
               "    }\n}\n")
        assert not self._bindings(src, (3, 5))

    def test_instance_state_body_refuses(self):
        # Cross-class instance bodies obey the strict state rule: a
        # bare assignment could write a field.
        src = (_IMP + "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = new W().doSomething(x);\n"
               "        out.println(y);\n"
               "    }\n"
               "    private class W {\n"
               "        String f = \"\";\n"
               "        public String doSomething(String p) "
               "{ f = p; return Encode.forHtml(f); }\n"
               "    }\n}\n")
        assert not self._bindings(src, (3, 5))

    def test_depth2_composition_binds(self):
        src = _src(
            "    private String inner(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private String outerw(String s) "
            "{ return inner(s) + \"!\"; }\n",
            "        String y = outerw(x);\n        out.println(y);\n")
        hint = _hint(src)
        (b,) = self._bindings(src, hint)
        assert b.input_symbols == frozenset({"x"})
        assert "forHtml" in b.callable

    def test_depth3_refuses(self):
        src = _src(
            "    private String w1(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private String w2(String s) { return w1(s); }\n"
            "    private String w3(String s) { return w2(s); }\n",
            "        String y = w3(x);\n        out.println(y);\n")
        summaries, decisions = _summaries(src)
        assert ("T", "w2", 1) in summaries      # depth-2 earns
        assert ("T", "w3", 1) not in summaries  # depth-3 refuses
        assert not [
            b for b in self._bindings(src, _hint(src))
            if "w3" in b.callable
        ]

    def test_wrapper_cycle_refuses(self):
        src = _src(
            "    private String a(String s) { return b(s); }\n"
            "    private String b(String s) { return a(s); }\n",
            "        String y = a(x);\n        out.println(y);\n")
        summaries, _decisions = _summaries(src)
        assert ("T", "a", 1) not in summaries
        assert ("T", "b", 1) not in summaries

    def test_ignored_position_arg_is_skipped(self):
        # inner ignores its second parameter entirely; passing raw
        # taint there is provably discarded, so outerw still earns.
        src = _src(
            "    private static String inner(String s, String unused) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String outerw(String s, String u) "
            "{ return inner(s, u); }\n",
            "        String y = outerw(x, x);\n        out.println(y);\n")
        summaries, _decisions = _summaries(src)
        assert ("T", "outerw", 2) in summaries
        assert summaries[("T", "outerw", 2)].sanitized_positions \
            == frozenset({0})

    def test_ambiguous_class_name_refuses_instance(self):
        src = (_IMP + "class Outer {\n"
               "    static class W {\n"
               "        static String esc(String s) { return s; }\n"
               "    }\n"
               "}\n"
               "class W {\n"
               "    static String esc(String s) "
               "{ return Encode.forHtml(s); }\n"
               "}\n"
               "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        String y = W.esc(x);\n"
               "        out.println(y);\n"
               "    }\n}\n")
        cfg = build_java_intraproc_cfg(src, "handle", line_hint=(11, 13))
        assert cfg is not None
        assert not synthetic_wrapper_bindings_java(
            cfg, src, (11, 13), "CWE-79", "java")
