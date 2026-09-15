"""Unit tests for :mod:`core.analysis.collection_guard_java` — guard
polarity, dominance, writer intervals, collection resolution (local,
same-class static final, cross-file), and the finite-set danger
check. End-to-end verdicts ride the precision corpus; these pin the
module contracts directly, including the cross-file discipline the
corpus can't express in single-file fixtures."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.collection_guard_java import collection_guard_reason


def _src(body: str, params: str = "String x, java.io.PrintWriter out",
         fields: str = "") -> str:
    return ("public class T {\n" + fields
            + f"    public void handle({params}) {{\n"
            + body + "    }\n}\n")


_ALLOWED = ('        java.util.List<String> allowed = '
            'java.util.Arrays.asList("home", "about");\n')


class TestGuardForms:
    def test_exit_on_fail_binds(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        reason = collection_guard_reason(src, 5, "x", "CWE-79")
        assert reason is not None
        assert "2 literal(s)" in reason

    def test_exit_via_throw_binds(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) "
                   "{ throw new IllegalArgumentException(); }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79")

    def test_enclosed_sink_binds(self):
        src = _src(_ALLOWED
                   + "        if (allowed.contains(x)) {\n"
                   + "            out.println(x);\n        }\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79")

    def test_exit_on_match_exclusion_never_binds(self):
        # Values OUTSIDE the set survive — the Benchmark's header
        # filter idiom. Both polarity inversions must refuse.
        src = _src(_ALLOWED
                   + "        if (allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79") is None

    def test_continue_exclusion_never_binds(self):
        src = ("public class T {\n"
               "    public void handle(String[] xs, "
               "java.io.PrintWriter out) {\n"
               + "        java.util.List<String> allowed = "
               'java.util.Arrays.asList("home", "about");\n'
               + "        for (String x : xs) {\n"
               + "            if (allowed.contains(x)) { continue; }\n"
               + "            out.println(x);\n        }\n    }\n}\n")
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_negated_guard_with_non_exit_body_refuses(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) "
                   "{ out.flush(); }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79") is None

    def test_guard_after_sink_never_binds(self):
        src = _src(_ALLOWED
                   + "        out.println(x);\n"
                   + "        if (!allowed.contains(x)) { return; }\n")
        assert collection_guard_reason(src, 4, "x", "CWE-79") is None

    def test_different_variable_refuses(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n",
                   params="String x, String y, java.io.PrintWriter out")
        assert collection_guard_reason(src, 5, "y", "CWE-79") is None

    def test_writer_between_guard_and_sink_refuses(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        x = x + \"suffix\";\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_writer_before_guard_is_fine(self):
        src = _src("        x = x.trim();\n" + _ALLOWED
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 6, "x", "CWE-79")


class TestTestedIdentifierScope:
    """The tested identifier needs local-grade (unaliasable) scope:
    a FIELD passes the syntactic writer-interval check trivially while
    any interleaved call can rewrite it at runtime."""

    def test_field_tested_identifier_refuses(self):
        src = ("public class T {\n"
               "    String data;\n"
               "    java.util.List<String> allowed = "
               'java.util.Arrays.asList("home", "about");\n'
               "    public void handle(Req req, "
               "java.sql.Statement st) throws Exception {\n"
               "        if (!allowed.contains(data)) { return; }\n"
               "        process(req);\n"
               "        st.executeQuery(data);\n"
               "    }\n"
               "    void process(Req req) { "
               "this.data = req.getParameter(); }\n"
               "}\n")
        decisions: list[str] = []
        reason = collection_guard_reason(
            src, 7, "data", "CWE-89", decisions=decisions)
        assert reason is None, (
            "field tested identifier suppressed across an "
            "interleaved-call rewrite"
        )
        assert any("not a declared local/param" in d for d in decisions)

    def test_parameter_tested_identifier_still_binds(self):
        # Control: a parameter is unaliasable across the interleaved
        # call — the guard legitimately binds.
        src = ("public class T {\n"
               "    public void handle(String data, Req req, "
               "java.sql.Statement st) throws Exception {\n"
               "        java.util.List<String> allowed = "
               'java.util.Arrays.asList("home", "about");\n'
               "        if (!allowed.contains(data)) { return; }\n"
               "        process(req);\n"
               "        st.executeQuery(data);\n"
               "    }\n"
               "}\n")
        reason = collection_guard_reason(src, 6, "data", "CWE-89")
        assert reason is not None
        assert "2 literal(s)" in reason

    def test_local_declared_after_guard_refuses(self):
        # Positional rule: a declarator BELOW the guard must not vouch
        # the tested name at the guard.
        src = ("public class T {\n"
               "    String data;\n"
               "    public void handle(java.sql.Statement st) "
               "throws Exception {\n"
               "        java.util.List<String> allowed = "
               'java.util.Arrays.asList("home", "about");\n'
               "        if (!allowed.contains(data)) { return; }\n"
               "        st.executeQuery(data);\n"
               '        String data = "late";\n'
               "        use(data);\n"
               "    }\n"
               "}\n")
        decisions: list[str] = []
        reason = collection_guard_reason(
            src, 6, "data", "CWE-89", decisions=decisions)
        assert reason is None
        assert any("not a declared local/param" in d for d in decisions)


class TestCollectionResolution:
    def test_mutated_local_refuses(self):
        src = _src(_ALLOWED
                   + "        allowed.add(x);\n"
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_aliased_local_refuses(self):
        src = _src(_ALLOWED
                   + "        java.util.List<String> alias = allowed;\n"
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_nonliteral_element_refuses(self):
        src = _src("        java.util.List<String> allowed = "
                   'java.util.Arrays.asList("home", x);\n'
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79") is None

    def test_setof_and_wrapper_ctor_bind(self):
        src = _src("        java.util.Set<String> allowed = new "
                   "java.util.HashSet<>(java.util.Arrays.asList("
                   '"a", "b"));\n'
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-79")

    def test_static_final_field_binds(self):
        src = _src("        if (!ALLOWED.contains(x)) { return; }\n"
                   + "        out.println(x);\n",
                   fields="    private static final "
                   "java.util.Set<String> ALLOWED = new "
                   "java.util.HashSet<>(java.util.Arrays.asList("
                   '"a", "b"));\n')
        assert collection_guard_reason(src, 5, "x", "CWE-79")

    def test_shadowing_local_never_resolves_the_field(self):
        # Java scoping: a method-local declarator shadows the
        # same-named static final field, so the guard's runtime
        # receiver is the (attacker-influenced) local. The
        # local->field fallback must fire only when NO local
        # declarator exists.
        src = _src(
            "        java.util.List<String> allowed = getUserList();\n"
            "        if (allowed.contains(x)) {\n"
            "            out.println(x);\n        }\n",
            fields=('    static final java.util.List<String> allowed'
                    ' = java.util.List.of("home", "about");\n'),
        )
        helper = ("    private java.util.List<String> getUserList()"
                  " { return null; }\n}\n")
        src = src[:-len("}\n")] + helper
        # Sink is the println INSIDE the guard (line 6: class=1,
        # field=2, handle=3, decl=4, if=5, println=6) — a wrong sink
        # line refuses for unrelated reasons and made this test pass
        # even against the unfixed fallback.
        assert 'out.println(x);' in src.splitlines()[5]
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_shadowing_local_with_mutation_refusal_never_falls_back(self):
        # A local that exists but refuses for ANY reason (here:
        # non-literal initializer) must refuse the guard outright,
        # not consult the field.
        src = _src(
            "        java.util.List<String> allowed = "
            "java.util.Arrays.asList(x);\n"
            "        if (allowed.contains(x)) {\n"
            "            out.println(x);\n        }\n",
            fields=('    static final java.util.List<String> allowed'
                    ' = java.util.List.of("home", "about");\n'),
        )
        assert 'out.println(x);' in src.splitlines()[5]
        assert collection_guard_reason(src, 6, "x", "CWE-79") is None

    def test_nonfinal_field_refuses(self):
        src = _src("        if (!ALLOWED.contains(x)) { return; }\n"
                   + "        out.println(x);\n",
                   fields="    static java.util.Set<String> ALLOWED = "
                   "new java.util.HashSet<>(java.util.Arrays.asList("
                   '"a", "b"));\n')
        assert collection_guard_reason(src, 5, "x", "CWE-79") is None


class TestDangerModels:
    def test_dangerous_literal_refuses_sqli(self):
        src = ("public class T {\n"
               "    public void handle(String x, java.sql.Statement st)"
               " throws Exception {\n"
               "        java.util.List<String> allowed = "
               "java.util.Arrays.asList(\"o'brien\", \"name\");\n"
               "        if (!allowed.contains(x)) { return; }\n"
               "        st.executeQuery(x);\n    }\n}\n")
        assert collection_guard_reason(src, 5, "x", "CWE-89") is None

    def test_clean_literals_bind_sqli(self):
        src = ("public class T {\n"
               "    public void handle(String x, java.sql.Statement st)"
               " throws Exception {\n"
               "        java.util.List<String> allowed = "
               'java.util.Arrays.asList("name", "email");\n'
               "        if (!allowed.contains(x)) { return; }\n"
               "        st.executeQuery(x);\n    }\n}\n")
        assert collection_guard_reason(src, 5, "x", "CWE-89")

    def test_pathtrav_separator_literal_refuses(self):
        src = _src("        java.util.List<String> allowed = "
                   'java.util.Arrays.asList("a/b", "c");\n'
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        open(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-22") is None

    def test_unknown_cwe_refuses(self):
        src = _src(_ALLOWED
                   + "        if (!allowed.contains(x)) { return; }\n"
                   + "        out.println(x);\n")
        assert collection_guard_reason(src, 5, "x", "CWE-0000") is None


class TestCrossFile:
    def _tree(self, tmp_path, mutator: str = "", *,
              final: bool = True) -> tuple:
        helpers = tmp_path / "org" / "example" / "helpers"
        helpers.mkdir(parents=True)
        fin = "final " if final else ""
        (helpers / "Utils.java").write_text(
            "package org.example.helpers;\n"
            "import java.util.*;\n"
            "public class Utils {\n"
            f"    public static {fin}Set<String> COMMON =\n"
            "            new HashSet<>(Arrays.asList("
            '"accept", "host"));\n'
            "}\n", encoding="utf-8")
        app = tmp_path / "org" / "example" / "app"
        app.mkdir(parents=True)
        src = ("package org.example.app;\n"
               "public class T {\n"
               "    public void handle(String x, "
               "java.io.PrintWriter out) {\n"
               "        if (!org.example.helpers.Utils.COMMON"
               ".contains(x)) { return; }\n"
               "        out.println(x);\n    }\n}\n")
        (app / "T.java").write_text(src, encoding="utf-8")
        if mutator:
            (app / "Mut.java").write_text(
                "package org.example.app;\n"
                "public class Mut {\n"
                "    void poke() { "
                f"org.example.helpers.Utils.COMMON.{mutator}; }}\n"
                "}\n", encoding="utf-8")
        return src, str(tmp_path)

    def test_cross_file_static_final_binds(self, tmp_path):
        src, root = self._tree(tmp_path)
        assert collection_guard_reason(
            src, 5, "x", "CWE-79", source_root=root)

    def test_cross_file_mutator_anywhere_refuses(self, tmp_path):
        src, root = self._tree(tmp_path, mutator='add("evil")')
        assert collection_guard_reason(
            src, 5, "x", "CWE-79", source_root=root) is None

    def test_cross_file_nonfinal_refuses(self, tmp_path):
        src, root = self._tree(tmp_path, final=False)
        assert collection_guard_reason(
            src, 5, "x", "CWE-79", source_root=root) is None

    def test_cross_file_without_root_refuses(self, tmp_path):
        src, _root = self._tree(tmp_path)
        assert collection_guard_reason(src, 5, "x", "CWE-79") is None


class TestInvisibleBindingWriters:
    """Binding forms beyond assignment shapes are writers too.

    A try-with-resources ``resource`` and pattern variables
    (``instanceof String x``, record components) legally rebind — or
    shadow a same-named field — between guard and sink; missing them
    from the writer enumeration lets the guard vouch for a DIFFERENT
    value than the one the sink consumes.
    """

    def test_resource_rebind_between_guard_and_sink_refuses(self):
        src = _src(
            _ALLOWED
            + "        if (!allowed.contains(x)) { return; }\n"
            + "        try (var x = open()) {\n"
            + "            out.println(x);\n        }\n",
            fields="    java.io.PrintWriter x;\n",
        )
        assert collection_guard_reason(src, 7, "x", "CWE-79") is None

    def test_instanceof_pattern_bind_before_sink_refuses(self):
        src = _src(
            _ALLOWED
            + "        if (!allowed.contains(x)) { return; }\n"
            + "        if (o instanceof String x) {\n"
            + "            out.println(x);\n        }\n",
            params="String x, Object o, java.io.PrintWriter out",
        )
        assert collection_guard_reason(src, 7, "x", "CWE-79") is None

    def test_record_pattern_component_bind_refuses(self):
        src = _src(
            _ALLOWED
            + "        if (!allowed.contains(x)) { return; }\n"
            + "        if (o instanceof P(String x)) {\n"
            + "            out.println(x);\n        }\n",
            params="String x, Object o, java.io.PrintWriter out",
        )
        assert collection_guard_reason(src, 7, "x", "CWE-79") is None

    def test_unrelated_resource_keeps_binding(self):
        # A resource binding a DIFFERENT name is not a writer of x.
        src = _src(
            _ALLOWED
            + "        if (!allowed.contains(x)) { return; }\n"
            + "        try (var r = open()) {\n"
            + "            out.println(x);\n        }\n",
        )
        assert collection_guard_reason(src, 7, "x", "CWE-79") is not None


class TestPatternBindingsVisibleToCfg:
    """The CFG twin: pattern/resource bindings must appear in defs so
    condition-3 exclusivity cannot hold over a live rebind."""

    def test_instanceof_binding_is_a_def(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = ("public class T {\n"
               "    String x;\n"
               "    void handle(Object o, java.io.PrintWriter out) {\n"
               "        if (o instanceof String x) { out.println(x); }\n"
               "    }\n}\n")
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        assert any("x" in n.defs for n in cfg.nodes())

    def test_record_pattern_bindings_are_defs(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = ("public class T {\n"
               "    void handle(Object o, java.io.PrintWriter out) {\n"
               "        if (o instanceof P(String a, int b)) "
               "{ out.println(a); }\n"
               "    }\n}\n")
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        defs = set().union(*(n.defs for n in cfg.nodes()))
        assert {"a", "b"} <= defs
