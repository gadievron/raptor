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
