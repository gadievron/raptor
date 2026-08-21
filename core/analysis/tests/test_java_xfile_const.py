"""b37: taint-free fold tier, cross-file static-final / returns-literal
resolution, and the string-op fold extensions — boundary discipline
first (TAINT_FREE must never escape a value-only consumer)."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import (  # noqa: E402
    REFUSE,
    TAINT_FREE,
    JavaConstIndex,
    definers_all_fold,
    fold_expr,
    fold_expr_at,
)
from core.analysis.java_xfile_const import make_xfile_resolver  # noqa: E402


def _expr_node(expr: str, decls: str = ""):
    src = ("public class T {\n    public void m(String x) {\n"
           + decls
           + f"        Object r = {expr};\n"
           + "    }\n}\n")
    from core.analysis.cfg_builder_java import _get_parser
    tree = _get_parser().parse(src.encode())
    nodes = []

    def find(n):
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None and name.text.decode() == "r":
                nodes.append(n.child_by_field_name("value"))
        for c in n.children:
            find(c)

    find(tree.root_node)
    assert nodes, "fixture must contain the r declarator"
    return nodes[0]


def _fold(expr: str, allow_tf: bool = False, xfile=None):
    return fold_expr(_expr_node(expr), lambda _n, _d: REFUSE,
                     allow_taint_free=allow_tf, xfile_resolver=xfile)


class TestTaintFreeBoundary:
    def test_system_getproperty_refuses_by_default(self):
        assert _fold('System.getProperty("user.dir")') is REFUSE

    def test_system_getproperty_refuses_without_write_proof(self):
        # System properties are runtime-writable; without the
        # cross-file resolver's tree-wide no-setProperty proof a
        # property read is NOT taint-free (the b22 corpus fixture pins
        # the gate-level consequence).
        assert _fold('System.getProperty("user.dir")',
                     allow_tf=True) is REFUSE

    def test_getenv_literal_refuses(self):
        # b45 re-pin (threat-model authority, post-b44 stop-ship):
        # the environment IS the attack surface under threat-model
        # local — getenv is a taint source and can never fold
        # taint-free, opt-in or not. The b44 counterexample was
        # exactly new File(System.getenv(...)).
        assert _fold('System.getenv("HOME")', allow_tf=True) is REFUSE
        assert _fold('System.getenv("HOME")') is REFUSE

    def test_variable_property_name_refuses(self):
        assert _fold("System.getProperty(x)", allow_tf=True) is REFUSE

    def test_file_separator_tf(self):
        assert _fold("File.separator", allow_tf=True) is TAINT_FREE
        assert _fold("File.separator") is REFUSE

    def test_non_system_receiver_refuses(self):
        assert _fold('request.getProperty("a")', allow_tf=True) is REFUSE


class TestTaintFreeAlgebra:
    def test_concat_tf_with_constant_is_tf(self):
        # b45: algebra coverage moved to a JVM-constant TF producer;
        # environment reads are sources (authority) and refuse below.
        assert _fold('File.separator + "x"',
                     allow_tf=True) is TAINT_FREE
        assert _fold('System.getenv("HOME") + "x"',
                     allow_tf=True) is REFUSE

    def test_concat_tf_with_unfoldable_refuses(self):
        assert _fold('System.getenv("HOME") + x',
                     allow_tf=True) is REFUSE

    def test_comparison_on_tf_refuses(self):
        assert _fold('System.getenv("OS") == "Linux"',
                     allow_tf=True) is REFUSE

    def test_ternary_join_both_branches_const_is_tf(self):
        assert _fold('x != null ? "a" : "b"', allow_tf=True) is TAINT_FREE

    def test_ternary_join_refuses_without_opt_in(self):
        assert _fold('x != null ? "a" : "b"') is REFUSE

    def test_ternary_join_tainted_branch_refuses(self):
        assert _fold('x != null ? "a" : x', allow_tf=True) is REFUSE


class TestStringOps:
    def test_substring_folds(self):
        assert _fold('"constant".substring(2)') == "nstant"
        assert _fold('"constant".substring(1, 3)') == "on"

    def test_substring_out_of_bounds_refuses(self):
        assert _fold('"abc".substring(9)') is REFUSE

    def test_case_ops_ascii_only(self):
        assert _fold('"MiXeD".toLowerCase()') == "mixed"
        assert _fold('"MiXeD".toUpperCase()') == "MIXED"

    def test_case_op_with_locale_arg_refuses(self):
        assert _fold('"A".toLowerCase(java.util.Locale.US)') is REFUSE

    def test_trim_and_concat(self):
        assert _fold('" a ".trim()') == "a"
        assert _fold('"a".concat("b")') == "ab"

    def test_string_valueof(self):
        assert _fold("String.valueOf(42)") == "42"
        assert _fold("String.valueOf(true)") == "true"

    def test_ops_on_tf_receiver_stay_tf(self):
        # b45: TF producer switched to File.separator (see authority).
        v = _fold('File.separator.substring(1)', allow_tf=True)
        assert v is TAINT_FREE
        assert _fold('File.separator.substring(1)') is REFUSE
        # Environment receivers refuse regardless of the ops chain.
        assert _fold('System.getenv("HOME").substring(1)',
                     allow_tf=True) is REFUSE


# ---- cross-file fixtures ------------------------------------------------


CFG_CLASS = (
    "package app;\n"
    "import java.io.File;\n"
    "public class Cfg {\n"
    '    public static final String SAFE = "safe-const";\n'
    '    public static final String BASE = SAFE + "-2";\n'
    "    public static final String USERDIR = "
    'System.getProperty("user.dir") + File.separator;\n'
    "    public static final String SEP2 = "
    'File.separator + File.separator;\n'
    '    public static String MUTABLE = "not-final";\n'
    '    public String getTheValue(String p) { return "bar"; }\n'
    '    public String echo(String p) { return p; }\n'
    '    public String twoStmt(String p) { String a = "x"; return a; }\n'
    "}\n"
)

CALLER = (
    "package app;\n"
    "public class T {\n"
    "    public void m(String x) {\n"
    "        Object r = REPLACED;\n"
    "    }\n"
    "}\n"
)


@pytest.fixture()
def xroot(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "Cfg.java").write_text(CFG_CLASS, encoding="utf-8")
    caller = tmp_path / "app" / "T.java"
    caller.write_text(CALLER, encoding="utf-8")
    return tmp_path, caller


def _xfold(xroot, expr: str, allow_tf: bool = False, decls: str = ""):
    root, caller = xroot
    caller.write_text(CALLER.replace("REPLACED", expr), encoding="utf-8")
    xfile = make_xfile_resolver(str(caller), str(root))
    assert xfile is not None
    return _fold(expr, allow_tf=allow_tf, xfile=xfile), xfile


class TestCrossFileField:
    def test_literal_static_final_folds(self, xroot):
        v, _ = _xfold(xroot, "Cfg.SAFE")
        assert v == "safe-const"

    def test_recursive_static_final_folds(self, xroot):
        v, _ = _xfold(xroot, "Cfg.BASE")
        assert v == "safe-const-2"

    def test_tf_initializer_is_tf_only_with_opt_in(self, xroot):
        # b45 re-pin: a static final initialized from an ENVIRONMENT
        # read is environment-influenced (authority: getProperty is a
        # source) and refuses even with the opt-in — the b44 class.
        v, _ = _xfold(xroot, "Cfg.USERDIR", allow_tf=True)
        assert v is REFUSE
        # The opt-in boundary itself still holds, on a JVM-constant
        # initializer (File.separator family stays taint-free).
        v3, _ = _xfold(xroot, "Cfg.SEP2", allow_tf=True)
        assert v3 is TAINT_FREE
        v4, _ = _xfold(xroot, "Cfg.SEP2")
        assert v4 is REFUSE

    def test_non_final_field_refuses(self, xroot):
        v, _ = _xfold(xroot, "Cfg.MUTABLE")
        assert v is REFUSE

    def test_unknown_class_refuses(self, xroot):
        v, _ = _xfold(xroot, "Nope.SAFE")
        assert v is REFUSE

    def test_ambiguous_class_refuses(self, xroot, tmp_path):
        (tmp_path / "b").mkdir()
        (tmp_path / "b" / "Cfg.java").write_text(
            CFG_CLASS, encoding="utf-8")
        v, _ = _xfold(xroot, "Cfg.SAFE")
        assert v is REFUSE


class TestCrossFileMethod:
    def test_returns_literal_via_creation(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().getTheValue("k")')
        assert v == "bar"

    def test_returns_param_refuses(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().echo("k")')
        assert v is REFUSE

    def test_multi_statement_body_refuses(self, xroot):
        v, _ = _xfold(xroot, 'new Cfg().twoStmt("k")')
        assert v is REFUSE

    def test_creation_typed_local_receiver(self, xroot, tmp_path):
        root, caller = xroot
        src = (
            "package app;\n"
            "public class T {\n"
            "    public void m(String x) {\n"
            "        Cfg scr = new Cfg();\n"
            '        Object r = scr.getTheValue("k");\n'
            "    }\n"
            "}\n"
        )
        caller.write_text(src, encoding="utf-8")
        n_lines = src.count("\n") + 1
        index = JavaConstIndex(src, (1, n_lines),
                               java_file_path=str(caller),
                               repo_root=str(root))
        assert index.receiver_type("scr") == "Cfg"
        assert index.xfile is not None

    def test_reassigned_receiver_poisons_type(self):
        src = (
            "public class T { public void m(Object o) {\n"
            "    Cfg scr = new Cfg();\n"
            "    scr = other();\n"
            "} }\n"
        )
        index = JavaConstIndex(src, (1, 5))
        assert index.receiver_type("scr") is None


class TestGateConsumers:
    def _rd_setup(self, decls: str, use: str):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               + decls
               + f"        sink({use});\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        n_lines = src.count("\n") + 1
        index = JavaConstIndex(src, (1, n_lines))
        rd = reaching_defs(graph)
        sink_node = None
        for n in graph.nodes():
            if getattr(n, "lineno", 0) == src.count("\n") - 2:
                sink_node = n
        assert sink_node is not None
        return rd, sink_node, index

    def test_definers_all_fold_accepts_tf(self):
        # b45: TF producer is a JVM constant; the environment read
        # must now FAIL the all-fold check (it is a taint source).
        rd, sink, index = self._rd_setup(
            '        String v = java.io.File.separator;\n', "v")
        assert definers_all_fold(rd, sink, "v", index)
        rd2, sink2, index2 = self._rd_setup(
            '        String v = System.getenv("HOME");\n', "v")
        assert not definers_all_fold(rd2, sink2, "v", index2)

    def test_fold_expr_at_stays_value_only_by_default(self):
        from core.analysis.cfg_builder_java import _get_parser
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               '        String v = System.getenv("HOME");\n'
               "        sink(v);\n"
               "    }\n"
               "}\n")
        rd, sink, index = self._rd_setup(
            '        String v = System.getenv("HOME");\n', "v")
        tree = _get_parser().parse(src.encode())
        exprs = []

        def find(n):
            if n.type == "method_invocation" and n.text.decode(
                    ).startswith("System.getenv"):
                exprs.append(n)
            for ch in n.children:
                find(ch)

        find(tree.root_node)
        # Value-only consumers (switch pruning, weak-name matching)
        # must never see TAINT_FREE.
        assert fold_expr_at(rd, sink, exprs[0], index) is REFUSE


class TestPropertyWriteScan:
    def test_clean_tree_property_still_refuses(self, xroot):
        # b45 re-pin: the no-setProperty proof only rules out
        # in-process writes; the environment itself is the attack
        # surface (authority) — clean tree or not, property reads
        # refuse. tf_property_key_ok stays exercised below as the
        # write-scan primitive.
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is REFUSE

    def test_written_key_refuses(self, xroot, tmp_path):
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String t) { "
            'System.setProperty("user.dir", t); }\n}\n',
            encoding="utf-8")
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is REFUSE

    def test_write_scan_primitive_per_key(self, xroot, tmp_path):
        # b45: the tree-wide write scan remains a valid primitive
        # (per-key answer), even though it no longer buys the fold
        # tier anything — pinned here directly.
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String t) { "
            'System.setProperty("other.key", t); }\n}\n',
            encoding="utf-8")
        _, xfile = _xfold(xroot, 'System.getProperty("user.dir")',
                          allow_tf=True)
        assert xfile.tf_property_key_ok("user.dir")
        assert not xfile.tf_property_key_ok("other.key")

    def test_variable_key_poisons_all(self, xroot, tmp_path):
        (tmp_path / "app" / "W.java").write_text(
            "package app;\npublic class W {\n"
            "    void w(String k, String t) { "
            "System.setProperty(k, t); }\n}\n",
            encoding="utf-8")
        v, _ = _xfold(xroot, 'System.getProperty("user.dir")',
                      allow_tf=True)
        assert v is REFUSE
        # the poison also kills TF static-finals derived from a
        # property read (Cfg.USERDIR)
        v2, _ = _xfold(xroot, "Cfg.USERDIR", allow_tf=True)
        assert v2 is REFUSE

    def test_definers_all_fold_still_refuses_taint(self):
        rd, sink, index = TestGateConsumers()._rd_setup(
            "        String v = x;\n", "v")
        assert not definers_all_fold(rd, sink, "v", index)


class TestJdkTier:
    """b36 merge: JDK class chains are TAINT_FREE (source-less classes
    XFileConst can never resolve from the tree)."""

    def _resolver(self, tmp_path, src):
        from core.analysis.java_xfile_const import make_xfile_resolver
        f = tmp_path / "T.java"
        f.write_text(src, encoding="utf-8")
        return make_xfile_resolver(str(f), str(tmp_path))

    def test_fqn_jdk_chain_taint_free(self, tmp_path):
        from core.analysis.const_fold_java import REFUSE, TAINT_FREE
        r = self._resolver(tmp_path, "public class T {}\n")
        assert r.resolve_field("java.sql.ResultSet",
                               "TYPE_FORWARD_ONLY", True) is TAINT_FREE
        # value consumers never see it
        assert r.resolve_field("java.sql.ResultSet",
                               "TYPE_FORWARD_ONLY", False) is REFUSE

    def test_imported_simple_jdk_chain(self, tmp_path):
        from core.analysis.const_fold_java import TAINT_FREE
        src = ("import java.sql.ResultSet;\n"
               "public class T {}\n")
        r = self._resolver(tmp_path, src)
        assert r.resolve_field("ResultSet", "CONCUR_READ_ONLY",
                               True) is TAINT_FREE

    def test_non_jdk_simple_name_still_tree_resolves(self, tmp_path):
        (tmp_path / "Cfg.java").write_text(
            'public class Cfg { public static final String '
            'D = "v"; }\n', encoding="utf-8")
        r = self._resolver(tmp_path, "public class T {}\n")
        assert r.resolve_field("Cfg", "D", True) == "v"

    def test_rootless_resolver_serves_jdk_only(self, tmp_path):
        from core.analysis.const_fold_java import REFUSE, TAINT_FREE
        from core.analysis.java_xfile_const import make_xfile_resolver
        f = tmp_path / "T.java"
        f.write_text("import java.sql.ResultSet;\npublic class T {}\n",
                     encoding="utf-8")
        r = make_xfile_resolver(str(f), None)
        assert r is not None
        assert r.resolve_field("ResultSet", "X", True) is TAINT_FREE
        assert r.resolve_field("Cfg", "D", True) is REFUSE


class TestCoveredIdentifiers:
    """b36 merge: statement-scoped sibling coverage."""

    def _resolver(self, tmp_path, src):
        from core.analysis.java_xfile_const import make_xfile_resolver
        f = tmp_path / "T.java"
        f.write_text(src, encoding="utf-8")
        return make_xfile_resolver(str(f), str(tmp_path))

    SRC = (
        "public class T {\n"
        "    void m(String sql, Object con) {\n"
        "        prepareCall(sql,\n"
        "            java.sql.ResultSet.TYPE_FORWARD_ONLY,\n"
        "            java.sql.ResultSet.CONCUR_READ_ONLY);\n"
        "    }\n"
        "    void prepareCall(String s, int a, int b) {}\n"
        "}\n"
    )

    def test_multiline_call_statement_scope(self, tmp_path):
        r = self._resolver(tmp_path, self.SRC)
        cov = r.covered_identifiers(self.SRC, 3)
        assert {"java", "ResultSet", "TYPE_FORWARD_ONLY",
                "CONCUR_READ_ONLY"} <= cov
        # 'sql' occurs bare outside every accepted chain:
        # uncovered-wins even though it is also a package segment.
        assert "sql" not in cov
        assert "prepareCall" not in cov

    def test_other_lines_do_not_leak(self, tmp_path):
        src = self.SRC.replace(
            "    void prepareCall",
            "    void n(String x) { f(x); }\n    void prepareCall")
        r = self._resolver(tmp_path, src)
        cov = r.covered_identifiers(src, 7)  # the n(...) line
        assert "TYPE_FORWARD_ONLY" not in cov
