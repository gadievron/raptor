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
    def test_concat_tf_with_constant_refuses_without_danger_authority(self):
        # b45: algebra coverage moved to a JVM-constant TF producer;
        # environment reads are sources (authority) and refuse below.
        # The concrete "x" is a MEMBER of the concat result: with no
        # danger predicate at this entry the mint refuses (b40 —
        # authority-carrying consumers pass union_member_check via
        # fold_expr_at / all_definers_constant and keep minting).
        assert _fold('File.separator + "x"',
                     allow_tf=True) is REFUSE
        assert _fold('System.getenv("HOME") + "x"',
                     allow_tf=True) is REFUSE

    def test_concat_tf_with_unfoldable_refuses(self):
        assert _fold('System.getenv("HOME") + x',
                     allow_tf=True) is REFUSE

    def test_comparison_on_tf_refuses(self):
        assert _fold('System.getenv("OS") == "Linux"',
                     allow_tf=True) is REFUSE

    def test_ternary_join_both_branches_const_refuses_without_authority(self):
        # Concrete branch strings are members of the result — no
        # danger predicate at this entry, no mint (b40).
        assert _fold('x != null ? "a" : "b"', allow_tf=True) is REFUSE

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
    # Annotation text contains "static"/"final" as substrings;
    # the field itself is neither — token-exact modifier matching
    # must refuse it.
    '    @staticfinal public String TRICKY = "looks-const";\n'
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

    def test_annotation_substring_never_qualifies(self, xroot):
        # A lowercase annotation containing "static"/"final" as
        # substrings must not qualify a plain mutable field as a
        # foldable constant (token-exact modifiers, the
        # collection-guard twin's discipline).
        v, _ = _xfold(xroot, "Cfg.TRICKY")
        assert v is REFUSE

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


class TestJdkNamespaceIdentity:
    """Namespace prefix is not identity: only ``java.*`` is
    JVM-classloader-reserved (prohibited package name); ``javax.*`` is
    user-definable, so a repo can declare its own javax class and a
    prefix-only tier would fold that class's MUTABLE static fields as
    attacker-free. The tier fires only when the class provably is not
    declared in the analysed tree."""

    HOLDER = (
        "package javax.legacy;\n"
        "public class Holder {\n"
        "    public static String CURRENT;\n"
        "    public static void set(javax.servlet.http."
        "HttpServletRequest r) {\n"
        '        CURRENT = r.getParameter("q");\n'
        "    }\n"
        "}\n"
    )

    def _resolver(self, tmp_path, caller_src):
        from core.analysis.java_xfile_const import make_xfile_resolver
        d = tmp_path / "src" / "javax" / "legacy"
        d.mkdir(parents=True)
        (d / "Holder.java").write_text(self.HOLDER, encoding="utf-8")
        f = tmp_path / "src" / "T.java"
        f.write_text(caller_src, encoding="utf-8")
        return make_xfile_resolver(str(f), str(tmp_path))

    def test_repo_declared_javax_class_never_blind_taint_free(
            self, tmp_path):
        from core.analysis.const_fold_java import REFUSE
        r = self._resolver(
            tmp_path,
            "import javax.legacy.Holder;\npublic class T {}\n")
        # In-tree declaration takes the normal static-final path:
        # CURRENT is a mutable static written from a request — REFUSE.
        assert r.resolve_field("Holder", "CURRENT", True) is REFUSE
        assert r.resolve_field(
            "javax.legacy.Holder", "CURRENT", True) is REFUSE

    def test_repo_declared_javax_static_final_folds_normally(
            self, tmp_path):
        from core.analysis.java_xfile_const import make_xfile_resolver
        d = tmp_path / "javax" / "legacy"
        d.mkdir(parents=True)
        (d / "K.java").write_text(
            "package javax.legacy;\n"
            "public class K { public static final String "
            'D = "v"; }\n', encoding="utf-8")
        f = tmp_path / "T.java"
        f.write_text("import javax.legacy.K;\npublic class T {}\n",
                     encoding="utf-8")
        r = make_xfile_resolver(str(f), str(tmp_path))
        assert r.resolve_field("K", "D", True) == "v"

    def test_genuine_javax_miss_keeps_the_tier(self, tmp_path):
        from core.analysis.const_fold_java import TAINT_FREE
        r = self._resolver(
            tmp_path,
            "import javax.sql.DataSource;\npublic class T {}\n")
        # No DataSource.java under the root — proven miss, tier fires.
        assert r.resolve_field("DataSource", "X", True) is TAINT_FREE

    def test_rootless_javax_refuses_java_star_stays(self, tmp_path):
        from core.analysis.const_fold_java import REFUSE, TAINT_FREE
        from core.analysis.java_xfile_const import make_xfile_resolver
        f = tmp_path / "T.java"
        f.write_text(
            "import javax.sql.DataSource;\n"
            "import java.sql.ResultSet;\npublic class T {}\n",
            encoding="utf-8")
        r = make_xfile_resolver(str(f), None)
        assert r is not None
        # Without a tree there is no miss proof for a user-definable
        # namespace; java.* is unloadable from application code and
        # stays blind-resolvable.
        assert r.resolve_field("DataSource", "X", True) is REFUSE
        assert r.resolve_field("ResultSet", "X", True) is TAINT_FREE


class TestSourceReadBoundary:
    @pytest.mark.parametrize("outside", [False, True])
    def test_declaration_symlink_stays_within_root(self, tmp_path, outside):
        repo = tmp_path / "repo"
        repo.mkdir()
        target = (tmp_path if outside else repo) / "owned-declaration.txt"
        target.write_text(CFG_CLASS)
        (repo / "Cfg.java").symlink_to(target)
        caller = repo / "T.java"
        value, _ = _xfold((repo, caller), "Cfg.SAFE")
        assert (value is REFUSE) if outside else (value == "safe-const")

    def test_unreadable_candidate_prevents_uniqueness_proof(self, xroot):
        root, _ = xroot
        other = root / "other"
        other.mkdir()
        (other / "Cfg.java").symlink_to(root / "missing-owned.txt")
        value, _ = _xfold(xroot, "Cfg.SAFE")
        assert value is REFUSE

    @pytest.mark.parametrize("overflow", [False, True])
    def test_declaring_source_byte_budget(self, xroot, monkeypatch, overflow):
        from core.analysis import java_xfile_const as stage

        root, _ = xroot
        source = CFG_CLASS.encode("utf-8")
        monkeypatch.setattr(stage, "_MAX_SOURCE_BYTES", len(source) + 16)
        (root / "app" / "Cfg.java").write_bytes(source + b" " * (16 + int(overflow)))
        value, _ = _xfold(xroot, "Cfg.SAFE")
        assert (value is REFUSE) if overflow else (value == "safe-const")

    @pytest.mark.parametrize("outside", [False, True])
    def test_write_absence_requires_contained_sources(self, tmp_path, outside):
        repo = tmp_path / "repo"
        repo.mkdir()
        target = (tmp_path if outside else repo) / "owned-writer.txt"
        target.write_text('class W { void w() { System.setProperty("other", "v"); } }')
        (repo / "W.java").symlink_to(target)
        _, resolver = _xfold((repo, repo / "T.java"), 'System.getProperty("untouched")')
        assert resolver.tf_property_key_ok("untouched") is (not outside)
        assert not resolver.tf_property_key_ok("other")


class TestDeclaringClassOwnership:
    def _tree(self, xroot, nested):
        root, _ = xroot
        (root / "app" / "Base.java").write_text(
            'package app; class Base { static String INHERITED = System.getenv("OWNED"); '
            'static String grab() { return System.getenv("OWNED"); } }'
        )
        other = (
            "static class Other {" if nested else "class Other {"
        ) + (
            ' static final String MUTABLE = "other"; '
            'static final String INHERITED = "other"; '
            'static final String SAFE = "other"; '
            'static String grab() { return "other"; } '
            'static String ownLiteral() { return "other"; } }'
        )
        body = (
            'static String MUTABLE = System.getenv("OWNED"); '
            'static final String DERIVED = INHERITED; '
            'static final String SAFE = "own-constant"; '
            'static String ownLiteral() { return SAFE; } '
        )
        (root / "app" / "Cfg.java").write_text(
            "package app; class Cfg extends Base { " + body
            + (other if nested else "") + " } " + ("" if nested else other)
        )

    @pytest.mark.parametrize("nested", [False, True])
    @pytest.mark.parametrize("field", ["MUTABLE", "DERIVED", "SAFE"])
    def test_fields_and_recursive_initializers_stay_on_owner(self, xroot, nested, field):
        self._tree(xroot, nested)
        value, _ = _xfold(xroot, f"Cfg.{field}")
        assert (value == "own-constant") if field == "SAFE" else (value is REFUSE)

    @pytest.mark.parametrize("nested", [False, True])
    @pytest.mark.parametrize("method", ["grab", "ownLiteral"])
    def test_methods_stay_on_owner(self, xroot, nested, method):
        self._tree(xroot, nested)
        value, _ = _xfold(xroot, f"new Cfg().{method}()")
        assert (value == "own-constant") if method == "ownLiteral" else (value is REFUSE)

    def test_filename_without_declaring_class_is_not_identity(self, xroot):
        root, _ = xroot
        (root / "app" / "Cfg.java").write_text(
            'package app; class Other { static final String SAFE = "other"; }'
        )
        value, _ = _xfold(xroot, "Cfg.SAFE")
        assert value is REFUSE


    @pytest.mark.parametrize("declaration", ["enum Cfg { ONE;", "record Cfg(int value) {"])
    def test_enum_and_record_direct_members_remain_foldable(self, xroot, declaration):
        root, _ = xroot
        (root / "app" / "Cfg.java").write_text(
            "package app; " + declaration
            + ' static final String SAFE = "own-constant"; '
            + 'static String ownLiteral() { return SAFE; } '
            + 'static class Other { static final String SAFE = "other"; '
            + 'static String ownLiteral() { return "other"; } } }'
        )
        value, resolver = _xfold(xroot, "Cfg.SAFE")
        assert value == "own-constant"
        assert resolver.resolve_method("Cfg", "ownLiteral", 0, False) == "own-constant"


class TestMethodParameterScope:
    @pytest.mark.parametrize("method,expected", [
        ("echo", None),
        ("concat", None),
        ("echoReceiver", None),
        ("echoMany", None),
        ("constant", "literal"),
        ("manyConstant", "literal"),
        ("qualified", "class-literal"),
        ("derived", "class-literal-derived"),
        ("composed", "literal"),
    ])
    def test_parameter_shadows_field_only_in_method_expression(self, xroot, method, expected):
        root, _ = xroot
        (root / "app" / "Cfg.java").write_text('''package app;
class Cfg {
    static final String SAFE = "class-literal";
    static final String DERIVED = SAFE + "-derived";
    String echo(String SAFE) { return SAFE; }
    String concat(String SAFE) { return "prefix" + SAFE; }
    String echoReceiver(Cfg this, String SAFE) { return SAFE; }
    String[] echoMany(String... SAFE) { return SAFE; }
    String constant(String SAFE) { return "literal"; }
    String manyConstant(String... SAFE) { return "literal"; }
    String qualified(String SAFE) { return Cfg.SAFE; }
    String derived(String SAFE) { return DERIVED; }
    String composed(String SAFE) { return new Cfg().constant(SAFE); }
}
''')
        value, _ = _xfold(xroot, f"new Cfg().{method}(x)")
        assert (value is REFUSE) if expected is None else (value == expected)


class TestMethodReceiverScope:
    @pytest.mark.parametrize("method,argument,expected", [
        ("field", "new Other()", None),
        ("method", "new Other()", None),
        ("jvmField", "new Other()", None),
        ("stringCall", "new Other()", None),
        ("packageHead", "new PackageValue()", None),
        ("fullyQualified", "new Other()", "class-literal"),
        ("fresh", "new Other()", "class-literal"),
        ("ignoredArgument", "new Other()", "literal"),
        ("derived", "new Other()", "class-literal-derived"),
    ])
    def test_value_receiver_binding_cannot_be_a_class_spelling(self, xroot, method,
                                                              argument, expected):
        root, _ = xroot
        (root / "app" / "Cfg.java").write_text('''package app;
class Cfg {
    static final String SAFE = "class-literal";
    static final String DERIVED = app.Cfg.SAFE + "-derived";
    String literal() { return "class-literal"; }
    String constant(Object value) { return "literal"; }
    String field(Other Cfg) { return Cfg.SAFE; }
    String method(Other Cfg) { return Cfg.literal(); }
    String jvmField(Other File) { return File.separator; }
    String stringCall(Other String) { return String.valueOf("fixed"); }
    String packageHead(PackageValue app) { return app.Cfg.SAFE; }
    String fullyQualified(Other Cfg) { return app.Cfg.SAFE; }
    String fresh(Other Cfg) { return new Cfg().literal(); }
    String ignoredArgument(Other Cfg) { return new Cfg().constant(Cfg.SAFE); }
    String derived(Other app) { return DERIVED; }
}
class Other {
    String SAFE = System.getenv("OWNED");
    String separator = System.getenv("OWNED");
    String literal() { return SAFE; }
    String valueOf(String ignored) { return SAFE; }
}
class PackageValue { Other Cfg = new Other(); }
''')
        value, _ = _xfold(xroot, f"new Cfg().{method}({argument})", allow_tf=True)
        assert (value is REFUSE) if expected is None else (value == expected)


class TestIndexReceiverScope:
    @pytest.mark.parametrize("case,params,body,expected", [
        ("parameter-field", "Other Cfg", "String value = Cfg.SAFE;", False),
        ("parameter-method", "Other Cfg", "String value = Cfg.literal();", False),
        ("parameter-jvm", "Other File", "String value = File.separator;", False),
        ("parameter-pure", "Other String", 'String value = String.valueOf("fixed");', False),
        ("local-field", "Other other", "Other Cfg = other;\nString value = Cfg.SAFE;", False),
        ("local-method", "Other other", "Other Cfg = other;\nString value = Cfg.literal();", False),
        ("created-method", "Other other", "Cfg receiver = new Cfg();\nString value = receiver.literal();", True),
        ("created-shadow", "Other other", "Cfg Cfg = new Cfg();\nString value = Cfg.literal();", True),
        ("reassigned", "Cfg unknown", "Cfg Cfg = new Cfg();\nCfg = unknown;\nString value = Cfg.literal();", False),
        ("dead-block", "Other other", "{ Other Cfg = other; }\nString value = Cfg.SAFE;", True),
        ("cross-scope", "Other receiver", "String value = receiver.literal();", False),
    ])
    def test_actual_definer_consumer_respects_value_receiver_scope(self, tmp_path,
                                                                  case, params, body, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        (tmp_path / "Cfg.java").write_text(
            'class Cfg { static final String SAFE="class-literal"; '
            'String literal() { return "class-literal"; } }'
        )
        (tmp_path / "Other.java").write_text(
            'class Other { String SAFE=System.getenv("OWNED"); '
            'String separator=System.getenv("OWNED"); '
            'String literal() { return SAFE; } String valueOf(String ignored) { return SAFE; } }'
        )
        setup = "void setup() { Cfg receiver = new Cfg(); }" if case == "cross-scope" else ""
        lines = ["class T {", setup, f"void m({params}, java.io.PrintWriter out) {{",
                 *body.splitlines(), "out.println(value);", "}", "}"]
        source = "\n".join(lines) + "\n"
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        sink_line = lines.index("out.println(value);") + 1
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        index = JavaConstIndex(source, (1, len(lines)), str(caller), str(tmp_path))
        assert index.ok
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    def test_value_only_consumer_without_xfile_keeps_receiver_scope(self, tmp_path):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        source = '''class T {
 void m(Other String, java.io.PrintWriter out) {
  String value = String.valueOf("fixed");
  out.println(value);
 }
}
class Other { String valueOf(String ignored) { return System.getenv("OWNED"); } }
'''
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, source.count("\n") + 1))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 4)
        rhs = index.rhs_at(3, "value")
        assert rhs is not None
        assert fold_expr_at(reaching_defs(graph), sink, rhs, index) is REFUSE


class TestMemberReceiverScope:
    @pytest.mark.parametrize("method_window", [False, True])
    @pytest.mark.parametrize("case", [
        "after", "static", "member-method", "record", "capture",
        "unrelated", "local-shadow", "outer-field", "interface", "enum",
    ])
    def test_actual_consumer_checks_ancestor_value_bindings(self, tmp_path,
                                                           method_window, case):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        (tmp_path / "Cfg.java").write_text(
            'class Cfg { static final String SAFE="class-literal"; '
            'String literal() { return "class-literal"; } }'
        )
        (tmp_path / "Other.java").write_text(
            'class Other { String SAFE=System.getenv("OWNED"); '
            'String separator=System.getenv("OWNED"); String literal() { return SAFE; } }'
        )
        prefix, suffix = "class T {\n", "}\n"
        body = "String value = Cfg.SAFE;"
        method_prefix = ""
        expected = False
        if case == "after":
            suffix = "Other Cfg = new Other();\n" + suffix
        elif case == "static":
            prefix += "static Other File = new Other();\n"
            body = "String value = File.separator;"
        elif case == "member-method":
            prefix += "Other Cfg;\nT(Other supplied) { this.Cfg = supplied; }\n"
            body = "{ Cfg Cfg = new Cfg(); }\nString value = Cfg.literal();"
        elif case == "record":
            prefix = "record T(Other Cfg) {\n"
        elif case == "capture":
            prefix += "void outer(Other Cfg) { class Inner {\n"
            suffix = "} }\n" + suffix
        elif case == "unrelated":
            prefix = "class Unrelated { Other Cfg; }\n" + prefix
            expected = True
        elif case == "local-shadow":
            prefix += "Other Cfg;\n"
            body = "Cfg Cfg = new Cfg();\nString value = Cfg.literal();"
            expected = True
        elif case == "outer-field":
            prefix += "Other Cfg = new Other();\nclass Inner {\n"
            suffix = "}\n" + suffix
        elif case == "interface":
            prefix = "interface T { Other File = new Other();\n"
            body = "String value = File.separator;"
            method_prefix = "default "
        elif case == "enum":
            prefix = "enum T { ONE; Other Cfg = new Other();\n"
        source = (prefix + method_prefix + "void m(java.io.PrintWriter out) {\n"
                  + body + "\nout.println(value);\n}\n" + suffix)
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        lines = source.splitlines()
        sink_line = lines.index("out.println(value);") + 1
        method_start = next(i + 1 for i, line in enumerate(lines) if "void m(" in line)
        span = (method_start, sink_line + 1) if method_window else (1, len(lines))
        index = JavaConstIndex(source, span, str(caller), str(tmp_path))
        assert index.ok
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected


class TestMemberReceiverCoverage:
    @pytest.mark.parametrize("binding,qualified,expected", [
        ("field", False, False),
        ("parameter", False, False),
        ("unrelated", False, True),
        ("field", True, True),
        ("none", False, True),
    ])
    def test_actual_constant_reason_requires_scoped_sibling_coverage(
            self, tmp_path, binding, qualified, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.sanitizer_cut import _sink_arg_constant_reason

        field = "Other File = new Other();\n" if binding == "field" else ""
        parameter = "Other File, " if binding == "parameter" else ""
        receiver = "java.io.File" if qualified else "File"
        sibling = "class Unrelated { Other File; }\n" if binding == "unrelated" else ""
        source = (
            "import java.io.File;\nclass T {\n" + field
            + f"void m({parameter}java.io.PrintWriter out) {{\n"
            + 'String format = "%s";\n'
            + f"out.printf(format, {receiver}.separator);\n"
            + "}\n}\n" + sibling
            + 'class Other { String separator=System.getenv("OWNED"); }\n'
        )
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        sink_line = next(i + 1 for i, line in enumerate(source.splitlines())
                         if "out.printf" in line)
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        # Empty taint front exercises the guard's independent fold-or-refuse duty.
        reason = _sink_arg_constant_reason(
            graph, set(), sink, "format", frozenset({"File"}), source,
            str(caller), str(tmp_path), "CWE-79",
        )
        assert (reason is not None) is expected


class TestTypeReceiverScope:
    @pytest.mark.parametrize("case,expected", [
        ("member-before", False), ("member-after", False),
        ("sibling", True), ("qualified", True),
        ("qualified-member", False), ("type-parameter", False),
        ("new-member", False), ("cached-member", False),
        ("new-value-name", True), ("plain-new", True),
    ])
    def test_actual_consumer_respects_type_namespace(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        (tmp_path / "Cfg.java").write_text(
            'class Cfg { String literal() { return "safe"; } }'
        )
        shadow = ('static class File { static String separator='
                  'System.getenv("OWNED"); }\n')
        cfg_shadow = ('static class Cfg { String literal() { '
                      'return System.getenv("OWNED"); } }\n')
        prefix, suffix, parameter = "", "", ""
        body = "String value = File.separator;\n"
        generic = ""
        if case == "member-before":
            prefix = shadow
        elif case == "member-after":
            suffix = shadow
        elif case == "sibling":
            prefix = "static class Other { " + shadow + "}\n"
        elif case == "qualified":
            prefix = shadow
            body = "String value = java.io.File.separator;\n"
        elif case == "qualified-member":
            prefix = shadow
            body = "String value = T.File.separator;\n"
        elif case == "type-parameter":
            generic = "<File> "
        elif case in ("new-member", "cached-member"):
            prefix = cfg_shadow
            body = "String value = new Cfg().literal();\n"
            if case == "cached-member":
                body = "Cfg receiver = new Cfg();\nString value = receiver.literal();\n"
        elif case in ("new-value-name", "plain-new"):
            parameter = "Object Cfg, " if case == "new-value-name" else ""
            body = "String value = new Cfg().literal();\n"
        source = ("import java.io.File;\nclass T {\n" + prefix + generic
                  + "void m(" + parameter + "java.io.PrintWriter out) {\n"
                  + body + "out.println(value);\n}\n" + suffix + "}\n")
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        sink_line = source.splitlines().index("out.println(value);") + 1
        index = JavaConstIndex(source, (1, len(source.splitlines())),
                               str(caller), str(tmp_path))
        assert index.ok
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    @pytest.mark.parametrize("shadowed", [False, True])
    def test_sibling_coverage_refuses_member_type(self, tmp_path, shadowed):
        from core.analysis.java_xfile_const import XFileConst

        source = ('import java.io.File;\nclass T {\n'
                  + ('static class File { static String separator=System.getenv("OWNED"); }'
                     if shadowed else "") + "\n"
                  + 'void m(java.io.PrintWriter out) {\n'
                  'out.printf("%s", File.separator);\n}\n}\n')
        caller = tmp_path / "T.java"
        caller.write_text(source)
        resolver = XFileConst(str(caller), str(tmp_path))
        assert resolver.ok
        assert ("File" in resolver.covered_identifiers(source, 5)) is not shadowed


    @pytest.mark.parametrize("before", [False, True])
    def test_local_type_scope_at_folder_boundary(self, before):
        from core.analysis.cfg_builder_java import _get_parser

        local = 'class File { static String separator=System.getenv("OWNED"); }'
        value = 'String value=File.separator;'
        source = ('import java.io.File; class T { void m() { '
                  + (local + value if before else value + local) + ' } }')
        tree = _get_parser().parse(source.encode())
        assert not tree.root_node.has_error
        stack = [tree.root_node]
        rhs = None
        while stack:
            node = stack.pop()
            if node.type == "variable_declarator":
                name = node.child_by_field_name("name")
                if name.text == b"value":
                    rhs = node.child_by_field_name("value")
            stack.extend(node.named_children)
        assert rhs is not None
        result = fold_expr(rhs, lambda _n, _d: REFUSE, allow_taint_free=True)
        assert result is (REFUSE if before else TAINT_FREE)


class TestSimpleFileIdentity:
    @pytest.mark.parametrize("case,expected", [
        ("mutable-own", False), ("literal-own", True),
        ("imported-owned", False), ("imported-jdk", True),
        ("qualified-jdk", True), ("wildcard-jdk", True),
    ])
    def test_actual_consumer_uses_source_and_import_identity(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        own = case in ("mutable-own", "literal-own")
        name = "File" if own else "T"
        declaration = ('static final String separator="safe";\n'
                       if case == "literal-own" else
                       'static String separator=System.getenv("OWNED");\n') if own else ""
        imports = ""
        receiver = "File"
        if case == "imported-owned":
            pkg = tmp_path / "owned"
            pkg.mkdir()
            (pkg / "File.java").write_text(
                'package owned; public class File { public static String '
                'separator=System.getenv("OWNED"); }')
            imports = "import owned.File;\n"
        elif case == "imported-jdk":
            imports = "import java.io.File;\n"
        elif case == "wildcard-jdk":
            imports = "import java.io.*;\n"
        elif case == "qualified-jdk":
            receiver = "java.io.File"
        source = (imports + f"class {name} {{\n" + declaration
                  + "void m(java.io.PrintWriter out) {\n"
                  + f"String value={receiver}.separator;\n"
                  + "out.println(value);\n}\n}\n")
        caller = tmp_path / f"{name}.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, len(source.splitlines())),
                               str(caller), str(tmp_path))
        sink_line = source.splitlines().index("out.println(value);") + 1
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    def test_context_free_folder_refuses_declared_top_level_file(self):
        from core.analysis.cfg_builder_java import _get_parser

        source = ('class File { static String separator=System.getenv("OWNED"); '
                  'String m() { return File.separator; } }')
        tree = _get_parser().parse(source.encode())
        assert not tree.root_node.has_error
        stack = [tree.root_node]
        fields = []
        while stack:
            node = stack.pop()
            if node.type == "field_access":
                fields.append(node)
            stack.extend(node.named_children)
        assert len(fields) == 1
        assert fold_expr(fields[0], lambda _n, _d: REFUSE,
                         allow_taint_free=True) is REFUSE


class TestAnonymousCreationIdentity:
    @pytest.mark.parametrize("anonymous,expected", [(False, True), (True, False)])
    def test_actual_consumer_through_cross_file_wrapper(self, tmp_path, anonymous, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        body = (' { String literal() { return System.getenv("OWNED"); } }'
                if anonymous else "")
        (tmp_path / "Cfg.java").write_text(
            'class Cfg { String literal() { return "safe"; } '
            'static String wrapper() { return new Cfg()' + body + '.literal(); } }'
        )
        source = ('class T {\nvoid m(java.io.PrintWriter out) {\n'
                  'String value=Cfg.wrapper();\nout.println(value);\n}\n}\n')
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, 6), str(caller), str(tmp_path))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 4)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    @pytest.mark.parametrize("anonymous", [False, True])
    def test_creation_cache_records_only_named_runtime_class(self, anonymous):
        body = ' { String literal() { return System.getenv("OWNED"); } }' if anonymous else ""
        source = 'class T { void m() { Cfg receiver=new Cfg()' + body + '; } }'
        index = JavaConstIndex(source, (1, 1))
        assert index.ok
        assert index.receiver_type("receiver") == (None if anonymous else "Cfg")


class TestDeclaringSourceContext:
    @pytest.mark.parametrize("case,expected", [
        ("mutable-field", False), ("imported-mutable", False),
        ("literal-field", True), ("imported-literal", True),
        ("method", False), ("creation", False),
        ("initializer", False), ("method-cycle", False), ("field-cycle", False),
    ])
    def test_actual_consumer_uses_declaring_namespace(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        for package in ("app", "lib", "safe", "owned"):
            (tmp_path / package).mkdir()
        imports = ""
        value = 'public static String VALUE=System.getenv("OWNED");'
        method = 'public static String literal() { return System.getenv("OWNED"); }'
        wrapper = 'public static String wrapper() { return Other.VALUE; }'
        expression = "Cfg.wrapper()"
        if case in ("literal-field", "imported-literal"):
            value = 'public static final String VALUE="safe";'
        if case.startswith("imported-"):
            imports = "import owned.Other; "
        if case == "method":
            wrapper = 'public static String wrapper() { return Other.literal(); }'
        elif case == "creation":
            wrapper = 'public static String wrapper() { return new Other().literal(); }'
        elif case == "initializer":
            wrapper = 'public static final String RESULT=Other.VALUE;'
            expression = "Cfg.RESULT"
        elif case == "method-cycle":
            wrapper = 'public static String wrapper() { return Other.literal(); }'
            method = 'public static String literal() { return Cfg.wrapper(); }'
        elif case == "field-cycle":
            wrapper = 'public static final String RESULT=Other.VALUE;'
            value = 'public static final String VALUE=Cfg.RESULT;'
            expression = "Cfg.RESULT"
        (tmp_path / "lib/Cfg.java").write_text(
            'package lib; ' + imports + 'public class Cfg { ' + wrapper + ' }')
        other = 'public class Other { ' + value + method + ' }'
        (tmp_path / "lib/Other.java").write_text('package lib; ' + other)
        (tmp_path / "owned/Other.java").write_text('package owned; ' + other)
        (tmp_path / "safe/Other.java").write_text(
            'package safe; public class Other { public static final String VALUE="safe"; '
            'public static String literal() { return "safe"; } }')
        source = ('package app;\nimport lib.Cfg;\nimport safe.Other;\nclass T {\n'
                  'void m(java.io.PrintWriter out) {\nString value=' + expression
                  + ';\nout.println(value);\n}\n}\n')
        caller = tmp_path / "app/T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, 9), str(caller), str(tmp_path))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 7)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    @pytest.mark.parametrize("hops,expected", [(2, True), (34, False)])
    def test_source_context_chain_is_bounded(self, tmp_path, hops, expected):
        from core.analysis.java_xfile_const import XFileConst

        caller = tmp_path / "T.java"
        caller.write_text("class T {}")
        for number in range(hops):
            expression = '"safe"' if number == hops - 1 else f"C{number + 1}.literal()"
            (tmp_path / f"C{number}.java").write_text(
                f"class C{number} {{ static String literal() {{ return {expression}; }} }}")
        resolver = XFileConst(str(caller), str(tmp_path))
        result = resolver.resolve_method("C0", "literal", 0, False)
        assert (result == "safe") is expected
        if not expected:
            assert result is REFUSE


class TestWrapperMemberReceiver:
    @pytest.mark.parametrize("case,expected", [
        ("field", False), ("after", False), ("method", False),
        ("record", False), ("unrelated", True), ("plain", True),
        ("constructor", True), ("initializer", False),
    ])
    def test_actual_consumer_applies_declaring_member_bindings(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        (tmp_path / "Other.java").write_text(
            'class Other { String VALUE=System.getenv("OWNED"); '
            'String literal() { return VALUE; } }')
        (tmp_path / "Helper.java").write_text(
            'class Helper { static final String VALUE="safe"; '
            'String literal() { return "safe"; } }')
        member = 'static Other Helper=new Other(); '
        prefix, suffix = "class Cfg { ", " }"
        expression = "Helper.VALUE"
        if case == "after":
            suffix = member + suffix
            member = ""
        elif case == "method":
            expression = "Helper.literal()"
        elif case == "record":
            prefix = "record Cfg(Other Helper) { "
            member = ""
        elif case == "unrelated":
            prefix = "class Unrelated { " + member + " } " + prefix
            member = ""
        elif case == "plain":
            member = ""
        elif case == "constructor":
            expression = "new Helper().literal()"
        expression_in_caller = "Cfg.wrapper()"
        wrapper = 'static String wrapper() { return ' + expression + '; } '
        if case == "record":
            wrapper = 'String wrapper() { return ' + expression + '; } '
            expression_in_caller = "new Cfg(new Other()).wrapper()"
        elif case == "initializer":
            wrapper = 'static final String VALUE=Helper.VALUE; '
            expression_in_caller = "Cfg.VALUE"
        (tmp_path / "Cfg.java").write_text(prefix + member + wrapper + suffix)
        source = ('class T {\nvoid m(java.io.PrintWriter out) {\nString value='
                  + expression_in_caller + ';\nout.println(value);\n}\n}\n')
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, 6), str(caller), str(tmp_path))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 4)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected


class TestEnclosingCreationIdentity:
    @pytest.mark.parametrize("case,expected", [
        ("enclosing", False), ("plain", True),
        ("package-qualified", True), ("constructor-argument", True),
    ])
    def test_actual_consumer_distinguishes_enclosing_instance(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        (tmp_path / "Outer.java").write_text(
            'class Outer { class Inner { String literal() { '
            'return System.getenv("OWNED"); } } }')
        (tmp_path / "Inner.java").write_text(
            'class Inner { Inner() {} Inner(Outer unused) {} '
            'String literal() { return "safe"; } }')
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg/Inner.java").write_text(
            'package pkg; public class Inner { public String literal() { return "safe"; } }')
        creation = {"enclosing": "new Outer().new Inner()", "plain": "new Inner()",
                    "package-qualified": "new pkg.Inner()",
                    "constructor-argument": "new Inner(new Outer())"}[case]
        (tmp_path / "Cfg.java").write_text(
            'class Cfg { static String wrapper() { return ' + creation + '.literal(); } }')
        source = ('class T {\nvoid m(java.io.PrintWriter out) {\n'
                  'String value=Cfg.wrapper();\nout.println(value);\n}\n}\n')
        caller = tmp_path / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, 6), str(caller), str(tmp_path))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 4)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected

    def test_creation_cache_does_not_guess_member_class(self):
        source = 'class T { void m() { Object receiver=new Outer().new Inner(); } }'
        index = JavaConstIndex(source, (1, 1))
        assert index.ok
        assert index.receiver_type("receiver") is None


class TestStringValueOfIdentity:
    @pytest.mark.parametrize("case,expected", [
        ("imported-owned", False), ("same-package", False),
        ("own-class", False), ("literal-owned", True),
        ("implicit-jdk", True), ("imported-jdk", True),
        ("unrelated-package", True),
    ])
    def test_actual_consumer_requires_jdk_identity_for_builtin(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        imports = ""
        name = "T"
        method = ('public static java.lang.String valueOf(java.lang.String ignored) '
                  '{ return System.getenv("OWNED"); }')
        if case == "literal-owned":
            method = ('public static java.lang.String valueOf(java.lang.String ignored) '
                      '{ return "owned-literal"; }')
        member = ""
        if case in ("imported-owned", "literal-owned", "unrelated-package"):
            (tmp_path / "owned").mkdir()
            (tmp_path / "owned/String.java").write_text(
                'package owned; public class String { ' + method + ' }')
            if case != "unrelated-package":
                imports = "import owned.String;\n"
        elif case == "same-package":
            (tmp_path / "String.java").write_text('class String { ' + method + ' }')
        elif case == "own-class":
            name, member = "String", method + "\n"
        elif case == "imported-jdk":
            imports = "import java.lang.String;\n"
        source = (imports + f"class {name} {{\n" + member
                  + 'void m(java.io.PrintWriter out) {\n'
                  + 'java.lang.String value=String.valueOf("fixed");\n'
                  + 'out.println(value);\n}\n}\n')
        caller = tmp_path / f"{name}.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, len(source.splitlines())), str(caller), str(tmp_path))
        sink_line = source.splitlines().index("out.println(value);") + 1
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected
        if case == "literal-owned":
            value_line = next(i + 1 for i, line in enumerate(source.splitlines())
                              if "value=String.valueOf" in line)
            rhs = index.rhs_at(value_line, "value")
            assert rhs is not None
            assert fold_expr_at(reaching_defs(graph), sink, rhs, index) == "owned-literal"

    def test_context_free_builtin_does_not_ignore_explicit_owned_import(self):
        from core.analysis.cfg_builder_java import _get_parser

        source = ('import owned.String; class T { java.lang.String m() { '
                  'return String.valueOf("fixed"); } }')
        tree = _get_parser().parse(source.encode())
        stack = [tree.root_node]
        calls = []
        while stack:
            node = stack.pop()
            if node.type == "method_invocation":
                calls.append(node)
            stack.extend(node.named_children)
        assert len(calls) == 1
        assert fold_expr(calls[0], lambda _n, _d: REFUSE) is REFUSE


    def test_unavailable_source_is_not_a_jdk_identity_miss(self, tmp_path):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        repo = tmp_path / "repo"
        repo.mkdir()
        outside = tmp_path / "String.java"
        outside.write_text('class String { static java.lang.String valueOf('
                           'java.lang.String ignored) { return System.getenv("OWNED"); } }')
        (repo / "String.java").symlink_to(outside)
        source = ('class T {\nvoid m(java.io.PrintWriter out) {\n'
                  'java.lang.String value=String.valueOf("fixed");\n'
                  'out.println(value);\n}\n}\n')
        caller = repo / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, 6), str(caller), str(repo))
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == 4)
        assert not definers_all_fold(reaching_defs(graph), sink, "value", index)


    def test_exhausted_source_lookup_budget_cannot_vouch_for_jdk(self, tmp_path):
        from core.analysis.java_xfile_const import XFileConst

        caller = tmp_path / "T.java"
        caller.write_text("class T {}")
        resolver = XFileConst(str(caller), str(tmp_path))
        for number in range(40):
            assert resolver.resolve_method(f"Missing{number}", "literal", 0, False) is REFUSE
        assert _fold('String.valueOf("fixed")', xfile=resolver) is REFUSE


class TestFileSourceFallback:
    @pytest.mark.parametrize("case,expected", [
        ("mutable", False), ("literal", True), ("unavailable", False),
        ("wildcard-jdk", True), ("unrelated-package", True),
        ("single-import-jdk", True), ("qualified-jdk", True),
    ])
    def test_actual_consumer_checks_other_compilation_unit(self, tmp_path, case, expected):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs

        repo = tmp_path / "repo"
        repo.mkdir()
        declaration = ('class File { static String separator=System.getenv("OWNED"); }')
        imports, receiver = "", "File"
        if case == "literal":
            declaration = 'class File { static final String separator="owned-literal"; }'
        if case == "unavailable":
            outside = tmp_path / "File.java"
            outside.write_text(declaration)
            (repo / "File.java").symlink_to(outside)
        elif case == "unrelated-package":
            (repo / "owned").mkdir()
            (repo / "owned/File.java").write_text('package owned; ' + declaration)
            imports = "import java.io.*;\n"
        elif case != "wildcard-jdk":
            (repo / "File.java").write_text(declaration)
        if case == "wildcard-jdk":
            imports = "import java.io.*;\n"
        elif case == "single-import-jdk":
            imports = "import java.io.File;\n"
        elif case == "qualified-jdk":
            receiver = "java.io.File"
        source = (imports + 'class T {\nvoid m(java.io.PrintWriter out) {\n'
                  + f'String value={receiver}.separator;\n'
                  + 'out.println(value);\n}\n}\n')
        caller = repo / "T.java"
        caller.write_text(source)
        graph = build_java_intraproc_cfg(source, "m")
        assert graph is not None
        index = JavaConstIndex(source, (1, len(source.splitlines())), str(caller), str(repo))
        sink_line = source.splitlines().index("out.println(value);") + 1
        sink = next(n for n in graph.nodes() if getattr(n, "lineno", 0) == sink_line)
        assert definers_all_fold(reaching_defs(graph), sink, "value", index) is expected
        if case == "literal":
            rhs = index.rhs_at(sink_line - 1, "value")
            assert rhs is not None
            assert fold_expr_at(reaching_defs(graph), sink, rhs, index) == "owned-literal"
