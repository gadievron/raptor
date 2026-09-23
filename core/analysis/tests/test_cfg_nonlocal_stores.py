"""Name-scope discipline for bare-name stores — all three builders.

The value gate's soundness premise is that a ``name = expr`` store is
a clean LOCAL rebinding: locals are unaliasable, so a sanitizer-output
binding (``assigned_names``) or a constant definition proven over
reaching defs holds at the sink. That premise is FALSE for bare-name
stores that bind outside the local frame:

* Java: ``data = "safe";`` with no local ``data`` writes a FIELD of
  the enclosing class — ``process(req)`` can re-taint it and the
  reaching-defs oracle (call nodes define nothing) never sees it.
* C/C++: the same store shape reaches a file-scope global / static /
  class member.
* Python: a name declared ``global`` / ``nonlocal`` binds the module
  (or enclosing-closure) slot — ``helper()`` can rewrite it.

Every builder must therefore withhold ``assigned_names`` for such
stores (the def itself stays — an extra definer only breaks
exclusivity proofs, never grants identity) and stamp the node
``may_escape``; ``JavaConstIndex`` must refuse to serve them as
definitions. These tests reproduce the hostile shapes end-to-end
through :func:`core.analysis.sanitizer_cut.evaluate_finding` — each
gate scenario suppressed before the scope discipline landed.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.cfg_builder import build_python_cfg

# ---------------------------------------------------------------------------
# Closure over the producer family
# ---------------------------------------------------------------------------

# Every CFG-builder module must have a leg in the scope-discipline
# fixtures below. A new language builder added to core/analysis is a
# new producer of defs/assigned_names and MUST implement (and pin) the
# same non-local-store demotion before this test will pass.
_COVERED_BUILDER_MODULES = {
    "cfg_builder.py",       # Python (+ the shared CallSite dataclass)
    "cfg_builder_java.py",
    "cfg_builder_cpp.py",   # both the "c" and "cpp" grammar legs
}


def test_every_builder_module_has_a_scope_discipline_leg():
    analysis_dir = Path(__file__).resolve().parents[1]
    on_disk = {p.name for p in analysis_dir.glob("cfg_builder*.py")}
    assert on_disk == _COVERED_BUILDER_MODULES, (
        "CFG-builder module set changed — every builder grants "
        "defs/assigned_names and must implement the non-local-store "
        "demotion (withhold assigned_names, stamp may_escape) and "
        "get a leg in this file's fixtures"
    )


# ---------------------------------------------------------------------------
# Builder-level assertions — one leg per language
# ---------------------------------------------------------------------------


_PY_GLOBAL = '''
import html
def handle(x):
    global cfg
    cfg = html.escape(x)
    helper()
    render(cfg)
'''

_PY_LOCAL = '''
import html
def handle(x):
    cfg = html.escape(x)
    helper()
    render(cfg)
'''


def _store_node(cfg, name):
    # The sanitizer-store node: defines ``name`` and calls a
    # sanitizer-shaped callable (html.escape / Encode.forHtml /
    # g_markup_escape_text).
    return next(
        n for n in cfg.nodes()
        if name in n.defs and any(
            "escape" in cs.name or "forHtml" in cs.name
            for cs in n.call_sites
        )
    )


class TestPythonGlobalStores:
    def test_global_store_demoted(self):
        cfg = build_python_cfg(_PY_GLOBAL, "handle")
        node = _store_node(cfg, "cfg")
        assert node.may_escape
        assert "cfg" in node.defs  # def kept: refusal direction
        assert all(not cs.assigned_names for cs in node.call_sites)

    def test_local_store_keeps_identity(self):
        cfg = build_python_cfg(_PY_LOCAL, "handle")
        node = _store_node(cfg, "cfg")
        assert not node.may_escape
        assert any("cfg" in cs.assigned_names for cs in node.call_sites)

    def test_nonlocal_store_demoted(self):
        src = _PY_GLOBAL.replace("global cfg", "nonlocal cfg")
        # nonlocal without an enclosing binding is a SyntaxError at
        # module level; wrap in an outer function.
        src = "def outer():\n    cfg = None\n" + "\n".join(
            "    " + line for line in src.splitlines() if line
        ) + "\n"
        cfg = build_python_cfg(src, "handle")
        node = _store_node(cfg, "cfg")
        assert node.may_escape
        assert all(not cs.assigned_names for cs in node.call_sites)

    def test_nested_def_globals_do_not_leak_into_enclosing(self):
        src = '''
def handle(x):
    def inner():
        global cfg
        cfg = 1
    cfg = html.escape(x)
    render(cfg)
'''
        cfg = build_python_cfg(src, "handle")
        node = _store_node(cfg, "cfg")
        # ``global`` inside the nested def binds the NESTED frame's
        # cfg, not handle's — handle's cfg stays a clean local.
        assert not node.may_escape
        assert any("cfg" in cs.assigned_names for cs in node.call_sites)


_JAVA_SRC = '''import org.owasp.encoder.Encode;
public class T {
    String data;
    public void handle(String x, java.io.PrintWriter out) {
        data = Encode.forHtml(x);
        mutate();
        out.println(data);
    }
    public void local(String x, java.io.PrintWriter out) {
        String data = Encode.forHtml(x);
        mutate();
        out.println(data);
    }
}
'''


class TestJavaBareNameFieldStores:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_java")

    def test_field_store_demoted(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        cfg = build_java_intraproc_cfg(_JAVA_SRC, "handle")
        node = _store_node(cfg, "data")
        assert node.may_escape
        assert "data" in node.defs
        assert all(not cs.assigned_names for cs in node.call_sites)

    def test_declared_local_keeps_identity(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        cfg = build_java_intraproc_cfg(_JAVA_SRC, "local")
        node = _store_node(cfg, "data")
        assert not node.may_escape
        assert any("data" in cs.assigned_names for cs in node.call_sites)

    def test_field_store_in_condition_stamps_escape(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = '''public class T {
    String d;
    void handle(String x, java.io.PrintWriter out) {
        if ((d = x) != null) { out.println(d); }
    }
}
'''
        cfg = build_java_intraproc_cfg(src, "handle")
        cond = next(n for n in cfg.nodes() if "d" in n.defs)
        assert cond.may_escape


_C_SRC = '''
char *g;
void handle(char *x) {
    g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
}
void local_fn(char *x) {
    char *g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
}
'''


class TestCGlobalStores:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_c")

    def test_global_store_demoted(self):
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        cfg = build_cpp_intraproc_cfg(_C_SRC, "handle", language="c")
        node = _store_node(cfg, "g")
        assert node.may_escape
        assert "g" in node.defs
        assert all(not cs.assigned_names for cs in node.call_sites)

    def test_declared_local_keeps_identity(self):
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        cfg = build_cpp_intraproc_cfg(_C_SRC, "local_fn", language="c")
        node = _store_node(cfg, "g")
        assert not node.may_escape
        assert any("g" in cs.assigned_names for cs in node.call_sites)

    def test_member_store_in_cpp_method_demoted(self):
        pytest.importorskip("tree_sitter_cpp")
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        src = '''
class C {
    char *m;
    void handle(char *x) {
        m = g_markup_escape_text(x, -1);
        helper();
        sink(m);
    }
};
'''
        cfg = build_cpp_intraproc_cfg(src, "handle", language="cpp")
        node = _store_node(cfg, "m")
        assert node.may_escape
        assert all(not cs.assigned_names for cs in node.call_sites)

    def test_field_lhs_never_earns_assigned_names(self):
        # ``s.f = call(x)`` mutates through the base name without
        # rebinding it — identity must not transfer to ``s``.
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        src = '''
struct S { char *f; };
void handle(struct S s, char *x) {
    s.f = g_markup_escape_text(x, -1);
    sink(s.f);
}
'''
        cfg = build_cpp_intraproc_cfg(src, "handle", language="c")
        node = next(n for n in cfg.nodes() if "s" in n.defs)
        assert all(not cs.assigned_names for cs in node.call_sites)


# ---------------------------------------------------------------------------
# JavaConstIndex — the constant-definers gate's definition oracle
# ---------------------------------------------------------------------------


class TestJavaConstIndexScope:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_java")

    SRC = '''public class T {
    String data;
    Helper h = new Helper();
    void handle(java.sql.Statement stmt, Req req) throws Exception {
        data = "safe";
        process(req);
        stmt.execute(data);
    }
    void other(java.io.PrintWriter out) {
        String data = "ok";
        out.println(data);
    }
}
'''

    def _index(self, src=None):
        from core.analysis.const_fold_java import JavaConstIndex
        src = src or self.SRC
        return JavaConstIndex(src, (1, src.count("\n") + 1))

    def test_bare_field_store_refuses(self):
        idx = self._index()
        assert idx.ok
        assert idx.rhs_at(5, "data") is None

    def test_shadowing_local_in_other_method_still_serves(self):
        idx = self._index()
        rhs = idx.rhs_at(10, "data")
        assert rhs is not None
        assert rhs.text.decode() == '"ok"'

    def test_field_declarator_not_indexed(self):
        idx = self._index()
        assert idx.rhs_at(2, "data") is None

    def test_field_creation_poisons_receiver_type(self):
        idx = self._index()
        # ``h`` is a field: another method (or thread) can rebind it
        # to a subclass — its exact class is not stable, so the
        # cross-file returns-literal resolver must not trust it.
        assert idx.receiver_type("h") is None

    def test_local_creation_still_typed(self):
        src = '''public class T {
    void m() {
        Helper h = new Helper();
        use(h);
    }
}
'''
        idx = self._index(src)
        assert idx.receiver_type("h") == "Helper"


class TestNestedTypeBodyBarriers:
    """Anonymous-class and local record/enum/interface BODIES declare
    members, not method locals. The refusal walk and the scope
    collector key on the body node types the installed grammar
    actually produces (anonymous classes emit ``class_body``; there is
    no ``anonymous_class_body``), so a member declarator can never
    re-arm the vouch oracle for a same-named field store."""

    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_java")

    def _build(self, body: str):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = ('public class T {\n'
               '    String data;\n'
               '    void handle(String req, java.io.PrintWriter out) {\n'
               f'{body}'
               '        data = "safe";\n'
               '        process(req);\n'
               '        out.println(data);\n'
               '    }\n'
               '}\n')
        return build_java_intraproc_cfg(src, "handle"), src

    def test_anonymous_class_refuses(self):
        cfg, _ = self._build(
            '        Object o = new Object() { String data = "x"; };\n')
        assert cfg is None, (
            "method containing an anonymous class must refuse — its "
            "declarators are members, not locals"
        )

    def test_local_record_refuses(self):
        cfg, _ = self._build(
            '        record R(int a) { static String data = "x"; }\n')
        assert cfg is None

    def test_local_enum_refuses(self):
        cfg, _ = self._build(
            '        enum E { A; }\n')
        assert cfg is None

    def test_local_interface_refuses(self):
        cfg, _ = self._build(
            '        interface I { String data = "x"; }\n')
        assert cfg is None

    def test_plain_method_still_builds(self):
        cfg, _ = self._build("")
        assert cfg is not None

    def test_anonymous_body_declarator_earns_no_vouch_window(self):
        # Scope-collector unit: the member declarator inside the
        # anonymous class body must not vouch a later bare-name store
        # in the enclosing method.
        import tree_sitter_java as tsj
        from core.analysis.cfg_builder_java import _declared_local_scopes
        from core.inventory.call_graph import _get_ts_parser
        src = ('public class T {\n'
               '    String data;\n'
               '    void handle(String req) {\n'
               '        Object o = new Object() { String data = "x"; };\n'
               '        data = "safe";\n'
               '    }\n'
               '}\n')
        parser = _get_ts_parser(tsj.language)
        tree = parser.parse(src.encode())
        stack = [tree.root_node]
        method = None
        while stack:
            cur = stack.pop()
            if cur.type == "method_declaration":
                method = cur
                break
            stack.extend(cur.children)
        assert method is not None
        scopes = _declared_local_scopes(method)
        store_byte = src.index('data = "safe"')
        assert not scopes.vouches("data", store_byte), (
            "anonymous-class member declarator re-armed the vouch "
            "oracle for a field store"
        )

    def test_const_index_refuses_anonymous_rearmed_store(self):
        # JavaConstIndex shares the scope collector; the bare field
        # store after an anonymous-body declarator must not serve as
        # a scoped-local definition.
        from core.analysis.const_fold_java import JavaConstIndex
        src = ('public class T {\n'
               '    String data;\n'
               '    void handle(java.sql.Statement stmt, Req req)'
               ' throws Exception {\n'
               '        Object o = new Object() { String data = "x"; };\n'
               '        data = "safe";\n'
               '        process(req);\n'
               '        stmt.execute(data);\n'
               '    }\n'
               '}\n')
        idx = JavaConstIndex(src, (1, src.count("\n") + 1))
        assert idx.ok
        assert idx.rhs_at(5, "data") is None, (
            "anonymous-body declarator granted the field store a "
            "scoped-local definition"
        )


# ---------------------------------------------------------------------------
# End-to-end through the production suppression gate
# ---------------------------------------------------------------------------


def _java_gate(src, method, sink_marker, sink_arg, source_symbols):
    from core.analysis.cfg_builder_java import build_java_intraproc_cfg
    from core.analysis.dataflow import reaching_defs  # noqa: F401 - substrate import guard
    from core.analysis.sanitizer_cut import evaluate_finding
    cfg = build_java_intraproc_cfg(src, method)
    assert cfg is not None
    sink = next(n for n in cfg.nodes() if sink_marker in n.label)
    return evaluate_finding(
        cfg, [cfg.entry], sink,
        cwe="CWE-79", language="java",
        source_symbols=source_symbols, sink_arg=sink_arg,
        java_source_text=src,
    )


class TestGateEndToEnd:
    """The exact false-suppress traces, through evaluate_finding."""

    def test_java_field_constant_precheck_does_not_suppress(self):
        pytest.importorskip("tree_sitter_java")
        src = '''public class T {
    String data;
    void handle(String req, java.io.PrintWriter out) {
        data = "safe";
        process(req);
        out.println(data);
    }
}
'''
        result = _java_gate(src, "handle", "out.println", "data", ["req"])
        assert not result.suppress
        # A LOCAL of the same shape stays provably constant.
        local_src = src.replace('        data = "safe";',
                                '        String data = "safe";')
        local_src = local_src.replace("    String data;\n", "")
        result2 = _java_gate(
            local_src, "handle", "out.println", "data", ["req"])
        assert result2.suppress
        assert "constant sink argument" in result2.reason

    def test_java_field_sanitizer_exclusivity_does_not_suppress(self):
        pytest.importorskip("tree_sitter_java")
        result = _java_gate(
            _JAVA_SRC, "handle", "out.println", "data", ["x"])
        assert not result.suppress
        # The declared-local twin still earns the suppression.
        result2 = _java_gate(
            _JAVA_SRC, "local", "out.println", "data", ["x"])
        assert result2.suppress

    def test_python_global_rebinding_does_not_suppress(self):
        from core.analysis.sanitizer_cut import evaluate_finding
        cfg = build_python_cfg(_PY_GLOBAL, "handle")
        sink = next(n for n in cfg.nodes() if "render" in n.calls)
        result = evaluate_finding(
            cfg, [cfg.entry], sink,
            cwe="CWE-79", language="python",
            source_symbols=["x"], sink_arg="cfg",
        )
        assert not result.suppress
        # The local twin still suppresses.
        cfg2 = build_python_cfg(_PY_LOCAL, "handle")
        sink2 = next(n for n in cfg2.nodes() if "render" in n.calls)
        result2 = evaluate_finding(
            cfg2, [cfg2.entry], sink2,
            cwe="CWE-79", language="python",
            source_symbols=["x"], sink_arg="cfg",
        )
        assert result2.suppress

    def test_c_global_rebinding_does_not_suppress(self):
        pytest.importorskip("tree_sitter_c")
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        from core.analysis.sanitizer_cut import evaluate_finding
        cfg = build_cpp_intraproc_cfg(_C_SRC, "handle", language="c")
        sink = next(n for n in cfg.nodes() if "sink" in n.calls)
        result = evaluate_finding(
            cfg, [cfg.entry], sink,
            cwe="CWE-79", language="c",
            source_symbols=["x"], sink_arg="g",
        )
        assert not result.suppress

    def test_java_branch_refinement_keeps_field_edges(self):
        # ``data`` is a FIELD: the if-refinement must NOT fold the
        # condition and prune the tainted arm — process(req) can
        # rewrite the field before the test.
        pytest.importorskip("tree_sitter_java")
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = '''public class T {
    String data;
    void handle(String req, java.io.PrintWriter out) {
        data = "a";
        process(req);
        if (data == "a") { out.println("x"); } else { out.println(req); }
    }
}
'''
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        assert "if:constant-resolved" not in cfg.build_notes

    def test_python_global_temp_helper_never_suppresses(self):
        # Interprocedural leg of the same class: a helper whose
        # tracked temp is bound ``global`` earned a cleanly-
        # sanitizing summary — ``other()`` can rewrite the module
        # slot before the return, yet the synthetic binding
        # suppressed the caller's flow end-to-end.
        import ast as _ast

        from core.analysis.interproc import synthetic_sanitizer_bindings
        from core.analysis.python_module_callgraph import (
            build_python_module_callgraph,
        )
        from core.analysis.sanitizer_cut import evaluate_finding
        from core.analysis.taint_summaries import build_taint_summaries

        src = (
            "import html\n"
            "def _clean(s):\n"
            "    global tmp\n"
            "    tmp = html.escape(s)\n"
            "    other()\n"
            "    return tmp\n"
            "def handler(x):\n"
            "    y = _clean(x)\n"
            "    render(y)\n"
        )

        def gate(source: str, sink_line: int):
            cg = build_python_module_callgraph(source)
            summaries = build_taint_summaries(cg, source)
            fn_ast = next(
                n for n in _ast.walk(_ast.parse(source))
                if isinstance(n, _ast.FunctionDef) and n.name == "handler"
            )
            cfg = build_python_cfg(source, "handler")
            bindings = synthetic_sanitizer_bindings(
                cfg, fn_ast, summaries, "CWE-79", "python")
            sink = next(n for n in cfg.nodes() if n.lineno == sink_line)
            return evaluate_finding(
                cfg, [cfg.entry_node], sink,
                cwe="CWE-79", language="python",
                source_symbols=["x"], sink_arg="y",
                extra_bindings=bindings,
            )

        assert not gate(src, 9).suppress
        # The local-temp twin keeps the interprocedural suppression.
        assert gate(src.replace("    global tmp\n", ""), 8).suppress


# ---------------------------------------------------------------------------
# Positional scope: a declarator vouches only for stores at/after it,
# inside its enclosing scope
# ---------------------------------------------------------------------------


class TestPositionalScope:
    """Flat per-method name membership was steerable: one dead
    block-scoped declarator anywhere in the method — after the sink,
    in unreachable code — re-armed local-grade semantics for every
    same-named FIELD/global bare store. Each hostile shape here
    suppressed before scope membership became positional."""

    def test_java_trailing_dead_declarator_constant_precheck(self):
        pytest.importorskip("tree_sitter_java")
        src = '''public class T {
    String data;
    void handle(String req, java.io.PrintWriter out) {
        data = "safe";
        process(req);
        out.println(data);
        if (req == null) { String data = ""; log(data); }
    }
}
'''
        result = _java_gate(src, "handle", "out.println", "data", ["req"])
        assert not result.suppress

    def test_java_early_disjoint_block_declarator(self):
        pytest.importorskip("tree_sitter_java")
        src = '''import org.owasp.encoder.Encode;
public class T {
    String data;
    void handle(String x, java.io.PrintWriter out) {
        if (x == null) { String data = ""; log(data); }
        data = Encode.forHtml(x);
        mutate();
        out.println(data);
    }
}
'''
        result = _java_gate(src, "handle", "out.println", "data", ["x"])
        assert not result.suppress

    def test_java_trailing_dead_declarator_sanitizer_exclusivity(self):
        pytest.importorskip("tree_sitter_java")
        src = '''import org.owasp.encoder.Encode;
public class T {
    String data;
    void handle(String x, java.io.PrintWriter out) {
        data = Encode.forHtml(x);
        mutate();
        out.println(data);
        if (x == null) { String data = ""; log(data); }
    }
}
'''
        result = _java_gate(src, "handle", "out.println", "data", ["x"])
        assert not result.suppress

    def test_c_dead_block_declarator(self):
        pytest.importorskip("tree_sitter_c")
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        from core.analysis.sanitizer_cut import evaluate_finding
        src = '''
char *g;
void handle(char *x) {
    g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
    if (!x) { char *g = 0; use(g); }
}
'''
        cfg = build_cpp_intraproc_cfg(src, "handle", language="c")
        sink = next(n for n in cfg.nodes() if "sink" in n.calls)
        result = evaluate_finding(
            cfg, [cfg.entry], sink,
            cwe="CWE-79", language="c",
            source_symbols=["x"], sink_arg="g",
        )
        assert not result.suppress

    def test_java_declarator_vouches_after_intervening_block(self):
        # Recall control for the positional rule: a method-top
        # declarator's window spans the whole body, so a store after
        # it — past an intervening nested block — keeps local grade
        # and the declared-local suppression.
        pytest.importorskip("tree_sitter_java")
        src = '''import org.owasp.encoder.Encode;
public class T {
    void handle(String x, java.io.PrintWriter out) {
        String data = "x";
        if (x == null) { log(x); }
        data = Encode.forHtml(x);
        mutate();
        out.println(data);
    }
}
'''
        result = _java_gate(src, "handle", "out.println", "data", ["x"])
        assert result.suppress

    def test_java_store_inside_nested_block_keeps_identity(self):
        # Builder-level twin: the store INSIDE a nested block is
        # still after the method-top declarator and inside its
        # window — local grade preserved.
        pytest.importorskip("tree_sitter_java")
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = '''import org.owasp.encoder.Encode;
public class T {
    void handle(String x, java.io.PrintWriter out) {
        String data = "";
        if (x != null) { data = Encode.forHtml(x); }
        out.println(data);
    }
}
'''
        cfg = build_java_intraproc_cfg(src, "handle")
        node = _store_node(cfg, "data")
        assert not node.may_escape
        assert any("data" in cs.assigned_names for cs in node.call_sites)

    def test_java_const_index_positional(self):
        pytest.importorskip("tree_sitter_java")
        from core.analysis.const_fold_java import JavaConstIndex
        src = '''public class T {
    String data;
    void handle(String req, java.io.PrintWriter out) {
        data = "safe";
        out.println(data);
        if (req == null) { String data = ""; log(data); }
    }
}
'''
        idx = JavaConstIndex(src, (1, src.count("\n") + 1))
        assert idx.ok
        # The FIELD store at line 4 has no preceding in-scope
        # declarator — the dead block declarator must not serve it.
        assert idx.rhs_at(4, "data") is None
        # The dead block's own declarator still serves inside its
        # block (a genuine local definition).
        assert idx.rhs_at(6, "data") is not None


# ---------------------------------------------------------------------------
# C storage classes and nested-scope barriers
# ---------------------------------------------------------------------------


class TestCStorageClassesAndBarriers:
    @pytest.fixture(autouse=True)
    def _grammar(self):
        pytest.importorskip("tree_sitter_c")

    def _c_gate(self, src):
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        from core.analysis.sanitizer_cut import evaluate_finding
        cfg = build_cpp_intraproc_cfg(src, "handle", language="c")
        sink = next(n for n in cfg.nodes() if "sink" in n.calls)
        return evaluate_finding(
            cfg, [cfg.entry], sink,
            cwe="CWE-79", language="c",
            source_symbols=["x"], sink_arg="g",
        )

    def test_extern_declaration_in_body_not_local(self):
        # ``extern char *g;`` inside the body DECLARES THE GLOBAL —
        # registering it as a local handed every subsequent bare
        # store to g local-grade semantics (undocumented class
        # member: the declaration syntax names the exact non-local
        # the oracle exists to demote).
        src = '''
char *g;
void handle(char *x) {
    extern char *g;
    g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
}
'''
        assert not self._c_gate(src).suppress

    def test_static_local_demoted(self):
        # Function-``static`` storage is shared across calls: the
        # value stays a sanitizer output only absent reentrancy.
        # Demoted with extern (fail closed) — the recall cost is one
        # rare idiom; the alternative trusts cross-call state.
        src = '''
void handle(char *x) {
    static char *g;
    g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
}
'''
        assert not self._c_gate(src).suppress

    def test_cpp_local_class_declarations_do_not_leak(self):
        pytest.importorskip("tree_sitter_cpp")
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        # The local class's method declares its own ``g`` — without
        # the nested-class barrier it leaked into the outer
        # function's local set and vouched for the GLOBAL store.
        src = '''
char *g;
void handle(char *x) {
    struct H { void m() { char *g = 0; use(g); } };
    g = g_markup_escape_text(x, -1);
    helper();
    sink(g);
}
'''
        cfg = build_cpp_intraproc_cfg(src, "handle", language="cpp")
        node = _store_node(cfg, "g")
        assert node.may_escape
        assert all(not cs.assigned_names for cs in node.call_sites)
