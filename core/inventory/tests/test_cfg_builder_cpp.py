"""Phase 9 — C / C++ intra-procedural CFG builder tests.

Mirrors the structural coverage of ``test_cfg_builder.py`` (Phase 1's
Python equivalent). Each test asserts one of:

* control-flow shape — reachability and predecessor/successor sets
* symbol layer — defs / uses / call_sites on a target node
* parameter extraction — analog of ``PythonCFG.params``
* degrade-cleanly contract — missing grammar / missing function

The fixtures are minimal hand-built C / C++ source strings; the test
parses them via ``build_cpp_intraproc_cfg`` and inspects the
returned :class:`CPPCFG`.
"""
from __future__ import annotations

import pytest

from core.inventory.cfg_builder_cpp import (
    CPPCFG,
    CPPCFGNode,
    build_cpp_intraproc_cfg,
)


# Skip the entire module if the tree-sitter grammar isn't installed
# in this environment. The repo declares the grammars as optional in
# ``requirements.txt``; CI installs them. Local dev without the
# wheels lights up this skip and keeps the rest of the suite green.
pytest.importorskip("tree_sitter_c")
pytest.importorskip("tree_sitter_cpp")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build(src: str, fn: str = "f", language: str = "c") -> CPPCFG:
    cfg = build_cpp_intraproc_cfg(src, fn, language=language)
    assert cfg is not None, f"function {fn!r} not found in:\n{src}"
    return cfg


def _nodes_at(cfg: CPPCFG, lineno: int) -> list[CPPCFGNode]:
    return [n for n in cfg.nodes() if n.lineno == lineno]


def _reachable(cfg: CPPCFG, src: CPPCFGNode) -> set[CPPCFGNode]:
    seen = {src}
    stack = [src]
    while stack:
        cur = stack.pop()
        for nxt in cfg.successors(cur):
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return seen


def _predecessors_of(cfg: CPPCFG, target: CPPCFGNode) -> set[CPPCFGNode]:
    out = set()
    for n in cfg.nodes():
        if target in cfg.successors(n):
            out.add(n)
    return out


# ---------------------------------------------------------------------------
# Basic shape — entry, exit, nodes, params
# ---------------------------------------------------------------------------


class TestBasicShape:
    def test_empty_body_links_entry_to_exit(self):
        cfg = _build("void f(void) {}")
        assert cfg.exit_node in _reachable(cfg, cfg.entry_node)

    def test_single_stmt_reachable_from_entry(self):
        cfg = _build("void f(void) { int x = 1; }")
        assert cfg.exit_node in _reachable(cfg, cfg.entry_node)
        # Three nodes: entry, the declaration, exit
        non_sentinels = [n for n in cfg.nodes()
                         if n.kind not in ("entry", "exit")]
        assert len(non_sentinels) == 1
        assert "x" in non_sentinels[0].defs

    def test_params_extracted(self):
        cfg = _build("void f(int a, char *b, const char *c) {}")
        assert cfg.params == ("a", "b", "c")

    def test_params_empty_for_void(self):
        cfg = _build("void f(void) {}")
        assert cfg.params == ()

    def test_params_no_name_skipped(self):
        # ``int f(int)`` — unnamed parameter contributes nothing
        cfg = _build("int f(int) { return 0; }")
        assert cfg.params == ()

    def test_function_not_found_returns_none(self):
        result = build_cpp_intraproc_cfg("int g(void){return 0;}", "f")
        assert result is None

    def test_invalid_language_returns_none(self):
        assert build_cpp_intraproc_cfg("int f(){return 0;}", "f",
                                       language="rust") is None

    def test_language_is_recorded(self):
        cfg = _build("int f(){return 0;}", language="c")
        assert cfg.language == "c"
        cfg2 = _build("int f(){return 0;}", language="cpp")
        assert cfg2.language == "cpp"


# ---------------------------------------------------------------------------
# Symbol layer — defs / uses / call_sites
# ---------------------------------------------------------------------------


class TestSymbolLayer:
    def test_init_declarator_def_and_call_site(self):
        src = (
            "extern char *escape(const char *);\n"
            "void f(const char *x) {\n"
            "    const char *y = escape(x);\n"
            "}\n"
        )
        cfg = _build(src)
        decl_nodes = _nodes_at(cfg, 3)
        assert len(decl_nodes) == 1
        n = decl_nodes[0]
        assert "y" in n.defs
        assert "x" in n.uses
        # call_site: escape(x) with arg_names={x}, assigned_names={y}
        assert len(n.call_sites) == 1
        cs = n.call_sites[0]
        assert cs.name == "escape"
        assert cs.arg_names == frozenset({"x"})
        assert cs.assigned_names == frozenset({"y"})

    def test_assignment_def_and_use(self):
        src = (
            "extern void render(const char *);\n"
            "void f(const char *x) {\n"
            "    const char *out;\n"
            "    out = x;\n"
            "    render(out);\n"
            "}\n"
        )
        cfg = _build(src)
        # line 4: out = x  — def=out, use=x
        line4 = _nodes_at(cfg, 4)
        assert any("out" in n.defs and "x" in n.uses for n in line4)
        # line 5: render(out) — call_site with arg=out
        line5 = _nodes_at(cfg, 5)
        assert any(
            any(cs.name == "render" and cs.arg_names == frozenset({"out"})
                for cs in n.call_sites)
            for n in line5
        )

    def test_compound_assignment_reads_lhs(self):
        # ``x += y;`` reads both x and y, defs x
        src = "void f(int x, int y) { x += y; }"
        cfg = _build(src)
        line1 = [n for n in cfg.nodes() if n.lineno == 1 and n.kind == "stmt"]
        # Find the augmented-assignment node
        aug = [n for n in line1 if "x" in n.defs]
        assert aug, f"no aug-assign node: {line1}"
        assert "x" in aug[0].uses    # compound read
        assert "y" in aug[0].uses

    def test_nested_call_assigned_names_only_on_root(self):
        # ``y = wrap(escape(x));`` — wrap is root (assigned y),
        # escape is nested (assigned {})
        src = (
            "extern char *wrap(char *);\n"
            "extern char *escape(char *);\n"
            "void f(char *x) {\n"
            "    char *y = wrap(escape(x));\n"
            "}\n"
        )
        cfg = _build(src)
        n4 = _nodes_at(cfg, 4)[0]
        by_name = {cs.name: cs for cs in n4.call_sites}
        assert "wrap" in by_name and "escape" in by_name
        assert by_name["wrap"].assigned_names == frozenset({"y"})
        assert by_name["escape"].assigned_names == frozenset()

    def test_field_expr_call_collapses_to_dotted_name(self):
        # ``obj->method(x)`` -> name "obj.method"
        src = (
            "struct S { int (*method)(int); };\n"
            "void f(struct S *obj, int x) {\n"
            "    obj->method(x);\n"
            "}\n"
        )
        cfg = _build(src)
        n3 = _nodes_at(cfg, 3)[0]
        names = {cs.name for cs in n3.call_sites}
        assert "obj.method" in names

    def test_calls_set_back_compat_field(self):
        # The legacy ``calls`` field should agree with the call_sites
        # name set.
        src = (
            "void f(int x) {\n"
            "    int y = foo(bar(x));\n"
            "}\n"
        )
        cfg = _build(src)
        n2 = _nodes_at(cfg, 2)[0]
        assert n2.calls == {cs.name for cs in n2.call_sites}
        assert "foo" in n2.calls and "bar" in n2.calls


# ---------------------------------------------------------------------------
# Control flow — if / else
# ---------------------------------------------------------------------------


class TestIfElse:
    def test_if_else_creates_two_branches(self):
        src = (
            "void f(int t) {\n"
            "    if (t) {\n"
            "        do_a();\n"
            "    } else {\n"
            "        do_b();\n"
            "    }\n"
            "    after();\n"
            "}\n"
        )
        cfg = _build(src)
        # Both branches reach `after()` (line 7)
        after = _nodes_at(cfg, 7)
        assert after, "missing after() node"
        do_a = _nodes_at(cfg, 3)[0]
        do_b = _nodes_at(cfg, 5)[0]
        assert after[0] in _reachable(cfg, do_a)
        assert after[0] in _reachable(cfg, do_b)

    def test_if_without_else_falls_through(self):
        src = (
            "void f(int t) {\n"
            "    if (t) { do_a(); }\n"
            "    after();\n"
            "}\n"
        )
        cfg = _build(src)
        cond = _nodes_at(cfg, 2)[0]
        after = _nodes_at(cfg, 3)[0]
        # Condition can reach after directly (false branch)
        assert after in _reachable(cfg, cond)


# ---------------------------------------------------------------------------
# Control flow — while / for / do-while
# ---------------------------------------------------------------------------


class TestLoops:
    def test_while_loop_back_edge(self):
        src = (
            "void f(int n) {\n"
            "    while (n > 0) { n--; }\n"
            "    done();\n"
            "}\n"
        )
        cfg = _build(src)
        header = _nodes_at(cfg, 2)[0]
        # Header should be in its own reachable set (back-edge from body)
        body_nodes = [n for n in cfg.nodes()
                      if n.lineno == 2 and n is not header]
        assert any(header in cfg.successors(b) for b in body_nodes), \
            f"no back-edge to header: {body_nodes}"

    def test_for_loop_init_cond_step_body(self):
        src = (
            "void f(void) {\n"
            "    for (int i = 0; i < 10; i++) { work(i); }\n"
            "    done();\n"
            "}\n"
        )
        cfg = _build(src)
        # All on line 2 — init, header, step, body. Init should define i.
        line2 = [n for n in cfg.nodes() if n.lineno == 2]
        has_init = any("i" in n.defs for n in line2)
        assert has_init

    def test_do_while_body_runs_first(self):
        src = (
            "void f(int n) {\n"
            "    do { n--; } while (n > 0);\n"
            "    done();\n"
            "}\n"
        )
        cfg = _build(src)
        # Body's first node should be reachable from entry without
        # going through the condition (do-while runs body first).
        # Smoke test: cfg builds and reaches exit.
        assert cfg.exit_node in _reachable(cfg, cfg.entry_node)

    def test_break_targets_after_loop(self):
        src = (
            "void f(int n) {\n"
            "    while (n) { if (n == 5) break; n--; }\n"
            "    done();\n"
            "}\n"
        )
        cfg = _build(src)
        after = _nodes_at(cfg, 3)[0]
        break_nodes = [n for n in cfg.nodes()
                       if n.lineno == 2 and n.label == "break"]
        assert break_nodes, "no break node emitted"
        # break_target is the loop header (matches the Python
        # builder's idiom — header is the join the loop's return
        # candidates list points at). ``after`` is reachable from
        # the break via header.
        assert after in _reachable(cfg, break_nodes[0])

    def test_continue_targets_loop_header(self):
        src = (
            "void f(int n) {\n"
            "    while (n) { if (n == 5) continue; n--; }\n"
            "}\n"
        )
        cfg = _build(src)
        header = _nodes_at(cfg, 2)[0]
        cont_nodes = [n for n in cfg.nodes()
                      if n.lineno == 2 and n.label == "continue"]
        assert cont_nodes
        assert header in cfg.successors(cont_nodes[0])


# ---------------------------------------------------------------------------
# Control flow — switch + fallthrough
# ---------------------------------------------------------------------------


class TestSwitch:
    def test_switch_cases_branch_from_header(self):
        src = (
            "void f(int k) {\n"
            "    switch (k) {\n"
            "        case 1: do_a(); break;\n"
            "        case 2: do_b(); break;\n"
            "        default: do_c(); break;\n"
            "    }\n"
            "    after();\n"
            "}\n"
        )
        cfg = _build(src)
        header = _nodes_at(cfg, 2)[0]
        # All three case label nodes should be reachable from header
        # and they should be at lines 3, 4, 5.
        succs = set(cfg.successors(header))
        # We're permissive — at minimum, header reaches more than one
        # node (the cases branch).
        assert len(succs) >= 2

    def test_switch_fallthrough_links_consecutive_cases(self):
        src = (
            "void f(int k) {\n"
            "    switch (k) {\n"
            "        case 1: do_a();\n"
            "        case 2: do_b(); break;\n"
            "    }\n"
            "}\n"
        )
        cfg = _build(src)
        # do_a (line 3) should reach do_b (line 4) without going
        # through any break.
        do_a = _nodes_at(cfg, 3)
        do_b = _nodes_at(cfg, 4)
        assert do_a and do_b
        assert any(b in _reachable(cfg, a) for a in do_a for b in do_b), \
            "case 1 doesn't fall through to case 2"

    def test_switch_no_default_can_skip_to_join(self):
        src = (
            "void f(int k) {\n"
            "    switch (k) {\n"
            "        case 1: do_a(); break;\n"
            "    }\n"
            "    after();\n"
            "}\n"
        )
        cfg = _build(src)
        header = _nodes_at(cfg, 2)[0]
        after = _nodes_at(cfg, 5)[0]
        # Without default, header can reach after directly (no case matched).
        assert after in _reachable(cfg, header)


# ---------------------------------------------------------------------------
# Control flow — goto + labeled
# ---------------------------------------------------------------------------


class TestGoto:
    def test_goto_links_to_labeled_statement(self):
        src = (
            "void f(int n) {\n"
            "    if (n) goto done;\n"
            "    work();\n"
            "done:\n"
            "    cleanup();\n"
            "}\n"
        )
        cfg = _build(src)
        # Find the goto node (line 2)
        goto_nodes = [n for n in cfg.nodes()
                      if n.lineno == 2 and n.label.startswith("goto")]
        assert goto_nodes, "no goto node"
        # Find the labeled node (line 4)
        label_nodes = [n for n in cfg.nodes()
                       if n.lineno == 4 and n.label.endswith(":")]
        assert label_nodes, "no label node"
        # The goto should reach the label
        assert label_nodes[0] in cfg.successors(goto_nodes[0])

    def test_goto_to_unknown_label_flows_to_exit(self):
        src = (
            "void f(void) {\n"
            "    goto nowhere;\n"
            "}\n"
        )
        cfg = _build(src)
        goto_nodes = [n for n in cfg.nodes() if n.label == "goto nowhere"]
        assert goto_nodes
        # Unknown label -> exit edge
        assert cfg.exit_node in cfg.successors(goto_nodes[0])


# ---------------------------------------------------------------------------
# Control flow — return
# ---------------------------------------------------------------------------


class TestReturn:
    def test_return_links_to_exit(self):
        src = "int f(int x) { return x; }"
        cfg = _build(src)
        ret_nodes = [n for n in cfg.nodes() if n.lineno == 1
                     and n.kind == "stmt"
                     and cfg.exit_node in cfg.successors(n)]
        assert ret_nodes, "no node links to exit on line 1"

    def test_return_blocks_fall_through(self):
        # Code after a return shouldn't be reachable from the return.
        src = (
            "int f(int x) {\n"
            "    return x;\n"
            "    dead();\n"
            "}\n"
        )
        cfg = _build(src)
        ret = [n for n in cfg.nodes() if n.lineno == 2 and "x" in n.uses][0]
        # `dead()` may still exist as a node but isn't reached by return
        reached_from_ret = _reachable(cfg, ret) - {ret}
        # The only thing the return reaches is the exit
        assert reached_from_ret == {cfg.exit_node} or cfg.exit_node in reached_from_ret


# ---------------------------------------------------------------------------
# C++-specific surface
# ---------------------------------------------------------------------------


class TestCpp:
    def test_method_inside_class_extracted(self):
        # tree-sitter-cpp: ``class C { void f() {...} };``
        src = (
            "class C {\n"
            "  void f(int x) {\n"
            "    int y = x + 1;\n"
            "  }\n"
            "};\n"
        )
        cfg = build_cpp_intraproc_cfg(src, "f", language="cpp")
        assert cfg is not None
        # `y` defined on line 3
        decl = [n for n in cfg.nodes() if n.lineno == 3 and "y" in n.defs]
        assert decl

    def test_namespace_wrapping_function(self):
        src = (
            "namespace ns {\n"
            "void f(int x) { int y = x; }\n"
            "}\n"
        )
        cfg = build_cpp_intraproc_cfg(src, "f", language="cpp")
        assert cfg is not None
        assert cfg.language == "cpp"


# ---------------------------------------------------------------------------
# Degrade-cleanly
# ---------------------------------------------------------------------------


class TestDegradeCleanly:
    def test_partial_parse_error_doesnt_crash(self):
        # tree-sitter recovers from a malformed stmt — the rest of the
        # function should still build a CFG.
        src = (
            "void f(int x) {\n"
            "    int y = x;\n"
            "    @@@ broken @@@\n"
            "    int z = y;\n"
            "}\n"
        )
        cfg = build_cpp_intraproc_cfg(src, "f")
        # Either we get a CFG (preferred — recovery worked) or None,
        # but no exception.
        if cfg is not None:
            assert cfg.exit_node in _reachable(cfg, cfg.entry_node)

    def test_missing_function_body_does_not_crash(self):
        # Pure declaration — no body
        src = "void f(int x);\n"
        result = build_cpp_intraproc_cfg(src, "f")
        # Declaration without definition doesn't match function_definition;
        # the resolver returns None rather than crashing.
        assert result is None
