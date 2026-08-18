"""Phase 12 — Python module-local call-graph tests."""
from __future__ import annotations

import ast

from core.analysis.python_module_callgraph import (
    MODULE_ENTRY_NAME,
    PyCallGraphNode,
    PyModuleCallGraph,
    build_python_module_callgraph,
)


def _build(src: str) -> PyModuleCallGraph:
    cg = build_python_module_callgraph(src)
    assert cg is not None
    return cg


def _names(nodes) -> set[str]:
    return {n.name for n in nodes}


def _successor_names(cg: PyModuleCallGraph, name: str) -> set[str]:
    node = cg.find(name)
    assert node is not None, f"missing node {name!r}"
    return {s.name for s in cg.successors(node)}


# ---------------------------------------------------------------------------
# Basic shape — nodes, module entry, empty module
# ---------------------------------------------------------------------------


class TestBasicShape:
    def test_empty_module_has_only_entry(self):
        cg = _build("")
        assert _names(cg.nodes()) == {MODULE_ENTRY_NAME}
        assert cg.entry.is_module_entry is True

    def test_single_function_is_node(self):
        cg = _build("def f(): pass\n")
        assert "f" in _names(cg.nodes())
        n = cg.find("f")
        assert n is not None and not n.is_method
        assert n.params == ()

    def test_function_params_captured(self):
        cg = _build("def f(a, b, *args, c=1, **kwargs): pass\n")
        n = cg.find("f")
        assert n is not None
        assert n.params == ("a", "b", "args", "c", "kwargs")

    def test_unparseable_source_returns_none(self):
        assert build_python_module_callgraph("def f(:::\n") is None

    def test_module_entry_reaches_top_level_functions(self):
        cg = _build("def f(): pass\ndef g(): pass\n")
        succ = _successor_names(cg, MODULE_ENTRY_NAME)
        assert {"f", "g"} <= succ

    def test_node_has_line_range(self):
        cg = _build(
            "def f():\n"
            "    x = 1\n"
            "    return x\n"
        )
        n = cg.find("f")
        assert n.lineno == 1
        assert n.end_lineno >= 3

    def test_function_ast_accessor(self):
        cg = _build("def f(x):\n    return x + 1\n")
        astn = cg.function_ast("f")
        assert isinstance(astn, ast.FunctionDef)
        assert astn.name == "f"

    def test_function_ast_unknown_name_returns_none(self):
        cg = _build("def f(): pass\n")
        assert cg.function_ast("missing") is None
        assert cg.function_ast(MODULE_ENTRY_NAME) is None


# ---------------------------------------------------------------------------
# Edges — top-level and intra-function calls
# ---------------------------------------------------------------------------


class TestEdges:
    def test_caller_to_callee(self):
        cg = _build(
            "def helper(x): return x\n"
            "def main(x): return helper(x)\n"
        )
        assert "helper" in _successor_names(cg, "main")

    def test_module_level_call_edge(self):
        cg = _build(
            "def helper(): pass\n"
            "helper()\n"
        )
        # The bare ``helper()`` at module level is an edge from
        # <module> to helper.
        assert "helper" in _successor_names(cg, MODULE_ENTRY_NAME)

    def test_recursion_self_edge(self):
        cg = _build("def f(n):\n    return f(n-1)\n")
        assert "f" in _successor_names(cg, "f")

    def test_cross_module_call_dropped(self):
        cg = _build(
            "import requests\n"
            "def fetch():\n"
            "    requests.get('/x')\n"
        )
        # ``requests.get`` is cross-module — no edge.
        assert _successor_names(cg, "fetch") == set()

    def test_builtin_call_dropped(self):
        cg = _build(
            "def f(xs):\n"
            "    return len(xs)\n"
        )
        # ``len`` isn't defined in this module — drop.
        assert _successor_names(cg, "f") == set()

    def test_undefined_local_call_dropped(self):
        cg = _build(
            "def f():\n"
            "    return not_defined_here()\n"
        )
        assert _successor_names(cg, "f") == set()

    def test_lambda_invocation_dropped(self):
        # ``(lambda x: x)(1)`` — call func isn't a name/attribute.
        cg = _build(
            "def f():\n"
            "    return (lambda x: x)(1)\n"
        )
        assert _successor_names(cg, "f") == set()

    def test_conditional_call_still_edge(self):
        cg = _build(
            "def a(): pass\n"
            "def b(): pass\n"
            "def f(t):\n"
            "    if t:\n"
            "        a()\n"
            "    else:\n"
            "        b()\n"
        )
        succ = _successor_names(cg, "f")
        assert succ == {"a", "b"}


# ---------------------------------------------------------------------------
# Methods — class context, self.method resolution
# ---------------------------------------------------------------------------


class TestMethods:
    def test_method_qualified_name(self):
        cg = _build(
            "class C:\n"
            "    def m(self): pass\n"
        )
        n = cg.find("C.m")
        assert n is not None
        assert n.is_method and n.class_name == "C"

    def test_method_qualified_name_in_node_set(self):
        cg = _build(
            "class C:\n"
            "    def foo(self): pass\n"
            "    def bar(self): pass\n"
        )
        names = _names(cg.nodes())
        assert {"C.foo", "C.bar"} <= names

    def test_self_dot_method_resolution(self):
        cg = _build(
            "class C:\n"
            "    def foo(self): pass\n"
            "    def bar(self):\n"
            "        self.foo()\n"
        )
        assert _successor_names(cg, "C.bar") == {"C.foo"}

    def test_cls_dot_method_resolution(self):
        cg = _build(
            "class C:\n"
            "    def foo(cls): pass\n"
            "    def bar(cls):\n"
            "        cls.foo()\n"
        )
        assert _successor_names(cg, "C.bar") == {"C.foo"}

    def test_class_dot_method_static_style(self):
        cg = _build(
            "class C:\n"
            "    def foo(): pass\n"
            "def call_it():\n"
            "    C.foo()\n"
        )
        assert _successor_names(cg, "call_it") == {"C.foo"}

    def test_constructor_resolves_to_init(self):
        cg = _build(
            "class C:\n"
            "    def __init__(self, x): pass\n"
            "def build():\n"
            "    return C(1)\n"
        )
        assert _successor_names(cg, "build") == {"C.__init__"}

    def test_constructor_without_init_drops(self):
        cg = _build(
            "class C:\n"
            "    pass\n"
            "def build():\n"
            "    return C()\n"
        )
        assert _successor_names(cg, "build") == set()

    def test_self_dot_method_outside_class_drops(self):
        # ``self.foo()`` in a free function — caller has no
        # class_name; resolution drops the edge.
        cg = _build(
            "def f(self):\n"
            "    self.foo()\n"
        )
        assert _successor_names(cg, "f") == set()


# ---------------------------------------------------------------------------
# Nested functions + lambdas
# ---------------------------------------------------------------------------


class TestNested:
    def test_nested_function_qualified_name(self):
        cg = _build(
            "def outer():\n"
            "    def inner(): pass\n"
            "    return inner\n"
        )
        assert "outer.inner" in _names(cg.nodes())

    def test_outer_calls_inner(self):
        cg = _build(
            "def outer():\n"
            "    def inner(): pass\n"
            "    inner()\n"
        )
        # ``inner()`` resolves to the nested def, not a top-level
        # one (there isn't one).
        assert "outer.inner" in _successor_names(cg, "outer")

    def test_nested_method_qualified_name(self):
        cg = _build(
            "class C:\n"
            "    def m(self):\n"
            "        def helper(): pass\n"
            "        helper()\n"
        )
        assert "C.m.helper" in _names(cg.nodes())
        assert "C.m.helper" in _successor_names(cg, "C.m")

    def test_lambda_assigned_to_name_is_node(self):
        cg = _build(
            "compute = lambda x: x + 1\n"
            "def caller():\n"
            "    return compute(5)\n"
        )
        assert "compute" in _names(cg.nodes())
        compute = cg.find("compute")
        assert compute.params == ("x",)
        assert "compute" in _successor_names(cg, "caller")

    def test_anonymous_lambda_not_a_node(self):
        cg = _build(
            "def f():\n"
            "    return (lambda x: x)(1)\n"
        )
        # No binding name for the lambda; nothing in the node set.
        names = _names(cg.nodes())
        assert names == {MODULE_ENTRY_NAME, "f"}


# ---------------------------------------------------------------------------
# Graph protocol — entry, nodes(), successors()
# ---------------------------------------------------------------------------


class TestGraphProtocol:
    def test_graph_protocol_satisfied(self):
        cg = _build("def f(): pass\n")
        # Just check the protocol-method surface — Graph[N] from
        # core.analysis.dominators is a Protocol class without
        # runtime isinstance checks against frozen dataclasses, so
        # we test by attribute access instead.
        assert hasattr(cg, "entry")
        assert callable(cg.nodes)
        assert callable(cg.successors)
        # Yielding an iterable of nodes
        node_list = list(cg.nodes())
        assert len(node_list) >= 1

    def test_unreachable_function_still_in_node_set(self):
        # A function with no incoming edges is still a node — it's
        # just unreachable from the entry. Phase 14 will refuse to
        # use summaries of unreachable functions on a per-finding
        # basis, but they exist for diagnostics.
        cg = _build(
            "class C:\n"
            "    def orphan(self): pass\n"
        )
        assert "C.orphan" in _names(cg.nodes())

    def test_successors_returns_iterable_for_unknown_node(self):
        cg = _build("def f(): pass\n")
        # A node not in the graph: no successors, no crash.
        ghost = PyCallGraphNode(name="ghost", lineno=999)
        assert list(cg.successors(ghost)) == []


class TestConditionalRedefinition:
    """``if X: def f() / else: def f()`` produces two distinct nodes;
    the name-keyed maps used to collapse last-writer-wins, dropping
    the earlier body from the graph (taint through it was invisible)
    and mis-attributing its outgoing calls to the later variant."""

    SRC = (
        "import os\n"
        "\n"
        "if os.environ.get('X'):\n"
        "    def f(a):\n"
        "        early_helper(a)\n"
        "        return a\n"
        "else:\n"
        "    def f(a):\n"
        "        late_helper(a)\n"
        "        return a\n"
        "\n"
        "def early_helper(a):\n"
        "    return a\n"
        "\n"
        "def late_helper(a):\n"
        "    return a\n"
        "\n"
        "def caller(x):\n"
        "    return f(x)\n"
    )

    def _graph(self):
        from core.analysis.python_module_callgraph import (
            build_python_module_callgraph,
        )
        return build_python_module_callgraph(self.SRC)

    def test_both_variants_are_nodes(self):
        cg = self._graph()
        variants = cg.find_all("f")
        assert len(variants) == 2
        assert variants[0].lineno < variants[1].lineno
        assert {v.lineno for v in variants} <= {n.lineno for n in cg.nodes()}

    def test_find_returns_last_variant_and_asts_returns_both(self):
        cg = self._graph()
        assert cg.find("f") is cg.find_all("f")[-1]
        assert len(cg.function_asts("f")) == 2

    def test_call_to_redefined_name_fans_out(self):
        cg = self._graph()
        caller = cg.find("caller")
        succ = set(cg.successors(caller))
        assert set(cg.find_all("f")) <= succ

    def test_each_variant_body_attributes_to_its_own_node(self):
        cg = self._graph()
        early, late = cg.find_all("f")
        early_succ = {n.name for n in cg.successors(early)}
        late_succ = {n.name for n in cg.successors(late)}
        assert "early_helper" in early_succ
        assert "early_helper" not in late_succ
        assert "late_helper" in late_succ

    def test_taint_summary_goes_conservative_on_variants(self):
        from core.analysis.taint_summaries import _compute_one_summary
        cg = self._graph()
        s = _compute_one_summary(cg, "f", {})
        assert s.summary_unknown
        assert "variant" in (s.summary_unknown_reason or "")
