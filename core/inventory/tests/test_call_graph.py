"""Tests for :mod:`core.inventory.call_graph`.

The call-graph extractor sits between the AST and the resolver.
Tests pin the data shape — broken extraction breaks reachability
verdicts silently, so the data layer needs explicit coverage.
"""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    INDIRECTION_BRACKET_DISPATCH,
    INDIRECTION_DUNDER_IMPORT,
    INDIRECTION_GETATTR,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_WILDCARD_IMPORT,
    FileCallGraph,
    extract_call_graph_python,
)

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def test_plain_import():
    g = extract_call_graph_python("import os\n")
    assert g.imports == {"os": "os"}


def test_dotted_import_binds_first_component():
    """``import os.path`` binds ``os`` (Python's import semantics);
    later use is ``os.path.join``."""
    g = extract_call_graph_python("import os.path\n")
    assert g.imports == {"os": "os"}


def test_aliased_import():
    g = extract_call_graph_python("import os.path as p\n")
    assert g.imports == {"p": "os.path"}


def test_from_import():
    g = extract_call_graph_python("from os.path import join\n")
    assert g.imports == {"join": "os.path.join"}


def test_from_import_aliased():
    g = extract_call_graph_python("from os.path import join as j\n")
    assert g.imports == {"j": "os.path.join"}


def test_from_import_multiple():
    g = extract_call_graph_python(
        "from os.path import join, dirname, basename\n",
    )
    assert g.imports == {
        "join": "os.path.join",
        "dirname": "os.path.dirname",
        "basename": "os.path.basename",
    }


def test_wildcard_import_flagged_not_mapped():
    g = extract_call_graph_python("from os.path import *\n")
    assert g.imports == {}
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_relative_import_skipped():
    """``from . import x`` isn't qualifiable without the package
    root — skipped from the import map and from the resolver."""
    g = extract_call_graph_python("from . import sibling\n")
    assert g.imports == {}


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_bare_call_recorded():
    g = extract_call_graph_python("from os.path import join\njoin('a', 'b')\n")
    assert any(c.chain == ["join"] for c in g.calls)


def test_attribute_chain_recorded():
    g = extract_call_graph_python("import os.path\nos.path.join('a', 'b')\n")
    assert any(c.chain == ["os", "path", "join"] for c in g.calls)


def test_caller_function_tracked():
    g = extract_call_graph_python(
        "def outer():\n"
        "    inner()\n"
    )
    inner = [c for c in g.calls if c.chain == ["inner"]]
    assert len(inner) == 1
    assert inner[0].caller == "outer"


def test_caller_innermost_function_wins():
    """Nested functions: the call's caller is the innermost
    enclosing function."""
    g = extract_call_graph_python(
        "def outer():\n"
        "    def inner():\n"
        "        target()\n"
        "    inner()\n"
    )
    target_call = [c for c in g.calls if c.chain == ["target"]]
    assert target_call[0].caller == "inner"


def test_module_level_call_has_no_caller():
    g = extract_call_graph_python("foo()\n")
    foo = [c for c in g.calls if c.chain == ["foo"]]
    assert foo[0].caller is None


def test_method_call_records_chain():
    g = extract_call_graph_python(
        "obj = something()\nobj.method()\n",
    )
    method_calls = [c for c in g.calls if c.chain == ["obj", "method"]]
    assert len(method_calls) == 1


def test_lambda_call_not_recorded():
    """``(lambda x: x)()`` has no qualified callee — skipped."""
    g = extract_call_graph_python("(lambda x: x)(1)\n")
    # The wrapped lambda call itself shouldn't appear in the chain;
    # there are no name-shaped callees here.
    assert all(c.chain != [] for c in g.calls)


def test_returned_function_call_not_recorded():
    """``f()()`` — the outer call has no qualified name."""
    g = extract_call_graph_python(
        "def f():\n    return lambda: None\nf()()\n"
    )
    # Inner ``f()`` recorded, outer call (with Call as func) skipped.
    assert any(c.chain == ["f"] for c in g.calls)


def test_call_line_numbers():
    g = extract_call_graph_python(
        "import os\n"
        "\n"
        "os.getcwd()\n"
    )
    osg = [c for c in g.calls if c.chain == ["os", "getcwd"]]
    assert osg[0].line == 3


# ---------------------------------------------------------------------------
# Indirection flags
# ---------------------------------------------------------------------------


def test_getattr_string_dispatch_flagged():
    g = extract_call_graph_python(
        "import os\n"
        "getattr(os, 'getcwd')()\n"
    )
    assert INDIRECTION_GETATTR in g.indirection


def test_getattr_aliased_via_import_flagged():
    """``from builtins import getattr as g; g(obj, "x")()`` — the
    alias resolves to ``builtins.getattr``. Without alias resolution
    a project that does this (lint workaround, deobfuscation,
    pattern-hiding) would slip past the masking signal."""
    from core.inventory.call_graph import INDIRECTION_GETATTR_OPAQUE
    g = extract_call_graph_python(
        "from builtins import getattr as g\n"
        "def f(obj, attr):\n"
        "    g(obj, attr)()\n"
        "    g(obj, 'literal')()\n"
    )
    assert INDIRECTION_GETATTR in g.indirection         # literal path
    assert "literal" in g.getattr_targets
    assert INDIRECTION_GETATTR_OPAQUE in g.indirection  # opaque path


def test_getattr_dotted_builtins_flagged():
    """``import builtins; builtins.getattr(obj, "x")``"""
    from core.inventory.call_graph import INDIRECTION_GETATTR_OPAQUE
    g = extract_call_graph_python(
        "import builtins\n"
        "def f(obj, attr):\n"
        "    builtins.getattr(obj, attr)()\n"
        "    builtins.getattr(obj, 'foo')()\n"
    )
    assert INDIRECTION_GETATTR in g.indirection
    assert "foo" in g.getattr_targets
    assert INDIRECTION_GETATTR_OPAQUE in g.indirection


def test_bracket_dispatch_flagged():
    """``HANDLERS[key]()`` dict-of-functions dispatch in Python — same
    opaque-dispatch semantic as JS ``obj[key]()``. Pre-fix the
    Subscript callee was returned-early and no flag fired; a function
    only reachable via this dispatch could be wrongly claimed dead."""
    g = extract_call_graph_python(
        "HANDLERS = {'a': handler_a, 'b': handler_b}\n"
        "def f(key):\n"
        "    HANDLERS[key]()\n"
    )
    assert INDIRECTION_BRACKET_DISPATCH in g.indirection


def test_getattr_with_non_constant_flagged_opaque():
    """``getattr(obj, attr)`` with a variable second arg IS the
    truly-opaque dispatch case — the resolver can't narrow to a
    specific tail name, so any target in the file's reverse closure
    could be the runtime callee. Flagged distinctly from literal-
    string ``getattr`` so masking can be applied per-target precisely
    in the literal case but blanket in the opaque case."""
    from core.inventory.call_graph import INDIRECTION_GETATTR_OPAQUE
    g = extract_call_graph_python(
        "def f(obj, attr):\n"
        "    getattr(obj, attr)()\n"
    )
    # The literal-string flag stays off (no string name captured).
    assert INDIRECTION_GETATTR not in g.indirection
    # The opaque variant fires.
    assert INDIRECTION_GETATTR_OPAQUE in g.indirection
    assert not g.getattr_targets  # no literal name to record


def test_importlib_import_module_flagged():
    g = extract_call_graph_python(
        "import importlib\n"
        "importlib.import_module('os.path')\n"
    )
    assert INDIRECTION_IMPORTLIB in g.indirection


def test_importlib_bare_import_module_flagged():
    """``from importlib import import_module`` then bare call."""
    g = extract_call_graph_python(
        "from importlib import import_module\n"
        "import_module('os.path')\n"
    )
    assert INDIRECTION_IMPORTLIB in g.indirection


def test_dunder_import_flagged():
    g = extract_call_graph_python("__import__('os.path')\n")
    assert INDIRECTION_DUNDER_IMPORT in g.indirection


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty_graph():
    """A malformed file shouldn't blow up the inventory build."""
    g = extract_call_graph_python("def broken(:\n  pass")
    assert g == FileCallGraph()


def test_round_trip_through_dict():
    """The extractor's output must round-trip cleanly through
    JSON-shaped dicts so the inventory artefact stays loadable."""
    g = extract_call_graph_python(
        "import os.path as p\n"
        "from sys import exit\n"
        "p.join('a')\n"
        "getattr(p, 'dirname')('/x')\n"
    )
    d = g.to_dict()
    g2 = FileCallGraph.from_dict(d)
    assert g2.imports == g.imports
    assert {tuple(c.chain) for c in g2.calls} == {
        tuple(c.chain) for c in g.calls
    }
    assert g2.indirection == g.indirection


def test_pep695_type_param_bound_call_captured():
    """PEP 695 (Python 3.12+): ``def f[T: get_base()](...)`` —
    the bound call evaluates in the enclosing scope and must be
    captured. Regression guard against ``type_params`` being
    missing from the function-def explicit child walk."""
    import sys
    if sys.version_info < (3, 12):
        import pytest
        pytest.skip("PEP 695 syntax requires Python 3.12+")
    from core.inventory.call_graph import extract_call_graph_python
    src = "def f[T: get_base()](x: T) -> T:\n    return x\n"
    g = extract_call_graph_python(src)
    chains = [tuple(c.chain) for c in g.calls]
    assert ("get_base",) in chains, (
        f"PEP 695 type-bound call missed; saw chains={chains}"
    )


class TestLoadCallGraphs:
    """Project-level loader consumed by the audit orchestrator
    (IRIS bypass analysis, structural detectors)."""

    def _tree(self, tmp_path):
        (tmp_path / "pkg").mkdir()
        (tmp_path / "pkg" / "a.py").write_text(
            "def f():\n    g()\n\ndef g():\n    pass\n", encoding="utf-8")
        (tmp_path / "main.py").write_text(
            "from pkg.a import f\nf()\n", encoding="utf-8")
        (tmp_path / "node_modules").mkdir()
        (tmp_path / "node_modules" / "dep.py").write_text(
            "def hidden():\n    pass\n", encoding="utf-8")
        (tmp_path / "README.md").write_text("docs", encoding="utf-8")
        return tmp_path

    def test_walk_mode_extracts_supported_files(self, tmp_path):
        from core.inventory.call_graph import load_call_graphs

        graphs = load_call_graphs(self._tree(tmp_path))
        assert set(graphs) == {"pkg/a.py", "main.py"}
        assert any(c.chain == ["g"] for c in graphs["pkg/a.py"].calls)

    def test_checklist_mode_keys_by_checklist_path(self, tmp_path):
        from core.inventory.call_graph import load_call_graphs

        self._tree(tmp_path)
        checklist = {"files": [{"path": "pkg/a.py"},
                               {"path": "missing.py"}]}
        graphs = load_call_graphs(tmp_path, checklist)
        assert set(graphs) == {"pkg/a.py"}

    def test_compositional_analyzer_accepts_result(self, tmp_path):
        """The orchestrator feeds the result straight into
        CompositionalAnalyzer — the two shapes must stay compatible."""
        from core.inventory.call_graph import load_call_graphs
        from core.iris import CompositionalAnalyzer

        graphs = load_call_graphs(self._tree(tmp_path))
        analyzer = CompositionalAnalyzer(graphs)
        assert analyzer.all_funcs

    def test_max_files_cap(self, tmp_path):
        from core.inventory.call_graph import load_call_graphs

        graphs = load_call_graphs(self._tree(tmp_path), max_files=1)
        assert len(graphs) == 1

    def test_oversized_file_skipped(self, tmp_path):
        from core.inventory.call_graph import load_call_graphs

        self._tree(tmp_path)
        graphs = load_call_graphs(tmp_path, max_bytes=10)
        assert graphs == {}


class TestLoaderLanguageDispatch:
    """The loader must honour the checklist's content-refined language
    field and route C++-marker headers to the cpp grammar; pure-suffix
    dispatch degraded them through the C grammar (qualified chains
    lost) and skipped .hxx entirely."""

    CPP_HEADER = (
        "namespace helper { void boot() { run(); } }\n"
        "struct X { void go() { helper::boot(); } };\n"
    )

    def test_checklist_language_overrides_suffix(self, tmp_path):
        pytest.importorskip("tree_sitter_cpp")
        from core.inventory.call_graph import load_call_graphs

        (tmp_path / "engine.h").write_text(self.CPP_HEADER)
        graphs = load_call_graphs(
            tmp_path,
            checklist={"files": [{"path": "engine.h", "language": "cpp"}]},
        )
        assert any(c.chain == ["helper", "boot"]
                   for c in graphs["engine.h"].calls)

    def test_walk_mode_refines_cpp_headers_by_content(self, tmp_path):
        pytest.importorskip("tree_sitter_cpp")
        from core.inventory.call_graph import load_call_graphs

        (tmp_path / "engine.h").write_text(self.CPP_HEADER)
        graphs = load_call_graphs(tmp_path)
        assert any(c.chain == ["helper", "boot"]
                   for c in graphs["engine.h"].calls)

    def test_plain_c_header_still_uses_c_grammar(self, tmp_path):
        pytest.importorskip("tree_sitter_c")
        from core.inventory.call_graph import load_call_graphs

        (tmp_path / "util.h").write_text(
            "static inline int add(int a, int b) { return helper(a, b); }\n"
        )
        graphs = load_call_graphs(tmp_path)
        assert any(c.chain == ["helper"] for c in graphs["util.h"].calls)

    def test_hxx_extension_recognised(self, tmp_path):
        pytest.importorskip("tree_sitter_cpp")
        from core.inventory.call_graph import load_call_graphs

        (tmp_path / "other.hxx").write_text(
            "namespace h2 { void b2() { r2(); } }\n"
        )
        graphs = load_call_graphs(tmp_path)
        assert "other.hxx" in graphs


class TestModuleExportContract:
    """``__all__`` must stay complete — it previously sat mid-file and
    silently omitted every extractor defined after it (scala / kotlin /
    swift) plus load_call_graphs."""

    def test_all_covers_every_public_extractor(self):
        from core.inventory import call_graph as cg

        public_extractors = {
            name for name in vars(cg)
            if name.startswith("extract_call_graph_")
        }
        assert public_extractors <= set(cg.__all__)
        assert "load_call_graphs" in cg.__all__

    def test_all_names_resolve(self):
        from core.inventory import call_graph as cg

        missing = [n for n in cg.__all__ if not hasattr(cg, n)]
        assert not missing


class TestChecklistPathContainment:
    def test_absolute_and_escaping_paths_skipped(self, tmp_path):
        # Run artifacts are data, not authority: an absolute or
        # parent-escaping path in a checklist must not read
        # out-of-tree content into extraction (Path join with an
        # absolute rhs REPLACES the root).
        from core.inventory.call_graph import iter_call_graph_candidates

        (tmp_path / "ok.py").write_text("def f():\n    pass\n")
        outside = tmp_path.parent / "outside.py"
        checklist = {"files": [
            {"path": "ok.py", "language": "python"},
            {"path": str(outside), "language": "python"},
            {"path": "../outside.py", "language": "python"},
        ]}
        cands = iter_call_graph_candidates(tmp_path, checklist)
        rels = [rel for rel, _, _ in cands]
        assert rels == ["ok.py"]


# ---------------------------------------------------------------------------
# Literal dynamic-dispatch facts (dispatch_tables / subscript_calls /
# getattr_calls)
# ---------------------------------------------------------------------------


def test_dispatch_table_harvested():
    g = extract_call_graph_python(
        "def handle_a():\n    pass\n"
        "def handle_b():\n    pass\n"
        "HANDLERS = {'a': handle_a, 'b': mod.handle_b}\n"
    )
    assert g.dispatch_tables == {
        "HANDLERS": [["handle_a"], ["mod", "handle_b"]],
    }


def test_dispatch_table_under_module_level_if():
    """A table bound under a module-level ``if`` still binds the
    module namespace at import — it must be harvested."""
    g = extract_call_graph_python(
        "if FLAG:\n    TABLE = {'x': fx}\n"
    )
    assert g.dispatch_tables == {"TABLE": [["fx"]]}


def test_dispatch_table_not_harvested_inside_function_or_class():
    g = extract_call_graph_python(
        "def f():\n    LOCAL = {'a': ha}\n"
        "class C:\n    CLS = {'b': hb}\n"
    )
    assert g.dispatch_tables == {}


def test_dispatch_table_non_chain_values_skipped():
    """Literal / lambda / call values have no name to join on —
    skipped individually, chain values kept."""
    g = extract_call_graph_python(
        "T = {'a': ha, 'b': 42, 'c': lambda: 1, 'd': make()}\n"
    )
    assert g.dispatch_tables == {"T": [["ha"]]}


def test_dispatch_table_later_assignment_wins():
    g = extract_call_graph_python(
        "T = {'a': ha}\nT = {'b': hb}\n"
    )
    assert g.dispatch_tables == {"T": [["hb"]]}


def test_dispatch_table_value_cap():
    from core.inventory.call_graph import _DISPATCH_TABLE_VALUE_CAP
    entries = ", ".join(
        f"'k{i}': f{i}" for i in range(_DISPATCH_TABLE_VALUE_CAP + 5)
    )
    g = extract_call_graph_python(f"T = {{{entries}}}\n")
    assert len(g.dispatch_tables["T"]) == _DISPATCH_TABLE_VALUE_CAP
    assert g.dispatch_tables["T"][0] == ["f0"]


def test_subscript_call_records_root_and_caller():
    g = extract_call_graph_python(
        "def dispatch(k):\n    HANDLERS[k]()\n"
    )
    assert len(g.subscript_calls) == 1
    site = g.subscript_calls[0]
    assert site.chain == ["HANDLERS"]
    assert site.caller == "dispatch"
    assert site.line == 2
    assert INDIRECTION_BRACKET_DISPATCH in g.indirection


def test_subscript_call_attribute_root():
    g = extract_call_graph_python("registry.table[k]()\n")
    assert [c.chain for c in g.subscript_calls] == [["registry", "table"]]
    assert g.subscript_calls[0].caller is None


def test_subscript_call_rootless_not_recorded():
    """``f()[0](...)`` has no static root — flag only, no site."""
    g = extract_call_graph_python("f()[0]()\n")
    assert g.subscript_calls == []
    assert INDIRECTION_BRACKET_DISPATCH in g.indirection


def test_getattr_call_site_literal():
    g = extract_call_graph_python(
        "def go(obj):\n    getattr(obj, 'run')()\n"
    )
    assert g.getattr_calls == [(2, "go", "run")]


def test_getattr_call_site_opaque():
    g = extract_call_graph_python(
        "def go(obj, name):\n    getattr(obj, name)()\n"
    )
    assert g.getattr_calls == [(2, "go", None)]


def test_dispatch_facts_round_trip():
    g = extract_call_graph_python(
        "T = {'a': ha}\n"
        "def d(k, obj):\n"
        "    T[k]()\n"
        "    getattr(obj, 'ha')()\n"
    )
    g2 = FileCallGraph.from_dict(g.to_dict())
    assert g2.dispatch_tables == g.dispatch_tables
    assert [(c.line, c.chain, c.caller) for c in g2.subscript_calls] == [
        (c.line, c.chain, c.caller) for c in g.subscript_calls
    ]
    assert g2.getattr_calls == g.getattr_calls


def test_dispatch_facts_absent_from_old_inventories():
    """Inventories written before these facts existed lack the keys —
    from_dict must default all three to empty."""
    g = FileCallGraph.from_dict({"imports": {}, "calls": []})
    assert g.dispatch_tables == {}
    assert g.subscript_calls == []
    assert g.getattr_calls == []


def test_dispatch_facts_omitted_from_dict_when_empty():
    d = extract_call_graph_python("x = 1\n").to_dict()
    assert "dispatch_tables" not in d
    assert "subscript_calls" not in d
    assert "getattr_calls" not in d

# ---------------------------------------------------------------------------
# Registration-shape facts (decorator_args / constructed_objects /
# string_ref_calls)
# ---------------------------------------------------------------------------


def test_decorator_args_aligned_with_chains():
    g = extract_call_graph_python(
        "@app.route('/users/<int:uid>', methods=['GET', 'POST'])\n"
        "@staticmethod\n"
        "def user(uid):\n    pass\n"
    )
    assert len(g.decorated_functions) == 1
    df = g.decorated_functions[0]
    assert df.decorators == [["app", "route"], ["staticmethod"]]
    assert len(df.decorator_args) == 2
    route_args, bare = df.decorator_args
    assert bare is None
    assert route_args is not None
    assert route_args.arg_count == 1
    assert route_args.string_args == [(0, "/users/<int:uid>")]
    assert route_args.kw_string_lists == {"methods": ["GET", "POST"]}


def test_decorator_args_zero_arg_call_distinct_from_bare():
    """``@app.route()`` is a CALL with no arguments — its facts entry
    exists (arg_count 0) while ``@app.route`` gets None. Registration
    consumers need the distinction."""
    g = extract_call_graph_python(
        "@app.route()\ndef a():\n    pass\n"
        "@app.route\ndef b():\n    pass\n"
    )
    a, b = g.decorated_functions
    assert a.decorator_args[0] is not None
    assert a.decorator_args[0].arg_count == 0
    assert b.decorator_args[0] is None


def test_decorator_args_dynamic_pattern_not_recorded_as_literal():
    g = extract_call_graph_python(
        "@app.route(BASE + '/x')\ndef d():\n    pass\n"
    )
    args = g.decorated_functions[0].decorator_args[0]
    assert args is not None
    assert args.arg_count == 1
    assert args.string_args == []


def test_decorator_args_mixed_method_list_not_recorded():
    """A partially-literal list would misstate the fact — dropped
    whole."""
    g = extract_call_graph_python(
        "@app.route('/x', methods=['GET', VERB])\ndef d():\n    pass\n"
    )
    args = g.decorated_functions[0].decorator_args[0]
    assert args is not None
    assert args.kw_string_lists == {}


def test_constructed_object_recorded_with_kwargs():
    g = extract_call_graph_python(
        "from fastapi import APIRouter\n"
        "router = APIRouter(prefix='/v1')\n"
    )
    co = g.constructed_objects["router"]
    assert co.chain == ["APIRouter"]
    assert co.line == 2
    assert co.args.kw_strings == {"prefix": "/v1"}


def test_constructed_object_annotated_assignment():
    g = extract_call_graph_python(
        "app: Flask = Flask(__name__)\n"
    )
    assert g.constructed_objects["app"].chain == ["Flask"]


def test_constructed_object_module_scope_only():
    g = extract_call_graph_python(
        "def make():\n    app = Flask(__name__)\n"
        "class C:\n    app = Flask(__name__)\n"
    )
    assert g.constructed_objects == {}


def test_constructed_object_non_call_values_skipped():
    g = extract_call_graph_python(
        "a = 1\nb = other\nc = [Flask(__name__)]\nd = f()()\n"
    )
    assert g.constructed_objects == {}


def test_constructed_object_later_assignment_wins():
    g = extract_call_graph_python(
        "app = Flask(__name__)\napp = Quart(__name__)\n"
    )
    assert g.constructed_objects["app"].chain == ["Quart"]


def test_constructed_object_cap():
    from core.inventory.call_graph import _CONSTRUCTED_OBJECT_CAP
    src = "".join(
        f"o{i} = C{i}()\n" for i in range(_CONSTRUCTED_OBJECT_CAP + 5)
    )
    g = extract_call_graph_python(src)
    assert len(g.constructed_objects) == _CONSTRUCTED_OBJECT_CAP
    # Overwrites of already-recorded names still land past the cap.
    g2 = extract_call_graph_python(src + "o0 = D0()\n")
    assert g2.constructed_objects["o0"].chain == ["D0"]


def test_string_ref_call_positional_ref():
    g = extract_call_graph_python(
        "urlpatterns = [path('users/<int:pk>/', views.detail,"
        " name='detail')]\n"
    )
    assert len(g.string_ref_calls) == 1
    site = g.string_ref_calls[0]
    assert site.chain == ["path"]
    assert site.caller is None
    assert site.args.string_args == [(0, "users/<int:pk>/")]
    assert site.args.ref_args == [(1, ["views", "detail"])]
    assert site.args.kw_strings == {"name": "detail"}


def test_string_ref_call_kw_ref_and_call_ref():
    g = extract_call_graph_python(
        "app.add_url_rule('/a', view_func=handler)\n"
        "app.add_url_rule('/b', view_func=Views.as_view('b'))\n"
        "path('c/', views.ItemView.as_view())\n"
    )
    a, b, c = g.string_ref_calls
    assert a.args.kw_refs == {"view_func": ["handler"]}
    assert b.args.kw_call_refs == {"view_func": ["Views", "as_view"]}
    assert c.args.call_ref_args == [(1, ["views", "ItemView", "as_view"])]


def test_string_ref_call_requires_string_first_arg_and_ref():
    g = extract_call_graph_python(
        "f(x, 'not-first')\n"           # string not at position 0
        "g('only-strings', 'again')\n"  # no reference-shaped argument
        "h(rule, handler)\n"            # no literal string at all
    )
    assert g.string_ref_calls == []


def test_string_ref_call_records_enclosing_caller():
    g = extract_call_graph_python(
        "def setup(app):\n    app.add_url_rule('/x', view_func=h)\n"
    )
    assert g.string_ref_calls[0].caller == "setup"
    assert g.string_ref_calls[0].line == 2


def test_string_ref_call_per_file_cap():
    from core.inventory.call_graph import _STRING_REF_CALL_CAP
    src = "".join(
        f"path('r{i}/', views.v{i})\n"
        for i in range(_STRING_REF_CALL_CAP + 5)
    )
    g = extract_call_graph_python(src)
    assert len(g.string_ref_calls) == _STRING_REF_CALL_CAP


def test_argument_fact_string_cap_degrades_to_dynamic():
    from core.inventory.call_graph import _ARG_STRING_CAP
    big = "x" * (_ARG_STRING_CAP + 1)
    g = extract_call_graph_python(
        f"@app.route('{big}')\ndef d():\n    pass\n"
    )
    args = g.decorated_functions[0].decorator_args[0]
    assert args is not None
    assert args.arg_count == 1
    assert args.string_args == []


def test_registration_facts_round_trip():
    g = extract_call_graph_python(
        "app = Flask(__name__)\n"
        "@app.route('/x', methods=['GET'])\n"
        "def x():\n    pass\n"
        "app.add_url_rule('/y', view_func=y)\n"
    )
    g2 = FileCallGraph.from_dict(g.to_dict())
    assert g2.to_dict() == g.to_dict()
    assert g2.decorated_functions[0].decorator_args[0].string_args == [
        (0, "/x"),
    ]
    assert g2.constructed_objects["app"].chain == ["Flask"]
    assert g2.string_ref_calls[0].args.kw_refs == {"view_func": ["y"]}


def test_registration_facts_absent_from_old_inventories():
    g = FileCallGraph.from_dict({
        "imports": {},
        "calls": [],
        "decorated_functions": [
            {"name": "f", "line": 1, "decorators": [["app", "route"]]},
        ],
    })
    assert g.constructed_objects == {}
    assert g.string_ref_calls == []
    # Pre-fact decorated functions default every args slot to None,
    # index-aligned with the chains.
    assert g.decorated_functions[0].decorator_args == [None]


def test_registration_facts_misaligned_args_dropped():
    """A hand-corrupted artifact whose decorator_args length disagrees
    with decorators must not desynchronise the alignment — args reset
    to all-None."""
    g = FileCallGraph.from_dict({
        "decorated_functions": [
            {"name": "f", "line": 1,
             "decorators": [["a"], ["b"]],
             "decorator_args": [{"arg_count": 1}]},
        ],
    })
    assert g.decorated_functions[0].decorator_args == [None, None]


def test_registration_facts_omitted_from_dict_when_empty():
    d = extract_call_graph_python("x = 1\n").to_dict()
    assert "constructed_objects" not in d
    assert "string_ref_calls" not in d
    assert all("decorator_args" not in df
               for df in d["decorated_functions"])


class TestDerivedFileCap:
    """max_files=None derivation: checklist mode covers the whole
    checklist up to _CHECKLIST_MAX_FILES; walk mode keeps 2000; an
    explicit int is honoured verbatim. Two-direction pins per the
    churn-prone-limits doctrine."""

    @staticmethod
    def _many_files(tmp_path, n):
        files = []
        for i in range(n):
            p = tmp_path / f"f{i}.c"
            p.write_text(f"int fn{i}(void) {{ return {i}; }}\n")
            files.append({"path": p.name})
        return {"files": files}

    def test_derivation_covers_beyond_walk_default(self):
        # The headline regression: a kernel-scale checklist must
        # derive its own size, not the 2000 walk default (pinned on
        # the derivation helper directly — minting 6k files to prove
        # it via extraction is what made the previous form vacuous).
        import core.inventory.call_graph as cg
        ck = {"files": [{"path": f"f{i}.c"} for i in range(6002)]}
        assert cg._derive_max_files(ck) == 6002

    def test_derivation_directions(self):
        import core.inventory.call_graph as cg
        assert cg._derive_max_files(None) == 2000        # bare walk
        assert cg._derive_max_files({"files": []}) == 2000
        big = {"files": [{"path": "x"}] * (cg._CHECKLIST_MAX_FILES + 5)}
        assert cg._derive_max_files(big) == cg._CHECKLIST_MAX_FILES

    def test_checklist_mode_ceiling_binds(self, tmp_path, monkeypatch):
        import core.inventory.call_graph as cg
        monkeypatch.setattr(cg, "_CHECKLIST_MAX_FILES", 10)
        checklist = self._many_files(tmp_path, 15)
        graphs = cg.load_call_graphs(tmp_path, checklist)
        assert len(graphs) == 10  # ceiling respected

    def test_small_checklist_fully_extracted(self, tmp_path):
        # Candidates never exceed the checklist, so the derived cap
        # (floored at 2000) can never truncate a small checklist.
        import core.inventory.call_graph as cg
        checklist = self._many_files(tmp_path, 3)
        graphs = cg.load_call_graphs(tmp_path, checklist)
        assert len(graphs) == 3

    def test_explicit_max_files_honoured_verbatim(self, tmp_path):
        import core.inventory.call_graph as cg
        checklist = self._many_files(tmp_path, 5)
        graphs = cg.load_call_graphs(tmp_path, checklist, max_files=2)
        assert len(graphs) == 2
