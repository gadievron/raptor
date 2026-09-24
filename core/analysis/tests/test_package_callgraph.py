"""Tests for :mod:`core.analysis.package_callgraph`.

The fixture package (``fixtures/package_callgraph/demo_pkg``) carries
one call site per resolution class; the inventory records are built
with the REAL inventory extractors (``PythonExtractor`` +
``extract_call_graph_python``) so the tests pin the whole
facts → resolution → edge chain, not a hand-crafted input shape.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.analysis.package_callgraph import (
    KIND_CALL,
    KIND_CONSTRUCTOR,
    KIND_DECORATOR,
    KIND_DICT_DISPATCH,
    KIND_GETATTR_DISPATCH,
    KIND_METHOD_CALL,
    MODULE_NODE_NAME,
    REASON_DISPATCH_TABLE_UNKNOWN,
    REASON_DYNAMIC_ATTRIBUTE,
    REASON_GETATTR_FANOUT_CAP,
    REASON_GETATTR_OPAQUE,
    REASON_UNKNOWN_NAME,
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_CONVENTION,
    TIER_RESOLVED_STATIC,
    PackageCallGraph,
    build_package_callgraph,
    load_package_callgraph,
)
from core.inventory.call_graph import extract_call_graph_python
from core.inventory.extractors import PythonExtractor

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "package_callgraph"


def _record_for(rel_path: str, content: str) -> dict:
    """One inventory file record, built with the real extractors —
    the same shape the inventory builder writes."""
    items = [i.to_dict() for i in PythonExtractor().extract(rel_path, content)]
    return {
        "path": rel_path,
        "language": "python",
        "items": items,
        "call_graph": extract_call_graph_python(content).to_dict(),
    }


def _build_inventory(root: Path) -> dict:
    files = []
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root).as_posix()
        files.append(_record_for(rel, path.read_text(encoding="utf-8")))
    return {"files": files}


@pytest.fixture(scope="module")
def graph() -> PackageCallGraph:
    return build_package_callgraph(_build_inventory(FIXTURE_ROOT))


def _node(g: PackageCallGraph, file_path: str, name: str):
    matches = [n for n in g.nodes
               if n.file_path == file_path and n.name == name]
    assert len(matches) == 1, (
        f"expected exactly one node {file_path}::{name}, got {matches}"
    )
    return matches[0]


def _edges(g: PackageCallGraph, src, dst):
    return [e for e in g.callees_of(src.node_id) if e.dst == dst.node_id]


def _the_edge(g: PackageCallGraph, src, dst):
    edges = _edges(g, src, dst)
    assert len(edges) == 1, (
        f"expected exactly one edge {src.name} -> {dst.name}, got {edges}"
    )
    return edges[0]


# ---------------------------------------------------------------------------
# Resolution classes — exact expected edges + tiers
# ---------------------------------------------------------------------------


class TestStaticImportResolution:
    def test_plain_import_dotted_call(self, graph):
        """``import demo_pkg.helpers`` + ``demo_pkg.helpers.top_helper()``."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_plain_import"),
            _node(graph, "demo_pkg/helpers.py", "top_helper"),
        )
        assert e.tier == TIER_RESOLVED_STATIC
        assert e.kind == KIND_CALL

    def test_aliased_from_import(self, graph):
        """``from demo_pkg.helpers import top_helper as th`` + ``th()``."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_aliased_import"),
            _node(graph, "demo_pkg/helpers.py", "top_helper"),
        )
        assert e.tier == TIER_RESOLVED_STATIC
        assert e.kind == KIND_CALL

    def test_relative_module_import(self, graph):
        """``from . import helpers`` + ``helpers.handle_a()``."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_relative_module"),
            _node(graph, "demo_pkg/helpers.py", "handle_a"),
        )
        assert e.tier == TIER_RESOLVED_STATIC

    def test_init_reexport(self, graph):
        """``from .sub import deep_fn`` resolves through
        ``sub/__init__.py``'s re-export to ``sub/impl.py``."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_reexport"),
            _node(graph, "demo_pkg/sub/impl.py", "deep_fn"),
        )
        assert e.tier == TIER_RESOLVED_STATIC

    def test_transitive_package_reexport(self, graph):
        """``from demo_pkg import deep_fn`` resolves through TWO
        ``__init__`` re-export hops (fixed-point iteration)."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_package_reexport"),
            _node(graph, "demo_pkg/sub/impl.py", "deep_fn"),
        )
        assert e.tier == TIER_RESOLVED_STATIC

    def test_same_file_bare_call(self, graph):
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/helpers.py", "top_helper"),
            _node(graph, "demo_pkg/helpers.py", "leaf"),
        )
        assert e.tier == TIER_RESOLVED_STATIC
        assert e.kind == KIND_CALL

    def test_nested_def_resolves_locally_but_is_not_exported(self, graph):
        """``inner`` (nested in ``outer``) gets a same-file edge but
        no package-qualified export."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/helpers.py", "outer"),
            _node(graph, "demo_pkg/helpers.py", "inner"),
        )
        assert e.tier == TIER_RESOLVED_STATIC
        # No OTHER file can reach ``inner`` — nothing imports it, and
        # a synthetic import would not resolve (not exported). The
        # export exclusion is observable via callers: only ``outer``.
        inner = _node(graph, "demo_pkg/helpers.py", "inner")
        callers = {e.src for e in graph.callers_of(inner.node_id)}
        assert callers == {
            _node(graph, "demo_pkg/helpers.py", "outer").node_id,
        }

    def test_module_level_call_attributed_to_module_node(self, graph):
        """``BOOT = use_plain_import()`` at module scope."""
        module_node = _node(graph, "demo_pkg/consumer.py", MODULE_NODE_NAME)
        e = _the_edge(
            graph, module_node,
            _node(graph, "demo_pkg/consumer.py", "use_plain_import"),
        )
        assert e.tier == TIER_RESOLVED_STATIC


class TestMethodResolution:
    def test_self_method_on_own_class(self, graph):
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "User.run"),
            _node(graph, "demo_pkg/consumer.py", "User.local_method"),
        )
        # Convention even for a direct hit — the runtime receiver
        # may be a subclass override.
        assert e.tier == TIER_RESOLVED_CONVENTION
        assert e.kind == KIND_METHOD_CALL

    def test_self_method_inherited_across_modules(self, graph):
        """``self.greet()`` in ``User`` resolves onto imported
        ``Base`` (defined in another module). The same body's direct
        ``Base.greet(self)`` produces a SEPARATE static-tier edge —
        the tiers stay distinct edges rather than merging."""
        edges = _edges(
            graph,
            _node(graph, "demo_pkg/consumer.py", "User.run"),
            _node(graph, "demo_pkg/helpers.py", "Base.greet"),
        )
        assert {(e.tier, e.kind) for e in edges} == {
            (TIER_RESOLVED_CONVENTION, KIND_METHOD_CALL),
            (TIER_RESOLVED_STATIC, KIND_METHOD_CALL),
        }

    def test_direct_class_method_call(self, graph):
        """``Base.greet(self)`` — the imported class is named
        statically, so the edge is static-tier."""
        edges = _edges(
            graph,
            _node(graph, "demo_pkg/consumer.py", "User.run"),
            _node(graph, "demo_pkg/helpers.py", "Base.greet"),
        )
        tiers = {e.tier for e in edges}
        assert TIER_RESOLVED_STATIC in tiers

    def test_self_method_same_file(self, graph):
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/helpers.py", "Base.helper_method"),
            _node(graph, "demo_pkg/helpers.py", "Base.greet"),
        )
        assert e.tier == TIER_RESOLVED_CONVENTION

    def test_constructor_resolves_to_inherited_init(self, graph):
        """``User()`` — no ``__init__`` on ``User``; the bases walk
        finds ``Base.__init__`` in the other module."""
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "make_user"),
            _node(graph, "demo_pkg/helpers.py", "Base.__init__"),
        )
        assert e.tier == TIER_RESOLVED_CONVENTION
        assert e.kind == KIND_CONSTRUCTOR


class TestDecoratorResolution:
    def test_decorator_application_edge(self, graph):
        """``@my_deco`` runs at import — edge from the module node."""
        module_node = _node(graph, "demo_pkg/consumer.py", MODULE_NODE_NAME)
        e = _the_edge(
            graph, module_node,
            _node(graph, "demo_pkg/consumer.py", "my_deco"),
        )
        assert e.kind == KIND_DECORATOR
        assert e.tier == TIER_RESOLVED_STATIC

    def test_decorated_function_still_a_plain_callee(self, graph):
        """Calls TO a decorated function resolve like any other."""
        decorated = _node(graph, "demo_pkg/consumer.py", "decorated")
        assert decorated.kind == "function"


class TestDynamicHeuristics:
    def test_dict_dispatch_cross_module_table(self, graph):
        """``HANDLERS[key]()`` where the table is imported — edges to
        every table value, heuristic tier."""
        src = _node(graph, "demo_pkg/consumer.py", "use_dispatch")
        for target in ("handle_a", "handle_b"):
            e = _the_edge(
                graph, src, _node(graph, "demo_pkg/helpers.py", target),
            )
            assert e.tier == TIER_HEURISTIC_DYNAMIC
            assert e.kind == KIND_DICT_DISPATCH

    def test_getattr_literal_edge(self, graph):
        e = _the_edge(
            graph,
            _node(graph, "demo_pkg/consumer.py", "use_getattr"),
            _node(graph, "demo_pkg/helpers.py", "handle_b"),
        )
        assert e.tier == TIER_HEURISTIC_DYNAMIC
        assert e.kind == KIND_GETATTR_DISPATCH


class TestUnresolvedAndExternal:
    def test_unknown_bare_name_marked(self, graph):
        src = _node(graph, "demo_pkg/consumer.py", "unresolvable")
        marks = [u for u in graph.unresolved_calls
                 if u.caller == src.node_id]
        assert any(
            u.chain == ("callback",) and u.reason == REASON_UNKNOWN_NAME
            for u in marks
        )

    def test_dynamic_attribute_marked(self, graph):
        src = _node(graph, "demo_pkg/consumer.py", "unresolvable")
        marks = [u for u in graph.unresolved_calls
                 if u.caller == src.node_id]
        assert any(
            u.chain == ("obj", "mystery")
            and u.reason == REASON_DYNAMIC_ATTRIBUTE
            for u in marks
        )

    def test_external_call_recorded_not_unresolved(self, graph):
        src = _node(graph, "demo_pkg/consumer.py", "unresolvable")
        externals = [x for x in graph.external_calls
                     if x.caller == src.node_id]
        assert any(x.target == "os.path.join" for x in externals)
        assert not any(
            "os" in u.chain for u in graph.unresolved_calls
            if u.caller == src.node_id
        )

    def test_builtin_calls_counted_not_recorded(self, graph):
        """``getattr(...)`` itself is a builtin call — counted in
        stats, never an unresolved marker."""
        assert graph.stats.get("builtin_calls_skipped", 0) >= 1
        assert not any(
            u.chain == ("getattr",) for u in graph.unresolved_calls
        )


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


class TestQueries:
    def test_paths_found_across_modules(self, graph):
        src = _node(graph, "demo_pkg/consumer.py", "use_plain_import")
        dst = _node(graph, "demo_pkg/helpers.py", "leaf")
        result = graph.paths_found(src.node_id, dst.node_id)
        assert result.paths, "expected at least one path"
        top_helper = _node(graph, "demo_pkg/helpers.py", "top_helper")
        assert result.paths[0] == (
            src.node_id, top_helper.node_id, dst.node_id,
        )

    def test_paths_found_unknown_node(self, graph):
        result = graph.paths_found("nope::x@1", "also::nope@2")
        assert result.paths == ()
        assert result.budget_exhausted is False

    def test_paths_found_budget_marks_exhaustion(self, graph):
        src = _node(graph, "demo_pkg/consumer.py", "use_plain_import")
        dst = _node(graph, "demo_pkg/helpers.py", "leaf")
        result = graph.paths_found(src.node_id, dst.node_id,
                                   max_expansions=1)
        assert result.budget_exhausted is True

    def test_no_refutation_surface(self, graph):
        """Doctrine: origination / prioritization only — no
        absence-of-path query may exist on the API."""
        for forbidden in ("no_path_exists", "is_dead", "not_called",
                          "unreachable"):
            assert not hasattr(graph, forbidden)

    def test_callers_of(self, graph):
        top_helper = _node(graph, "demo_pkg/helpers.py", "top_helper")
        caller_ids = {e.src for e in graph.callers_of(top_helper.node_id)}
        assert _node(
            graph, "demo_pkg/consumer.py", "use_plain_import",
        ).node_id in caller_ids
        assert _node(
            graph, "demo_pkg/consumer.py", "use_aliased_import",
        ).node_id in caller_ids

    def test_nodes_by_name_matches_methods_bare(self, graph):
        names = {n.name for n in graph.nodes_by_name("greet")}
        assert names == {"Base.greet"}

    def test_qual_name_is_dotted_package_scope(self, graph):
        """``qual_name`` is the dotted form downstream consumers key
        off — module + module-local name."""
        greet = _node(graph, "demo_pkg/helpers.py", "Base.greet")
        assert greet.qual_name == "demo_pkg.helpers.Base.greet"
        module_node = _node(graph, "demo_pkg/helpers.py", MODULE_NODE_NAME)
        assert module_node.qual_name == "demo_pkg.helpers.<module>"


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_round_trip(self, graph):
        g2 = PackageCallGraph.from_dict(graph.to_dict())
        assert g2.nodes == graph.nodes
        assert g2.edges == graph.edges
        assert g2.unresolved_calls == graph.unresolved_calls
        assert g2.external_calls == graph.external_calls
        assert g2.caps_hit == graph.caps_hit
        # Whole-graph equality ignores the lazily-built indices — an
        # already-queried graph equals its freshly-loaded twin.
        assert g2 == graph

    def test_save_and_load(self, graph, tmp_path):
        out = tmp_path / "package-callgraph.json"
        graph.save(out)
        g2 = load_package_callgraph(out)
        assert g2.edges == graph.edges

    def test_doctrine_marker_in_artifact(self, graph):
        assert graph.to_dict()["doctrine"] == "originate_and_prioritize_only"

    def test_deterministic_output(self):
        inv = _build_inventory(FIXTURE_ROOT)
        d1 = build_package_callgraph(inv).to_dict()
        d2 = build_package_callgraph(
            _build_inventory(FIXTURE_ROOT)).to_dict()
        assert d1 == d2


# ---------------------------------------------------------------------------
# Caps + degradation
# ---------------------------------------------------------------------------


class TestCaps:
    def test_file_cap_degrades_with_marker(self):
        inv = _build_inventory(FIXTURE_ROOT)
        g = build_package_callgraph(inv, max_files=1)
        assert "files" in g.caps_hit
        assert g.stats["files_processed"] == 1
        assert g.stats["files_skipped_cap"] >= 1

    def test_edge_cap_degrades_with_marker(self):
        inv = _build_inventory(FIXTURE_ROOT)
        g = build_package_callgraph(inv, max_edges=2)
        assert "edges" in g.caps_hit
        assert len(g.edges) <= 2
        assert g.stats["edges_dropped_cap"] >= 1

    def test_node_cap_degrades_with_marker(self):
        inv = _build_inventory(FIXTURE_ROOT)
        g = build_package_callgraph(inv, max_nodes=3)
        assert "nodes" in g.caps_hit

    def test_time_budget_degrades_with_marker(self):
        inv = _build_inventory(FIXTURE_ROOT)
        g = build_package_callgraph(inv, time_budget_s=-1.0)
        assert "time_budget" in g.caps_hit

    def test_per_file_unresolved_cap(self):
        from core.analysis.package_callgraph import (
            _MAX_UNRESOLVED_PER_FILE,
        )
        calls = "\n".join(
            f"    unknown_{i}()"
            for i in range(_MAX_UNRESOLVED_PER_FILE + 50)
        )
        content = f"def f():\n{calls}\n"
        inv = {"files": [_record_for("hostile.py", content)]}
        g = build_package_callgraph(inv)
        assert "unresolved" in g.caps_hit
        assert len(g.unresolved_calls) == _MAX_UNRESOLVED_PER_FILE
        # The full count stays visible in stats — capped, not silent.
        assert (g.stats["unresolved_total"]
                == _MAX_UNRESOLVED_PER_FILE + 50)

    def test_getattr_fanout_cap(self):
        from core.analysis.package_callgraph import _MAX_GETATTR_FANOUT
        n = _MAX_GETATTR_FANOUT + 1
        files = [
            _record_for(f"m{i}.py", f"def run():\n    return {i}\n")
            for i in range(n)
        ]
        files.append(_record_for(
            "caller.py", "def go(obj):\n    getattr(obj, 'run')()\n",
        ))
        g = build_package_callgraph({"files": files})
        marks = [u for u in g.unresolved_calls
                 if u.reason == REASON_GETATTR_FANOUT_CAP]
        assert len(marks) == 1
        assert not any(e.kind == KIND_GETATTR_DISPATCH for e in g.edges)


# ---------------------------------------------------------------------------
# Hostile input — degrade, never crash
# ---------------------------------------------------------------------------


class TestHostileInput:
    def test_syntax_error_file_degrades(self):
        g = build_package_callgraph({"files": [
            _record_for("broken.py", "def broken(:\n  pass"),
            _record_for("ok.py", "def f():\n    return 1\n"),
        ]})
        assert any(n.file_path == "ok.py" for n in g.nodes)

    def test_absurd_nesting_degrades(self):
        # 60 nested ifs + a call at the bottom; the extractors own
        # their parse limits — whatever facts survive, assembly must
        # not crash.
        depth = 60
        body = "".join(
            "    " * (i + 1) + "if x:\n" for i in range(depth)
        )
        content = ("def f(x):\n" + body
                   + "    " * (depth + 1) + "g()\n")
        g = build_package_callgraph({"files": [
            _record_for("deep.py", content),
        ]})
        assert any(n.file_path == "deep.py" for n in g.nodes)

    def test_garbage_records_degrade(self):
        inv = {"files": [
            "not-a-dict",
            {"path": "a.py", "language": "python",
             "items": "garbage", "call_graph": "garbage"},
            {"path": "b.py", "language": "python",
             "items": [{"kind": "function"}, None, 42],
             "call_graph": {
                 "calls": [{"chain": None}, "junk", {}],
                 "imports": {"x": "y"},
                 "relative_imports": [[1], "junk", [99, "", "n", None]],
                 "classes": ["junk", {"name": ""}],
                 "decorated_functions": [{"decorators": [[]]}, "junk"],
                 "subscript_calls": ["junk", {"chain": []}],
                 "getattr_calls": [[1], "junk", [1, None, None]],
                 "dispatch_tables": {"T": "junk"},
             }},
            {"no_path_key": True},
        ]}
        g = build_package_callgraph(inv)
        assert isinstance(g, PackageCallGraph)

    def test_reexport_alias_cycle_terminates(self):
        """``a/__init__`` re-exports from ``b``, ``b/__init__`` from
        ``a`` — the fixed-point bound terminates the pass."""
        inv = {"files": [
            _record_for("a/__init__.py", "from b import thing\n"),
            _record_for("b/__init__.py", "from a import thing\n"),
        ]}
        g = build_package_callgraph(inv)
        assert isinstance(g, PackageCallGraph)

    def test_unknown_dispatch_table_marked(self):
        g = build_package_callgraph({"files": [
            _record_for(
                "d.py",
                "def go(k):\n    MYSTERY[k]()\n",
            ),
        ]})
        assert any(
            u.reason == REASON_DISPATCH_TABLE_UNKNOWN
            for u in g.unresolved_calls
        )

    def test_opaque_getattr_marked(self):
        g = build_package_callgraph({"files": [
            _record_for(
                "d.py",
                "def go(obj, name):\n    getattr(obj, name)()\n",
            ),
        ]})
        assert any(
            u.reason == REASON_GETATTR_OPAQUE for u in g.unresolved_calls
        )

    def test_empty_inventory(self):
        g = build_package_callgraph({})
        assert g.nodes == ()
        assert g.edges == ()

    def test_malformed_field_shapes_degrade_with_stat(self):
        """The never-raises contract holds for arbitrary disk-loaded
        record field shapes: wrong container types and non-numeric
        numerics coerce/drop with a malformed_facts count."""
        shapes = [
            {"imports": ["x", "y"]},
            {"dispatch_tables": ["EVIL"],
             "subscript_calls": [{"line": 1, "chain": ["EVIL"]}]},
            {"calls": [{"line": "xx", "chain": ["f"]}]},
            {"calls": [{"line": 1, "chain": 42}]},
            {"relative_imports": [["x", "m", "n"]]},
            {"classes": [{"name": "C", "bases": 42}]},
            {"decorated_functions": [{"line": 1, "decorators": [42]}]},
            {"getattr_calls": [["xx", None, "run"]]},
            {"subscript_calls": [{"line": 1, "chain": 7}]},
            {"dispatch_tables": {"T": [42, [3]]},
             "subscript_calls": [{"line": 1, "chain": ["T"]}]},
            {"calls": "junk", "relative_imports": "junk",
             "classes": "junk", "decorated_functions": "junk",
             "subscript_calls": "junk", "getattr_calls": "junk"},
        ]
        for cg in shapes:
            g = build_package_callgraph({"files": [
                {"path": "a.py", "language": "python", "items": [],
                 "call_graph": cg},
            ]})
            assert isinstance(g, PackageCallGraph), cg
        g = build_package_callgraph({"files": [
            {"path": "a.py", "language": "python",
             "items": [{"kind": "function", "name": "f",
                        "line_start": "xx"}],
             "call_graph": {"imports": ["x"]}},
        ]})
        assert g.stats.get("malformed_facts", 0) >= 1


class TestScopedBareNameResolution:
    """A nested def is a runtime binding only inside its enclosing
    function — never a file-wide shadow."""

    def test_nested_def_does_not_hijack_imported_name(self):
        """A bare call OUTSIDE the nesting function must resolve to
        the import, not the nested def."""
        g = build_package_callgraph({"files": [
            _record_for("pkg/__init__.py", ""),
            _record_for("pkg/utils.py", "def helper():\n    return 'real'\n"),
            _record_for(
                "pkg/m.py",
                "from pkg.utils import helper\n"
                "def f():\n"
                "    def helper():\n"
                "        return 'nested'\n"
                "    return helper()\n"
                "def go():\n"
                "    return helper()\n",
            ),
        ]})
        go = [n for n in g.nodes
              if n.file_path == "pkg/m.py" and n.name == "go"][0]
        targets = {e.dst for e in g.callees_of(go.node_id)}
        assert targets == {"pkg/utils.py::helper@1"}
        # The in-scope call inside f still binds the nested def.
        f = [n for n in g.nodes
             if n.file_path == "pkg/m.py" and n.name == "f"][0]
        assert {e.dst for e in g.callees_of(f.node_id)} == {
            "pkg/m.py::helper@3",
        }

    def test_in_scope_nested_def_wins_over_module_level(self):
        """Python scoping: inside the enclosing function the nested
        def shadows a same-name module-level def."""
        g = build_package_callgraph({"files": [_record_for(
            "m.py",
            "def helper():\n    return 'module'\n"
            "def f():\n"
            "    def helper():\n"
            "        return 'nested'\n"
            "    return helper()\n",
        )]})
        f = [n for n in g.nodes if n.name == "f"][0]
        assert {e.dst for e in g.callees_of(f.node_id)} == {
            "m.py::helper@4",
        }

    def test_out_of_scope_nested_only_falls_to_unresolved(self):
        """No import, no module-level def — a bare call outside the
        nesting function gets a marker, never the nested node."""
        g = build_package_callgraph({"files": [_record_for(
            "m.py",
            "def f():\n"
            "    def helper():\n"
            "        return 1\n"
            "    return helper()\n"
            "def go():\n"
            "    return helper()\n",
        )]})
        go = [n for n in g.nodes if n.name == "go"][0]
        assert g.callees_of(go.node_id) == ()
        assert any(
            u.chain == ("helper",) and u.reason == REASON_UNKNOWN_NAME
            and u.caller == go.node_id
            for u in g.unresolved_calls
        )

    def test_relative_import_rebind_counted(self):
        """Two relative imports binding the same local name (the
        conditional-import idiom) bump the partial rebind stat —
        absolute-vs-absolute rebinds are collapsed at extraction
        and stay uncountable (documented silent gap)."""
        g = build_package_callgraph({"files": [
            _record_for("pkg/__init__.py", ""),
            _record_for("pkg/fast.py", "def loads(s):\n    return 1\n"),
            _record_for("pkg/slow.py", "def loads(s):\n    return 2\n"),
            _record_for(
                "pkg/m.py",
                "try:\n"
                "    from .fast import loads\n"
                "except ImportError:\n"
                "    from .slow import loads\n"
                "def go(s):\n    return loads(s)\n",
            ),
        ]})
        assert g.stats.get("import_name_rebound", 0) == 1
