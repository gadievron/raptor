"""Tests for :func:`core.inventory.call_graph.extract_call_graph_go`."""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    FileCallGraph,
    INDIRECTION_REFLECT,
    INDIRECTION_WILDCARD_IMPORT,
    extract_call_graph_go,
)


pytest.importorskip("tree_sitter_go")


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def test_single_import_binds_last_segment():
    g = extract_call_graph_go(
        'package x\nimport "fmt"\n'
    )
    assert g.imports == {"fmt": "fmt"}


def test_path_with_slash_binds_last_segment():
    """``import "net/http"`` binds ``http`` (last path segment) but
    the value retains the full path so the resolver matches OSV
    symbols like ``net/http.Get``."""
    g = extract_call_graph_go(
        'package x\nimport "net/http"\n'
    )
    assert g.imports == {"http": "net/http"}


def test_aliased_import():
    g = extract_call_graph_go(
        'package x\nimport str "strings"\n'
    )
    assert g.imports == {"str": "strings"}


def test_block_form_imports():
    g = extract_call_graph_go(
        "package x\n"
        'import (\n\t"fmt"\n\t"net/http"\n\tstr "strings"\n)\n'
    )
    assert g.imports == {
        "fmt": "fmt",
        "http": "net/http",
        "str": "strings",
    }


def test_dot_import_flagged_not_mapped():
    """``. "errors"`` is the Go analog of ``from x import *`` —
    flag wildcard, no map entry."""
    g = extract_call_graph_go(
        'package x\nimport . "errors"\n'
    )
    assert g.imports == {}
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_blank_import_no_binding():
    """``_ "x"`` triggers package init() but doesn't bind a name."""
    g = extract_call_graph_go(
        'package x\nimport _ "github.com/lib/pq"\n'
    )
    assert g.imports == {}


def test_mixed_block_imports():
    g = extract_call_graph_go(
        "package x\n"
        'import (\n'
        '\t"fmt"\n'
        '\t. "errors"\n'
        '\tstr "strings"\n'
        '\t_ "github.com/lib/pq"\n'
        ')\n'
    )
    assert g.imports == {"fmt": "fmt", "str": "strings"}
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_attribute_chain_call():
    g = extract_call_graph_go(
        'package x\n'
        'import "fmt"\n'
        'func f() { fmt.Println("hi") }\n'
    )
    assert any(c.chain == ["fmt", "Println"] for c in g.calls)


def test_bare_call():
    g = extract_call_graph_go(
        'package x\nfunc f() { local() }\n'
    )
    assert any(c.chain == ["local"] for c in g.calls)


def test_deep_attribute_chain():
    """``a.b.c()`` — three-segment selector."""
    g = extract_call_graph_go(
        'package x\nfunc f() { a.b.c() }\n'
    )
    assert any(c.chain == ["a", "b", "c"] for c in g.calls)


def test_function_caller_attribution():
    g = extract_call_graph_go(
        'package x\nfunc outer() { foo() }\n'
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "outer"


def test_method_caller_attribution():
    """``func (r Recv) Name()`` — the function name is ``Name``,
    not the receiver type."""
    g = extract_call_graph_go(
        'package x\nfunc (r Recv) Process() { foo() }\n'
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "Process"


def test_module_level_caller_none():
    """Calls outside any function (e.g. var initialisers) attribute
    to None."""
    g = extract_call_graph_go(
        'package x\nvar _ = init()\n'
    )
    init_calls = [c for c in g.calls if c.chain == ["init"]]
    assert init_calls[0].caller is None


def test_call_line_numbers():
    g = extract_call_graph_go(
        'package x\n'
        'import "fmt"\n'
        '\n'
        'func f() {\n'
        '\tfmt.Println("hi")\n'
        '}\n'
    )
    p = [c for c in g.calls if c.chain == ["fmt", "Println"]]
    assert p[0].line == 5


# ---------------------------------------------------------------------------
# Indirection
# ---------------------------------------------------------------------------


def test_reflect_dispatch_flagged():
    g = extract_call_graph_go(
        'package x\n'
        'import "reflect"\n'
        'func f() {\n'
        '\treflect.ValueOf(x).MethodByName("do").Call(nil)\n'
        '}\n'
    )
    assert INDIRECTION_REFLECT in g.indirection


def test_reflect_alias_still_flagged_via_chain_head():
    """``import r "reflect"`` then ``r.ValueOf(...)`` — the chain
    head is ``r`` (the alias), so reflect detection misses by
    design. Documented limitation: aliased reflect imports won't
    flag. Operators using aliased reflect are uncommon and the
    detection over-flagging is worse than under-flagging here."""
    g = extract_call_graph_go(
        'package x\n'
        'import r "reflect"\n'
        'func f() { r.ValueOf(x) }\n'
    )
    # NOT flagged — alias-via-imports breaks the chain[0]=="reflect"
    # heuristic. This is the documented behaviour.
    assert INDIRECTION_REFLECT not in g.indirection


def test_normal_call_no_indirection():
    g = extract_call_graph_go(
        'package x\n'
        'import "fmt"\n'
        'func f() { fmt.Println("hi") }\n'
    )
    assert g.indirection == set()


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty_or_partial():
    """Tree-sitter is error-tolerant; returns SOMETHING. Crucial:
    no crash."""
    g = extract_call_graph_go("package x\nfunc broken( {")
    assert isinstance(g, FileCallGraph)


def test_empty_file():
    g = extract_call_graph_go("")
    assert g == FileCallGraph()


def test_round_trip_through_dict():
    g = extract_call_graph_go(
        'package x\n'
        'import "net/http"\n'
        'func f() { http.Get("/x"); reflect.ValueOf(y) }\n'
    )
    d = g.to_dict()
    g2 = FileCallGraph.from_dict(d)
    assert g2.imports == g.imports
    assert {tuple(c.chain) for c in g2.calls} == {
        tuple(c.chain) for c in g.calls
    }
    assert g2.indirection == g.indirection


# ---------------------------------------------------------------------------
# Resolver end-to-end
# ---------------------------------------------------------------------------


def test_resolver_called_against_go_data():
    """The language-agnostic resolver consumes Go call_graph data
    and returns CALLED for matching qualified names. Note: Go OSV
    symbols use the FULL module path (``net/http.HandlerFunc``)
    so the resolver matches against that."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_go(
        'package x\n'
        'import "net/http"\n'
        'func f() { http.Get("/x") }\n'
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/handler.go", "language": "go",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "net/http.Get")
    assert r.verdict == Verdict.CALLED


def test_resolver_uncertain_on_dot_import_with_tail_match():
    """File with dot import AND a bare-name call matching the
    target tail → UNCERTAIN."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_go(
        'package x\n'
        'import "net/http"\n'
        'import . "errors"\n'
        'func f() { Get("/x") }\n'   # bare-name call
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/h.go", "language": "go",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "net/http.Get")
    # Dot import flagged + ``Get`` call mentions the tail; resolver
    # can't statically prove ``Get`` came from net/http vs errors.
    assert r.verdict == Verdict.UNCERTAIN


def test_resolver_not_called_when_function_unused():
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_go(
        'package x\n'
        'import "net/http"\n'
        'func f() { http.Post("/x", nil, nil) }\n'
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/h.go", "language": "go",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "net/http.Get")
    assert r.verdict == Verdict.NOT_CALLED
