"""Tests for the four new ``extract_call_graph_<lang>`` functions
(Rust / Ruby / C# / PHP) added alongside the Java extractor.

Each language gets a small focused suite covering the import,
call, and indirection shapes the SCA function-level reachability
tier consumes. Deeper grammar coverage lands in language-specific
PRs as needed."""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    FileCallGraph,
    INDIRECTION_EVAL,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_REFLECT,
    INDIRECTION_WILDCARD_IMPORT,
    extract_call_graph_csharp,
    extract_call_graph_php,
    extract_call_graph_ruby,
    extract_call_graph_rust,
)


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_rust")


def test_rust_simple_use():
    g = extract_call_graph_rust("use foo::bar::Baz;\n")
    # Imports stored with ``.`` separator (matching the cross-
    # language resolver convention) even though Rust source uses
    # ``::``.
    assert g.imports == {"Baz": "foo.bar.Baz"}


def test_rust_use_alias():
    g = extract_call_graph_rust("use foo::bar::Baz as Q;\n")
    assert g.imports == {"Q": "foo.bar.Baz"}


def test_rust_use_list():
    g = extract_call_graph_rust("use foo::{Bar, Qux};\n")
    assert g.imports == {"Bar": "foo.Bar", "Qux": "foo.Qux"}


def test_rust_use_wildcard_flagged():
    g = extract_call_graph_rust("use foo::*;\n")
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_rust_scoped_call():
    g = extract_call_graph_rust(
        "fn main() { Baz::new(); }\n"
    )
    assert any(c.chain == ["Baz", "new"] for c in g.calls)


def test_rust_field_chain_call():
    g = extract_call_graph_rust(
        "fn main() { inst.deep.chain(); }\n"
    )
    assert any(
        c.chain == ["inst", "deep", "chain"] for c in g.calls
    )


def test_rust_caller_attribution():
    g = extract_call_graph_rust(
        "fn outer() { inner_fn(); }\n"
    )
    inner_calls = [c for c in g.calls if c.chain == ["inner_fn"]]
    assert inner_calls and inner_calls[0].caller == "outer"


def test_rust_round_trip():
    g = extract_call_graph_rust("use foo::Bar;\nfn m() { Bar::x(); }\n")
    g2 = FileCallGraph.from_dict(g.to_dict())
    assert g2.imports == g.imports


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_ruby")


def test_ruby_require_recorded():
    g = extract_call_graph_ruby('require "json"\n')
    assert g.imports == {"json": "json"}


def test_ruby_require_relative_path_basename():
    g = extract_call_graph_ruby('require_relative "lib/utils"\n')
    assert g.imports == {"utils": "lib/utils"}


def test_ruby_constant_method_call():
    g = extract_call_graph_ruby(
        'class C\n  def m\n    JSON.parse(s)\n  end\nend\n'
    )
    assert any(c.chain == ["JSON", "parse"] for c in g.calls)


def test_ruby_send_flagged_reflect():
    g = extract_call_graph_ruby(
        'class C\n  def m\n    obj.send(:bar)\n  end\nend\n'
    )
    assert INDIRECTION_REFLECT in g.indirection


def test_ruby_eval_flagged():
    g = extract_call_graph_ruby(
        'def m; eval(s); end\n'
    )
    assert INDIRECTION_EVAL in g.indirection


def test_ruby_const_get_flagged():
    g = extract_call_graph_ruby(
        'def m; Object.const_get("X"); end\n'
    )
    assert INDIRECTION_IMPORTLIB in g.indirection


# ---------------------------------------------------------------------------
# C# (NuGet)
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_c_sharp")


def test_csharp_using():
    g = extract_call_graph_csharp("using System.Text;\n")
    assert g.imports == {"Text": "System.Text"}


def test_csharp_using_alias():
    g = extract_call_graph_csharp(
        "using JsonNet = Newtonsoft.Json.Linq;\n"
    )
    assert "JsonNet" in g.imports


def test_csharp_static_member_call():
    g = extract_call_graph_csharp(
        "class C { void M() { Console.WriteLine(\"hi\"); } }\n"
    )
    assert any(
        c.chain == ["Console", "WriteLine"] for c in g.calls
    )


def test_csharp_assembly_load_importlib():
    g = extract_call_graph_csharp(
        "class C { void M() { Assembly.Load(name); } }\n"
    )
    assert INDIRECTION_IMPORTLIB in g.indirection


def test_csharp_complex_chain_reflect_via_tail():
    """When the chain is too complex to extract cleanly, the
    fallback ``_tail_identifier`` still flags reflection on
    Invoke."""
    g = extract_call_graph_csharp(
        'class C { void M() { '
        'typeof(C).GetMethod("X").Invoke(null, null); } }\n'
    )
    assert INDIRECTION_REFLECT in g.indirection


# ---------------------------------------------------------------------------
# PHP (Composer / Packagist)
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_php")


def test_php_use_simple():
    g = extract_call_graph_php(
        '<?php\nuse Foo\\Bar\\Baz;\n'
    )
    assert g.imports == {"Baz": "Foo\\Bar\\Baz"}


def test_php_use_alias():
    g = extract_call_graph_php(
        '<?php\nuse Foo\\Bar as B;\n'
    )
    assert g.imports == {"B": "Foo\\Bar"}


def test_php_static_call():
    g = extract_call_graph_php(
        '<?php\nclass C { function m() { Baz::method(); } }\n'
    )
    assert any(c.chain == ["Baz", "method"] for c in g.calls)


def test_php_call_user_func_reflect():
    g = extract_call_graph_php(
        '<?php\nfunction m() { call_user_func("foo"); }\n'
    )
    assert INDIRECTION_REFLECT in g.indirection


def test_php_eval_flagged():
    g = extract_call_graph_php(
        '<?php\nfunction m() { eval($s); }\n'
    )
    assert INDIRECTION_EVAL in g.indirection
