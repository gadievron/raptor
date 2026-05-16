"""Tests for :func:`core.inventory.call_graph.extract_call_graph_java`."""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    FileCallGraph,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_REFLECT,
    INDIRECTION_WILDCARD_IMPORT,
    extract_call_graph_java,
)


pytest.importorskip("tree_sitter_java")


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------


def test_simple_import():
    g = extract_call_graph_java(
        "package x;\nimport java.util.Map;\nclass C {}\n"
    )
    assert g.imports == {"Map": "java.util.Map"}


def test_deeply_scoped_import():
    g = extract_call_graph_java(
        "package x;\n"
        "import org.springframework.web.bind.annotation.GetMapping;\n"
        "class C {}\n"
    )
    assert g.imports == {
        "GetMapping":
            "org.springframework.web.bind.annotation.GetMapping",
    }


def test_static_import():
    """``import static x.y.Z.method;`` binds the method name to
    its full path."""
    g = extract_call_graph_java(
        "package x;\n"
        "import static java.util.Collections.emptyList;\n"
        "class C {}\n"
    )
    assert g.imports == {
        "emptyList": "java.util.Collections.emptyList",
    }


def test_wildcard_import_flagged_not_mapped():
    """``import x.y.*;`` — bound names are statically unknowable.
    Flag wildcard, no map entry."""
    g = extract_call_graph_java(
        "package x;\n"
        "import com.example.wildcard.*;\n"
        "class C {}\n"
    )
    assert g.imports == {}
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_static_wildcard_import_flagged():
    """``import static x.y.Z.*;`` — same wildcard treatment."""
    g = extract_call_graph_java(
        "package x;\n"
        "import static java.util.Collections.*;\n"
        "class C {}\n"
    )
    assert g.imports == {}
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_multiple_imports():
    g = extract_call_graph_java(
        "package x;\n"
        "import java.util.Map;\n"
        "import java.util.HashMap;\n"
        "import com.example.lib.Util;\n"
        "class C {}\n"
    )
    assert g.imports == {
        "Map": "java.util.Map",
        "HashMap": "java.util.HashMap",
        "Util": "com.example.lib.Util",
    }


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_static_method_call():
    g = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "class C { void m() { Util.run(\"x\"); } }\n"
    )
    assert any(c.chain == ["Util", "run"] for c in g.calls)


def test_bare_method_call():
    g = extract_call_graph_java(
        "package x;\nclass C { void m() { local(); } }\n"
    )
    assert any(c.chain == ["local"] for c in g.calls)


def test_field_access_chain_call():
    """``a.b.c()`` flattens to a three-element chain."""
    g = extract_call_graph_java(
        "package x;\nclass C { void m() { a.b.c(); } }\n"
    )
    assert any(c.chain == ["a", "b", "c"] for c in g.calls)


def test_method_caller_attribution():
    g = extract_call_graph_java(
        "package x;\n"
        "class C {\n"
        "    void outer() { foo(); }\n"
        "}\n"
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "outer"


def test_constructor_caller_attribution():
    """Constructors push the class name onto the enclosing
    stack."""
    g = extract_call_graph_java(
        "package x;\n"
        "class MyClass {\n"
        "    public MyClass() { foo(); }\n"
        "}\n"
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "MyClass"


def test_call_line_numbers():
    g = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "\n"
        "class C {\n"
        "    void m() {\n"
        "        Util.run();\n"
        "    }\n"
        "}\n"
    )
    util_calls = [c for c in g.calls if c.chain == ["Util", "run"]]
    assert util_calls[0].line == 6


# ---------------------------------------------------------------------------
# Indirection
# ---------------------------------------------------------------------------


def test_class_forname_flagged():
    """``Class.forName("x.y.Z")`` is Java's analog of Python's
    ``importlib.import_module``. Flag it."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C { void m() { Class.forName(\"y.Z\"); } }\n"
    )
    assert INDIRECTION_IMPORTLIB in g.indirection


def test_method_invoke_flagged():
    """``method.invoke(target)`` — reflective dispatch."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C { void m() { method.invoke(target); } }\n"
    )
    assert INDIRECTION_REFLECT in g.indirection


def test_constructor_newinstance_flagged():
    """``Class.getConstructor().newInstance(...)`` —
    reflective construction."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C { void m() { ctor.newInstance(); } }\n"
    )
    assert INDIRECTION_REFLECT in g.indirection


def test_normal_call_no_indirection():
    g = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "class C { void m() { Util.run(); } }\n"
    )
    assert g.indirection == set()


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty_or_partial():
    g = extract_call_graph_java(
        "package x;\nclass C { void m( {"
    )
    assert isinstance(g, FileCallGraph)


def test_empty_file():
    g = extract_call_graph_java("")
    assert g == FileCallGraph()


def test_round_trip_through_dict():
    g = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "class C {\n"
        "    void m() { Util.run(); Class.forName(\"y\"); }\n"
        "}\n"
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


def test_resolver_called_against_java_data():
    """Static method call resolves correctly through the
    import map. ``Util.run()`` → ``com.example.Util.run`` →
    matches the OSV-style qualified name."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "class C { void m() { Util.run(); } }\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/Handler.java", "language": "java",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "com.example.Util.run")
    assert r.verdict == Verdict.CALLED


def test_resolver_uncertain_with_class_forname():
    """File uses ``Class.forName`` AND mentions the target tail
    name in a chain that does NOT statically resolve to the
    target. The reflective dispatch could be the call;
    UNCERTAIN. (When the chain DOES resolve, the resolver
    returns CALLED — evidence trumps masking.)"""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_java(
        "package x;\n"
        "class C {\n"
        "    void m() {\n"
        "        Class.forName(\"y\");\n"
        "        someInstance.run();\n"
        "    }\n"
        "}\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/H.java", "language": "java",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "com.example.Util.run")
    assert r.verdict == Verdict.UNCERTAIN


def test_resolver_not_called_when_function_unused():
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_java(
        "package x;\n"
        "import com.example.Util;\n"
        "class C { void m() { Util.other(); } }\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/H.java", "language": "java",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "com.example.Util.run")
    assert r.verdict == Verdict.NOT_CALLED


def test_resolver_static_import_resolves():
    """``import static x.Y.helper; helper();`` — the static
    import binds the helper name; bare-call resolves to its
    full path."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_java(
        "package x;\n"
        "import static com.example.Helpers.helper;\n"
        "class C { void m() { helper(); } }\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/H.java", "language": "java",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "com.example.Helpers.helper")
    assert r.verdict == Verdict.CALLED
