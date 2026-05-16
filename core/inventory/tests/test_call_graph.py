"""Tests for :mod:`core.inventory.call_graph`.

The call-graph extractor sits between the AST and the resolver.
Tests pin the data shape — broken extraction breaks reachability
verdicts silently, so the data layer needs explicit coverage.
"""

from __future__ import annotations

from core.inventory.call_graph import (
    CallSite,
    FileCallGraph,
    INDIRECTION_DUNDER_IMPORT,
    INDIRECTION_GETATTR,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_WILDCARD_IMPORT,
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


def test_getattr_with_non_constant_not_flagged():
    """``getattr(obj, attr)`` with a variable second arg isn't the
    string-dispatch pattern we care about."""
    g = extract_call_graph_python(
        "def f(obj, attr):\n"
        "    getattr(obj, attr)()\n"
    )
    assert INDIRECTION_GETATTR not in g.indirection


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
