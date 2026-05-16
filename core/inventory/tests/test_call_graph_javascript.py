"""Tests for :func:`core.inventory.call_graph.extract_call_graph_javascript`.

The Python extractor's tests in ``test_call_graph.py`` cover the
language-agnostic shape of ``FileCallGraph``; here we pin the
JS-specific data shapes (ESM imports, CommonJS require,
destructured require, dynamic import, bracket dispatch, eval).
The resolver in :mod:`core.inventory.reachability` is unchanged —
it just consumes the per-file dicts emitted by either extractor.
"""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    FileCallGraph,
    INDIRECTION_BRACKET_DISPATCH,
    INDIRECTION_DYNAMIC_IMPORT,
    INDIRECTION_EVAL,
    extract_call_graph_javascript,
)


pytest.importorskip("tree_sitter_javascript")


# ---------------------------------------------------------------------------
# Imports — ES modules
# ---------------------------------------------------------------------------


def test_default_import():
    g = extract_call_graph_javascript("import lodash from 'lodash';\n")
    assert g.imports == {"lodash": "lodash"}


def test_named_import():
    g = extract_call_graph_javascript(
        "import { get, set } from 'lodash';\n",
    )
    assert g.imports == {"get": "lodash.get", "set": "lodash.set"}


def test_named_import_with_alias():
    g = extract_call_graph_javascript(
        "import { get as g, set as s } from 'lodash';\n",
    )
    assert g.imports == {"g": "lodash.get", "s": "lodash.set"}


def test_namespace_import():
    g = extract_call_graph_javascript(
        "import * as fp from 'lodash/fp';\n",
    )
    assert g.imports == {"fp": "lodash/fp"}


def test_default_plus_named_import():
    g = extract_call_graph_javascript(
        "import lodash, { get } from 'lodash';\n",
    )
    assert g.imports == {"lodash": "lodash", "get": "lodash.get"}


def test_relative_path_import():
    """Relative import — module path stays as the literal string;
    OSV won't match (it's project-internal), but the resolver
    can still consume the data without crashing."""
    g = extract_call_graph_javascript(
        "import x from './local';\n",
    )
    assert g.imports == {"x": "./local"}


# ---------------------------------------------------------------------------
# Imports — CommonJS require
# ---------------------------------------------------------------------------


def test_simple_require():
    g = extract_call_graph_javascript(
        "const lodash = require('lodash');\n",
    )
    assert g.imports == {"lodash": "lodash"}


def test_destructured_require():
    g = extract_call_graph_javascript(
        "const { get, set } = require('lodash');\n",
    )
    assert g.imports == {"get": "lodash.get", "set": "lodash.set"}


def test_destructured_require_with_alias():
    """``const { get: g } = require('lodash')`` — alias rename."""
    g = extract_call_graph_javascript(
        "const { get: g } = require('lodash');\n",
    )
    assert g.imports == {"g": "lodash.get"}


def test_var_declaration_require():
    """``var x = require(...)`` (legacy) works the same as ``const``."""
    g = extract_call_graph_javascript(
        "var lodash = require('lodash');\n",
    )
    assert g.imports == {"lodash": "lodash"}


# ---------------------------------------------------------------------------
# Calls
# ---------------------------------------------------------------------------


def test_attribute_chain_call():
    g = extract_call_graph_javascript(
        "import lodash from 'lodash';\nlodash.get(obj, 'k');\n",
    )
    assert any(c.chain == ["lodash", "get"] for c in g.calls)


def test_bare_call():
    g = extract_call_graph_javascript(
        "import { get } from 'lodash';\nget(obj);\n",
    )
    assert any(c.chain == ["get"] for c in g.calls)


def test_deep_attribute_chain():
    g = extract_call_graph_javascript(
        "import _ from 'lodash';\n_.fp.flow.compose(a, b);\n",
    )
    assert any(
        c.chain == ["_", "fp", "flow", "compose"] for c in g.calls
    )


def test_module_level_call_caller_none():
    g = extract_call_graph_javascript("foo();\n")
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls
    assert foo_calls[0].caller is None


def test_caller_attribution_named_function():
    g = extract_call_graph_javascript(
        "function outer() { foo(); }\n",
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "outer"


def test_arrow_does_not_break_caller_attribution():
    """Calls inside an anonymous arrow inside a named function
    attribute to the named function, not to the arrow."""
    g = extract_call_graph_javascript(
        "function outer() { arr.map(x => x.foo()); }\n",
    )
    foo_calls = [c for c in g.calls if c.chain == ["x", "foo"]]
    assert foo_calls[0].caller == "outer"


def test_method_definition_caller_attribution():
    g = extract_call_graph_javascript(
        "class C { meth() { foo(); } }\n",
    )
    foo_calls = [c for c in g.calls if c.chain == ["foo"]]
    assert foo_calls[0].caller == "meth"


# ---------------------------------------------------------------------------
# Indirection flags
# ---------------------------------------------------------------------------


def test_dynamic_import_flagged():
    g = extract_call_graph_javascript(
        "import('./dynamic').then(m => m.foo());\n",
    )
    assert INDIRECTION_DYNAMIC_IMPORT in g.indirection


def test_require_with_variable_arg_flagged():
    """``require(variable)`` is dynamic — flag it."""
    g = extract_call_graph_javascript(
        "function f(name) { return require(name); }\n",
    )
    assert INDIRECTION_DYNAMIC_IMPORT in g.indirection


def test_bracket_dispatch_flagged():
    g = extract_call_graph_javascript(
        "function f(name) { obj[name](); }\n",
    )
    assert INDIRECTION_BRACKET_DISPATCH in g.indirection


def test_bracket_with_string_literal_captures_target():
    """``obj["get"]()`` is the JS analog of Python's
    ``getattr(obj, "get")()``. The literal ``"get"`` is captured
    as a getattr_target so the resolver's tail-name detection
    fires on queries about ``<lib>.get``."""
    g = extract_call_graph_javascript(
        "obj['someName']();\n",
    )
    assert "someName" in g.getattr_targets
    assert INDIRECTION_BRACKET_DISPATCH in g.indirection


def test_eval_flagged():
    g = extract_call_graph_javascript("eval('alert(1)');\n")
    assert INDIRECTION_EVAL in g.indirection


def test_new_function_flagged():
    """``new Function('return 1')()`` is the indirect-eval
    pattern."""
    g = extract_call_graph_javascript(
        "new Function('return 1')();\n",
    )
    assert INDIRECTION_EVAL in g.indirection


def test_normal_call_no_indirection():
    g = extract_call_graph_javascript(
        "import lodash from 'lodash';\nlodash.get(obj);\n",
    )
    assert g.indirection == set()


# ---------------------------------------------------------------------------
# Resilience
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty():
    """Malformed JS shouldn't crash the inventory build. tree-
    sitter is error-tolerant so it'll return SOMETHING — we just
    need it to not blow up."""
    g = extract_call_graph_javascript("function broken( {")
    # Either FileCallGraph() or a partial extract — both
    # acceptable. Crucial: no exception.
    assert isinstance(g, FileCallGraph)


def test_empty_file():
    g = extract_call_graph_javascript("")
    assert g == FileCallGraph()


def test_round_trip_through_dict():
    """Same shape as the Python extractor — round-trips cleanly."""
    g = extract_call_graph_javascript(
        "import lodash from 'lodash';\n"
        "function f() { lodash.get(obj); obj['k'](); }\n",
    )
    d = g.to_dict()
    g2 = FileCallGraph.from_dict(d)
    assert g2.imports == g.imports
    assert {tuple(c.chain) for c in g2.calls} == {
        tuple(c.chain) for c in g.calls
    }
    assert g2.indirection == g.indirection
    assert g2.getattr_targets == g.getattr_targets


# ---------------------------------------------------------------------------
# End-to-end with the resolver
# ---------------------------------------------------------------------------


def test_resolver_called_against_js_data():
    """The language-agnostic resolver consumes JS call_graph data
    just like Python's. Synthesise an inventory entry from the JS
    extractor and verify ``function_called`` returns CALLED for a
    matching qualified name."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_javascript(
        "import lodash from 'lodash';\n"
        "lodash.get(obj, 'k');\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/app.js", "language": "javascript",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "lodash.get")
    assert r.verdict == Verdict.CALLED
    assert r.evidence == (("src/app.js", 2),)


def test_resolver_uncertain_on_eval():
    """File uses eval AND mentions the target tail name (via a
    bracket-string literal) → UNCERTAIN."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_javascript(
        "import lodash from 'lodash';\n"
        "function f() {\n"
        "    lodash['get'](obj);\n"
        "}\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/app.js", "language": "javascript",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "lodash.get")
    assert r.verdict == Verdict.UNCERTAIN


def test_resolver_not_called_when_function_unused():
    """JS file imports lodash but never calls .get."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_javascript(
        "import lodash from 'lodash';\n"
        "lodash.set(obj, 'k', 1);\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/app.js", "language": "javascript",
             "call_graph": cg},
        ],
    }
    r = function_called(inv, "lodash.get")
    assert r.verdict == Verdict.NOT_CALLED
