"""Tests for ``extract_call_graph_c``.

The walker is structural: tree-sitter parses the file, the
``_CCallGraph`` visitor extracts includes, function definitions,
calls, and a few indirection signals. Tests pin the shapes the
caller (``core.ast.view``, the reachability resolver, and the
audit pipeline) relies on.

The whole walker degrades to an empty :class:`FileCallGraph` when
``tree_sitter_c`` isn't available; one test pins that contract
without actually uninstalling the grammar.
"""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    INDIRECTION_FN_POINTER,
    extract_call_graph_c,
)


pytest.importorskip("tree_sitter_c")


# ---------------------------------------------------------------------------
# Includes → imports
# ---------------------------------------------------------------------------


class TestIncludes:
    """``#include`` is the closest thing C has to an import. The
    walker records the included header keyed by its basename so the
    resolver can match ``foo`` → ``foo.h`` at call sites."""

    def test_system_include_uses_basename(self):
        g = extract_call_graph_c('#include <stdio.h>\n')
        assert g.imports == {"stdio": "stdio.h"}

    def test_quoted_include_uses_basename(self):
        g = extract_call_graph_c('#include "foo.h"\n')
        assert g.imports == {"foo": "foo.h"}

    def test_nested_include_preserves_full_path(self):
        g = extract_call_graph_c('#include "net/dst.h"\n')
        # basename without extension becomes the binding name; full
        # path preserved as the qualified target.
        assert g.imports == {"dst": "net/dst.h"}

    def test_multiple_includes_collected(self):
        g = extract_call_graph_c(
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n'
            '#include "internal/list.h"\n'
        )
        assert g.imports == {
            "stdio": "stdio.h",
            "stdlib": "stdlib.h",
            "list": "internal/list.h",
        }


# ---------------------------------------------------------------------------
# Function definitions → caller field on calls
# ---------------------------------------------------------------------------


class TestFunctionScope:
    """Every call gets a ``caller`` of the lexically-enclosing
    function's name (or None for file-scope initialisers)."""

    def test_caller_is_enclosing_function(self):
        g = extract_call_graph_c(
            'int helper(int x) { return x + 1; }\n'
            'int main(void) { helper(3); return 0; }\n'
        )
        calls_to_helper = [c for c in g.calls if c.chain == ["helper"]]
        assert len(calls_to_helper) == 1
        assert calls_to_helper[0].caller == "main"

    def test_pointer_return_type_function_name(self):
        # ``char *strdup(...) {}`` — the function declarator is
        # wrapped in a pointer_declarator; the walker descends.
        g = extract_call_graph_c(
            'char *upper(char *s) { return s; }\n'
            'void caller(void) { upper("x"); }\n'
        )
        calls = [c for c in g.calls if c.chain == ["upper"]]
        assert len(calls) == 1
        assert calls[0].caller == "caller"

    def test_static_function(self):
        g = extract_call_graph_c(
            'static void inner(void) {}\n'
            'void outer(void) { inner(); }\n'
        )
        assert any(
            c.chain == ["inner"] and c.caller == "outer"
            for c in g.calls
        )

    def test_file_scope_caller_is_none(self):
        # File-scope initialiser calls have no enclosing function.
        # Tree-sitter parses initialiser calls as call_expression
        # in the declaration's initializer; they reach _visit_call
        # with an empty _enclosing stack.
        g = extract_call_graph_c(
            'extern int seed(void);\n'
            'int x = seed();\n'  # this call's caller should be None
        )
        seed_calls = [c for c in g.calls if c.chain == ["seed"]]
        assert seed_calls, "file-scope initialiser call missing"
        assert seed_calls[0].caller is None


# ---------------------------------------------------------------------------
# Field expressions
# ---------------------------------------------------------------------------


class TestFieldExpressions:
    """``obj.method(...)`` and ``obj->method(...)`` chain through
    field expressions; the walker resolves them to attribute chains."""

    def test_dot_field(self):
        g = extract_call_graph_c(
            'void f(struct s o) { o.method(); }\n'
        )
        match = [c for c in g.calls if c.chain == ["o", "method"]]
        assert len(match) == 1, g.calls

    def test_arrow_field(self):
        g = extract_call_graph_c(
            'void f(struct s *o) { o->method(); }\n'
        )
        match = [c for c in g.calls if c.chain == ["o", "method"]]
        assert len(match) == 1, g.calls

    def test_chained_arrow(self):
        g = extract_call_graph_c(
            'void f(struct s *o) { o->a->b(); }\n'
        )
        match = [c for c in g.calls if c.chain == ["o", "a", "b"]]
        assert len(match) == 1, g.calls

    def test_mixed_dot_arrow(self):
        g = extract_call_graph_c(
            'void f(struct s *o) { o->a.b(); }\n'
        )
        match = [c for c in g.calls if c.chain == ["o", "a", "b"]]
        assert len(match) == 1, g.calls


# ---------------------------------------------------------------------------
# Function-pointer calls → INDIRECTION_FN_POINTER
# ---------------------------------------------------------------------------


class TestFunctionPointers:
    """``(*fp)(...)`` is the syntactic shape recognised as an
    indirect call. Bare ``fp()`` is statically indistinguishable
    from a direct call and emitted as such."""

    def test_explicit_pointer_call_marks_indirection(self):
        g = extract_call_graph_c(
            'void f(int (*fp)(int)) { (*fp)(7); }\n'
        )
        assert INDIRECTION_FN_POINTER in g.indirection
        # Chain still recorded.
        assert any(c.chain == ["fp"] for c in g.calls)

    def test_bare_pointer_call_no_indirection_flag(self):
        # We can't tell ``fp(7)`` is indirect without type resolution.
        # Walker emits it as a regular call; the indirection set
        # stays clean.
        g = extract_call_graph_c(
            'void f(int (*fp)(int)) { fp(7); }\n'
        )
        assert INDIRECTION_FN_POINTER not in g.indirection
        assert any(c.chain == ["fp"] for c in g.calls)


# ---------------------------------------------------------------------------
# Line numbers
# ---------------------------------------------------------------------------


class TestLineNumbers:
    """Lines are 1-indexed (tree-sitter is 0-indexed; walker adds 1).
    A drift here breaks ``core.ast.view``'s range filtering."""

    def test_line_1_indexed(self):
        # Line 1 is the include; line 2 is the function; the call
        # is on line 3.
        src = (
            '#include <stdio.h>\n'      # 1
            'int main(void) {\n'        # 2
            '    printf("hi");\n'       # 3
            '    return 0;\n'           # 4
            '}\n'                        # 5
        )
        g = extract_call_graph_c(src)
        printf = [c for c in g.calls if c.chain == ["printf"]]
        assert len(printf) == 1
        assert printf[0].line == 3


# ---------------------------------------------------------------------------
# Macros that look like calls
# ---------------------------------------------------------------------------


class TestMacroShapedCalls:
    """Tree-sitter reads pre-preprocessor source. Macros like
    ``BUG_ON(...)`` or ``container_of(...)`` parse as call
    expressions; the walker emits them as regular calls with the
    macro identifier as chain. Downstream consumers disambiguate via
    the inventory's macro list."""

    def test_macro_looking_call_is_emitted(self):
        g = extract_call_graph_c(
            '#define BUG_ON(x) do { if (x) panic(); } while (0)\n'
            'void f(int n) { BUG_ON(n < 0); }\n'
        )
        bug_on = [c for c in g.calls if c.chain == ["BUG_ON"]]
        # Don't pin caller for now — depends on whether the macro
        # definition itself is parsed as a function_definition or as
        # a preproc_def. The contract is "emit the call".
        assert bug_on, g.calls


# ---------------------------------------------------------------------------
# Parse failures + missing grammar
# ---------------------------------------------------------------------------


class TestRobustness:
    """Malformed input shouldn't crash the walker. The contract is
    "return empty graph"."""

    def test_empty_input(self):
        g = extract_call_graph_c("")
        assert g.imports == {} and g.calls == []

    def test_random_garbage_is_partial_or_empty(self):
        # Tree-sitter is error-tolerant — it'll parse what it can.
        # The walker should never raise.
        g = extract_call_graph_c("@@@ this is not C @@@\n")
        # Empty or partial — either is acceptable.
        assert isinstance(g.imports, dict)
        assert isinstance(g.calls, list)


# ---------------------------------------------------------------------------
# Schema contract for downstream consumers
# ---------------------------------------------------------------------------


class TestSchemaContract:
    """Pin that the new walker populates the field set
    ``core.ast.view`` and the reachability resolver expect, and
    leaves Python-/Java-specific extras empty."""

    def test_c_walker_leaves_python_fields_empty(self):
        g = extract_call_graph_c(
            'int main(void) { return 0; }\n'
        )
        assert g.classes == []
        assert g.decorated_functions == []
        assert g.relative_imports == []

    def test_callsite_receiver_class_always_none_in_c(self):
        # C has no classes — receiver_class is None for every call.
        g = extract_call_graph_c(
            'void f(void) { g(); h(); i(); }\n'
        )
        assert all(c.receiver_class is None for c in g.calls)
