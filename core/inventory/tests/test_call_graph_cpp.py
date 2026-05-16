"""Tests for ``extract_call_graph_cpp``.

The C++ walker subclasses the C base, so the C tests cover the
shared shapes (includes, function pointers, field expressions).
This file pins the C++-specific extensions:

  * ``class_specifier`` / ``struct_specifier`` → ``ClassDef``
  * Method declarations populate ``ClassDef.methods``
  * ``qualified_identifier`` (``Foo::bar``, ``std::cout``)
  * ``this->member`` → ``receiver_class`` tag
  * Bare in-class call to a sibling method → ``receiver_class``
  * Out-of-line definitions (``int Foo::bar() {...}``) push a
    synthetic class so calls inside get the right receiver tag
  * Destructors
  * Bases with access specifiers
  * Namespaces (transparent)
"""

from __future__ import annotations

import pytest

from core.inventory.call_graph import (
    INDIRECTION_FN_POINTER,
    extract_call_graph_cpp,
)


pytest.importorskip("tree_sitter_cpp")


# ---------------------------------------------------------------------------
# Classes — ClassDef entries
# ---------------------------------------------------------------------------


class TestClassDef:
    def test_class_recorded(self):
        g = extract_call_graph_cpp(
            'class Widget { public: void f(); };\n'
        )
        assert len(g.classes) == 1
        assert g.classes[0].name == "Widget"
        assert g.classes[0].nested is False

    def test_struct_recorded(self):
        # struct_specifier should produce a ClassDef the same way
        # class_specifier does — C++ semantics for structs match
        # classes (modulo default access).
        g = extract_call_graph_cpp(
            'struct S { void f(); };\n'
        )
        names = [c.name for c in g.classes]
        assert "S" in names, g.classes

    def test_nested_class_marked_nested(self):
        g = extract_call_graph_cpp(
            'class Outer { class Inner { void f(); }; };\n'
        )
        inner = next(c for c in g.classes if c.name == "Inner")
        outer = next(c for c in g.classes if c.name == "Outer")
        assert outer.nested is False
        assert inner.nested is True

    def test_anonymous_struct_skipped_in_class_list(self):
        # ``struct { int x; } var;`` has no type identifier. We
        # don't record an anonymous ClassDef but still descend so
        # any nested calls aren't lost.
        g = extract_call_graph_cpp(
            'struct { int x; } var;\n'
            'void f() { use(var); }\n'
        )
        assert g.classes == []
        # The call inside f is still picked up.
        assert any(c.chain == ["use"] for c in g.calls)


# ---------------------------------------------------------------------------
# Method declarations → methods list
# ---------------------------------------------------------------------------


class TestMethods:
    def test_declared_methods_listed(self):
        g = extract_call_graph_cpp(
            'class W {\n'
            'public:\n'
            '    void setup();\n'
            '    int run(int x);\n'
            '};\n'
        )
        w = g.classes[0]
        names = [m[0] for m in w.methods]
        assert "setup" in names
        assert "run" in names

    def test_destructor_listed(self):
        # Destructors parse as ``declaration`` (no return type), not
        # as ``field_declaration`` — pin that the walker handles
        # both shapes.
        g = extract_call_graph_cpp(
            'class W { void f(); ~W(); };\n'
        )
        names = [m[0] for m in g.classes[0].methods]
        assert "~W" in names, g.classes[0].methods

    def test_method_line_recorded(self):
        g = extract_call_graph_cpp(
            'class W {\n'   # 1
            '    void f();\n'  # 2
            '};\n'             # 3
        )
        f = next(m for m in g.classes[0].methods if m[0] == "f")
        assert f[1] == 2


# ---------------------------------------------------------------------------
# Base classes
# ---------------------------------------------------------------------------


class TestBases:
    def test_single_base_no_access_specifier(self):
        g = extract_call_graph_cpp(
            'class D : Base { void f(); };\n'
        )
        assert g.classes[0].bases == ["Base"]

    def test_multiple_bases_with_access_specifiers(self):
        g = extract_call_graph_cpp(
            'class D : public A, protected B { void f(); };\n'
        )
        assert g.classes[0].bases == ["A", "B"]

    def test_qualified_base(self):
        g = extract_call_graph_cpp(
            'class D : public mixins::M { void f(); };\n'
        )
        assert g.classes[0].bases == ["mixins::M"]


# ---------------------------------------------------------------------------
# this->member — receiver_class tagging
# ---------------------------------------------------------------------------


class TestThisCall:
    def test_this_arrow_member_in_inline_method(self):
        g = extract_call_graph_cpp(
            'class W {\n'
            'public:\n'
            '    void setup() {}\n'
            '    void run() { this->setup(); }\n'
            '};\n'
        )
        call = next(c for c in g.calls if c.chain == ["this", "setup"])
        assert call.caller == "run"
        assert call.receiver_class == "W"

    def test_this_arrow_in_out_of_line_method(self):
        g = extract_call_graph_cpp(
            'class W { public: void setup(); void run(); };\n'
            'void W::setup() {}\n'
            'void W::run() { this->setup(); }\n'
        )
        call = next(c for c in g.calls if c.chain == ["this", "setup"])
        assert call.caller == "run"
        assert call.receiver_class == "W"


# ---------------------------------------------------------------------------
# Bare in-class call — receiver_class tagging
# ---------------------------------------------------------------------------


class TestBareInClassCall:
    """A bare ``method()`` call from inside a class member function
    refers to ``this->method()`` if ``method`` is a sibling member.
    The walker tags receiver_class iff the bare name is in the
    class's method list (collected in the pre-pass)."""

    def test_bare_call_to_sibling_method(self):
        g = extract_call_graph_cpp(
            'class W {\n'
            'public:\n'
            '    void helper() {}\n'
            '    void run() { helper(); }\n'
            '};\n'
        )
        helper_calls = [c for c in g.calls if c.chain == ["helper"]]
        # The relevant call site is inside W::run.
        from_run = [c for c in helper_calls if c.caller == "run"]
        assert from_run, helper_calls
        assert from_run[0].receiver_class == "W"

    def test_bare_call_to_free_function_no_receiver_tag(self):
        g = extract_call_graph_cpp(
            'void helper() {}\n'
            'class W {\n'
            'public:\n'
            '    void run() { helper(); }\n'  # not a W method
            '};\n'
        )
        helper_calls = [c for c in g.calls if c.chain == ["helper"]]
        from_run = [c for c in helper_calls if c.caller == "run"]
        assert from_run, helper_calls
        # ``helper`` is a free function, not a W method → no tag.
        assert from_run[0].receiver_class is None


# ---------------------------------------------------------------------------
# Qualified identifiers
# ---------------------------------------------------------------------------


class TestQualifiedIdentifier:
    def test_two_level_qualified_call(self):
        g = extract_call_graph_cpp(
            'namespace ns { void f() {} }\n'
            'void caller() { ns::f(); }\n'
        )
        # ns::f() → chain ["ns", "f"]
        call = next(c for c in g.calls if c.chain == ["ns", "f"])
        assert call.caller == "caller"

    def test_three_level_qualified_call(self):
        g = extract_call_graph_cpp(
            'void caller() { a::b::c(); }\n'
        )
        assert any(c.chain == ["a", "b", "c"] for c in g.calls)

    def test_std_namespace_call(self):
        # ``std::sort(...)`` should chain as ["std", "sort"].
        g = extract_call_graph_cpp(
            '#include <algorithm>\n'
            'void caller() { std::sort(nullptr, nullptr); }\n'
        )
        assert any(c.chain == ["std", "sort"] for c in g.calls)


# ---------------------------------------------------------------------------
# Out-of-line method definitions
# ---------------------------------------------------------------------------


class TestOutOfLineMethod:
    def test_out_of_line_definition_caller_is_method_name(self):
        # ``void W::run() {...}`` — the caller for inner calls is
        # ``run``, NOT ``W::run``. This matches the C-side convention
        # of caller = bare function name.
        g = extract_call_graph_cpp(
            'class W { public: void run(); };\n'
            'void W::run() { helper(); }\n'
        )
        calls = [c for c in g.calls if c.chain == ["helper"]]
        assert len(calls) == 1
        assert calls[0].caller == "run"

    def test_out_of_line_destructor_caller(self):
        g = extract_call_graph_cpp(
            'class W { public: ~W(); };\n'
            'W::~W() { cleanup(); }\n'
        )
        calls = [c for c in g.calls if c.chain == ["cleanup"]]
        assert len(calls) == 1
        assert calls[0].caller == "~W"


# ---------------------------------------------------------------------------
# C base inheritance — make sure C-style constructs still work
# ---------------------------------------------------------------------------


class TestCInheritanceInCpp:
    """The C++ walker subclasses the C base. Sanity-check that C-style
    constructs still extract correctly when the file is parsed as
    C++."""

    def test_includes_still_work(self):
        g = extract_call_graph_cpp(
            '#include <iostream>\n#include "foo.h"\n'
        )
        assert g.imports == {"iostream": "iostream", "foo": "foo.h"}

    def test_function_pointer_indirection(self):
        g = extract_call_graph_cpp(
            'void f(int (*fp)(int)) { (*fp)(7); }\n'
        )
        assert INDIRECTION_FN_POINTER in g.indirection

    def test_arrow_field_access_in_function(self):
        g = extract_call_graph_cpp(
            'struct s { int x; };\n'
            'void f(struct s *o) { o->x; }\n'
        )
        # No call site (just an expression statement) — sanity check
        # that the walker doesn't crash.
        assert isinstance(g.imports, dict)


# ---------------------------------------------------------------------------
# Schema fields for downstream consumers
# ---------------------------------------------------------------------------


class TestSchemaContract:
    def test_python_specific_fields_remain_empty(self):
        g = extract_call_graph_cpp(
            'class W { public: void f(); };\n'
        )
        assert g.decorated_functions == []
        assert g.relative_imports == []
