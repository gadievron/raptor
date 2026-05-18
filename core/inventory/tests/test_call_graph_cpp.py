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


# ---------------------------------------------------------------------------
# Namespace capture
# ---------------------------------------------------------------------------


class TestNamespaceCapture:
    """``namespace ns { ... }`` → ``graph.package_name``. Enables
    resolver canonicalisation of ``ns::Class::method`` calls."""

    def test_simple_namespace(self):
        g = extract_call_graph_cpp(
            "namespace ns {\n    class C { void m() {} };\n}\n"
        )
        assert g.package_name == "ns"
        assert any(c.name == "C" for c in g.classes)

    def test_nested_namespace_specifier(self):
        """``namespace a::b { ... }`` is one node with
        ``nested_namespace_specifier``."""
        g = extract_call_graph_cpp("namespace a::b { class C {}; }\n")
        assert g.package_name == "a.b"

    def test_namespace_within_namespace(self):
        """Pushed segments concatenate; inner gets the dotted form."""
        g = extract_call_graph_cpp(
            "namespace outer {\n"
            "    namespace inner { class C {}; }\n"
            "}\n"
        )
        assert g.package_name == "outer.inner"

    def test_anonymous_namespace(self):
        """``namespace { ... }`` (no name) — internal linkage; no
        qualified-name prefix."""
        g = extract_call_graph_cpp("namespace { void f() {} }\n")
        assert g.package_name is None

    def test_no_namespace(self):
        g = extract_call_graph_cpp("class C { void m() {} };\n")
        assert g.package_name is None


# ---------------------------------------------------------------------------
# Implicit-this receiver_class fix (inline method registered pre-walk)
# ---------------------------------------------------------------------------


class TestImplicitThisReceiverClass:
    """Pre-pass now collects inline ``function_definition`` nodes
    too, so a bare ``helper()`` call from a sibling method walked
    earlier still sees ``helper`` in the methods list and tags
    receiver_class."""

    def test_inline_method_called_before_sibling_defined(self):
        g = extract_call_graph_cpp(
            "class Service {\n"
            "public:\n"
            "    void run() { helper(); }\n"
            "    void helper() {}\n"
            "};\n"
        )
        call = next(c for c in g.calls if c.chain == ["helper"])
        assert call.receiver_class == "Service"
        assert call.caller == "run"

    def test_method_definition_not_duplicated(self):
        """Inline method shouldn't appear twice in ClassDef.methods."""
        g = extract_call_graph_cpp("class C { void m() {} };\n")
        cls = next(c for c in g.classes if c.name == "C")
        names = [m[0] for m in cls.methods]
        assert names.count("m") == 1

    def test_struct_implicit_this_works(self):
        """Struct is class with default-public access; same
        implicit-this rules apply."""
        g = extract_call_graph_cpp(
            "struct S {\n"
            "    void method() { helper(); }\n"
            "    void helper() {}\n"
            "};\n"
        )
        call = next(c for c in g.calls if c.chain == ["helper"])
        assert call.receiver_class == "S"


# ---------------------------------------------------------------------------
# function_called consumer wiring — receiver_class fast-path resolves
# C++ implicit-this calls via the new ``<ns>.<Class>.<method>`` synthesis
# ---------------------------------------------------------------------------


class TestFunctionCalledIntegration:
    """The receiver_class fast-path in ``function_called`` (added
    alongside the multi-lang substrate) now sees C++ classes too —
    when a bare or ``this->`` call's chain tail matches the target
    and the call carries ``receiver_class``, the resolver
    synthesises ``<file_pkg>.<Class>.<tail>`` and compares against
    the query."""

    def test_namespace_class_method_resolves(self):
        """``ns::Foo::bar()`` invoked via implicit-this from
        ``ns::Foo::other()`` — resolver synthesises
        ``ns.Foo.bar`` from the file's namespace + receiver_class."""
        from core.inventory.reachability import (
            Verdict, function_called,
        )

        g = extract_call_graph_cpp(
            "namespace ns {\n"
            "    class Foo {\n"
            "    public:\n"
            "        void other() { bar(); }\n"
            "        void bar() {}\n"
            "    };\n"
            "}\n"
        )
        inv = {"files": [{"path": "src/foo.cpp", "language": "cpp",
                           "call_graph": g.to_dict()}]}
        r = function_called(inv, "ns.Foo.bar")
        assert r.verdict == Verdict.CALLED
        # Wrong class — same method name on a sibling → NOT_CALLED
        r = function_called(inv, "ns.Other.bar")
        assert r.verdict == Verdict.NOT_CALLED


# ---------------------------------------------------------------------------
# Templated callees + constructor initialiser lists
# ---------------------------------------------------------------------------


class TestTemplatedCallees:
    """``get<int>()`` and ``this->put<double>()`` callees wrap their
    name in ``template_function`` / ``template_method`` nodes. The
    chain extraction recovers the inner identifier; template args
    are dropped (parity with what other languages do — call
    matching is by name, not by argument types)."""

    def test_template_function_bare_call(self):
        """``get<int>()`` → chain ``["get"]``."""
        g = extract_call_graph_cpp(
            "void f() { get<int>(); }\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["get"] in chains

    def test_template_method_via_this(self):
        """``this->put<double>(1.0)`` → chain ``["this", "put"]``
        with ``receiver_class`` tagged."""
        g = extract_call_graph_cpp(
            "class C {\n"
            "public:\n"
            "    template<typename T> void put(T x);\n"
            "    void use() { this->put<double>(1.0); }\n"
            "};\n"
        )
        call = next(c for c in g.calls if c.chain == ["this", "put"])
        assert call.receiver_class == "C"

    def test_template_method_in_class_implicit_this(self):
        """``get<int>()`` inside a sibling method of a class that
        declares a template method ``get`` → receiver_class tag
        fires via the implicit-this rule. Requires the pre-pass
        to unwrap ``template_declaration`` so ``get`` registers as
        a method on the class."""
        g = extract_call_graph_cpp(
            "class C {\n"
            "public:\n"
            "    template<typename T> T get();\n"
            "    void use() { get<int>(); }\n"
            "};\n"
        )
        cls = next(c for c in g.classes if c.name == "C")
        method_names = [m[0] for m in cls.methods]
        assert "get" in method_names
        call = next(c for c in g.calls if c.chain == ["get"])
        assert call.receiver_class == "C"


class TestConstructorInitialiserList:
    """``Derived(int x) : Base(x), member_(0) {}`` — the
    field_initializer_list entries become call sites with the
    base/member name as the chain head. Distinguishing base-
    constructor delegation from data-member initialisation
    requires symbol-table access we don't have at extract time,
    so both shapes emit; the resolver's class-context narrowing
    keeps the noise contained."""

    def test_base_constructor_call_in_init_list(self):
        """``: Base(x)`` records a call to ``Base`` — load-bearing
        for SCA queries against subclass-of-known-base sinks."""
        g = extract_call_graph_cpp(
            "class Derived : public Base {\n"
            "public:\n"
            "    Derived(int x) : Base(x) {}\n"
            "};\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["Base"] in chains

    def test_member_initialiser_emits_call(self):
        """``member_(0)`` emits ``chain=["member_"]``. Cost is some
        noise on data-member inits; benefit is uniform handling
        of base-constructor delegation."""
        g = extract_call_graph_cpp(
            "class C {\n"
            "public:\n"
            "    C(int x) : member_(x) {}\n"
            "private:\n"
            "    int member_;\n"
            "};\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["member_"] in chains

    def test_nested_call_inside_init_arg_still_walked(self):
        """``member_(helper(x))`` should yield both ``member_``
        and ``helper`` calls — the fall-through walks the
        argument_list."""
        g = extract_call_graph_cpp(
            "class C {\n"
            "public:\n"
            "    C(int x) : member_(helper(x)) {}\n"
            "};\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["member_"] in chains
        assert ["helper"] in chains

    def test_init_list_caller_is_constructor(self):
        """Calls inside the init list attribute to the enclosing
        constructor (the function_definition pushes its name)."""
        g = extract_call_graph_cpp(
            "class Derived : public Base {\n"
            "public:\n"
            "    Derived(int x) : Base(x) {}\n"
            "};\n"
        )
        call = next(c for c in g.calls if c.chain == ["Base"])
        assert call.caller == "Derived"

    def test_templated_base_class_captured(self):
        """``class D : public B<T>`` → base ``B`` (template args
        erased, parity with template_function callee handling)."""
        g = extract_call_graph_cpp(
            "template<typename T>\n"
            "class D : public B<T> {};\n"
        )
        d = next(c for c in g.classes if c.name == "D")
        assert "B" in d.bases

    def test_templated_base_constructor_in_init_list(self):
        """``Derived() : B<T>()`` — the init list entry uses
        ``template_method`` instead of ``field_identifier``;
        recover the inner identifier so the base-constructor
        call still emits."""
        g = extract_call_graph_cpp(
            "template<typename T>\n"
            "class D : public B<T> {\n"
            "public:\n"
            "    D() : B<T>() {}\n"
            "};\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["B"] in chains


# ---------------------------------------------------------------------------
# Cross-file resolver — fully-qualified-call fast-path
# ---------------------------------------------------------------------------


class TestCrossFileFullyQualifiedCall:
    """C++ ``ns::Util::helper()`` doesn't go through any import
    map — namespace names are used directly. The import-map path
    in function_called can't resolve such chains; the
    receiver_class fast-path doesn't fire either (the chain isn't
    a ``this->X()`` or implicit-this shape). The fully-qualified
    fast-path catches them: strict equality of the joined dotted
    chain to the target → CALLED with no false-positive risk."""

    def test_cross_file_namespace_class_method(self):
        """File A defines ``ns::Util::helper()``; file B calls
        ``ns::Util::helper()`` directly. The resolver matches via
        the dotted-chain fast-path, NOT via the import map."""
        from core.inventory.reachability import (
            Verdict, function_called,
        )

        util_cg = extract_call_graph_cpp(
            "namespace ns {\n"
            "    class Util {\n"
            "    public:\n"
            "        static void helper() {}\n"
            "    };\n"
            "}\n"
        ).to_dict()
        caller_cg = extract_call_graph_cpp(
            "void use() { ns::Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [
            {"path": "src/util.cpp", "language": "cpp",
             "call_graph": util_cg,
             "items": [{"kind": "function", "name": "helper",
                        "line_start": 4}]},
            {"path": "src/main.cpp", "language": "cpp",
             "call_graph": caller_cg,
             "items": [{"kind": "function", "name": "use",
                        "line_start": 1}]},
        ]}
        r = function_called(inv, "ns.Util.helper")
        assert r.verdict == Verdict.CALLED

    def test_wrong_class_not_called(self):
        """Strict equality: target ``ns.Other.helper`` doesn't
        match chain ``ns::Util::helper`` — must return
        NOT_CALLED."""
        from core.inventory.reachability import (
            Verdict, function_called,
        )

        caller_cg = extract_call_graph_cpp(
            "void use() { ns::Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [{"path": "src/main.cpp", "language": "cpp",
                           "call_graph": caller_cg}]}
        r = function_called(inv, "ns.Other.helper")
        assert r.verdict == Verdict.NOT_CALLED

    def test_partial_chain_match_not_false_positive(self):
        """Chain ``["Util", "helper"]`` (no namespace prefix) must
        NOT match target ``ns.Util.helper``. Strict equality
        guards against partial-match false positives."""
        from core.inventory.reachability import (
            Verdict, function_called,
        )

        caller_cg = extract_call_graph_cpp(
            "void use() { Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [{"path": "src/main.cpp", "language": "cpp",
                           "call_graph": caller_cg}]}
        r = function_called(inv, "ns.Util.helper")
        assert r.verdict == Verdict.NOT_CALLED


# ---------------------------------------------------------------------------
# Compound-literal receivers + dependent-name disambiguation
# ---------------------------------------------------------------------------


class TestCompoundLiteralReceiver:
    """``vector<int>{}.size()`` / ``Foo{}.method()`` — the receiver
    is an unnamed temporary. Recover the type name as the chain
    head so a target like ``vector.size`` matches; template args
    are erased (same as template_function callees). Loses
    namespace prefix (would need symbol-table access)."""

    def test_template_temporary_method_call(self):
        """``vector<int>{}.size()`` → ``["vector", "size"]``."""
        g = extract_call_graph_cpp(
            "void f() { vector<int>{}.size(); }\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["vector", "size"] in chains

    def test_non_template_temporary_method_call(self):
        """``Foo{}.method()`` → ``["Foo", "method"]``."""
        g = extract_call_graph_cpp(
            "void f() { Foo{}.method(); }\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["Foo", "method"] in chains


class TestDependentNameDisambiguation:
    """``c.template put<int>()`` — the ``template`` keyword
    disambiguates dependent names in template functions. The
    grammar wraps the call's name in a ``dependent_name`` node
    containing a ``template_method`` containing the
    ``field_identifier``. Recover the inner name, drop template
    args."""

    def test_dependent_template_method_call(self):
        g = extract_call_graph_cpp(
            "template<typename T> void f(T& c) {\n"
            "    c.template put<int>();\n"
            "}\n"
        )
        chains = [c.chain for c in g.calls]
        assert ["c", "put"] in chains


# ---------------------------------------------------------------------------
# callers_of / callees_of index-side fast-path
# ---------------------------------------------------------------------------


class TestCallersCalleesIndexParity:
    """Index-side equivalent of the function_called
    fully-qualified-call fast-path: C++ ``ns::Util::helper()`` chains
    land in the definitive forward/reverse graph (not just
    method_match_overinclusive) when the dotted chain matches a
    seeded ``qualified_to_internal`` entry. Without this, callers_of
    returned the C++ caller in method_match instead of definitive."""

    def test_callers_of_namespace_class_method_definitive(self):
        from core.inventory.reachability import (
            callers_of, InternalFunction,
        )

        util = extract_call_graph_cpp(
            "namespace ns {\n"
            "    class Util {\n"
            "    public:\n"
            "        static void helper() {}\n"
            "    };\n"
            "}\n"
        ).to_dict()
        caller = extract_call_graph_cpp(
            "void use() { ns::Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [
            {"path": "src/util.cpp", "language": "cpp",
             "call_graph": util,
             "items": [{"kind": "function", "name": "helper",
                        "line_start": 4}]},
            {"path": "src/main.cpp", "language": "cpp",
             "call_graph": caller,
             "items": [{"kind": "function", "name": "use",
                        "line_start": 1}]},
        ]}
        target = InternalFunction(
            file_path="src/util.cpp", name="helper", line=4,
        )
        r = callers_of(inv, target, exclude_test_files=False)
        # Caller must be in definitive, not method_match.
        assert any(
            c.file_path == "src/main.cpp" for c in r.definitive
        ), (
            f"caller not in definitive — "
            f"definitive={r.definitive}, "
            f"method_match={r.method_match_overinclusive}"
        )

    def test_callees_of_namespace_class_method_definitive(self):
        """Symmetric: callees_of(use) lists ns::Util::helper as
        a definitive callee."""
        from core.inventory.reachability import (
            callees_of, InternalFunction,
        )

        util = extract_call_graph_cpp(
            "namespace ns {\n"
            "    class Util {\n"
            "    public:\n"
            "        static void helper() {}\n"
            "    };\n"
            "}\n"
        ).to_dict()
        caller = extract_call_graph_cpp(
            "void use() { ns::Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [
            {"path": "src/util.cpp", "language": "cpp",
             "call_graph": util,
             "items": [{"kind": "function", "name": "helper",
                        "line_start": 4}]},
            {"path": "src/main.cpp", "language": "cpp",
             "call_graph": caller,
             "items": [{"kind": "function", "name": "use",
                        "line_start": 1}]},
        ]}
        source = InternalFunction(
            file_path="src/main.cpp", name="use", line=1,
        )
        r = callees_of(inv, source, exclude_test_files=False)
        assert any(
            getattr(c, "file_path", None) == "src/util.cpp"
            for c in r.definitive
        )

    def test_partial_chain_stays_in_method_match(self):
        """Chain ``["Util", "helper"]`` (no namespace prefix) does
        NOT match the seeded ``ns.Util.helper`` qualified name —
        falls through to method_match_overinclusive. Strict
        equality guards against over-promoting partial matches."""
        from core.inventory.reachability import (
            callers_of, InternalFunction,
        )

        util = extract_call_graph_cpp(
            "namespace ns {\n"
            "    class Util {\n"
            "    public:\n"
            "        static void helper() {}\n"
            "    };\n"
            "}\n"
        ).to_dict()
        caller = extract_call_graph_cpp(
            "void use() { Util::helper(); }\n"
        ).to_dict()
        inv = {"files": [
            {"path": "src/util.cpp", "language": "cpp",
             "call_graph": util,
             "items": [{"kind": "function", "name": "helper",
                        "line_start": 4}]},
            {"path": "src/main.cpp", "language": "cpp",
             "call_graph": caller,
             "items": [{"kind": "function", "name": "use",
                        "line_start": 1}]},
        ]}
        target = InternalFunction(
            file_path="src/util.cpp", name="helper", line=4,
        )
        r = callers_of(inv, target, exclude_test_files=False)
        # Partial chain stays in method_match (over-inclusive),
        # NOT promoted to definitive.
        assert not any(
            c.file_path == "src/main.cpp" for c in r.definitive
        )
