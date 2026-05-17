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


# ---------------------------------------------------------------------------
# package_declaration + class capture
# ---------------------------------------------------------------------------


def test_package_declaration_captured():
    """``package com.foo.bar;`` lands on ``graph.package_name`` so
    the resolver can canonicalise method calls to their fully-
    qualified Java names."""
    g = extract_call_graph_java(
        "package com.foo.bar;\nclass C {}\n"
    )
    assert g.package_name == "com.foo.bar"


def test_unnamed_package_stays_none():
    """No ``package`` declaration → ``package_name`` is None."""
    g = extract_call_graph_java("class C {}\n")
    assert g.package_name is None


def test_class_declaration_captures_bases_and_methods():
    """``class Service extends Base implements Logger, Audit``
    captures all three bases + each method definition (with line
    numbers) on the ClassDef."""
    g = extract_call_graph_java(
        "package com.foo;\n"
        "public class Service extends Base "
        "implements Logger, Audit {\n"
        "    public void run() {}\n"
        "    private void helper() {}\n"
        "}\n"
    )
    assert len(g.classes) == 1
    cls = g.classes[0]
    assert cls.name == "Service"
    assert cls.bases == ["Base", "Logger", "Audit"]
    method_names = [m[0] for m in cls.methods]
    assert method_names == ["run", "helper"]
    assert cls.nested is False


def test_interface_declaration_captured():
    """``interface I extends A, B`` lands on classes with bases
    populated."""
    g = extract_call_graph_java(
        "package x;\n"
        "interface I extends A, B {\n"
        "    default void doIt() {}\n"
        "}\n"
    )
    assert len(g.classes) == 1
    cls = g.classes[0]
    assert cls.name == "I"
    assert cls.bases == ["A", "B"]
    assert ("doIt", 3) in cls.methods


def test_nested_class_marked_nested():
    """Inner class inside another class → ``nested=True``."""
    g = extract_call_graph_java(
        "package x;\n"
        "class Outer {\n"
        "    static class Inner {\n"
        "        void f() {}\n"
        "    }\n"
        "}\n"
    )
    outer = next(c for c in g.classes if c.name == "Outer")
    inner = next(c for c in g.classes if c.name == "Inner")
    assert outer.nested is False
    assert inner.nested is True


def test_implicit_receiver_call_tags_receiver_class():
    """``foo()`` inside a class method → ``receiver_class``
    points at the enclosing class."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C {\n"
        "    void run() { helper(); }\n"
        "    void helper() {}\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["helper"])
    assert call.receiver_class == "C"
    assert call.caller == "run"


def test_this_dot_method_tags_receiver_class():
    """``this.helper()`` is a known-self dispatch — tag
    receiver_class same as implicit-receiver."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C {\n"
        "    void run() { this.helper(); }\n"
        "    void helper() {}\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["this", "helper"])
    assert call.receiver_class == "C"


def test_super_dot_method_leaves_receiver_class_none():
    """``super.foo()`` dispatches on the parent class. Leave
    receiver_class=None and let the resolver search the
    hierarchy."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C extends Base {\n"
        "    void run() { super.bake(); }\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["super", "bake"])
    assert call.receiver_class is None


def test_qualified_call_leaves_receiver_class_none():
    """``Util.shared()`` — receiver isn't this/self, so no
    narrowing on the enclosing class."""
    g = extract_call_graph_java(
        "package x;\n"
        "class C {\n"
        "    void run() { Util.shared(); }\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["Util", "shared"])
    assert call.receiver_class is None


def test_constructor_registered_on_class():
    """Constructor definitions land on ``ClassDef.methods`` with
    the class name as the method name."""
    g = extract_call_graph_java(
        "package x;\n"
        "class Foo {\n"
        "    public Foo() {}\n"
        "    public Foo(int x) {}\n"
        "}\n"
    )
    cls = g.classes[0]
    method_names = [m[0] for m in cls.methods]
    assert method_names.count("Foo") == 2


def test_java_record_declaration_captured():
    """Java 14+ ``record Point(int x, int y) implements P { ... }``
    shares class_body shape with class_declaration — capture
    methods and implements bases."""
    g = extract_call_graph_java(
        "package x;\n"
        "record Point(int x, int y) implements P {\n"
        "    int area() { return 0; }\n"
        "}\n"
    )
    pt = next(c for c in g.classes if c.name == "Point")
    assert "P" in pt.bases
    method_names = [m[0] for m in pt.methods]
    assert "area" in method_names


def test_java_enum_declaration_captured():
    """``enum Color { RED, GREEN; int code() {...} }`` — body
    holds constants AND methods. Capture as ClassDef."""
    g = extract_call_graph_java(
        "package x;\n"
        "enum Color {\n"
        "    RED, GREEN;\n"
        "    int code() { return 0; }\n"
        "}\n"
    )
    color = next(c for c in g.classes if c.name == "Color")
    method_names = [m[0] for m in color.methods]
    assert "code" in method_names


def test_resolver_no_module_level_collision_for_java():
    """Pathological shape: file A is ``package com.example.Util;``
    + class X with method helper. File B is ``package
    com.example;`` + class Util with method helper. Without the
    Java-specific guard, both files would seed
    ``qualified_to_internal['com.example.Util.helper']`` via
    setdefault — the first file in iteration order would win and
    the other's Util.helper would canonicalise wrong. The fix
    skips the module-level ``<pkg>.<fn>`` candidate for Java
    (which has no module-level functions anyway)."""
    from core.inventory.reachability import _get_or_build_index

    a = extract_call_graph_java(
        "package com.example.Util;\nclass X { void helper() {} }\n"
    ).to_dict()
    b = extract_call_graph_java(
        "package com.example;\nclass Util { void helper() {} }\n"
    ).to_dict()
    inv = {"files": [
        {"path": "src/com/example/Util/X.java", "language": "java",
         "call_graph": a,
         "items": [{"kind": "function", "name": "helper",
                    "line_start": 2}]},
        {"path": "src/com/example/Util.java", "language": "java",
         "call_graph": b,
         "items": [{"kind": "function", "name": "helper",
                    "line_start": 2}]},
    ]}
    idx = _get_or_build_index(inv, exclude_test_files=False)
    # com.example.Util.helper must canonicalise to Util.java
    # (the Util class's helper), NOT to X.java (whose package
    # happens to spell ``com.example.Util``).
    target = idx.qualified_to_internal.get("com.example.Util.helper")
    assert target is not None
    assert target.file_path == "src/com/example/Util.java", (
        f"collision — Util.helper wrongly canonicalised to "
        f"{target.file_path}"
    )


def test_function_called_resolves_java_implicit_this():
    """``helper()`` from inside ``Svc.run()`` is an implicit-this
    dispatch — Java has no module-level functions. The chain head
    isn't in the import map (no ``import helper``), so the
    chain-based ``_resolves_to`` path can't see it. The
    receiver_class fast-path on ``function_called`` synthesises
    ``<pkg>.<receiver_class>.<tail>`` and compares to the target."""
    from core.inventory.reachability import Verdict, function_called

    cg = extract_call_graph_java(
        "package com.example;\n"
        "public class Svc {\n"
        "    public void run() { helper(); }\n"
        "    public void helper() {}\n"
        "}\n"
    )
    inv = {"files": [{"path": "src/com/example/Svc.java",
                       "language": "java",
                       "call_graph": cg.to_dict()}]}
    # Right class — CALLED
    r = function_called(inv, "com.example.Svc.helper")
    assert r.verdict == Verdict.CALLED

    # Different class same method name — NOT_CALLED (narrowing
    # held: receiver_class tagged Svc, target asked Other).
    r = function_called(inv, "com.example.Other.helper")
    assert r.verdict == Verdict.NOT_CALLED


def test_resolver_cross_file_class_qualified():
    """Caller in file A invokes ``Util.helper()``; Util.java in
    file B declares ``package com.example; class Util { static
    void helper() {} }``. The resolver canonicalises the callee
    to ``com.example.Util.helper`` (class-qualified) and matches
    the internal definition that lives in B."""
    from core.inventory.reachability import Verdict, function_called

    util = extract_call_graph_java(
        "package com.example;\n"
        "public class Util {\n"
        "    public static void helper() {}\n"
        "}\n"
    ).to_dict()
    caller = extract_call_graph_java(
        "package com.example.client;\n"
        "import com.example.Util;\n"
        "class Client { void m() { Util.helper(); } }\n"
    ).to_dict()
    inv = {
        "files": [
            {"path": "src/com/example/Util.java", "language": "java",
             "call_graph": util},
            {"path": "src/com/example/client/Client.java",
             "language": "java",
             "call_graph": caller},
        ],
    }
    r = function_called(inv, "com.example.Util.helper")
    assert r.verdict == Verdict.CALLED
