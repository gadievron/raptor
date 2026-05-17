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
    extract_call_graph_javascript,
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


# ---------------------------------------------------------------------------
# Rust class capture (struct / enum / trait / impl)
# ---------------------------------------------------------------------------


def test_rust_struct_recorded():
    """``struct Foo;`` lands on classes with empty bases and no
    methods (methods live in impl blocks)."""
    g = extract_call_graph_rust("struct Foo;\n")
    assert len(g.classes) == 1
    cls = g.classes[0]
    assert cls.name == "Foo"
    assert cls.bases == []
    assert cls.methods == []
    assert cls.nested is False


def test_rust_impl_methods_attach_to_struct():
    """``impl Foo { fn helper() {} }`` — helper attaches to the
    same ClassDef as ``struct Foo;``."""
    g = extract_call_graph_rust(
        "struct Foo;\n"
        "impl Foo {\n"
        "    fn new() -> Foo { Foo }\n"
        "    fn helper(&self) -> u32 { 0 }\n"
        "}\n"
    )
    foos = [c for c in g.classes if c.name == "Foo"]
    assert len(foos) == 1
    method_names = [m[0] for m in foos[0].methods]
    assert method_names == ["new", "helper"]


def test_rust_impl_trait_for_struct_binds_to_struct():
    """``impl Trait for Foo { fn m() {} }`` — m attaches to Foo,
    not Trait."""
    g = extract_call_graph_rust(
        "struct Foo;\n"
        "impl Greeter for Foo {\n"
        "    fn greet(&self) {}\n"
        "}\n"
    )
    foo = next(c for c in g.classes if c.name == "Foo")
    method_names = [m[0] for m in foo.methods]
    assert "greet" in method_names


def test_rust_trait_default_methods_captured():
    """Trait body holds function_signature_item for required
    methods and function_item for default methods. Both land
    on the trait's ClassDef."""
    g = extract_call_graph_rust(
        "trait Greeter {\n"
        "    fn greet(&self);\n"
        "    fn default_method(&self) {}\n"
        "}\n"
    )
    trait = next(c for c in g.classes if c.name == "Greeter")
    method_names = [m[0] for m in trait.methods]
    assert "greet" in method_names
    assert "default_method" in method_names


def test_rust_trait_supertraits_become_bases():
    """``trait T: A + B`` → bases=[A, B]."""
    g = extract_call_graph_rust(
        "trait T: A + B { fn m(&self); }\n"
    )
    t = next(c for c in g.classes if c.name == "T")
    assert "A" in t.bases
    assert "B" in t.bases


def test_rust_self_method_call_tags_receiver_class():
    """``self.foo()`` inside an impl block → receiver_class
    points at the impl target."""
    g = extract_call_graph_rust(
        "struct Foo;\n"
        "impl Foo {\n"
        "    fn helper(&self) {}\n"
        "    fn run(&self) { self.helper(); }\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["self", "helper"])
    assert call.receiver_class == "Foo"
    assert call.caller == "run"


def test_rust_qualified_call_no_receiver_class():
    """``Bar::new()`` — class-qualified call doesn't get
    narrowed by the enclosing impl context."""
    g = extract_call_graph_rust(
        "struct Bar;\n"
        "impl Bar {\n"
        "    fn new() -> Bar { Bar }\n"
        "}\n"
        "fn other() { Bar::new(); }\n"
    )
    call = next(c for c in g.calls if c.chain == ["Bar", "new"])
    assert call.receiver_class is None


def test_rust_mod_marks_inner_class_nested():
    """``mod foo { struct Bar; }`` — Bar is nested."""
    g = extract_call_graph_rust(
        "mod inner {\n"
        "    struct Bar;\n"
        "}\n"
    )
    bar = next(c for c in g.classes if c.name == "Bar")
    assert bar.nested is True


def test_rust_impl_on_external_type_synthesises_classdef():
    """``impl Foo`` where Foo is imported (no in-file struct
    declaration) — synthesise a ClassDef so cross-file method
    matching still works."""
    g = extract_call_graph_rust(
        "use other::Foo;\n"
        "impl Foo {\n"
        "    fn local_method(&self) {}\n"
        "}\n"
    )
    foo = next(c for c in g.classes if c.name == "Foo")
    method_names = [m[0] for m in foo.methods]
    assert "local_method" in method_names


# ---------------------------------------------------------------------------
# Ruby class + module capture
# ---------------------------------------------------------------------------


def test_ruby_class_with_superclass():
    """``class Service < Base`` → bases=['Base']."""
    g = extract_call_graph_ruby(
        "class Service < Base\n"
        "  def run; end\n"
        "  def helper; end\n"
        "end\n"
    )
    cls = next(c for c in g.classes if c.name == "Service")
    assert cls.bases == ["Base"]
    method_names = [m[0] for m in cls.methods]
    assert method_names == ["run", "helper"]


def test_ruby_class_no_superclass():
    """``class Foo\n  def m; end\nend`` → bases=[]."""
    g = extract_call_graph_ruby("class Foo\n  def m; end\nend\n")
    cls = next(c for c in g.classes if c.name == "Foo")
    assert cls.bases == []


def test_ruby_module_nesting_sets_package_name():
    """Nested ``module Foo; module Bar; ...`` populates the
    deepest dotted name on ``graph.package_name``."""
    g = extract_call_graph_ruby(
        "module Foo\n"
        "  module Bar\n"
        "    class Service; def m; end; end\n"
        "  end\n"
        "end\n"
    )
    assert g.package_name == "Foo.Bar"


def test_ruby_self_dot_method_tags_receiver_class():
    """``self.foo`` inside an instance method → receiver_class
    points at the enclosing class."""
    g = extract_call_graph_ruby(
        "class C\n"
        "  def run\n"
        "    self.helper\n"
        "  end\n"
        "  def helper; end\n"
        "end\n"
    )
    call = next(c for c in g.calls if c.chain == ["self", "helper"])
    assert call.receiver_class == "C"
    assert call.caller == "run"


def test_ruby_unqualified_call_no_receiver_class():
    """Bare-name calls in Ruby could be from a mixin / superclass
    / current class — we can't narrow without runtime semantics."""
    g = extract_call_graph_ruby(
        "class C\n"
        "  def run\n"
        "    helper()\n"
        "  end\n"
        "  def helper; end\n"
        "end\n"
    )
    call = next(c for c in g.calls if c.chain == ["helper"])
    assert call.receiver_class is None


# ---------------------------------------------------------------------------
# C# namespace + class capture
# ---------------------------------------------------------------------------


def test_csharp_namespace_captured():
    """``namespace Foo.Bar { ... }`` → package_name='Foo.Bar'."""
    g = extract_call_graph_csharp(
        "namespace Foo.Bar { class C {} }\n"
    )
    assert g.package_name == "Foo.Bar"


def test_csharp_class_with_base_list():
    """``class Service : Base, ILogger`` → bases=['Base', 'ILogger']."""
    g = extract_call_graph_csharp(
        "class Service : Base, ILogger {\n"
        "    public void Run() {}\n"
        "    private void Helper() {}\n"
        "}\n"
    )
    cls = next(c for c in g.classes if c.name == "Service")
    assert cls.bases == ["Base", "ILogger"]
    method_names = [m[0] for m in cls.methods]
    assert method_names == ["Run", "Helper"]


def test_csharp_this_dot_method_tags_receiver_class():
    """``this.X()`` inside an instance method → receiver_class
    points at the enclosing class. Tree-sitter-c_sharp marks the
    ``this`` keyword as unnamed; the parser special-cases it."""
    g = extract_call_graph_csharp(
        "class C {\n"
        "    void Run() { this.Helper(); }\n"
        "    void Helper() {}\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["this", "Helper"])
    assert call.receiver_class == "C"


def test_csharp_unqualified_call_tags_receiver_class():
    """C# unqualified ``Helper()`` is implicit-this — no module-
    level functions exist in C# so the dispatch target is always
    a method of the enclosing class or a base class."""
    g = extract_call_graph_csharp(
        "class C {\n"
        "    void Run() { Helper(); }\n"
        "    void Helper() {}\n"
        "}\n"
    )
    call = next(c for c in g.calls if c.chain == ["Helper"])
    assert call.receiver_class == "C"


def test_csharp_interface_declaration_captured():
    """``interface I {}`` → recorded as a class with no methods
    (interface methods are signatures, but the resolver still
    benefits from the class-ID entry for ``ClassName.method``
    canonicalisation)."""
    g = extract_call_graph_csharp(
        "interface I {\n"
        "    void DoIt();\n"
        "}\n"
    )
    cls = next(c for c in g.classes if c.name == "I")
    assert cls.name == "I"


# ---------------------------------------------------------------------------
# PHP namespace + class capture
# ---------------------------------------------------------------------------


def test_php_namespace_captured():
    """``namespace Foo\\Bar;`` → package_name='Foo.Bar' (dotted)."""
    g = extract_call_graph_php(
        '<?php\nnamespace Foo\\Bar;\nclass C {}\n'
    )
    assert g.package_name == "Foo.Bar"


def test_php_class_extends_and_implements():
    """``class Service extends Base implements I1, I2`` →
    bases=['Base', 'I1', 'I2']."""
    g = extract_call_graph_php(
        '<?php\n'
        'class Service extends Base implements I1, I2 {\n'
        '    public function run() {}\n'
        '    public function helper() {}\n'
        '}\n'
    )
    cls = next(c for c in g.classes if c.name == "Service")
    assert "Base" in cls.bases
    assert "I1" in cls.bases
    assert "I2" in cls.bases
    method_names = [m[0] for m in cls.methods]
    assert method_names == ["run", "helper"]


def test_php_this_arrow_method_tags_receiver_class():
    """``$this->helper()`` inside an instance method →
    receiver_class points at the enclosing class. The $-stripping
    in _object_chain makes the chain ``["this", "helper"]``."""
    g = extract_call_graph_php(
        '<?php\n'
        'class C {\n'
        '    public function run() { $this->helper(); }\n'
        '    public function helper() {}\n'
        '}\n'
    )
    call = next(c for c in g.calls if c.chain == ["this", "helper"])
    assert call.receiver_class == "C"
    assert call.caller == "run"


def test_php_bare_function_call_no_receiver_class():
    """Bare function calls in PHP resolve to namespaced/global
    functions — NOT implicit-this. No narrowing."""
    g = extract_call_graph_php(
        '<?php\n'
        'class C {\n'
        '    public function run() { global_func(); }\n'
        '}\n'
    )
    call = next(c for c in g.calls if c.chain == ["global_func"])
    assert call.receiver_class is None


def test_php_interface_declaration_captured():
    """``interface I { function doIt(); }`` → recorded as class
    with the method signature on methods."""
    g = extract_call_graph_php(
        '<?php\n'
        'interface I {\n'
        '    public function doIt();\n'
        '}\n'
    )
    cls = next(c for c in g.classes if c.name == "I")
    method_names = [m[0] for m in cls.methods]
    assert "doIt" in method_names


# ---------------------------------------------------------------------------
# Adversarial edge cases (real-language constructs caught during review)
# ---------------------------------------------------------------------------


def test_rust_generic_impl_captures_target():
    """``impl<T> Box<T>`` — the impl target is wrapped in a
    ``generic_type`` node. Extract the inner type_identifier so
    methods still attach to Box."""
    g = extract_call_graph_rust(
        "struct Box<T>(T);\n"
        "impl<T> Box<T> {\n"
        "    fn new(x: T) -> Box<T> { Box(x) }\n"
        "}\n"
    )
    box = next(c for c in g.classes if c.name == "Box")
    method_names = [m[0] for m in box.methods]
    assert "new" in method_names


def test_rust_impl_on_unknown_generic_synthesises():
    """``impl<T: Clone> Vec<T>`` for a Vec not declared in this
    file — synthesise a ClassDef so cross-file method matching
    still works."""
    g = extract_call_graph_rust(
        "impl<T: Clone> Vec<T> {\n"
        "    fn cloned(&self) -> Self { self.clone() }\n"
        "}\n"
    )
    vec = next(c for c in g.classes if c.name == "Vec")
    assert any(m[0] == "cloned" for m in vec.methods)


def test_csharp_file_scoped_namespace_captured():
    """C# 10's ``namespace Foo.Bar;`` (no braces) — the
    declarations are SIBLINGS of the namespace node, not nested.
    Set package_name without push/pop so it applies file-wide."""
    g = extract_call_graph_csharp(
        "namespace Foo.Bar;\n"
        "\n"
        "class C { void m() {} }\n"
    )
    assert g.package_name == "Foo.Bar"
    cls = next(c for c in g.classes if c.name == "C")
    assert any(m[0] == "m" for m in cls.methods)


def test_ruby_singleton_method_registered():
    """``def self.foo`` (singleton_method node) inside a class /
    module body — register as a method on the class same as
    regular ``def`` would."""
    g = extract_call_graph_ruby(
        "class C\n"
        "  def self.class_method\n"
        "  end\n"
        "  def instance_method\n"
        "  end\n"
        "end\n"
    )
    cls = next(c for c in g.classes if c.name == "C")
    method_names = [m[0] for m in cls.methods]
    assert "class_method" in method_names
    assert "instance_method" in method_names


def test_js_private_method_captured():
    """``#priv()`` method uses private_property_identifier as
    its name node. Function-name extraction + member-chain
    extraction both need to accept private_property_identifier
    so ``this.#priv()`` is recorded with chain ``["this", "#priv"]``."""
    g = extract_call_graph_javascript(
        "class C {\n"
        "  #priv() {}\n"
        "  pub() { this.#priv(); }\n"
        "}\n"
    )
    cls = g.classes[0]
    method_names = [m[0] for m in cls.methods]
    assert "#priv" in method_names
    assert "pub" in method_names
    call = next(c for c in g.calls if c.chain == ["this", "#priv"])
    assert call.receiver_class == "C"


def test_js_class_expression_assigned_to_const():
    """``const Foo = class extends Bar { method() {} }`` —
    class expressions are anonymous in the grammar; we
    synthesise a ClassDef using the variable_declarator's LHS
    identifier as the class name."""
    g = extract_call_graph_javascript(
        "const Foo = class extends Bar {\n"
        "  method() {}\n"
        "  helper() {}\n"
        "};\n"
    )
    foo = next(c for c in g.classes if c.name == "Foo")
    assert foo.bases == ["Bar"]
    method_names = [m[0] for m in foo.methods]
    assert "method" in method_names
    assert "helper" in method_names
