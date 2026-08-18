"""Tests for ``extract_call_graph_scala`` / ``_kotlin`` / ``_swift``.

Same shape as ``test_call_graph_new_langs.py`` (the Rust/Ruby/C#/PHP
batch): per-language focused suites covering the import, class, call,
and indirection shapes the reachability tier consumes, plus a deep-AST
regression (the walkers are generator/iterative — parse depth must not
be bounded by Python's recursion limit) and item-extraction checks for
the two languages new to the tree-sitter extractor (Kotlin / Swift).
"""

from __future__ import annotations

import sys

import pytest

from core.inventory.call_graph import (
    INDIRECTION_WILDCARD_IMPORT,
    extract_call_graph_kotlin,
    extract_call_graph_scala,
    extract_call_graph_swift,
)
from core.inventory.extractors import extract_items

# ---------------------------------------------------------------------------
# Scala
# ---------------------------------------------------------------------------

pytest.importorskip("tree_sitter_scala")
pytest.importorskip("tree_sitter_kotlin")
pytest.importorskip("tree_sitter_swift")


SCALA_SRC = """package com.example
import java.util.List

class C(x: Int) extends Base with Trait1 {
  def m(a: String): Int = {
    n()
    this.o()
    obj.p(1, cb)
    1
  }
}
object S extends App {
  def t(): Unit = { helper() }
}
trait Trait1 {
  def v(): Int = 0
}
"""


def test_scala_package_and_imports():
    g = extract_call_graph_scala(SCALA_SRC)
    assert g.package_name == "com.example"
    assert g.imports == {"List": "java.util.List"}


def test_scala_wildcard_import_flags_indirection():
    g = extract_call_graph_scala("import scala.io._\n")
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_scala_classes_bases_methods():
    g = extract_call_graph_scala(SCALA_SRC)
    by_name = {c.name: c for c in g.classes}
    assert set(by_name) == {"C", "S", "Trait1"}
    assert by_name["C"].bases == ["Base", "Trait1"]
    assert by_name["S"].bases == ["App"]
    assert [m[0] for m in by_name["C"].methods] == ["m"]
    assert [m[0] for m in by_name["Trait1"].methods] == ["v"]


def test_scala_calls_callers_receivers():
    g = extract_call_graph_scala(SCALA_SRC)
    by_chain = {tuple(c.chain): c for c in g.calls}
    assert by_chain[("n",)].caller == "m"
    assert by_chain[("n",)].receiver_class == "C"
    assert by_chain[("this", "o")].receiver_class == "C"
    assert by_chain[("obj", "p")].receiver_class is None
    assert by_chain[("obj", "p")].argument_identifiers == ["cb"]
    assert by_chain[("helper",)].caller == "t"


# ---------------------------------------------------------------------------
# Kotlin
# ---------------------------------------------------------------------------

KOTLIN_SRC = """package com.example
import java.util.List

class C(val x: Int) : Base(), I {
    fun m(a: String): Int {
        n()
        this.o()
        obj.p(1, cb)
        return 1
    }
    constructor(y: Int) : this(y) {
        setup()
    }
}
object S {
    fun t() {
        helper()
    }
}
fun topLevel() {
    free()
}
"""


def test_kotlin_package_and_imports():
    g = extract_call_graph_kotlin(KOTLIN_SRC)
    assert g.package_name == "com.example"
    assert g.imports == {"List": "java.util.List"}


def test_kotlin_wildcard_import_flags_indirection():
    g = extract_call_graph_kotlin("import kotlin.io.*\n")
    assert INDIRECTION_WILDCARD_IMPORT in g.indirection


def test_kotlin_classes_bases_methods():
    g = extract_call_graph_kotlin(KOTLIN_SRC)
    by_name = {c.name: c for c in g.classes}
    assert set(by_name) == {"C", "S"}
    assert by_name["C"].bases == ["Base", "I"]
    assert [m[0] for m in by_name["C"].methods] == ["m", "constructor"]
    assert [m[0] for m in by_name["S"].methods] == ["t"]


def test_kotlin_calls_callers_receivers():
    g = extract_call_graph_kotlin(KOTLIN_SRC)
    by_chain = {tuple(c.chain): c for c in g.calls}
    assert by_chain[("n",)].caller == "m"
    assert by_chain[("n",)].receiver_class == "C"
    assert by_chain[("this", "o")].receiver_class == "C"
    assert by_chain[("obj", "p")].receiver_class is None
    assert by_chain[("obj", "p")].argument_identifiers == ["cb"]
    assert by_chain[("setup",)].caller == "constructor"
    assert by_chain[("free",)].caller == "topLevel"
    assert by_chain[("free",)].receiver_class is None


def test_kotlin_items_extracted():
    items = extract_items("t.kt", "kotlin", KOTLIN_SRC)
    fns = {i.name: i for i in items if i.kind == "function"}
    assert set(fns) == {"m", "constructor", "t", "topLevel"}
    assert fns["m"].metadata.class_name == "C"
    assert fns["t"].metadata.class_name == "S"
    assert fns["topLevel"].metadata.class_name is None
    assert fns["m"].line_end is not None


# ---------------------------------------------------------------------------
# Swift
# ---------------------------------------------------------------------------

SWIFT_SRC = """import Foundation

class C: Base, P {
    func m(_ a: String) -> Int {
        n()
        self.o()
        obj.p(x, cb)
        return 1
    }
    init() { setup() }
    deinit { teardown() }
}
struct St {
    func u() { helper() }
}
protocol P {
    func v()
}
extension C {
    func w() { m("x") }
}
func topLevel() { free() }
"""


def test_swift_imports():
    g = extract_call_graph_swift(SWIFT_SRC)
    assert g.imports == {"Foundation": "Foundation"}


def test_swift_classes_bases_methods():
    g = extract_call_graph_swift(SWIFT_SRC)
    by_name = {c.name: c for c in g.classes}
    assert set(by_name) == {"C", "St", "P"}
    assert by_name["C"].bases == ["Base", "P"]
    # extension C methods merge onto the existing ClassDef
    assert [m[0] for m in by_name["C"].methods] == [
        "m", "init", "deinit", "w",
    ]
    # protocol requirement signatures registered like Rust trait sigs
    assert [m[0] for m in by_name["P"].methods] == ["v"]


def test_swift_calls_callers_receivers():
    g = extract_call_graph_swift(SWIFT_SRC)
    by_chain = {tuple(c.chain): c for c in g.calls}
    assert by_chain[("n",)].caller == "m"
    assert by_chain[("n",)].receiver_class == "C"
    assert by_chain[("self", "o")].receiver_class == "C"
    assert by_chain[("obj", "p")].receiver_class is None
    assert by_chain[("obj", "p")].argument_identifiers == ["x", "cb"]
    assert by_chain[("setup",)].caller == "init"
    assert by_chain[("teardown",)].caller == "deinit"
    # extension method attributes to the extended class
    assert by_chain[("m",)].caller == "w"
    assert by_chain[("m",)].receiver_class == "C"


def test_swift_items_extracted():
    items = extract_items("t.swift", "swift", SWIFT_SRC)
    fns = {i.name: i for i in items if i.kind == "function"}
    assert set(fns) == {
        "m", "init", "deinit", "u", "w", "topLevel",
    }
    assert fns["m"].metadata.class_name == "C"
    assert fns["init"].metadata.class_name == "C"
    assert fns["w"].metadata.class_name == "C"


# ---------------------------------------------------------------------------
# Deep-AST regression (all three)
# ---------------------------------------------------------------------------

DEPTH = max(2000, sys.getrecursionlimit() * 2)


@pytest.mark.parametrize(
    ("extract", "template"),
    [
        (extract_call_graph_scala,
         "def f(): Int = {{ val x = {open}1{close}\n g()\n 1 }}"),
        (extract_call_graph_kotlin,
         "fun f() {{ val x = {open}1{close}\n g()\n}}"),
        (extract_call_graph_swift,
         "func f() {{ let x = {open}1{close}\n g()\n}}"),
    ],
    ids=["scala", "kotlin", "swift"],
)
def test_deep_ast_does_not_hit_recursion_limit(extract, template):
    src = template.format(open="(" * DEPTH, close=")" * DEPTH)
    g = extract(src)
    assert ["g"] in [c.chain for c in g.calls]
