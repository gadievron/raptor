"""Extraction-completeness self-audit: a curated file per language exercises
the tricky method/function shapes, and every expected name MUST be extracted
by the tree-sitter path (the production extractor). Guards against the class
of bug where a shape is silently dropped from the inventory — e.g. C++
operator overloads / conversion operators, Rust impl methods, JS ``#private``
methods, C#/Ruby operators (all found + fixed 2026-05-28/29).

(A regex-vs-tree-sitter superset differential was prototyped too, but the
crude regex over-matches — e.g. it captures ``int`` from ``operator int(...)``
— so it's too noisy for a hard gate. The shape-coverage assertion below is the
reliable guard.)

Each case skips without its grammar.
"""

from __future__ import annotations

import pytest

from core.inventory.extractors import TreeSitterExtractor, _ts_language

# language -> (grammar module, source, {expected function/method names})
_SHAPES = {
    "python": ("tree_sitter_python",
               "def free(): pass\n"
               "async def af(): pass\n"
               "class C:\n  def m(self): pass\n  async def am(self): pass\n"
               "  def __init__(self): pass\n",
               {"free", "af", "m", "am", "__init__"}),
    "javascript": ("tree_sitter_javascript",
                   "function f(){}\nclass C { m(){} static s(){} #priv(){} *g(){} }\n",
                   {"f", "m", "s", "#priv", "g"}),
    "typescript": ("tree_sitter_typescript",
                   "export function exp(){}\n"
                   "class C { async am(): Promise<void>{} get x(){return 1} m(){} }\n",
                   {"exp", "am", "x", "m"}),
    "java": ("tree_sitter_java",
             "class O { void m(){} O(){} class I { void n(){} } }\n"
             "enum E { X; void ev(){} }\ninterface I2 { default void d(){} }\n",
             {"m", "O", "n", "ev", "d"}),
    "csharp": ("tree_sitter_c_sharp",
               "class C {\n  void M(){}\n  C(){}\n"
               "  public static C operator +(C a, C b){ return a; }\n"
               "  public int this[int i] => i;\n"
               "  public static explicit operator int(C c){ return 0; }\n}\n",
               {"M", "C", "operator+", "this[]", "operator int"}),
    "go": ("tree_sitter_go",
           "package p\ntype T struct{}\nfunc (t *T) M(){}\n"
           "func Generic[X any](x X) X { return x }\nfunc Free(){}\n",
           {"M", "Generic", "Free"}),
    "rust": ("tree_sitter_rust",
             "pub fn api(){}\nfn free(){}\ntrait T { fn td(&self){} }\n"
             "struct F;\nimpl T for F { fn h(&self){} }\nimpl F { fn inh(&self){} }\n",
             {"api", "free", "td", "h", "inh"}),
    "ruby": ("tree_sitter_ruby",
             "class C\n  def m; end\n  def self.cm; end\n  def []=(k,v); end\nend\n",
             {"m", "cm", "[]="}),
    "php": ("tree_sitter_php",
            "<?php\nclass C { public function m(){} function __construct(){} }\n"
            "trait Tr { function tm(){} }\ninterface I { public function im(); }\n",
            {"m", "__construct", "tm", "im"}),
    "cpp": ("tree_sitter_cpp",
            "class Foo {\npublic:\n  void m(){}\n  Foo(){}\n  ~Foo(){}\n"
            "  Foo& operator+(const Foo& o){ return *this; }\n"
            "  operator bool() const { return true; }\n};\n"
            "template<class X> class Tpl { public: void tm(){} };\n",
            {"m", "Foo", "~Foo", "operator+", "operator bool", "tm"}),
    "c": ("tree_sitter_c",
          "int f(void){ return 1; }\nstatic int g(void){ return 2; }\n"
          "char *ptr(void){ return 0; }\n",
          {"f", "g", "ptr"}),
}


@pytest.mark.parametrize("lang", sorted(_SHAPES))
def test_treesitter_extracts_all_shapes(lang):
    grammar, src, expected = _SHAPES[lang]
    pytest.importorskip(grammar)
    if _ts_language(lang) is None:
        pytest.skip(f"{grammar} not available")
    got = {fi.name for fi in TreeSitterExtractor(lang).extract("f", src)}
    missing = expected - got
    assert not missing, f"{lang}: tree-sitter dropped {missing} (extracted {got})"
