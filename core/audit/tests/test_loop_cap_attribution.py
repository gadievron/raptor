"""Nearest-loop grouping preserves existing cap attribution and provider seams."""

import dataclasses

from core.audit import ts_extract as extract
from core.testing.module_views import module_function_view
from core.testing.treesitter import requires_ts


def legacy_view():
    return module_function_view(extract, bindings={
        "_switch_case_map": lambda *args: extract._switch_case_map(*args),
    })


@requires_ts("c")
def test_nested_cap_belongs_to_inner_loop_only():
    source = '''int f(int x) {
  while (x) {
    while (x) {
      if (x >= 10) break;
    }
  }
  return 0;
}'''
    result = extract.extract_loop_caps("inner.c", source)
    expected = legacy_view().extract_loop_caps("inner.c", source)
    assert [dataclasses.asdict(r) for r in result] == [dataclasses.asdict(r) for r in expected]
    assert [r.line for r in result] == [3]


@requires_ts("c")
def test_nested_break_still_counts_for_outer_condition():
    source = '''int partial_f(int x) {
  while (x) {
    if (x >= 10) {
      while (x) { break; }
    }
  }
  return 0;
}'''
    result = extract.extract_loop_caps("break.c", source)
    assert [(r.line, r.signals_truncation) for r in result] == [(2, True)]


@requires_ts("javascript")
def test_condition_in_nested_function_keeps_existing_outer_loop_semantics():
    source = '''function outer(x) {
  while (x) {
    function inner() { if (x >= 10) return 0; }
  }
}'''
    result = extract.extract_loop_caps("scope.js", source)
    expected = legacy_view().extract_loop_caps("scope.js", source)
    assert [dataclasses.asdict(r) for r in result] == [dataclasses.asdict(r) for r in expected]
    assert [(r.line, r.function) for r in result] == [(2, "outer")]


@requires_ts("c")
def test_loop_preorder_and_sibling_function_names():
    source = '''int first(int x) {
 while(x) { if(x >= 5) break; }
 while(x) { if(x >= 6) return 1; }
 return 0;
}
int second(int x) {
 while(x) { if(x == 7) break; }
 return 0;
}'''
    result = extract.extract_loop_caps("siblings.c", source)
    assert [(r.line, r.function) for r in result] == [(2, "first"), (3, "first"), (7, "second")]


@requires_ts("c")
def test_foreign_enclosing_provider_remains_authoritative():
    calls = []

    def provider(node, lang):
        calls.append(node.type)
        return None

    view = module_function_view(extract, bindings={"_find_enclosing_function": provider})
    result = view.extract_loop_caps("provider.c", 'int f(int x) { while(x) { if(x>=4) break; } }')
    assert [r.function for r in result] == ["<module>"]
    assert calls == ["while_statement"]


def test_foreign_tree_root_property_is_read_once_per_extraction():
    class Root:
        children = []

    class Tree:
        def __init__(self):
            self.reads = 0

        @property
        def root_node(self):
            self.reads += 1
            return Root()

    for name in ["extract_loop_caps"]:
        tree = Tree()
        view = module_function_view(extract, bindings={"_parse_file": lambda *args: (tree, "c", b"")})
        assert getattr(view, name)("foreign.c", "") == []
        assert tree.reads == 1


@requires_ts("c")
def test_comparison_anywhere_in_condition_subtree_keeps_existing_semantics():
    source = '''int f(int x) {
 while(x) { if(x) { while(x) { if(x >= 4) break; } } }
 return 0;
}'''
    result = extract.extract_loop_caps("whole_if.c", source)
    assert [(r.line, r.function) for r in result] == [(2, "f"), (2, "f")]


@requires_ts("c")
def test_break_without_comparison_does_not_create_cap():
    result = extract.extract_loop_caps(
        "no_comparison.c", 'int f(int x) { while(x) { if(x) break; } }',
    )
    assert result == []


@requires_ts("c")
def test_overlapping_function_and_loop_kinds_keep_parent_ownership(monkeypatch):
    monkeypatch.setattr(extract, "_FUNCTION_TYPES", {"c": ("while_statement",)})
    result = extract.extract_loop_caps(
        "overlap.c", 'int f(int x) { while(x) { if(x>=4) break; } while(x) {} }',
    )
    assert [r.function for r in result] == ["<module>"]


@requires_ts("c")
def test_overlapping_condition_and_loop_kinds_keep_parent_cap(monkeypatch):
    monkeypatch.setattr(extract, "_LOOP_TYPES", {"c": ("while_statement", "if_statement")})
    result = extract.extract_loop_caps(
        "condition_overlap.c", 'int f(int x) {\n while(x) {\n if(x>=4) break;\n } while(x) {}\n}',
    )
    assert [(r.line, r.function) for r in result] == [(2, "f")]
