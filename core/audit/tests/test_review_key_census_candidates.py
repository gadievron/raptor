"""Parsed review-key seeds survive the census's irrelevant-function fast path."""
from __future__ import annotations

import pytest

from core.audit.tests import _review_keys as scanner


def _scan(tmp_path, rel, source):
    path = tmp_path / rel
    path.parent.mkdir(parents=True)
    path.write_text(source, encoding="utf-8")
    return scanner.scan_full(tmp_path)


@pytest.mark.parametrize("rel,source,read_keys,write_keys", [
    ("packages/other/f.py", 'def f(o):\n    return o.𝗋𝖾𝗏𝗂𝖾𝗐_𝗋𝖾𝗌𝗎𝗅𝗍["unicode_attr"]\n',
     {"unicode_attr"}, set()),
    ("packages/other/f.py", 'def f():\n    Thing(𝗋𝖾𝗏𝗂𝖾𝗐_𝗋𝖾𝗌𝗎𝗅𝗍={"unicode_keyword": 1})\n',
     set(), {"unicode_keyword"}),
    ("packages/other/f.py", 'def f():\n    Thing(**{"review_\\x72esult": {"escaped_unpack": 1}})\n',
     set(), {"escaped_unpack"}),
    ("packages/other/f.py", 'def f(o):\n    value = getattr(o, "review_\\x72esult")\n    return value["escaped_getattr"]\n',
     {"escaped_getattr"}, set()),
    ("packages/other/f.py", 'def f(o):\n    setattr(o, "review_\\x72esult", {"escaped_setattr": 1})\n',
     set(), {"escaped_setattr"}),
    ("packages/other/f.py", 'def f(o):\n    o.__setattr__("review_\\x72esult", {"method_setattr": 1})\n',
     set(), {"method_setattr"}),
    ("packages/other/f.py", 'def outer(o):\n    def inner():\n        o.review_result = {"nested": 1}\n',
     set(), {"nested"}),
    ("core/audit/f.py", 'def f(rr):\n    return rr["parameter"]\n',
     {"parameter"}, set()),
    ("core/audit/f.py", 'def f():\n    rr = {"local": 1}\n',
     set(), {"local"}),
    ("core/llm/multi_model/f.py", 'def f(primary):\n    return primary.get("panel")\n',
     {"panel"}, set()),
    ("core/audit/llm_review.py", 'def review_fn():\n    result = {"model": 1}\n    return result["model"]\n',
     {"model"}, {"model"}),
    ("packages/other/f.py", 'def f():\n    value = {"before_seed": 1}\n    value["later"] = 2\n    Thing(review_result=value)\n',
     set(), {"before_seed", "later"}),
], ids=["unicode-attribute", "unicode-keyword", "escaped-unpack", "escaped-getattr",
        "escaped-setattr", "escaped-method-setattr", "nested-function",
        "audit-parameter", "audit-local", "panel-parameter", "model-dict", "late-keyword-seed"])
def test_candidate_seeds_keep_exact_reads_and_writes(tmp_path, rel, source, read_keys, write_keys):
    reads, writes, unresolved = _scan(tmp_path, rel, source)
    assert {key for key, _, _ in reads} == read_keys
    assert {key for key, _, _ in writes} == write_keys
    assert {path for _, path, _ in reads | writes} == {rel}
    assert not unresolved


@pytest.mark.parametrize("statement", [
    "Thing(review_result=build())",
    'setattr(o, "review_\\x72esult", build())',
    "o.review_result = build()",
])
def test_nonliteral_explicit_writes_remain_unresolved(tmp_path, statement):
    rel = "packages/other/f.py"
    reads, writes, unresolved = _scan(tmp_path, rel, "def f(o):\n    " + statement + "\n")
    assert not reads and not writes
    assert len(unresolved) == 1
    site, = unresolved
    assert (site.file, site.line, site.qualname, site.shape) == (rel, 2, "f", "value-expression")


@pytest.mark.parametrize("source", [
    'def f(rr):\n    return rr["unrelated_parameter"]\n',
    'def f():\n    rr = {"unrelated_local": 1}\n',
    'def f():\n    return "getattr(o, review_result)"\n',
])
def test_unrelated_names_outside_alias_scope_remain_unclassified(tmp_path, source):
    assert _scan(tmp_path, "packages/other/f.py", source) == (set(), set(), set())


@pytest.mark.parametrize("source", [
    '@decorate()\nclass Outer(base()):\n    async def run(self, value: hint() = initial()):\n'
    '        def inner():\n            return value\n        return inner()\n',
    'def outer():\n    class Inner:\n        def method(self):\n            return lambda: self\n'
    '    return Inner\n',
    'async def run(items):\n    async with context() as value:\n'
    '        return [item for item in items if accept(item)]\n',
    'def run(value):\n    match value:\n        case {"key": captured}:\n'
    '            return f"{render(captured):{width()}}"\n',
])
def test_qualname_walk_keeps_all_node_owners_and_function_order(source):
    import ast

    tree = ast.parse(source)
    before = ast.dump(tree, include_attributes=True)
    expected, expected_functions = {}, []

    def reference(node, owner, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not isinstance(child, ast.ClassDef):
                    expected_functions.append(child)
                name = prefix + child.name
                expected[id(child)] = name
                reference(child, name, name + ("." if isinstance(child, ast.ClassDef) else ".<locals>."))
            else:
                expected[id(child)] = owner
                reference(child, owner, prefix)

    reference(tree, "<module>", "")
    functions = []
    assert scanner._qualnames(tree, functions=functions) == expected
    assert functions == expected_functions
    assert ast.dump(tree, include_attributes=True) == before
