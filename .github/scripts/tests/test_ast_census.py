"""Shared census traversal keeps the stdlib visitor's order and dispatch."""
from __future__ import annotations

import ast
import importlib.util
import weakref
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def visitor_module():
    spec = importlib.util.spec_from_file_location(
        "census_visitor_contract", Path(__file__).resolve().parents[1] / "ast_census.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Recording:
    def __init__(self):
        super().__init__()
        self.events = []

    def visit(self, node):
        # Contexts carry no expressions; the census omits them below names,
        # attributes and subscripts. Compare every other node's entry order.
        if not isinstance(node, ast.expr_context):
            self.events.append((type(node).__name__, getattr(node, "lineno", None)))
        return super().visit(node)

    def visit_Name(self, node):
        self.events.append(("name", node.id))

    def visit_Constant(self, node):
        self.events.append(("constant", node.value))


@pytest.mark.parametrize("source", [
    "@decorate(option=1)\nclass Outer(Base):\n    async def run(self, value: Kind = 3):\n"
    "        return [item.attr for item in value if item]\n",
    "def run(value):\n    try:\n        return f'heading {render(value)}'\n"
    "    except Exception as exc:\n        print(str(exc))\n",
    "from package import item as alias\nwith context() as value:\n"
    "    result = {'key': (value[0], lambda x: x + 1)}\n",
    "def run(value):\n    match value:\n        case {'key': result}:\n"
    "            return result if result else None\n",
    "def run(value: annotate(options={'schema': 'retained'})):\n"
    "    del value[render(0)].entry\n"
    "    value[0] = transform(option=['kept'])\n",
])
def test_traversal_matches_stdlib(visitor_module, source):
    class Reference(_Recording, ast.NodeVisitor):
        pass

    class Census(_Recording, visitor_module.CensusVisitor):
        pass

    tree = ast.parse(source)
    before = ast.dump(tree, include_attributes=True)
    reference, census = Reference(), Census()
    reference.visit(tree)
    census.visit(tree)
    assert census.events == reference.events
    assert ast.dump(tree, include_attributes=True) == before


def test_handler_cache_does_not_retain_visitor(visitor_module):
    visitor = visitor_module.CensusVisitor()
    visitor.visit(ast.parse("result = fn(value=1)"))
    borrowed = weakref.ref(visitor)
    del visitor
    assert borrowed() is None


@pytest.mark.parametrize("source", [
    "outer(inner(), option=other())\nlast()",
    "@decorate(option=default())\ndef run(value: annotate() = initial()) -> result():\n"
    "    return nested(value)\n",
    "class Outer(base(), metaclass=meta()):\n    value = make()\n",
    "result = [render(item) for item in source() if accept(item)]\n",
    "result = f'{format_value():{width()}}'\n",
    "try:\n    work()\nexcept kind():\n    recover()\nfinally:\n    finish()\n",
    "match subject():\n    case {'key': value} if guard():\n        handle(value)\n",
    "result = lambda value=initial(): nested(value)\ntext = 'not_a_call()'\n",
    "values = {'literal': 1}\n",
])
def test_call_iterator_preserves_every_call_and_breadth_first_order(visitor_module, source):
    tree = ast.parse(source)
    before = ast.dump(tree, include_attributes=True)
    expected = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    # Identity and order matter: consumers report the original nodes' locations.
    actual = list(visitor_module.iter_calls(tree))
    assert len(actual) == len(expected)
    assert all(left is right for left, right in zip(actual, expected, strict=True))
    assert ast.dump(tree, include_attributes=True) == before
