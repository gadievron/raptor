"""Definition headers retain valid Lambda inputs without deferred bodies."""
import ast

import pytest

from core.dataflow.smt_barrier import _python_definition_headers, _python_possible_call


@pytest.mark.parametrize("prefix", ["def", "async def"])
def test_function_header_retains_annotations_defaults_and_decorators(prefix):
    node = ast.parse(
        "@decorate()\n"
        f"{prefix} handle(a: Pos = first(), /, b: Arg = second(), *rest: Rest, "
        "key: Key = keyword(), **options: Options) -> Result:\n"
        "    deferred()\n"
    ).body[0]
    assert [ast.unparse(part) for part in _python_definition_headers(node)] == [
        "decorate()", "first()", "second()", "keyword()",
        "Pos", "Arg", "Key", "Rest", "Options", "Result",
    ]


def test_lambda_defaults_remain_definition_headers_without_returns_field():
    node = ast.parse(
        "lambda value=default(), /, *rest, key=keyword(), required, **options: deferred()",
        mode="eval",
    ).body
    assert isinstance(node, ast.Lambda)
    assert "returns" not in node._fields
    assert [ast.unparse(part) for part in _python_definition_headers(node)] == [
        "default()", "keyword()",
    ]


@pytest.mark.parametrize("expression,expected", [
    ("lambda value=effect(): value", True),
    ("lambda value: deferred()", False),
])
def test_lambda_effect_boundary_distinguishes_defaults_from_body(expression, expected):
    node = ast.parse(expression, mode="eval").body
    assert _python_possible_call(node) is expected


def test_class_headers_remain_separate_from_body():
    node = ast.parse("@decorate()\nclass Subject(Base, metaclass=Meta):\n    deferred()\n").body[0]
    assert [ast.unparse(part) for part in _python_definition_headers(node)] == [
        "decorate()", "Base", "Meta",
    ]


def test_non_definition_has_no_headers():
    assert _python_definition_headers(ast.parse("value = compute()").body[0]) == []
