"""Lexical scope transitions restore overlapping and sibling expression bindings."""

import ast

import pytest

from core.analysis.taint_summaries import _scoped_expression_loads


def reads(expression):
    return _scoped_expression_loads(ast.parse(expression, mode="eval").body)


@pytest.mark.parametrize(
    "expression, expected",
    [("((lambda raw: raw), raw)", {"raw"}),
     ("(raw, (lambda raw: raw))", {"raw"}),
     ("lambda raw: ((lambda raw: raw), raw)", set()),
     ("lambda raw: ((lambda raw=raw: raw), raw)", set()),
     ("([raw for raw in seq], raw)", {"raw", "seq"}),
     ("lambda raw: ([raw for raw in seq], raw)", {"seq"}),
     ("lambda raw: (lambda *, raw=raw: raw)", set())],
    ids=["lambda-before-sibling", "lambda-after-sibling", "overlapping-lambdas",
         "nested-default", "comp-before-sibling", "overlapping-comp", "keyword-default"],
)
def test_scopes_restore_outer_bindings(expression, expected):
    assert reads(expression) == frozenset(expected)


def test_aborted_inner_scope_does_not_leak_into_next_invocation():
    assert not reads("lambda raw: (yield raw)")
    assert reads("raw") == frozenset({"raw"})


def test_first_iterable_uses_outer_scope_after_comprehension_body():
    assert reads("[0 for raw in raw]") == frozenset({"raw"})


def test_malformed_body_is_checked_before_unsupported_default():
    expression = ast.parse("lambda value=(yield 0): raw", mode="eval").body
    del expression.body.ctx
    with pytest.raises(AttributeError, match="ctx"):
        _scoped_expression_loads(expression)


def test_malformed_payload_is_checked_before_unsupported_first_iterable():
    expression = ast.parse("[raw for item in (yield 0)]", mode="eval").body
    del expression.elt.ctx
    with pytest.raises(AttributeError, match="ctx"):
        _scoped_expression_loads(expression)
