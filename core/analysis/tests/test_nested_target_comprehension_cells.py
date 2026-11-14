"""Nested comprehension target addresses retain their own lexical scopes."""

import ast
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _child_expression_is_supported,
    _comprehension_target_scope,
    _scoped_expression_loads,
    build_taint_summaries,
)


CAPTURES = [
    '[0 for box[[raw for item in ()]] in ()]',
    '[0 for box[{raw for item in ()}] in ()]',
    '[0 for box[{raw: item for item in ()}] in ()]',
    '[0 for box[{item: raw for item in ()}] in ()]',
    '[0 for box[(raw for item in ())] in ()]',
    '[0 for box[[item for item in () if raw]] in ()]',
    '[0 for box[[item for item in () for other in raw]] in ()]',
    '[0 for box[[raw for raw in raw]] in ()]',
    '[0 for box[[0 for other[raw] in ()]] in ()]',
    '[0 for box[(lambda value=raw: [value for item in ()])()] in ()]',
    '[0 for box[[raw for raw in ()]] in raw for raw in ()]',
]
MASKED = [
    '[0 for box[[raw for raw in ()]] in ()]',
    '[0 for box[[item for item in raw]] in () for raw in ()]',
    '[0 for box[(lambda raw: [raw for item in ()])(0)] in ()]',
    '[0 for box[[0 for other[raw] in () for raw in ()]] in ()]',
]


def summarise(source):
    compiled = compile(source, '<nested-target-contract>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return compiled, build_taint_summaries(graph, source)


@pytest.mark.parametrize('expression,captures', [(e, True) for e in CAPTURES]
                         + [(e, False) for e in MASKED])
def test_nested_target_cells_match_compiler_metadata(expression, captures):
    source = f'def handle(raw):\n    def nested():\n        return {expression}\n    return nested\n'
    compiled, summaries = summarise(source)
    outer = next(c for c in compiled.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    node = ast.parse(expression, mode='eval').body
    assert _child_expression_is_supported(node)
    assert ('raw' in _scoped_expression_loads(node)) is captures
    assert summaries['handle'].summary_unknown is captures


def test_nested_target_caller_keeps_raw_flow():
    _, summaries = summarise(
        'import html\ndef helper(raw):\n    def nested():\n'
        '        return [0 for box[[raw for item in ()]] in ()]\n    return nested\n'
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


def test_legacy_strict_statement_target_contract_is_unchanged():
    expression = ast.parse(CAPTURES[0], mode='eval').body
    target = expression.generators[0].target
    assert _comprehension_target_scope(target, require_scope_free_reads=True) is None
    assert _comprehension_target_scope(target) == (frozenset(), frozenset({'box'}))
    assert _bounded_body_expression_loads(ast.parse(
        'for box[[(lambda: (yield raw))() for item in ()]] in ():\n pass'
    ).body) is None


@pytest.mark.parametrize('expression', [
    '[0 for box[[(lambda: (yield raw))() for item in ()]] in ()]',
    '[0 for box[[item for item in () if (lambda: (yield raw))()]] in ()]',
    '[0 for box[[item for item in (lambda: (yield raw))()]] in ()]',
    '[0 for box[[(lambda: (value := (yield raw)))() for item in ()]] in ()]',
    '[0 for box[[0 for other[(lambda: (value := (yield raw)))()] in ()]] in ()]',
])
def test_excluded_descendants_cannot_hide_in_nested_targets(expression):
    compile(expression, '<excluded-target-contract>', 'eval', dont_inherit=True)
    node = ast.parse(expression, mode='eval').body
    assert not _child_expression_is_supported(node)
    assert _scoped_expression_loads(node) == frozenset()
