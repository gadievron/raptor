"""Delegation operands in target lambdas retain lexical cells only."""

import ast

from core.analysis.tests.target_ast_helpers import parse_target_refusal_fixture
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _child_expression_is_supported,
    _scoped_expression_loads,
    build_taint_summaries,
)


CASES = [
    ('(lambda: (yield from raw))()', True),
    ('(lambda: (yield from raw.member))()', True),
    ('(lambda raw: (yield from raw))(())', False),
    ('(lambda: (yield from (raw := ())))()', False),
    ('(lambda value=raw: (yield from value))()', True),
    ('(lambda: (yield from [raw for item in ()]))()', True),
    ('(lambda: (yield from [raw for raw in ()]))()', False),
    ('(lambda: (lambda value=(yield from raw): value))()', True),
]


def source_for(part, context, deep):
    lines = ['def handle(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append(indent + 'def child():')
        indent += '    '
    if context == 'comprehension':
        lines.append(indent + f'return [0 for box[{part}] in ()]')
    else:
        lines.extend([indent + f'box[{part}] = 0', indent + 'return 0'])
    if deep:
        lines.append('        return child')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<target-lambda-yieldfrom>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('part,captures', CASES)
@pytest.mark.parametrize('context', ['comprehension', 'statement'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_yieldfrom_target_cells_match_compiler(part, captures, context, deep):
    code, summaries = summarise(source_for(part, context, deep))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures
    if context == 'comprehension':
        node = ast.parse(f'[0 for box[{part}] in ()]', mode='eval').body
        assert _child_expression_is_supported(node)
        assert ('raw' in _scoped_expression_loads(node)) is captures


def test_yieldfrom_target_keeps_caller_raw_flow():
    source = source_for('(lambda: (yield from raw))()', 'comprehension', False)
    source = source.replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('target', [
    'box[_raptor_unsupported_target]',
    'box[(lambda value=(yield from raw): value)()]',
    'box[((lambda: (yield from ())), (lambda value=(yield from raw): value))]',
])
def test_synthetic_target_and_unowned_default_stay_excluded(target):
    source = f'def nested():\n {target} = 0'
    compile(source, '<excluded-yield-target>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(parse_target_refusal_fixture(source).body[0].body) is None


def test_yieldfrom_does_not_grant_generator_return_value_authority():
    _, summaries = summarise('def handle(raw):\n yield from raw\n')
    assert summaries['handle'].summary_unknown
    assert 'generator' in summaries['handle'].summary_unknown_reason
