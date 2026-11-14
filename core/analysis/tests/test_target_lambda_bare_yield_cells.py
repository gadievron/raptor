"""Bare yields in target lambdas leave sibling and default cell reads intact."""

import ast
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
    ('(lambda value=raw: (yield))()', True),
    ('(lambda raw: (yield))(0)', False),
    ('((lambda: (yield))(), raw)', True),
    ('(raw, (lambda: (yield))())', True),
    ('[(lambda: (yield))() for item in raw]', True),
    ('[(lambda: (yield))() for raw in ()]', False),
    ('(lambda: (raw, (lambda: (yield))()))()', True),
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
    code = compile(source, '<target-lambda-bare-yield>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('part,captures', CASES)
@pytest.mark.parametrize('context', ['comprehension', 'statement'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_bare_yield_target_cells_match_compiler(part, captures, context, deep):
    code, summaries = summarise(source_for(part, context, deep))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures
    if context == 'comprehension':
        node = ast.parse(f'[0 for box[{part}] in ()]', mode='eval').body
        assert _child_expression_is_supported(node)
        assert ('raw' in _scoped_expression_loads(node)) is captures


def test_bare_yield_target_keeps_caller_raw_flow():
    source = source_for('(lambda value=raw: (yield))()', 'comprehension', False)
    source = source.replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('target', [
    'box[(lambda: (yield raw))()]',
    'box[(lambda value=(yield): value)()]',
    'box[((lambda: (yield)), (lambda value=(yield): value))]',
])
def test_valued_yield_and_unowned_bare_default_stay_excluded(target):
    source = f'def nested():\n {target} = 0'
    compile(source, '<excluded-target-yield>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body[0].body) is None


def test_own_generator_return_authority_stays_unknown():
    _, summaries = summarise('def handle(raw):\n yield\n return raw\n')
    assert summaries['handle'].summary_unknown
    assert 'generator' in summaries['handle'].summary_unknown_reason
