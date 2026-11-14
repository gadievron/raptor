"""Target-address assignment expressions retain lambda-local ownership."""

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
    ('(lambda: (value := raw))()', True),
    ('(lambda: (raw := 0))()', False),
    ('(lambda: (raw := raw))()', False),
    ('(lambda raw: (value := raw))(0)', False),
    ('(lambda value=raw: (result := value))()', True),
    ('(lambda: (lambda value=(tmp := raw): value))()', True),
    ('(lambda: (lambda value=(raw := 0): value))()', False),
    ('(lambda: (raw, (lambda: (raw := 0))))()', True),
    ('(lambda: [(value := raw) for item in ()])()', True),
    ('(lambda: [(raw := 0) for item in ()])()', False),
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
    code = compile(source, '<lambda-owned-target-write>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('part,captures', CASES)
@pytest.mark.parametrize('context', ['comprehension', 'statement'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_lambda_owned_target_writes_match_compiler_cells(part, captures, context, deep):
    code, summaries = summarise(source_for(part, context, deep))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures
    if context == 'comprehension':
        node = ast.parse(f'[0 for box[{part}] in ()]', mode='eval').body
        assert _child_expression_is_supported(node)
        assert ('raw' in _scoped_expression_loads(node)) is captures


def test_target_lambda_write_keeps_caller_raw_flow():
    source = source_for('(lambda: (value := raw))()', 'comprehension', False)
    source = source.replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


def test_first_lambda_default_still_writes_enclosing_frame_and_refuses():
    source = 'box[(lambda value=(tmp := raw): value)()] = 0'
    compile(source, '<enclosing-default-write>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_malformed_lambda_owned_namedexpr_target_refuses():
    node = ast.parse('[0 for box[(lambda: (value := raw))()] in ()]', mode='eval').body
    write = next(n for n in ast.walk(node) if isinstance(n, ast.NamedExpr))
    write.target = ast.Attribute(value=ast.Name(id='obj', ctx=ast.Load()), attr='member', ctx=ast.Store())
    assert not _child_expression_is_supported(node)
    assert _scoped_expression_loads(node) == frozenset()
