"""Valued yields in target lambdas expose lexical operands, not yielded values."""

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
from core.analysis.tests.target_ast_helpers import parse_target_refusal_fixture


CASES = [
    ('(lambda: (yield raw))()', True),
    ('(lambda: (yield raw.member))()', True),
    ('(lambda raw: (yield raw))(0)', False),
    ('(lambda: (yield (raw := 0)))()', False),
    ('(lambda: (yield (raw := raw)))()', False),
    ('(lambda value=raw: (yield value))()', True),
    ('(lambda: (yield [raw for raw in ()]))()', False),
    ('(lambda: (lambda value=(yield raw): value))()', True),
]


def source_for(body, deep=False):
    lines = ['def handle(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append(indent + 'def child():')
        indent += '    '
    lines.extend(indent + line for line in body.splitlines())
    if deep:
        lines.append('        return child')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<target-lambda-valued-yield>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('part,captures', CASES)
@pytest.mark.parametrize('context', ['comprehension', 'statement'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_valued_yield_target_cells_match_compiler(part, captures, context, deep):
    expression = f'[0 for box[{part}] in ()]'
    body = f'return {expression}' if context == 'comprehension' else f'box[{part}] = 0\nreturn 0'
    code, summaries = summarise(source_for(body, deep))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures
    node = ast.parse(expression, mode='eval').body
    assert _child_expression_is_supported(node)
    assert ('raw' in _scoped_expression_loads(node)) is captures


E = '[0 for box[(lambda: (yield raw))()] in ()]'
T = 'box[(lambda: (yield raw))()]'
BODIES = [
    f'def deeper(value={E}):\n    return 0\nreturn deeper',
    f'@factory({E})\ndef deeper():\n    return 0\nreturn deeper',
    f'assert {E}\nreturn 0',
    f'raise {E}\nreturn 0',
    f'match {E}:\n    case _:\n        return 0',
    f'with manager as {T}:\n    pass\nreturn 0',
    f'for {T} in ():\n    pass\nreturn 0',
    f'del {T}\nreturn 0',
    f'{T} += 0\nreturn 0',
    f'{T}: object = 0\nreturn 0',
    f'value = lambda arg={E}: arg\nreturn 0',
    f'return lambda: {E}',
]


@pytest.mark.parametrize('body', BODIES)
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_migrated_consumer_contexts_retain_valid_source_cells(body, deep):
    code, summaries = summarise(source_for(body, deep))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


def test_valued_yield_target_keeps_caller_raw_flow():
    source = source_for(f'return {E}').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('target', [
    'box[(lambda value=(yield raw): value)()]',
    'box[((lambda: (yield raw)), (lambda value=(yield raw): value))]',
])
def test_unowned_target_default_yield_stays_excluded(target):
    source = f'def nested():\n {target} = 0'
    compile(source, '<unowned-target-yield>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body[0].body) is None


def test_synthetic_refusal_fixture_is_distinct_from_compiled_source():
    source = '[0 for box[_raptor_unsupported_target] in ()]'
    compile(source, '<valid-marker-source>', 'eval', dont_inherit=True)
    valid = ast.parse(source, mode='eval').body
    assert _child_expression_is_supported(valid)
    synthetic = parse_target_refusal_fixture(source, mode='eval').body
    marker = next(n for n in ast.walk(synthetic) if isinstance(n, ast.Name) and n.id == '_raptor_unsupported_target')
    assert isinstance(marker.ctx, ast.Del)
    assert not _child_expression_is_supported(synthetic)
    assert _scoped_expression_loads(synthetic) == frozenset()


def test_synthetic_refusal_marker_must_start_as_a_load():
    with pytest.raises(AssertionError, match='must start as loads'):
        parse_target_refusal_fixture('_raptor_unsupported_target = 0')


def test_plain_source_without_refusal_marker_is_unchanged():
    source = 'raw.member'
    assert ast.dump(parse_target_refusal_fixture(source)) == ast.dump(ast.parse(source))


def test_own_generator_result_authority_stays_unknown():
    _, summaries = summarise('def handle(raw):\n yield raw\n')
    assert summaries['handle'].summary_unknown
    assert 'generator' in summaries['handle'].summary_unknown_reason
