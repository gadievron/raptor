"""Statement target address scopes retain enclosing cells without rebinding them."""

import ast
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _comprehension_target_scope,
    build_taint_summaries,
)


def source_for(body, deep=False):
    lines = ['def handle(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append('        def child():')
        indent += '    '
    lines.extend(indent + line for line in body.splitlines())
    lines.append(indent + 'return 0')
    if deep:
        lines.append('        return child')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    compiled = compile(source, '<statement-target-contract>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return compiled, build_taint_summaries(graph, source)


@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('body', [
    'box[(lambda: raw)()] = 0',
    'box[(lambda: raw)()] += 0',
    'box[(lambda: raw)()]: object = 0',
    'del box[(lambda: raw)()]',
    'for box[(lambda: raw)()] in ():\n    pass',
    'with manager as box[(lambda: raw)()]:\n    pass',
    'box[[raw for item in ()]] = 0',
    'box[(lambda value=raw: 0)()] = 0',
    '(lambda: raw)().member = 0',
])
def test_scoped_statement_target_retains_cell(body, deep):
    compiled, summaries = summarise(source_for(body, deep))
    outer = next(c for c in compiled.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('body', [
    'box[(lambda raw: raw)(0)] = 0',
    'box[[raw for raw in ()]] = 0',
    'box[(lambda: raw)()] = 0\nraw = 0',
    'box[(lambda: raw)()] = 0\ndel raw',
    'for raw, box[(lambda: raw)()] in ():\n    pass',
])
def test_complete_function_or_inner_scope_bindings_mask_reads(body, deep):
    _, summaries = summarise(source_for(body, deep))
    assert not summaries['handle'].summary_unknown


def test_statement_target_keeps_caller_raw_flow():
    source = source_for('box[(lambda: raw)()] = 0').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


def test_legacy_strict_wrapper_keeps_its_contract():
    target = ast.parse('box[(lambda: raw)()] = 0').body[0].targets[0]
    assert _comprehension_target_scope(target, require_scope_free_reads=True) is None
    assert _comprehension_target_scope(target) == (frozenset(), frozenset({'box'}))


@pytest.mark.parametrize('target', [
    'box[(lambda: (yield raw))()]',
    'box[(lambda: (value := (yield raw)))()]',
    'box[[(lambda: (yield raw))() for item in ()]]',
])
def test_excluded_target_descendant_invalidates_complete_body(target):
    source = f'raw\n{target} = 0'
    compile(source, '<excluded-statement-target>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body) is None


def test_awaited_statement_target_preserves_async_cell():
    source = ('def handle(raw):\n    async def nested():\n'
              '        for box[await raw] in ():\n            pass\n'
              '        return 0\n    return nested\n')
    _, summaries = summarise(source)
    assert summaries['handle'].summary_unknown
