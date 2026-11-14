"""Literal arithmetic headers preserve lexical cells without evaluating annotations."""

import ast
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _bounded_body_expression_loads,
    _literal_header_annotation,
    build_taint_summaries,
)


ANNOTATIONS = ['1+2', '1-2', '2*3', '1/2', '5//2', '5%2', '2**3', '-(1+2j)',
               '1+(-2j)', '++1', '+(-1)', '+(1+2j)', '++1+2j', '+(-1)+2j',
               '+2j+3j', '+1+2', '+1+(-2j)', '(1+2, [2*3])', 'f"{1+2}"', 't"{1+2}"',
               'f"{0:{1+2}}"', '1/0']


def source_for(annotation, body='return raw', deep=False, future=False, returns=False, header=None):
    if 't"' in annotation and not hasattr(ast, 'TemplateStr'):
        pytest.skip('Template strings require Python 3.14')
    prefix = ['from __future__ import annotations'] if future else []
    lines = prefix + ['def handle(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append(indent + 'def middle():')
        indent += '    '
    signature = f'leaf() -> {annotation}' if returns else f'leaf(value: {annotation})'
    if header is not None:
        signature = f'leaf({header})'
    lines.append(indent + f'def {signature}:')
    lines.extend(indent + '    ' + line for line in body.splitlines())
    lines.append(indent + 'return leaf')
    if deep:
        lines.append('        return middle')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<arithmetic-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('returns', [False, True], ids=['parameter', 'return'])
def test_literal_arithmetic_headers_preserve_body_cells(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, deep=deep, future=future, returns=returns))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_arithmetic_header_has_no_name_reads_with_clean_body(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' not in nested.co_freevars
    assert not summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: 1+2 = raw', 'return 0', True),
    ('raw: 2*3', 'return raw', False),
    ('value: 5%2 = (raw := 0)', 'return raw', False),
])
def test_defaults_and_binding_masks_remain_unchanged(header, body, captures, future):
    code, summaries = summarise(source_for('0', header=header, body=body, future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_literal_arithmetic_header_keeps_caller_raw_flow():
    source = source_for('(1+2, 2*3)').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('annotation', ['raw+1', '1*raw', 'f"{raw+1}"', 'f"{0:{raw/2}}"'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_dynamic_numeric_operand_mode_boundary_stays_excluded(annotation, future):
    source = source_for(annotation, body='return 0', future=future)
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


@pytest.mark.parametrize('annotation', ['-True', 'True+2j', '1+False', '1<<2', '~1', '1@2',
                                     '[0]+[1]', '"a"+"b"', '1+None', 'invoke()+1'])
def test_non_numeric_dynamic_and_unlisted_operators_remain_excluded(annotation):
    compile(source_for(annotation), '<excluded-arithmetic-header>', 'exec', dont_inherit=True)
    assert not _literal_header_annotation(ast.parse(annotation, mode='eval').body)


@pytest.mark.parametrize('expression', ['1+2', '2*3', '1/0', '-(1+2j)'])
def test_arithmetic_does_not_widen_match_pattern_grammar(expression):
    from core.analysis.taint_summaries import _match_literal_expression

    assert not _match_literal_expression(ast.parse(expression, mode='eval').body)
