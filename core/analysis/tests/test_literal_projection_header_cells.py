"""Literal projection headers preserve lexical cells without evaluating annotations."""

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


ANNOTATIONS = ['(0,1)[0]', '{0:1}[0]', '(0,1)[0:1]', '(0,1)[::1]', '"raw"[0]',
               '(1+2j).real', '"raw".upper', '{}[0:1,0]', '{(0,):1}[*(0,)]',
               '{(0,):1}[*(0,),:]', 'f"{(0,1)[0]}"', 't"{0}".strings',
               '((0,1)[0], [(1+2j).real])']


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
    code = compile(source, '<projection-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('returns', [False, True], ids=['parameter', 'return'])
def test_literal_projection_headers_preserve_body_cells(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, deep=deep, future=future, returns=returns))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_projection_header_has_no_name_reads_with_clean_body(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' not in nested.co_freevars
    assert not summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: (0,1)[0] = raw', 'return 0', True),
    ('raw: (1+2j).real', 'return raw', False),
    ('value: {}[0:1,0] = (raw := 0)', 'return raw', False),
])
def test_defaults_and_binding_masks_remain_unchanged(header, body, captures, future):
    code, summaries = summarise(source_for('0', header=header, body=body, future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_literal_projection_header_keeps_caller_raw_flow():
    source = source_for('((0,1)[0], (1+2j).real)').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('annotation', ['raw.real', '(0,raw)[0]', '(0,1)[raw]', '(0,1)[raw:]',
                                     '(0,1)[:raw]', '(0,1)[::raw]', '{}[0:1,raw]'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_dynamic_numeric_operand_mode_boundary_stays_excluded(annotation, future):
    source = source_for(annotation, body='return 0', future=future)
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


@pytest.mark.parametrize('annotation', ['invoke()[0]', 'invoke().raw', 'list[0]',
                                     '1+(0,)[0]', '{}[*(raw,)]', '{}[0:1,::raw]'])
def test_dynamic_unknown_and_numeric_projection_operands_remain_excluded(annotation):
    compile(source_for(annotation), '<excluded-projection-header>', 'exec', dont_inherit=True)
    assert not _literal_header_annotation(ast.parse(annotation, mode='eval').body)


def test_synthetic_projection_contexts_and_standalone_slice_stay_excluded():
    # Synthetic malformed AST controls, not compiler-accepted source witnesses.
    zero = ast.Constant(0)
    malformed = [ast.Attribute(value=zero, attr='real', ctx=ast.Store()),
                 ast.Subscript(value=zero, slice=zero, ctx=ast.Del()),
                 ast.Subscript(value=zero, slice=ast.Tuple(elts=[zero], ctx=ast.Store()), ctx=ast.Load()),
                 ast.Subscript(value=zero, slice=ast.Tuple(
                     elts=[ast.Starred(value=zero, ctx=ast.Store())], ctx=ast.Load()), ctx=ast.Load()),
                 ast.Slice(lower=zero, upper=None, step=None),
                 ast.Starred(value=zero, ctx=ast.Load())]
    for expression in malformed:
        assert not _literal_header_annotation(expression)
