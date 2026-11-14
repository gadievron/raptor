"""Bound-reference headers preserve lexical cells without evaluating annotations."""

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


ANNOTATIONS = ['(lambda value:value)', '(lambda raw:raw)', '(lambda value:(lambda:value))',
               '(lambda value:(lambda other=value:other))', '(lambda value:(lambda value=value:value))',
               '(lambda raw:(raw,(lambda raw:raw)))', '(lambda raw:[raw for item in ()])',
               '(lambda raw:[raw for raw in raw])', '[item for item in ()]', '{item for item in ()}',
               '{item:0 for item in ()}', '(item for item in ())', '[item for item in () if item]',
               '[item for item in () if raw for raw in ()]', '[raw for raw in () for item in raw]',
               '[[item for item in raw] for raw in ()]', '[*(x for x in ())]',
               '(lambda value,/:value)', '(lambda *,value:value)', '(lambda *items:items)',
               '(lambda **items:items)', '[0 for () in ()]', '[0 for [] in ()]',
               'f"{(lambda value:value)}"', 't"{[item for item in ()]}"']


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
    code = compile(source, '<bound-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('returns', [False, True], ids=['parameter', 'return'])
def test_bound_reference_headers_preserve_body_cells(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, deep=deep, future=future, returns=returns))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_bound_header_has_no_name_reads_with_clean_body(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' not in nested.co_freevars
    assert not summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: (lambda raw:raw) = raw', 'return 0', True),
    ('raw: (lambda raw:raw)', 'return raw', False),
    ('value: [item for item in ()] = (raw := 0)', 'return raw', False),
])
def test_defaults_and_binding_masks_remain_unchanged(header, body, captures, future):
    code, summaries = summarise(source_for('0', header=header, body=body, future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_bound_reference_header_keeps_caller_raw_flow():
    source = source_for('(lambda value:value)').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('annotation', ['raw', '(lambda value:raw)', '(lambda raw=raw:raw)',
                                     '(lambda value:(lambda raw=raw:value))', '[raw for raw in raw]',
                                     '(raw,(lambda raw:raw))', '[item for item in raw]',
                                     '[item for item in () if raw]', '[item for item in () for other in raw]'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_enclosing_default_iterator_and_sibling_reads_stay_excluded(annotation, future):
    source = source_for(annotation, body='return 0', future=future)
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


@pytest.mark.parametrize('annotation', ['(lambda value:value+1)', '[item+1 for item in ()]',
                                     '(lambda value:value())', '(lambda value:(other:=value))',
                                     '(lambda target:[0 for target.attr in ()])',
                                     '(lambda target:[0 for target[0] in ()])'])
def test_numeric_unknown_call_write_and_address_scopes_stay_excluded(annotation):
    compile(source_for(annotation), '<excluded-bound-header>', 'exec', dont_inherit=True)
    assert not _literal_header_annotation(ast.parse(annotation, mode='eval').body)


@pytest.mark.parametrize('future', [False, True])
def test_parameter_annotation_scopes_do_not_leak_into_siblings(future):
    source = source_for('0', body='return 0', future=future,
                        header='first: (lambda raw:raw), second: raw')
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


def test_synthetic_bound_name_requires_load_context():
    # Synthetic malformed AST control, not a compiler-accepted source witness.
    expression = ast.parse('lambda raw:raw', mode='eval').body
    expression.body.ctx = ast.Store()
    assert not _literal_header_annotation(expression)
