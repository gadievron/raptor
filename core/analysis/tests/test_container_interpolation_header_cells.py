"""Literal container interpolation headers retain lexical body cells."""

import ast
from types import CodeType

import pytest

from core.analysis import taint_summaries as module
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph


ANNOTATIONS = [prefix + '"{' + value + '}"'
               for prefix in ('f', 't')
               for value in ('(0,)', '[0]', '({0})', '({0:1})',
                             '([0], {1: (2,)})', "f'{0}'", "t'{0}'", '[0]!r')]


def source_for(annotation, body='return raw', future=False, deep=False, returns=False):
    if ('t"' in annotation or "t'" in annotation) and not hasattr(ast, 'TemplateStr'):
        pytest.skip('Template strings require Python 3.14')
    lines = ['from __future__ import annotations'] if future else []
    lines += ['def helper(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append(indent + 'def middle():')
        indent += '    '
    signature = f'leaf() -> {annotation}' if returns else f'leaf(value: {annotation})'
    lines += [indent + f'def {signature}:', indent + '    ' + body, indent + 'return leaf']
    if deep:
        lines.append('        return middle')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<container-interpolation-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, module.build_taint_summaries(graph, source)


def captures_raw(code):
    outer = next(c for c in code.co_consts if isinstance(c, CodeType) and c.co_name == 'helper')
    nested = next(c for c in outer.co_consts if isinstance(c, CodeType) and c.co_name == 'nested')
    return 'raw' in nested.co_freevars


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True])
@pytest.mark.parametrize('deep,returns', [(False, False), (True, True)])
def test_container_interpolation_preserves_body_capture(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, future=future, deep=deep, returns=returns))
    assert captures_raw(code)
    assert summaries['helper'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True])
def test_container_interpolation_does_not_invent_capture(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    assert not captures_raw(code)
    assert not summaries['helper'].summary_unknown


def test_container_interpolation_keeps_caller_raw_flow():
    _, summaries = summarise('import html\n' + source_for('f"{([0], {1: (2,)})}"')
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('prefix', ['f', 't'])
@pytest.mark.parametrize('value', ['[raw]', '(raw,)', '({raw})', '({0:raw})', '[*raw]', '({**raw})', "f'{raw}'", '[x for x in raw]', '[0]:{raw}'])
def test_dynamic_and_nonliteral_values_stay_excluded(prefix, value):
    annotation = prefix + '"{' + value + '}"'
    source = source_for(annotation)
    compile(source, '<excluded-interpolation>', 'exec', dont_inherit=True)
    assert not module._literal_header_annotation(ast.parse(annotation, mode='eval').body)


@pytest.mark.parametrize('future', [False, True])
@pytest.mark.parametrize('header,body,captures', [
    ('value: f"{[0]}" = raw', 'return 0', True),
    ('raw: f"{[0]}"', 'return raw', False),
    ('value: f"{(0,)}" = (raw := 0)', 'return raw', False),
])
def test_container_interpolation_preserves_binding_ownership(header, body, captures, future):
    source = source_for('0', body=body, future=future)
    source = source.replace('leaf(value: 0)', 'leaf(' + header + ')')
    code, summaries = summarise(source)
    assert captures_raw(code) is captures
    assert summaries['helper'].summary_unknown is captures


@pytest.mark.parametrize('future', [False, True])
def test_dynamic_container_header_mode_stays_excluded(future):
    source = source_for('f"{[raw]}"', body='return 0', future=future)
    code, _ = summarise(source)
    assert captures_raw(code) is (not future)
    assert module._bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None
