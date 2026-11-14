"""Constant interpolation headers retain lexical body cells without evaluation."""

import ast
from types import CodeType

import pytest

from core.analysis import taint_summaries as module
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph


ANNOTATIONS = [prefix + '"{' + value + '}"'
               for prefix in ('f', 't')
               for value in ('0', '0!a', '0!r', '0!s', '-1', '1+2j', '0:04', '0:{1}')]


def source_for(annotation, body='return raw', future=False, deep=False, returns=False):
    if annotation.startswith('t') and not hasattr(ast, 'TemplateStr'):
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
    code = compile(source, '<constant-interpolation-header>', 'exec', dont_inherit=True)
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
def test_constant_interpolation_preserves_body_capture(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, future=future, deep=deep, returns=returns))
    assert captures_raw(code)
    assert summaries['helper'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True])
def test_constant_interpolation_does_not_invent_capture(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    assert not captures_raw(code)
    assert not summaries['helper'].summary_unknown


def test_constant_interpolation_keeps_caller_raw_flow():
    _, summaries = summarise('import html\n' + source_for('f"{0:{1}}"')
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('prefix', ['f', 't'])
@pytest.mark.parametrize('value', ['raw', '0:{raw}', '1+2', '-True', '+1', '[0]'])
def test_dynamic_and_nonliteral_values_stay_excluded(prefix, value):
    annotation = prefix + '"{' + value + '}"'
    source = source_for(annotation)
    compile(source, '<excluded-interpolation>', 'exec', dont_inherit=True)
    assert not module._literal_header_annotation(ast.parse(annotation, mode='eval').body)


@pytest.mark.parametrize('conversion', [True, None, 0, 98, 'r'])
def test_invalid_synthetic_conversion_stays_excluded(conversion):
    # Synthetic AST control, not compiler-accepted source.
    part = ast.FormattedValue(value=ast.Constant(0), conversion=conversion, format_spec=None)
    assert not module._literal_header_annotation(ast.JoinedStr(values=[part]))


def test_invalid_synthetic_spec_and_parent_parts_stay_excluded():
    # Synthetic AST controls do not establish compiler acceptance.
    part = ast.FormattedValue(value=ast.Constant(0), conversion=-1, format_spec=ast.Constant('04'))
    assert not module._literal_header_annotation(ast.JoinedStr(values=[part]))
    assert not module._literal_header_annotation(part)
    if hasattr(ast, 'TemplateStr'):
        part.format_spec = None
        assert not module._literal_header_annotation(ast.TemplateStr(values=[part]))
        interpolation = ast.Interpolation(value=ast.Constant(0), str='raw', conversion=-1,
                                          format_spec=None)
        assert not module._literal_header_annotation(ast.JoinedStr(values=[interpolation]))
        # Metadata text is not reparsed into a name read.
        assert module._literal_header_annotation(ast.TemplateStr(values=[interpolation]))
