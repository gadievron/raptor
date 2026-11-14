"""Literal child annotations do not hide supported lexical cell reads."""

import ast
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


HEADERS = [
    ('value: 0', ''),
    ('value: "raw"', ''),
    ('value: None', ''),
    ('value: 0, /', ''),
    ('*, value: "raw"', ''),
    ('*values: 0', ''),
    ('**values: None', ''),
    ('', ' -> 0'),
    ('value: 0', ' -> "raw"'),
]


def source_for(header, returns='', body='return raw', deep=False, future=False):
    lines = ['from __future__ import annotations'] if future else []
    lines.extend(['def handle(raw):', '    def nested():'])
    indent = '        '
    if deep:
        lines.append(indent + 'def middle():')
        indent += '    '
    lines.append(indent + f'def leaf({header}){returns}:')
    lines.extend(indent + '    ' + line for line in body.splitlines())
    lines.append(indent + 'return leaf')
    if deep:
        lines.append('        return middle')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<literal-child-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('header,returns', HEADERS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_literal_headers_preserve_body_cells(header, returns, future, deep):
    code, summaries = summarise(source_for(header, returns, deep=deep, future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: 0 = raw', 'return 0', True),
    ('value: 0', 'return 0', False),
    ('value: "raw"', 'return 0', False),
    ('raw: 0', 'return raw', False),
    ('value: 0 = (raw := 0)', 'return raw', False),
])
def test_defaults_and_own_binding_masks_stay_in_their_frames(header, body, captures, future, deep):
    code, summaries = summarise(source_for(header, ' -> "raw"', body, deep, future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_literal_header_keeps_caller_raw_flow():
    source = source_for('value: "raw"').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_dynamic_annotation_mode_boundary_remains_excluded(future):
    source = source_for('value: raw', body='return 0', future=future)
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    handle = ast.parse(source).body[-1]
    assert _bounded_body_expression_loads(handle.body[0].body) is None


def test_type_parameters_remain_excluded_with_literal_annotations():
    source = 'def child[T](value: 0) -> 0:\n return raw'
    compile(source, '<generic-header-control>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body) is None
