"""Literal annotation containers do not hide child-body lexical cells."""

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


ANNOTATIONS = ['(0, "raw")', '[0, "raw"]', '{"raw": 0}', '{0, "raw"}',
               '(0, [None, {"raw": (True, ...)}])', '{}', '[]', '()']


def source_for(annotation, body='return raw', deep=False, future=False, returns=False, header=None):
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
    code = compile(source, '<literal-container-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('returns', [False, True], ids=['parameter', 'return'])
def test_literal_containers_preserve_body_cells(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, deep=deep, future=future, returns=returns))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' in nested.co_freevars
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_literal_header_has_no_name_reads_with_clean_body(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert 'raw' not in nested.co_freevars
    assert not summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: (0, "raw") = raw', 'return 0', True),
    ('raw: [0, "raw"]', 'return raw', False),
    ('value: {"raw": 0} = (raw := 0)', 'return raw', False),
])
def test_default_and_parameter_binding_ownership_is_unchanged(header, body, captures, future):
    code, summaries = summarise(source_for('0', header=header, body=body, future=future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_literal_container_header_keeps_caller_raw_flow():
    source = source_for('(0, ["raw"])').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('annotation', ['(0, raw)', '{"raw": raw}'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_dynamic_container_mode_boundary_stays_excluded(annotation, future):
    source = source_for(annotation, body='return 0', future=future)
    code, _ = summarise(source)
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is (not future)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


@pytest.mark.parametrize('annotation', ['(0, [raw])', 'list[0]',
                                     '(lambda: 0)', '[item for item in ()]'])
def test_unknown_annotation_descendant_refuses_the_complete_header(annotation):
    source = source_for(annotation)
    compile(source, '<excluded-container-header>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


def test_malformed_container_ast_refuses():
    # Synthetic AST controls, not compiler-accepted source counterexamples.
    tuple_node = ast.parse('(0,)', mode='eval').body
    tuple_node.ctx = ast.Store()
    assert not _literal_header_annotation(tuple_node)
    mapping = ast.Dict(keys=[ast.Constant(value=0)], values=[])
    assert not _literal_header_annotation(mapping)
