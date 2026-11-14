"""Docstring-only child bodies retain defining-frame header reads."""

import ast
import types

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import _bounded_body_expression_loads, build_taint_summaries


CASES = [
    ('value=raw', '', '', True),
    ('*, value=raw', '', '', True),
    ('value: (-1, 0)=raw', '', ' -> 0', True),
    ('value=0', '', '', False),
    ('raw=0', '', '', False),
    ('', 'raw', '', True),
    ('value=0', '(lambda: raw)()', '', True),
    ('raw=raw', '', '', True),
    ('value=(raw := 0)', '', '', False),
]


def source_for(header, decorator='', returns='', deep=False, asynchronous=False, future=False):
    prefix = ['from __future__ import annotations'] if future else []
    lines = prefix + ['def handle(raw):', '    def nested():']
    indent = '        '
    if deep:
        lines.append(indent + 'def middle():')
        indent += '    '
    if decorator:
        lines.append(indent + '@' + decorator)
    kind = 'async ' if asynchronous else ''
    lines.extend([indent + f'{kind}def leaf({header}){returns}:',
                  indent + '    "raw.member + lambda: raw"', indent + 'return leaf'])
    if deep:
        lines.append('        return middle')
    lines.append('    return nested')
    return '\n'.join(lines) + '\n'


def summarise(source):
    code = compile(source, '<docstring-only-child>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, build_taint_summaries(graph, source)


@pytest.mark.parametrize('header,decorator,returns,captures', CASES)
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('asynchronous', [False, True], ids=['sync', 'async'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_docstring_only_headers_match_compiler_cells(header, decorator, returns, captures,
                                                     deep, asynchronous, future):
    code, summaries = summarise(source_for(header, decorator, returns, deep, asynchronous, future))
    outer = next(c for c in code.co_consts if isinstance(c, types.CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, types.CodeType) and c.co_name == 'nested')
    assert ('raw' in nested.co_freevars) is captures
    assert summaries['handle'].summary_unknown is captures


def test_docstring_only_child_keeps_caller_raw_flow():
    source = source_for('value=raw').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_docstring_view_does_not_mutate_the_source_ast(deep):
    tree = ast.parse(source_for('value=raw', deep=deep))
    body = tree.body[0].body[0].body
    before = ast.dump(tree, include_attributes=True)
    assert 'raw' in _bounded_body_expression_loads(body)
    assert ast.dump(tree, include_attributes=True) == before


@pytest.mark.parametrize('definition', [
    'def leaf(value: raw):\n "docs"',
    'def leaf() -> raw:\n "docs"',
    'def leaf[T](value=raw):\n "docs"',
])
def test_docstring_only_body_does_not_bypass_header_validation(definition):
    compile(definition, '<excluded-docstring-header>', 'exec', dont_inherit=True)
    assert _bounded_body_expression_loads(ast.parse(definition).body) is None


@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
def test_malformed_original_empty_body_stays_excluded(deep):
    # Synthetic malformed AST; a parsed docstring-only function is nonempty.
    source = 'def child():\n def leaf():\n  "docs"' if deep else 'def leaf():\n "docs"'
    tree = ast.parse(source)
    leaf = tree.body[0].body[0] if deep else tree.body[0]
    leaf.body = []
    before = ast.dump(tree, include_attributes=True)
    assert _bounded_body_expression_loads(tree.body) is None
    assert ast.dump(tree, include_attributes=True) == before
