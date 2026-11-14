"""Literal-only formatted headers preserve child-cell reads without interpolation."""

import ast
from types import CodeType, SimpleNamespace

import pytest

from core.analysis import taint_summaries as module
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph


ANNOTATIONS = ['f"raw"', 'f""', 'fr"raw.member"', '(f"raw", {"raw": f""})',
               't"raw"', 't""', '(t"raw", [f"raw"])']


def require_syntax(annotation):
    if 't"' in annotation and not hasattr(ast, 'TemplateStr'):
        pytest.skip('Template strings require Python 3.14')


def source_for(annotation, body='return raw', deep=False, future=False, returns=False, header=None):
    require_syntax(annotation if header is None else header)
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
    code = compile(source, '<literal-string-header>', 'exec', dont_inherit=True)
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return code, module.build_taint_summaries(graph, source)


def retained_raw(code):
    outer = next(c for c in code.co_consts if isinstance(c, CodeType) and c.co_name == 'handle')
    nested = next(c for c in outer.co_consts if isinstance(c, CodeType) and c.co_name == 'nested')
    return 'raw' in nested.co_freevars


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('deep', [False, True], ids=['root', 'child'])
@pytest.mark.parametrize('returns', [False, True], ids=['parameter', 'return'])
def test_literal_string_headers_preserve_body_cells(annotation, future, deep, returns):
    code, summaries = summarise(source_for(annotation, deep=deep, future=future, returns=returns))
    assert retained_raw(code)
    assert summaries['handle'].summary_unknown


@pytest.mark.parametrize('annotation', ANNOTATIONS)
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_literal_text_does_not_become_a_header_name_read(annotation, future):
    code, summaries = summarise(source_for(annotation, body='return 0', future=future))
    assert not retained_raw(code)
    assert not summaries['handle'].summary_unknown


@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
@pytest.mark.parametrize('header,body,captures', [
    ('value: f"raw" = raw', 'return 0', True),
    ('raw: f"raw"', 'return raw', False),
    ('value: f"" = (raw := 0)', 'return raw', False),
])
def test_default_and_parameter_binding_ownership_is_unchanged(header, body, captures, future):
    code, summaries = summarise(source_for('0', header=header, body=body, future=future))
    assert retained_raw(code) is captures
    assert summaries['handle'].summary_unknown is captures


def test_literal_string_header_keeps_caller_raw_flow():
    source = source_for('f"raw"').replace('def handle(raw):', 'def helper(raw):')
    _, summaries = summarise('import html\n' + source
                            + 'def handle(raw):\n    return html.escape(raw) + helper(raw)\n')
    assert summaries['helper'].summary_unknown
    assert summaries['handle'].param_taints_return(0)
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})


@pytest.mark.parametrize('annotation', ['f"{raw}"', 't"{raw}"'])
@pytest.mark.parametrize('future', [False, True], ids=['ordinary', 'future'])
def test_interpolated_header_mode_boundary_stays_excluded(annotation, future):
    source = source_for(annotation, body='return 0', future=future)
    code, _ = summarise(source)
    assert retained_raw(code) is (not future)
    assert module._bounded_body_expression_loads(ast.parse(source).body[-1].body[0].body) is None


@pytest.mark.parametrize('annotation', ['f"{0}"', 't"{0}"'])
def test_constant_interpolations_remain_outside_the_literal_only_grammar(annotation):
    require_syntax(annotation)
    compile(source_for(annotation), '<excluded-interpolation>', 'exec', dont_inherit=True)
    assert not module._literal_header_annotation(ast.parse(annotation, mode='eval').body)


def test_absent_template_classes_use_the_existing_ast_facade_convention(monkeypatch):
    # An absent-class facade is not a claim of execution on an older Python.
    facade = SimpleNamespace(**{k: v for k, v in vars(ast).items()
                               if k not in {'TemplateStr', 'Interpolation'}})
    monkeypatch.setattr(module, 'ast', facade)
    assert module._literal_header_annotation(ast.parse('f"raw"', mode='eval').body)
    assert not module._literal_header_annotation(ast.parse('f"{raw}"', mode='eval').body)


def test_non_string_synthetic_parts_stay_excluded():
    # Synthetic AST control, not a compiler-accepted source counterexample.
    malformed = ast.JoinedStr(values=[ast.Constant(value=0)])
    assert not module._literal_header_annotation(malformed)
