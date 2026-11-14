"""Comprehension reader provenance stays inside its lexical scope."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _comprehension_retains_reflective_reader,
    _detect_summary_unknown,
    _function_reflective_readers,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('expression', [
    '[read(witness, "value") for read in ({reader},)][0]',
    'next(iter({{read(witness, "value") for read in ({reader},)}}))',
    '{{0: read(witness, "value") for read in ({reader},)}}[0]',
    'tuple(read(witness, "value") for read in ({reader},))[0]',
    '[alias(witness, "value") for read in ({reader},) for alias in (read,)][0]',
    '[[read(witness, "value") for _ in (0,)][0] for read in ({reader},)][0]',
], ids=['list', 'set', 'dict', 'generator', 'multiple-generators', 'nested-comprehension'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'nested'])
def test_comprehension_reader_cannot_certify_clean_flow(reader, template, expression, nested):
    prefix = template[:template.index('def helper(raw):')]
    indent = '        ' if nested else '    '
    body = indent + 'result = ' + expression.format(reader=reader) + '\n'
    body += indent + ('return observed[-1]\n' if reader == 'hasattr' else 'return result\n')
    if nested:
        body = '    def nested():\n' + body + '    return nested()\n'
    source = prefix + 'def helper(raw):\n' + body + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_comprehension_reader_fixture'}
    exec(compile(source, '<owned-comprehension-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-comprehension-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def function(source):
    return ast.parse(source).body[0]


def test_unused_comprehension_reader_keeps_outer_and_sibling_precision():
    source = ('import html\ndef helper(raw):\n'
              '    unused = [0 for read in (getattr,)]\n    return html.escape(raw)\n'
              'def sibling(raw):\n    return html.escape(raw)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    for name in ('helper', 'sibling'):
        assert not summaries[name].summary_unknown
        assert _param_cleanly_sanitized(summaries[name], 0, {'html.escape'})


def test_comprehension_local_reader_never_seeds_function_wide_aliases():
    fn = function('def helper(obj, field):\n'
                  '    read = lambda obj, field: "owned"\n'
                  '    unused = [0 for read in (getattr,)]\n    return read(obj, field)\n')
    assert 'read' not in _function_reflective_readers(fn, frozenset({'getattr', 'hasattr'}))
    assert _detect_summary_unknown(fn) is None


def test_lambda_owned_payload_name_masks_comprehension_reader():
    fn = function('def helper():\n'
                  '    return [lambda read: read for read in (getattr,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_lambda_default_retains_comprehension_reader_in_defining_scope():
    fn = function('def helper():\n'
                  '    return [lambda saved=read: saved for read in (getattr,)]\n')
    assert _detect_summary_unknown(fn) == 'comprehension retains an unmodelled reflective reader'


def test_nested_comprehension_owned_binder_masks_outer_reader():
    fn = function('def helper(obj, field):\n'
                  '    safe = lambda obj, field: "owned"\n'
                  '    return [[read(obj, field) for read in (safe,)] for read in (getattr,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_first_iterable_uses_enclosing_reader_before_target_mask():
    expression = ast.parse('[getattr(obj, field) for getattr in (getattr,)]', mode='eval').body
    assert _comprehension_retains_reflective_reader(expression, frozenset({'getattr', 'hasattr'}))


def test_scalar_iterable_masks_outer_reader_spelling():
    expression = ast.parse('[getattr(obj, field) for getattr in (safe,)]', mode='eval').body
    assert not _comprehension_retains_reflective_reader(expression, frozenset({'getattr', 'hasattr'}))


@pytest.mark.parametrize('body,reason', [
    ('return [read(obj, field, **mapping) for read in (getattr,)]', 'forwards **kwargs'),
    ('global external\n    return [read(obj, field) for read in (getattr,)]', 'declares global external'),
])
def test_comprehension_reader_preserves_existing_reason_priority(body, reason):
    fn = function('def helper(obj, field, mapping):\n    ' + body + '\n')
    assert _detect_summary_unknown(fn) == reason


def test_outer_comprehension_binder_masks_inner_iterable_reader_spelling():
    fn = function('def helper(obj, field):\n'
                  '    safe = lambda obj, field: "owned"\n'
                  '    return [[read(obj, field) for read in (getattr,)] for getattr in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_nested_comprehension_fresh_reader_keeps_enclosing_candidates():
    fn = function('def helper(obj, field):\n'
                  '    return [[read(obj, field) for read in (getattr,)] for unused in (0,)]\n')
    assert _detect_summary_unknown(fn) == 'comprehension retains an unmodelled reflective reader'


def test_own_default_comprehension_uses_defining_frame_before_body_aliases():
    fn = function('def helper(raw, unused=[read(obj, field) for read in (fallback,)]):\n'
                  '    fallback = getattr\n    return raw\n')
    assert _detect_summary_unknown(fn) is None


def test_adjacent_child_default_comprehension_uses_defining_frame():
    fn = function('def helper():\n'
                  '    def nested(unused=[read(obj, field) for read in (fallback,)]):\n'
                  '        fallback = getattr\n        return "owned"\n'
                  '    return nested()\n')
    assert _detect_summary_unknown(fn) is None
