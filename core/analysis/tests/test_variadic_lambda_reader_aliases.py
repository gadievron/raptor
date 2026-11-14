"""Explicit lambda surplus arguments carry only negative reader provenance."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _detect_summary_unknown,
    _immediate_lambda_retains_reflective_reader,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('call,projection', [
    ('(lambda *reads: {body})({reader})', 'reads[0]'),
    ('(lambda ignored, *reads: {body})(0, {reader})', 'reads[0]'),
    ('(lambda *reads, unused=0: {body})({reader}, unused=1)', 'reads[0]'),
    ('(lambda fixed=0, *reads: {body})(0, {reader})', 'reads[0]'),
    ('(lambda *reads: {body})(0, {reader})', 'reads[1]'),
], ids=['vararg', 'fixed-prefix', 'keyword-only', 'default-prefix', 'later-surplus'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_variadic_lambda_reader_cannot_certify_clean_flow(reader, template, call, projection, nested):
    prefix = template[:template.index('def helper(raw):')]
    getter = projection + '(witness, "value")'
    consumer = getter if reader == 'getattr' else '(' + getter + ', observed[-1])[1]'
    expression = call.format(reader=reader, body=consumer)
    body = ('    def nested():\n        return ' + expression + '\n    return nested()\n'
            if nested else '    return ' + expression + '\n')
    source = prefix + 'def helper(raw):\n' + body + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_variadic_lambda_reader_fixture'}
    exec(compile(source, '<owned-variadic-lambda-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-variadic-lambda-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def reason(source):
    return _detect_summary_unknown(ast.parse(source).body[0])


def test_unused_vararg_reader_does_not_withhold_certification():
    assert reason('def helper():\n    return (lambda *read: 0)(getattr)\n') is None


def test_fixed_reader_does_not_seed_safe_surplus_binding():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda first, *read: read[0](obj, field))(getattr, safe)\n') is None


def test_empty_vararg_masks_inherited_reader_spelling():
    node = ast.parse('(lambda *getattr: getattr)()', mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


def test_nested_lambda_parameter_masks_vararg_reader():
    assert reason('def helper():\n'
                  '    return (lambda *read: (lambda read: read)(0))(getattr)\n') is None


def test_comprehension_scope_masks_explicit_surplus_origin():
    assert reason('def helper(safe, obj, field):\n'
                  '    return [(lambda *read: read[0](obj, field))(getattr) for getattr in (safe,)]\n') is None


def test_own_default_preserves_defining_frame_origin():
    assert reason('def helper(raw, unused=(lambda *read: read[0](obj, field))(fallback)):\n'
                  '    fallback = getattr\n    return raw\n') is None


def test_adjacent_child_default_preserves_defining_frame_origin():
    assert reason('def helper():\n'
                  '    def nested(unused=(lambda *read: read[0](obj, field))(fallback)):\n'
                  '        fallback = getattr\n        return "owned"\n'
                  '    return nested()\n') is None


@pytest.mark.parametrize('call', [
    '(lambda *read: read)(*(getattr,))',
    '(lambda **read: read)(value=getattr)',
])
def test_actual_expansion_and_keyword_collection_remain_outside_added_check(call):
    node = ast.parse(call, mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


@pytest.mark.parametrize('body,expected', [
    ('return (lambda *read: read)(getattr, **mapping)', 'forwards **kwargs'),
    ('global external\n    return (lambda *read: read)(getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    assert reason('def helper(obj, field, mapping):\n    ' + body + '\n') == expected
