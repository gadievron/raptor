"""Fixed immediate lambda bindings retain negative reader provenance locally."""
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
@pytest.mark.parametrize('call', [
    '(lambda read: {body})({reader})',
    '(lambda read: {body})(read={reader})',
    '(lambda read, /: {body})({reader})',
    '(lambda read={reader}: {body})()',
    '(lambda *, read: {body})(read={reader})',
    '(lambda *, read={reader}: {body})()',
], ids=['positional', 'keyword', 'positional-only', 'default', 'keyword-only', 'keyword-default'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_immediate_lambda_reader_cannot_certify_clean_flow(reader, template, call, nested):
    prefix = template[:template.index('def helper(raw):')]
    consumer = ('read(witness, "value")' if reader == 'getattr'
                else '(read(witness, "value"), observed[-1])[1]')
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
    namespace = {'__name__': 'owned_immediate_lambda_reader_fixture'}
    exec(compile(source, '<owned-immediate-lambda-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-immediate-lambda-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def reason(source):
    return _detect_summary_unknown(ast.parse(source).body[0])


def test_supplied_safe_argument_overrides_reader_default():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read=getattr: read(obj, field))(safe)\n') is None


def test_safe_keyword_overrides_keyword_only_reader_default():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda *, read=getattr: read(obj, field))(read=safe)\n') is None


def test_unused_reader_parameter_does_not_withhold_certification():
    assert reason('def helper(raw):\n    return (lambda read: 0)(getattr)\n') is None


def test_nested_lambda_parameter_masks_outer_reader_binding():
    assert reason('def helper():\n'
                  '    return (lambda read: (lambda read: read)(0))(getattr)\n') is None


def test_parameter_spelling_masks_inherited_reader():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda getattr: getattr(obj, field))(safe)\n') is None


def test_enclosing_comprehension_masks_reader_argument_spelling():
    assert reason('def helper(safe, obj, field):\n'
                  '    return [(lambda read: read(obj, field))(getattr) for getattr in (safe,)]\n') is None


def test_own_default_uses_defining_frame_before_body_aliases():
    assert reason('def helper(raw, unused=(lambda read: read(obj, field))(fallback)):\n'
                  '    fallback = getattr\n    return raw\n') is None


def test_adjacent_child_default_uses_defining_frame():
    assert reason('def helper():\n'
                  '    def nested(unused=(lambda read: read(obj, field))(fallback)):\n'
                  '        fallback = getattr\n        return "owned"\n'
                  '    return nested()\n') is None


@pytest.mark.parametrize('call', [
    '(lambda read: read)(*values)',
    '(lambda read: read)()',
])
def test_opaque_or_incomplete_binding_is_outside_additional_check(call):
    node = ast.parse(call, mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


@pytest.mark.parametrize('body,expected', [
    ('return (lambda read: read(obj, field))(**mapping)', 'forwards **kwargs'),
    ('global external\n    return (lambda read: read(obj, field))(getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    assert reason('def helper(obj, field, mapping):\n    ' + body + '\n') == expected


def test_explicit_vararg_reader_retention_is_now_supported():
    node = ast.parse('(lambda *read: read)(getattr)', mode='eval').body
    assert _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


def test_explicit_keyword_collection_reader_retention_is_now_supported():
    node = ast.parse('(lambda **read: read)(value=getattr)', mode='eval').body
    assert _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))
