"""Explicit keyword collection carries only negative lambda reader provenance."""
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
    ('(lambda **reads: {body})(reader={reader})', 'reads["reader"]'),
    ('(lambda fixed, **reads: {body})(0, reader={reader})', 'reads["reader"]'),
    ('(lambda *, fixed=0, **reads: {body})(fixed=1, reader={reader})', 'reads["reader"]'),
    ('(lambda read, /, **reads: {body})(0, read={reader})', 'reads["read"]'),
    ('(lambda *unused, **reads: {body})(0, 1, reader={reader})', 'reads["reader"]'),
    ('(lambda fixed=0, **reads: {body})(reader={reader})', 'reads["reader"]'),
], ids=['collection', 'fixed-prefix', 'keyword-only', 'positional-only-name', 'vararg', 'default'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_keyword_lambda_reader_cannot_certify_clean_flow(reader, template, call, projection, nested):
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
    namespace = {'__name__': 'owned_keyword_lambda_reader_fixture'}
    exec(compile(source, '<owned-keyword-lambda-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-keyword-lambda-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def reason(source):
    return _detect_summary_unknown(ast.parse(source).body[0])


def test_unused_keyword_reader_does_not_withhold_certification():
    assert reason('def helper():\n    return (lambda **read: 0)(reader=getattr)\n') is None


def test_fixed_keyword_reader_does_not_seed_safe_collection():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda fixed, **read: read["safe"](obj, field))(fixed=getattr, safe=safe)\n') is None


def test_collected_reader_does_not_seed_safe_fixed_parameter():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read, **extra: read(obj, field))(read=safe, unused=getattr)\n') is None


def test_positional_only_same_name_keyword_does_not_replace_fixed_value():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read, /, **extra: read(obj, field))(safe, read=getattr)\n') is None


def test_collected_positional_only_name_cannot_satisfy_missing_fixed_parameter():
    node = ast.parse('(lambda read, /, **extra: extra)(read=getattr)', mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


def test_empty_keyword_collection_masks_inherited_spelling():
    node = ast.parse('(lambda **getattr: getattr)()', mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


def test_nested_lambda_parameter_masks_collection_reader():
    assert reason('def helper():\n'
                  '    return (lambda **read: (lambda read: read)(0))(value=getattr)\n') is None


def test_comprehension_scope_masks_explicit_keyword_origin():
    assert reason('def helper(safe, obj, field):\n'
                  '    return [(lambda **read: read["value"](obj, field))(value=getattr) for getattr in (safe,)]\n') is None


def test_own_default_preserves_defining_frame_origin():
    assert reason('def helper(raw, unused=(lambda **read: read["value"](obj, field))(value=fallback)):\n'
                  '    fallback = getattr\n    return raw\n') is None


def test_adjacent_child_default_preserves_defining_frame_origin():
    assert reason('def helper():\n'
                  '    def nested(unused=(lambda **read: read["value"](obj, field))(value=fallback)):\n'
                  '        fallback = getattr\n        return "owned"\n'
                  '    return nested()\n') is None


@pytest.mark.parametrize('call', [
    '(lambda **read: read)(**mapping)',
    '(lambda **read: read)(*values)',
    '(lambda **read: read)(value=getattr, value=getattr)',
])
def test_opaque_or_duplicate_binding_is_outside_added_check(call):
    node = ast.parse(call, mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


@pytest.mark.parametrize('body,expected', [
    ('return (lambda **read: read)(value=getattr, **mapping)', 'forwards **kwargs'),
    ('global external\n    return (lambda **read: read)(value=getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    assert reason('def helper(obj, field, mapping):\n    ' + body + '\n') == expected
