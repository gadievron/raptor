"""Literal positional stars preserve negative reader binding and source ASTs."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _detect_summary_unknown,
    _immediate_lambda_retains_reflective_reader,
    _literal_star_lambda_arguments,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('call,projection', [
    ('(lambda read: {body})(*({reader},))', 'read'),
    ('(lambda read: {body})(*[{reader}])', 'read'),
    ('(lambda read: {body})(*(*[{reader}],))', 'read'),
    ('(lambda ignored, read: {body})(0, *({reader},))', 'read'),
    ('(lambda ignored, read: {body})(*(0,), *[{reader}])', 'read'),
    ('(lambda *reads: {body})(*({reader},))', 'reads[0]'),
    ('(lambda read={reader}: {body})(*())', 'read'),
    ('(lambda **reads: {body})(*(), reader={reader})', 'reads["reader"]'),
], ids=['tuple', 'list', 'nested-literal', 'mixed-prefix', 'multiple-stars', 'vararg', 'empty-default', 'keyword'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_literal_star_lambda_reader_cannot_certify_clean_flow(reader, template, call, projection, nested):
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
    namespace = {'__name__': 'owned_literal_star_reader_fixture'}
    exec(compile(source, '<owned-literal-star-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-literal-star-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def reason(source):
    return _detect_summary_unknown(ast.parse(source).body[0])


def test_safe_literal_star_overrides_reader_default():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read=getattr: read(obj, field))(*(safe,))\n') is None


def test_empty_star_preserves_safe_default():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read=safe: read(obj, field))(*())\n') is None


def test_literal_star_keeps_fixed_and_variadic_origins_separate():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda fixed, *read: read[0](obj, field))(*(getattr, safe))\n') is None


def test_enclosing_comprehension_masks_literal_star_origin():
    assert reason('def helper(safe, obj, field):\n'
                  '    return [(lambda read: read(obj, field))(*(getattr,)) for getattr in (safe,)]\n') is None


def test_own_default_preserves_defining_frame_origin():
    assert reason('def helper(raw, unused=(lambda read: read(obj, field))(*(fallback,))):\n'
                  '    fallback = getattr\n    return raw\n') is None


def test_adjacent_child_default_preserves_defining_frame_origin():
    assert reason('def helper():\n'
                  '    def nested(unused=(lambda read: read(obj, field))(*(fallback,))):\n'
                  '        fallback = getattr\n        return "owned"\n'
                  '    return nested()\n') is None


def test_literal_star_keeps_positional_only_value_separate_from_keyword_collection():
    assert reason('def helper(safe, obj, field):\n'
                  '    return (lambda read, /, **extra: read(obj, field))(*(safe,), read=getattr)\n') is None


def test_literal_star_expansion_preserves_node_identity_order_and_source_tree():
    node = ast.parse('(lambda a, b, c: a)(0, *(first, *[second]))', mode='eval').body
    before = ast.dump(node, include_attributes=True)
    identities = tuple(id(child) for child in ast.walk(node))
    values = _literal_star_lambda_arguments(node.args)
    assert values is not None
    assert values[0] is node.args[0]
    assert values[1] is node.args[1].value.elts[0]
    assert values[2] is node.args[1].value.elts[1].value.elts[0]
    assert ast.dump(node, include_attributes=True) == before
    assert tuple(id(child) for child in ast.walk(node)) == identities


def test_ordinary_nested_container_remains_a_single_argument():
    node = ast.parse('(lambda read: read)(*((getattr,),))', mode='eval').body
    values = _literal_star_lambda_arguments(node.args)
    assert values is not None and len(values) == 1
    assert values[0] is node.args[0].value.elts[0]
    assert isinstance(values[0], ast.Tuple)


@pytest.mark.parametrize('call', [
    '(lambda read: read)(*values)',
    '(lambda read: read)(*(*values,))',
    '(lambda read: read)(*(getattr,), read=getattr)',
    '(lambda **read: read)(*(getattr,))',
])
def test_opaque_or_invalid_binding_is_outside_added_check(call):
    node = ast.parse(call, mode='eval').body
    assert not _immediate_lambda_retains_reflective_reader(node, frozenset({'getattr', 'hasattr'}))


@pytest.mark.parametrize('body,expected', [
    ('return (lambda read: read)(*(getattr,), **mapping)', 'forwards **kwargs'),
    ('global external\n    return (lambda read: read)(*(getattr,))', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    assert reason('def helper(obj, field, mapping):\n    ' + body + '\n') == expected
