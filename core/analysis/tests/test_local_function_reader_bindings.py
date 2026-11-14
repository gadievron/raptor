"""Closed local function candidates carry negative reader bindings only."""
import ast
import html
import textwrap

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _detect_summary_unknown,
    _function_comprehension_retains_reflective_reader,
    _function_local_callable_candidates,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('setup,call,projection', [
    ('def consume(read):\n    return {body}', 'consume({reader})', 'read'),
    ('def base(read):\n    return {body}\nconsume = base', 'consume(read={reader})', 'read'),
    ('def base(read):\n    return {body}\nintermediate = base\nconsume = intermediate',
     'consume(*({reader},))', 'read'),
    ('def consume(*, read):\n    return {body}', 'consume(read={reader})', 'read'),
    ('def consume(*reads):\n    return {body}', 'consume({reader})', 'reads[0]'),
    ('def consume(**reads):\n    return {body}', 'consume(reader={reader})', 'reads["reader"]'),
    ('def consume(read={reader}):\n    return {body}', 'consume()', 'read'),
    ('def consume(read):\n    "owned"\n    return {body}', 'consume({reader})', 'read'),
], ids=['stored', 'alias', 'alias-chain-star', 'keyword-only', 'vararg', 'keyword-collection', 'saved-default', 'docstring'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_local_function_reader_cannot_certify_clean_flow(reader, template, setup, call, projection, nested):
    prefix = template[:template.index('def helper(raw):')]
    getter = projection + '(witness, "value")'
    consumer = getter if reader == 'getattr' else '(' + getter + ', observed[-1])[1]'
    indent = '        ' if nested else '    '
    definitions = setup.format(reader=reader, body=consumer)
    body = ''.join(indent + line + '\n' for line in definitions.splitlines())
    body += indent + 'return ' + call.format(reader=reader) + '\n'
    if nested:
        body = '    def nested():\n' + body + '    return nested()\n'
    source = prefix + 'def helper(raw):\n' + body + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_local_function_reader_fixture'}
    exec(compile(source, '<owned-local-function-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-local-function-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def function(source):
    return ast.parse(source).body[0]


def test_unused_local_definition_keeps_existing_precision():
    fn = function('def helper(raw):\n    def consume(read):\n        return read(obj, field)\n    return raw\n')
    assert _detect_summary_unknown(fn) is None


def test_local_definitions_do_not_leak_to_sibling():
    source = ('import html\ndef helper(raw):\n'
              '    def consume(read):\n        return read(obj, field)\n    return consume(getattr)\n'
              'def sibling(raw):\n    def consume(read):\n        return "owned"\n'
              '    return html.escape(raw) + consume(getattr)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    assert summaries['helper'].summary_unknown
    assert not summaries['sibling'].summary_unknown
    assert _param_cleanly_sanitized(summaries['sibling'], 0, {'html.escape'})


def test_unused_nested_scope_does_not_seed_outer_definition():
    fn = function('def helper():\n    def consume(read):\n        return "owned"\n'
                  '    def unused():\n        def consume(read):\n            return read(obj, field)\n'
                  '    return consume(getattr)\n')
    assert _detect_summary_unknown(fn) is None


def test_comprehension_binder_masks_callback_name():
    fn = function('def helper(safe):\n    def consume(read):\n        return read(obj, field)\n'
                  '    return [consume(getattr) for consume in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_comprehension_binder_masks_actual_reader_argument():
    fn = function('def helper(safe):\n    def consume(read):\n        return read(obj, field)\n'
                  '    return [consume(getattr) for getattr in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_saved_default_keeps_defining_frame_under_call_site_shadowing():
    fn = function('def helper(safe):\n    def consume(read=getattr):\n        return read(obj, field)\n'
                  '    return [consume() for getattr in (safe,)]\n')
    assert _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_functions=True,
    )


def test_safe_override_preserves_existing_broader_refusal_priority():
    fn = function('def helper(safe):\n    def consume(read=getattr):\n        return read(obj, field)\n'
                  '    return consume(safe)\n')
    assert not _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_functions=True,
    )
    assert _detect_summary_unknown(fn) == 'returned local call may have unmodelled reflective effects'


def test_own_defaults_cannot_use_future_body_definitions():
    fn = function('def helper(unused=consume(getattr)):\n'
                  '    def consume(read):\n        return read(obj, field)\n    return 0\n')
    assert _detect_summary_unknown(fn) is None


def test_child_defaults_cannot_use_future_child_body_definitions():
    fn = function('def helper():\n    def nested(unused=consume(getattr)):\n'
                  '        def consume(read):\n            return read(obj, field)\n        return 0\n'
                  '    return nested()\n')
    assert _detect_summary_unknown(fn) is None


def test_original_function_and_call_nodes_are_not_mutated():
    fn = function('def helper():\n    def consume(read):\n        "owned"\n        return read(obj, field)\n'
                  '    return consume(getattr)\n')
    before = ast.dump(fn, include_attributes=True)
    identities = tuple(id(node) for node in ast.walk(fn))
    assert _detect_summary_unknown(fn) == 'local function call retains an unmodelled reflective reader'
    assert ast.dump(fn, include_attributes=True) == before
    assert tuple(id(node) for node in ast.walk(fn)) == identities


def test_named_alias_cycles_keep_finite_source_candidates():
    fn = function('def helper():\n    def first(read):\n        return read(obj, field)\n'
                  '    second = first\n    first = second\n    return second(getattr)\n')
    candidates = _function_local_callable_candidates(fn)
    prototype = fn.body[0]
    assert candidates['first'] == candidates['second'] == frozenset({prototype})


@pytest.mark.parametrize('definition', [
    '@decorator\ndef consume(read):\n    return read(obj, field)\n',
    'def consume(read: object):\n    return read(obj, field)\n',
    'def consume(read) -> object:\n    return read(obj, field)\n',
    'async def consume(read):\n    return read(obj, field)\n',
    'def consume(read):\n    pass\n    return read(obj, field)\n',
    'def consume(read):\n    return (yield read(obj, field))\n',
    'def consume[T](read):\n    return read(obj, field)\n',
])
def test_unsupported_function_shapes_stay_outside_added_catalogue(definition):
    fn = function('def helper():\n' + textwrap.indent(definition, '    '))
    assert 'consume' not in _function_local_callable_candidates(fn)


@pytest.mark.parametrize('body,expected', [
    ('return consume(**mapping)', 'forwards **kwargs'),
    ('global external\n    return consume(getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    fn = function('def helper(mapping):\n    def consume(read):\n        return read(obj, field)\n    '
                  + body + '\n')
    assert _detect_summary_unknown(fn) == expected
