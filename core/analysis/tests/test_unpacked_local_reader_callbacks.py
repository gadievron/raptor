"""Literal unpacking preserves negative local callback provenance."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _detect_summary_unknown,
    _function_local_callable_candidates,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('setup', [
    'consume, = (lambda read: {body},)',
    '[consume] = [lambda read: {body}]',
    'safe, (consume,) = (None, (lambda read: {body},))',
    'def base(read):\n    return {body}\nconsume, = (base,)',
    'def base(read):\n    return {body}\n[intermediate] = [base]\nconsume, = (intermediate,)',
], ids=['tuple', 'list', 'nested', 'named', 'named-alias-chain'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_unpacked_local_callback_cannot_certify_clean_flow(reader, template, setup, nested):
    prefix = template[:template.index('def helper(raw):')]
    getter = 'read(witness, "value")'
    consumer = getter if reader == 'getattr' else '(' + getter + ', observed[-1])[1]'
    indent = '        ' if nested else '    '
    body = ''.join(indent + line + '\n' for line in setup.format(body=consumer).splitlines())
    body += indent + 'return consume(' + reader + ')\n'
    if nested:
        body = '    def nested():\n' + body + '    return nested()\n'
    source = prefix + 'def helper(raw):\n' + body + (
        'def handle(raw):\n    return html.escape(raw) + helper(raw)\n'
    )
    graph = build_python_module_callgraph(source)
    assert graph is not None
    assert not graph.namespace_unprovable
    summaries = build_taint_summaries(graph, source)
    namespace = {'__name__': 'owned_unpacked_callback_fixture'}
    exec(compile(source, '<owned-unpacked-callback>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-unpacked-callback>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def function(source):
    return ast.parse(source).body[0]


def test_literal_projection_does_not_mix_sibling_candidates():
    fn = function('def helper():\n'
                  '    safe, other = (lambda read: "owned", lambda read: read(obj, field))\n'
                  '    return safe(getattr)\n')
    assert _detect_summary_unknown(fn) is None


def test_unpacking_preserves_original_source_objects_and_finite_cycles():
    fn = function('def helper():\n'
                  '    consume, = (lambda read: read(obj, field),)\n'
                  '    [alias] = [consume]\n'
                  '    consume, = (alias,)\n'
                  '    return alias(getattr)\n')
    prototype = fn.body[0].value.elts[0]
    before = ast.dump(fn, include_attributes=True)
    identities = tuple(id(node) for node in ast.walk(fn))
    candidates = _function_local_callable_candidates(fn)
    assert candidates['consume'] == candidates['alias'] == frozenset({prototype})
    assert ast.dump(fn, include_attributes=True) == before
    assert tuple(id(node) for node in ast.walk(fn)) == identities


@pytest.mark.parametrize('setup', [
    'consume, = unknown',
    'consume, = (lambda read: read(obj, field), None)',
    '*consume, = (lambda read: read(obj, field),)',
    'consume, = (*unknown,)',
], ids=['opaque-iterable', 'arity-mismatch', 'star-target', 'star-value'])
def test_unsupported_unpacking_shapes_do_not_add_callable_candidates(setup):
    fn = function('def helper():\n    ' + setup + '\n    return raw\n')
    assert not _function_local_callable_candidates(fn)


def test_unused_nested_unpacking_does_not_seed_outer_catalogue():
    fn = function('def helper():\n'
                  '    def unused():\n'
                  '        consume, = (lambda read: read(obj, field),)\n'
                  '    return consume(getattr)\n')
    assert 'consume' not in _function_local_callable_candidates(fn)
    assert _detect_summary_unknown(fn) is None


def test_comprehension_binder_masks_unpacked_callback():
    fn = function('def helper(safe):\n'
                  '    consume, = (lambda read: read(obj, field),)\n'
                  '    return [consume(getattr) for consume in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_unused_unpacked_callback_keeps_existing_precision():
    fn = function('def helper(raw):\n'
                  '    consume, = (lambda read: read(obj, field),)\n'
                  '    return raw\n')
    assert _detect_summary_unknown(fn) is None
