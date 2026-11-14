"""Starred literal unpacking preserves negative local callback provenance."""
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
    'consume, *unused = (lambda read: {body}, None)',
    '*unused, consume = (None, lambda read: {body})',
    'consume, *unused = (lambda read: {body},)',
    '*unused, consume = (lambda read: {body},)',
    'left, consume, *unused, right = (None, lambda read: {body}, None, None)',
    '[*unused, (consume,)] = [None, (lambda read: {body},)]',
    'def base(read):\n    return {body}\nconsume, *unused = (base, None)',
], ids=['prefix', 'suffix', 'empty-middle-prefix', 'empty-middle-suffix', 'both-ends', 'nested-list', 'named'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_starred_local_callback_cannot_certify_clean_flow(reader, template, setup, nested):
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
    namespace = {'__name__': 'owned_starred_callback_fixture'}
    exec(compile(source, '<owned-starred-callback>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-starred-callback>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown



def function(source):
    return ast.parse(source).body[0]


def test_starred_collection_is_not_a_callable_candidate():
    fn = function('def helper():\n'
                  '    safe, *collected = (lambda read: "owned", lambda read: read(obj, field))\n'
                  '    return safe(getattr)\n')
    candidates = _function_local_callable_candidates(fn)
    assert 'collected' not in candidates
    assert _detect_summary_unknown(fn) is None


def test_fixed_suffix_preserves_source_identity_and_alias_cycles():
    fn = function('def helper():\n'
                  '    *unused, consume = (None, lambda read: read(obj, field))\n'
                  '    alias, *unused = (consume,)\n'
                  '    *unused, consume = (alias,)\n'
                  '    return consume(getattr)\n')
    prototype = fn.body[0].value.elts[-1]
    before = ast.dump(fn, include_attributes=True)
    identities = tuple(id(node) for node in ast.walk(fn))
    candidates = _function_local_callable_candidates(fn)
    assert candidates['consume'] == candidates['alias'] == frozenset({prototype})
    assert ast.dump(fn, include_attributes=True) == before
    assert tuple(id(node) for node in ast.walk(fn)) == identities


@pytest.mark.parametrize('setup', [
    'consume, *unused = unknown',
    'consume, *unused, tail = (lambda read: read(obj, field),)',
    'consume, *unused = (*unknown,)',
    '*collected, = (lambda read: read(obj, field),)',
], ids=['opaque', 'insufficient', 'starred-rhs', 'collection-only'])
def test_unsupported_starred_shapes_add_no_callable_candidates(setup):
    fn = function('def helper():\n    ' + setup + '\n    return raw\n')
    assert not _function_local_callable_candidates(fn)


def test_multiple_synthetic_stars_decline_fixed_projection():
    fn = function('def helper():\n'
                  '    consume, *unused, tail = (lambda read: read(obj, field), None)\n'
                  '    return raw\n')
    fn.body[0].targets[0].elts[-1] = ast.Starred(value=ast.Name(id='tail', ctx=ast.Store()), ctx=ast.Store())
    assert not _function_local_callable_candidates(fn)


def test_comprehension_masks_starred_fixed_callback():
    fn = function('def helper(safe):\n'
                  '    consume, *unused = (lambda read: read(obj, field),)\n'
                  '    return [consume(getattr) for consume in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_unused_starred_fixed_callback_keeps_precision():
    fn = function('def helper(raw):\n'
                  '    *unused, consume = (lambda read: read(obj, field),)\n'
                  '    return raw\n')
    assert _detect_summary_unknown(fn) is None
