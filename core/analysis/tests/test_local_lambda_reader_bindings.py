"""Local lambda candidates withhold certification without trusted call identity."""
import ast
import html

import pytest

from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import (
    _detect_summary_unknown,
    _function_comprehension_retains_reflective_reader,
    _function_local_lambda_candidates,
    build_taint_summaries,
)
from core.analysis.tests.test_adjacent_getter_frame_effects import SOURCE as GETTER_SOURCE
from core.analysis.tests.test_adjacent_hasattr_frame_effects import SOURCE as CHECK_SOURCE


class Marker(str):
    pass


@pytest.mark.parametrize('reader,template', [('getattr', GETTER_SOURCE), ('hasattr', CHECK_SOURCE)],
                         ids=['getattr', 'hasattr'])
@pytest.mark.parametrize('setup,call,projection', [
    ('consume = lambda read: {body}', 'consume({reader})', 'read'),
    ('base = lambda read: {body}\nconsume = base', 'consume(read={reader})', 'read'),
    ('base = lambda read: {body}\nintermediate = base\nconsume = intermediate',
     'consume(*({reader},))', 'read'),
    ('consume = lambda *, read: {body}', 'consume(read={reader})', 'read'),
    ('consume = lambda *reads: {body}', 'consume({reader})', 'reads[0]'),
    ('consume = lambda **reads: {body}', 'consume(reader={reader})', 'reads["reader"]'),
    ('consume = lambda read={reader}: {body}', 'consume()', 'read'),
], ids=['stored', 'alias', 'alias-chain-star', 'keyword-only', 'vararg', 'keyword-collection', 'saved-default'])
@pytest.mark.parametrize('nested', [False, True], ids=['direct', 'adjacent'])
def test_local_lambda_reader_cannot_certify_clean_flow(reader, template, setup, call, projection, nested):
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
    namespace = {'__name__': 'owned_local_lambda_reader_fixture'}
    exec(compile(source, '<owned-local-lambda-reader>', 'exec', dont_inherit=True), namespace)
    marker = Marker('<owned-local-lambda-reader>')
    assert namespace['helper'](marker) is marker
    assert str(marker) in namespace['handle'](marker)
    assert html.escape(marker) != marker
    assert not _param_cleanly_sanitized(summaries['handle'], 0, {'html.escape'})
    assert summaries['helper'].summary_unknown


def function(source):
    return ast.parse(source).body[0]


def test_unused_local_prototype_keeps_existing_precision():
    fn = function('def helper(raw):\n    consume = lambda read: read(obj, field)\n    return raw\n')
    assert _detect_summary_unknown(fn) is None


def test_prototypes_do_not_leak_to_sibling():
    source = ('import html\ndef helper(raw):\n'
              '    consume = lambda read: read(obj, field)\n    return consume(getattr)\n'
              'def sibling(raw):\n    consume = lambda read: "owned"\n'
              '    return html.escape(raw) + consume(getattr)\n')
    graph = build_python_module_callgraph(source)
    assert graph is not None
    summaries = build_taint_summaries(graph, source)
    assert summaries['helper'].summary_unknown
    assert not summaries['sibling'].summary_unknown
    assert _param_cleanly_sanitized(summaries['sibling'], 0, {'html.escape'})


def test_unused_nested_scope_does_not_seed_outer_prototype():
    fn = function('def helper():\n    consume = lambda read: "owned"\n'
                  '    def unused():\n        consume = lambda read: read(obj, field)\n'
                  '    return consume(getattr)\n')
    assert _detect_summary_unknown(fn) is None


def test_comprehension_binder_masks_callback_catalogue_name():
    fn = function('def helper(safe):\n    consume = lambda read: read(obj, field)\n'
                  '    return [consume(getattr) for consume in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_comprehension_binder_masks_actual_reader_argument():
    fn = function('def helper(safe):\n    consume = lambda read: read(obj, field)\n'
                  '    return [consume(getattr) for getattr in (safe,)]\n')
    assert _detect_summary_unknown(fn) is None


def test_saved_default_keeps_defining_frame_under_call_site_shadowing():
    fn = function('def helper(safe):\n    consume = lambda read=getattr: read(obj, field)\n'
                  '    return [consume() for getattr in (safe,)]\n')
    assert _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_lambdas=True,
    )


def test_safe_actual_argument_overrides_saved_reader_default_locally():
    fn = function('def helper(safe):\n    consume = lambda read=getattr: read(obj, field)\n'
                  '    return consume(safe)\n')
    assert not _function_comprehension_retains_reflective_reader(
        fn, frozenset({'getattr', 'hasattr'}), local_lambdas=True,
    )
    # Existing broader negative reader acquisition still has its own priority.
    assert _detect_summary_unknown(fn) == 'calls consume'


def test_own_defaults_cannot_use_future_body_prototypes():
    fn = function('def helper(unused=consume(getattr)):\n'
                  '    consume = lambda read: read(obj, field)\n    return 0\n')
    assert _detect_summary_unknown(fn) is None


def test_child_defaults_cannot_use_future_child_body_prototypes():
    fn = function('def helper():\n    def nested(unused=consume(getattr)):\n'
                  '        consume = lambda read: read(obj, field)\n        return 0\n'
                  '    return nested()\n')
    assert _detect_summary_unknown(fn) is None


def test_local_call_views_preserve_original_tree_and_node_identity():
    fn = function('def helper():\n    consume = lambda read: read(obj, field)\n'
                  '    return consume(getattr)\n')
    before = ast.dump(fn, include_attributes=True)
    identities = tuple(id(node) for node in ast.walk(fn))
    assert _detect_summary_unknown(fn) == 'local lambda call retains an unmodelled reflective reader'
    assert ast.dump(fn, include_attributes=True) == before
    assert tuple(id(node) for node in ast.walk(fn)) == identities


def test_alias_cycles_preserve_finite_source_candidates():
    fn = function('def helper():\n    first = lambda read: read(obj, field)\n'
                  '    second = first\n    first = second\n    return second(getattr)\n')
    candidates = _function_local_lambda_candidates(fn)
    prototype = fn.body[0].value
    assert candidates['first'] == candidates['second'] == frozenset({prototype})


@pytest.mark.parametrize('body,expected', [
    ('return consume(**mapping)', 'forwards **kwargs'),
    ('global external\n    return consume(getattr)', 'declares global external'),
])
def test_existing_reason_priority_is_preserved(body, expected):
    fn = function('def helper(mapping):\n    consume = lambda read: read(obj, field)\n    '
                  + body + '\n')
    assert _detect_summary_unknown(fn) == expected
